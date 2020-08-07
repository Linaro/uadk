/* SPDX-License-Identifier: Apache-2.0 */
#include "hisi_comp.h"

#define BLOCK_SIZE	(1 << 19)
#define CACHE_NUM	1	//4

#define ZLIB_HEADER	"\x78\x9c"
#define ZLIB_HEADER_SZ	2

/*
 * We use a extra field for gzip block length. So the fourth byte is \x04.
 * This is necessary because our software don't know the size of block when
 * using an hardware decompresser (It is known by hardware). This help our
 * decompresser to work and helpfully, compatible with gzip.
 */
#define GZIP_HEADER	"\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\x03"
#define GZIP_HEADER_SZ	10
#define GZIP_EXTRA_SZ	10
#define GZIP_TAIL_SZ	8

#define BLOCK_MIN		(1 << 10)
#define BLOCK_MIN_MASK		0x3FF
#define BLOCK_MAX		(1 << 20)
#define BLOCK_MAX_MASK		0xFFFFF
#define STREAM_MIN		(1 << 10)
#define STREAM_MIN_MASK		0x3FF
#define STREAM_MAX		(1 << 20)
#define STREAM_MAX_MASK		0xFFFFF

#define HISI_SCHED_INPUT	0
#define HISI_SCHED_OUTPUT	1

#define Z_OK            0
#define Z_STREAM_END    1
#define Z_ERRNO		(-1)
#define Z_STREAM_ERROR	(-EIO)

#define swab32(x) \
	((((x) & 0x000000ff) << 24) | \
	(((x) & 0x0000ff00) <<  8) | \
	(((x) & 0x00ff0000) >>  8) | \
	(((x) & 0xff000000) >> 24))

#define cpu_to_be32(x) swab32(x)

#ifndef container_of
#define container_of(ptr, type, member) \
	(type *)((char *)(ptr) - (char *) &((type *)0)->member)
#endif

/* new code */
#include "../include/drv/wd_comp_drv.h"

struct hisi_zip_ctx {
	struct wd_ctx_config	config;
};

static int hisi_zip_init(struct wd_ctx_config *config, void *priv)
{
	struct hisi_qm_priv qm_priv;
	struct hisi_zip_ctx *zip_ctx = (struct hisi_zip_ctx *)priv;
	handle_t h_ctx, h_qp;
	int i, j, ret = 0;

	/* allocate qp for each context */
	for (i = 0; i < config->ctx_num; i++) {
		h_ctx = config->ctxs[i].ctx;
		qm_priv.sqe_size = sizeof(struct hisi_zip_sqe);
		qm_priv.op_type = config->ctxs[i].op_type;
		h_qp = hisi_qm_alloc_qp(&qm_priv, h_ctx);
		if (!h_qp) {
			ret = -EINVAL;
			goto out;
		}
		memcpy(&zip_ctx->config, config, sizeof(struct wd_ctx_config));
	}
	return 0;
out:
	for (j = 0; j < i; j++) {
		h_qp = (handle_t)wd_ctx_get_sess_priv(config->ctxs[j].ctx);
		hisi_qm_free_qp(h_qp);
	}
	return ret;
}

static void hisi_zip_exit(void *priv)
{
	struct hisi_zip_ctx *zip_ctx = (struct hisi_zip_ctx *)priv;
	struct wd_ctx_config *config = &zip_ctx->config;
	handle_t h_qp;
	int i;

	for (i = 0; i < config->ctx_num; i++) {
		h_qp = (handle_t)wd_ctx_get_sess_priv(config->ctxs[i].ctx);
		hisi_qm_free_qp(h_qp);
	}
}


#define STREAM_FLUSH_SHIFT 25
#define MIN_AVAILOUT_SIZE 4096
#define STREAM_POS_SHIFT 2
#define STREAM_MODE_SHIFT 1

#define HZ_NEGACOMPRESS 0x0d
#define HZ_CRC_ERR 0x10
#define HZ_DECOMP_END 0x13

#define HZ_CTX_ST_MASK 0x000f
#define HZ_LSTBLK_MASK 0x0100
#define HZ_STATUS_MASK 0xff
#define HZ_REQ_TYPE_MASK 0xff

#define HZ_HADDR_SHIFT		32

#define lower_32_bits(addr) ((__u32)((__u64)(addr)))
#define upper_32_bits(addr) ((__u32)((__u64)(addr) >> HZ_HADDR_SHIFT))

static int hisi_zip_comp_send(handle_t ctx, struct wd_comp_msg *msg)
{
	struct hisi_zip_sqe sqe;
	__u8 flush_type;
	int ret;

	memset(&sqe, 0, sizeof(struct hisi_zip_sqe));
	switch (msg->alg_type) {
	case WD_ZLIB:
		sqe.dw9 = HW_ZLIB;
		break;
	case WD_GZIP:
		sqe.dw9 = HW_GZIP;
		break;
	default:
		return -WD_EINVAL;
	}

	sqe.source_addr_l = lower_32_bits((__u64)msg->src);
	sqe.source_addr_h = upper_32_bits((__u64)msg->src);
	sqe.dest_addr_l = lower_32_bits((__u64)msg->dst);
	sqe.dest_addr_h = upper_32_bits((__u64)msg->dst);
	sqe.stream_ctx_addr_l = lower_32_bits((__u64)msg->ctx_buf);
	sqe.stream_ctx_addr_h = upper_32_bits((__u64)msg->ctx_buf);


	flush_type = (msg->flush_type == 1) ? HZ_FINISH :
			  HZ_SYNC_FLUSH;
	sqe.dw7 |= ((msg->stream_pos << STREAM_POS_SHIFT) |
		     (STATEFUL << STREAM_MODE_SHIFT) |
		     (flush_type)) << STREAM_FLUSH_SHIFT;
	sqe.input_data_length = msg->in_size;
	if (msg->avail_out > MIN_AVAILOUT_SIZE)
		sqe.dest_avail_out = msg->avail_out;
	else
		sqe.dest_avail_out = MIN_AVAILOUT_SIZE;
	sqe.ctx_dw0 = msg->ctx_priv0;
	sqe.ctx_dw1 = msg->ctx_priv1;
	sqe.ctx_dw2 = msg->ctx_priv2;
	sqe.isize = msg->isize;
	sqe.checksum = msg->checksum;
	sqe.tag = msg->tag;
	ret = hisi_qm_send(ctx, &sqe, 1);
	if (ret < 0) {
		WD_ERR("hisi_qm_send is err(%d)!\n", ret);
		return ret;
	}

	return ret;
}


static int hisi_zip_comp_recv(handle_t ctx, struct wd_comp_msg *recv_msg)
{
	struct hisi_zip_sqe sqe;
	int ret;

	ret = hisi_qm_recv(ctx, &sqe);
	if (ret < 0) {
		if (ret != -EAGAIN)
			WD_ERR("hisi_qm_recv is err(%d)!\n", ret);
		return ret;
	}

	__u16 ctx_st = sqe.ctx_dw0 & HZ_CTX_ST_MASK;
	//__u16 lstblk = sqe.dw3 & HZ_LSTBLK_MASK;
	__u32 status = sqe.dw3 & HZ_STATUS_MASK;
	__u32 type = sqe.dw9 & HZ_REQ_TYPE_MASK;

	if (status != 0 && status != HZ_NEGACOMPRESS &&
	    status != HZ_CRC_ERR && status != HZ_DECOMP_END) {
		WD_ERR("bad status(ctx_st=0x%x, s=0x%x, t=%u)\n",
		       ctx_st, status, type);
		recv_msg->status = WD_IN_EPARA;
	} else {
		if (!sqe.consumed || !sqe.produced)
			return -EAGAIN;
		recv_msg->status = 0;
	}
	recv_msg->in_cons = sqe.consumed;
	recv_msg->in_size = sqe.input_data_length;
	recv_msg->produced = sqe.produced;
	recv_msg->avail_out = sqe.dest_avail_out;
	recv_msg->comp_lv = 0;
	recv_msg->op_type = 0;
	recv_msg->win_size = 0;
	recv_msg->ctx_priv0 = sqe.ctx_dw0;
	recv_msg->ctx_priv1 = sqe.ctx_dw1;
	recv_msg->ctx_priv2 = sqe.ctx_dw2;
	recv_msg->isize = sqe.isize;
	recv_msg->checksum = sqe.checksum;
	recv_msg->tag = sqe.tag;

	return 0;

}

static struct wd_comp_driver hisi_zip = {
	.drv_name		= "hisi_zip",
	.alg_name		= "zlib\ngzip",
	.drv_ctx_size		= sizeof(struct hisi_zip_ctx),
	.init			= hisi_zip_init,
	.exit			= hisi_zip_exit,
	.comp_send		= hisi_zip_comp_send,
	.comp_recv		= hisi_zip_comp_recv,
};

WD_COMP_SET_DRIVER(hisi_zip);
