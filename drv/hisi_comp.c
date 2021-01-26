// SPDX-License-Identifier: Apache-2.0

#include <asm/types.h>
#include "drv/wd_comp_drv.h"
#include "hisi_qm_udrv.h"
#include "wd.h"

#define	ZLIB		0
#define	GZIP		1

#define DEFLATE		0
#define INFLATE		1

#define ASIZE		(2 * 512 * 1024)
#define HW_CTX_SIZE	(64*1024)

enum alg_type {
	HW_DEFLATE = 0x1,
	HW_ZLIB,
	HW_GZIP,
};

enum hw_state {
	HZ_STATELESS,
	HZ_STATEFUL,
};

enum hw_flush {
	HZ_SYNC_FLUSH,
	HZ_FINISH,
};

enum hw_stream_status {
	HZ_STREAM_OLD,
	HZ_STREAM_NEW,
};

struct hisi_zip_sqe {
	__u32 consumed;
	__u32 produced;
	__u32 comp_data_length;

	/*
	 * status: 0~7 bits
	 * rsvd: 8~31 bits
	 */
	__u32 dw3;

	__u32 input_data_length;
	__u32 dw5;
	__u32 dw6;

	/*
	 * in_sge_data_offset: 0~23 bits
	 * rsvd: 24 bit
	 * flush_type: 25 bit
	 * stream_mode: 26 bit
	 * steam_new_flag: 27 bit
	 * sqe_type: 28~31 bits
	 */
	__u32 dw7;

	/*
	 * out_sge_data_offset: 0~23 bits
	 * rsvd: 24~31 bits
	 */
	__u32 dw8;

	/*
	 * request_type: 0~7 bits
	 * buffer_type: 8~11 bits
	 * window_size: 12~15 bits
	 * rsvd: 16~31 bits
	 */
	__u32 dw9;

	__u32 dw10;
	__u32 dw11;
	__u32 dw12;

	/* tag: in sqe type 0 */
	__u32 dw13;

	__u32 dest_avail_out;
	__u32 ctx_dw0;
	__u32 dw16;
	__u32 dw17;
	__u32 source_addr_l;
	__u32 source_addr_h;
	__u32 dest_addr_l;
	__u32 dest_addr_h;
	__u32 stream_ctx_addr_l;
	__u32 stream_ctx_addr_h;
	__u32 dw24;
	__u32 dw25;

	/* tag: in sqe type 3 */
	__u32 dw26;

	__u32 dw27;
	__u32 ctx_dw1;
	__u32 ctx_dw2;
	__u32 isize;
	__u32 checksum;
};

struct hisi_zip_sqe_ops {
	const char *alg_name;
	void (*fill_buf)(struct hisi_zip_sqe *sqe, struct wd_comp_msg *msg);
	void (*fill_sqe_type)(struct hisi_zip_sqe *sqe);
	void (*fill_alg)(struct hisi_zip_sqe *sqe);
	void (*fill_tag)(struct hisi_zip_sqe *sqe, __u32 tag);
	void (*get_data_size)(struct hisi_zip_sqe *sqe, int op_type,
			      struct wd_comp_msg *recv_msg);
	int (*get_tag)(struct hisi_zip_sqe *sqe);
};

#define BLOCK_SIZE	(1 << 19)

#define ZLIB_HEADER	"\x78\x9c"
#define ZLIB_HEADER_SZ	2

/*
 * We use a extra field for gzip block length. So the fourth byte is \x04.
 * This is necessary because our software don't know the size of block when
 * using an hardware decompresser (It is known by hardware). This help our
 * decompresser to work and helpfully, compatible with gzip.
 */
#define GZIP_HEADER	"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03"
#define GZIP_HEADER_SZ	10

#define GZIP_HEADER_EX	"\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\x03"
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

#define STREAM_FLUSH_SHIFT 25
#define MIN_AVAILOUT_SIZE 4096
#define STREAM_POS_SHIFT 2
#define STREAM_MODE_SHIFT 1

#define HZ_NEGACOMPRESS 0x0d
#define HZ_CRC_ERR 0x10
#define HZ_DECOMP_END 0x13

#define HZ_DECOMP_NO_SPACE 0x01
#define HZ_DECOMP_BLK_NOSTART 0x03

#define HZ_CTX_ST_MASK 0x000f
#define HZ_LSTBLK_MASK 0x0100
#define HZ_STATUS_MASK 0xff
#define HZ_REQ_TYPE_MASK 0xff
#define HZ_STREAM_POS_MASK 0x08000000

#define HZ_HADDR_SHIFT		32
#define HZ_SQE_TYPE_V1		0x0
#define HZ_SQE_TYPE_V3		0x30000000

#define lower_32_bits(addr) ((__u32)((__u64)(addr)))
#define upper_32_bits(addr) ((__u32)((__u64)(addr) >> HZ_HADDR_SHIFT))

#define HZ_MAX_SIZE (8 * 1024 * 1024)

#define RSV_OFFSET 64
#define CTX_DW1_OFFSET 4
#define CTX_DW2_OFFSET 8

struct hisi_zip_ctx {
	struct wd_ctx_config_internal	config;
};

static void fill_buf_size_deflate(struct hisi_zip_sqe *sqe, __u32 in_size,
				  __u32 out_size)
{
	sqe->input_data_length = in_size;
	sqe->dest_avail_out = out_size;
}

static void fill_buf_addr_deflate(struct hisi_zip_sqe *sqe, void *src,
				  void *dst, void *ctx_buf)
{
	sqe->source_addr_l = lower_32_bits((__u64)src);
	sqe->source_addr_h = upper_32_bits((__u64)src);
	sqe->dest_addr_l = lower_32_bits((__u64)dst);
	sqe->dest_addr_h = upper_32_bits((__u64)dst);
	sqe->stream_ctx_addr_l = lower_32_bits((__u64)ctx_buf);
	sqe->stream_ctx_addr_h = upper_32_bits((__u64)ctx_buf);
}

static void fill_buf_deflate(struct hisi_zip_sqe *sqe, struct wd_comp_msg *msg)
{
	struct wd_comp_req *req = &msg->req;
	void *ctx_buf;

	fill_buf_size_deflate(sqe, req->src_len, msg->avail_out);

	if (msg->ctx_buf)
		ctx_buf = msg->ctx_buf + RSV_OFFSET;
	else
		ctx_buf = NULL;

	fill_buf_addr_deflate(sqe, req->src, req->dst, ctx_buf);
}

static void fill_buf_zlib(struct hisi_zip_sqe *sqe, struct wd_comp_msg *msg)
{
	__u32 in_size = msg->req.src_len;
	__u32 out_size = msg->avail_out;
	void *src = msg->req.src;
	void *dst = msg->req.dst;
	void *ctx_buf;

	if (msg->stream_pos == WD_COMP_STREAM_NEW) {
		if (msg->req.op_type == WD_DIR_COMPRESS) {
			memcpy(dst, ZLIB_HEADER, ZLIB_HEADER_SZ);
			dst += ZLIB_HEADER_SZ;
			out_size -= ZLIB_HEADER_SZ;
		} else {
			src += ZLIB_HEADER_SZ;
			in_size -= ZLIB_HEADER_SZ;
		}
	}

	fill_buf_size_deflate(sqe, in_size, out_size);

	if (msg->ctx_buf)
		ctx_buf = msg->ctx_buf + RSV_OFFSET;
	else
		ctx_buf = NULL;

	fill_buf_addr_deflate(sqe, src, dst, ctx_buf);
}

static void fill_buf_gzip(struct hisi_zip_sqe *sqe, struct wd_comp_msg *msg)
{
	__u32 in_size = msg->req.src_len;
	__u32 out_size = msg->avail_out;
	void *src = msg->req.src;
	void *dst = msg->req.dst;
	void *ctx_buf;

	if (msg->stream_pos == WD_COMP_STREAM_NEW) {
		if (msg->req.op_type == WD_DIR_COMPRESS) {
			memcpy(dst, GZIP_HEADER, GZIP_HEADER_SZ);
			dst += GZIP_HEADER_SZ;
			out_size -= GZIP_HEADER_SZ;
		} else {
			src += GZIP_HEADER_SZ;
			in_size -= GZIP_HEADER_SZ;
		}
	}

	fill_buf_size_deflate(sqe, in_size, out_size);

	if (msg->ctx_buf)
		ctx_buf = msg->ctx_buf + RSV_OFFSET;
	else
		ctx_buf = NULL;

	fill_buf_addr_deflate(sqe, src, dst, ctx_buf);
}

static void fill_sqe_type_v1(struct hisi_zip_sqe *sqe)
{
	__u32 val;
	val = sqe->dw7 & ~HZ_SQE_TYPE_V1;
	val |= HZ_SQE_TYPE_V1;
	sqe->dw7 = val;
}

static void fill_sqe_type_v3(struct hisi_zip_sqe *sqe)
{
	__u32 val;
	val = sqe->dw7 & ~HZ_SQE_TYPE_V3;
	val |= HZ_SQE_TYPE_V3;
	sqe->dw7 = val;
}

static void fill_alg_deflate(struct hisi_zip_sqe *sqe)
{
	__u32 val;
	val = sqe->dw9 & ~HZ_REQ_TYPE_MASK;
	val |= HW_DEFLATE;
	sqe->dw9 = val;
}

static void fill_alg_zlib(struct hisi_zip_sqe *sqe)
{
	__u32 val;
	val = sqe->dw9 & ~HZ_REQ_TYPE_MASK;
	val |= HW_ZLIB;
	sqe->dw9 = val;
}

static void fill_alg_gzip(struct hisi_zip_sqe *sqe)
{
	__u32 val;
	val = sqe->dw9 & ~HZ_REQ_TYPE_MASK;
	val |= HW_GZIP;
	sqe->dw9 = val;
}

static void fill_tag_v1(struct hisi_zip_sqe *sqe, __u32 tag)
{
	sqe->dw13 = tag;
}

static void fill_tag_v3(struct hisi_zip_sqe *sqe, __u32 tag)
{
	sqe->dw26 = tag;
}

static void get_data_size_deflate(struct hisi_zip_sqe *sqe, int op_type,
				  struct wd_comp_msg *recv_msg)
{
	recv_msg->in_cons = sqe->consumed;
	recv_msg->produced = sqe->produced;
}

static void get_data_size_zlib(struct hisi_zip_sqe *sqe, int op_type,
			       struct wd_comp_msg *recv_msg)
{
	__u32 stream_pos = sqe->dw7 & HZ_STREAM_POS_MASK;

	recv_msg->in_cons = sqe->consumed;
	recv_msg->produced = sqe->produced;

	if (stream_pos) {
		if (op_type == WD_DIR_COMPRESS)
			recv_msg->produced += ZLIB_HEADER_SZ;
		else
			recv_msg->in_cons += ZLIB_HEADER_SZ;
	}
}

static void get_data_size_gzip(struct hisi_zip_sqe *sqe, int op_type,
			       struct wd_comp_msg *recv_msg)
{
	__u32 stream_pos = sqe->dw7 & HZ_STREAM_POS_MASK;

	recv_msg->in_cons = sqe->consumed;
	recv_msg->produced = sqe->produced;

	if (stream_pos) {
		if (op_type == WD_DIR_COMPRESS)
			recv_msg->produced += GZIP_HEADER_SZ;
		else
			recv_msg->in_cons += GZIP_HEADER_SZ;
	}
}

static int get_tag_v1(struct hisi_zip_sqe *sqe)
{
	return sqe->dw13;
}

static int get_tag_v3(struct hisi_zip_sqe *sqe)
{
	return sqe->dw26;
}

struct hisi_zip_sqe_ops ops[] = { {
		.alg_name = "deflate",
		.fill_buf = fill_buf_deflate,
		.fill_sqe_type = fill_sqe_type_v3,
		.fill_alg = fill_alg_deflate,
		.fill_tag = fill_tag_v3,
		.get_data_size = get_data_size_deflate,
		.get_tag = get_tag_v3,
	}, {
		.alg_name = "zlib",
		.fill_buf = fill_buf_zlib,
		.fill_alg = fill_alg_zlib,
		.get_data_size = get_data_size_zlib,
	}, {
		.alg_name = "gzip",
		.fill_buf = fill_buf_gzip,
		.fill_alg = fill_alg_gzip,
		.get_data_size = get_data_size_gzip,
	},
};

static void hisi_zip_sqe_ops_adapt(handle_t h_qp)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;

	if (qp->q_info.hw_type == HISI_QM_API_VER2_BASE) {
		ops[WD_ZLIB].fill_sqe_type = fill_sqe_type_v1;
		ops[WD_ZLIB].fill_tag = fill_tag_v1;
		ops[WD_ZLIB].get_tag = get_tag_v1;
		ops[WD_GZIP].fill_sqe_type = fill_sqe_type_v1;
		ops[WD_GZIP].fill_tag = fill_tag_v1;
		ops[WD_GZIP].get_tag = get_tag_v1;
	} else if (qp->q_info.hw_type >= HISI_QM_API_VER3_BASE) {
		ops[WD_ZLIB].fill_sqe_type = fill_sqe_type_v3;
		ops[WD_ZLIB].fill_tag = fill_tag_v3;
		ops[WD_ZLIB].get_tag = get_tag_v3;
		ops[WD_GZIP].fill_sqe_type = fill_sqe_type_v3;
		ops[WD_GZIP].fill_tag = fill_tag_v3;
		ops[WD_GZIP].get_tag = get_tag_v3;
	}
}

static int hisi_zip_init(struct wd_ctx_config_internal *config, void *priv)
{
	struct hisi_zip_ctx *zip_ctx = (struct hisi_zip_ctx *)priv;
	struct hisi_qm_priv qm_priv;
	handle_t h_qp = 0;
	handle_t h_ctx;
	int i;

	memcpy(&zip_ctx->config, config, sizeof(struct wd_ctx_config));
	/* allocate qp for each context */
	for (i = 0; i < config->ctx_num; i++) {
		h_ctx = config->ctxs[i].ctx;
		qm_priv.sqe_size = sizeof(struct hisi_zip_sqe);
		qm_priv.op_type = config->ctxs[i].op_type;
		h_qp = hisi_qm_alloc_qp(&qm_priv, h_ctx);
		if (!h_qp)
			goto out;
	}

	hisi_zip_sqe_ops_adapt(h_qp);

	return 0;
out:
	for (; i >= 0; i--) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[i].ctx);
		hisi_qm_free_qp(h_qp);
	}
	return -EINVAL;
}

static void hisi_zip_exit(void *priv)
{
	struct hisi_zip_ctx *zip_ctx = (struct hisi_zip_ctx *)priv;
	struct wd_ctx_config_internal *config = &zip_ctx->config;
	handle_t h_qp;
	int i;

	for (i = 0; i < config->ctx_num; i++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[i].ctx);
		hisi_qm_free_qp(h_qp);
	}
}
static int fill_zip_comp_sqe(struct hisi_qp *qp, struct wd_comp_msg *msg,
			     struct hisi_zip_sqe *sqe)
{
	__u8 alg_type = msg->alg_type;
	__u8 flush_type;
	__u8 stream_pos;
	__u8 state;

	if (alg_type >= WD_COMP_ALG_MAX) {
		WD_ERR("invalid algorithm type(%d)\n", alg_type);
		return -EINVAL;
	}

	ops[alg_type].fill_buf(sqe, msg);

	ops[alg_type].fill_sqe_type(sqe);

	ops[alg_type].fill_alg(sqe);

	ops[alg_type].fill_tag(sqe, msg->tag);

	state = (msg->stream_mode == WD_COMP_STATEFUL) ? HZ_STATEFUL :
		HZ_STATELESS;
	stream_pos = (msg->stream_pos == WD_COMP_STREAM_NEW) ? HZ_STREAM_NEW :
		     HZ_STREAM_OLD;
	flush_type = (msg->req.last == 1) ? HZ_FINISH : HZ_SYNC_FLUSH;
	sqe->dw7 |= ((stream_pos << STREAM_POS_SHIFT) |
		    (state << STREAM_MODE_SHIFT) |
		    (flush_type)) << STREAM_FLUSH_SHIFT;
	sqe->isize = msg->isize;
	sqe->checksum = msg->checksum;

	if (msg->ctx_buf) {
		sqe->ctx_dw0 = *(__u32 *)msg->ctx_buf;
		sqe->ctx_dw1 = *(__u32 *)(msg->ctx_buf + CTX_DW1_OFFSET);
		sqe->ctx_dw2 = *(__u32 *)(msg->ctx_buf + CTX_DW2_OFFSET);
	}

	return 0;
}

static int hisi_zip_comp_send(handle_t ctx, struct wd_comp_msg *msg, void *priv)
{
	struct hisi_qp *qp = wd_ctx_get_priv(ctx);
	handle_t h_qp = (handle_t)qp;
	struct hisi_zip_sqe sqe = {0};
	__u16 count = 0;
	int ret;

	if (unlikely(msg->req.src_len > HZ_MAX_SIZE)) {
		WD_ERR("invalid: out of range in_len(%u)!\n", msg->req.src_len);
		return -WD_EINVAL;
	}

	if (unlikely(msg->avail_out > HZ_MAX_SIZE)) {
		WD_ERR("warning: out of range avail_out(%u), will set 8MB size max!\n", msg->avail_out);
		msg->avail_out = HZ_MAX_SIZE;
	}

	ret = fill_zip_comp_sqe(qp, msg, &sqe);
	if (ret < 0) {
		WD_ERR("failed to fill zip sqe(%d)!\n", ret);
		return ret;
	}
	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0)
		WD_ERR("qm send is err(%d)!\n", ret);

	return ret;
}

static int parse_zip_sqe(struct hisi_qp *qp, struct hisi_zip_sqe *sqe, 
			 struct wd_comp_msg *recv_msg)
{
	__u16 ctx_st = sqe->ctx_dw0 & HZ_CTX_ST_MASK;
	__u16 lstblk = sqe->dw3 & HZ_LSTBLK_MASK;
	__u32 status = sqe->dw3 & HZ_STATUS_MASK;
	__u32 type = sqe->dw9 & HZ_REQ_TYPE_MASK;
	int alg_type = 0;

	if (status != 0 && status != HZ_NEGACOMPRESS &&
	    status != HZ_CRC_ERR && status != HZ_DECOMP_END) {
		WD_ERR("bad status(ctx_st=0x%x, s=0x%x, t=%u)\n",
		       ctx_st, status, type);
		recv_msg->req.status = WD_IN_EPARA;
	} else {
		if (!sqe->produced)
			return -EAGAIN;
		recv_msg->req.status = 0;
	}

	if (type == HW_DEFLATE)
		alg_type = WD_DEFLATE;
	else if (type == HW_ZLIB)
		alg_type = WD_ZLIB;
	else if (type == HW_GZIP)
		alg_type = WD_GZIP;

	ops[alg_type].get_data_size(sqe, qp->q_info.qc_type, recv_msg);

	recv_msg->avail_out = sqe->dest_avail_out;
	if (sqe->stream_ctx_addr_l && sqe->stream_ctx_addr_h) {
		/*
		 * In ASYNC mode, recv_msg->ctx_buf is NULL.
		 * recv_msg->ctx_buf is only valid in SYNC mode.
		 * ctx_dwx uses 4 BYTES
		 */
		*(__u32 *)recv_msg->ctx_buf = sqe->ctx_dw0;
		*(__u32 *)(recv_msg->ctx_buf + CTX_DW1_OFFSET) = sqe->ctx_dw1;
		*(__u32 *)(recv_msg->ctx_buf + CTX_DW2_OFFSET) = sqe->ctx_dw2;
	}

	/* last block no space, need resend null size req */
	if (ctx_st == HZ_DECOMP_NO_SPACE)
		recv_msg->req.status = WD_EAGAIN;

	dbg("zip recv lst =%hu, ctx_st=0x%x, status=0x%x, alg=%u\n", lstblk, ctx_st, status, type);
	if (lstblk && (status == HZ_DECOMP_END))
		recv_msg->req.status = WD_STREAM_END;

	recv_msg->isize = sqe->isize;
	recv_msg->checksum = sqe->checksum;
	recv_msg->tag = ops[alg_type].get_tag(sqe);

	return 0;
}

static int hisi_zip_comp_recv(handle_t ctx, struct wd_comp_msg *recv_msg,
			      void *priv)
{
	struct hisi_qp *qp = wd_ctx_get_priv(ctx);
	handle_t h_qp = (handle_t)qp;
	struct hisi_zip_sqe sqe = {0};
	__u16 count = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (ret < 0)
		return ret;

	return parse_zip_sqe(qp, &sqe, recv_msg);
}

struct wd_comp_driver hisi_zip = {
	.drv_name		= "hisi_zip",
	.alg_name		= "zlib\ngzip",
	.drv_ctx_size		= sizeof(struct hisi_zip_ctx),
	.init			= hisi_zip_init,
	.exit			= hisi_zip_exit,
	.comp_send		= hisi_zip_comp_send,
	.comp_recv		= hisi_zip_comp_recv,
};

WD_COMP_SET_DRIVER(hisi_zip);
