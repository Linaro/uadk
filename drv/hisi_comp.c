// SPDX-License-Identifier: Apache-2.0
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <asm/types.h>
#include "drv/wd_comp_drv.h"
#include "hisi_qm_udrv.h"
#include "wd.h"

#define	ZLIB				0
#define	GZIP				1

#define DEFLATE				0
#define INFLATE				1

#define ZLIB_HEADER			"\x78\x9c"
#define ZLIB_HEADER_SZ			2

/*
 * We use a extra field for gzip block length. So the fourth byte is \x04.
 * This is necessary because our software don't know the size of block when
 * using an hardware decompressor (It is known by hardware). This help our
 * decompressor to work and helpfully, compatible with gzip.
 */
#define GZIP_HEADER			"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03"
#define GZIP_HEADER_SZ			10

#define GZIP_HEADER_EX			"\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\x03"
#define GZIP_EXTRA_SZ			10
#define GZIP_TAIL_SZ			8

#define ZSTD_MAX_SIZE			(1 << 17)

#define swab32(x) \
	((((x) & 0x000000ff) << 24) | \
	(((x) & 0x0000ff00) <<  8) | \
	(((x) & 0x00ff0000) >>  8) | \
	(((x) & 0xff000000) >> 24))

#define STREAM_FLUSH_SHIFT		25
#define STREAM_POS_SHIFT		2
#define STREAM_MODE_SHIFT		1
#define LITLEN_OVERFLOW_CNT_SHIFT	24
#define BUF_TYPE_SHIFT			8
#define WINDOW_SIZE_SHIFT		12

#define LITLEN_OVERFLOW_POS_MASK	0xffffff

#define HZ_DECOMP_NO_SPACE		0x01
#define HZ_NEGACOMPRESS			0x0d
#define HZ_CRC_ERR			0x10
#define HZ_DECOMP_END			0x13

#define HZ_CTX_ST_MASK			0x000f
#define HZ_LSTBLK_MASK			0x0100
#define HZ_STATUS_MASK			0xff
#define HZ_REQ_TYPE_MASK		0xff
#define HZ_SGL_OFFSET_MASK		0xffffff
#define HZ_STREAM_POS_MASK		0x08000000
#define HZ_BUF_TYPE_MASK		0xf00
#define HZ_HADDR_SHIFT			32
#define HZ_SQE_TYPE_V1			0x0
#define HZ_SQE_TYPE_V3			0x30000000

#define lower_32_bits(addr)		((__u32)((uintptr_t)(addr)))
#define upper_32_bits(addr)		((__u32)((uintptr_t)(addr) >> HZ_HADDR_SHIFT))

#define HZ_MAX_SIZE			(8 * 1024 * 1024)

#define RSV_OFFSET			64
#define CTX_DW1_OFFSET			4
#define CTX_DW2_OFFSET			8
#define CTX_REPCODE1_OFFSET		12
#define CTX_REPCODE2_OFFSET		24
#define CTX_HW_REPCODE_OFFSET		784
#define OVERFLOW_DATA_SIZE		2
#define ZSTD_FREQ_DATA_SIZE		784
#define ZSTD_LIT_RESV_SIZE		16
#define REPCODE_SIZE			12

#define BUF_TYPE			2

enum alg_type {
	HW_DEFLATE = 0x1,
	HW_ZLIB,
	HW_GZIP,
	HW_LZ77_ZSTD_PRICE = 0x42,
	HW_LZ77_ZSTD,
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

enum lz77_compress_status {
	UNCOMP_BLK,
	RLE_BLK,
	COMP_BLK,
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
	__u32 literals_addr_l;
	__u32 literals_addr_h;
	/* tag: in sqe type 3 */
	__u32 dw26;
	__u32 dw27;
	__u32 ctx_dw1;
	__u32 ctx_dw2;
	__u32 isize;
	/*
	 * checksum: in alg gzip
	 * linlength_overflow_pos: 0~23 bits in alg lz77_zstd
	 * linlength_overflow_cnt: 24~31 bits in alg lz77_zstd
	 */
	__u32 dw31;
};

struct hisi_zip_sqe_ops {
	const char *alg_name;
	int (*fill_buf[BUF_TYPE])(handle_t h_qp, struct hisi_zip_sqe *sqe,
				  struct wd_comp_msg *msg);
	void (*fill_sqe_type)(struct hisi_zip_sqe *sqe);
	void (*fill_alg)(struct hisi_zip_sqe *sqe);
	void (*fill_tag)(struct hisi_zip_sqe *sqe, __u32 tag);
	int (*fill_comp_level)(struct hisi_zip_sqe *sqe, enum wd_comp_level comp_lv);
	void (*get_data_size)(struct hisi_zip_sqe *sqe, enum wd_comp_op_type op_type,
			      struct wd_comp_msg *recv_msg);
	int (*get_tag)(struct hisi_zip_sqe *sqe);
};

struct hisi_zip_ctx {
	struct wd_ctx_config_internal	config;
};

static int buf_size_check_deflate(__u32 *in_size, __u32 *out_size)
{
	if (unlikely(*in_size > HZ_MAX_SIZE)) {
		WD_ERR("invalid: out of range in_len(%u)!\n", *in_size);
		return -WD_EINVAL;
	}

	if (unlikely(*out_size > HZ_MAX_SIZE)) {
		WD_ERR("warning: out of range avail_out(%u), will set 8MB size max!\n",
		       *out_size);
		*out_size = HZ_MAX_SIZE;
	}

	return 0;
}

static void fill_buf_size_deflate(struct hisi_zip_sqe *sqe, __u32 in_size,
				  __u32 out_size)
{
	sqe->input_data_length = in_size;
	sqe->dest_avail_out = out_size;
}

static void fill_buf_addr_deflate(struct hisi_zip_sqe *sqe, void *src,
				  void *dst, void *ctx_buf)
{
	sqe->source_addr_l = lower_32_bits(src);
	sqe->source_addr_h = upper_32_bits(src);
	sqe->dest_addr_l = lower_32_bits(dst);
	sqe->dest_addr_h = upper_32_bits(dst);
	sqe->stream_ctx_addr_l = lower_32_bits(ctx_buf);
	sqe->stream_ctx_addr_h = upper_32_bits(ctx_buf);
}

static int fill_buf_deflate(handle_t h_qp, struct hisi_zip_sqe *sqe,
			    struct wd_comp_msg *msg)
{
	struct wd_comp_req *req = &msg->req;
	__u32 out_size = msg->avail_out;
	__u32 in_size = req->src_len;
	void *ctx_buf;
	int ret;

	ret = buf_size_check_deflate(&in_size, &out_size);
	if (ret)
		return ret;

	fill_buf_size_deflate(sqe, in_size, out_size);

	if (msg->ctx_buf)
		ctx_buf = msg->ctx_buf + RSV_OFFSET;
	else
		ctx_buf = NULL;

	fill_buf_addr_deflate(sqe, req->src, req->dst, ctx_buf);

	return 0;
}

static int fill_buf_zlib(handle_t h_qp, struct hisi_zip_sqe *sqe,
			 struct wd_comp_msg *msg)
{
	__u32 in_size = msg->req.src_len;
	__u32 out_size = msg->avail_out;
	void *src = msg->req.src;
	void *dst = msg->req.dst;
	void *ctx_buf = NULL;
	int ret;

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

	ret = buf_size_check_deflate(&in_size, &out_size);
	if (ret)
		return ret;

	fill_buf_size_deflate(sqe, in_size, out_size);

	if (msg->ctx_buf)
		ctx_buf = msg->ctx_buf + RSV_OFFSET;

	fill_buf_addr_deflate(sqe, src, dst, ctx_buf);

	return 0;
}

static int fill_buf_gzip(handle_t h_qp, struct hisi_zip_sqe *sqe,
			 struct wd_comp_msg *msg)
{
	__u32 in_size = msg->req.src_len;
	__u32 out_size = msg->avail_out;
	void *src = msg->req.src;
	void *dst = msg->req.dst;
	void *ctx_buf = NULL;
	int ret;

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

	ret = buf_size_check_deflate(&in_size, &out_size);
	if (ret)
		return ret;

	fill_buf_size_deflate(sqe, in_size, out_size);

	if (msg->ctx_buf)
		ctx_buf = msg->ctx_buf + RSV_OFFSET;

	fill_buf_addr_deflate(sqe, src, dst, ctx_buf);

	return 0;
}

static void fill_buf_type_sgl(struct hisi_zip_sqe *sqe)
{
	__u32 val;

	val = sqe->dw9 & HZ_BUF_TYPE_MASK;
	val |= 1 << BUF_TYPE_SHIFT;
	sqe->dw9 = val;
}

static int fill_buf_addr_deflate_sgl(handle_t h_qp, struct hisi_zip_sqe *sqe,
				     struct wd_comp_msg *msg)
{
	struct wd_comp_req *req = &msg->req;
	void *hw_sgl_in, *hw_sgl_out;
	handle_t h_sgl_pool;

	h_sgl_pool = hisi_qm_get_sglpool(h_qp);
	if (!h_sgl_pool) {
		WD_ERR("failed to get sglpool\n");
		return -WD_EINVAL;
	}

	hw_sgl_in = hisi_qm_get_hw_sgl(h_sgl_pool, req->list_src);
	if (!hw_sgl_in) {
		WD_ERR("failed to get hw sgl in\n");
		return -WD_ENOMEM;
	}

	hw_sgl_out = hisi_qm_get_hw_sgl(h_sgl_pool, req->list_dst);
	if (!hw_sgl_out) {
		WD_ERR("failed to get hw sgl out\n");
		hisi_qm_put_hw_sgl(h_sgl_pool, hw_sgl_in);
		return -WD_ENOMEM;
	}

	fill_buf_addr_deflate(sqe, hw_sgl_in, hw_sgl_out, NULL);

	return 0;
}

static int fill_buf_deflate_sgl(handle_t h_qp, struct hisi_zip_sqe *sqe,
				struct wd_comp_msg *msg)
{
	struct wd_comp_req *req = &msg->req;
	int ret;

	fill_buf_type_sgl(sqe);

	ret = fill_buf_addr_deflate_sgl(h_qp, sqe, msg);
	if (ret)
		return ret;

	fill_buf_size_deflate(sqe, req->src_len, msg->avail_out);

	return 0;
}

static void fill_buf_sgl_skip(struct hisi_zip_sqe *sqe, __u32 src_skip,
			      __u32 dst_skip)
{
	__u32 val;

	val = sqe->dw7 & ~HZ_SGL_OFFSET_MASK;
	val |= src_skip;
	sqe->dw7 = val;

	val = sqe->dw8 & ~HZ_SGL_OFFSET_MASK;
	val |= dst_skip;
	sqe->dw8 = val;
}

static int fill_buf_zlib_sgl(handle_t h_qp, struct hisi_zip_sqe *sqe,
			     struct wd_comp_msg *msg)
{
	struct wd_comp_req *req = &msg->req;
	__u32 out_size = msg->avail_out;
	__u32 in_size = req->src_len;
	__u32 src_skip = 0;
	__u32 dst_skip = 0;
	int ret;

	fill_buf_type_sgl(sqe);

	ret = fill_buf_addr_deflate_sgl(h_qp, sqe, msg);
	if (ret)
		return ret;

	if (msg->req.op_type == WD_DIR_COMPRESS) {
		memcpy(req->list_dst->data, ZLIB_HEADER, ZLIB_HEADER_SZ);
		dst_skip = ZLIB_HEADER_SZ;
		out_size -= ZLIB_HEADER_SZ;
	} else {
		src_skip = ZLIB_HEADER_SZ;
		in_size -= ZLIB_HEADER_SZ;
	}

	fill_buf_sgl_skip(sqe, src_skip, dst_skip);

	fill_buf_size_deflate(sqe, in_size, out_size);

	return 0;
}

static int fill_buf_gzip_sgl(handle_t h_qp, struct hisi_zip_sqe *sqe,
			     struct wd_comp_msg *msg)
{
	struct wd_comp_req *req = &msg->req;
	__u32 out_size = msg->avail_out;
	__u32 in_size = req->src_len;
	__u32 src_skip = 0;
	__u32 dst_skip = 0;
	int ret;

	fill_buf_type_sgl(sqe);

	ret = fill_buf_addr_deflate_sgl(h_qp, sqe, msg);
	if (ret)
		return ret;

	if (msg->req.op_type == WD_DIR_COMPRESS) {
		memcpy(req->list_dst->data, GZIP_HEADER, GZIP_HEADER_SZ);
		dst_skip = GZIP_HEADER_SZ;
		out_size -= GZIP_HEADER_SZ;
	} else {
		src_skip = GZIP_HEADER_SZ;
		in_size -= GZIP_HEADER_SZ;
	}

	fill_buf_sgl_skip(sqe, src_skip, dst_skip);

	fill_buf_size_deflate(sqe, in_size, out_size);

	return 0;
}

static void fill_buf_size_lz77_zstd(struct hisi_zip_sqe *sqe, __u32 in_size,
				    __u32 lits_size, __u32 seqs_size)
{
	sqe->input_data_length = in_size;

	/* fill the literals output size */
	sqe->dw13 = lits_size;

	/* fill the sequences output size */
	sqe->dest_avail_out = seqs_size;
}

static void fill_buf_addr_lz77_zstd(struct hisi_zip_sqe *sqe,
				    void *src, void *lits_start,
				    void *seqs_start, void *ctx_buf)
{
	sqe->source_addr_l = lower_32_bits(src);
	sqe->source_addr_h = upper_32_bits(src);
	sqe->dest_addr_l = lower_32_bits(seqs_start);
	sqe->dest_addr_h = upper_32_bits(seqs_start);
	sqe->literals_addr_l = lower_32_bits(lits_start);
	sqe->literals_addr_h = upper_32_bits(lits_start);
	sqe->stream_ctx_addr_l = lower_32_bits(ctx_buf);
	sqe->stream_ctx_addr_h = upper_32_bits(ctx_buf);
}

static int fill_buf_lz77_zstd(handle_t h_qp, struct hisi_zip_sqe *sqe,
			      struct wd_comp_msg *msg)
{
	struct wd_comp_req *req = &msg->req;
	struct wd_lz77_zstd_data *data = req->priv;
	__u32 in_size = msg->req.src_len;
	__u32 lit_size = in_size + ZSTD_LIT_RESV_SIZE;
	__u32 out_size = msg->avail_out;
	void *ctx_buf = NULL;

	if (unlikely(!data)) {
		WD_ERR("wd_lz77_zstd_data address is NULL\n");
		return -WD_EINVAL;
	}

	if (unlikely(in_size > ZSTD_MAX_SIZE)) {
		WD_ERR("invalid input data size of lz77_zstd(%u)\n", in_size);
		return -WD_EINVAL;
	}

	if (unlikely(out_size > HZ_MAX_SIZE)) {
		WD_ERR("warning: out of range avail_out(%u), will set 8MB size max!\n",
		       out_size);
		out_size = HZ_MAX_SIZE;
	}

	/*
	 * For lz77_zstd, the hardware need 784 Bytes buffer to output
	 * the frequency information about input data.
	 */
	if (unlikely(out_size < ZSTD_FREQ_DATA_SIZE + lit_size)) {
		WD_ERR("output buffer size of lz77_zstd is not enough(%u)\n",
		       ZSTD_FREQ_DATA_SIZE + in_size);
		return -WD_EINVAL;
	}

	if (msg->ctx_buf) {
		ctx_buf = msg->ctx_buf + RSV_OFFSET;
		if (data->blk_type != COMP_BLK)
			memcpy(ctx_buf + CTX_HW_REPCODE_OFFSET,
			       msg->ctx_buf + CTX_REPCODE2_OFFSET, REPCODE_SIZE);
	}

	fill_buf_size_lz77_zstd(sqe, in_size, lit_size, out_size - lit_size);

	fill_buf_addr_lz77_zstd(sqe, req->src, req->dst,
				req->dst + lit_size, ctx_buf);

	data->literals_start = req->dst;
	data->sequences_start = req->dst + lit_size;

	return 0;
}

static struct wd_datalist *get_seq_start_list(struct wd_comp_req *req)
{
	struct wd_datalist *cur = req->list_dst;
	__u32 lits_size = 0;

	while (cur) {
		lits_size += cur->len;
		cur = cur->next;
		if (lits_size >= req->src_len + ZSTD_LIT_RESV_SIZE)
			break;
	}

	return cur;
}

static int fill_buf_lz77_zstd_sgl(handle_t h_qp, struct hisi_zip_sqe *sqe,
				  struct wd_comp_msg *msg)
{
	void *hw_sgl_in, *hw_sgl_out_lit, *hw_sgl_out_seq;
	struct wd_comp_req *req = &msg->req;
	struct wd_lz77_zstd_data *data = req->priv;
	__u32 in_size = msg->req.src_len;
	__u32 out_size = msg->avail_out;
	struct wd_datalist *seq_start;
	handle_t h_sgl_pool;
	__u32 lits_size;
	int ret;

	if (unlikely(in_size > ZSTD_MAX_SIZE)) {
		WD_ERR("invalid input data size of lz77_zstd(%u)\n", in_size);
		return -WD_EINVAL;
	}

	if (unlikely(!data)) {
		WD_ERR("wd_lz77_zstd_data address is NULL\n");
		return -WD_EINVAL;
	}

	fill_buf_type_sgl(sqe);

	seq_start = get_seq_start_list(req);

	data->literals_start = req->list_dst;
	data->sequences_start = seq_start;

	lits_size = hisi_qm_get_list_size(req->list_dst, seq_start);

	fill_buf_size_lz77_zstd(sqe, in_size, lits_size, out_size - lits_size);

	h_sgl_pool = hisi_qm_get_sglpool(h_qp);
	if (!h_sgl_pool) {
		WD_ERR("failed to get sglpool\n");
		return -WD_EINVAL;
	}

	hw_sgl_in = hisi_qm_get_hw_sgl(h_sgl_pool, req->list_src);
	if (!hw_sgl_in) {
		WD_ERR("failed to get hw sgl in\n");
		return -WD_ENOMEM;
	}

	hw_sgl_out_lit = hisi_qm_get_hw_sgl(h_sgl_pool, req->list_dst);
	if (!hw_sgl_out_lit) {
		WD_ERR("failed to get hw sgl out for literals\n");
		ret = -WD_ENOMEM;
		goto err_free_sgl_in;
	}

	hw_sgl_out_seq = hisi_qm_get_hw_sgl(h_sgl_pool, seq_start);
	if (!hw_sgl_out_seq) {
		WD_ERR("failed to get hw sgl out for sequences\n");
		ret = -WD_ENOMEM;
		goto err_free_sgl_out_lit;
	}

	fill_buf_addr_lz77_zstd(sqe, hw_sgl_in, hw_sgl_out_lit,
				hw_sgl_out_seq, NULL);

	return 0;

err_free_sgl_out_lit:
	hisi_qm_put_hw_sgl(h_sgl_pool, hw_sgl_out_lit);
err_free_sgl_in:
	hisi_qm_put_hw_sgl(h_sgl_pool, hw_sgl_in);
	return ret;
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

static void fill_alg_lz77_zstd(struct hisi_zip_sqe *sqe)
{
	__u32 val;

	val = sqe->dw9 & ~HZ_REQ_TYPE_MASK;
	val |= HW_LZ77_ZSTD;
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

static int fill_comp_level_deflate(struct hisi_zip_sqe *sqe, enum wd_comp_level comp_lv)
{
	return 0;
}

static int fill_comp_level_lz77_zstd(struct hisi_zip_sqe *sqe, enum wd_comp_level comp_lv)
{
	__u32 val;

	switch (comp_lv) {
	case WD_COMP_L8:
		break;
	case WD_COMP_L9:
		val = sqe->dw9 & ~HZ_REQ_TYPE_MASK;
		val |= HW_LZ77_ZSTD_PRICE;
		sqe->dw9 = val;
		break;
	default:
		WD_ERR("invalid: comp_lv in unsupported (%d)\n", comp_lv);
		return -WD_EINVAL;
	}

	return 0;
}

static void get_data_size_deflate(struct hisi_zip_sqe *sqe, enum wd_comp_op_type op_type,
				  struct wd_comp_msg *recv_msg)
{
	recv_msg->in_cons = sqe->consumed;
	recv_msg->produced = sqe->produced;
}

static void get_data_size_zlib(struct hisi_zip_sqe *sqe, enum wd_comp_op_type op_type,
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

static void get_data_size_gzip(struct hisi_zip_sqe *sqe, enum wd_comp_op_type op_type,
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

static void get_data_size_lz77_zstd(struct hisi_zip_sqe *sqe, enum wd_comp_op_type op_type,
				    struct wd_comp_msg *recv_msg)
{
	struct wd_lz77_zstd_data *data = recv_msg->req.priv;
	void *ctx_buf = recv_msg->ctx_buf;

	if (!data)
		return;

	data->lit_num = sqe->comp_data_length;
	data->seq_num = sqe->produced;
	data->lit_length_overflow_cnt = sqe->dw31 >> LITLEN_OVERFLOW_CNT_SHIFT;
	data->lit_length_overflow_pos = sqe->dw31 & LITLEN_OVERFLOW_POS_MASK;
	data->freq = data->sequences_start + data->seq_num + OVERFLOW_DATA_SIZE;

	if (ctx_buf) {
		memcpy(ctx_buf + CTX_REPCODE2_OFFSET,
		       ctx_buf + CTX_REPCODE1_OFFSET, REPCODE_SIZE);
		memcpy(ctx_buf + CTX_REPCODE1_OFFSET,
		       ctx_buf + RSV_OFFSET + CTX_HW_REPCODE_OFFSET, REPCODE_SIZE);
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
		.fill_buf[WD_FLAT_BUF] = fill_buf_deflate,
		.fill_buf[WD_SGL_BUF] = fill_buf_deflate_sgl,
		.fill_sqe_type = fill_sqe_type_v3,
		.fill_alg = fill_alg_deflate,
		.fill_tag = fill_tag_v3,
		.fill_comp_level = fill_comp_level_deflate,
		.get_data_size = get_data_size_deflate,
		.get_tag = get_tag_v3,
	}, {
		.alg_name = "zlib",
		.fill_buf[WD_FLAT_BUF] = fill_buf_zlib,
		.fill_buf[WD_SGL_BUF] = fill_buf_zlib_sgl,
		.fill_alg = fill_alg_zlib,
		.fill_comp_level = fill_comp_level_deflate,
		.get_data_size = get_data_size_zlib,
	}, {
		.alg_name = "gzip",
		.fill_buf[WD_FLAT_BUF] = fill_buf_gzip,
		.fill_buf[WD_SGL_BUF] = fill_buf_gzip_sgl,
		.fill_alg = fill_alg_gzip,
		.fill_comp_level = fill_comp_level_deflate,
		.get_data_size = get_data_size_gzip,
	}, {
		.alg_name = "lz77_zstd",
		.fill_buf[WD_FLAT_BUF] = fill_buf_lz77_zstd,
		.fill_buf[WD_SGL_BUF] = fill_buf_lz77_zstd_sgl,
		.fill_sqe_type = fill_sqe_type_v3,
		.fill_alg = fill_alg_lz77_zstd,
		.fill_tag = fill_tag_v3,
		.fill_comp_level = fill_comp_level_lz77_zstd,
		.get_data_size = get_data_size_lz77_zstd,
		.get_tag = get_tag_v3,
	}
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

	memcpy(&zip_ctx->config, config, sizeof(struct wd_ctx_config_internal));
	/* allocate qp for each context */
	for (i = 0; i < config->ctx_num; i++) {
		h_ctx = config->ctxs[i].ctx;
		qm_priv.sqe_size = sizeof(struct hisi_zip_sqe);
		qm_priv.op_type = config->ctxs[i].op_type;
		qm_priv.qp_mode = config->ctxs[i].ctx_mode;
		qm_priv.idx = i;
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
	return -WD_EINVAL;
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
	enum hisi_hw_type hw_type = qp->q_info.hw_type;
	enum wd_comp_alg_type alg_type = msg->alg_type;
	__u32 win_sz = msg->win_sz;
	__u8 flush_type;
	__u8 stream_pos;
	__u8 state;
	int ret;

	if ((hw_type <= HISI_QM_API_VER2_BASE && alg_type > WD_GZIP) ||
	    (hw_type >= HISI_QM_API_VER3_BASE && alg_type >= WD_COMP_ALG_MAX)) {
		WD_ERR("invalid algorithm type(%d)\n", alg_type);
		return -WD_EINVAL;
	}

	ret = ops[alg_type].fill_buf[msg->req.data_fmt]((handle_t)qp, sqe, msg);
	if (ret)
		return ret;

	ops[alg_type].fill_sqe_type(sqe);

	ops[alg_type].fill_alg(sqe);

	ops[alg_type].fill_tag(sqe, msg->tag);

	ret = ops[alg_type].fill_comp_level(sqe, msg->comp_lv);
	if (ret)
		return ret;

	state = (msg->stream_mode == WD_COMP_STATEFUL) ? HZ_STATEFUL :
		HZ_STATELESS;
	stream_pos = (msg->stream_pos == WD_COMP_STREAM_NEW) ? HZ_STREAM_NEW :
		     HZ_STREAM_OLD;
	flush_type = (msg->req.last == 1) ? HZ_FINISH : HZ_SYNC_FLUSH;
	sqe->dw7 |= ((stream_pos << STREAM_POS_SHIFT) |
		    (state << STREAM_MODE_SHIFT) |
		    (flush_type)) << STREAM_FLUSH_SHIFT;
	sqe->dw9 |= win_sz << WINDOW_SIZE_SHIFT;
	sqe->isize = msg->isize;
	sqe->dw31 = msg->checksum;

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

	ret = fill_zip_comp_sqe(qp, msg, &sqe);
	if (ret < 0) {
		WD_ERR("failed to fill zip sqe(%d)!\n", ret);
		return ret;
	}
	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (ret < 0 && ret != -WD_EBUSY)
		WD_ERR("qm send is err(%d)!\n", ret);

	hisi_qm_enable_interrupt(ctx, msg->is_polled);

	return ret;
}

static int get_alg_type(__u32 type)
{
	int alg_type = -WD_EINVAL;

	switch (type) {
	case HW_DEFLATE:
		alg_type = WD_DEFLATE;
		break;
	case HW_ZLIB:
		alg_type = WD_ZLIB;
		break;
	case HW_GZIP:
		alg_type = WD_GZIP;
		break;
	case HW_LZ77_ZSTD:
	case HW_LZ77_ZSTD_PRICE:
		alg_type = WD_LZ77_ZSTD;
		break;
	default:
		break;
	}

	return alg_type;
}

static void free_hw_sgl(handle_t h_qp, struct hisi_zip_sqe *sqe,
			enum wd_comp_alg_type alg_type)
{
	void *hw_sgl_in, *hw_sgl_out;
	handle_t h_sgl_pool;

	h_sgl_pool = hisi_qm_get_sglpool(h_qp);
	if (!h_sgl_pool) {
		WD_ERR("failed to get sglpool to free hw sgl\n");
		return;
	}

	hw_sgl_in = VA_ADDR(sqe->source_addr_h, sqe->source_addr_l);
	hisi_qm_put_hw_sgl(h_sgl_pool, hw_sgl_in);

	hw_sgl_out = VA_ADDR(sqe->dest_addr_h, sqe->dest_addr_l);
	hisi_qm_put_hw_sgl(h_sgl_pool, hw_sgl_out);

	if (alg_type == WD_LZ77_ZSTD) {
		hw_sgl_out = VA_ADDR(sqe->literals_addr_h,
				     sqe->literals_addr_l);
		hisi_qm_put_hw_sgl(h_sgl_pool, hw_sgl_out);
	}
}

static int parse_zip_sqe(struct hisi_qp *qp, struct hisi_zip_sqe *sqe,
			 struct wd_comp_msg *recv_msg)
{
	__u32 buf_type = (sqe->dw9 & HZ_BUF_TYPE_MASK) >> BUF_TYPE_SHIFT;
	__u16 ctx_st = sqe->ctx_dw0 & HZ_CTX_ST_MASK;
	__u16 lstblk = sqe->dw3 & HZ_LSTBLK_MASK;
	__u32 status = sqe->dw3 & HZ_STATUS_MASK;
	__u32 type = sqe->dw9 & HZ_REQ_TYPE_MASK;
	int alg_type;
	__u32 tag;

	alg_type = get_alg_type(type);
	if (alg_type < 0) {
		WD_ERR("failed to get request algorithm type(%u)\n", type);
		return -WD_EINVAL;
	}

	tag = ops[alg_type].get_tag(sqe);

	recv_msg->tag = tag;

	if (qp->q_info.qp_mode == CTX_MODE_ASYNC) {
		recv_msg = wd_comp_get_msg(qp->q_info.idx, tag);
		if (!recv_msg) {
			WD_ERR("failed to get send msg! idx = %u, tag = %u.\n",
			       qp->q_info.idx, tag);
			return -WD_EINVAL;
		}
	}

	recv_msg->req.status = 0;

	if (status != 0 && status != HZ_NEGACOMPRESS &&
	    status != HZ_CRC_ERR && status != HZ_DECOMP_END) {
		WD_ERR("bad status(ctx_st=0x%x, s=0x%x, t=%u)\n",
		       ctx_st, status, type);
		recv_msg->req.status = WD_IN_EPARA;
	}

	ops[alg_type].get_data_size(sqe, qp->q_info.qc_type, recv_msg);

	recv_msg->avail_out = sqe->dest_avail_out;
	if (VA_ADDR(sqe->stream_ctx_addr_h, sqe->stream_ctx_addr_l)) {
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
	recv_msg->checksum = sqe->dw31;
	recv_msg->alg_type = alg_type;

	if (buf_type == WD_SGL_BUF)
		free_hw_sgl((handle_t)qp, sqe, alg_type);

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
	.alg_name		= "zlib\ngzip\ndeflate\nlz77_zstd",
	.drv_ctx_size		= sizeof(struct hisi_zip_ctx),
	.init			= hisi_zip_init,
	.exit			= hisi_zip_exit,
	.comp_send		= hisi_zip_comp_send,
	.comp_recv		= hisi_zip_comp_recv,
};

WD_COMP_SET_DRIVER(hisi_zip);
