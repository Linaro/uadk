// SPDX-License-Identifier: Apache-2.0
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <asm/types.h>
#include "drv/wd_comp_drv.h"
#include "drv/hisi_comp_huf.h"
#include "hisi_qm_udrv.h"

#define	ZLIB				0
#define	GZIP				1

#define DEFLATE				0
#define INFLATE				1

#define ZLIB_HEADER			"\x78\x9c"
#define ZLIB_HEADER_SZ			2
#define ZIP_CTX_Q_NUM_DEF		1
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

/* Error status 0xe indicates that dest_avail_out insufficient */
#define ERR_DSTLEN_OUT			0xe

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
#define HZ_DECOMP_BLK_NOSTART		0x03
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

/* the min output buffer size is (input size * 1.125) */
#define min_out_buf_size(inl)		((((__u64)inl * 9) + 7) >> 3)
/* the max input size is (output buffer size * 8 / 9) and align with 4 byte */
#define max_in_data_size(outl)		((__u32)(((__u64)outl << 3) / 9) & 0xfffffffc)

#define HZ_MAX_SIZE			(8 * 1024 * 1024)

#define RSV_OFFSET			64
#define CTX_DW1_OFFSET			4
#define CTX_DW2_OFFSET			8
#define CTX_REPCODE1_OFFSET		12
#define CTX_REPCODE2_OFFSET		24
#define CTX_HW_REPCODE_OFFSET		784
#define OVERFLOW_DATA_SIZE		8
#define SEQ_DATA_SIZE_SHIFT		3
#define ZSTD_FREQ_DATA_SIZE		784
#define ZSTD_LIT_RESV_SIZE		16
#define REPCODE_SIZE			12

#define BUF_TYPE			2

/* 200 * 1.125 + GZIP_HEADER_SZ, align with 4 byte */
#define STORE_BUF_SIZE			236
/* The hardware requires at least 200byte output buffers */
#define SW_STOREBUF_TH			200
/* The 38KB offset in ctx_buf is used as the internal buffer */
#define CTX_STOREBUF_OFFSET		0x9800

#define CTX_BLOCKST_OFFSET		0xc00
#define CTX_WIN_LEN_MASK		0xffff
#define CTX_HEAD_BIT_CNT_SHIFT		0xa
#define CTX_HEAD_BIT_CNT_MASK		0xfC00
#define WIN_LEN_ALIGN(len)		((len + 15) & ~(__u32)0x0F)

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

struct hisi_comp_buf {
	/* Denoted whether the output is copied from the storage buffer */
	bool skip_hw;
	/* Denoted internal store buf */
	__u8 dst[STORE_BUF_SIZE];
	/* Denoted data size left in uadk */
	__u32 pending_out;
	/* Size that have been copied */
	__u32 output_offset;
	/* Store end flag return by HW */
	__u32 status;
	/* Denoted internal store sgl */
	struct wd_datalist list_dst;
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

static void dump_zip_msg(struct wd_comp_msg *msg)
{
	WD_ERR("dump zip message after a task error occurs.\n");
	WD_ERR("avali_out:%u in_cons:%u produced:%u data_fmt:%u.\n",
		msg->avail_out, msg->in_cons, msg->produced, msg->data_fmt);
}

static int buf_size_check_deflate(__u32 *in_size, __u32 *out_size)
{
	if (unlikely(*in_size > HZ_MAX_SIZE)) {
		WD_ERR("invalid: in_len(%u) is out of range!\n", *in_size);
		return -WD_EINVAL;
	}

	if (unlikely(*out_size > HZ_MAX_SIZE)) {
		WD_ERR("warning: avail_out(%u) is out of range, will set 8MB size max!\n",
		       *out_size);
		*out_size = HZ_MAX_SIZE;
	}

	return 0;
}

static __u32 copy_to_out(struct wd_comp_msg *msg, struct hisi_comp_buf *buf, __u32 total_len)
{
	struct wd_comp_req *req = &msg->req;
	struct wd_datalist *node = req->list_dst;
	__u32 sgl_restlen, copy_len;
	__u32 len = 0, sgl_cplen = 0;

	copy_len = total_len > req->dst_len ?
		   req->dst_len : total_len;
	sgl_restlen = copy_len;

	if (req->data_fmt == WD_FLAT_BUF) {
		memcpy(req->dst, buf->dst + buf->output_offset, copy_len);
		return copy_len;
	}

	while (node != NULL && sgl_restlen > 0) {
		len = node->len > sgl_restlen ? sgl_restlen : node->len;
		memcpy(node->data, buf->list_dst.data + buf->output_offset + sgl_cplen,
			len);
		sgl_restlen -= len;
		sgl_cplen += len;
		node = node->next;
	}

	return sgl_cplen;
}

static int check_store_buf(struct wd_comp_msg *msg)
{
	struct wd_comp_req *req = &msg->req;
	struct hisi_comp_buf *buf;
	__u32 copy_len;

	if (!msg->ctx_buf)
		return 0;

	buf = (struct hisi_comp_buf *)(msg->ctx_buf + CTX_STOREBUF_OFFSET);
	if (!buf->pending_out)
		return 0;

	copy_len = copy_to_out(msg, buf, buf->pending_out);
	buf->pending_out -= copy_len;
	msg->produced = copy_len;
	buf->skip_hw = true;

	if (!buf->pending_out) {
		/* All data copied to output */
		buf->output_offset = 0;
		memset(buf->dst, 0, STORE_BUF_SIZE);
		req->status = buf->status == WD_STREAM_END ? WD_STREAM_END : WD_SUCCESS;
	} else {
		/* Still data need to be copied */
		buf->output_offset += copy_len;
		req->status = WD_SUCCESS;
	}

	return 1;
}

static void copy_from_hw(struct wd_comp_msg *msg, struct hisi_comp_buf *buf)
{
	struct wd_comp_req *req = &msg->req;
	__u32 copy_len;

	copy_len = copy_to_out(msg, buf, msg->produced);
	buf->pending_out = msg->produced - copy_len;
	msg->produced = copy_len;

	if (!buf->pending_out) {
		/* All data copied to output */
		buf->output_offset = 0;
		memset(buf->dst, 0, STORE_BUF_SIZE);
	} else {
		/* Still data need to be copied */
		buf->output_offset += copy_len;

		/*
		 * The end flag is cached. It can be output only
		 * after the data is completely copied to the output.
		 */
		if (req->status == WD_STREAM_END) {
			buf->status = WD_STREAM_END;
			req->status = WD_EAGAIN;
		}
	}
}

static int check_enable_store_buf(struct wd_comp_msg *msg, __u32 out_size, int head_size)
{
	if (msg->stream_mode != WD_COMP_STATEFUL)
		return 0;

	if (msg->stream_pos != WD_COMP_STREAM_NEW && out_size > SW_STOREBUF_TH)
		return 0;

	if (msg->stream_pos == WD_COMP_STREAM_NEW &&
	    out_size - head_size > SW_STOREBUF_TH)
		return 0;

	/* 1 mean it need store buf */
	return 1;
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

static int fill_buf_deflate_generic(struct hisi_zip_sqe *sqe,
				    struct wd_comp_msg *msg,
				    const char *head, int head_size)
{
	__u32 in_size = msg->req.src_len;
	__u32 out_size = msg->avail_out;
	struct hisi_comp_buf *buf;
	void *src = msg->req.src;
	void *dst = msg->req.dst;
	void *ctx_buf = NULL;
	int ret;

	/*
	 * When the output buffer is smaller than the SW_STOREBUF_TH in STATEFUL,
	 * the internal buffer is used.
	 */
	ret = check_enable_store_buf(msg, out_size, head_size);
	if (ret) {
		if (!msg->ctx_buf) {
			WD_ERR("ctx_buf is NULL when out_size is less than 200!\n");
			return -WD_EINVAL;
		}

		buf = (struct hisi_comp_buf *)(msg->ctx_buf + CTX_STOREBUF_OFFSET);
		dst = buf->dst;
		out_size = STORE_BUF_SIZE;
		buf->pending_out = STORE_BUF_SIZE;
	}

	if (msg->stream_pos == WD_COMP_STREAM_NEW && head != NULL) {
		if (msg->req.op_type == WD_DIR_COMPRESS) {
			memcpy(dst, head, head_size);
			dst += head_size;
			out_size -= head_size;
		} else {
			src += head_size;
			in_size -= head_size;
		}
	}

	/*
	 * When the output buffer is smaller than the 1.125*input len in STATEFUL compression,
	 * shrink the input len.
	 */
	if (msg->stream_mode == WD_COMP_STATEFUL && msg->req.op_type == WD_DIR_COMPRESS &&
	    (__u64)out_size < min_out_buf_size(in_size)) {
		in_size = max_in_data_size(out_size);
		msg->req.last = 0;
	}

	ret = buf_size_check_deflate(&in_size, &out_size);
	if (unlikely(ret))
		return ret;

	fill_buf_size_deflate(sqe, in_size, out_size);

	if (msg->ctx_buf)
		ctx_buf = msg->ctx_buf + RSV_OFFSET;

	fill_buf_addr_deflate(sqe, src, dst, ctx_buf);

	return 0;
}

static int fill_buf_deflate(handle_t h_qp, struct hisi_zip_sqe *sqe,
			    struct wd_comp_msg *msg)
{
	return fill_buf_deflate_generic(sqe, msg, NULL, 0);
}

static int fill_buf_zlib(handle_t h_qp, struct hisi_zip_sqe *sqe,
			 struct wd_comp_msg *msg)
{
	return fill_buf_deflate_generic(sqe, msg, ZLIB_HEADER, ZLIB_HEADER_SZ);
}

static int fill_buf_gzip(handle_t h_qp, struct hisi_zip_sqe *sqe,
			 struct wd_comp_msg *msg)
{
	return fill_buf_deflate_generic(sqe, msg, GZIP_HEADER, GZIP_HEADER_SZ);
}

static void fill_buf_type_sgl(struct hisi_zip_sqe *sqe)
{
	__u32 val;

	val = sqe->dw9 & HZ_BUF_TYPE_MASK;
	val |= 1 << BUF_TYPE_SHIFT;
	sqe->dw9 = val;
}

static int fill_buf_addr_deflate_sgl(handle_t h_qp, struct hisi_zip_sqe *sqe,
				     struct wd_datalist	*list_src,
				     struct wd_datalist *list_dst)
{
	void *hw_sgl_in, *hw_sgl_out;
	handle_t h_sgl_pool;

	h_sgl_pool = hisi_qm_get_sglpool(h_qp);
	if (unlikely(!h_sgl_pool)) {
		WD_ERR("failed to get sglpool!\n");
		return -WD_EINVAL;
	}

	hw_sgl_in = hisi_qm_get_hw_sgl(h_sgl_pool, list_src);
	if (unlikely(!hw_sgl_in)) {
		WD_ERR("failed to get hw sgl in!\n");
		return -WD_ENOMEM;
	}

	hw_sgl_out = hisi_qm_get_hw_sgl(h_sgl_pool, list_dst);
	if (unlikely(!hw_sgl_out)) {
		WD_ERR("failed to get hw sgl out!\n");
		hisi_qm_put_hw_sgl(h_sgl_pool, hw_sgl_in);
		return -WD_ENOMEM;
	}

	fill_buf_addr_deflate(sqe, hw_sgl_in, hw_sgl_out, NULL);

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

static int fill_buf_deflate_sgl_generic(handle_t h_qp, struct hisi_zip_sqe *sqe,
					struct wd_comp_msg *msg, const char *head,
					int head_size)
{
	struct wd_comp_req *req = &msg->req;
	struct wd_datalist *list_src = req->list_src;
	struct wd_datalist *list_dst = req->list_dst;
	__u32 out_size = msg->avail_out;
	__u32 in_size = req->src_len;
	struct hisi_comp_buf *buf;
	__u32 src_skip = 0;
	__u32 dst_skip = 0;
	int ret;

	/*
	 * When the output buffer is smaller than the SW_STOREBUF_TH in STATEFUL,
	 * the internal buffer is used.
	 */
	ret = check_enable_store_buf(msg, out_size, head_size);
	if (ret) {
		if (!msg->ctx_buf) {
			WD_ERR("ctx_buf is NULL when out_size is less than 200!\n");
			return -WD_EINVAL;
		}

		buf = (struct hisi_comp_buf *)(msg->ctx_buf + CTX_STOREBUF_OFFSET);
		buf->pending_out = STORE_BUF_SIZE;
		buf->list_dst.data = buf->dst;
		buf->list_dst.len = STORE_BUF_SIZE;
		list_dst = &buf->list_dst;
		out_size = STORE_BUF_SIZE;
	}

	fill_buf_type_sgl(sqe);

	ret = fill_buf_addr_deflate_sgl(h_qp, sqe, list_src, list_dst);
	if (unlikely(ret))
		return ret;

	if (head != NULL && msg->req.op_type == WD_DIR_COMPRESS) {
		memcpy(req->list_dst->data, head, head_size);
		dst_skip = head_size;
		out_size -= head_size;
	} else if (head != NULL && msg->req.op_type == WD_DIR_DECOMPRESS) {
		src_skip = head_size;
		in_size -= head_size;
	}

	/*
	 * When the output buffer is smaller than the 1.125*input len in STATEFUL compression,
	 * shrink the input len.
	 */
	if (msg->stream_mode == WD_COMP_STATEFUL && msg->req.op_type == WD_DIR_COMPRESS &&
	    (__u64)out_size < min_out_buf_size(in_size)) {
		in_size = max_in_data_size(out_size);
		msg->req.last = 0;
	}

	fill_buf_sgl_skip(sqe, src_skip, dst_skip);

	fill_buf_size_deflate(sqe, in_size, out_size);

	return 0;
}

static int fill_buf_deflate_sgl(handle_t h_qp, struct hisi_zip_sqe *sqe,
				struct wd_comp_msg *msg)
{
	return fill_buf_deflate_sgl_generic(h_qp, sqe, msg, NULL, 0);
}

static int fill_buf_zlib_sgl(handle_t h_qp, struct hisi_zip_sqe *sqe,
			     struct wd_comp_msg *msg)
{
	return fill_buf_deflate_sgl_generic(h_qp, sqe, msg, ZLIB_HEADER, ZLIB_HEADER_SZ);
}

static int fill_buf_gzip_sgl(handle_t h_qp, struct hisi_zip_sqe *sqe,
			     struct wd_comp_msg *msg)
{
	return fill_buf_deflate_sgl_generic(h_qp, sqe, msg, GZIP_HEADER, GZIP_HEADER_SZ);
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
	__u32 lits_size = in_size + ZSTD_LIT_RESV_SIZE;
	__u32 out_size = msg->avail_out;
	void *ctx_buf = NULL;

	if (unlikely(!data)) {
		WD_ERR("invalid: wd_lz77_zstd_data address is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(in_size > ZSTD_MAX_SIZE)) {
		WD_ERR("invalid: in_len(%u) of lz77_zstd is out of range!\n",
		       in_size);
		return -WD_EINVAL;
	}

	if (unlikely(out_size > HZ_MAX_SIZE)) {
		WD_ERR("warning: avail_out(%u) is out of range , will set 8MB size max!\n",
		       out_size);
		out_size = HZ_MAX_SIZE;
	}

	/*
	 * For lz77_zstd, the hardware needs 784 Bytes buffer to output
	 * the frequency information about input data.
	 */
	if (unlikely(out_size < ZSTD_FREQ_DATA_SIZE + lits_size)) {
		WD_ERR("invalid: output is not enough, %u bytes are minimum!\n",
		       ZSTD_FREQ_DATA_SIZE + lits_size);
		return -WD_EINVAL;
	}

	if (msg->ctx_buf) {
		ctx_buf = msg->ctx_buf + RSV_OFFSET;
		if (data->blk_type != COMP_BLK)
			memcpy(ctx_buf + CTX_HW_REPCODE_OFFSET,
			       msg->ctx_buf + CTX_REPCODE2_OFFSET, REPCODE_SIZE);
	}

	fill_buf_size_lz77_zstd(sqe, in_size, lits_size, out_size - lits_size);

	fill_buf_addr_lz77_zstd(sqe, req->src, req->dst, req->dst + lits_size, ctx_buf);

	data->literals_start = req->dst;
	data->sequences_start = req->dst + lits_size;

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
		WD_ERR("invalid: in_len(%u) of lz77_zstd is out of range!\n",
		       in_size);
		return -WD_EINVAL;
	}

	if (unlikely(!data)) {
		WD_ERR("invalid: wd_lz77_zstd_data address is NULL!\n");
		return -WD_EINVAL;
	}

	fill_buf_type_sgl(sqe);

	seq_start = get_seq_start_list(req);
	if (unlikely(!seq_start))
		return -WD_EINVAL;

	data->literals_start = req->list_dst;
	data->sequences_start = seq_start;

	/*
	 * For lz77_zstd, the hardware needs 784 Bytes buffer to output
	 * the frequency information about input data. The sequences
	 * and frequency data need to be written to an independent sgl
	 * splited from list_dst.
	 */
	lits_size = hisi_qm_get_list_size(req->list_dst, seq_start);
	if (unlikely(lits_size < in_size + ZSTD_LIT_RESV_SIZE)) {
		WD_ERR("invalid: output is not enough for literals, %u bytes are minimum!\n",
		       ZSTD_FREQ_DATA_SIZE + lits_size);
		return -WD_EINVAL;
	} else if (unlikely(out_size < ZSTD_FREQ_DATA_SIZE + lits_size)) {
		WD_ERR("invalid: output is not enough for sequences, at least %u bytes more!\n",
		       ZSTD_FREQ_DATA_SIZE + lits_size - out_size);
		return -WD_EINVAL;
	}

	fill_buf_size_lz77_zstd(sqe, in_size, lits_size, out_size - lits_size);

	h_sgl_pool = hisi_qm_get_sglpool(h_qp);
	if (unlikely(!h_sgl_pool)) {
		WD_ERR("failed to get sglpool!\n");
		return -WD_EINVAL;
	}

	hw_sgl_in = hisi_qm_get_hw_sgl(h_sgl_pool, req->list_src);
	if (unlikely(!hw_sgl_in)) {
		WD_ERR("failed to get hw sgl in!\n");
		return -WD_ENOMEM;
	}

	hw_sgl_out_lit = hisi_qm_get_hw_sgl(h_sgl_pool, req->list_dst);
	if (unlikely(!hw_sgl_out_lit)) {
		WD_ERR("failed to get hw sgl out for literals!\n");
		ret = -WD_ENOMEM;
		goto err_free_sgl_in;
	}

	hw_sgl_out_seq = hisi_qm_get_hw_sgl(h_sgl_pool, seq_start);
	if (unlikely(!hw_sgl_out_seq)) {
		WD_ERR("failed to get hw sgl out for sequences!\n");
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
	/*
	 * L8 indicates that the price mode is disabled.
	 * By default, the price mode is disabled.
	 */
		break;
	case WD_COMP_L9:
		val = sqe->dw9 & ~HZ_REQ_TYPE_MASK;
		val |= HW_LZ77_ZSTD_PRICE;
		sqe->dw9 = val;
		break;
	default:
		WD_ERR("invalid: comp_lv(%u) is unsupport!\n", comp_lv);
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

	if (unlikely(!data))
		return;

	data->lit_num = sqe->comp_data_length;
	data->seq_num = sqe->produced;
	data->lit_length_overflow_cnt = sqe->dw31 >> LITLEN_OVERFLOW_CNT_SHIFT;
	data->lit_length_overflow_pos = sqe->dw31 & LITLEN_OVERFLOW_POS_MASK;
	data->freq = data->sequences_start + (data->seq_num << SEQ_DATA_SIZE_SHIFT) +
		     OVERFLOW_DATA_SIZE;

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

static int hisi_zip_init(struct wd_alg_driver *drv, void *conf)
{
	struct wd_ctx_config_internal *config = conf;
	struct hisi_qm_priv qm_priv;
	struct hisi_zip_ctx *priv;
	handle_t h_qp = 0;
	handle_t h_ctx;
	__u32 i, j;

	if (!config->ctx_num) {
		WD_ERR("invalid: zip init config ctx num is 0!\n");
		return -WD_EINVAL;
	}

	priv = malloc(sizeof(struct hisi_zip_ctx));
	if (!priv)
		return -WD_EINVAL;

	memcpy(&priv->config, config, sizeof(struct wd_ctx_config_internal));
	/* allocate qp for each context */
	for (i = 0; i < config->ctx_num; i++) {
		h_ctx = config->ctxs[i].ctx;
		qm_priv.sqe_size = sizeof(struct hisi_zip_sqe);
		qm_priv.op_type = config->ctxs[i].op_type;
		qm_priv.qp_mode = config->ctxs[i].ctx_mode;
		/* Setting the epoll en to 0 for ASYNC ctx */
		qm_priv.epoll_en = (qm_priv.qp_mode == CTX_MODE_SYNC) ?
				   config->epoll_en : 0;
		qm_priv.idx = i;
		h_qp = hisi_qm_alloc_qp(&qm_priv, h_ctx);
		if (unlikely(!h_qp))
			goto out;
		config->ctxs[i].sqn = qm_priv.sqn;
	}

	hisi_zip_sqe_ops_adapt(h_qp);
	drv->priv = priv;

	return 0;
out:
	for (j = 0; j < i; j++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[j].ctx);
		hisi_qm_free_qp(h_qp);
	}
	free(priv);
	return -WD_EINVAL;
}

static void hisi_zip_exit(struct wd_alg_driver *drv)
{
	struct wd_ctx_config_internal *config;
	struct hisi_zip_ctx *priv;
	handle_t h_qp;
	__u32 i;

	if (!drv || !drv->priv)
		return;

	priv = (struct hisi_zip_ctx *)drv->priv;
	config = &priv->config;
	for (i = 0; i < config->ctx_num; i++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[i].ctx);
		hisi_qm_free_qp(h_qp);
	}
	free(priv);
	drv->priv = NULL;
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

	if (unlikely((hw_type <= HISI_QM_API_VER2_BASE && alg_type > WD_GZIP) ||
		     (hw_type >= HISI_QM_API_VER3_BASE && alg_type >= WD_COMP_ALG_MAX))) {
		WD_ERR("invalid: algorithm type is %u!\n", alg_type);
		return -WD_EINVAL;
	}

	ret = ops[alg_type].fill_comp_level(sqe, msg->comp_lv);
	if (unlikely(ret))
		return ret;

	ret = ops[alg_type].fill_buf[msg->req.data_fmt]((handle_t)qp, sqe, msg);
	if (unlikely(ret))
		return ret;

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

static void free_hw_sgl(handle_t h_qp, struct hisi_zip_sqe *sqe,
			enum wd_comp_alg_type alg_type)
{
	void *hw_sgl_in, *hw_sgl_out;
	handle_t h_sgl_pool;

	h_sgl_pool = hisi_qm_get_sglpool(h_qp);
	if (unlikely(!h_sgl_pool)) {
		WD_ERR("failed to get sglpool to free hw sgl!\n");
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

static int hisi_zip_comp_send(struct wd_alg_driver *drv, handle_t ctx, void *comp_msg)
{
	struct hisi_qp *qp = wd_ctx_get_priv(ctx);
	struct wd_comp_msg *msg = comp_msg;
	handle_t h_qp = (handle_t)qp;
	struct hisi_zip_sqe sqe = {0};
	__u16 count = 0;
	int ret;

	/* Skip hardware, if the store buffer need to be copied to output */
	ret = check_store_buf(msg);
	if (ret)
		return ret < 0 ? ret : 0;

	hisi_set_msg_id(h_qp, &msg->tag);
	ret = fill_zip_comp_sqe(qp, msg, &sqe);
	if (unlikely(ret < 0)) {
		WD_ERR("failed to fill zip sqe, ret = %d!\n", ret);
		return ret;
	}
	ret = hisi_qm_send(h_qp, &sqe, 1, &count);
	if (unlikely(ret < 0)) {
		if (msg->req.data_fmt == WD_SGL_BUF)
			free_hw_sgl(h_qp, &sqe, msg->alg_type);
		if (ret != -WD_EBUSY)
			WD_ERR("failed to send to hardware, ret = %d!\n", ret);

		return ret;
	}

	return 0;
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

static void get_ctx_buf(struct hisi_zip_sqe *sqe,
			 struct wd_comp_msg *recv_msg)
{
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
}

static int parse_zip_sqe(struct hisi_qp *qp, struct hisi_zip_sqe *sqe,
			 struct wd_comp_msg *msg)
{
	__u32 buf_type = (sqe->dw9 & HZ_BUF_TYPE_MASK) >> BUF_TYPE_SHIFT;
	__u32 ctx_win_len = sqe->ctx_dw2 & CTX_WIN_LEN_MASK;
	__u16 ctx_st = sqe->ctx_dw0 & HZ_CTX_ST_MASK;
	__u16 lstblk = sqe->dw3 & HZ_LSTBLK_MASK;
	__u32 status = sqe->dw3 & HZ_STATUS_MASK;
	__u32 type = sqe->dw9 & HZ_REQ_TYPE_MASK;
	struct wd_comp_msg *recv_msg = msg;
	bool need_debug = wd_need_debug();
	__u32 bit_cnt, tag;
	int alg_type, ret;
	void *cache_data;

	alg_type = get_alg_type(type);
	if (unlikely(alg_type < 0)) {
		WD_ERR("invalid: hardware type is %u!\n", type);
		return -WD_EINVAL;
	}

	tag = ops[alg_type].get_tag(sqe);
	ret = hisi_check_bd_id((handle_t)qp, recv_msg->tag, tag);
	if (ret)
		return ret;

	recv_msg->tag = tag;

	if (qp->q_info.qp_mode == CTX_MODE_ASYNC) {
		recv_msg = wd_comp_get_msg(qp->q_info.idx, tag);
		if (unlikely(!recv_msg)) {
			WD_ERR("failed to get send msg! idx = %u, tag = %u!\n",
			       qp->q_info.idx, tag);
			return -WD_EINVAL;
		}
	}

	recv_msg->req.status = 0;

	if (unlikely(status != 0 && status != HZ_NEGACOMPRESS &&
		     status != HZ_CRC_ERR && status != HZ_DECOMP_END)) {
		if (status == ERR_DSTLEN_OUT)
			WD_DEBUG("bad request(ctx_st=0x%x, status=0x%x, algorithm type=%u)!\n",
				ctx_st, status, type);
		else
			WD_ERR("bad request(ctx_st=0x%x, status=0x%x, algorithm type=%u)!\n",
				ctx_st, status, type);
		recv_msg->req.status = WD_IN_EPARA;
	}

	ops[alg_type].get_data_size(sqe, qp->q_info.qc_type, recv_msg);

	get_ctx_buf(sqe, recv_msg);

	/* last block no space, need resend null size req */
	if (ctx_st == HZ_DECOMP_NO_SPACE)
		recv_msg->req.status = WD_EAGAIN;

	/*
	 * It need to analysis the data cache by hardware.
	 * If the cache data is a complete huffman block,
	 * the drv send WD_EAGAIN to user to continue
	 * sending a request for clearing the cache.
	 */
	bit_cnt = (sqe->ctx_dw0 & CTX_HEAD_BIT_CNT_MASK) >> CTX_HEAD_BIT_CNT_SHIFT;
	if (!recv_msg->req.status && bit_cnt && ctx_st == HZ_DECOMP_BLK_NOSTART &&
	    recv_msg->alg_type == WD_DEFLATE) {
		/* ctx_win_len need to aligned with 16 */
		ctx_win_len = WIN_LEN_ALIGN(ctx_win_len);
		cache_data = recv_msg->ctx_buf + RSV_OFFSET + CTX_BLOCKST_OFFSET + ctx_win_len;
		ret = check_bfinal_complete_block(cache_data, bit_cnt);
		if (ret < 0) {
			WD_ERR("invalid: unable to parse data!\n");
			recv_msg->req.status = WD_IN_EPARA;
		} else if (ret) {
			recv_msg->req.status = WD_EAGAIN;
		}
	}

	if (need_debug)
		WD_DEBUG("zip recv lst =%hu, ctx_st=0x%x, status=0x%x, alg=%u!\n",
		 lstblk, ctx_st, status, type);
	if (lstblk && (status == HZ_DECOMP_END))
		recv_msg->req.status = WD_STREAM_END;

	recv_msg->isize = sqe->isize;
	recv_msg->checksum = sqe->dw31;
	recv_msg->alg_type = alg_type;

	if (buf_type == WD_SGL_BUF)
		free_hw_sgl((handle_t)qp, sqe, alg_type);

	if (unlikely(recv_msg->req.status == WD_IN_EPARA))
		dump_zip_msg(recv_msg);

	return 0;
}

static int hisi_zip_comp_recv(struct wd_alg_driver *drv, handle_t ctx, void *comp_msg)
{
	struct hisi_qp *qp = wd_ctx_get_priv(ctx);
	struct wd_comp_msg *recv_msg = comp_msg;
	struct hisi_comp_buf *buf = NULL;
	handle_t h_qp = (handle_t)qp;
	struct hisi_zip_sqe sqe = {0};
	__u16 count = 0;
	int ret;

	if (recv_msg && recv_msg->ctx_buf) {
		buf = (struct hisi_comp_buf *)(recv_msg->ctx_buf + CTX_STOREBUF_OFFSET);
		/*
		 * The output has been copied from the storage buffer,
		 * and no data need to be received.
		 */
		if (buf->skip_hw) {
			buf->skip_hw = false;
			return 0;
		}
	}

	ret = hisi_qm_recv(h_qp, &sqe, 1, &count);
	if (unlikely(ret < 0))
		return ret;

	ret = parse_zip_sqe(qp, &sqe, recv_msg);
	if (unlikely(ret < 0 || recv_msg->req.status == WD_IN_EPARA))
		return ret;

	/* There are data in buf, copy to output */
	if (buf && buf->pending_out)
		copy_from_hw(recv_msg, buf);

	return 0;
}

#define GEN_ZIP_ALG_DRIVER(zip_alg_name) \
{\
	.drv_name = "hisi_zip",\
	.alg_name = (zip_alg_name),\
	.calc_type = UADK_ALG_HW,\
	.priority = 100,\
	.queue_num = ZIP_CTX_Q_NUM_DEF,\
	.op_type_num = 2,\
	.fallback = 0,\
	.init = hisi_zip_init,\
	.exit = hisi_zip_exit,\
	.send = hisi_zip_comp_send,\
	.recv = hisi_zip_comp_recv,\
}

static struct wd_alg_driver zip_alg_driver[] = {
	GEN_ZIP_ALG_DRIVER("zlib"),
	GEN_ZIP_ALG_DRIVER("gzip"),

	GEN_ZIP_ALG_DRIVER("deflate"),
	GEN_ZIP_ALG_DRIVER("lz77_zstd"),
};

#ifdef WD_STATIC_DRV
void hisi_zip_probe(void)
#else
static void __attribute__((constructor)) hisi_zip_probe(void)
#endif
{
	int alg_num = ARRAY_SIZE(zip_alg_driver);
	int i, ret;

	WD_INFO("Info: register ZIP alg drivers!\n");

	for (i = 0; i < alg_num; i++) {
		ret = wd_alg_driver_register(&zip_alg_driver[i]);
		if (ret && ret != -WD_ENODEV)
			WD_ERR("Error: register ZIP %s failed!\n",
				zip_alg_driver[i].alg_name);
	}
}

#ifdef WD_STATIC_DRV
void hisi_zip_remove(void)
#else
static void __attribute__((destructor)) hisi_zip_remove(void)
#endif
{
	int alg_num = ARRAY_SIZE(zip_alg_driver);
	int i;

	WD_INFO("Info: unregister ZIP alg drivers!\n");
	for (i = 0; i < alg_num; i++)
		wd_alg_driver_unregister(&zip_alg_driver[i]);
}
