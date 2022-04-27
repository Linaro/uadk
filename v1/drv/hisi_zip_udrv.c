/*
 * Copyright 2019 Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include "config.h"
#include "v1/wd_util.h"
#include "v1/wd_comp.h"
#include "v1/wd_cipher.h"
#include "v1/drv/hisi_zip_udrv.h"
#include "v1/wd_sgl.h"

#define BD_TYPE_SHIFT			28
#define STREAM_FLUSH_SHIFT		25
#define STREAM_POS_SHIFT		2
#define STREAM_MODE_SHIFT		1
#define WINDOWS_SIZE_SHIFT		12
#define SEQUENCE_SZIE			8

#define HW_NEGACOMPRESS			0x0d
#define HW_CRC_ERR			0x10
#define HW_DECOMP_END			0x13
#define HW_IN_DATA_DIF_CHECK_ERR	0xf
#define HW_UNCOMP_DIF_CHECK_ERR		0x12

#define HW_DECOMP_NO_SPACE		0x01
#define HW_DECOMP_BLK_NOSTART		0x03
#define HW_DECOMP_NO_CRC		0x04
#define ZIP_DIF_LEN			8
#define ZIP_PAD_LEN			56
#define MAX_BUFFER_SIZE			0x800000
#define MAX_ZSTD_INPUT_SIZE		0x20000
#define ZSTD_LIT_RSV_SIZE		16
#define ZSTD_FREQ_DATA_SIZE		784
#define REPCODE_SIZE			12

#define CTX_PRIV1_OFFSET		4
#define CTX_PRIV2_OFFSET		8
#define CTX_REPCODE1_OFFSET		12
#define CTX_REPCODE2_OFFSET		24
#define CTX_BUFFER_OFFSET		64
#define CTX_HW_REPCODE_OFFSET		784

#define get_arrsize(arr)		(sizeof(arr) / sizeof(arr[0]))
#define lower_32_bits(phy)		((__u32)((__u64)(phy)))
#define upper_32_bits(phy)		((__u32)((__u64)(phy) >> QM_HADDR_SHIFT))

enum {
	BD_TYPE,
	BD_TYPE3 = 3,
};

enum lz77_compress_status {
	UNCOMP_BLK,
	RLE_BLK,
	COMP_BLK,
};

struct hisi_zip_sqe_addr {
	uintptr_t source_addr;
	uintptr_t dest_addr;
	uintptr_t ctxbuf_addr;
};

struct zip_fill_sqe_ops {
	const char *alg_type;
	int (*fill_sqe_alg)(void *ssqe, struct wcrypto_comp_msg *msg);
	int (*fill_sqe_buffer_size)(void *ssqe, struct wcrypto_comp_msg *msg);
	int (*fill_sqe_window_size)(void *ssqe, struct wcrypto_comp_msg *msg);
	int (*fill_sqe_addr)(void *ssqe, struct wcrypto_comp_msg *msg,
			     struct wd_queue *q);
	void (*fill_sqe_hw_info)(void *ssqe, struct wcrypto_comp_msg *msg);
};

static int fill_zip_comp_alg_v1(struct hisi_zip_sqe *sqe,
				struct wcrypto_comp_msg *msg)
{
	switch (msg->alg_type) {
	case WCRYPTO_ZLIB:
		sqe->dw9 = HW_ZLIB;
		break;
	case WCRYPTO_GZIP:
		sqe->dw9 = HW_GZIP;
		break;
	default:
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int qm_fill_zip_sqe_get_phy_addr(struct hisi_zip_sqe_addr *addr,
					struct wcrypto_comp_msg *msg,
					struct wd_queue *q, bool is_lz77)
{
	uintptr_t phy_ctxbuf = 0;
	uintptr_t phy_out = 0;
	uintptr_t phy_in;

	phy_in = (uintptr_t)drv_iova_map(q, msg->src, msg->in_size);
	if (!phy_in) {
		WD_ERR("Get zip in buf dma address fail!\n");
		return -WD_ENOMEM;
	}
	if (!(is_lz77 && msg->data_fmt == WD_SGL_BUF)) {
		phy_out = (uintptr_t)drv_iova_map(q, msg->dst, msg->avail_out);
		if (!phy_out) {
			WD_ERR("Get zip out buf dma address fail!\n");
			goto unmap_phy_in;
		}
	}

	if (msg->stream_mode == WCRYPTO_COMP_STATEFUL) {
		phy_ctxbuf = (uintptr_t)drv_iova_map(q, msg->ctx_buf,
						     MAX_CTX_RSV_SIZE);
		if (!phy_ctxbuf) {
			WD_ERR("Get zip ctx buf dma address fail!\n");
			goto unmap_phy_out;
		}
	}

	addr->source_addr = phy_in;
	addr->dest_addr = phy_out;
	addr->ctxbuf_addr = phy_ctxbuf + CTX_BUFFER_OFFSET;

	return WD_SUCCESS;

unmap_phy_out:
	if (!(is_lz77 && msg->data_fmt == WD_SGL_BUF))
		drv_iova_unmap(q, msg->dst, (void *)phy_out, msg->avail_out);
unmap_phy_in:
	drv_iova_unmap(q, msg->src, (void *)phy_in, msg->in_size);

	return -WD_ENOMEM;
}

int qm_fill_zip_sqe(void *smsg, struct qm_queue_info *info, __u16 i)
{
	struct hisi_zip_sqe *sqe = (struct hisi_zip_sqe *)info->sq_base + i;
	struct wcrypto_comp_msg *msg = smsg;
	struct wcrypto_comp_tag *tag = (void *)(uintptr_t)msg->udata;
	struct hisi_zip_sqe_addr addr = {0};
	struct wd_queue *q = info->q;
	__u8 flush_type;
	__u8 data_fmt;
	int ret;

	memset((void *)sqe, 0, sizeof(*sqe));

	ret = fill_zip_comp_alg_v1(sqe, msg);
	if (ret) {
		WD_ERR("The algorithm is invalid!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->data_fmt != WD_SGL_BUF &&
		     msg->in_size > MAX_BUFFER_SIZE)) {
		WD_ERR("The in_len is out of range in_len(%u)!\n", msg->in_size);
		return -WD_EINVAL;
	}
	if (unlikely(msg->data_fmt != WD_SGL_BUF &&
		     msg->avail_out > MAX_BUFFER_SIZE)) {
		WD_ERR("warning: avail_out is out of range (%u), will set 8MB size max!\n",
		       msg->avail_out);
		msg->avail_out = MAX_BUFFER_SIZE;
	}
	sqe->input_data_length = msg->in_size;
	sqe->dest_avail_out = msg->avail_out;

	ret = qm_fill_zip_sqe_get_phy_addr(&addr, msg, q, false);
	if (ret)
		return ret;

	sqe->source_addr_l = lower_32_bits((__u64)addr.source_addr);
	sqe->source_addr_h = upper_32_bits((__u64)addr.source_addr);
	sqe->dest_addr_l = lower_32_bits((__u64)addr.dest_addr);
	sqe->dest_addr_h = upper_32_bits((__u64)addr.dest_addr);
	sqe->stream_ctx_addr_l = lower_32_bits((__u64)addr.ctxbuf_addr);
	sqe->stream_ctx_addr_h = upper_32_bits((__u64)addr.ctxbuf_addr);

	flush_type = (msg->flush_type == WCRYPTO_FINISH) ? HZ_FINISH :
		      HZ_SYNC_FLUSH;
	sqe->dw7 |= ((msg->stream_pos << STREAM_POS_SHIFT) |
		     (msg->stream_mode << STREAM_MODE_SHIFT) |
		     (flush_type)) << STREAM_FLUSH_SHIFT;

	/* data_fmt: 4'b0000 - Pbuffer, 4'b0001 - SGL */
	data_fmt = (msg->data_fmt == WD_SGL_BUF) ? HISI_SGL_BUF : HISI_FLAT_BUF;
	sqe->dw9 |= data_fmt << HZ_BUF_TYPE_SHIFT;

	if (msg->ctx_buf) {
		sqe->ctx_dw0 = *(__u32 *)msg->ctx_buf;
		sqe->ctx_dw1 = *(__u32 *)(msg->ctx_buf + CTX_PRIV1_OFFSET);
		sqe->ctx_dw2 = *(__u32 *)(msg->ctx_buf + CTX_PRIV2_OFFSET);
	}
	sqe->isize = msg->isize;
	sqe->checksum = msg->checksum;
	sqe->tag = msg->tag;
	if (tag && info->sqe_fill_priv)
		info->sqe_fill_priv(sqe, WCRYPTO_COMP, tag->priv);

	info->req_cache[i] = msg;

	return WD_SUCCESS;
}

static void qm_parse_zip_sqe_set_status(struct wcrypto_comp_msg *recv_msg,
				__u32 status, __u16 lstblk, __u16 ctx_st)
{
	if ((status == HW_DECOMP_END) && lstblk)
		recv_msg->status = WCRYPTO_DECOMP_END;
	else if (status == HW_CRC_ERR) /* deflate type no crc, do normal */
		recv_msg->status = WD_VERIFY_ERR;
	else if (status == HW_IN_DATA_DIF_CHECK_ERR)
		recv_msg->status = WCRYPTO_SRC_DIF_ERR;
	else if (status == HW_UNCOMP_DIF_CHECK_ERR)
		recv_msg->status = WCRYPTO_DST_DIF_ERR;
	else if (status == HW_NEGACOMPRESS)
		recv_msg->status = WCRYPTO_NEGTIVE_COMP_ERR;

	/* deflate type no crc, need return status */
	if (ctx_st == HW_DECOMP_NO_CRC)
		recv_msg->status = WCRYPTO_DECOMP_NO_CRC;
	/* last block no space, need resend null size req */
	else if (ctx_st == HW_DECOMP_NO_SPACE)
		recv_msg->status = WCRYPTO_DECOMP_END_NOSPACE;
	else if (ctx_st == HW_DECOMP_BLK_NOSTART && lstblk)
		recv_msg->status = WCRYPTO_DECOMP_BLK_NOSTART;
}

int qm_parse_zip_sqe(void *hw_msg, const struct qm_queue_info *info,
		     __u16 i, __u16 usr)
{
	struct wcrypto_comp_msg *recv_msg = info->req_cache[i];
	struct hisi_zip_sqe *sqe = hw_msg;
	__u16 ctx_st = sqe->ctx_dw0 & HZ_CTX_ST_MASK;
	__u16 lstblk = sqe->dw3 & HZ_LSTBLK_MASK;
	__u32 status = sqe->dw3 & HZ_STATUS_MASK;
	__u32 type = sqe->dw9 & HZ_REQ_TYPE_MASK;
	uintptr_t phy_in, phy_out, phy_ctxbuf;
	struct wd_queue *q = info->q;

	if (unlikely(!recv_msg)) {
		WD_ERR("info->req_cache is null at index:%hu\n", i);
		return 0;
	}

	if (usr && sqe->tag != usr)
		return 0;

	if (status != 0 && status != HW_NEGACOMPRESS &&
	    status != HW_CRC_ERR && status != HW_DECOMP_END) {
		WD_ERR("bad status(ctx_st=0x%x, s=0x%x, t=%u)\n",
		       ctx_st, status, type);
		recv_msg->status = WD_IN_EPARA;
	} else {
		recv_msg->status = 0;
	}
	recv_msg->in_cons = sqe->consumed;
	recv_msg->produced = sqe->produced;
	if (recv_msg->ctx_buf) {
		*(__u32 *)recv_msg->ctx_buf = sqe->ctx_dw0;
		*(__u32 *)(recv_msg->ctx_buf + CTX_PRIV1_OFFSET) = sqe->ctx_dw1;
		*(__u32 *)(recv_msg->ctx_buf + CTX_PRIV2_OFFSET) = sqe->ctx_dw2;
	}
	recv_msg->isize = sqe->isize;
	recv_msg->checksum = sqe->checksum;

	phy_in = DMA_ADDR(sqe->source_addr_h, sqe->source_addr_l);
	drv_iova_unmap(q, recv_msg->src, (void *)phy_in, recv_msg->in_size);
	phy_out = DMA_ADDR(sqe->dest_addr_h, sqe->dest_addr_l);
	drv_iova_unmap(q, recv_msg->dst, (void *)phy_out, recv_msg->avail_out);
	if (recv_msg->ctx_buf) {
		phy_ctxbuf = DMA_ADDR(sqe->stream_ctx_addr_h,
				      sqe->stream_ctx_addr_l);
		drv_iova_unmap(q, recv_msg->ctx_buf, (void *)phy_ctxbuf,
			       MAX_CTX_RSV_SIZE);
	}

	qm_parse_zip_sqe_set_status(recv_msg, status, lstblk, ctx_st);

	return 1;
}

static int fill_zip_comp_alg_deflate(void *ssqe, struct wcrypto_comp_msg *msg)
{
	struct hisi_zip_sqe_v3 *sqe = ssqe;

	switch (msg->alg_type) {
	case WCRYPTO_ZLIB:
		sqe->dw9 = HW_ZLIB;
		break;
	case WCRYPTO_GZIP:
		sqe->dw9 = HW_GZIP;
		break;
	case WCRYPTO_RAW_DEFLATE:
		sqe->dw9 = HW_RAW_DEFLATE;
		break;
	default:
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int fill_zip_comp_alg_zstd(void *ssqe, struct wcrypto_comp_msg *msg)
{
	struct hisi_zip_sqe_v3 *sqe = ssqe;

	if (msg->comp_lv == WCRYPTO_COMP_L9) {
		sqe->dw9 = HW_LZ77_ZSTD_PRICE;
	} else if (msg->comp_lv == WCRYPTO_COMP_L8 || msg->comp_lv == 0) {
		sqe->dw9 = HW_LZ77_ZSTD;
	} else {
		WD_ERR("The compress level is invalid!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int fill_zip_buffer_size_deflate(void *ssqe, struct wcrypto_comp_msg *msg)
{
	struct hisi_zip_sqe_v3 *sqe = ssqe;

	if (unlikely(msg->data_fmt != WD_SGL_BUF &&
		     msg->in_size > MAX_BUFFER_SIZE)) {
		WD_ERR("The in_len is out of range in_len(%u)!\n", msg->in_size);
		return -WD_EINVAL;
	}

	if (unlikely(msg->data_fmt != WD_SGL_BUF &&
		     msg->avail_out > MAX_BUFFER_SIZE)) {
		WD_ERR("warning: avail_out is out of range (%u), will set 8MB size max!\n",
		       msg->avail_out);
		msg->avail_out = MAX_BUFFER_SIZE;
	}

	sqe->input_data_length = msg->in_size;
	sqe->dest_avail_out = msg->avail_out;

	return WD_SUCCESS;
}

static int fill_zip_buffer_size_zstd(void *ssqe, struct wcrypto_comp_msg *msg)
{
	__u32 lit_size = msg->in_size + ZSTD_LIT_RSV_SIZE;
	struct hisi_zip_sqe_v3 *sqe = ssqe;
	struct wcrypto_zstd_out *zstd_out;

	if (unlikely(msg->in_size > MAX_ZSTD_INPUT_SIZE)) {
		WD_ERR("The in_len is out of range in_len(%u)!\n", msg->in_size);
		return -WD_EINVAL;
	}

	if (msg->data_fmt == WD_SGL_BUF) {
		zstd_out = (void *)msg->dst;

		if (unlikely(zstd_out->lit_sz < lit_size ||
			     zstd_out->seq_sz < ZSTD_FREQ_DATA_SIZE )) {
			WD_ERR("literal(%u) or sequence(%u) of lz77_zstd is not enough.\n",
			       zstd_out->lit_sz, zstd_out->seq_sz);
			return -WD_EINVAL;
		}
		sqe->dw13 = zstd_out->lit_sz;
		/* fill the sequences output size */
		sqe->dest_avail_out = zstd_out->seq_sz;
	} else {
		if (unlikely(msg->avail_out > MAX_BUFFER_SIZE)) {
			WD_ERR("warning: avail_out is out of range (%u), will set 8MB size max!\n",
			       msg->avail_out);
			msg->avail_out = MAX_BUFFER_SIZE;
		}

		/*
		 * For lz77_zstd, the hardware need 784 Bytes buffer to output
		 * the frequency information about input data.
		 */
		if (unlikely(msg->avail_out < ZSTD_FREQ_DATA_SIZE + lit_size)) {
			WD_ERR("output buffer size of lz77_zstd is not enough(%u)\n",
			       ZSTD_FREQ_DATA_SIZE + lit_size);
			return -WD_EINVAL;
		}
		/* fill the literals output size */
		sqe->dw13 = lit_size;
		/* fill the sequences output size */
		sqe->dest_avail_out = msg->avail_out - lit_size;
	}
	sqe->input_data_length = msg->in_size;

	return WD_SUCCESS;
}

static int fill_zip_window_size(void *ssqe, struct wcrypto_comp_msg *msg)
{
	struct hisi_zip_sqe_v3 *sqe = ssqe;

	if (msg->op_type == WCRYPTO_INFLATE)
		return WD_SUCCESS;

	switch (msg->win_size) {
	case WCRYPTO_COMP_WS_4K:
	case WCRYPTO_COMP_WS_8K:
	case WCRYPTO_COMP_WS_16K:
	case WCRYPTO_COMP_WS_24K:
	case WCRYPTO_COMP_WS_32K:
		sqe->dw9 |= msg->win_size << WINDOWS_SIZE_SHIFT;
		break;
	default:
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int fill_zip_addr_deflate(void *ssqe,
				 struct wcrypto_comp_msg *msg,
				 struct wd_queue *q)
{
	struct hisi_zip_sqe_v3 *sqe = ssqe;
	struct hisi_zip_sqe_addr addr = {0};
	int ret;

	ret = qm_fill_zip_sqe_get_phy_addr(&addr, msg, q, false);
	if (ret)
		return ret;

	sqe->source_addr_l = lower_32_bits((__u64)addr.source_addr);
	sqe->source_addr_h = upper_32_bits((__u64)addr.source_addr);
	sqe->dest_addr_l = lower_32_bits((__u64)addr.dest_addr);
	sqe->dest_addr_h = upper_32_bits((__u64)addr.dest_addr);
	sqe->stream_ctx_addr_l = lower_32_bits((__u64)addr.ctxbuf_addr);
	sqe->stream_ctx_addr_h = upper_32_bits((__u64)addr.ctxbuf_addr);

	return WD_SUCCESS;
}

static int fill_zip_addr_lz77_zstd(void *ssqe,
				   struct wcrypto_comp_msg *msg,
				   struct wd_queue *q)
{
	struct hisi_zip_sqe_addr addr = {0};
	struct hisi_zip_sqe_v3 *sqe = ssqe;
	struct wcrypto_zstd_out *zstd_out;
	uintptr_t phy_lit, phy_seq;
	int ret;

	ret = qm_fill_zip_sqe_get_phy_addr(&addr, msg, q, true);
	if (ret)
		return ret;

	sqe->source_addr_l = lower_32_bits((__u64)addr.source_addr);
	sqe->source_addr_h = upper_32_bits((__u64)addr.source_addr);
	if (msg->data_fmt == WD_SGL_BUF) {
		zstd_out = (void *)msg->dst;
		phy_lit = (uintptr_t)drv_iova_map(q, zstd_out->literal, zstd_out->lit_sz);
		if (!phy_lit) {
			WD_ERR("Get literal buf dma address fail!\n");
			goto unmap_phy_lit;
		}

		phy_seq = (uintptr_t)drv_iova_map(q, zstd_out->sequence, zstd_out->seq_sz);
		if (!phy_seq) {
			WD_ERR("Get sequence buf dma address fail!\n");
			goto unmap_phy_seq;
		}

		sqe->cipher_key_addr_l = lower_32_bits((__u64)phy_lit);
		sqe->cipher_key_addr_h = upper_32_bits((__u64)phy_lit);
		sqe->dest_addr_l = lower_32_bits((__u64)phy_seq);
		sqe->dest_addr_h = upper_32_bits((__u64)phy_seq);
	} else {
		sqe->cipher_key_addr_l = lower_32_bits((__u64)addr.dest_addr);
		sqe->cipher_key_addr_h = upper_32_bits((__u64)addr.dest_addr);
		sqe->dest_addr_l = lower_32_bits((__u64)addr.dest_addr + msg->in_size);
		sqe->dest_addr_h = upper_32_bits((__u64)addr.dest_addr + msg->in_size);
	}

	sqe->stream_ctx_addr_l = lower_32_bits((__u64)addr.ctxbuf_addr);
	sqe->stream_ctx_addr_h = upper_32_bits((__u64)addr.ctxbuf_addr);

	return WD_SUCCESS;

unmap_phy_seq:
	drv_iova_unmap(q, zstd_out->literal, (void *)phy_lit, zstd_out->lit_sz);
unmap_phy_lit:
	drv_iova_unmap(q, msg->src, (void *)addr.source_addr, msg->in_size);
	return -WD_ENOMEM;
}

static void fill_zip_sqe_hw_info(void *ssqe, struct wcrypto_comp_msg *msg)
{
	struct hisi_zip_sqe_v3 *sqe = ssqe;

	if (msg->ctx_buf) {
		sqe->ctx_dw0 = *(__u32 *)msg->ctx_buf;
		sqe->ctx_dw1 = *(__u32 *)(msg->ctx_buf + CTX_PRIV1_OFFSET);
		sqe->ctx_dw2 = *(__u32 *)(msg->ctx_buf + CTX_PRIV2_OFFSET);
	}

	sqe->isize = msg->isize;
	sqe->checksum = msg->checksum;
}

static void fill_zip_sqe_hw_info_lz77_zstd(void *ssqe, struct wcrypto_comp_msg *msg)
{
	struct wcrypto_comp_tag *tag = (void *)(uintptr_t)msg->udata;
	struct wcrypto_lz77_zstd_format *format = tag->priv;
	struct hisi_zip_sqe_v3 *sqe = ssqe;

	if (msg->ctx_buf) {
		sqe->ctx_dw0 = *(__u32 *)msg->ctx_buf;
		sqe->ctx_dw1 = *(__u32 *)(msg->ctx_buf + CTX_PRIV1_OFFSET);
		sqe->ctx_dw2 = *(__u32 *)(msg->ctx_buf + CTX_PRIV2_OFFSET);
		if (format->blk_type != COMP_BLK)
			memcpy(msg->ctx_buf + CTX_HW_REPCODE_OFFSET + CTX_BUFFER_OFFSET,
			       msg->ctx_buf + CTX_REPCODE2_OFFSET, REPCODE_SIZE);
	}

	sqe->isize = msg->isize;
	sqe->checksum = msg->checksum;
}

static struct zip_fill_sqe_ops ops[] = { {
		.alg_type = "zlib",
		.fill_sqe_alg = fill_zip_comp_alg_deflate,
		.fill_sqe_buffer_size = fill_zip_buffer_size_deflate,
		.fill_sqe_window_size = fill_zip_window_size,
		.fill_sqe_addr = fill_zip_addr_deflate,
		.fill_sqe_hw_info = fill_zip_sqe_hw_info,
	}, {
		.alg_type = "gzip",
		.fill_sqe_alg = fill_zip_comp_alg_deflate,
		.fill_sqe_buffer_size = fill_zip_buffer_size_deflate,
		.fill_sqe_window_size = fill_zip_window_size,
		.fill_sqe_addr = fill_zip_addr_deflate,
		.fill_sqe_hw_info = fill_zip_sqe_hw_info,
	}, {
		.alg_type = "raw_deflate",
		.fill_sqe_alg = fill_zip_comp_alg_deflate,
		.fill_sqe_buffer_size = fill_zip_buffer_size_deflate,
		.fill_sqe_window_size = fill_zip_window_size,
		.fill_sqe_addr = fill_zip_addr_deflate,
		.fill_sqe_hw_info = fill_zip_sqe_hw_info,
	}, {
		.alg_type = "lz77_zstd",
		.fill_sqe_alg = fill_zip_comp_alg_zstd,
		.fill_sqe_buffer_size = fill_zip_buffer_size_zstd,
		.fill_sqe_window_size = fill_zip_window_size,
		.fill_sqe_addr = fill_zip_addr_lz77_zstd,
		.fill_sqe_hw_info = fill_zip_sqe_hw_info_lz77_zstd,
	},
};

int qm_fill_zip_sqe_v3(void *smsg, struct qm_queue_info *info, __u16 i)
{
	struct hisi_zip_sqe_v3 *sqe = (struct hisi_zip_sqe_v3 *)info->sq_base + i;
	struct wcrypto_comp_msg *msg = smsg;
	struct wd_queue *q = info->q;
	__u8 flush_type;
	__u8 data_fmt;
	int ret;

	memset(sqe, 0, sizeof(*sqe));

	if (unlikely(msg->alg_type >= get_arrsize(ops))) {
		WD_ERR("The algorithm is invalid!\n");
		return -WD_EINVAL;
	}

	ret = ops[msg->alg_type].fill_sqe_alg(sqe, msg);
	if (unlikely(ret)) {
		WD_ERR("The algorithm is unsupported!\n");
		return ret;
	}

	ret = ops[msg->alg_type].fill_sqe_buffer_size(sqe, msg);
	if (unlikely(ret)) {
		WD_ERR("The buffer size is invalid!\n");
		return ret;
	}

	ret = ops[msg->alg_type].fill_sqe_window_size(sqe, msg);
	if (unlikely(ret)) {
		WD_ERR("The window size is invalid!\n");
		return ret;
	}

	ret = ops[msg->alg_type].fill_sqe_addr(sqe, msg, q);
	if (unlikely(ret))
		return ret;

	flush_type = (msg->flush_type == WCRYPTO_FINISH) ? HZ_FINISH :
		      HZ_SYNC_FLUSH;
	sqe->dw7 |= ((msg->stream_pos << STREAM_POS_SHIFT) |
		     (msg->stream_mode << STREAM_MODE_SHIFT) |
		     (flush_type)) << STREAM_FLUSH_SHIFT |
		     BD_TYPE3 << BD_TYPE_SHIFT;

	/* data_fmt: 4'b0000 - Pbuffer, 4'b0001 - SGL */
	data_fmt = (msg->data_fmt == WD_SGL_BUF) ? HISI_SGL_BUF : HISI_FLAT_BUF;
	sqe->dw9 |= data_fmt << HZ_BUF_TYPE_SHIFT;

	ops[msg->alg_type].fill_sqe_hw_info(sqe, msg);
	sqe->tag_l = msg->tag;

	info->req_cache[i] = msg;

	return WD_SUCCESS;
}

/*
 * Checksum[31:24] equals LitLength_Overflow_Pos;
 * Checksum[23:0] equals Freq_Literal_Overflow_cnt;
 */
#define LILL_OVERFLOW_POS 	0x00ffffff
#define LILL_OVERFLOW_CNT_OFFSET 24
static void fill_priv_lz77_zstd(void *ssqe, struct wcrypto_comp_msg *recv_msg)
{
	struct wcrypto_comp_tag *tag = (void *)(uintptr_t)recv_msg->udata;
	struct wcrypto_lz77_zstd_format *format = tag->priv;
	struct hisi_zip_sqe_v3 *sqe = ssqe;
	struct wcrypto_zstd_out *zstd_out;
	void *ctx_buf = recv_msg->ctx_buf;

	format->lit_num = sqe->comp_data_length;
	format->seq_num = sqe->produced;

	format->lit_length_overflow_cnt = sqe->checksum & LILL_OVERFLOW_POS;
	format->lit_length_overflow_pos = (sqe->checksum & ~LILL_OVERFLOW_POS) >>
					  LILL_OVERFLOW_CNT_OFFSET;

	if (recv_msg->data_fmt == WD_SGL_BUF) {
		zstd_out = (void *)recv_msg->dst;
		format->literals_start = zstd_out->literal;
		format->sequences_start = zstd_out->sequence;
	} else {
		format->literals_start = recv_msg->dst;
		format->sequences_start = recv_msg->dst + recv_msg->in_size;
		format->freq = (void *)(&format->lit_length_overflow_pos + 1);
	}

	if (ctx_buf) {
		memcpy(ctx_buf + CTX_REPCODE2_OFFSET,
		       ctx_buf + CTX_REPCODE1_OFFSET, REPCODE_SIZE);
		memcpy(ctx_buf + CTX_REPCODE1_OFFSET,
		       ctx_buf + CTX_BUFFER_OFFSET + CTX_HW_REPCODE_OFFSET,
		       REPCODE_SIZE);
	}
}

int qm_parse_zip_sqe_v3(void *hw_msg, const struct qm_queue_info *info,
			__u16 i, __u16 usr)
{
	struct wcrypto_comp_msg *recv_msg = info->req_cache[i];
	struct hisi_zip_sqe_v3 *sqe = hw_msg;
	__u16 ctx_st = sqe->ctx_dw0 & HZ_CTX_ST_MASK;
	__u16 lstblk = sqe->dw3 & HZ_LSTBLK_MASK;
	__u32 status = sqe->dw3 & HZ_STATUS_MASK;
	__u32 type = sqe->dw9 & HZ_REQ_TYPE_MASK;
	uintptr_t phy_in, phy_out, phy_ctxbuf;
	struct wd_queue *q = info->q;
	struct wcrypto_comp_tag *tag;

	if (unlikely(!recv_msg)) {
		WD_ERR("info->req_cache is null at index:%hu\n", i);
		return 0;
	}

	if (usr && sqe->tag_l != usr)
		return 0;

	if (status != 0 && status != HW_NEGACOMPRESS && status != HW_DECOMP_END) {
		WD_ERR("bad status(ctx_st=0x%x, s=0x%x, t=%u)\n",
		       ctx_st, status, type);
		recv_msg->status = WD_IN_EPARA;
	} else {
		recv_msg->status = 0;
	}
	recv_msg->in_cons = sqe->consumed;
	recv_msg->produced = sqe->produced;
	if (recv_msg->ctx_buf) {
		*(__u32 *)recv_msg->ctx_buf = sqe->ctx_dw0;
		*(__u32 *)(recv_msg->ctx_buf + CTX_PRIV1_OFFSET) = sqe->ctx_dw1;
		*(__u32 *)(recv_msg->ctx_buf + CTX_PRIV2_OFFSET) = sqe->ctx_dw2;
	}
	recv_msg->isize = sqe->isize;
	recv_msg->checksum = sqe->checksum;

	phy_in = DMA_ADDR(sqe->source_addr_h, sqe->source_addr_l);
	drv_iova_unmap(q, recv_msg->src, (void *)phy_in, recv_msg->in_size);
	phy_out = DMA_ADDR(sqe->dest_addr_h, sqe->dest_addr_l);
	drv_iova_unmap(q, recv_msg->dst, (void *)phy_out, recv_msg->avail_out);
	if (recv_msg->ctx_buf) {
		phy_ctxbuf = DMA_ADDR(sqe->stream_ctx_addr_h,
				      sqe->stream_ctx_addr_l);
		drv_iova_unmap(q, recv_msg->ctx_buf, (void *)phy_ctxbuf,
			       MAX_CTX_RSV_SIZE);
	}

	qm_parse_zip_sqe_set_status(recv_msg, status, lstblk, ctx_st);

	tag = (void *)(uintptr_t)recv_msg->udata;
	if (tag && tag->priv && !info->sqe_fill_priv)
		fill_priv_lz77_zstd(sqe, recv_msg);

	return 1;
}

static void qm_fill_zip_cipher_sqe_with_priv(struct hisi_zip_sqe *sqe, void *priv)
{
	struct wd_sec_udata *udata = priv;
	__u32 dif_size = 0;
	__u32 pad_size = 0;

	if (!udata)
		return;

	sqe->lba_l = lower_32_bits(udata->dif.lba);
	sqe->lba_h = upper_32_bits(udata->dif.lba);
	sqe->dw7 = udata->src_offset;
	sqe->dw8 = udata->dst_offset;
	sqe->dw10 = (udata->dif.ctrl.gen.page_layout_gen_type) |
		(udata->dif.ctrl.gen.grd_gen_type << HZ_GRD_GTYPE_SHIFT) |
		(udata->dif.ctrl.gen.ver_gen_type << HZ_VER_GTYPE_SHIFT) |
		(udata->dif.ctrl.gen.app_gen_type << HZ_APP_GTYPE_SHIFT) |
		(udata->dif.app << HZ_APP_SHIFT) | (udata->dif.ver << HZ_VER_SHIFT);
	sqe->priv_info = udata->dif.priv_info;
	sqe->dw12 = (udata->dif.ctrl.gen.ref_gen_type) |
		(udata->dif.ctrl.gen.page_layout_pad_type << HZ_PAD_TYPE_SHIFT) |
		(udata->dif.ctrl.verify.grd_verify_type << HZ_GRD_VTYPE_SHIFT) |
		(udata->dif.ctrl.verify.ref_verify_type << HZ_REF_VTYPE_SHIFT) |
		(udata->block_size << HZ_BLK_SIZE_SHIFT);

	if (udata->dif.ctrl.gen.grd_gen_type) {
		dif_size = ZIP_DIF_LEN;
		if (udata->dif.ctrl.gen.page_layout_gen_type)
			pad_size = ZIP_PAD_LEN;
	}

	sqe->input_data_length =
		(udata->block_size + dif_size + pad_size) * udata->gran_num;
	sqe->dest_avail_out = sqe->input_data_length;
}

static int fill_zip_cipher_alg(struct wcrypto_cipher_msg *msg,
		struct hisi_zip_sqe *sqe, __u16 *key_len)
{
	int ret = -WD_EINVAL;
	__u16 len;

	if (msg->mode != WCRYPTO_CIPHER_XTS)
		return -WD_EINVAL;

	len = msg->key_bytes >> XTS_MODE_KEY_SHIFT;

	switch (msg->alg) {
	case WCRYPTO_CIPHER_SM4:
		sqe->dw9 = HW_XTS_SM4_128;
		ret = WD_SUCCESS;
		break;
	case WCRYPTO_CIPHER_AES:
		if (len == AES_KEYSIZE_128) {
			sqe->dw9 = HW_XTS_AES_128;
			ret = WD_SUCCESS;
		} else if (len == AES_KEYSIZE_256) {
			sqe->dw9 = HW_XTS_AES_256;
			ret = WD_SUCCESS;
		} else {
			WD_ERR("Zip invalid AES key size!\n");
		}
		break;
	default:
		WD_ERR("Zip invalid cipher type!\n");
		break;
	}

	*key_len = len;
	return ret;
}

int qm_fill_zip_cipher_sqe(void *send_msg, struct qm_queue_info *info, __u16 i)
{
	struct hisi_zip_sqe *sqe = (struct hisi_zip_sqe *)info->sq_base + i;
	struct wcrypto_cipher_msg *msg = send_msg;
	struct wcrypto_cipher_tag *cipher_tag = (void *)(uintptr_t)msg->usr_data;
	struct wd_queue *q = info->q;
	__u8 data_fmt;
	uintptr_t phy;
	__u16 key_len;
	int ret;

	memset((void *)sqe, 0, sizeof(*sqe));

	ret = fill_zip_cipher_alg(msg, sqe, &key_len);
	if (ret)
		return ret;

	phy = (uintptr_t)msg->in;
	sqe->source_addr_l = lower_32_bits(phy);
	sqe->source_addr_h = upper_32_bits(phy);

	phy = (uintptr_t)msg->out;
	sqe->dest_addr_l = lower_32_bits(phy);
	sqe->dest_addr_h = upper_32_bits(phy);

	data_fmt = (msg->data_fmt == WD_SGL_BUF) ? HISI_SGL_BUF : HISI_FLAT_BUF;
	sqe->dw9 |= data_fmt << HZ_BUF_TYPE_SHIFT;

	phy = (uintptr_t)drv_iova_map(q, msg->key, msg->key_bytes);
	if (!phy) {
		WD_ERR("Get zip key buf dma address fail!\n");
		return -WD_ENOMEM;
	}
	sqe->cipher_key1_addr_l = lower_32_bits(phy);
	sqe->cipher_key1_addr_h = upper_32_bits(phy);

	phy += key_len;
	sqe->cipher_key2_addr_l = lower_32_bits(phy);
	sqe->cipher_key2_addr_h = upper_32_bits(phy);
	if (cipher_tag) {
		sqe->tag = cipher_tag->wcrypto_tag.ctx_id;
		qm_fill_zip_cipher_sqe_with_priv(sqe, cipher_tag->priv);
	}

	info->req_cache[i] = msg;

	return WD_SUCCESS;
}

int qm_parse_zip_cipher_sqe(void *hw_msg, const struct qm_queue_info *info,
			__u16 i, __u16 usr)
{
	struct wcrypto_cipher_msg *recv_msg = info->req_cache[i];
	struct hisi_zip_sqe *sqe = hw_msg;
	struct wd_queue *q = info->q;
	__u32 status = sqe->dw3 & HZ_STATUS_MASK;
	__u32 type = sqe->dw9 & HZ_REQ_TYPE_MASK;
	__u64 dma_addr;

	if (unlikely(!recv_msg)) {
		WD_ERR("info->req_cache is null at index:%hu\n", i);
		return 0;
	}

	if (usr && sqe->tag != usr)
		return 0;

	if (status == 0)
		recv_msg->result = 0;
	else if (status == HW_IN_DATA_DIF_CHECK_ERR)
		recv_msg->result = WCRYPTO_SRC_DIF_ERR;
	else {
		WD_ERR("bad status(s=0x%x, t=%u)\n", status, type);
		recv_msg->result = WD_IN_EPARA;
	}

	dma_addr = DMA_ADDR(sqe->cipher_key1_addr_h, sqe->cipher_key1_addr_l);
	drv_iova_unmap(q, recv_msg->key, (void *)(uintptr_t)dma_addr,
		recv_msg->key_bytes);

	return 1;
}
