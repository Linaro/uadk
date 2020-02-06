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

#include "config.h"
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
#include "wd_util.h"
#include "wd_comp.h"
#include "wd_cipher.h"
#include "hisi_zip_udrv.h"

#define STREAM_FLUSH_SHIFT 25
#define MIN_AVAILOUT_SIZE 4096
#define STREAM_POS_SHIFT 2
#define STREAM_MODE_SHIFT 1

#define HW_NEGACOMPRESS 0x0d
#define HW_CRC_ERR 0x10
#define HW_DECOMP_END 0x13
#define HW_IN_DATA_DIF_CHECK_ERR 0xf
#define HW_UNCOMP_DIF_CHECK_ERR 0x12

#define HW_DECOMP_NO_SPACE 0x01
#define HW_DECOMP_BLK_NOSTART 0x03
#define HW_DECOMP_NO_CRC 0x04
#define ZIP_DIF_LEN 8
#define ZIP_PAD_LEN 56
#define lower_32_bits(phy) ((__u32)((__u64)(phy)))
#define upper_32_bits(phy) ((__u32)((__u64)(phy) >> QM_HADDR_SHIFT))

struct hisi_zip_sgl {
	__u32 in_sge_data_off;
	__u32 out_sge_data_off;
	void *ctrl;
};

struct hisi_zip_udata {
	struct hisi_zip_sgl sgl;
	struct wd_dif dif;
	void *comp_head;
	__u8 buf_type;
	__u16 block_size;
	__u16 align_size;
	__u8 req_type;
	void *priv;
};

static void qm_fill_zip_sqe_with_priv(struct hisi_zip_sqe *sqe, void *priv)
{
	struct hisi_zip_udata *udata = priv;

	if (!udata)
		return;

	sqe->lba_l = lower_32_bits(udata->dif.lba);
	sqe->lba_h = upper_32_bits(udata->dif.lba);
	sqe->dw7 = udata->sgl.in_sge_data_off;
	sqe->dw8 = udata->sgl.out_sge_data_off;
	sqe->dw9 = (udata->req_type) | (udata->buf_type << HZ_BUF_TYPE_SHIFT) |
		(udata->align_size << HZ_ALIGN_SIZE_SHIFT);
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
	sqe->comp_head_addr_l = lower_32_bits((uintptr_t)udata->comp_head);
	sqe->comp_head_addr_h = upper_32_bits((uintptr_t)udata->comp_head);
}

static int qm_fill_zip_sqe_get_phy_addr(struct hisi_zip_sqe *sqe,
		struct wcrypto_comp_msg *msg, struct wd_queue *q)
{
	struct q_info *qinfo = q->qinfo;
	uintptr_t phy_in, phy_out;
	uintptr_t phy_ctxbuf = 0;

	if (qinfo->dev_flags & UACCE_DEV_NOIOMMU) {
		phy_in = (uintptr_t)drv_iova_map(q, msg->src, msg->in_size);
		if (!phy_in) {
			WD_ERR("Get zip in buf dma address fail!\n");
			return -WD_ENOMEM;
		}
		phy_out = (uintptr_t)drv_iova_map(q, msg->dst, msg->avail_out);
		if (!phy_out) {
			WD_ERR("Get zip out buf dma address fail!\n");
			return -WD_ENOMEM;
		}
		if (msg->stream_mode == WCRYPTO_COMP_STATEFUL) {
			phy_ctxbuf = (uintptr_t)drv_iova_map(q, msg->ctx_buf, 0);
			if (!phy_ctxbuf) {
				WD_ERR("Get zip ctx buf dma address fail!\n");
				return -WD_ENOMEM;
			}
		}
	} else {
		phy_in = (uintptr_t)msg->src;
		phy_out = (uintptr_t)msg->dst;
		if (msg->stream_mode == WCRYPTO_COMP_STATEFUL)
			phy_ctxbuf = (uintptr_t)msg->ctx_buf;
	}
	sqe->source_addr_l = lower_32_bits((__u64)phy_in);
	sqe->source_addr_h = upper_32_bits((__u64)phy_in);
	sqe->dest_addr_l = lower_32_bits((__u64)phy_out);
	sqe->dest_addr_h = upper_32_bits((__u64)phy_out);
	sqe->stream_ctx_addr_l = lower_32_bits((__u64)phy_ctxbuf);
	sqe->stream_ctx_addr_h = upper_32_bits((__u64)phy_ctxbuf);

	return WD_SUCCESS;
}

int qm_fill_zip_sqe(void *smsg, struct qm_queue_info *info, __u16 i)
{
	struct hisi_zip_sqe *sqe = (struct hisi_zip_sqe *)info->sq_base + i;
	struct wcrypto_comp_msg *msg = smsg;
	struct wcrypto_comp_tag *tag = (void *)(uintptr_t)msg->udata;
	struct wd_queue *q = info->q;
	int ret;

	memset((void *)sqe, 0, sizeof(*sqe));

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

	ret = qm_fill_zip_sqe_get_phy_addr(sqe, msg, q);
	if (ret)
		return ret;

	msg->flush_type = (msg->flush_type == WCRYPTO_FINISH) ? HZ_FINISH :
			  HZ_SYNC_FLUSH;
	sqe->dw7 |= ((msg->stream_pos << STREAM_POS_SHIFT) |
		     (msg->stream_mode << STREAM_MODE_SHIFT) |
		     (msg->flush_type)) << STREAM_FLUSH_SHIFT;
	sqe->input_data_length = msg->in_size;
	if (msg->avail_out > MIN_AVAILOUT_SIZE)
		sqe->dest_avail_out = msg->avail_out;
	else
		sqe->dest_avail_out = MIN_AVAILOUT_SIZE;
	sqe->ctx_dw0 = msg->ctx_priv0;
	sqe->ctx_dw1 = msg->ctx_priv1;
	sqe->ctx_dw2 = msg->ctx_priv2;
	sqe->isize = msg->isize;
	sqe->checksum = msg->checksum;
	sqe->tag = msg->tag;
	if (tag)
		qm_fill_zip_sqe_with_priv(sqe, tag->priv);

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
	else if (ctx_st == HW_DECOMP_BLK_NOSTART)
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
	recv_msg->in_size = sqe->input_data_length;
	recv_msg->produced = sqe->produced;
	recv_msg->avail_out = sqe->dest_avail_out;
	recv_msg->comp_lv = 0;
	recv_msg->op_type = 0;
	recv_msg->win_size = 0;
	recv_msg->ctx_priv0 = sqe->ctx_dw0;
	recv_msg->ctx_priv1 = sqe->ctx_dw1;
	recv_msg->ctx_priv2 = sqe->ctx_dw2;
	recv_msg->isize = sqe->isize;
	recv_msg->checksum = sqe->checksum;
	recv_msg->tag = sqe->tag;

	qm_parse_zip_sqe_set_status(recv_msg, status, lstblk, ctx_st);

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

	len = msg->key_bytes / XTS_MODE_KEY_DIVISOR;

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
	uintptr_t phy;
	struct wd_queue *q = info->q;
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
	sqe->dw9 |= msg->data_fmt << HZ_BUF_TYPE_SHIFT;

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

