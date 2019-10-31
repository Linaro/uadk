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
#include "hisi_zip_udrv.h"

#define STREAM_FLUSH_SHIFT 25
#define MIN_AVAILOUT_SIZE 4096
#define STREAM_POS_SHIFT 2
#define STREAM_MODE_SHIFT 1

#define HW_NEGACOMPRESS 0x0d
#define HW_CRC_ERR 0x10
#define HW_DECOMP_END 0x13

#define HW_DECOMP_NO_SPACE 0x01
#define HW_DECOMP_BLK_NOSTART 0x03
#define HW_DECOMP_NO_CRC 0x04

#ifdef DEBUG_LOG
void zip_sqe_dump(struct hisi_zip_sqe *sqe)
{
	int i;

	WD_ERR("[%s][%d]sqe info:\n", __func__, __LINE__);
	for (i = 0; i < sizeof(struct hisi_zip_sqe) / sizeof(int); i++)
		WD_ERR("sqe-word[%d]: 0x%x.\n", i, *((int *)sqe+i));
}
#endif

int qm_fill_zip_sqe(void *smsg, struct qm_queue_info *info, __u16 i)
{
	struct hisi_zip_sqe *sqe = (struct hisi_zip_sqe *)info->sq_base + i;
	struct wcrypto_comp_msg *msg = smsg;
	struct wcrypto_cb_tag *tag = (void *)(uintptr_t)msg->udata;
	uintptr_t phy_in, phy_out;
	uintptr_t phy_ctxbuf = 0;
	struct wd_queue *q = info->q;
	struct q_info *qinfo = q->qinfo;

	memset((void *)sqe, 0, sizeof(*sqe));

	switch (msg->alg_type) {
	case WCRYPTO_ZLIB:
		sqe->dw9 = HW_ZLIB;
		break;
	case WCRYPTO_GZIP:
		sqe->dw9 = HW_GZIP;
		break;
	default:
		return -EINVAL;
	}

	if (qinfo->dev_flags & UACCE_DEV_NOIOMMU) {
		phy_in = (uintptr_t)drv_iova_map(q, msg->src, msg->in_size);
		if (!phy_in) {
			WD_ERR("Get zip in buf dma address fail!\n");
			return -WD_ENOMEM;
		}
		phy_out = (uintptr_t)drv_iova_map(q, msg->dst, 0);
		if (!phy_out) {
			WD_ERR("Get zip out buf dma address fail!\n");
			return -WD_ENOMEM;
		}
		if (msg->stream_mode == WCRYPTO_COMP_STATEFUL) {
			phy_ctxbuf = (uintptr_t)drv_iova_map(q,
				msg->ctx_buf, 0);
			if (!phy_ctxbuf) {
				WD_ERR("Get zip ctx buf dma address fail!\n");
				return -WD_ENOMEM;
			}
		}
	} else {
		phy_in = (uintptr_t)msg->src;
		phy_out = (uintptr_t)msg->dst;
		phy_ctxbuf = (uintptr_t)msg->ctx_buf;
	}

	msg->flush_type = (msg->flush_type == WCRYPTO_FINISH) ? HZ_FINISH :
			  HZ_SYNC_FLUSH;
	sqe->dw7 |= ((msg->stream_pos << STREAM_POS_SHIFT |
		     msg->stream_mode << STREAM_MODE_SHIFT |
		     msg->flush_type)) << STREAM_FLUSH_SHIFT;
	sqe->source_addr_l = (__u64)phy_in & QM_L32BITS_MASK;
	sqe->source_addr_h = (__u64)phy_in >> QM_HADDR_SHIFT;
	sqe->dest_addr_l = (__u64)phy_out & QM_L32BITS_MASK;
	sqe->dest_addr_h = (__u64)phy_out >> QM_HADDR_SHIFT;
	sqe->input_data_length = msg->in_size;
	if (msg->avail_out > MIN_AVAILOUT_SIZE)
		sqe->dest_avail_out = msg->avail_out;
	else
		sqe->dest_avail_out = MIN_AVAILOUT_SIZE;
	sqe->stream_ctx_addr_l = (__u64)phy_ctxbuf & QM_L32BITS_MASK;
	sqe->stream_ctx_addr_h = (__u64)phy_ctxbuf >> QM_HADDR_SHIFT;
	sqe->ctx_dw0 = msg->ctx_priv0;
	sqe->ctx_dw1 = msg->ctx_priv1;
	sqe->ctx_dw2 = msg->ctx_priv2;
	sqe->isize = msg->isize;
	sqe->checksum = msg->checksum;

	if (tag)
		sqe->tag = tag->ctx_id;

	ASSERT(!info->req_cache[i]);
	info->req_cache[i] = msg;

	dbg("%s, %p, %p, %d\n", __func__, info->req_cache[i], sqe,
	    info->sqe_size);
#ifdef DEBUG_LOG
	zip_sqe_dump(sqe);
#endif

	return WD_SUCCESS;
}

int qm_parse_zip_sqe(void *hw_msg, const struct qm_queue_info *info,
		     __u16 i, __u16 usr)
{
	ASSERT(info->req_cache[i]);

	struct wcrypto_comp_msg *recv_msg = info->req_cache[i];
	struct hisi_zip_sqe *sqe = hw_msg;
	__u16 ctx_st = sqe->ctx_dw0 & 0x000f;
	__u16 lstblk = sqe->dw3 & 0x0100;
	__u16 status = sqe->dw3 & 0x00ff;
	__u16 type = sqe->dw9 & 0x00ff;

	if (usr && sqe->tag != usr)
		return 0;

	if (status != 0 && status != HW_NEGACOMPRESS &&
	    status != HW_CRC_ERR && status != HW_DECOMP_END) {
		WD_ERR("bad status(ctx_st=0x%x, s=0x%x, t=%u)\n",
		       ctx_st, status, type);
#ifdef DEBUG_LOG
		zip_sqe_dump(sqe);
#endif
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

	if ((status == HW_DECOMP_END) && lstblk)
		recv_msg->status = WCRYPTO_DECOMP_END;
	else if (status == HW_CRC_ERR) /* deflate type no crc, do normal*/
		recv_msg->status = WD_VERIFY_ERR;

	/* deflate type no crc, need return status */
	if (ctx_st == HW_DECOMP_NO_CRC)
		recv_msg->status = WCRYPTO_DECOMP_NO_CRC;
	/* last block no space, need resend null size req */
	else if (ctx_st == HW_DECOMP_NO_SPACE)
		recv_msg->status = WCRYPTO_DECOMP_END_NOSPACE;
	else if (ctx_st == HW_DECOMP_BLK_NOSTART)
		recv_msg->status = WCRYPTO_DECOMP_BLK_NOSTART;

	dbg("%s: %p, %p, %d\n", __func__, info->req_cache[i], sqe,
	    info->sqe_size);

	return 1;
}
