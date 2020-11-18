// SPDX-License-Identifier: Apache-2.0
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

#define MIN_AVAILOUT_SIZE 4096
#define STREAM_POS_SHIFT 2
#define STREAM_MODE_SHIFT 1
#define NEGACOMPRESS 0x0d
#define CRC_ERR 0x10
#define DECOMP_END 0x13

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
	uintptr_t phy_in, phy_out;
	uintptr_t phy_ctxbuf = 0;
	struct wd_queue *q = info->q;
	struct q_info *qinfo = q->info;

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
		phy_in = (uintptr_t)drv_dma_map(q, msg->src, msg->in_size);
		if (!phy_in) {
			WD_ERR("Get zip in buf dma address fail!\n");
			return -WD_ENOMEM;
		}
		phy_out = (uintptr_t)drv_dma_map(q, msg->dst, 0);
		if (!phy_out) {
			WD_ERR("Get zip out buf dma address fail!\n");
			return -WD_ENOMEM;
		}
		if (msg->stream_mode == WCRYPTO_COMP_STATEFUL) {
			phy_ctxbuf = (uintptr_t)drv_dma_map(q, msg->ctx_buf, 0);
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
	sqe->tag = msg->tag;

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
	__u32 status = sqe->dw3 & 0xff;
	__u32 type = sqe->dw9 & 0xff;

	if (usr && sqe->tag != usr)
		return 0;

	if (status != 0 && status != NEGACOMPRESS &&
	    status != CRC_ERR && status != DECOMP_END) {
		WD_ERR("bad status (s=%d, t=%d)\n", status, type);
#ifdef DEBUG_LOG
		zip_sqe_dump(sqe);
#endif
		recv_msg->status = WD_MSG_PARA_ERR;
	} else {
		recv_msg->status = 0;
	}
	recv_msg->in_cons = sqe->consumed;
	recv_msg->in_size = sqe->input_data_length;
	recv_msg->produced = sqe->produced;
	recv_msg->avail_out = sqe->dest_avail_out;
	recv_msg->comp_lv = 0;
	recv_msg->file_type = 0;
	recv_msg->humm_type = 0;
	recv_msg->op_type = 0;
	recv_msg->win_size = 0;
	if ((sqe->dw3 & DECOMP_STREAM_END_MASK) == DECOMP_STREAM_END)
		recv_msg->status = WCRYPTO_DECOMP_END;
	recv_msg->ctx_priv0 = sqe->ctx_dw0;
	recv_msg->ctx_priv1 = sqe->ctx_dw1;
	recv_msg->ctx_priv2 = sqe->ctx_dw2;
	recv_msg->isize = sqe->isize;
	recv_msg->checksum = sqe->checksum;
	recv_msg->tag = sqe->tag;

	if (status == CRC_ERR)
		recv_msg->status = WD_VERIFY_ERR;

	dbg("%s: %p, %p, %d\n", __func__, info->req_cache[i], sqe,
	    info->sqe_size);

	return 1;
}
