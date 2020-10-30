/*
 * Copyright 2018-2019 Huawei Technologies Co.,Ltd.All rights reserved.
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

#ifndef __HISI_QM_DRV_H__
#define __HISI_QM_DRV_H__

#include <linux/types.h>
#include "config.h"
#include "../wd.h"
#include "../wd_ecc.h"
#include "../wd_rsa.h"
#include "../wd_util.h"
#include "../wd_dh.h"


/* default queue depth for sq/cq/eq */
#define QM_Q_DEPTH		1024

#define QM_CQE_SIZE		16

/* page number for queue file region */
#define QM_DOORBELL_PAGE_NR	1
#define QM_DKO_PAGE_NR		4
#define QM_DUS_PAGE_NR		36

#define QM_DOORBELL_PG_START 0
#define QM_DKO_PAGE_START (QM_DOORBELL_PG_START + QM_DOORBELL_PAGE_NR)
#define QM_DUS_PAGE_START (QM_DKO_PAGE_START + QM_DKO_PAGE_NR)
#define QM_SS_PAGE_START (QM_DUS_PAGE_START + QM_DUS_PAGE_NR)

#define QM_DOORBELL_OFFSET      0x340
#define QM_V2_DOORBELL_OFFSET   0x1000

#define QM_CQE_SIZE		16
#define QM_HPRE_BD_SIZE		64
#define QM_ZIP_BD_SIZE		128
#define QM_SEC_BD_SIZE		128
#define QM_RDE_BD_SIZE		64
#define DOORBELL_CMD_SQ		0
#define DOORBELL_CMD_CQ		1
#define HPRE_NO_HW_ERR		0
#define HPRE_HW_TASK_DONE	3
#define HPRE_HW_TASK_INIT	1
#define QM_DBELL_CMD_SHIFT	16
#define QM_V2_DBELL_CMD_SHIFT	12
#define QM_DBELL_PRI_SHIFT	16
#define QM_DBELL_HLF_SHIFT	32
#define QM_DBELL_SQN_MASK	0x3ff
#define QM_DBELL_CMD_MASK	0xf
#define QM_L32BITS_MASK		0xffffffff
#define QM_L16BITS_MASK		0xffff
#define QM_HADDR_SHIFT		32
#define HI_U32(pa)	((__u32)(((pa) >> QM_HADDR_SHIFT) & QM_L32BITS_MASK))
#define DMA_ADDR(hi, lo)	((__u64)(((__u64)(hi) << 32) | (__u64)(lo)))
#define LOW_U16(val)	(__u16)((val) & QM_L16BITS_MASK)


/* cqe shift */
#define CQE_PHASE(cq)	(((*((__u32 *)(cq) + 3)) >> 16) & 0x1)
#define CQE_SQ_NUM(cq)	((*((__u32 *)(cq) + 2)) >> 16)
#define CQE_SQ_HEAD_INDEX(cq)	((*((__u32 *)(cq) + 2)) & 0xffff)

/* wd sgl len */
#define WD_SGL_PAD0_LEN			2
#define WD_SGL_PAD1_LEN			8
#define WD_SGL_RESERVERD_LEN		24

struct cqe {
	__le32 rsvd0;
	__le16 cmd_id;
	__le16 rsvd1;
	__le16 sq_head;
	__le16 sq_num;
	__le16 rsvd2;
	__le16 w7;
};

struct hisi_qp_ctx {
	__u16 id;
	__u16 qc_type;
};

struct qm_queue_info;

typedef int (*qm_sqe_fill)(void *msg,
			   struct qm_queue_info *info, __u16 i);
typedef int (*qm_sqe_parse)(void *hw_msg,
	const struct qm_queue_info *info, __u16 i, __u16 usr);
typedef int (*hisi_qm_sqe_fill_priv)(
	void *hw_msg, enum wcrypto_type atype, void *opdata);
typedef int (*hisi_qm_sqe_parse_priv)(
	void *hw_msg, enum wcrypto_type atype, void *opdata);

struct qm_queue_info {
	void *sq_base;
	void *cq_base;
	void *mmio_base;
	void *doorbell_base;
	int (*db)(struct qm_queue_info *q, __u8 cmd,
		  __u16 index, __u8 priority);
	void *ds_tx_base;
	void *ds_rx_base;
	__u16 sq_tail_index;
	__u16 cq_head_index;
	__u16 sqn;
	__u16 resv;
	bool is_poll;
	int cqc_phase;
	int used;
	int sqe_size;
	void *req_cache[QM_Q_DEPTH];
	qm_sqe_fill sqe_fill[WCRYPTO_MAX_ALG];
	qm_sqe_parse sqe_parse[WCRYPTO_MAX_ALG];
	hisi_qm_sqe_fill_priv sqe_fill_priv;
	hisi_qm_sqe_parse_priv sqe_parse_priv;
	struct wd_lock sd_lock;
	struct wd_lock rc_lock;
	struct wd_queue *q;
};

struct wd_sgl_entry {
	__u8 *buf;	/* Start address of page data, 64bit */
	void *page_ctrl;
	__u32 len;	/* Valid data length in Byte */
	__u32 pad;
	__u32 pad0;
	__u32 pad1;
};

struct wd_sgl {
	/* next sgl point, to make up chain, 64bit */
	struct wd_sgl *next;
	/* sum of entry_sum_in_sgl in sgl chain */
	__u16 entry_sum_in_chain;
	/* valid sgl_entry num in this sgl */
	__u16 entry_sum_in_sgl;
	/* sgl_entry num in this sgl */
	__u16 entry_num_in_sgl;
	__u8 pad0[WD_SGL_PAD0_LEN];
	__u64 serial_num;
	__u32 flag;
	__u32 cpu_id;
	__u8 pad1[WD_SGL_PAD1_LEN];
	__u8 reserved[WD_SGL_RESERVERD_LEN];
	/* sgl_entry point */
	struct wd_sgl_entry entries[0];
};

struct hisi_qm_inject_op {
	const char *hw_type;
	hisi_qm_sqe_fill_priv sqe_fill_priv;
	hisi_qm_sqe_parse_priv sqe_parse_priv;
};

int qm_init_queue(struct wd_queue *q);
void qm_uninit_queue(struct wd_queue *q);
int qm_send(struct wd_queue *q, void **msg, __u32 num);
int qm_recv(struct wd_queue *q, void **resp, __u32 num);
int hisi_qm_inject_op_register(struct wd_queue *q, struct hisi_qm_inject_op *op);
void qm_tx_update(struct qm_queue_info *info, __u32 num);
void qm_rx_update(struct qm_queue_info *info, __u32 num);
void qm_rx_from_cache(struct qm_queue_info *info, void **resp, __u32 num);

#define HISI_QM_API_VER_BASE "hisi_qm_v1"
#define HISI_QM_API_VER2_BASE "hisi_qm_v2"
#define HISI_QM_API_VER3_BASE "hisi_qm_v3"

#define WD_UACCE_CMD_QM_SET_QP_CTX	_IOWR('H', 10, struct hisi_qp_ctx)

#endif
