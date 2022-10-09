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

#include <asm/byteorder.h>
#include <linux/types.h>
#include "config.h"
#include "v1/wd.h"
#include "v1/wd_ecc.h"
#include "v1/wd_rsa.h"
#include "v1/wd_util.h"
#include "v1/wd_dh.h"
#include "v1/wd_sgl.h"

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
#define CQE_PHASE(cq)	(__le16_to_cpu((cq)->w7) & 0x1)
#define CQE_SQ_NUM(cq)	__le16_to_cpu((cq)->sq_num)
#define CQE_SQ_HEAD_INDEX(cq)	(__le16_to_cpu((cq)->sq_head) & 0xffff)

/* wd sgl len */
#define WD_SGL_PAD0_LEN			2
#define WD_SGL_PAD1_LEN			8
#define WD_SGL_RESERVERD_LEN		24

enum hisi_buff_type {
	HISI_FLAT_BUF,
	HISI_SGL_BUF,
};

/* in little-endian */
struct hisi_sge {
	uintptr_t buf;
	void *page_ctrl;
	__le32 len;
	__le32 pad;
	__le32 pad0;
	__le32 pad1;
};

/* use default sgl head size 64B, in little-endian */
struct hisi_sgl {
	/* next sgl point, to make up chain, 64bit */
	uintptr_t next_dma;
	/* sum of sge in all sgl chain */
	__le16 entry_sum_in_chain;
	/* valid sge num in this sgl */
	__le16 entry_sum_in_sgl;
	/* sge num in this sgl */
	__le16 entry_length_in_sgl;
	__le16 pad0;
	__le64 pad1[6];

	struct hisi_sge sge_entries[];
};

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

struct hisi_qp_info {
	__u32 sqe_size;
	__u16 sq_depth;
	__u16 cq_depth;
	__u64 reserved;
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
	__u16 sq_depth;
	__u16 cq_depth;
	__u16 sqn;
	__u16 resv;
	bool is_poll;
	int cqc_phase;
	int used;
	int sqe_size;
	void **req_cache;
	qm_sqe_fill sqe_fill[WCRYPTO_MAX_ALG];
	qm_sqe_parse sqe_parse[WCRYPTO_MAX_ALG];
	hisi_qm_sqe_fill_priv sqe_fill_priv;
	hisi_qm_sqe_parse_priv sqe_parse_priv;
	struct wd_lock sd_lock;
	struct wd_lock rc_lock;
	struct wd_queue *q;
	int (*sgl_info)(struct hw_sgl_info *info);
	int (*sgl_init)(void *pool, struct wd_sgl *sgl);
	void (*sgl_uninit)(void *pool, struct wd_sgl *sgl);
	int (*sgl_merge)(void *pool, struct wd_sgl *dst_sgl, struct wd_sgl *src_sgl);
};

struct hisi_qm_inject_op {
	const char *hw_type;
	hisi_qm_sqe_fill_priv sqe_fill_priv;
	hisi_qm_sqe_parse_priv sqe_parse_priv;
};

int qm_init_queue(struct wd_queue *q);
void qm_uninit_queue(struct wd_queue *q);
int qm_send(struct wd_queue *q, void **req, __u32 num);
int qm_recv(struct wd_queue *q, void **resp, __u32 num);
int hisi_qm_inject_op_register(struct wd_queue *q, struct hisi_qm_inject_op *op);
int qm_get_hwsgl_info(struct wd_queue *q, struct hw_sgl_info *sgl_info);
int qm_init_hwsgl_mem(struct wd_queue *q, void *pool, struct wd_sgl *sgl);
int qm_uninit_hwsgl_mem(struct wd_queue *q, void *pool, struct wd_sgl *sgl);
int qm_merge_hwsgl(struct wd_queue *q, void *pool,
		   struct wd_sgl *dst_sgl, struct wd_sgl *src_sgl);
void qm_tx_update(struct qm_queue_info *info, __u32 num);
void qm_rx_update(struct qm_queue_info *info, __u32 num);
void qm_rx_from_cache(struct qm_queue_info *info, void **resp, __u32 num);

#define HISI_QM_API_VER_BASE "hisi_qm_v1"
#define HISI_QM_API_VER2_BASE "hisi_qm_v2"
#define HISI_QM_API_VER3_BASE "hisi_qm_v3"

#define WD_UACCE_CMD_QM_SET_QP_CTX	_IOWR('H', 10, struct hisi_qp_ctx)
#define WD_UACCE_CMD_QM_SET_QP_INFO	_IOWR('H', 11, struct hisi_qp_info)

#endif
