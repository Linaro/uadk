/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __HISI_QM_DRV_H__
#define __HISI_QM_DRV_H__

#include <linux/types.h>
#include "config.h"
#include "wd.h"
#include "include/qm_usr_if.h"
#include "wd_rsa.h"
#include "wd_util.h"
#include "wd_dh.h"
#include "../include/hpre_usr_if.h"

#define QM_CQE_SIZE			16
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
#define QM_HADDR_SHIFT		32
#define HI_U32(pa)	((__u32)(((pa) >> QM_HADDR_SHIFT) & QM_L32BITS_MASK))
#define DMA_ADDR(hi, lo)	((__u64)(((__u64)(hi) << 32) | (__u64)(lo)))

/* cqe shift */
#define CQE_PHASE(cq)	(((*((__u32 *)(cq) + 3)) >> 16) & 0x1)
#define CQE_SQ_NUM(cq)	((*((__u32 *)(cq) + 2)) >> 16)
#define CQE_SQ_HEAD_INDEX(cq)	((*((__u32 *)(cq) + 2)) & 0xffff)

struct qm_queue_info;

typedef int (*qm_sqe_fill)(void *msg,
			   struct qm_queue_info *info, __u16 i);
typedef int (*qm_sqe_parse)(void *hw_msg,
	const struct qm_queue_info *info, __u16 i, __u16 usr);

struct qm_queue_info {
	void *sq_base;
	void *cq_base;
	void *mmio_base;
	void *doorbell_base;
	int (*db)(struct qm_queue_info *q, __u8 cmd,
		  __u16 index, __u8 priority);
	void *dko_base;
	void *ds_base;
	__u16 sq_tail_index;
	__u16 cq_head_index;
	__u16 sqn;
	__u16 resv;
	int cqc_phase;
	int used;
	int sqe_size;
	void *req_cache[QM_Q_DEPTH];
	qm_sqe_fill sqe_fill[WD_MAX_ALG];
	qm_sqe_parse sqe_parse[WD_MAX_ALG];
	struct wd_lock sd_lock;
	struct wd_lock rc_lock;
	struct wd_queue *q;
};

int qm_init_queue(struct wd_queue *q);
void qm_uninit_queue(struct wd_queue *q);
int qm_send(struct wd_queue *q, void *msg);
int qm_recv(struct wd_queue *q, void **resp);

#endif
