// SPDX-License-Identifier: GPL-2.0
#ifndef __HZIP_DRV_H__
#define __HZIP_DRV_H__

#include "config.h"
#include <linux/types.h>
#include "wd.h"
#include "include/qm_usr_if.h"

struct hisi_qm_priv {
	__u16 sqe_size;
};

int hisi_qm_set_queue_dio(struct wd_queue *q);
int hisi_qm_set_queue_dio_noiommu(struct wd_queue *q);
void hisi_qm_unset_queue_dio(struct wd_queue *q);
int hisi_qm_add_to_dio_q(struct wd_queue *q, void *req);
int hisi_qm_get_from_dio_q(struct wd_queue *q, void **resp);
void *hisi_qm_preserve_mem(struct wd_queue *q, size_t size);

#define QM_DOORBELL_SIZE (QM_DOORBELL_PAGE_NR * PAGE_SIZE)
#define QM_DKO_SIZE (QM_DKO_PAGE_NR * PAGE_SIZE)
#define QM_DUS_SIZE (QM_DUS_PAGE_NR * PAGE_SIZE)

#define QM_DOORBELL_START 0
#if ENABLE_NOIOMMU
#define QM_DUS_START (QM_DOORBELL_START + QM_DOORBELL_SIZE)
#define QM_SS_START (QM_DUS_START + QM_DUS_SIZE)
#else
#define QM_DKO_START (QM_DOORBELL_START + QM_DOORBELL_SIZE)
#define QM_DUS_START (QM_DKO_START + QM_DKO_SIZE)
#define QM_SS_START (QM_DUS_START + QM_DUS_SIZE)
#endif

#endif
