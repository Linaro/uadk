// SPDX-License-Identifier: GPL-2.0
#ifndef __HZIP_DRV_H__
#define __HZIP_DRV_H__

#include "config.h"
#include <linux/types.h>
#include "wd.h"
#include "include/qm_usr_if.h"

/* this is unnecessary big, the hardware should optimize it */
struct hisi_qm_msg {
	__u32 consumed;
	__u32 produced;
	__u32 comp_date_length;
	__u32 dw3;
	__u32 input_date_length;
	__u32 lba_l;
	__u32 lba_h;
	__u32 dw7;
	__u32 dw8;
	__u32 dw9;
	__u32 dw10;
	__u32 priv_info;
	__u32 dw12;
	__u32 tag;
	__u32 dest_avail_out;
	__u32 rsvd0;
	__u32 comp_head_addr_l;
	__u32 comp_head_addr_h;
	__u32 source_addr_l;
	__u32 source_addr_h;
	__u32 dest_addr_l;
	__u32 dest_addr_h;
	__u32 stream_ctx_addr_l;
	__u32 stream_ctx_addr_h;
	__u32 cipher_key1_addr_l;
	__u32 cipher_key1_addr_h;
	__u32 cipher_key2_addr_l;
	__u32 cipher_key2_addr_h;
	__u32 rsvd1[4];
};

int hisi_qm_set_queue_dio(struct wd_queue *q);
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
