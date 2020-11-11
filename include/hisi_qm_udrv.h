// SPDX-License-Identifier: Apache-2.0
#ifndef __HZIP_DRV_H__
#define __HZIP_DRV_H__

#include <linux/types.h>
#include <stdbool.h>

#include "config.h"
#include "wd.h"

#define WD_CAPA_PRIV_DATA_SIZE		64

#define QM_L32BITS_MASK		0xffffffff
#define QM_HADDR_SHIFT		32
#define LW_U32(pa)	((__u32)((pa) & QM_L32BITS_MASK))
#define HI_U32(pa)	((__u32)(((pa) >> QM_HADDR_SHIFT) & QM_L32BITS_MASK))
#define VA_ADDR(hi, lo)	((void *)(((__u64)(hi) << 32) | (__u64)(lo)))

#define BYTE_BITS			8
#define BYTE_BITS_SHIFT		3
struct hisi_qm_priv {
	__u16 sqe_size;
	__u16 op_type;
};

struct hisi_qm_queue_info {
	void *sq_base;
	void *cq_base;
	int sqe_size;
	void *mmio_base;
	void *db_base;
	int (*db)(struct hisi_qm_queue_info *q, __u8 cmd,
		  __u16 index, __u8 priority);
	__u16 sq_tail_index;
	__u16 sq_head_index;
	__u16 cq_head_index;
	__u16 sqn;
	__u16 qc_type;
	__u16 used_num;
	bool cqc_phase;
};

struct hisi_qp {
	struct hisi_qm_queue_info q_info;
	handle_t h_ctx;
};

/* Capabilities */
struct hisi_qm_capa {
	char *alg;
	int throughput;
	int latency;
	__u32 flags;
	__u8 priv[WD_CAPA_PRIV_DATA_SIZE];/* For algorithm parameters */
};

handle_t hisi_qm_alloc_ctx(char *dev_path, void *priv, void **data);
void hisi_qm_free_ctx(handle_t h_ctx);

/**
 * hisi_qm_send - Send req to the queue of the device.
 * @h_qp: Handle of the qp.
 * @req: User req from the alg drvie.
 * @expect: User send req num.
 * @count: The count of actual sending message.
 *
 * There is not one locked in the qm internal, Alg should
 * ensure resource non-reentrant.
 * If the free queue num is zero, the return value is -EBUSY
 */
int hisi_qm_send(handle_t h_qp, void *req, __u16 expect, __u16 *count);

/**
 * hisi_qm_recv - Recieve msg from qm of the device.
 * @h_qp: Handle of the qp.
 * @resp: Msg out buffer of the user.
 * @expect: User recieve req num.
 * @count: The count of actual recieving message.
 */
int hisi_qm_recv(handle_t h_qp, void *resp, __u16 expect, __u16 *count);

handle_t hisi_qm_alloc_qp(struct hisi_qm_priv *config, handle_t ctx);
void hisi_qm_free_qp(handle_t h_qp);

#endif
