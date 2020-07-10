// SPDX-License-Identifier: GPL-2.0
#ifndef __HZIP_DRV_H__
#define __HZIP_DRV_H__

#include <linux/types.h>
#include <stdbool.h>

#include "config.h"
#include "wd.h"
#include "include/qm_usr_if.h"

struct hisi_qm_priv {
	__u16 sqe_size;
	__u16 op_type;
};

/* Capabilities */
struct hisi_qm_capa {
	char *alg;
	int throughput;
	int latency;
	__u32 flags;
	__u8 priv[WD_CAPA_PRIV_DATA_SIZE];/* For algorithm parameters */
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
	bool cqc_phase;
	void *req_cache[QM_Q_DEPTH];
	int is_sq_full;
};

struct hisi_qp {
	struct hisi_qm_queue_info q_info;
	handle_t h_ctx;
};

extern handle_t hisi_qm_alloc_ctx(char *node_path, void *priv, void **data);
extern void hisi_qm_free_ctx(handle_t h_ctx);
extern int hisi_qm_send(handle_t h_ctx, void *req);
extern int hisi_qm_recv(handle_t h_ctx, void **resp);

#endif
