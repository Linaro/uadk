// SPDX-License-Identifier: GPL-2.0
#ifndef __HZIP_DRV_H__
#define __HZIP_DRV_H__

#include "config.h"
#include <linux/types.h>
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

extern int hisi_qm_alloc_ctx(struct wd_ctx *ctx, struct hisi_qm_capa *capa);
extern void hisi_qm_free_ctx(struct wd_ctx *ctx);
extern int hisi_qm_send(struct wd_ctx *ctx, void *req);
extern int hisi_qm_recv(struct wd_ctx *ctx, void **resp);

#endif
