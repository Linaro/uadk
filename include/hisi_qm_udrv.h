// SPDX-License-Identifier: Apache-2.0
#ifndef __HZIP_DRV_H__
#define __HZIP_DRV_H__

#include <linux/types.h>
#include <stdbool.h>

#include "config.h"
#include "wd.h"

#define WD_CAPA_PRIV_DATA_SIZE		64

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
