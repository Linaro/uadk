// SPDX-License-Identifier: Apache-2.0
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __HZIP_DRV_H__
#define __HZIP_DRV_H__

#include <linux/types.h>
#include <stdbool.h>
#include <pthread.h>

#include "config.h"
#include "wd.h"
#include "wd_alg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WD_CAPA_PRIV_DATA_SIZE		64

#define QM_L32BITS_MASK		0xffffffff
#define QM_L16BITS_MASK		0xffff
#define QM_HADDR_SHIFT		32
#define LW_U32(pa)	((__u32)((pa) & QM_L32BITS_MASK))
#define HI_U32(pa)	((__u32)(((pa) >> QM_HADDR_SHIFT) & QM_L32BITS_MASK))
#define VA_ADDR(hi, lo)	((void *)(((uintptr_t)(hi) << 32) | (uintptr_t)(lo)))
#define LW_U16(val)	((__u16)((val) & QM_L16BITS_MASK))

#define BYTE_BITS			8
#define BYTE_BITS_SHIFT		3

enum hisi_qm_sgl_copy_dir {
	COPY_SGL_TO_PBUFF,
	COPY_PBUFF_TO_SGL
};

enum hisi_hw_type {
	HISI_QM_API_VER_BASE = 1,
	HISI_QM_API_VER2_BASE,
	HISI_QM_API_VER3_BASE
};

struct hisi_qm_priv {
	/* flag for SYNC or ASYNC */
	__u8 qp_mode;
	__u16 sqe_size;
	__u16 op_type;
	/* index of ctxs */
	__u32 idx;
	bool epoll_en;
};

struct hisi_qm_queue_info {
	void *sq_base;
	void *cq_base;
	int sqe_size;
	void *mmio_base;
	void *db_base;
	int (*db)(struct hisi_qm_queue_info *q, __u8 cmd,
		  __u16 index, __u8 priority);
	void *ds_tx_base;
	void *ds_rx_base;
	__u8 qp_mode;
	__u16 sq_tail_index;
	__u16 sq_head_index;
	__u16 cq_head_index;
	__u16 sqn;
	__u16 qc_type;
	__u16 used_num;
	__u16 hw_type;
	__u32 idx;
	bool cqc_phase;
	pthread_spinlock_t lock;
	unsigned long region_size[UACCE_QFRT_MAX];
	bool epoll_en;
};

struct hisi_qp {
	struct hisi_qm_queue_info q_info;
	handle_t h_sgl_pool;
	handle_t h_ctx;
};

/* Capabilities */
struct hisi_qm_capa {
	char *alg;
	int throughput;
	int latency;
	__u32 flags;
	/* For algorithm parameters */
	__u8 priv[WD_CAPA_PRIV_DATA_SIZE];
};

/**
 * hisi_qm_send - Send req to the queue of the device.
 * @h_qp: Handle of the qp.
 * @req: User req from the alg driver.
 * @expect: User send req num.
 * @count: The count of actual sending message.
 *
 * There is not one locked in the qm internal, Alg should
 * ensure resource non-reentrant.
 * If the free queue num is zero, the return value is -WD_EBUSY
 */
int hisi_qm_send(handle_t h_qp, const void *req, __u16 expect, __u16 *count);

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

/**
 * hisi_check_bd_id - Check the SQE BD's id and send msg id.
 * @h_qp: Handle of the qp.
 * @mid: send message id.
 * @bid: recv BD id.
 */
int hisi_check_bd_id(handle_t h_qp, __u32 mid, __u32 bid);

/**
 * hisi_set_msg_id - set the message tag id.
 * @h_qp: Handle of the qp.
 * @tag: the message tag id.
 */
void hisi_set_msg_id(handle_t h_qp, __u32 *tag);

/**
 * hisi_qm_create_sglpool - Create sgl pool in qm.
 * @sgl_num: the sgl number.
 * @sge_num: the sge num in every sgl num.
 *
 * Fixed me: the sge buff's size now is Fixed.
 */
handle_t hisi_qm_create_sglpool(__u32 sgl_num, __u32 sge_num);

/**
 * hisi_qm_destroy_sglpool - Destroy sgl pool in qm.
 * @sgl_pool: Handle of the sgl pool.
 */
void hisi_qm_destroy_sglpool(handle_t sgl_pool);

/**
 * hisi_qm_get_hw_sgl - Get sgl pointer from sgl pool.
 * @sgl_pool: Handle of the sgl pool.
 * @sgl: The user sgl info's pointer.
 *
 * Return the hw sgl addr which can fill into the sqe.
 */
void *hisi_qm_get_hw_sgl(handle_t sgl_pool, struct wd_datalist *sgl);

/**
 * hisi_qm_put_hw_sgl - Reback the hw sgl to the sgl pool.
 * @sgl_pool: Handle of the sgl pool.
 * @hw_sgl: The pointer of the hw sgl which get from sgl pool.
 */
void hisi_qm_put_hw_sgl(handle_t sgl_pool, void *hw_sgl);

/**
 * hisi_qm_get_sglpool - Get the qp's hw sgl pool handle
 * @h_qp: Handle of the qp.
 */
handle_t hisi_qm_get_sglpool(handle_t h_qp);

/**
 * hisi_qm_sgl_copy: Buffer copying from hw sgl to pbuff or pbuff to sgl
 * @pbuff: pbuff point
 * @hw_sgl: Src hw sgl point
 * @offset: Offset in hw sgl chain
 * @size: Copy size
 * @direct: 0:sgl to pbuff, 1:pbuff to sgl, from enum hisi_qm_sgl_copy_dir
 *
 * If the len of sgl is not enough, will copy much as soon as
 * possible before the offset to end of the sgl.
 */
void hisi_qm_sgl_copy(void *pbuff, void *hw_sgl, __u32 offset,
	__u32 size, __u8 direct);

/**
 * hisi_qm_get_free_sqe_num - Get the qp's available sqe num
 * @h_qp: Handle of the qp.
 *
 * This interface does not add locks, guaranteed by the caller
 */
int hisi_qm_get_free_sqe_num(handle_t h_qp);

/**
 * hisi_qm_get_list_size - Calculate the total length between two nodes.
 * Excludes the length of the end_node.
 * @start_node: The start node.
 * @end_node: The end node.
 */
__u32 hisi_qm_get_list_size(struct wd_datalist *start_node,
			    struct wd_datalist *end_node);

#ifdef __cplusplus
}
#endif

#endif
