/* SPDX-License-Identifier: Apache-2.0 */
#include "config.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "wd_drv.h"
#include "hisi_qm_udrv.h"

#define QM_SQE_SIZE		128 /* todo: get it from sysfs */
#define QM_CQE_SIZE		16

#define DOORBELL_CMD_SQ		0
#define DOORBELL_CMD_CQ		1

/* cqe shift */
#define CQE_PHASE(cq)	(((*((__u32 *)(cq) + 3)) >> 16) & 0x1)
#define CQE_SQ_NUM(cq)	((*((__u32 *)(cq) + 2)) >> 16)
#define CQE_SQ_HEAD_INDEX(cq)	((*((__u32 *)(cq) + 2)) & 0xffff)

struct hisi_qm_queue_info {
	void *sq_base;
	void *cq_base;
	int sqe_size;
	void *mmio_base;
	void *doorbell_base;
	int (*db)(struct hisi_qm_queue_info *q, __u8 cmd,
		  __u16 index, __u8 priority);
	void *dko_base;
	__u16 sq_tail_index;
	__u16 sq_head_index;
	__u16 cq_head_index;
	__u16 sqn;
	bool cqc_phase;
	void *req_cache[QM_Q_DEPTH];
	int is_sq_full;
};

int hacc_db_v1(struct hisi_qm_queue_info *q, __u8 cmd,
	       __u16 index, __u8 priority)
{
	void *base = q->doorbell_base;
	__u16 sqn = q->sqn;
	__u64 doorbell = 0;

	doorbell = (__u64)sqn | ((__u64)cmd << 16);
	doorbell |= ((__u64)index | ((__u64)priority << 16)) << 32;

	*((__u64 *)base) = doorbell;

	return 0;
}

/* Only Hi1620 CS, we just need version 2 doorbell. */
static int hacc_db_v2(struct hisi_qm_queue_info *q, __u8 cmd,
		      __u16 index, __u8 priority)
{
	void *base = q->doorbell_base;
	__u16 sqn = q->sqn & 0x3ff;
	__u64 doorbell = 0;

	doorbell = (__u64)sqn | ((__u64)(cmd & 0xf) << 12);
	doorbell |= ((__u64)index | ((__u64)priority << 16)) << 32;

	*((__u64 *)base) = doorbell;

	return 0;
}

static int hisi_qm_fill_sqe(void *sqe, struct hisi_qm_queue_info *info, __u16 i)
{
	memcpy(info->sq_base + i * info->sqe_size, sqe, info->sqe_size);

	assert(!info->req_cache[i]);
	info->req_cache[i] = sqe;

	return 0;
}

static int hisi_qm_recv_sqe(void *sqe,
			    struct hisi_qm_queue_info *info, __u16 i)
{
	assert(info->req_cache[i]);
	dbg("hisi_qm_recv_sqe: %p, %p, %d\n", info->req_cache[i], sqe,
	    info->sqe_size);
	memcpy(info->req_cache[i], sqe, info->sqe_size);
	return 0;
}

int hisi_qm_set_queue_dio(struct wd_queue *q)
{
	struct hisi_qm_queue_info *info;
	struct hisi_qm_priv *priv = (struct hisi_qm_priv *)q->capa.priv;
	struct hisi_qp_ctx qp_ctx;
	void *vaddr;
	int ret;
	int has_dko = !(q->dev_flags & (UACCE_DEV_NOIOMMU | UACCE_DEV_SVA));

	alloc_obj(info);
	if (!info) {
		WD_ERR("no mem!\n");
		return -ENOMEM;
	}

	q->priv = info;

	vaddr = wd_drv_mmap_qfr(q, UACCE_QFRT_DUS, 0);
	if (vaddr == MAP_FAILED) {
		WD_ERR("mmap dus fail\n");
		ret = -errno;
		goto err_with_info;
	}
	info->sqe_size = priv->sqe_size;
	info->sq_base = vaddr;
	info->cq_base = vaddr + info->sqe_size * QM_Q_DEPTH;

	vaddr = wd_drv_mmap_qfr(q, UACCE_QFRT_MMIO, 0);
	if (vaddr == MAP_FAILED) {
		WD_ERR("mmap mmio fail\n");
		ret = -errno;
		goto err_with_dus;
	}
	info->mmio_base = vaddr;
	if (strstr(q->hw_type, HISI_QM_API_VER2_BASE)) {
		info->db = hacc_db_v2;
		info->doorbell_base = vaddr + QM_V2_DOORBELL_OFFSET;
	} else if (strstr(q->hw_type, HISI_QM_API_VER_BASE)) {
		info->db = hacc_db_v1;
		info->doorbell_base = vaddr + QM_DOORBELL_OFFSET;
	} else {
		WD_ERR("hw version mismatch!\n");
		ret = -EINVAL;
		goto err_with_mmio;
	}
	info->sq_tail_index = 0;
	info->sq_head_index = 0;
	info->cq_head_index = 0;
	info->cqc_phase = 1;
	info->is_sq_full = 0;
	if (!info->sqe_size) {
		WD_ERR("sqe size =%d err!\n", info->sqe_size);
		ret = -EINVAL;
		goto err_with_mmio;
	}

	if (has_dko) {
		vaddr = wd_drv_mmap_qfr(q, UACCE_QFRT_DKO, 0);
		if (vaddr == MAP_FAILED) {
			WD_ERR("mmap dko fail!\n");
			ret = -errno;
			goto err_with_mmio;
		}
		info->dko_base = vaddr;
	}
	qp_ctx.qc_type = priv->op_type;
	ret = ioctl(q->fd, UACCE_CMD_QM_SET_QP_CTX, &qp_ctx);
	if (ret < 0) {
		WD_ERR("hisi qm set qc_type fail, use default!\n");
		goto err_with_dko;
	}

	info->sqn = qp_ctx.id;

	dbg("create hisi qm queue (id = %d, sqe = %p, size = %d, type = %d)\n",
	    info->sqn, info->sq_base, info->sqe_size, qp_ctx.qc_type);
	return 0;
err_with_dko:
	if (has_dko)
		wd_drv_unmmap_qfr(q, info->dko_base, UACCE_QFRT_DKO, 0);
err_with_mmio:
	wd_drv_unmmap_qfr(q, info->mmio_base, UACCE_QFRT_MMIO, 0);
err_with_dus:
	wd_drv_unmmap_qfr(q, info->sq_base, UACCE_QFRT_DUS, 0);
err_with_info:
	free(info);
	return ret;
}

void hisi_qm_unset_queue_dio(struct wd_queue *q)
{
	struct hisi_qm_queue_info *info = (struct hisi_qm_queue_info *)q->priv;
	int has_dko = !(q->dev_flags & (UACCE_DEV_NOIOMMU | UACCE_DEV_SVA));

	if (has_dko) {
		wd_drv_unmmap_qfr(q, info->dko_base,
				  UACCE_QFRT_DKO, 0);
		wd_drv_unmmap_qfr(q, info->mmio_base, UACCE_QFRT_MMIO, 0);
	} else {
		wd_drv_unmmap_qfr(q, info->mmio_base, UACCE_QFRT_MMIO, 0);
	}
	wd_drv_unmmap_qfr(q, info->sq_base, UACCE_QFRT_DUS, 0);
	free(info);
	q->priv = NULL;
}

int hisi_qm_add_to_dio_q(struct wd_queue *q, void *req)
{
	struct hisi_qm_queue_info *info = (struct hisi_qm_queue_info *)q->priv;
	__u16 i;

	if (info->is_sq_full) {
		WD_ERR("queue is full!\n");
		return -EBUSY;
	}

	i = info->sq_tail_index;

	hisi_qm_fill_sqe(req, q->priv, i);

	mb(); /* make sure the request is all in memory before doorbell*/

	if (i == (QM_Q_DEPTH - 1))
		i = 0;
	else
		i++;

	info->db(info, DOORBELL_CMD_SQ, i, 0);

	info->sq_tail_index = i;

	if (i == info->sq_head_index)
		info->is_sq_full = 1;

	return 0;
}

int hisi_qm_get_from_dio_q(struct wd_queue *q, void **resp)
{
	struct hisi_qm_queue_info *info = (struct hisi_qm_queue_info *)q->priv;
	__u16 i = info->cq_head_index, j;
	int ret;
	struct cqe *cqe = info->cq_base + i * sizeof(struct cqe);

	if (info->cqc_phase == CQE_PHASE(cqe)) {
		j = CQE_SQ_HEAD_INDEX(cqe);
		if (j >= QM_Q_DEPTH) {
			WD_ERR("CQE_SQ_HEAD_INDEX(%d) error\n", j);
			errno = -EIO;
			return -EIO;
		}

		ret = hisi_qm_recv_sqe(info->sq_base + j * info->sqe_size,
				info, i);
		if (ret < 0) {
			WD_ERR("recv sqe error %d\n", j);
			errno = -EIO;
			return -EIO;
		}

		if (info->is_sq_full)
			info->is_sq_full = 0;
	} else
		return -EAGAIN;

	*resp = info->req_cache[i];
	info->req_cache[i] = NULL;

	if (i == (QM_Q_DEPTH - 1)) {
		info->cqc_phase = !(info->cqc_phase);
		i = 0;
	} else
		i++;

	info->db(info, DOORBELL_CMD_CQ, i, 0);

	info->cq_head_index = i;
	info->sq_head_index = i;

	return ret;
}
