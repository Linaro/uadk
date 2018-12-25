/* SPDX-License-Identifier: GPL-2.0 */
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

struct hisi_acc_qm_sqc {
	__u16 sqn;
};

struct hisi_qm_queue_info {
	void *sq_base;
	void *cq_base;
	void *doorbell_base;
	void *dko_base;
	__u16 sq_tail_index;
	__u16 sq_head_index;
	__u16 cq_head_index;
	__u16 sqn;
	bool cqc_phase;
	void *req_cache[QM_Q_DEPTH];
	int is_sq_full;
};

int hacc_db(struct hisi_qm_queue_info *q, __u8 cmd, __u16 index, __u8 priority)
{
	void *base = q->doorbell_base;
	__u16 sqn = q->sqn;
	__u64 doorbell = 0;

	doorbell = (__u64)sqn | ((__u64)cmd << 16);
	doorbell |= ((__u64)index | ((__u64)priority << 16)) << 32;

	*((__u64 *)base) = doorbell;

	return 0;
}

static int hisi_qm_fill_sqe(void *msg, struct hisi_qm_queue_info *info, __u16 i)
{
	struct hisi_qm_msg *sqe = (struct hisi_qm_msg *)info->sq_base + i;

	memcpy((void *)sqe, msg, sizeof(struct hisi_qm_msg));

	assert(!info->req_cache[i]);
	info->req_cache[i] = msg;

	return 0;
}

static int hisi_qm_recv_sqe(struct hisi_qm_msg *sqe,
			    struct hisi_qm_queue_info *info, __u16 i)
{
	__u32 status = sqe->dw3 & 0xff;
	__u32 type = sqe->dw9 & 0xff;

	if (status != 0 && status != 0x0d) {
		fprintf(stderr, "bad status (s=%d, t=%d)\n", status, type);
		return -EIO;
	}

	assert(info->req_cache[i]);
	memcpy((void *)info->req_cache[i], sqe, sizeof(struct hisi_qm_msg));
	return 0;
}

int hisi_qm_set_queue_dio(struct wd_queue *q)
{
	struct hisi_qm_queue_info *info;
	void *vaddr;
	int ret;

	alloc_obj(info);
	if (!info)
		return -1;

	q->priv = info;

	vaddr = wd_drv_mmap(q, QM_DUS_SIZE, QM_DUS_START);
	if (vaddr == MAP_FAILED) {
		ret = -errno;
		goto err_with_info;
	}
	info->sq_base = vaddr;
	info->cq_base = vaddr + QM_SQE_SIZE * QM_Q_DEPTH;

	vaddr = wd_drv_mmap(q, QM_DOORBELL_SIZE, QM_DOORBELL_START);
	if (vaddr == MAP_FAILED) {
		ret = -errno;
		goto err_with_dus;
	}
	info->doorbell_base = vaddr + QM_DOORBELL_OFFSET;
	info->sq_tail_index = 0;
	info->sq_head_index = 0;
	info->cq_head_index = 0;
	info->cqc_phase = 1;
	info->is_sq_full = 0;

#if !defined(ENABLE_NOIOMMU) && !defined(ENABLE_SVA)
	vaddr = wd_drv_mmap(q, QM_DKO_SIZE, QM_DKO_START);
	if (vaddr == MAP_FAILED) {
		ret = -errno;
		munmap(info->doorbell_base - QM_DOORBELL_OFFSET,
		       QM_DOORBELL_SIZE);
		goto err_with_dus;
	}
	info->dko_base = vaddr;
#endif

	return 0;

err_with_dus:
	munmap(info->sq_base, QM_DUS_SIZE);
err_with_info:
	free(info);
	return ret;
}

void hisi_qm_unset_queue_dio(struct wd_queue *q)
{
	struct hisi_qm_queue_info *info = (struct hisi_qm_queue_info *)q->priv;

#if !defined(ENABLE_NOIOMMU) && !defined(ENABLE_SVA)
	munmap(info->dko_base, QM_DKO_SIZE);
#endif
	munmap(info->doorbell_base - QM_DOORBELL_OFFSET, QM_DOORBELL_SIZE);
	munmap(info->sq_base, QM_DUS_SIZE);
	free(info);
	q->priv = NULL;
}

/* todo: endian-independent support */
#if ENABLE_NOIOMMU
static void _tran_addr(__u32 *addr_l, __u32 *addr_h, size_t offset)
{
	__u64 addr = ((__u64)*addr_h << 32) + *addr_l + offset;
	*addr_l = addr & 0xffffffff;
	*addr_h = addr >> 32;
}
#endif

int hisi_qm_add_to_dio_q(struct wd_queue *q, void *req)
{
	struct hisi_qm_queue_info *info = (struct hisi_qm_queue_info *)q->priv;
	__u16 i;
#if ENABLE_NOIOMMU
	struct hisi_qm_msg *msg = req;
#endif

	if (info->is_sq_full)
		return -EBUSY;

	i = info->sq_tail_index;

#if ENABLE_NOIOMMU
	_tran_addr(&msg->source_addr_l, &msg->source_addr_h,
			q->ss_pa - q->ss_va);
	_tran_addr(&msg->dest_addr_l, &msg->dest_addr_h,
			q->ss_pa - q->ss_va);
	/* todo: tran other field in the future
	 * __u32 stream_ctx_addr_l;
	 * __u32 stream_ctx_addr_h;
	 * __u32 cipher_key1_addr_l;
	 * __u32 cipher_key1_addr_h;
	 * __u32 cipher_key2_addr_l;
	 * __u32 cipher_key2_addr_h;
	 * And we can provide better interface than this
	 */
#endif

	hisi_qm_fill_sqe(req, q->priv, i);

	mb(); /* make sure the request is all in memory before doorbell*/

	if (i == (QM_Q_DEPTH - 1))
		i = 0;
	else
		i++;

	hacc_db(info, DOORBELL_CMD_SQ, i, 0);

	info->sq_tail_index = i;

	if (i == info->sq_head_index)
		info->is_sq_full = 1;

	return 0;
}

int hisi_qm_get_from_dio_q(struct wd_queue *q, void **resp)
{
	struct hisi_qm_queue_info *info = (struct hisi_qm_queue_info *)q->priv;
	__u16 i = info->cq_head_index, j;
	struct cqe *cq_base = info->cq_base;
	struct hisi_qm_msg *sq_base = info->sq_base;
	struct cqe *cqe = cq_base + i;
	struct hisi_qm_msg *sqe;
#if ENABLE_NOIOMMU
	struct hisi_qm_msg *msg;
#endif
	int ret;

	if (info->cqc_phase == CQE_PHASE(cqe)) {
		j = CQE_SQ_HEAD_INDEX(cqe);
		if (j >= QM_Q_DEPTH) {
			fprintf(stderr, "CQE_SQ_HEAD_INDEX(%d) error\n", j);
			errno = -EIO;
			return -EIO;
		}

		sqe = sq_base + j;
		ret = hisi_qm_recv_sqe(sqe, info, i);
		if (ret < 0) {
			fprintf(stderr, "recv sqe error %d\n", j);
			errno = -EIO;
			return -EIO;
		}

		if (info->is_sq_full)
			info->is_sq_full = 0;
	} else {
		return -EAGAIN;
	}

	*resp = info->req_cache[i];
#if ENABLE_NOIOMMU
	msg = *resp;
	_tran_addr(&msg->source_addr_l, &msg->source_addr_h,
			q->ss_va - q->ss_pa);
	_tran_addr(&msg->dest_addr_l, &msg->dest_addr_h,
			q->ss_va - q->ss_pa);
#endif
	info->req_cache[i] = NULL;

	if (i == (QM_Q_DEPTH - 1)) {
		info->cqc_phase = !(info->cqc_phase);
		i = 0;
	} else
		i++;

	hacc_db(info, DOORBELL_CMD_CQ, i, 0);

	info->cq_head_index = i;
	info->sq_head_index = i;

	return ret;
}

int hisi_qm_set_optype(struct wd_queue *q, __u16 type)
{
	return ioctl(q->fd, UACCE_CMD_QM_SET_OPTYPE, type);
}
