/* SPDX-License-Identifier: Apache-2.0 */
#include "config.h"
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hisi_qm_udrv.h"
#include "wd.h"

#define QM_SQE_SIZE		128 /* TODO: get it from sysfs */
#define QM_CQE_SIZE		16

#define DOORBELL_CMD_SQ		0
#define DOORBELL_CMD_CQ		1

/* cqe shift */
#define CQE_PHASE(cq)	(((*((__u32 *)(cq) + 3)) >> 16) & 0x1)
#define CQE_SQ_NUM(cq)	((*((__u32 *)(cq) + 2)) >> 16)
#define CQE_SQ_HEAD_INDEX(cq)	((*((__u32 *)(cq) + 2)) & 0xffff)

struct hisi_qm_type {
	char	*qm_name;
	int	qm_db_offs;
	int	(*hacc_db)(struct hisi_qm_queue_info *q, __u8 cmd,
			   __u16 index, __u8 prority);
};

static int hacc_db_v1(struct hisi_qm_queue_info *q, __u8 cmd,
		      __u16 index, __u8 priority)
{
	void *base = q->db_base;
	__u16 sqn = q->sqn;
	__u64 doorbell = 0;

	doorbell = (__u64)sqn | ((__u64)cmd << 16);
	doorbell |= ((__u64)index | ((__u64)priority << 16)) << 32;
	wd_iowrite64(base, doorbell);
	return 0;
}

/* Only Hi1620 CS, we just need version 2 doorbell. */
static int hacc_db_v2(struct hisi_qm_queue_info *q, __u8 cmd,
		      __u16 index, __u8 priority)
{
	void *base = q->db_base;
	__u16 sqn = q->sqn & 0x3ff;
	__u64 doorbell = 0;

	doorbell = (__u64)sqn | ((__u64)(cmd & 0xf) << 12);
	doorbell |= ((__u64)index | ((__u64)priority << 16)) << 32;
	wd_iowrite64(base, doorbell);
	return 0;
}

static struct hisi_qm_type qm_type[] = {
	{
		.qm_name	= "hisi_qm_v1",
		.qm_db_offs	= QM_DOORBELL_OFFSET,
		.hacc_db	= hacc_db_v1,
	}, {
		.qm_name	= "hisi_qm_v2",
		.qm_db_offs	= QM_V2_DOORBELL_OFFSET,
		.hacc_db	= hacc_db_v2,
	},
};

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

handle_t hisi_qm_alloc_ctx(char *node_path, void *priv, void **data)
{
	struct hisi_qp_ctx		qp_ctx;
	struct hisi_qm_priv		*qm_priv = (struct hisi_qm_priv *)priv;
	struct hisi_qp			*qp;
	struct hisi_qm_queue_info	*q_info;
	int	i, size, fd, ret;
	char	*api_name;

	if (!priv || !data)
		goto out;
	if (qm_priv->sqe_size <= 0) {
		WD_ERR("invalid sqe size (%d)\n", qm_priv->sqe_size);
		goto out;
	}

	qp = calloc(1, sizeof(struct hisi_qp));
	if (!qp)
		goto out;
	*data = qp;

	qp->h_ctx = wd_request_ctx(node_path);
	if (!qp->h_ctx)
		goto out_ctx;

	wd_ctx_init_qfrs_offs(qp->h_ctx);

	q_info = &qp->q_info;
	q_info->sq_base = wd_drv_mmap_qfr(qp->h_ctx, UACCE_QFRT_DUS, 0);
	if (q_info->sq_base == MAP_FAILED) {
		WD_ERR("fail to mmap DUS region\n");
		ret = -errno;
		goto out_mmap;
	}
	q_info->sqe_size = qm_priv->sqe_size;
	q_info->cq_base = q_info->sq_base + qm_priv->sqe_size * QM_Q_DEPTH;

	q_info->mmio_base = wd_drv_mmap_qfr(qp->h_ctx, UACCE_QFRT_MMIO, 0);
	if (q_info->mmio_base == MAP_FAILED) {
		WD_ERR("fail to mmap MMIO region\n");
		ret = -errno;
		goto out_mmio;
	}
	size = ARRAY_SIZE(qm_type);
	api_name = wd_ctx_get_api(qp->h_ctx);
	for (i = 0; i < size; i++) {
		if (!strncmp(api_name, qm_type[i].qm_name, strlen(api_name))) {
			q_info->db = qm_type[i].hacc_db;
			q_info->db_base = q_info->mmio_base +
					  qm_type[i].qm_db_offs;
			break;
		}
	}
	if (i == size) {
		WD_ERR("fail to find matched type of QM\n");
		ret = -ENODEV;
		goto out_qm;
	}
	q_info->sq_tail_index = 0;
	q_info->sq_head_index = 0;
	q_info->cq_head_index = 0;
	q_info->cqc_phase = 1;
	q_info->is_sq_full = 0;
	memset(&qp_ctx, 0, sizeof(struct hisi_qp_ctx));
	qp_ctx.qc_type = qm_priv->op_type;
	fd = wd_ctx_get_fd(qp->h_ctx);
	ret = ioctl(fd, UACCE_CMD_QM_SET_QP_CTX, &qp_ctx);
	if (ret < 0) {
		WD_ERR("HISI QM fail to set qc_type, use default value\n");
		goto out_qm;
	}
	q_info->sqn = qp_ctx.id;

	ret = wd_ctx_start(qp->h_ctx);
	if (ret)
		goto out_qm;
	wd_ctx_set_sess_priv(qp->h_ctx, qp);
	return qp->h_ctx;

out_qm:
	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_MMIO, q_info->mmio_base);
out_mmio:
	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_DUS, q_info->sq_base);
out_mmap:
	wd_release_ctx(qp->h_ctx);
out_ctx:
	free(qp);
out:
	return (handle_t)NULL;
}

void hisi_qm_free_ctx(handle_t h_ctx)
{
	struct hisi_qp			*qp;
	struct hisi_qm_queue_info	*q_info;
	void	*va;

	qp = (struct hisi_qp *)wd_ctx_get_sess_priv(h_ctx);
	q_info = &qp->q_info;

	wd_ctx_stop(qp->h_ctx);
	va = wd_ctx_get_shared_va(qp->h_ctx);
	if (va) {
		wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_SS, va);
		wd_ctx_set_shared_va(qp->h_ctx, NULL);
	}
	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_MMIO, q_info->mmio_base);
	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_DUS, q_info->sq_base);
	wd_release_ctx(qp->h_ctx);
}

int hisi_qm_send(handle_t h_ctx, void *req)
{
	struct hisi_qp			*qp;
	struct hisi_qm_queue_info	*q_info;
	__u16 i;

	qp = (struct hisi_qp *)wd_ctx_get_sess_priv(h_ctx);
	if (!qp)
		return -EINVAL;
	q_info = &qp->q_info;
	if (q_info->is_sq_full) {
		WD_ERR("queue is full!\n");
		return -EBUSY;
	}

	i = q_info->sq_tail_index;

	hisi_qm_fill_sqe(req, q_info, i);

	if (i == (QM_Q_DEPTH - 1))
		i = 0;
	else
		i++;

	q_info->db(q_info, DOORBELL_CMD_SQ, i, 0);

	q_info->sq_tail_index = i;

	if (i == q_info->sq_head_index)
		q_info->is_sq_full = 1;

	return 0;
}

int hisi_qm_recv(handle_t h_ctx, void **resp)
{
	struct hisi_qp			*qp;
	struct hisi_qm_queue_info	*q_info;
	__u16 i, j;
	int ret;
	struct cqe *cqe;

	qp = (struct hisi_qp *)wd_ctx_get_sess_priv(h_ctx);
	q_info = &qp->q_info;
	i = q_info->cq_head_index;
	cqe = q_info->cq_base + i * sizeof(struct cqe);

	if (q_info->cqc_phase == CQE_PHASE(cqe)) {
		j = CQE_SQ_HEAD_INDEX(cqe);
		if (j >= QM_Q_DEPTH) {
			WD_ERR("CQE_SQ_HEAD_INDEX(%d) error\n", j);
			errno = -EIO;
			return -EIO;
		}

		ret = hisi_qm_recv_sqe(q_info->sq_base + j * q_info->sqe_size,
				       q_info, i);
		if (ret < 0) {
			WD_ERR("recv sqe error %d\n", j);
			errno = -EIO;
			return -EIO;
		}

		if (q_info->is_sq_full)
			q_info->is_sq_full = 0;
	} else {
		/* enable interrupt for poll notifying */
		q_info->db(q_info, DOORBELL_CMD_CQ, i, 1);
		return -EAGAIN;
	}

	*resp = q_info->req_cache[i];
	q_info->req_cache[i] = NULL;

	if (i == (QM_Q_DEPTH - 1)) {
		q_info->cqc_phase = !(q_info->cqc_phase);
		i = 0;
	} else
		i++;

	/* disable interrupt, keep reading */
	q_info->db(q_info, DOORBELL_CMD_CQ, i, 0);

	q_info->cq_head_index = i;
	q_info->sq_head_index = i;

	return ret;
}
