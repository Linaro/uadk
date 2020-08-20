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

static void hisi_qm_fill_sqe(void *sqe, struct hisi_qm_queue_info *info, __u16 tail, __u16 num)
{
	int sqe_offset;

	if (tail + num < QM_Q_DEPTH) {
		memcpy(info->sq_base + tail * info->sqe_size, sqe, info->sqe_size * num);
	} else {
		sqe_offset = QM_Q_DEPTH - tail;
		memcpy(info->sq_base + tail * info->sqe_size, sqe, info->sqe_size * sqe_offset);
		memcpy(info->sq_base, sqe + info->sqe_size * sqe_offset, info->sqe_size * (num - sqe_offset));
	}
}

static int hisi_qm_setup_info(struct hisi_qp *qp, struct hisi_qm_priv *config)
{
	char *api_name;
	int ret = 0;
	int i, size, fd;
	struct hisi_qp_ctx qp_ctx;
	struct hisi_qm_queue_info *q_info = NULL;

	q_info = &qp->q_info;
	q_info->sq_base = wd_drv_mmap_qfr(qp->h_ctx, UACCE_QFRT_DUS, 0);
	if (q_info->sq_base == MAP_FAILED) {
		WD_ERR("fail to mmap DUS region\n");
		ret = -errno;
		goto out;
	}
	q_info->sqe_size = config->sqe_size;
	q_info->cq_base = q_info->sq_base + config->sqe_size * QM_Q_DEPTH;

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
			q_info->db_base = q_info->mmio_base + qm_type[i].qm_db_offs;
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
	qp_ctx.qc_type = config->op_type;
	fd = wd_ctx_get_fd(qp->h_ctx);
	ret = ioctl(fd, UACCE_CMD_QM_SET_QP_CTX, &qp_ctx);
	if (ret < 0) {
		WD_ERR("HISI QM fail to set qc_type, use default value\n");
		goto out_qm;
	}
	q_info->sqn = qp_ctx.id;

	return 0;

out_qm:
	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_MMIO, q_info->mmio_base);
out_mmio:
	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_DUS, q_info->sq_base);
out:
	return ret;
}

static int hisi_qm_get_free_num(struct hisi_qm_queue_info	*q_info)
{
	if (q_info->is_sq_full) {
		return 0;
	}

	return QM_Q_DEPTH - q_info->sq_tail_index + q_info->sq_head_index;
}

handle_t hisi_qm_alloc_ctx(char *node_path, void *priv, void **data)
{
	return (handle_t)NULL;
}

handle_t hisi_qm_alloc_qp(struct hisi_qm_priv *config, handle_t ctx)
{
	struct hisi_qp *qp;
	int	ret;

	if (!config)
		goto out;

	if (config->sqe_size <= 0) {
		WD_ERR("invalid sqe size (%d)\n", config->sqe_size);
		goto out;
	}

	qp = calloc(1, sizeof(struct hisi_qp));
	if (!qp)
		goto out;

	qp->h_ctx = ctx;
	wd_ctx_init_qfrs_offs(qp->h_ctx);

	ret = hisi_qm_setup_info(qp, config);
	if (ret)
		goto out_qp;

	ret = wd_ctx_start(qp->h_ctx);
	if (ret)
		goto out_qp;

	wd_ctx_set_sess_priv(qp->h_ctx, qp);

	return (handle_t)qp;

out_qp:
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


void hisi_qm_free_qp(handle_t h_qp)
{
	struct hisi_qp *qp = (struct hisi_qp*)h_qp;
	struct hisi_qm_queue_info *q_info;
	void *va;

	q_info = &qp->q_info;

	wd_ctx_stop(qp->h_ctx);
	va = wd_ctx_get_shared_va(qp->h_ctx);
	if (va) {
		wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_SS, va);
		wd_ctx_set_shared_va(qp->h_ctx, NULL);
	}
	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_MMIO, q_info->mmio_base);
	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_DUS, q_info->sq_base);
	free(qp);
}


int hisi_qm_send(handle_t h_qp, void *req, __u16 expect, __u16 *count)
{
	struct hisi_qp *qp = (struct hisi_qp*)h_qp;
	struct hisi_qm_queue_info *q_info;
	__u16 tail;
	__u16 free_num, send_num;

	if (!qp || !req || !count)
		return -EINVAL;

	q_info = &qp->q_info;

	free_num = hisi_qm_get_free_num(q_info);
	if (free_num == 0) {
		WD_ERR("queue is full!\n");
		return -EBUSY;
	}

	send_num = expect > free_num ? free_num : expect;

	tail = q_info->sq_tail_index;
	hisi_qm_fill_sqe(req, q_info, tail, send_num);

	tail = (tail + send_num) % QM_Q_DEPTH;

	q_info->db(q_info, DOORBELL_CMD_SQ, tail, 0);

	q_info->sq_tail_index = tail;

	if (tail == q_info->sq_head_index)
		q_info->is_sq_full = 1;

	*count = send_num;

	return 0;
}

static int hisi_qm_recv_single(struct hisi_qm_queue_info *q_info, void *resp)
{
	__u16 i, j;
	struct cqe *cqe;

	i = q_info->cq_head_index;
	cqe = q_info->cq_base + i * sizeof(struct cqe);

	if (q_info->cqc_phase == CQE_PHASE(cqe)) {
		j = CQE_SQ_HEAD_INDEX(cqe);
		if (j >= QM_Q_DEPTH) {
			WD_ERR("CQE_SQ_HEAD_INDEX(%d) error\n", j);
			errno = -EIO;
			return -EIO;
		}
		memcpy(resp, (void *)q_info->sq_base + j * q_info->sqe_size, q_info->sqe_size);
		if (q_info->is_sq_full)
			q_info->is_sq_full = 0;
	} else
		return -EAGAIN;

	if (i == (QM_Q_DEPTH - 1)) {
		q_info->cqc_phase = !(q_info->cqc_phase);
		i = 0;
	} else
		i++;

	q_info->db(q_info, DOORBELL_CMD_CQ, i, 0);

	q_info->cq_head_index = i;
	q_info->sq_head_index = i;

	return 0;
}

int hisi_qm_recv(handle_t h_qp, void *resp, __u16 expect, __u16 *count)
{
	int i, offset;
	int ret = 0;
	int recv_num = 0;
	struct hisi_qp *qp = (struct hisi_qp*)h_qp;
	struct hisi_qm_queue_info *q_info = NULL;

	if (!resp || !qp || !count)
		return -EINVAL;

	q_info = &qp->q_info;

	for (i = 0; i < expect; i++) {
		offset = i * q_info->sqe_size;
		ret = hisi_qm_recv_single(q_info, resp + offset);
		if (ret)
			break;
		recv_num++;
	}

	*count = recv_num++;

	return ret;
}
