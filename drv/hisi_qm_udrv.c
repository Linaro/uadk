/* SPDX-License-Identifier: Apache-2.0 */
#include "config.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "wd.h"
#include "hisi_qm_udrv.h"

#define QM_SQE_SIZE		128 /* TODO: get it from sysfs */
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
	void *db_base;
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

struct hisi_qm_type {
	char	*qm_name;
	int	qm_db_offs;
	int	(*hacc_db)(struct hisi_qm_queue_info *q, __u8 cmd,
			   __u16 index, __u8 prority);
};

struct hisi_qm_ctx {
	struct hisi_qm_queue_info	q_info;
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

int hisi_qm_alloc_ctx(struct wd_ctx *ctx, void *data)
{
	struct hisi_qm_capa		*capa;
	struct hisi_qm_ctx		*ctx_priv;
	struct hisi_qm_priv		*capa_priv;
	struct hisi_qm_queue_info	*q_info;
	struct hisi_qp_ctx		qp_ctx;
	int	i, size, ret;
	char	*api_name;

	capa = (struct hisi_qm_capa *)data;
	capa_priv = (struct hisi_qm_priv *)capa->priv;
	if (capa_priv->sqe_size <= 0) {
		WD_ERR("invalid sqe size (%d)\n", capa_priv->sqe_size);
		return -EINVAL;
	}
	ctx_priv = calloc(1, sizeof(struct hisi_qm_ctx));
	if (ctx_priv == NULL)
		return -ENOMEM;

	memcpy(&ctx->qfrs_offs, &ctx->dev_info->qfrs_offs,
	       sizeof(ctx->qfrs_offs));

	q_info = &ctx_priv->q_info;
	q_info->sq_base = wd_drv_mmap_qfr(ctx, UACCE_QFRT_DUS, 0);
	if (q_info->sq_base == MAP_FAILED) {
		WD_ERR("fail to mmap DUS region\n");
		ret = -errno;
		goto out;
	}
	q_info->sqe_size = capa_priv->sqe_size;
	q_info->cq_base = q_info->sq_base + capa_priv->sqe_size * QM_Q_DEPTH;

	q_info->mmio_base = wd_drv_mmap_qfr(ctx, UACCE_QFRT_MMIO, 0);
	if (q_info->mmio_base == MAP_FAILED) {
		WD_ERR("fail to mmap MMIO region\n");
		ret = -errno;
		goto out_mmio;
	}
	size = ARRAY_SIZE(qm_type);
	api_name = ctx->dev_info->api;
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
	qp_ctx.qc_type = capa_priv->op_type;
	ret = ioctl(ctx->fd, UACCE_CMD_QM_SET_QP_CTX, &qp_ctx);
	if (ret < 0) {
		WD_ERR("HISI QM fail to set qc_type, use default value\n");
		goto out_qm;
	}
	q_info->sqn = qp_ctx.id;
	ctx->priv = ctx_priv;
	return 0;

out_qm:
	wd_drv_unmap_qfr(ctx, UACCE_QFRT_MMIO, q_info->mmio_base);
out_mmio:
	wd_drv_unmap_qfr(ctx, UACCE_QFRT_DUS, q_info->sq_base);
out:
	free(ctx_priv);
	return ret;
}

void hisi_qm_free_ctx(struct wd_ctx *ctx)
{
	struct hisi_qm_ctx		*ctx_priv;
	struct hisi_qm_queue_info	*q_info;

	if (ctx->ss_va)
		wd_drv_unmap_qfr(ctx, UACCE_QFRT_SS, ctx->ss_va);
	ctx_priv = (struct hisi_qm_ctx *)ctx->priv;
	q_info = &ctx_priv->q_info;
	wd_drv_unmap_qfr(ctx, UACCE_QFRT_MMIO, q_info->mmio_base);
	wd_drv_unmap_qfr(ctx, UACCE_QFRT_DUS, q_info->sq_base);
	free(ctx_priv);
}

int hisi_qm_send(struct wd_ctx *ctx, void *req)
{
	struct hisi_qm_ctx		*ctx_priv;
	struct hisi_qm_queue_info	*q_info;
	__u16 i;

	ctx_priv = (struct hisi_qm_ctx *)ctx->priv;
	q_info = &ctx_priv->q_info;
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

int hisi_qm_recv(struct wd_ctx *ctx, void **resp)
{
	struct hisi_qm_ctx		*ctx_priv;
	struct hisi_qm_queue_info	*q_info;
	__u16 i, j;
	int ret;
	struct cqe *cqe;

	ctx_priv = (struct hisi_qm_ctx *)ctx->priv;
	q_info = &ctx_priv->q_info;
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
	} else
		return -EAGAIN;

	*resp = q_info->req_cache[i];
	q_info->req_cache[i] = NULL;

	if (i == (QM_Q_DEPTH - 1)) {
		q_info->cqc_phase = !(q_info->cqc_phase);
		i = 0;
	} else
		i++;

	q_info->db(q_info, DOORBELL_CMD_CQ, i, 0);

	q_info->cq_head_index = i;
	q_info->sq_head_index = i;

	return ret;
}
