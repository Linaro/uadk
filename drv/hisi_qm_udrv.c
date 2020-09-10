/* SPDX-License-Identifier: Apache-2.0 */
#include "config.h"
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hisi_qm_udrv.h"
#include "wd.h"
#include "wd_alg_common.h"

#define QM_SQE_SIZE		128 /* TODO: get it from sysfs */
#define QM_CQE_SIZE		16

#define DOORBELL_CMD_SQ		0
#define DOORBELL_CMD_CQ		1

/* cqe shift */
#define CQE_PHASE(cq)	(((*((__u32 *)(cq) + 3)) >> 16) & 0x1)
#define CQE_SQ_NUM(cq)	((*((__u32 *)(cq) + 2)) >> 16)
#define CQE_SQ_HEAD_INDEX(cq)	((*((__u32 *)(cq) + 2)) & 0xffff)

#define ARRAY_SIZE(x)			(sizeof(x) / sizeof((x)[0]))

struct hisi_qm_type {
	char	*qm_name;
	int	qm_db_offs;
	int	(*hacc_db)(struct hisi_qm_queue_info *q, __u8 cmd,
			   __u16 index, __u8 prority);
};

#define QM_CQE_SIZE			16

/* default queue depth for sq/cq/eq */
#define QM_Q_DEPTH			1024

/* page number for queue file region */
#define QM_DOORBELL_PAGE_NR	1
#define QM_DKO_PAGE_NR		4
#define QM_DUS_PAGE_NR		36

#define QM_DOORBELL_PG_START 0
#define QM_DKO_PAGE_START (QM_DOORBELL_PG_START + QM_DOORBELL_PAGE_NR)
#define QM_DUS_PAGE_START (QM_DKO_PAGE_START + QM_DKO_PAGE_NR)
#define QM_SS_PAGE_START (QM_DUS_PAGE_START + QM_DUS_PAGE_NR)

#define QM_DOORBELL_OFFSET      0x340
#define QM_V2_DOORBELL_OFFSET   0x1000

struct cqe {
	__le32 rsvd0;
	__le16 cmd_id;
	__le16 rsvd1;
	__le16 sq_head;
	__le16 sq_num;
	__le16 rsvd2;
	__le16 w7;
};

struct hisi_qp_ctx {
	__u16 id;
	__u16 qc_type;
};

#define HISI_QM_API_VER_BASE "hisi_qm_v1"
#define HISI_QM_API_VER2_BASE "hisi_qm_v2"

#define UACCE_CMD_QM_SET_QP_CTX	_IOWR('H', 10, struct hisi_qp_ctx)

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
	int sqe_size = info->sqe_size;
	void *sq_base = info->sq_base;

	if (tail + num < QM_Q_DEPTH) {
		memcpy(sq_base + tail * sqe_size, sqe, sqe_size * num);
	} else {
		sqe_offset = QM_Q_DEPTH - tail;
		memcpy(sq_base + tail * sqe_size, sqe, sqe_size * sqe_offset);
		memcpy(sq_base, sqe + sqe_size * sqe_offset, sqe_size * (num - sqe_offset));
	}
}

static int hisi_qm_setup_region(handle_t h_ctx, struct hisi_qm_queue_info *q_info)
{
	q_info->sq_base = wd_drv_mmap_qfr(h_ctx, UACCE_QFRT_DUS);
	if (q_info->sq_base == MAP_FAILED) {
		WD_ERR("mmap dus fail\n");
		goto err_out;
	}

	q_info->mmio_base = wd_drv_mmap_qfr(h_ctx, UACCE_QFRT_MMIO);
	if (q_info->mmio_base == MAP_FAILED) {
		wd_drv_unmap_qfr(h_ctx, UACCE_QFRT_DUS);
		WD_ERR("mmap mmio fail\n");
		goto err_out;
	}

	return 0;
err_out:
	q_info->sq_base = NULL;
	q_info->mmio_base = NULL;
	return -ENOMEM;
}

static void hisi_qm_unset_region(handle_t h_ctx, struct hisi_qm_queue_info *q_info)
{
	wd_drv_unmap_qfr(h_ctx, UACCE_QFRT_DUS);
	wd_drv_unmap_qfr(h_ctx, UACCE_QFRT_MMIO);
	q_info->sq_base = NULL;
	q_info->mmio_base = NULL;
}

static int hisi_qm_setup_db(handle_t h_ctx, struct hisi_qm_queue_info *q_info)
{
	int i, size;
	char *api_name;

	size = ARRAY_SIZE(qm_type);
	api_name = wd_ctx_get_api(h_ctx);
	for (i = 0; i < size; i++) {
		if (!strncmp(api_name, qm_type[i].qm_name, strlen(api_name))) {
			q_info->db = qm_type[i].hacc_db;
			q_info->db_base = q_info->mmio_base + qm_type[i].qm_db_offs;
			break;
		}
	}

	if (i == size) {
		WD_ERR("fail to find matched type of QM\n");
		return -ENODEV;
	}

	return 0;
}

static int his_qm_set_qp_ctx(handle_t h_ctx, struct hisi_qm_priv *config, struct hisi_qm_queue_info *q_info)
{
	struct hisi_qp_ctx qp_ctx;
	int ret;

	memset(&qp_ctx, 0, sizeof(struct hisi_qp_ctx));
	qp_ctx.qc_type = config->op_type;
	q_info->qc_type = qp_ctx.qc_type;
	ret = wd_ctx_set_io_cmd(h_ctx, UACCE_CMD_QM_SET_QP_CTX, &qp_ctx);
	if (ret < 0) {
		WD_ERR("HISI QM fail to set qc_type, use default value\n");
		return ret;
	}

	q_info->sqn = qp_ctx.id;

	return 0;
}

static int hisi_qm_setup_info(struct hisi_qp *qp, struct hisi_qm_priv *config)
{
	struct hisi_qm_queue_info *q_info = NULL;
	int ret;

	q_info = &qp->q_info;
	ret = hisi_qm_setup_region(qp->h_ctx, q_info);
	if (ret) {
		WD_ERR("setup region fail\n");
		return ret;
	}

	ret = hisi_qm_setup_db(qp->h_ctx, q_info);
	if (ret) {
		WD_ERR("setup region fail\n");
		goto err_out;
	}

	ret = his_qm_set_qp_ctx(qp->h_ctx, config, q_info);
	if (ret) {
		WD_ERR("setup io cmd fail\n");
		goto err_out;
	}

	q_info->sqe_size = config->sqe_size;
	q_info->cqc_phase = 1;
	q_info->cq_base = q_info->sq_base + config->sqe_size * QM_Q_DEPTH;

#if 0
	size = sizeof(struct cqe) * QM_Q_DEPTH;
	ret = mprotect(q_info->cq_base, size, PROT_READ);
	if (ret) {
		WD_ERR("cqe mprotect set err!\n");
		goto err_out;
	}
#endif

	return 0;

err_out:
	hisi_qm_unset_region(qp->h_ctx, q_info);
	return ret;
}

static int hisi_qm_get_free_num(struct hisi_qm_queue_info	*q_info)
{
	/* The device should reserve one buffer. */
	return (QM_Q_DEPTH - 1) - q_info->used_num;
}

handle_t hisi_qm_alloc_ctx(char *dev_path, void *priv, void **data)
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

	ret = hisi_qm_setup_info(qp, config);
	if (ret)
		goto out_qp;

	ret = wd_ctx_start(qp->h_ctx);
	if (ret)
		goto out_qp;

	wd_ctx_set_priv(qp->h_ctx, qp);

	return (handle_t)qp;

out_qp:
	free(qp);
out:
	return (handle_t)NULL;
}


void hisi_qm_free_ctx(handle_t h_ctx)
{
	struct hisi_qp *qp = wd_ctx_get_priv(h_ctx);

	wd_release_ctx_force(qp->h_ctx);

	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_MMIO);
	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_DUS);
	wd_release_ctx(qp->h_ctx);
}


void hisi_qm_free_qp(handle_t h_qp)
{
	struct hisi_qp *qp = (struct hisi_qp*)h_qp;
	if (!qp) {
		WD_ERR("h_qp is NULL.\n");
		return;
	}

	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_MMIO);
	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_DUS);

	free(qp);
}


int hisi_qm_send(handle_t h_qp, void *req, __u16 expect, __u16 *count)
{
	struct hisi_qp *qp = (struct hisi_qp*)h_qp;
	struct hisi_qm_queue_info *q_info;
	__u16 free_num, send_num;
	__u16 tail;

	if (!qp || !req || !count)
		return -EINVAL;

	q_info = &qp->q_info;

	free_num = hisi_qm_get_free_num(q_info);
	if (!free_num) {
		return -EBUSY;
	}

	send_num = expect > free_num ? free_num : expect;

	tail = q_info->sq_tail_index;
	hisi_qm_fill_sqe(req, q_info, tail, send_num);
	tail = (tail + send_num) % QM_Q_DEPTH;
	q_info->db(q_info, DOORBELL_CMD_SQ, tail, 0);
	q_info->sq_tail_index = tail;
	q_info->used_num += send_num;
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
	} else
		return -EAGAIN;

	if (i == QM_Q_DEPTH - 1) {
		q_info->cqc_phase = !(q_info->cqc_phase);
		i = 0;
	} else
		i++;

	q_info->db(q_info, DOORBELL_CMD_CQ, i, 0);

	q_info->cq_head_index = i;
	q_info->sq_head_index = i;
	q_info->used_num--;

	return 0;
}

int hisi_qm_recv(handle_t h_qp, void *resp, __u16 expect, __u16 *count)
{
	struct hisi_qp *qp = (struct hisi_qp*)h_qp;
	struct hisi_qm_queue_info *q_info;
	int i, offset;
	int recv_num = 0;
	int ret = 0;

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
