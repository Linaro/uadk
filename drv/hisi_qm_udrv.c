/* SPDX-License-Identifier: Apache-2.0 */
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "hisi_qm_udrv.h"

#define DOORBELL_CMD_SQ		0
#define DOORBELL_CMD_CQ		1
#define QM_DOORBELL_OFFSET      0x340
#define QM_V2_DOORBELL_OFFSET   0x1000
#define QM_Q_DEPTH		1024
#define CQE_PHASE(cq)		(((*((__u32 *)(cq) + 3)) >> 16) & 0x1)
#define CQE_SQ_HEAD_INDEX(cq)	((*((__u32 *)(cq) + 2)) & 0xffff)

#define UACCE_CMD_QM_SET_QP_CTX	_IOWR('H', 10, struct hisi_qp_ctx)
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))

/* The max sge num in one sgl */
#define HISI_SGL_SGE_NUM_MAX 255
#define QM_SGL_NUM 16

struct hisi_qm_type {
	char	*qm_name;
	int	qm_db_offs;
	int	(*hacc_db)(struct hisi_qm_queue_info *q, __u8 cmd,
			   __u16 index, __u8 prority);
};

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

struct hisi_sge {
	uintptr_t buff;
	void *page_ctrl;
	__le32 len;
	__le32 pad;
	__le32 pad0;
	__le32 pad1;
};

/* use default hw sgl head size 64B, in little-endian */
struct hisi_sgl {
	/* the next sgl addr */
	uintptr_t next_dma;
	/* the sge num of all the sgl */
	__le16 entry_sum_in_chain;
	/* valid sge(has buff) num in this sgl */
	__le16 entry_sum_in_sgl;
	/* the sge num in this sgl */
	__le16 entry_length_in_sgl;
	__le16 pad0;
	__le64 pad1[6];

	struct hisi_sge sge_entries[];
};

struct hisi_sgl_pool {
	void **sgl;
	__u32 depth;
	__u32 top;
	__u32 sge_num;
	__u32 sgl_num;
	pthread_spinlock_t lock;
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

static int hacc_db_v2(struct hisi_qm_queue_info *q, __u8 cmd,
		      __u16 index, __u8 priority)
{
	__u16 sqn = q->sqn & 0x3ff;
	void *base = q->db_base;
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
	}
};

static void hisi_qm_fill_sqe(void *sqe, struct hisi_qm_queue_info *info,
			     __u16 tail, __u16 num)
{
	int sqe_size = info->sqe_size;
	void *sq_base = info->sq_base;
	int sqe_offset;

	if (tail + num < QM_Q_DEPTH) {
		memcpy(sq_base + tail * sqe_size, sqe, sqe_size * num);
	} else {
		sqe_offset = QM_Q_DEPTH - tail;
		memcpy(sq_base + tail * sqe_size, sqe, sqe_size * sqe_offset);
		memcpy(sq_base, sqe + sqe_size * sqe_offset, sqe_size *
		       (num - sqe_offset));
	}
}

static int hisi_qm_setup_region(handle_t h_ctx,
				struct hisi_qm_queue_info *q_info)
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

static void hisi_qm_unset_region(handle_t h_ctx,
				 struct hisi_qm_queue_info *q_info)
{
	wd_drv_unmap_qfr(h_ctx, UACCE_QFRT_DUS);
	wd_drv_unmap_qfr(h_ctx, UACCE_QFRT_MMIO);
	q_info->sq_base = NULL;
	q_info->mmio_base = NULL;
}

static int hisi_qm_setup_db(handle_t h_ctx, struct hisi_qm_queue_info *q_info)
{
	char *api_name;
	int i, size;

	size = ARRAY_SIZE(qm_type);
	api_name = wd_ctx_get_api(h_ctx);
	for (i = 0; i < size; i++) {
		if (!strncmp(api_name, qm_type[i].qm_name, strlen(api_name))) {
			q_info->db = qm_type[i].hacc_db;
			q_info->db_base = q_info->mmio_base +
					  qm_type[i].qm_db_offs;
			break;
		}
	}

	if (i == size) {
		WD_ERR("default matched type v2 of QM\n");
		q_info->db = hacc_db_v2;
		q_info->db_base = q_info->mmio_base + QM_V2_DOORBELL_OFFSET;
	}
	q_info->hw_type = i;

	return 0;
}

static int his_qm_set_qp_ctx(handle_t h_ctx, struct hisi_qm_priv *config,
			     struct hisi_qm_queue_info *q_info)
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
		WD_ERR("setup db fail\n");
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
	pthread_spin_init(&q_info->lock, PTHREAD_PROCESS_SHARED);

	return 0;

err_out:
	hisi_qm_unset_region(qp->h_ctx, q_info);
	return ret;
}

static int hisi_qm_get_free_num(struct hisi_qm_queue_info *q_info)
{
	/* The device should reserve one buffer. */
	return (QM_Q_DEPTH - 1) - q_info->used_num;
}

handle_t hisi_qm_alloc_qp(struct hisi_qm_priv *config, handle_t ctx)
{
	struct hisi_qp *qp;
	int ret;

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

	qp->h_sgl_pool = hisi_qm_create_sglpool(QM_SGL_NUM, HISI_SGL_SGE_NUM_MAX);
	if (!qp->h_sgl_pool)
		goto out_qp;

	ret = wd_ctx_start(qp->h_ctx);
	if (ret)
		goto out_qp;

	wd_ctx_set_priv(qp->h_ctx, qp);

	return (handle_t)qp;

out_qp:
	hisi_qm_destroy_sglpool(qp->h_sgl_pool);
	free(qp);
out:
	return (handle_t)NULL;
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
	hisi_qm_destroy_sglpool(qp->h_sgl_pool);

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

	pthread_spin_lock(&q_info->lock);

	free_num = hisi_qm_get_free_num(q_info);
	if (!free_num) {
		pthread_spin_unlock(&q_info->lock);
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

	pthread_spin_unlock(&q_info->lock);

	return 0;
}

static int hisi_qm_recv_single(struct hisi_qm_queue_info *q_info, void *resp)
{
	struct cqe *cqe;
	__u16 i, j;

	i = q_info->cq_head_index;
	cqe = q_info->cq_base + i * sizeof(struct cqe);

	if (q_info->cqc_phase == CQE_PHASE(cqe)) {
		j = CQE_SQ_HEAD_INDEX(cqe);
		if (j >= QM_Q_DEPTH) {
			WD_ERR("CQE_SQ_HEAD_INDEX(%d) error\n", j);
			errno = -EIO;
			return -EIO;
		}
		memcpy(resp, (void *)q_info->sq_base + j * q_info->sqe_size,
		       q_info->sqe_size);
	} else {
		return -EAGAIN;
	}

	if (i == QM_Q_DEPTH - 1) {
		q_info->cqc_phase = !(q_info->cqc_phase);
		i = 0;
	} else {
		i++;
	}

	q_info->db(q_info, DOORBELL_CMD_CQ, i, 0);

	/* only support one thread poll one queue, so no need protect */
	q_info->cq_head_index = i;
	q_info->sq_head_index = i;

	pthread_spin_lock(&q_info->lock);
	q_info->used_num--;
	pthread_spin_unlock(&q_info->lock);

	return 0;
}

int hisi_qm_recv(handle_t h_qp, void *resp, __u16 expect, __u16 *count)
{
	struct hisi_qp *qp = (struct hisi_qp*)h_qp;
	struct hisi_qm_queue_info *q_info;
	int recv_num = 0;
	int i, offset;
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

static struct hisi_sgl *hisi_qm_create_sgl(__u32 sge_num)
{
	struct hisi_sgl *sgl;
	int size;

	size = sizeof(struct hisi_sgl) + sge_num * (sizeof(struct hisi_sge));
	sgl = (struct hisi_sgl*)calloc(1, size);
	if (!sgl)
		return NULL;

	sgl->entry_sum_in_chain = sge_num;
	sgl->entry_sum_in_sgl = 0;
	sgl->entry_length_in_sgl = sge_num;
	sgl->next_dma = 0;

	return sgl;
}

handle_t hisi_qm_create_sglpool(__u32 sgl_num, __u32 sge_num)
{
	struct hisi_sgl_pool *sgl_pool;
	int ret = 0;
	int i;

	if (!sgl_num || !sge_num || sge_num > HISI_SGL_SGE_NUM_MAX) {
		WD_ERR("Create sgl_pool failed, sgl_num=%u, sge_num=%u\n",
			sgl_num, sge_num);
		return 0;
	}

	sgl_pool = calloc(1, sizeof(struct hisi_sgl_pool));
	if (!sgl_pool) {
		WD_ERR("Sgl pool alloc memory failed.\n");
		return (handle_t)0;
	}

	sgl_pool->sgl = calloc(sgl_num, sizeof(void*));
	if (!sgl_pool->sgl)
		goto err_out;

	/* base the sgl_num create the sgl chain */
	for (i = 0; i < sgl_num; i++) {
		sgl_pool->sgl[i] = hisi_qm_create_sgl(sge_num);
		if (ret)
			goto err_out;
	}

	sgl_pool->sgl_num = sgl_num;
	sgl_pool->sge_num = sge_num;
	sgl_pool->depth = sge_num;
	sgl_pool->top = sgl_num;
	pthread_spin_init(&sgl_pool->lock, PTHREAD_PROCESS_SHARED);

	return (handle_t)sgl_pool;

err_out:
	hisi_qm_destroy_sglpool((handle_t)sgl_pool);
	return (handle_t)0;
}

void hisi_qm_destroy_sglpool(handle_t sgl_pool)
{
	struct hisi_sgl_pool *pool = (struct hisi_sgl_pool*)sgl_pool;
	int i;

	if (pool) {
		if (pool->sgl) {
			for (i = 0; i < pool->sgl_num; i++)
				if (pool->sgl[i])
					free(pool->sgl[i]);

			free(pool->sgl);
		}
		free(pool);
	}

	return;
}

void hisi_qm_put_hw_sgl(handle_t sgl_pool, void *hw_sgl)
{
	struct hisi_sgl_pool *pool = (struct hisi_sgl_pool*)sgl_pool;
	struct hisi_sgl *tmp = (struct hisi_sgl*)hw_sgl;
	struct hisi_sgl *tmp1;
	int i;

	if (!pool)
		return;

	pthread_spin_lock(&pool->lock);

	/* The max hw sgl num is the pool depth */
	for (i = 0; i < pool->depth; i++) {
		if (!tmp || pool->top > pool->depth) {
			/* The pool stack is full : top > depth */
			break;
		}

		/*
		 * Because must clear the next dma befort put into the pool
		 * so we should user two tmp here.
		*/
		tmp1 = tmp;
		tmp = (struct hisi_sgl*)tmp->next_dma;

		/* Restore the para before put into the pool*/
		tmp1->next_dma = 0;
		tmp1->entry_sum_in_sgl = 0;
		tmp1->entry_sum_in_chain = pool->sge_num;
		tmp1->entry_length_in_sgl = pool->sge_num;
		pool->sgl[pool->top] = tmp;
		pool->top++;
	}

	pthread_spin_unlock(&pool->lock);
}

void *hisi_qm_get_hw_sgl(handle_t sgl_pool, struct wd_sgl *sgl)
{
	struct hisi_sgl_pool *pool = (struct hisi_sgl_pool*)sgl_pool;
	struct hisi_sgl *hw_sgl;
	struct wd_sgl *tmp = sgl;
	__u32 valid_num = 0;
	int i;

	if (!pool || !sgl) {
		WD_ERR("Get hw sgl pool or sgl is NULL\n");
		return NULL;
	}

	pthread_spin_lock(&pool->lock);

	if (pool->top == 0) {
		WD_ERR("The sgl pool is empty\n");
		pthread_spin_unlock(&pool->lock);
		return NULL;
	}

	/* The top point to the upper of data location */
	pool->top--;
	hw_sgl = pool->sgl[pool->top];

	/* Transform the data to hw data, now only support one sgl */
	for (i= 0; i < hw_sgl->entry_length_in_sgl; i++) {
		if (!tmp || !tmp->data)
			break;

		hw_sgl->sge_entries[i].buff = (uintptr_t)tmp->data;
		hw_sgl->sge_entries[i].len = tmp->len;
		tmp = tmp->next;
		valid_num++;
	}

	/* There is no valid data, reback the hw_sgl to pool */
	if (!valid_num) {
		pool->top++;
		pthread_spin_unlock(&pool->lock);
		return NULL;
	}

	hw_sgl->entry_sum_in_sgl = valid_num;

	pthread_spin_unlock(&pool->lock);

	return hw_sgl;
}

handle_t hisi_qm_get_sglpool(handle_t h_qp)
{
	struct hisi_qp *qp = (struct hisi_qp*)h_qp;
	return qp->h_sgl_pool;
}

void hisi_qm_dump_sgl(void *sgl)
{
	struct hisi_sgl *tmp = (struct hisi_sgl*)sgl;
	int i;
	while (tmp) {
		printf("sgl = %p\n", sgl);
		printf("sgl->next_dma : %lu\n", tmp->next_dma);
		printf("sgl->entry_sum_in_chain : %u\n", tmp->entry_sum_in_chain);
		printf("sgl->entry_sum_in_sgl : %u\n", tmp->entry_sum_in_sgl);
		printf("sgl->entry_length_in_sgl : %d\n", tmp->entry_length_in_sgl);
		for (i = 0; i < tmp->entry_sum_in_sgl; i++) {
			printf("sgl->sge_entries[%d].buff : 0x%lx\n", i, tmp->sge_entries[i].buff);
			printf("sgl->sge_entries[%d].len : %u\n", i, tmp->sge_entries[i].len);
		}
		printf("\n");
		tmp = (struct hisi_sgl*)tmp->next_dma;
	}
}
