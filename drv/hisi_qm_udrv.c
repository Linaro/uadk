/* SPDX-License-Identifier: Apache-2.0 */
#include <limits.h>
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
#define VERSION_ID_SHIFT	9

#define UACCE_CMD_QM_SET_QP_CTX	_IOWR('H', 10, struct hisi_qp_ctx)
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))

/* the max sge num in one sgl */
#define HISI_SGE_NUM_IN_SGL 255

/* the max sge num in on BD, QM user it be the sgl pool size */
#define HISI_SGL_NUM_IN_BD 256

/* sgl address must be 64 bytes aligned */
#define HISI_SGL_ALIGE 64

#define HISI_MAX_SIZE_IN_SGE (1024 * 1024 * 8)

#define ADDR_ALIGN_64(addr) ((((__u64)(addr) >> 6) + 1) << 6)

struct hisi_qm_type {
	__u16	qm_ver;
	int	qm_db_offs;
	int	(*hacc_db)(struct hisi_qm_queue_info *q, __u8 cmd,
			   __u16 idx, __u8 prority);
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
	/* the next sgl address */
	uintptr_t next_dma;
	/* the sge num of all the sgl */
	__le16 entry_sum_in_chain;
	/* valid sge(has buff) num in this sgl */
	__le16 entry_sum_in_sgl;
	/* the sge num in this sgl */
	__le16 entry_length_in_sgl;
	__le16 pad0;
	__le64 pad1[5];
	/* valid sge buffs total size */
	__le64 entry_size_in_sgl;
	struct hisi_sge sge_entries[];
};

struct hisi_sgl_pool {
	/* the addr64 align offset base sgl */
	void **sgl_align;
	/* the sgl src address array*/
	void **sgl;
	/* the sgl pool stack depth */
	__u32 depth;
	__u32 top;
	__u32 sge_num;
	__u32 sgl_num;
	pthread_spinlock_t lock;
};

static int hacc_db_v1(struct hisi_qm_queue_info *q, __u8 cmd,
		      __u16 idx, __u8 priority)
{
	void *base = q->db_base;
	__u16 sqn = q->sqn;
	__u64 doorbell;

	doorbell = (__u64)sqn | ((__u64)cmd << 16);
	doorbell |= ((__u64)idx | ((__u64)priority << 16)) << 32;
	wd_iowrite64(base, doorbell);

	return 0;
}

static int hacc_db_v2(struct hisi_qm_queue_info *q, __u8 cmd,
		      __u16 idx, __u8 priority)
{
	__u16 sqn = q->sqn & 0x3ff;
	void *base = q->db_base;
	__u64 doorbell;

	doorbell = (__u64)sqn | ((__u64)(cmd & 0xf) << 12);
	doorbell |= ((__u64)idx | ((__u64)priority << 16)) << 32;
	wd_iowrite64(base, doorbell);

	return 0;
}

static struct hisi_qm_type qm_type[] = {
	{
		.qm_ver		= HISI_QM_API_VER_BASE,
		.qm_db_offs	= QM_DOORBELL_OFFSET,
		.hacc_db	= hacc_db_v1,
	}, {
		.qm_ver		= HISI_QM_API_VER2_BASE,
		.qm_db_offs	= QM_V2_DOORBELL_OFFSET,
		.hacc_db	= hacc_db_v2,
	}
};

static void hisi_qm_fill_sqe(void *sqe, struct hisi_qm_queue_info *info,
			     __u16 tail, __u16 num)
{
	int sqe_size = info->sqe_size;
	void *sq_base = info->sq_base;
	int idx;

	if (tail + num < QM_Q_DEPTH) {
		memcpy((void *)((uintptr_t)sq_base + tail * sqe_size),
			sqe, sqe_size * num);
	} else {
		idx = QM_Q_DEPTH - tail;
		memcpy((void *)((uintptr_t)sq_base + tail * sqe_size),
			sqe, sqe_size * idx);
		memcpy(sq_base, (void *)((uintptr_t)sqe + sqe_size * idx),
			sqe_size * (num - idx));
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
	return -WD_ENOMEM;
}

static void hisi_qm_unset_region(handle_t h_ctx,
				 struct hisi_qm_queue_info *q_info)
{
	wd_drv_unmap_qfr(h_ctx, UACCE_QFRT_DUS);
	wd_drv_unmap_qfr(h_ctx, UACCE_QFRT_MMIO);
	q_info->sq_base = NULL;
	q_info->mmio_base = NULL;
}

static __u32 get_version_id(handle_t h_ctx)
{
	char *api_name, *id;
	unsigned long ver;

	api_name = wd_ctx_get_api(h_ctx);
	if (strlen(api_name) <= VERSION_ID_SHIFT) {
		WD_ERR("api name error = %s\n", api_name);
		return 0;
	}

	id = api_name + VERSION_ID_SHIFT;
	ver = strtoul(id, NULL, 10);
	if (!ver || ver == ULONG_MAX) {
		WD_ERR("fail to strtoul, ver = %lu\n", ver);
		return 0;
	}

	return (__u32)ver;
}

static int hisi_qm_setup_db(handle_t h_ctx, struct hisi_qm_queue_info *q_info)
{
	__u32 ver_id;
	int i, size;

	ver_id = get_version_id(h_ctx);
	if (!ver_id)
		return -WD_EINVAL;

	q_info->hw_type = ver_id;
	size = ARRAY_SIZE(qm_type);
	for (i = 0; i < size; i++) {
		if (qm_type[i].qm_ver == ver_id) {
			q_info->db = qm_type[i].hacc_db;
			q_info->db_base = q_info->mmio_base +
					  qm_type[i].qm_db_offs;
			break;
		}
	}

	if (i == size) {
		q_info->db = hacc_db_v2;
		q_info->db_base = q_info->mmio_base + QM_V2_DOORBELL_OFFSET;
	}

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

static int hisi_qm_get_qfrs_offs(handle_t h_ctx,
				 struct hisi_qm_queue_info *q_info)
{
	q_info->region_size[UACCE_QFRT_DUS] = wd_ctx_get_region_size(h_ctx,
								UACCE_QFRT_DUS);
	if (!q_info->region_size[UACCE_QFRT_DUS]) {
		WD_ERR("fail to get DUS qfrs offset.\n");
		return -WD_EINVAL;
	}
	q_info->region_size[UACCE_QFRT_MMIO] = wd_ctx_get_region_size(h_ctx,
								UACCE_QFRT_MMIO);
	if (!q_info->region_size[UACCE_QFRT_MMIO]) {
		WD_ERR("fail to get MMIO qfrs offset.\n");
		return -WD_EINVAL;
	}

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

	ret = hisi_qm_get_qfrs_offs(qp->h_ctx, q_info);
	if (ret) {
		WD_ERR("get dev qfrs offset fail.\n");
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
	/* The last 32 bits of DUS show device or qp statuses */
	q_info->ds_tx_base = q_info->sq_base +
		q_info->region_size[UACCE_QFRT_DUS] - sizeof(uint32_t);
	q_info->ds_rx_base = q_info->ds_tx_base - sizeof(uint32_t);

	pthread_spin_init(&q_info->lock, PTHREAD_PROCESS_SHARED);

	return 0;

err_out:
	hisi_qm_unset_region(qp->h_ctx, q_info);
	return ret;
}

static int get_free_num(struct hisi_qm_queue_info *q_info)
{
	/* The device should reserve one buffer. */
	return (QM_Q_DEPTH - 1) - q_info->used_num;
}

int hisi_qm_get_free_sqe_num(handle_t h_qp)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;

	return get_free_num(&qp->q_info);
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

	qp->h_sgl_pool = hisi_qm_create_sglpool(HISI_SGL_NUM_IN_BD, HISI_SGE_NUM_IN_SGL);
	if (!qp->h_sgl_pool)
		goto out_qp;

	ret = wd_ctx_start(qp->h_ctx);
	if (ret)
		goto free_pool;

	wd_ctx_set_priv(qp->h_ctx, qp);

	return (handle_t)qp;

free_pool:
	hisi_qm_destroy_sglpool(qp->h_sgl_pool);
out_qp:
	free(qp);
out:
	return (handle_t)NULL;
}

void hisi_qm_free_qp(handle_t h_qp)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;

	if (!qp) {
		WD_ERR("h_qp is NULL.\n");
		return;
	}

	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_MMIO);
	wd_drv_unmap_qfr(qp->h_ctx, UACCE_QFRT_DUS);
	if (qp->h_sgl_pool)
		hisi_qm_destroy_sglpool(qp->h_sgl_pool);

	free(qp);
}

int hisi_qm_send(handle_t h_qp, void *req, __u16 expect, __u16 *count)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct hisi_qm_queue_info *q_info;
	__u16 free_num, send_num;
	__u16 tail;

	if (!qp || !req || !count)
		return -WD_EINVAL;

	q_info = &qp->q_info;

	pthread_spin_lock(&q_info->lock);

	if (wd_ioread32(q_info->ds_tx_base) == 1) {
		WD_ERR("wd queue hw error happened before qm send!\n");
		pthread_spin_unlock(&q_info->lock);
		return -WD_HW_EACCESS;
	}

	free_num = get_free_num(q_info);
	if (!free_num) {
		pthread_spin_unlock(&q_info->lock);
		return -WD_EBUSY;
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
			errno = -WD_EIO;
			return -WD_EIO;
		}
		memcpy(resp, (void *)((uintptr_t)q_info->sq_base +
			j * q_info->sqe_size), q_info->sqe_size);
	} else {
		return -WD_EAGAIN;
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
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct hisi_qm_queue_info *q_info;
	int recv_num = 0;
	int i, ret, offset;

	if (!resp || !qp || !count)
		return -WD_EINVAL;

	if (!expect)
		return 0;

	q_info = &qp->q_info;
	if (wd_ioread32(q_info->ds_rx_base) == 1) {
		WD_ERR("wd queue hw error happened before qm receive!\n");
		return -WD_HW_EACCESS;
	}

	for (i = 0; i < expect; i++) {
		offset = i * q_info->sqe_size;
		ret = hisi_qm_recv_single(q_info, resp + offset);
		if (ret)
			break;
		recv_num++;
	}

	*count = recv_num++;
	if (wd_ioread32(q_info->ds_rx_base) == 1) {
		WD_ERR("wd queue hw error happened in qm receive!\n");
		return -WD_HW_EACCESS;
	}

	return ret;
}

static void *hisi_qm_create_sgl(__u32 sge_num)
{
	void *sgl;
	int size;

	size = sizeof(struct hisi_sgl) +
			sge_num * (sizeof(struct hisi_sge)) + HISI_SGL_ALIGE;
	sgl = calloc(1, size);
	if (!sgl)
		return NULL;

	return sgl;
}

static struct hisi_sgl *hisi_qm_align_sgl(void *sgl, __u32 sge_num)
{
	struct hisi_sgl *sgl_align;

	/* Hardware require the address must be 64 bytes aligned */
	sgl_align = (struct hisi_sgl *)ADDR_ALIGN_64(sgl);
	sgl_align->entry_sum_in_chain = sge_num;
	sgl_align->entry_sum_in_sgl = 0;
	sgl_align->entry_length_in_sgl = sge_num;
	sgl_align->next_dma = 0;

	return sgl_align;
}

handle_t hisi_qm_create_sglpool(__u32 sgl_num, __u32 sge_num)
{
	struct hisi_sgl_pool *sgl_pool;
	int i;

	if (!sgl_num || !sge_num || sge_num > HISI_SGE_NUM_IN_SGL) {
		WD_ERR("create sgl_pool failed, sgl_num=%u, sge_num=%u\n",
			sgl_num, sge_num);
		return 0;
	}

	sgl_pool = calloc(1, sizeof(struct hisi_sgl_pool));
	if (!sgl_pool) {
		WD_ERR("sgl pool alloc memory failed.\n");
		return 0;
	}

	sgl_pool->sgl = calloc(sgl_num, sizeof(void *));
	if (!sgl_pool->sgl) {
		WD_ERR("sgl array alloc memory failed.\n");
		goto err_out;
	}

	sgl_pool->sgl_align = calloc(sgl_num, sizeof(void *));
	if (!sgl_pool->sgl_align) {
		WD_ERR("sgl align array alloc memory failed.\n");
		goto err_out;
	}

	/* base the sgl_num create the sgl chain */
	for (i = 0; i < sgl_num; i++) {
		sgl_pool->sgl[i] = hisi_qm_create_sgl(sge_num);
		if (!sgl_pool->sgl[i]) {
			WD_ERR("sgl create failed.\n");
			goto err_out;
		}

		sgl_pool->sgl_align[i] = hisi_qm_align_sgl(sgl_pool->sgl[i], sge_num);
	}

	sgl_pool->sgl_num = sgl_num;
	sgl_pool->sge_num = sge_num;
	sgl_pool->depth = sgl_num;
	sgl_pool->top = sgl_num;
	pthread_spin_init(&sgl_pool->lock, PTHREAD_PROCESS_SHARED);

	return (handle_t)sgl_pool;

err_out:
	hisi_qm_destroy_sglpool((handle_t)sgl_pool);
	return (handle_t)0;
}

void hisi_qm_destroy_sglpool(handle_t sgl_pool)
{
	struct hisi_sgl_pool *pool = (struct hisi_sgl_pool *)sgl_pool;
	int i;

	if (!pool) {
		WD_ERR("sgl_pool is NULL\n");
		return;
	}
	if (pool->sgl) {
		for (i = 0; i < pool->sgl_num; i++)
			if (pool->sgl[i])
				free(pool->sgl[i]);

		free(pool->sgl);
	}

	if (pool->sgl_align)
		free(pool->sgl_align);
	free(pool);
}

static struct hisi_sgl *hisi_qm_sgl_pop(struct hisi_sgl_pool *pool)
{
	struct hisi_sgl *hw_sgl;

	pthread_spin_lock(&pool->lock);

	if (pool->top == 0) {
		WD_ERR("The sgl pool is empty\n");
		pthread_spin_unlock(&pool->lock);
		return NULL;
	}

	pool->top--;
	hw_sgl = pool->sgl_align[pool->top];
	pthread_spin_unlock(&pool->lock);
	return hw_sgl;
}

static int hisi_qm_sgl_push(struct hisi_sgl_pool *pool, struct hisi_sgl *hw_sgl)
{
	pthread_spin_lock(&pool->lock);
	if (pool->top >= pool->depth) {
		WD_ERR("The sgl pool is full\n");
		pthread_spin_unlock(&pool->lock);
		return -WD_EINVAL;
	}

	hw_sgl->next_dma = 0;
	hw_sgl->entry_sum_in_sgl = 0;
	hw_sgl->entry_sum_in_chain = pool->sge_num;
	hw_sgl->entry_length_in_sgl = pool->sge_num;
	hw_sgl->entry_size_in_sgl = 0;

	pool->sgl_align[pool->top] = hw_sgl;
	pool->top++;
	pthread_spin_unlock(&pool->lock);

	return 0;
}

void hisi_qm_put_hw_sgl(handle_t sgl_pool, void *hw_sgl)
{
	struct hisi_sgl_pool *pool = (struct hisi_sgl_pool *)sgl_pool;
	struct hisi_sgl *cur = (struct hisi_sgl *)hw_sgl;
	struct hisi_sgl *next = (struct hisi_sgl *)hw_sgl;
	int ret;

	if (!pool)
		return;

	while (cur) {
		next = (struct hisi_sgl *)cur->next_dma;
		ret = hisi_qm_sgl_push(pool, cur);
		if (ret)
			break;

		cur = next;
	}

	return;
}

void *hisi_qm_get_hw_sgl(handle_t sgl_pool, struct wd_datalist *sgl)
{
	struct hisi_sgl_pool *pool = (struct hisi_sgl_pool *)sgl_pool;
	struct wd_datalist *tmp = sgl;
	struct hisi_sgl *head;
	struct hisi_sgl *next;
	struct hisi_sgl *cur;
	int i = 0;

	if (!pool || !sgl) {
		WD_ERR("get hw sgl pool or sgl is NULL\n");
		return NULL;
	}

	head = hisi_qm_sgl_pop(pool);
	if (!head)
		return NULL;

	cur = head;
	tmp = sgl;
	while (tmp) {
		/* if the user's data is NULL, jump next one */
		if (!tmp->data || tmp->len == 0) {
			tmp = tmp->next;
			continue;
		}

		if (tmp->len > HISI_MAX_SIZE_IN_SGE) {
			WD_ERR("the data len is invalid: %u\n", tmp->len);
			goto err_out;
		}

		cur->sge_entries[i].buff = (uintptr_t)tmp->data;
		cur->sge_entries[i].len = tmp->len;
		cur->entry_sum_in_sgl++;
		cur->entry_size_in_sgl += tmp->len;
		i++;

		/*
		 * If current sgl chain is full and there is still user sgl data,
		 * we should allocate another hardware sgl to hold up them until
		 * the sgl pool is not enough or all the data is transform to
		 * hardware sgl.
		 */
		if (i == pool->sge_num && tmp->next) {
			next = hisi_qm_sgl_pop(pool);
			if (!next) {
				WD_ERR("the sgl pool is not enough");
				goto err_out;
			}
			cur->next_dma = (uintptr_t)next;
			cur = next;
			head->entry_sum_in_chain += pool->sge_num;
			/* In the new sgl chain, the subscript must be reset */
			i = 0;
		}

		tmp = tmp->next;
	}

	/* There is no data, recycle the hardware sgl head to pool */
	if (!head->entry_sum_in_chain)
		goto err_out;

	return head;
err_out:
	hisi_qm_put_hw_sgl(sgl_pool, head);
	return NULL;
}

handle_t hisi_qm_get_sglpool(handle_t h_qp)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;

	return qp->h_sgl_pool;
}

static void hisi_qm_sgl_copy_inner(void *dst_buff, struct hisi_sgl *hw_sgl,
				   int begin_sge, __u32 sge_offset, __u32 size)
{
	struct hisi_sgl *tmp = hw_sgl;
	__u32 offset = 0;
	__u32 len;
	int i;

	len = tmp->sge_entries[begin_sge].len - sge_offset;
	/* the first one is enough for copy size, copy and return*/
	if (len >= size) {
		memcpy(dst_buff, (void *)tmp->sge_entries[begin_sge].buff + sge_offset, size);
		return;
	}

	memcpy(dst_buff, (void *)tmp->sge_entries[begin_sge].buff + sge_offset, len);
	offset += len;

	i = begin_sge + 1;

	while (tmp) {
		for (; i < tmp->entry_sum_in_sgl; i++) {
			if (offset + tmp->sge_entries[i].len >= size) {
				memcpy(dst_buff + offset, (void *)tmp->sge_entries[i].buff, size - offset);
				return;
			}

			memcpy(dst_buff + offset, (void *)tmp->sge_entries[i].buff, tmp->sge_entries[i].len);
			offset += tmp->sge_entries[i].len;
		}

		tmp = (struct hisi_sgl *)tmp->next_dma;
		i = 0;
	}
}

void hisi_qm_sgl_copy(void *dst_buff, void *hw_sgl, __u32 offset, __u32 size)
{
	struct hisi_sgl *tmp = (struct hisi_sgl *)hw_sgl;
	__u32 len = 0;
	__u32 sge_offset = 0;
	int begin_sge = 0;
	int i;

	if (!dst_buff || !hw_sgl || !size)
		return;

	/* find the sgl chain position */
	while (tmp) {
		/* the sgl chain is find */
		if (len + tmp->entry_size_in_sgl > offset)
			break;

		/* the offset is over the sgl */
		if (!tmp->next_dma)
			return;

		tmp = (struct hisi_sgl *)tmp->next_dma;
		len += tmp->entry_size_in_sgl;
	}

	if (!tmp)
		return;

	/* find the start sge position and start offset */
	for (i = 0; i < tmp->entry_sum_in_sgl; i++) {
		if (len + tmp->sge_entries[i].len > offset) {
			begin_sge = i;
			sge_offset = offset - len;
			break;
		}
		if(len + tmp->sge_entries[i].len == offset) {
			begin_sge = i + 1;
			sge_offset = 0;
			break;
		}

		len += tmp->sge_entries[i].len;
	}

	hisi_qm_sgl_copy_inner(dst_buff, tmp, begin_sge, sge_offset, size);
}

void hisi_qm_dump_sgl(void *sgl)
{
	struct hisi_sgl *tmp = (struct hisi_sgl *)sgl;
	int i;

	while (tmp) {
		printf("sgl = %p\n", tmp);
		printf("sgl->next_dma : 0x%lx\n", tmp->next_dma);
		printf("sgl->entry_sum_in_chain : %u\n", tmp->entry_sum_in_chain);
		printf("sgl->entry_sum_in_sgl : %u\n", tmp->entry_sum_in_sgl);
		printf("sgl->entry_length_in_sgl : %d\n", tmp->entry_length_in_sgl);
		for (i = 0; i < tmp->entry_sum_in_sgl; i++) {
			printf("sgl->sge_entries[%d].buff : 0x%lx\n", i, tmp->sge_entries[i].buff);
			printf("sgl->sge_entries[%d].len : %u\n", i, tmp->sge_entries[i].len);
		}
		tmp = (struct hisi_sgl *)tmp->next_dma;
	}
}
