/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <asm/byteorder.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "hisi_qm_udrv.h"
#include "wd_util.h"

#define QM_DBELL_CMD_SQ		0
#define QM_DBELL_CMD_CQ		1
#define QM_DBELL_OFFSET		0x340
#define QM_DBELL_OFFSET_V2	0x1000
#define QM_DBELL_CMD_SHIFT	16
#define QM_DBELL_CMD_SHIFT_V2	12
#define QM_DBELL_PRI_SHIFT	16
#define QM_DBELL_HLF_SHIFT	32
#define QM_DBELL_SQN_MASK	0x3ff
#define QM_DBELL_CMD_MASK	0xf
#define QM_Q_DEPTH		1024
#define CQE_PHASE(cqe)		(__le16_to_cpu((cqe)->w7) & 0x1)
#define CQE_SQ_HEAD_INDEX(cqe)	(__le16_to_cpu((cqe)->sq_head) & 0xffff)
#define VERSION_ID_SHIFT	9

#define UACCE_CMD_QM_SET_QP_CTX		_IOWR('H', 10, struct hisi_qp_ctx)
#define UACCE_CMD_QM_SET_QP_INFO	_IOWR('H', 11, struct hisi_qp_info)
#define ARRAY_SIZE(x)			(sizeof(x) / sizeof((x)[0]))

/* the max sge num in one sgl */
#define HISI_SGE_NUM_IN_SGL 255

/* the max sge num in on BD, QM user it be the sgl pool size */
#define HISI_SGL_NUM_IN_BD 256

/* sgl address must be 64 bytes aligned */
#define HISI_SGL_ALIGE 64

#define HISI_MAX_SIZE_IN_SGE (1024 * 1024 * 8)

#define ADDR_ALIGN_64(addr) ((((uintptr_t)(addr) >> 6) + 1) << 6)

#define QM_TYPE_USAGE_OFFSET	0x1100
#define QM_DEV_USAGE_OFFSET	16
#define QM_CHANNEL_ADDR_INTRVL	0x4
#define QM_MAX_DEV_USAGE	100
#define QM_DEV_USAGE_RATE	100

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

struct hisi_qp_info {
	__u32 sqe_size;
	__u16 sq_depth;
	__u16 cq_depth;
	__u64 reserved;
};

struct hisi_sge {
	uintptr_t buff;
	void *page_ctrl;
	__le32 len;
	__le32 pad;
	uintptr_t vbuff;
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
	__le64 pad1[4];
	struct hisi_sgl *next;
	/* valid sge buffs total size */
	__le64 entry_size_in_sgl;
	struct hisi_sge sge_entries[];
};

struct hisi_sgl_pool {
	/* the addr64 align offset base sgl */
	void **sgl_align;
	/* the sgl src address array */
	void **sgl;
	/* the sgl pool stack depth */
	__u32 depth;
	__u32 top;
	__u32 sge_num;
	__u32 sgl_num;
	struct wd_mm_ops *mm_ops;
	pthread_spinlock_t lock;
};

static int hacc_db_v1(struct hisi_qm_queue_info *q, __u8 cmd,
		      __u16 idx, __u8 priority)
{
	void *base = q->db_base;
	__u16 sqn = q->sqn;
	__u64 doorbell;

	doorbell = (__u64)sqn | ((__u64)cmd << QM_DBELL_CMD_SHIFT);
	doorbell |= ((__u64)idx | ((__u64)priority << QM_DBELL_CMD_SHIFT))
			<< QM_DBELL_HLF_SHIFT;
	wd_iowrite64(base, doorbell);

	return 0;
}

static int hacc_db_v2(struct hisi_qm_queue_info *q, __u8 cmd,
		      __u16 idx, __u8 priority)
{
	__u16 sqn = q->sqn & QM_DBELL_SQN_MASK;
	void *base = q->db_base;
	__u64 doorbell;

	doorbell = (__u64)sqn | ((__u64)(cmd & QM_DBELL_CMD_MASK) <<
			QM_DBELL_CMD_SHIFT_V2);
	doorbell |= ((__u64)idx | ((__u64)priority << QM_DBELL_CMD_SHIFT))
			<< QM_DBELL_HLF_SHIFT;
	wd_iowrite64(base, doorbell);

	return 0;
}

static struct hisi_qm_type qm_type[] = {
	{
		.qm_ver		= HISI_QM_API_VER_BASE,
		.qm_db_offs	= QM_DBELL_OFFSET,
		.hacc_db	= hacc_db_v1,
	}, {
		.qm_ver		= HISI_QM_API_VER2_BASE,
		.qm_db_offs	= QM_DBELL_OFFSET_V2,
		.hacc_db	= hacc_db_v2,
	}
};

int hisi_qm_get_usage(handle_t h_qp, __u8 type)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct hisi_qm_queue_info *q_info;
	__u16 count;
	__u32 val;
	int usage;

	if (!qp)
		return -WD_EINVAL;

	q_info = &qp->q_info;
	if (q_info->hw_type < HISI_QM_API_VER5_BASE) {
		WD_ERR("invalid: device not support get usage!\n");
		return -WD_EINVAL;
	}

	val = wd_ioread32(q_info->mmio_base + QM_TYPE_USAGE_OFFSET +
			  type * QM_CHANNEL_ADDR_INTRVL);
	count = val >> QM_DEV_USAGE_OFFSET;
	if (!count) {
		WD_ERR("failed to get dev count usage!\n");
		return -WD_EINVAL;
	}

	if (count <= (__u16)val)
		return QM_MAX_DEV_USAGE;

	usage = (int)((__u16)val) * QM_DEV_USAGE_RATE / count;

	return usage;
}

static void hisi_qm_fill_sqe(const void *sqe, struct hisi_qm_queue_info *info,
			     __u16 tail, __u16 num)
{
	int sqe_size = info->sqe_size;
	void *sq_base = info->sq_base;
	int idx;

	if (tail + num < info->sq_depth) {
		memcpy((void *)((uintptr_t)sq_base + tail * sqe_size),
			sqe, sqe_size * num);
	} else {
		idx = info->sq_depth - tail;
		memcpy((void *)((uintptr_t)sq_base + tail * sqe_size),
			sqe, sqe_size * idx);
		memcpy(sq_base, (void *)((uintptr_t)sqe + sqe_size * idx),
			sqe_size * (num - idx));
	}
}

static int hisi_qm_setup_region(handle_t h_ctx,
				struct hisi_qm_queue_info *q_info)
{
	q_info->sq_base = wd_ctx_mmap_qfr(h_ctx, UACCE_QFRT_DUS);
	if (!q_info->sq_base) {
		WD_DEV_ERR(h_ctx, "failed to mmap dus!\n");
		return -WD_ENOMEM;
	}

	q_info->mmio_base = wd_ctx_mmap_qfr(h_ctx, UACCE_QFRT_MMIO);
	if (!q_info->mmio_base) {
		wd_ctx_unmap_qfr(h_ctx, UACCE_QFRT_DUS);
		WD_DEV_ERR(h_ctx, "failed to mmap mmio!\n");
		return -WD_ENOMEM;
	}

	return 0;
}

static void hisi_qm_unset_region(handle_t h_ctx,
				 struct hisi_qm_queue_info *q_info)
{
	wd_ctx_unmap_qfr(h_ctx, UACCE_QFRT_DUS);
	wd_ctx_unmap_qfr(h_ctx, UACCE_QFRT_MMIO);
	q_info->sq_base = NULL;
	q_info->mmio_base = NULL;
}

static __u32 get_version_id(handle_t h_ctx)
{
	char *api_name, *id;
	unsigned long ver;

	api_name = wd_ctx_get_api(h_ctx);
	if (!api_name || strlen(api_name) <= VERSION_ID_SHIFT) {
		WD_DEV_ERR(h_ctx, "invalid: api name is %s!\n", api_name);
		return 0;
	}

	id = api_name + VERSION_ID_SHIFT;
	ver = strtoul(id, NULL, 10);
	if (!ver || ver == ULONG_MAX) {
		WD_DEV_ERR(h_ctx, "failed to strtoul, ver = %lu!\n", ver);
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
		q_info->db_base = q_info->mmio_base + QM_DBELL_OFFSET_V2;
	}

	return 0;
}

static int his_qm_set_qp_ctx(handle_t h_ctx, struct hisi_qm_priv *config,
			     struct hisi_qm_queue_info *q_info)
{
	struct hisi_qp_info qp_cfg = {0};
	struct hisi_qp_ctx qp_ctx = {0};
	int ret;

	qp_ctx.qc_type = config->op_type;
	q_info->qc_type = qp_ctx.qc_type;
	ret = wd_ctx_set_io_cmd(h_ctx, UACCE_CMD_QM_SET_QP_CTX, &qp_ctx);
	if (ret < 0) {
		WD_DEV_ERR(h_ctx, "failed to set qc_type!\n");
		return ret;
	}

	q_info->sqn = qp_ctx.id;
	config->sqn = qp_ctx.id;

	ret = wd_ctx_set_io_cmd(h_ctx, UACCE_CMD_QM_SET_QP_INFO, &qp_cfg);
	if (ret < 0) {
		WD_INFO("getting qp information is not supported, use default value!\n");

		q_info->sq_depth = QM_Q_DEPTH;
		q_info->cq_depth = QM_Q_DEPTH;
		q_info->sqe_size = config->sqe_size;
	} else {
		q_info->sq_depth = qp_cfg.sq_depth;
		q_info->cq_depth = qp_cfg.cq_depth;
		q_info->sqe_size = qp_cfg.sqe_size;
	}

	return 0;
}

static int hisi_qm_get_qfrs_offs(handle_t h_ctx,
				 struct hisi_qm_queue_info *q_info)
{
	enum uacce_qfrt type;

	type = UACCE_QFRT_DUS;
	q_info->region_size[type] = wd_ctx_get_region_size(h_ctx, type);
	if (!q_info->region_size[type]) {
		WD_DEV_ERR(h_ctx, "failed to get DUS qfrs offset!\n");
		return -WD_EINVAL;
	}

	type = UACCE_QFRT_MMIO;
	q_info->region_size[type] = wd_ctx_get_region_size(h_ctx, type);
	if (!q_info->region_size[type]) {
		WD_DEV_ERR(h_ctx, "failed to get MMIO qfrs offset!\n");
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
		WD_DEV_ERR(qp->h_ctx, "failed to setup region!\n");
		return ret;
	}

	ret = hisi_qm_get_qfrs_offs(qp->h_ctx, q_info);
	if (ret) {
		WD_DEV_ERR(qp->h_ctx, "failed to get dev qfrs offset!\n");
		goto err_out;
	}

	ret = hisi_qm_setup_db(qp->h_ctx, q_info);
	if (ret) {
		WD_DEV_ERR(qp->h_ctx, "failed to setup db!\n");
		goto err_out;
	}

	ret = his_qm_set_qp_ctx(qp->h_ctx, config, q_info);
	if (ret) {
		WD_DEV_ERR(qp->h_ctx, "failed to setup io cmd!\n");
		goto err_out;
	}

	q_info->qp_mode = config->qp_mode;
	q_info->epoll_en = config->epoll_en;
	q_info->idx = config->idx;
	q_info->cqc_phase = 1;
	q_info->cq_base = q_info->sq_base + (__u64)config->sqe_size * q_info->sq_depth;
	/* The last 32 bits of DUS show device or qp statuses */
	q_info->ds_tx_base = q_info->sq_base +
		q_info->region_size[UACCE_QFRT_DUS] - sizeof(uint32_t);
	q_info->ds_rx_base = q_info->ds_tx_base - sizeof(uint32_t);

	ret = pthread_spin_init(&q_info->rv_lock, PTHREAD_PROCESS_SHARED);
	if (ret) {
		WD_DEV_ERR(qp->h_ctx, "failed to init qinfo rv_lock!\n");
		goto err_out;
	}

	ret = pthread_spin_init(&q_info->sd_lock, PTHREAD_PROCESS_SHARED);
	if (ret) {
		WD_DEV_ERR(qp->h_ctx, "failed to init qinfo sd_lock!\n");
		goto err_destroy_lock;
	}

	ret = pthread_spin_init(&q_info->sgl_lock, PTHREAD_PROCESS_SHARED);
	if (ret) {
		WD_DEV_ERR(qp->h_ctx, "failed to init qinfo sgl_lock!\n");
		goto err_destroy_sd_lock;
	}

	return 0;

err_destroy_sd_lock:
	pthread_spin_destroy(&q_info->sd_lock);
err_destroy_lock:
	pthread_spin_destroy(&q_info->rv_lock);
err_out:
	hisi_qm_unset_region(qp->h_ctx, q_info);
	return ret;
}

static void hisi_qm_clear_info(struct hisi_qp *qp)
{
	struct hisi_qm_queue_info *q_info = &qp->q_info;

	pthread_spin_destroy(&q_info->sgl_lock);
	pthread_spin_destroy(&q_info->sd_lock);
	pthread_spin_destroy(&q_info->rv_lock);
	hisi_qm_unset_region(qp->h_ctx, q_info);
}

static int get_free_num(struct hisi_qm_queue_info *q_info)
{
	/* The device should reserve one buffer. */
	return (q_info->sq_depth - 1) -
		__atomic_load_n(&q_info->used_num, __ATOMIC_RELAXED);
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

	if (!config->sqe_size) {
		WD_ERR("invalid: sqe size is zero!\n");
		goto out;
	}

	qp = calloc(1, sizeof(struct hisi_qp));
	if (!qp)
		goto out;

	qp->h_ctx = ctx;

	ret = hisi_qm_setup_info(qp, config);
	if (ret)
		goto out_qp;

	qp->h_sgl_pool = hisi_qm_create_sglpool(HISI_SGL_NUM_IN_BD,
						HISI_SGE_NUM_IN_SGL, NULL);
	if (!qp->h_sgl_pool)
		goto free_info;

	ret = wd_ctx_start(qp->h_ctx);
	if (ret)
		goto free_pool;

	ret = wd_ctx_set_priv(qp->h_ctx, qp);
	if (ret) {
		wd_release_ctx_force(qp->h_ctx);
		goto free_pool;
	}

	return (handle_t)qp;

free_pool:
	hisi_qm_destroy_sglpool(qp->h_sgl_pool);
free_info:
	hisi_qm_clear_info(qp);
out_qp:
	free(qp);
out:
	return (handle_t)NULL;
}

void hisi_qm_free_qp(handle_t h_qp)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;

	if (!qp) {
		WD_ERR("invalid: h_qp is NULL!\n");
		return;
	}

	wd_release_ctx_force(qp->h_ctx);

	hisi_qm_destroy_sglpool(qp->h_sgl_pool);
	if (qp->h_nosva_sgl_pool)
		hisi_qm_destroy_sglpool(qp->h_nosva_sgl_pool);

	hisi_qm_clear_info(qp);

	free(qp);
}

int hisi_qm_send(handle_t h_qp, const void *req, __u16 expect, __u16 *count)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct hisi_qm_queue_info *q_info;
	__u16 free_num;
	__u16 tail;

	if (unlikely(!qp || !req || !count))
		return -WD_EINVAL;

	q_info = &qp->q_info;

	pthread_spin_lock(&q_info->sd_lock);
	free_num = get_free_num(q_info);
	if (!free_num) {
		pthread_spin_unlock(&q_info->sd_lock);
		return -WD_EBUSY;
	}

	if (expect > free_num) {
		pthread_spin_unlock(&q_info->sd_lock);
		return -WD_EBUSY;
	}

	tail = q_info->sq_tail_index;
	hisi_qm_fill_sqe(req, q_info, tail, expect);
	tail = (tail + expect) % q_info->sq_depth;

	/*
	 * Before sending doorbell, check the queue status,
	 * if the queue is disable, return failure.
	 */
	if (unlikely(wd_ioread32(q_info->ds_tx_base) == 1)) {
		pthread_spin_unlock(&q_info->sd_lock);
		WD_DEV_ERR(qp->h_ctx, "wd queue hw error happened before qm send!\n");
		return -WD_HW_EACCESS;
	}

	/* Make sure sqe is filled before db ring and queue status check is complete. */
	mb();
	q_info->db(q_info, QM_DBELL_CMD_SQ, tail, 0);
	q_info->sq_tail_index = tail;

	/* Make sure used_num is changed before the next thread gets free sqe. */
	__atomic_add_fetch(&q_info->used_num, expect, __ATOMIC_RELAXED);
	pthread_spin_unlock(&q_info->sd_lock);
	*count = expect;

	return 0;
}

static int hisi_qm_recv_single(struct hisi_qm_queue_info *q_info, handle_t h_ctx,
			       void *resp, __u16 idx)
{
	__u16 i, j, cqe_phase;
	struct cqe *cqe;

	pthread_spin_lock(&q_info->rv_lock);
	i = q_info->cq_head_index;
	cqe = q_info->cq_base + i * sizeof(struct cqe);
	cqe_phase = CQE_PHASE(cqe);
	/* Use dsb to read from memory and improve the receiving efficiency. */
	rmb();

	if (q_info->cqc_phase != cqe_phase) {
		pthread_spin_unlock(&q_info->rv_lock);
		return -WD_EAGAIN;
	}

	j = CQE_SQ_HEAD_INDEX(cqe);
	if (unlikely(j >= q_info->sq_depth)) {
		pthread_spin_unlock(&q_info->rv_lock);
		WD_DEV_ERR(h_ctx, "CQE_SQ_HEAD_INDEX(%u) error!\n", j);
		return -WD_EIO;
	}
	memcpy((void *)((uintptr_t)resp + idx * q_info->sqe_size),
	       (void *)((uintptr_t)q_info->sq_base + j * q_info->sqe_size), q_info->sqe_size);

	if (i == q_info->cq_depth - 1) {
		q_info->cqc_phase = !(q_info->cqc_phase);
		i = 0;
	} else {
		i++;
	}

	/*
	 * Before sending doorbell, check the queue status,
	 * if the queue is disable, return failure.
	 */
	if (unlikely(wd_ioread32(q_info->ds_rx_base) == 1)) {
		pthread_spin_unlock(&q_info->rv_lock);
		WD_DEV_ERR(h_ctx, "wd queue hw error happened before qm receive!\n");
		return -WD_HW_EACCESS;
	}

	/* Make sure queue status check is complete. */
	rmb();
	q_info->db(q_info, QM_DBELL_CMD_CQ, i, q_info->epoll_en);

	/* only support one thread poll one queue, so no need protect */
	q_info->cq_head_index = i;

	__atomic_sub_fetch(&q_info->used_num, 1, __ATOMIC_RELAXED);
	pthread_spin_unlock(&q_info->rv_lock);

	return 0;
}

int hisi_qm_recv(handle_t h_qp, void *resp, __u16 expect, __u16 *count)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct hisi_qm_queue_info *q_info;
	__u16 recv_num = 0;
	__u16 i;
	int ret;

	if (unlikely(!resp || !qp || !count))
		return -WD_EINVAL;

	if (unlikely(!expect))
		return 0;

	q_info = &qp->q_info;
	if (unlikely(wd_ioread32(q_info->ds_rx_base) == 1)) {
		WD_DEV_ERR(qp->h_ctx, "wd queue hw error happened before qm receive!\n");
		return -WD_HW_EACCESS;
	}

	for (i = 0; i < expect; i++) {
		ret = hisi_qm_recv_single(q_info, qp->h_ctx, resp, i);
		if (ret)
			break;
		recv_num++;
	}

	*count = recv_num;

	return ret;
}

int hisi_check_bd_id(handle_t h_qp, __u32 mid, __u32 bid)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	__u8 mode = qp->q_info.qp_mode;

	if (mode == CTX_MODE_SYNC && mid != bid) {
		WD_DEV_ERR(qp->h_ctx, "failed to recv self bd, send id: %u, recv id: %u\n",
			    mid, bid);
		return -WD_EINVAL;
	}

	return 0;
}

void hisi_set_msg_id(handle_t h_qp, __u32 *tag)
{
	static __thread __u64 rand_seed = 0x330eabcd;
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	__u8 mode = qp->q_info.qp_mode;
	__u16 seeds[3] = {0};
	__u64 id;

	/*
	 * The random message id on a single queue is obtained through the
	 * system's pseudo-random number generation algorithm to ensure
	 * that 1024 packets on a queue will not have duplicate id
	 */
	if (mode == CTX_MODE_SYNC) {
		seeds[0] = LW_U16(rand_seed);
		seeds[1] = LW_U16(rand_seed >> 16);
		id = nrand48(seeds);
		*tag = LW_U32(id);
		rand_seed = id;
	}
}

static void *hisi_qm_create_sgl(__u32 sge_num, struct wd_mm_ops *mm_ops)
{
	void *sgl;
	int size;

	size = sizeof(struct hisi_sgl) +
			sge_num * (sizeof(struct hisi_sge)) + HISI_SGL_ALIGE;
	if (mm_ops)
		sgl = mm_ops->alloc(mm_ops->usr, size);
	else
		sgl = calloc(1, size);

	if (!sgl)
		WD_ERR("failed to alloc memory for the hisi qm sgl!\n");

	return sgl;
}

static struct hisi_sgl *hisi_qm_align_sgl(const void *sgl, __u32 sge_num,
					  struct wd_mm_ops *mm_ops)
{
	struct hisi_sgl *sgl_align;
	uintptr_t iova, iova_align;

	/* Hardware require the address must be 64 bytes aligned */
	if (mm_ops) {
		iova = (uintptr_t)mm_ops->iova_map(mm_ops->usr, (struct hisi_sgl *)sgl,
						   sizeof(struct hisi_sgl));
		if (!iova)
			return NULL;
		iova_align = ADDR_ALIGN_64(iova);
		sgl_align = (struct hisi_sgl *)((uintptr_t)sgl + iova_align - iova);
	} else {
		sgl_align = (struct hisi_sgl *)ADDR_ALIGN_64(sgl);
	}
	sgl_align->entry_sum_in_chain = sge_num;
	sgl_align->entry_sum_in_sgl = 0;
	sgl_align->entry_length_in_sgl = sge_num;
	sgl_align->next_dma = 0;
	sgl_align->next = 0;

	return sgl_align;
}

static void hisi_qm_free_sglpool(struct hisi_sgl_pool *pool)
{
	__u32 i;

	if (pool->sgl) {
		if (pool->mm_ops && !pool->mm_ops->sva_mode) {
			for (i = 0; i < pool->sgl_num; i++)
				pool->mm_ops->free(pool->mm_ops->usr, pool->sgl[i]);
		} else {
			for (i = 0; i < pool->sgl_num; i++)
				free(pool->sgl[i]);
		}

		free(pool->sgl);
	}

	if (pool->sgl_align)
		free(pool->sgl_align);

	if (pool->mm_ops)
		free(pool->mm_ops);

	free(pool);
}

handle_t hisi_qm_create_sglpool(__u32 sgl_num, __u32 sge_num, struct wd_mm_ops *mm_ops)
{
	struct hisi_sgl_pool *sgl_pool;
	int ret;
	__u32 i;

	if (!sgl_num || !sge_num || sge_num > HISI_SGE_NUM_IN_SGL) {
		WD_ERR("failed to create sgl_pool, sgl_num=%u, sge_num=%u!\n",
			sgl_num, sge_num);
		return 0;
	}

	sgl_pool = calloc(1, sizeof(struct hisi_sgl_pool));
	if (!sgl_pool) {
		WD_ERR("failed to alloc memory for sgl_pool!\n");
		return 0;
	}

	if (mm_ops && !mm_ops->sva_mode && mm_ops->alloc && mm_ops->free &&
	    mm_ops->iova_map && mm_ops->usr) {
		sgl_pool->mm_ops = malloc(sizeof(struct wd_mm_ops));
		if (!sgl_pool->mm_ops) {
			WD_ERR("failed to alloc memory for sglpool mm_ops!\n");
			goto err_out;
		}
		memcpy(sgl_pool->mm_ops, mm_ops, sizeof(struct wd_mm_ops));
	}

	sgl_pool->sgl = calloc(sgl_num, sizeof(void *));
	if (!sgl_pool->sgl) {
		WD_ERR("failed to alloc memory for sgl!\n");
		goto err_out;
	}

	sgl_pool->sgl_align = calloc(sgl_num, sizeof(void *));
	if (!sgl_pool->sgl_align) {
		WD_ERR("failed to alloc memory for sgl align!\n");
		goto err_out;
	}

	/* base the sgl_num create the sgl chain */
	for (i = 0; i < sgl_num; i++) {
		sgl_pool->sgl[i] = hisi_qm_create_sgl(sge_num, sgl_pool->mm_ops);
		if (!sgl_pool->sgl[i]) {
			sgl_pool->sgl_num = i;
			goto err_out;
		}

		sgl_pool->sgl_align[i] = hisi_qm_align_sgl(sgl_pool->sgl[i],
							   sge_num, sgl_pool->mm_ops);
	}

	sgl_pool->sgl_num = sgl_num;
	sgl_pool->sge_num = sge_num;
	sgl_pool->depth = sgl_num;
	sgl_pool->top = sgl_num;
	ret = pthread_spin_init(&sgl_pool->lock, PTHREAD_PROCESS_SHARED);
	if (ret) {
		WD_ERR("failed to init sgl pool lock!\n");
		goto err_out;
	}

	return (handle_t)sgl_pool;

err_out:
	hisi_qm_free_sglpool(sgl_pool);
	return (handle_t)0;
}

void hisi_qm_destroy_sglpool(handle_t sgl_pool)
{
	struct hisi_sgl_pool *pool;

	if (!sgl_pool) {
		WD_ERR("invalid: sgl_pool is NULL!\n");
		return;
	}

	pool = (struct hisi_sgl_pool *)sgl_pool;
	pthread_spin_destroy(&pool->lock);
	hisi_qm_free_sglpool(pool);
}

static struct hisi_sgl *hisi_qm_sgl_pop(struct hisi_sgl_pool *pool)
{
	struct hisi_sgl *hw_sgl;

	pthread_spin_lock(&pool->lock);

	if (pool->top == 0) {
		pthread_spin_unlock(&pool->lock);
		WD_DEBUG("debug: the sgl pool is empty now!\n");
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
		pthread_spin_unlock(&pool->lock);
		WD_ERR("invalid: the sgl pool is full!\n");
		return -WD_EINVAL;
	}

	hw_sgl->next_dma = 0;
	hw_sgl->next = 0;
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
		next = (struct hisi_sgl *)cur->next;
		ret = hisi_qm_sgl_push(pool, cur);
		if (ret)
			break;

		cur = next;
	}

	return;
}

static void hisi_qm_dump_sgl(void *sgl)
{
	struct hisi_sgl *tmp = (struct hisi_sgl *)sgl;
	bool need_debug = wd_need_debug();
	int k = 0;
	int i;

	if (!need_debug)
		return;

	while (tmp) {
		WD_DEBUG("[sgl-%d]->entry_sum_in_chain: %u\n", k,
		       tmp->entry_sum_in_chain);
		WD_DEBUG("[sgl-%d]->entry_sum_in_sgl: %u\n", k,
		       tmp->entry_sum_in_sgl);
		WD_DEBUG("[sgl-%d]->entry_length_in_sgl: %u\n", k,
		       tmp->entry_length_in_sgl);
		for (i = 0; i < tmp->entry_sum_in_sgl; i++)
			WD_DEBUG("[sgl-%d]->sge_entries[%d].len: %u\n", k, i,
			       tmp->sge_entries[i].len);

		tmp = (struct hisi_sgl *)tmp->next;
		k++;

		if (!tmp) {
			WD_DEBUG("debug: sgl num size:%d\n", k);
			return;
		}
	}
}

void *hisi_qm_get_hw_sgl(handle_t sgl_pool, struct wd_datalist *sgl)
{
	struct hisi_sgl_pool *pool = (struct hisi_sgl_pool *)sgl_pool;
	struct wd_datalist *tmp = sgl;
	struct hisi_sgl *head, *next, *cur;
	struct wd_mm_ops *mm_ops;
	void *ret = NULL;
	__u32 i = 0;

	if (!pool || !sgl) {
		WD_ERR("invalid: hw sgl pool or sgl is NULL!\n");
		return WD_ERR_PTR(-WD_EINVAL);
	}

	if (pool->mm_ops && !pool->mm_ops->iova_map) {
		WD_ERR("invalid: mm_ops iova_map function is NULL!\n");
		return WD_ERR_PTR(-WD_EINVAL);
	}

	mm_ops = pool->mm_ops;
	head = hisi_qm_sgl_pop(pool);
	if (!head)
		return WD_ERR_PTR(-WD_EBUSY);

	cur = head;
	tmp = sgl;
	while (tmp) {
		/* if the user's data is NULL, jump next one */
		if (!tmp->data || !tmp->len) {
			tmp = tmp->next;
			continue;
		}

		if (tmp->len > HISI_MAX_SIZE_IN_SGE) {
			WD_ERR("invalid: the data len is %u!\n", tmp->len);
			ret = WD_ERR_PTR(-WD_EINVAL);
			goto err_out;
		}

		if (mm_ops)
			cur->sge_entries[i].buff = (uintptr_t)mm_ops->iova_map(mm_ops->usr,
									       tmp->data, tmp->len);
		else
			cur->sge_entries[i].buff = (uintptr_t)tmp->data;

		if (!cur->sge_entries[i].buff) {
			WD_ERR("invalid: the iova map addr of sge is NULL!\n");
			ret = WD_ERR_PTR(-WD_EINVAL);
			goto err_out;
		}

		cur->sge_entries[i].vbuff = (uintptr_t)tmp->data;
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
				ret = WD_ERR_PTR(-WD_EBUSY);
				goto err_out;
			}
			if (mm_ops)
				cur->next_dma = (uintptr_t)mm_ops->iova_map(mm_ops->usr,
									    next, sizeof(*next));
			else
				cur->next_dma = (uintptr_t)next;
			cur->next = next;
			cur = next;
			head->entry_sum_in_chain += pool->sge_num;
			/* In the new sgl chain, the subscript must be reset */
			i = 0;
		}

		tmp = tmp->next;
	}

	/* There is no data, recycle the hardware sgl head to pool */
	if (!head->entry_sum_in_chain) {
		ret = WD_ERR_PTR(-WD_EINVAL);
		goto err_out;
	}

	hisi_qm_dump_sgl(head);

	return head;
err_out:
	hisi_qm_put_hw_sgl(sgl_pool, head);
	return ret;
}

handle_t hisi_qm_get_sglpool(handle_t h_qp, struct wd_mm_ops *mm_ops)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;

	if (mm_ops && !mm_ops->sva_mode) {
		pthread_spin_lock(&qp->q_info.sgl_lock);
		if (!qp->h_nosva_sgl_pool)
			qp->h_nosva_sgl_pool = hisi_qm_create_sglpool(HISI_SGL_NUM_IN_BD,
								      HISI_SGE_NUM_IN_SGL, mm_ops);
		pthread_spin_unlock(&qp->q_info.sgl_lock);
		return qp->h_nosva_sgl_pool;
	}

	return qp->h_sgl_pool;
}

static void hisi_qm_sgl_copy_inner(void *pbuff, struct hisi_sgl *hw_sgl,
				   int begin_sge, __u32 sge_offset, __u32 size)
{
	struct hisi_sgl *tmp = hw_sgl;
	int i = begin_sge + 1;
	__u32 offset;
	void *src;

	src = (void *)tmp->sge_entries[begin_sge].vbuff + sge_offset;
	offset = tmp->sge_entries[begin_sge].len - sge_offset;
	/* the first one is enough for copy size, copy and return */
	if (offset >= size) {
		memcpy(pbuff, src, size);
		return;
	}

	memcpy(pbuff, src, offset);

	while (tmp) {
		for (; i < tmp->entry_sum_in_sgl; i++) {
			src = (void *)tmp->sge_entries[i].vbuff;
			if (offset + tmp->sge_entries[i].len >= size) {
				memcpy(pbuff + offset, src, size - offset);
				return;
			}

			memcpy(pbuff + offset, src, tmp->sge_entries[i].len);
			offset += tmp->sge_entries[i].len;
		}

		tmp = (struct hisi_sgl *)tmp->next;
		i = 0;
	}
}

static void hisi_qm_pbuff_copy_inner(void *pbuff, struct hisi_sgl *hw_sgl,
				     int begin_sge, __u32 sge_offset,
				     __u32 size)
{
	struct hisi_sgl *tmp = hw_sgl;
	int i = begin_sge + 1;
	__u32 offset = 0;
	void *dst;

	if (tmp->sge_entries[begin_sge].len - sge_offset >= size) {
		dst = (void *)tmp->sge_entries[begin_sge].vbuff + sge_offset;
		memcpy(dst, pbuff, size);
		return;
	}

	while (tmp) {
		for (; i < tmp->entry_sum_in_sgl; i++) {
			dst = (void *)tmp->sge_entries[i].vbuff;
			if (offset + tmp->sge_entries[i].len >= size) {
				memcpy(dst, pbuff + offset, size - offset);
				return;
			}

			memcpy(dst, pbuff + offset, tmp->sge_entries[i].len);
			offset += tmp->sge_entries[i].len;
		}

		tmp = (struct hisi_sgl *)tmp->next;
		i = 0;
	}
}

void hisi_qm_sgl_copy(void *pbuff, void *hw_sgl, __u32 offset, __u32 size,
		      __u8 direct)
{
	struct hisi_sgl *tmp = hw_sgl;
	int begin_sge = 0, i;
	__u32 sge_offset = 0;
	__u64 len = 0;

	if (!pbuff || !size || !tmp)
		return;

	while (len + tmp->entry_size_in_sgl <= offset) {
		len += tmp->entry_size_in_sgl;

		tmp = (struct hisi_sgl *)tmp->next;
		if (!tmp)
			return;
	}

	/* find the start sge position and start offset */
	for (i = 0; i < tmp->entry_sum_in_sgl; i++) {
		if (len + tmp->sge_entries[i].len > offset) {
			begin_sge = i;
			sge_offset = offset - len;
			break;
		}
		if (len + tmp->sge_entries[i].len == offset) {
			begin_sge = i + 1;
			sge_offset = 0;
			break;
		}

		len += tmp->sge_entries[i].len;
	}

	if (direct == COPY_SGL_TO_PBUFF)
		hisi_qm_sgl_copy_inner(pbuff, tmp, begin_sge, sge_offset, size);
	else
		hisi_qm_pbuff_copy_inner(pbuff, tmp, begin_sge, sge_offset,
					 size);
}

__u32 hisi_qm_get_list_size(struct wd_datalist *start_node,
			    struct wd_datalist *end_node)
{
	struct wd_datalist *cur = start_node;
	__u32 lits_size = 0;

	while (cur != end_node) {
		lits_size += cur->len;
		cur = cur->next;
	}

	return lits_size;
}
