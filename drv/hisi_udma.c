// SPDX-License-Identifier: Apache-2.0
/* Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include "hisi_qm_udrv.h"
#include "../include/drv/wd_udma_drv.h"

#define BIT(nr)			(1UL << (nr))
#define UDMA_CTX_Q_NUM_DEF	1
#define UDMA_TASK_TYPE		0x3
#define UDMA_SQE_TYPE		0x1
#define UDMA_ALG_TYPE		2
/* Multi max data size is (16M -1) * 64 */
#define UDMA_M_MAX_ADDR_SIZE	1073741760
/* Single max data size is (16M - 1) */
#define UDMA_S_MAX_ADDR_SIZE	16777215
#define UDMA_MAX_ADDR_NUM	64
#define UDMA_ADDR_NUM_SHIFT	6
#define UDMA_MULTI_ADDR_EN	BIT(14)
#define UDMA_ADDR_NUM_SHIFT	6
#define UDMA_SVA_PREFETCH_EN	BIT(15)
#define UDMA_ADDR_RESV_NUM	16
#define UDMA_ADDR_ALIGN_SIZE	128

enum {
	DATA_MEMCPY = 0x0,
	DATA_MEMSET = 0x7,
};

enum {
	UDMA_TASK_DONE = 0x1,
	UDMA_TASK_ERROR = 0x2,
};

struct udma_addr {
	__u64 addr;
	__u64 data_size;
};

struct udma_addr_array {
	__u64 resv_addr[UDMA_ADDR_RESV_NUM];
	struct udma_addr src_addr[UDMA_MAX_ADDR_NUM];
	struct udma_addr dst_addr[UDMA_MAX_ADDR_NUM];
};

struct udma_sqe {
	__u32 bd_type : 6;
	__u32 resv1 : 2;
	__u32 task_type : 6;
	__u32 resv2 : 2;
	__u32 task_type_ext : 6;
	__u32 resv3 : 9;
	__u32 bd_invlid : 1;
	__u32 rsv4[2];
	__u32 low_tag;
	__u32 hi_tag;
	/* The number of bytes to be copied or filled for single address. */
	__u32 data_size;
	__u32 rsv5;
	/*
	 * 0 ~ 13 bits: reserved,
	 * 14 bit： single address or multi addresses,
	 * 15 bit: sva prefetch en.
	 */
	__u16 dw0;
	/*
	 * 0 ~5 bits: reserved,
	 * 6 ~ 13 bits: address num,
	 * 14 ~15 bits: reserved.
	 */
	__u16 dw1;
	__u64 init_val;
	__u32 rsv6[12];
	/* dst addr for single address task */
	__u64 dst_addr;
	__u32 rsv7[2];
	/* src addr for single address task, addr array for multi addresses. */
	__u64 addr_array;
	__u32 done_flag : 3;
	__u32 rsv8 : 1;
	__u32 ext_err_type : 12;
	__u32 err_type : 8;
	__u32 wtype : 8;
	__u32 rsv9[3];
};

struct udma_internal_addr {
	struct udma_addr_array *addr_array;
	__u8 *addr_status;
	__u16 addr_count;
	__u16 tail;
};

struct hisi_udma_ctx {
	struct wd_ctx_config_internal config;
};

static int get_free_inter_addr(struct udma_internal_addr *inter_addr)
{
	__u16 addr_count = inter_addr->addr_count;
	__u16 idx = inter_addr->tail;
	__u16 cnt = 0;

	if (unlikely(!addr_count)) {
		WD_ERR("invalid: internal addr count is 0!\n");
		return -WD_EINVAL;
	}

	while (__atomic_test_and_set(&inter_addr->addr_status[idx], __ATOMIC_ACQUIRE)) {
		idx = (idx + 1) % addr_count;
		cnt++;
		if (cnt == addr_count)
			return -WD_EBUSY;
	}

	inter_addr->tail = (idx + 1) % addr_count;

	return idx;
}

static void put_inter_addr(struct udma_internal_addr *inter_addr, int idx)
{
	__atomic_clear(&inter_addr->addr_status[idx], __ATOMIC_RELEASE);
}

static int check_udma_param(struct wd_udma_msg *msg)
{
	int i;

	if (unlikely(!msg)) {
		WD_ERR("invalid: input udma msg is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(msg->addr_num > UDMA_MAX_ADDR_NUM)) {
		WD_ERR("invalid: input addr_num is more than %d!\n", UDMA_MAX_ADDR_NUM);
		return -WD_EINVAL;
	}

	/*
	 * When the single address length exceeds UDMA_S_MAX_ADDR_SIZE,
	 * the driver will split the address into multiple addresses and
	 * send them to the hardware.
	 */
	if (msg->addr_num == 1) {
		if (unlikely(msg->dst->data_size > UDMA_M_MAX_ADDR_SIZE)) {
			WD_ERR("invalid: input size %lu is more than %d!\n",
				msg->dst->data_size, UDMA_M_MAX_ADDR_SIZE);
			return -WD_EINVAL;
		}

		return WD_SUCCESS;
	}

	for (i = 0; i < msg->addr_num; i++) {
		if (unlikely(msg->dst[i].data_size > UDMA_S_MAX_ADDR_SIZE)) {
			WD_ERR("invalid: addr %d input size %lu is more than %d!\n",
				i, msg->dst[i].data_size, UDMA_S_MAX_ADDR_SIZE);
			return -WD_EINVAL;
		}
	}

	return WD_SUCCESS;
}

static void fill_long_size_memcpy_info(struct udma_sqe *sqe, struct wd_udma_msg *msg,
				       struct udma_addr_array *addr_array)
{
	__u32 addr_num = 0;
	__u64 count;

	for (count = 0; count < msg->src->data_size; count += UDMA_S_MAX_ADDR_SIZE) {
		addr_array->src_addr[addr_num].addr = (__u64)(uintptr_t)msg->src->addr + count;
		addr_array->dst_addr[addr_num].addr = (__u64)(uintptr_t)msg->dst->addr + count;
		if (count + UDMA_S_MAX_ADDR_SIZE <= msg->src->data_size) {
			addr_array->src_addr[addr_num].data_size = UDMA_S_MAX_ADDR_SIZE;
			addr_array->dst_addr[addr_num].data_size = UDMA_S_MAX_ADDR_SIZE;
		} else {
			addr_array->src_addr[addr_num].data_size = msg->src->data_size - count;
			addr_array->dst_addr[addr_num].data_size = msg->dst->data_size - count;
		}
		addr_num++;
	}
	sqe->dw1 |= (addr_num - 1) << UDMA_ADDR_NUM_SHIFT;
}

static void fill_long_size_memset_info(struct udma_sqe *sqe, struct wd_udma_msg *msg,
				       struct udma_addr_array *addr_array)
{
	__u32 addr_num = 0;
	__u64 count;

	for (count = 0; count < msg->dst->data_size; count += UDMA_S_MAX_ADDR_SIZE) {
		addr_array->dst_addr[addr_num].addr = (__u64)(uintptr_t)msg->dst->addr + count;
		if (count + UDMA_S_MAX_ADDR_SIZE <= msg->dst->data_size)
			addr_array->dst_addr[addr_num].data_size = UDMA_S_MAX_ADDR_SIZE;
		else
			addr_array->dst_addr[addr_num].data_size = msg->dst->data_size - count;
		addr_num++;
	}

	sqe->dw1 |= (addr_num - 1) << UDMA_ADDR_NUM_SHIFT;
}

static void fill_multi_memset_addr_info(struct udma_sqe *sqe, struct wd_udma_msg *msg,
					struct udma_addr_array *addr_array)
{
	int i;

	for (i = 0; i < msg->addr_num; i++) {
		addr_array->dst_addr[i].addr = (__u64)(uintptr_t)msg->dst[i].addr;
		addr_array->dst_addr[i].data_size = (__u64)(uintptr_t)msg->dst[i].data_size;
	}

	sqe->dw1 |= ((__u32)msg->addr_num - 1) << UDMA_ADDR_NUM_SHIFT;
}

static void fill_multi_memcpy_addr_info(struct udma_sqe *sqe, struct wd_udma_msg *msg,
					struct udma_addr_array *addr_array)
{
	int i;

	for (i = 0; i < msg->addr_num; i++) {
		addr_array->src_addr[i].addr = (__u64)(uintptr_t)msg->src[i].addr;
		addr_array->src_addr[i].data_size = (__u64)(uintptr_t)msg->src[i].data_size;
		addr_array->dst_addr[i].addr = (__u64)(uintptr_t)msg->dst[i].addr;
		addr_array->dst_addr[i].data_size = (__u64)(uintptr_t)msg->dst[i].data_size;
	}

	sqe->dw1 |= ((__u32)msg->addr_num - 1) << UDMA_ADDR_NUM_SHIFT;
}

static void fill_multi_addr_info(struct udma_sqe *sqe, struct wd_udma_msg *msg,
				 struct udma_addr_array *addr_array)
{
	if (msg->addr_num == 1) {
		if (msg->op_type == WD_UDMA_MEMCPY)
			fill_long_size_memcpy_info(sqe, msg, addr_array);
		else
			fill_long_size_memset_info(sqe, msg, addr_array);
	} else {
		if (msg->op_type == WD_UDMA_MEMCPY)
			fill_multi_memcpy_addr_info(sqe, msg, addr_array);
		else
			fill_multi_memset_addr_info(sqe, msg, addr_array);
	}

	sqe->addr_array = (__u64)(uintptr_t)addr_array;
	sqe->dw0 |= UDMA_MULTI_ADDR_EN;
}

static void fill_single_addr_info(struct udma_sqe *sqe, struct wd_udma_msg *msg)
{
	if (msg->op_type == WD_UDMA_MEMCPY)
		sqe->addr_array = (__u64)(uintptr_t)msg->src->addr;
	sqe->dst_addr = (__u64)(uintptr_t)msg->dst->addr;
	sqe->data_size = msg->dst->data_size;
}

static void fill_udma_sqe_addr(struct udma_sqe *sqe, struct wd_udma_msg *msg,
			       struct udma_addr_array *addr_array)
{
	if (!addr_array)
		fill_single_addr_info(sqe, msg);
	else
		fill_multi_addr_info(sqe, msg, addr_array);
}

static void fill_sqe_type(struct udma_sqe *sqe, struct wd_udma_msg *msg)
{
	sqe->bd_type = UDMA_SQE_TYPE;
	sqe->task_type = UDMA_TASK_TYPE;
	if (msg->op_type == WD_UDMA_MEMCPY)
		sqe->task_type_ext = DATA_MEMCPY;
	else
		sqe->task_type_ext = DATA_MEMSET;
}

static void fill_init_value(struct udma_sqe *sqe, struct wd_udma_msg *msg)
{
	if (msg->op_type == WD_UDMA_MEMSET)
		memset(&sqe->init_val, msg->value, sizeof(__u64));
}

static int udma_send(struct wd_alg_driver *drv, handle_t ctx, void *udma_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct udma_internal_addr *inter_addr = qp->priv;
	struct udma_addr_array *addr_array = NULL;
	struct wd_udma_msg *msg = udma_msg;
	struct udma_sqe sqe = {0};
	__u16 send_cnt = 0;
	int idx = 0;
	int ret;

	ret = check_udma_param(msg);
	if (unlikely(ret))
		return ret;

	if (msg->addr_num > 1 || msg->dst->data_size > UDMA_S_MAX_ADDR_SIZE) {
		idx = get_free_inter_addr(inter_addr);
		if (idx < 0)
			return -WD_EBUSY;

		addr_array = &inter_addr->addr_array[idx];
		memset(addr_array, 0, sizeof(struct udma_addr_array));
	}

	fill_sqe_type(&sqe, msg);
	fill_init_value(&sqe, msg);
	fill_udma_sqe_addr(&sqe, msg, addr_array);

	hisi_set_msg_id(h_qp, &msg->tag);
	sqe.low_tag = msg->tag;
	sqe.hi_tag = (__u32)idx;
	sqe.dw0 |= UDMA_SVA_PREFETCH_EN;

	ret = hisi_qm_send(h_qp, &sqe, 1, &send_cnt);
	if (unlikely(ret)) {
		if (ret != -WD_EBUSY)
			WD_ERR("failed to send to hardware, ret = %d!\n", ret);
		if (addr_array)
			put_inter_addr(inter_addr, idx);
		return ret;
	}

	return WD_SUCCESS;
}

static void dump_udma_msg(struct udma_sqe *sqe, struct wd_udma_msg *msg)
{
	WD_ERR("dump UDMA message after a task error occurs.\n"
	       "op_type:%u addr_num:%d.\n", msg->op_type, msg->addr_num);
}

static int udma_recv(struct wd_alg_driver *drv, handle_t ctx, void *udma_msg)
{
	handle_t h_qp = (handle_t)wd_ctx_get_priv(ctx);
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct udma_internal_addr *inter_addr = qp->priv;
	struct wd_udma_msg *msg = udma_msg;
	struct wd_udma_msg *temp_msg = msg;
	struct udma_sqe sqe = {0};
	__u16 recv_cnt = 0;
	int ret;

	ret = hisi_qm_recv(h_qp, &sqe, 1, &recv_cnt);
	if (ret)
		return ret;

	ret = hisi_check_bd_id(h_qp, msg->tag, sqe.low_tag);
	if (ret)
		goto out;

	msg->tag = sqe.low_tag;
	if (qp->q_info.qp_mode == CTX_MODE_ASYNC) {
		temp_msg = wd_udma_get_msg(qp->q_info.idx, msg->tag);
		if (!temp_msg) {
			WD_ERR("failed to get send msg! idx = %u, tag = %u.\n",
			       qp->q_info.idx, msg->tag);
			ret = -WD_EINVAL;
			goto out;
		}
	}

	msg->result = WD_SUCCESS;
	if (sqe.done_flag != UDMA_TASK_DONE ||
	    sqe.err_type || sqe.ext_err_type || sqe.wtype) {
		WD_ERR("failed to do udma task! done=0x%x, err_type=0x%x\n"
		       "ext_err_type=0x%x, wtype=0x%x!\n",
			(__u32)sqe.done_flag, (__u32)sqe.err_type,
			(__u32)sqe.ext_err_type, (__u32)sqe.wtype);
		msg->result = WD_IN_EPARA;
	}

	if (unlikely(msg->result != WD_SUCCESS))
		dump_udma_msg(&sqe, temp_msg);

out:
	if (sqe.dw0 & UDMA_MULTI_ADDR_EN)
		put_inter_addr(inter_addr, sqe.hi_tag);
	return ret;
}

static void udma_uninit_qp_priv(handle_t h_qp)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	struct udma_internal_addr *inter_addr;

	if (!qp)
		return;

	inter_addr = (struct udma_internal_addr *)qp->priv;
	if (!inter_addr)
		return;

	free(inter_addr->addr_array);
	free(inter_addr->addr_status);
	free(inter_addr);
	qp->priv = NULL;
}

static int udma_init_qp_priv(handle_t h_qp)
{
	struct hisi_qp *qp = (struct hisi_qp *)h_qp;
	__u16 sq_depth = qp->q_info.sq_depth;
	struct udma_internal_addr *inter_addr;
	int ret = -WD_ENOMEM;

	inter_addr = calloc(1, sizeof(struct udma_internal_addr));
	if (!inter_addr)
		return ret;

	inter_addr->addr_status = calloc(1, sizeof(__u8) * sq_depth);
	if (!inter_addr->addr_status)
		goto free_inter_addr;

	inter_addr->addr_array = aligned_alloc(UDMA_ADDR_ALIGN_SIZE,
					       sizeof(struct udma_addr_array) * sq_depth);
	if (!inter_addr->addr_array)
		goto free_addr_status;

	inter_addr->addr_count = sq_depth;
	qp->priv = inter_addr;

	return WD_SUCCESS;

free_addr_status:
	free(inter_addr->addr_status);
free_inter_addr:
	free(inter_addr);

	return ret;
}

static int udma_init(struct wd_alg_driver *drv, void *conf)
{
	struct wd_ctx_config_internal *config = conf;
	struct hisi_qm_priv qm_priv;
	struct hisi_udma_ctx *priv;
	handle_t h_qp = 0;
	handle_t h_ctx;
	__u32 i, j;
	int ret;

	if (!config || !config->ctx_num) {
		WD_ERR("invalid: udma init config is null or ctx num is 0!\n");
		return -WD_EINVAL;
	}

	priv = malloc(sizeof(struct hisi_udma_ctx));
	if (!priv)
		return -WD_ENOMEM;

	qm_priv.op_type = UDMA_ALG_TYPE;
	qm_priv.sqe_size = sizeof(struct udma_sqe);
	/* Allocate qp for each context */
	for (i = 0; i < config->ctx_num; i++) {
		h_ctx = config->ctxs[i].ctx;
		qm_priv.qp_mode = config->ctxs[i].ctx_mode;
		/* Setting the epoll en to 0 for ASYNC ctx */
		qm_priv.epoll_en = (qm_priv.qp_mode == CTX_MODE_SYNC) ?
				    config->epoll_en : 0;
		qm_priv.idx = i;
		h_qp = hisi_qm_alloc_qp(&qm_priv, h_ctx);
		if (!h_qp) {
			ret = -WD_ENOMEM;
			goto out;
		}
		config->ctxs[i].sqn = qm_priv.sqn;
		ret = udma_init_qp_priv(h_qp);
		if (ret)
			goto free_h_qp;
	}
	memcpy(&priv->config, config, sizeof(struct wd_ctx_config_internal));
	drv->priv = priv;

	return WD_SUCCESS;
free_h_qp:
	hisi_qm_free_qp(h_qp);
out:
	for (j = 0; j < i; j++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[j].ctx);
		udma_uninit_qp_priv(h_qp);
		hisi_qm_free_qp(h_qp);
	}
	free(priv);
	return ret;
}

static void udma_exit(struct wd_alg_driver *drv)
{
	struct wd_ctx_config_internal *config;
	struct hisi_udma_ctx *priv;
	handle_t h_qp;
	__u32 i;

	if (!drv || !drv->priv)
		return;

	priv = (struct hisi_udma_ctx *)drv->priv;
	config = &priv->config;
	for (i = 0; i < config->ctx_num; i++) {
		h_qp = (handle_t)wd_ctx_get_priv(config->ctxs[i].ctx);
		udma_uninit_qp_priv(h_qp);
		hisi_qm_free_qp(h_qp);
	}

	free(priv);
	drv->priv = NULL;
}

static int udma_get_usage(void *param)
{
	struct hisi_dev_usage *udma_usage = (struct hisi_dev_usage *)param;
	struct wd_alg_driver *drv = udma_usage->drv;
	struct wd_ctx_config_internal *config;
	struct hisi_udma_ctx *priv;
	char *ctx_dev_name;
	handle_t ctx = 0;
	handle_t qp = 0;
	__u32 i;

	if (udma_usage->alg_op_type >= drv->op_type_num) {
		WD_ERR("invalid: alg_op_type %u is error!\n", udma_usage->alg_op_type);
		return -WD_EINVAL;
	}

	priv = (struct hisi_udma_ctx *)drv->priv;
	if (!priv)
		return -WD_EACCES;

	config = &priv->config;
	for (i = 0; i < config->ctx_num; i++) {
		ctx_dev_name = wd_ctx_get_dev_name(config->ctxs[i].ctx);
		if (!strcmp(udma_usage->dev_name, ctx_dev_name)) {
			ctx = config->ctxs[i].ctx;
			break;
		}
	}

	if (ctx)
		qp = (handle_t)wd_ctx_get_priv(ctx);

	if (qp)
		return hisi_qm_get_usage(qp, UDMA_ALG_TYPE);

	return -WD_EACCES;
}

static struct wd_alg_driver udma_driver = {
	.drv_name = "hisi_zip",
	.alg_name = "udma",
	.calc_type = UADK_ALG_HW,
	.priority = 100,
	.queue_num = UDMA_CTX_Q_NUM_DEF,
	.op_type_num = 1,
	.fallback = 0,
	.init = udma_init,
	.exit = udma_exit,
	.send = udma_send,
	.recv = udma_recv,
	.get_usage = udma_get_usage,
};

#ifdef WD_STATIC_DRV
void hisi_udma_probe(void)
#else
static void __attribute__((constructor)) hisi_udma_probe(void)
#endif
{
	int ret;

	WD_INFO("Info: register UDMA alg drivers!\n");

	ret = wd_alg_driver_register(&udma_driver);
	if (ret && ret != -WD_ENODEV)
		WD_ERR("failed to register UDMA driver, ret = %d!\n", ret);
}

#ifdef WD_STATIC_DRV
void hisi_udma_remove(void)
#else
static void __attribute__((destructor)) hisi_udma_remove(void)
#endif
{
	WD_INFO("Info: unregister UDMA alg drivers!\n");

	wd_alg_driver_unregister(&udma_driver);
}
