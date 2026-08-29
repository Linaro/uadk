// SPDX-License-Identifier: Apache-2.0
/* Copyright 2020-2026 Huawei Technologies Co.,Ltd. All rights reserved. */
#include <stdlib.h>
#include <sched.h>

#include "wd_internal.h"
#include "wd_alg.h"
#include "wd_util.h"
#include "wd_drv.h"

int wd_soft_alloc_ctx(char *alg_name, void *params, handle_t *ctx)
{
	struct wd_soft_ctx *sfctx;

	if (!params || !ctx) {
		WD_ERR("invalid: params, or ctx is NULL!\n");
		return -WD_EINVAL;
	}

	/* Allocate ONE software context structure */
	sfctx = calloc(1, sizeof(struct wd_soft_ctx));
	if (!sfctx) {
		WD_ERR("failed to alloc ctx!\n");
		return -WD_ENOMEM;
	}

	/* Initialize as software context */
	sfctx->fd = -1;
	sfctx->ctx_type = UADK_ALG_SOFT;
	pthread_spin_init(&sfctx->slock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&sfctx->rlock, PTHREAD_PROCESS_PRIVATE);

	/* Return context handle */
	*ctx = (handle_t)sfctx;

	return WD_SUCCESS;
}

void wd_soft_free_ctx(handle_t ctx)
{
	struct wd_soft_ctx *sfctx = (struct wd_soft_ctx *)ctx;

	if (!sfctx) {
		WD_ERR("invalid: ctx is NULL!\n");
		return;
	}

	/* Simply free the allocated wd_ctx_h structure */
	pthread_spin_destroy(&sfctx->slock);
	pthread_spin_destroy(&sfctx->rlock);
	free(sfctx);
}

static int wd_compare_dev_distance(const void *a, const void *b)
{
	struct uacce_dev_list *node_a = *(struct uacce_dev_list **)a;
	struct uacce_dev_list *node_b = *(struct uacce_dev_list **)b;
	unsigned int curr_node;
	int dist_a, dist_b;

	if (getcpu(NULL, &curr_node) || curr_node == (unsigned int)NUMA_NO_NODE)
		return 0;

	dist_a = numa_distance((int)curr_node, node_a->dev->numa_id);
	dist_b = numa_distance((int)curr_node, node_b->dev->numa_id);

	return dist_a - dist_b;
}

static struct uacce_dev_list *wd_sort_dev_list(struct uacce_dev_list *list, int list_count)
{
	struct uacce_dev_list *p, **nodes = NULL;
	struct uacce_dev_list *result = NULL;
	int i;

	if (!list || !list_count)
		return NULL;

	/* Convert to array */
	nodes = calloc(list_count, sizeof(struct uacce_dev_list *));
	if (!nodes)
		return list; /* Return original list on allocation failure */

	p = list;
	for (i = 0; i < list_count; i++) {
		if (!p)
			break;
		nodes[i] = p;
		p = p->next;
	}

	/* Sort by NUMA distance */
	qsort(nodes, list_count, sizeof(struct uacce_dev_list *), wd_compare_dev_distance);

	/* Rebuild sorted list */
	for (i = 0; i < list_count; i++) {
		nodes[i]->next = NULL;
		if (!result)
			result = nodes[i];
		else
			wd_add_dev_to_list(result, nodes[i]);
	}
	free(nodes);

	return result;
}

struct uacce_dev_list *wd_get_usable_list(struct uacce_dev_list *list, int target_numa)
{
	struct uacce_dev_list *p, *node, *result = NULL;
	struct uacce_dev_list *ret, *head = NULL;
	struct uacce_dev *dev;
	int count = 0;
	int numa_id;

	p = list;
	while (p) {
		dev = p->dev;
		numa_id = dev->numa_id;
		if (numa_id != target_numa) {
			p = p->next;
			continue;
		}

		node = calloc(1, sizeof(*node));
		if (!node) {
			ret = WD_ERR_PTR(-WD_ENOMEM);
			goto out_free_list;
		}

		node->dev = wd_clone_dev(dev);
		if (!node->dev) {
			ret = WD_ERR_PTR(-WD_ENOMEM);
			goto out_free_node;
		}

		if (!head)
			head = node;
		else
			wd_add_dev_to_list(head, node);

		count++;
		p = p->next;
	}

	if (!count)
		return NULL;

	/* Sort by NUMA distance */
	result = wd_sort_dev_list(head, count);
	if (!result) {
		ret = WD_ERR_PTR(-WD_ENODEV);
		goto out_free_list;
	}

	return result;

out_free_node:
	free(node);
out_free_list:
	wd_free_list_accels(head);
	return ret;
}

/**
 * wd_hw_alloc_ctx() - HW driver's alloc_ctx callback.
 *
 * Allocates ONE hardware context from UACCE device.
 * Device selection strategy:
 *   1. Filter devices by bmp (NUMA bitmask)
 *   2. Sort by NUMA distance (nearest first)
 *   3. Prefer devices on target_numa; fall back to others in distance order
 *
 * @alg_name: The algorithm name
 * @params: Minimal allocation parameters (ctx_mode, op_type, numa_id, bmp)
 * @ctx: (output) Allocated context handle
 *
 * Return: 0 on success, negative on failure
 */
int wd_hw_alloc_ctx(char *alg_name, void *params, handle_t *ctx)
{
	struct wd_drv_ctx_params *ctx_params = (struct wd_drv_ctx_params *)params;
	struct uacce_dev_list *dev_list, *used_list = NULL;
	char alg_type[CRYPTO_MAX_ALG_NAME];
	struct uacce_dev_list *curr;
	struct wd_ctx_h *ctx_h;
	int target_numa;
	handle_t hctx;
	int ret;

	if (!params || !ctx) {
		WD_ERR("invalid: parameters are NULL!\n");
		return -WD_EINVAL;
	}
	target_numa = ctx_params->numa_id;

	/* Get algorithm type and device list */
	ret = wd_get_alg_type(alg_name, alg_type);
	if (ret) {
		WD_ERR("invalid: alg_name is NULL!\n");
		return -WD_EINVAL;
	}
	if (!strcmp(alg_type, "ecc"))
		(void)strcpy(alg_type, "sm2");
	if (!strcmp(alg_type, "comp"))
		(void)strcpy(alg_type, "zlib");

	dev_list = wd_get_accel_list(alg_type);
	if (!dev_list) {
		WD_ERR("failed to get device list for alg %s\n", alg_name);
		return -WD_ENODEV;
	}

	/* Filter by bmp and sort by NUMA distance */
	used_list = wd_get_usable_list(dev_list, target_numa);
	if (WD_IS_ERR(used_list) || !used_list) {
		WD_INFO("Info: No usable device detected on numa<%d>\n", target_numa);
		used_list = NULL;
		ret = -WD_ENODEV;
		goto out;
	}

	curr = used_list;
	while (curr) {
		if (curr->dev) {
			hctx = wd_request_ctx(curr->dev);
			if (hctx)
				goto success;
		}
		curr = curr->next;
	}

	WD_ERR("failed to request ctx on NUMA node %d for %s\n",
	       target_numa, alg_name);
	ret = -WD_EBUSY;
	goto out;

success:
	ctx_h = (struct wd_ctx_h *)hctx;
	ctx_h->priv = NULL;
	ctx_h->ctx_type = UADK_ALG_HW;
	*ctx = hctx;
	ret = 0;
out:
	if (dev_list)
		wd_free_list_accels(dev_list);
	if (used_list && !WD_IS_ERR(used_list))
		wd_free_list_accels(used_list);

	return ret;
}

/**
 * wd_hw_free_ctx() - HW driver's free_ctx callback.
 *
 * Releases ONE hardware context back to UACCE device.
 *
 * @ctx: The context handle to release
 */
void wd_hw_free_ctx(handle_t ctx)
{
	struct wd_ctx_h *ctx_h = (struct wd_ctx_h *)ctx;

	if (!ctx_h) {
		WD_ERR("invalid: ctx is NULL!\n");
		return;
	}

	/* Release hardware context back to device */
	wd_release_ctx(ctx);
}

int wd_get_sqe_from_queue(struct wd_soft_ctx *sctx, __u32 tag_id)
{
	struct wd_soft_sqe *sqe = NULL;

	if (!sctx) {
		WD_ERR("invalid: sctx is NULL!\n");
		return -WD_EINVAL;
	}

	pthread_spin_lock(&sctx->slock);
	sqe = &sctx->qfifo[sctx->head];
	if (!sqe->used && !sqe->complete) { // find the next not used sqe
		sctx->head++;
		if (unlikely(sctx->head == MAX_SOFT_QUEUE_LENGTH))
			sctx->head = 0;

		sqe->used = 1;
		sqe->complete = 1;
		sqe->id = tag_id;
		sqe->result = 0;
		__atomic_fetch_add(&sctx->run_num, 0x1, __ATOMIC_ACQUIRE);
		pthread_spin_unlock(&sctx->slock);
	} else {
		pthread_spin_unlock(&sctx->slock);
		return -WD_EBUSY;
	}

	return WD_SUCCESS;
}

int wd_put_sqe_to_queue(struct wd_soft_ctx *sctx, __u32 *tag_id, __u8 *result)
{
	struct wd_soft_sqe *sqe = NULL;

	/* The queue is not used */
	if (!sctx || !tag_id || !result || sctx->run_num < 1)
		return -WD_EAGAIN;

	if (pthread_spin_trylock(&sctx->rlock))
		return -WD_EAGAIN;
	sqe = &sctx->qfifo[sctx->tail];
	if (sqe->used && sqe->complete) { // find a used sqe
		sctx->tail++;
		if (unlikely(sctx->tail == MAX_SOFT_QUEUE_LENGTH))
			sctx->tail = 0;

		*tag_id = sqe->id;
		*result = sqe->result;
		sqe->used = 0x0;
		sqe->complete = 0x0;
		__atomic_fetch_sub(&sctx->run_num, 0x1, __ATOMIC_ACQUIRE);
		pthread_spin_unlock(&sctx->rlock);
	} else {
		pthread_spin_unlock(&sctx->rlock);
		return -WD_EAGAIN;
	}

	return WD_SUCCESS;
}

int wd_queue_is_busy(struct wd_soft_ctx *sctx)
{
	/* The queue is not used */
	if (!sctx)
		return -WD_EINVAL;

	if (__atomic_load_n(&sctx->run_num, __ATOMIC_ACQUIRE) >= MAX_SOFT_QUEUE_LENGTH - 1)
		return -WD_EBUSY;

	return WD_SUCCESS;
}
