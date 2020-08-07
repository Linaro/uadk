/*
 * Copyright 2019 Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Block Memory Menagament (lib): A block memory algorithm */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <sys/queue.h>

#include "wd.h"
#include "wd_util.h"
#include "wd_bmm.h"

#define __ALIGN_MASK(x, mask)  (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) __ALIGN_MASK(x, (typeof(x))(a)-1)

#define TAG_FREE 0x12345678  /* block is free */
#define TAG_USED 0x87654321  /* block is busy */

struct wd_blk_hd {
	unsigned int blk_tag;
	void *blk_dma;
	void *blk;

	TAILQ_ENTRY(wd_blk_hd) next;
};

TAILQ_HEAD(wd_blk_list, wd_blk_hd);

struct wd_blkpool {
	struct wd_lock pool_lock;
	unsigned int free_blk_num;
	unsigned int alloc_failures;
	struct wd_queue *q;
	struct wd_blk_list head;
	void *usr_mem_start;
	void *act_start;
	unsigned int act_hd_sz;
	unsigned int act_blk_sz;
	unsigned long act_mem_sz;
	struct wd_blkpool_setup setup;
};

static struct wd_blk_hd *wd_blk_head(struct wd_blkpool *pool, void *blk)
{
	unsigned long offset = (unsigned long)((uintptr_t)blk -
					       (uintptr_t)pool->act_start);
	unsigned long sz = pool->act_hd_sz + pool->act_blk_sz;
	unsigned long blk_idx = offset / sz;

	return (struct wd_blk_hd *)((uintptr_t)pool->act_start + blk_idx * sz);
}

static int pool_params_check(struct wd_blkpool_setup *setup)
{
#define MAX_ALIGN_SIZE 0x1000
	if (!setup->block_num || !setup->block_size) {
		WD_ERR("Invalid block_size or block_num.\n");
		return -WD_EINVAL;
	}

	/* check the params, and align_size must be 2^N */
	if (setup->align_size == 0x1 || setup->align_size > MAX_ALIGN_SIZE ||
	    setup->align_size & (setup->align_size - 0x1)) {
		WD_ERR("Invalid align_size.\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_pool_pre_layout(struct wd_blkpool *p,
			      struct wd_blkpool_setup *sp)
{
	unsigned int asz;
	int ret;

#define BLK_BALANCE_SZ		0x100000ul
	ret = pool_params_check(sp);
	if (ret)
		return ret;

	asz = sp->align_size;

	/* Get actual value by align */
	p->act_hd_sz = ALIGN(sizeof(struct wd_blk_hd), asz);
	p->act_blk_sz = ALIGN(sp->block_size, asz);
	p->act_mem_sz = (p->act_hd_sz + p->act_blk_sz) *
			 (unsigned long)sp->block_num + asz;

	/* When we use WD reserve memory and the blk_sz is larger than 1M,
	 * in order to ensure the mem_pool to be succuss,
	 * we should to reserve more memory
	 */
	if (!sp->br.alloc)
		p->act_mem_sz *= (1 + p->act_blk_sz / BLK_BALANCE_SZ);

	return WD_SUCCESS;
}

static int wd_pool_init(struct wd_queue *q, struct wd_blkpool *p)
{
	__u32 blk_size = p->setup.block_size;
	void *dma_start, *dma_end, *va;
	struct wd_blk_hd *hd = NULL;
	unsigned int dma_num = 0;
	unsigned int i, act_num;

	p->act_start = (void *)ALIGN((uintptr_t)p->usr_mem_start,
				     p->setup.align_size);

	act_num = p->act_mem_sz / (p->act_hd_sz + p->act_blk_sz);

	/* get dma addr and init blks */
	for (i = 0; i < act_num; i++) {
		va = (void *)((uintptr_t)p->act_start + p->act_hd_sz +
			      (unsigned long)(p->act_hd_sz +
			       p->act_blk_sz) * i);
		dma_start = wd_iova_map(q, va, 0);
		dma_end = wd_iova_map(q, va + blk_size - 1, 0);
		if (!dma_start || !dma_end) {
			WD_ERR("wd_iova_map err.\n");
			return -WD_ENOMEM;
		}

		if ((uintptr_t)dma_end - (uintptr_t)dma_start != blk_size - 1)
			continue;

		hd = (void *)((uintptr_t)va - p->act_hd_sz);
		hd->blk_dma = dma_start;
		hd->blk = va;
		hd->blk_tag = TAG_FREE;
		TAILQ_INSERT_TAIL(&p->head, hd, next);

		dma_num++;

		/* Never exceed user's request */
		if (dma_num == p->setup.block_num)
			break;
	}

	/*
	 * if dma_num <= (1 / 1.15) * user's block_num, we think the pool
	 * is created with failure.
	 */
#define NUM_TIMES(x)	(87 * (x) / 100)
	if (dma_num <= NUM_TIMES(p->setup.block_num)) {
		WD_ERR("dma_num = %d, not enough.\n", dma_num);
		return -WD_EINVAL;
	}

	p->free_blk_num = dma_num;
	p->setup.block_num = dma_num;

	return WD_SUCCESS;
}

static int usr_pool_init(struct wd_blkpool *p)
{
	struct wd_blkpool_setup *sp = &p->setup;
	__u32 blk_size = sp->block_size;
	struct wd_blk_hd *hd = NULL;
	int i;

	p->act_start = (void *)ALIGN((uintptr_t)p->usr_mem_start,
				     sp->align_size);
	for (i = 0; i < sp->block_num; i++) {
		hd = p->act_start + (p->act_hd_sz + p->act_blk_sz) * i;
		hd->blk = (void *)((uintptr_t)hd + p->act_hd_sz);
		hd->blk_dma = sp->br.iova_map(sp->br.usr, hd->blk, blk_size);
		if (!hd->blk_dma) {
			WD_ERR("Usr blk map failed.\n");
			return -WD_ENOMEM;
		}
		hd->blk_tag = TAG_FREE;
		TAILQ_INSERT_TAIL(&p->head, hd, next);
	}

	p->free_blk_num = sp->block_num;

	return WD_SUCCESS;
}

static void *pool_init(struct wd_queue *q, struct wd_blkpool *pool,
				  struct wd_blkpool_setup *setup)
{
	void *addr = NULL;

	/* use user's memory, and its br alloc function */
	if (setup->br.alloc) {
		addr = setup->br.alloc(setup->br.usr, pool->act_mem_sz);
		if (!addr) {
			WD_ERR("User pool ops_alloc fail.\n");
			return NULL;
		}

		pool->usr_mem_start = addr;
		if (usr_pool_init(pool)) {
			WD_ERR("User pool init failed.\n");
			goto err_pool_init;
		}
	} else {
		/* use wd to reserve memory */
		if (!q) {
			WD_ERR("q is NULL.\n");
			goto err_pool_init;
		}

		addr = wd_reserve_memory(q, pool->act_mem_sz);
		if (!addr) {
			WD_ERR("wd_reserve_memory fail.\n");
			goto err_pool_init;
		}

		pool->usr_mem_start = addr;
		if (wd_pool_init(q, pool)) {
			WD_ERR("WD pool init failed.\n");

			/* release q will free the addr */
			goto err_pool_init;
		}
		setup->block_num = pool->setup.block_num;
		pool->q = q;
	}

	return pool;

err_pool_init:
	if (setup->br.alloc && setup->br.free)
		setup->br.free(setup->br.usr, addr);

	return NULL;
}

void *wd_blkpool_create(struct wd_queue *q, struct wd_blkpool_setup *setup)
{
	struct wd_blkpool *pool;
	int ret;

	if (!setup) {
		WD_ERR("Pool setup is NULL!\n");
		return NULL;
	}

	pool = calloc(1, sizeof(*pool));
	if (!pool) {
		WD_ERR("Failed to malloc pool.\n");
		return NULL;
	}
	memcpy(&pool->setup, setup, sizeof(*setup));

	ret = wd_pool_pre_layout(pool, setup);
	if (ret)
		goto err_pool_alloc;

	TAILQ_INIT(&pool->head);

	if (!pool_init(q, pool, setup))
		goto err_pool_alloc;

	return pool;

err_pool_alloc:
	free(pool);

	return NULL;
}

void wd_blkpool_destroy(void *pool)
{
	struct wd_blkpool_setup *setup;
	struct wd_blkpool *p = pool;

	if (!p) {
		WD_ERR("pool destroy err, pool is NULL.\n");
		return;
	}

	setup = &p->setup;
	if (p->free_blk_num != setup->block_num) {
		WD_ERR("Can not destroy pool, as it's in use.\n");
		return;
	}

	if (setup->br.free)
		setup->br.free(setup->br.usr, p->usr_mem_start);

	free(p);
}

void *wd_alloc_blk(void *pool)
{
	struct wd_blkpool *p = pool;
	struct wd_blk_hd *hd;

	if (unlikely(!p)) {
		WD_ERR("blk alloc pool is null!\n");
		return NULL;
	}

	wd_spinlock(&p->pool_lock);

	hd = TAILQ_LAST(&p->head, wd_blk_list);
	if (unlikely(!hd || hd->blk_tag != TAG_FREE)) {
		p->alloc_failures++;
		wd_unspinlock(&p->pool_lock);
		WD_ERR("Failed to malloc blk.\n");

		return NULL;
	}

	/* Delete the block buffer from free list */
	TAILQ_REMOVE(&p->head, hd, next);
	p->free_blk_num--;
	hd->blk_tag = TAG_USED;
	wd_unspinlock(&p->pool_lock);

	return hd->blk;
}

void wd_free_blk(void *pool, void *blk)
{
	struct wd_blkpool *p = pool;
	struct wd_blk_hd *hd;

	if (unlikely(!p || !blk)) {
		WD_ERR("free blk params err!\n");
		return;
	}

	hd = wd_blk_head(p, blk);
	if (unlikely(hd->blk_tag != TAG_USED)) {
		WD_ERR("Free block fail!\n");
		return;
	}

	wd_spinlock(&p->pool_lock);
	TAILQ_INSERT_TAIL(&p->head, hd, next);
	p->free_blk_num++;
	hd->blk_tag = TAG_FREE;
	wd_unspinlock(&p->pool_lock);
}

void *wd_blk_iova_map(void *pool, void *blk)
{
	struct wd_blk_hd *hd;

	if (unlikely(!pool || !blk)) {
		WD_ERR("blk map err, pool is NULL!\n");
		return NULL;
	}

	hd = wd_blk_head(pool, blk);
	if (unlikely(hd->blk_tag != TAG_USED ||
	    (uintptr_t)blk < (uintptr_t)hd->blk)) {
		WD_ERR("dma map fail!\n");
		return NULL;
	}

	return (void *)((uintptr_t)hd->blk_dma + ((uintptr_t)blk -
			(uintptr_t)hd->blk));
}

void wd_blk_iova_unmap(void *pool, void *blk_dma, void *blk)
{
	/* do nothting at no-iommu mode */
}

int wd_get_free_blk_num(void *pool, __u32 *free_num)
{
	struct wd_blkpool *p = pool;

	if (!p || !free_num) {
		WD_ERR("get_free_blk_num err, param err!\n");
		return -WD_EINVAL;
	}

	*free_num = __atomic_load_n(&p->free_blk_num, __ATOMIC_RELAXED);

	return WD_SUCCESS;
}

int wd_blk_alloc_failures(void *pool, __u32 *fail_num)
{
	struct wd_blkpool *p = pool;

	if (!p || !fail_num) {
		WD_ERR("get_blk_alloc_failure err, pool is NULL!\n");
		return -WD_EINVAL;
	}

	*fail_num = __atomic_load_n(&p->alloc_failures, __ATOMIC_RELAXED);

	return WD_SUCCESS;
}

__u32 wd_blksize(void *pool)
{
	struct wd_blkpool *p = pool;

	if (!p) {
		WD_ERR("get blk_size pool is null!\n");
		return 0;
	}

	return p->act_blk_sz;
}
