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
	unsigned long usr_mem_size;
	struct wd_blkpool_setup setup;
};

static struct wd_blk_hd *wd_blk_head(void *blk)
{
	return (struct wd_blk_hd *)((uintptr_t)blk - sizeof(struct wd_blk_hd));
}

static unsigned long wd_calc_memsize(struct wd_blkpool_setup *setup)
{
	__u32 hd_size = ALIGN(sizeof(struct wd_blk_hd), setup->align_size);
	__u32 act_blksize = ALIGN(setup->block_size, setup->align_size);

	return (hd_size + act_blksize) * (unsigned long)setup->block_num;
}

static int wd_pool_init(struct wd_queue *q, struct wd_blkpool *pool)
{
	__u16 align_sz = pool->setup.align_size;
	__u32 hd_sz = ALIGN(sizeof(struct wd_blk_hd), align_sz);
	__u32 blk_size = pool->setup.block_size;
	__u32 act_blksz = ALIGN(blk_size, align_sz);
	void *dma_start, *dma_end, *va, *addr;
	struct wd_blk_hd *hd = NULL;
	unsigned int dma_num = 0;
	unsigned int i;

	/* get the started addr by align */
	addr = (void *)ALIGN((unsigned long long)pool->usr_mem_start, align_sz);

	/* get dma addr and init blks */
	for (i = 0; i < pool->setup.block_num; i++) {
		va = addr + hd_sz + (hd_sz + act_blksz) * i;

		dma_start = wd_iova_map(q, va, 0);
		dma_end = wd_iova_map(q, va + blk_size - 1, 0);
		if (!dma_start || !dma_end) {
			WD_ERR("wd_iova_map err.\n");
			return -WD_ENOMEM;
		}

		if ((uintptr_t)dma_end - (uintptr_t)dma_start != blk_size - 1)
			continue;

		hd = va - sizeof(struct wd_blk_hd);
		hd->blk_dma = dma_start;
		hd->blk_tag = TAG_FREE;
		TAILQ_INSERT_TAIL(&pool->head, hd, next);

		dma_num++;
	}

	/*
	 * if dma_num <= (1 / 1.15) * user's block_num, we think the pool
	 * is created with failure.
	 */
#define NUM_TIMES(x)	(87 * (x) / 100)
	if (dma_num <= NUM_TIMES(pool->setup.block_num)) {
		WD_ERR("dma_num = %d, not enough.\n", dma_num);
		return -WD_EINVAL;
	}

	pool->free_blk_num = dma_num;
	pool->setup.block_num = dma_num;

	return WD_SUCCESS;
}

static int usr_pool_init(struct wd_blkpool *pool)
{
	__u16 align_sz = pool->setup.align_size;
	__u32 hd_sz = ALIGN(sizeof(struct wd_blk_hd), align_sz);
	__u32 act_blksz = ALIGN(pool->setup.block_size, align_sz);
	struct wd_blk_hd *hd = NULL;
	void *addr;
	int i;

	/* get the started addr by align */
	addr = (void *)ALIGN((uintptr_t)pool->usr_mem_start, align_sz);

	for (i = 0; i < pool->setup.block_num; i++) {
		hd = addr + hd_sz - sizeof(*hd) + (hd_sz + act_blksz) * i;

		hd->blk_dma = pool->setup.br.iova_map(pool->setup.br.usr,
						      hd + 1, act_blksz);
		if (!hd->blk_dma) {
			WD_ERR("Usr blk map failed.\n");
			return -WD_ENOMEM;
		}

		hd->blk_tag = TAG_FREE;
		TAILQ_INSERT_TAIL(&pool->head, hd, next);
	}

	pool->free_blk_num = pool->setup.block_num;
	return WD_SUCCESS;
}

static int para_valid_judge(struct wd_blkpool_setup *setup)
{
	if (!setup) {
		WD_ERR("Invalid setup.\n");
		return -WD_EINVAL;
	}

	if (setup->block_num == 0 || setup->block_size == 0) {
		WD_ERR("Invalid block_size or block_num.\n");
		return -WD_EINVAL;
	}

	/* check the params, and align_size must be 2^N */
	if ((setup->align_size < 2) || setup->align_size > 0x1000 ||
	     (setup->align_size & (setup->align_size - 1))) {
		WD_ERR("Invalid align_size.\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

void *wd_blkpool_create(struct wd_queue *q, struct wd_blkpool_setup *setup)
{
	struct wd_blkpool *pool;
	unsigned long size;
	void *addr;
	int ret;

	ret = para_valid_judge(setup);
	if (ret)
		return NULL;

	size = wd_calc_memsize(setup);

	pool = calloc(1, sizeof(*pool));
	if (!pool) {
		WD_ERR("Failed to malloc pool.\n");
		return NULL;
	}
	memcpy(&pool->setup, setup, sizeof(*setup));

	TAILQ_INIT(&pool->head);

	/* use user's memory, and its br alloc function */
	if (setup->br.alloc) {
		addr = setup->br.alloc(setup->br.usr, size);
		if (!addr) {
			WD_ERR("User pool ops_alloc fail.\n");
			goto err_pool_alloc;
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
			goto err_pool_alloc;
		}

		addr = wd_reserve_memory(q, size);
		if (!addr) {
			WD_ERR("wd_reserve_memory fail.\n");
			goto err_pool_alloc;
		}

		pool->usr_mem_start = addr;
		if (wd_pool_init(q, pool)) {
			WD_ERR("WD pool init failed.\n");

			/* release q will free the addr */
			goto err_pool_alloc;
		}
		setup->block_num = pool->setup.block_num;
	}

	pool->alloc_failures = 0;
	pool->q = q;
	pool->usr_mem_size = size;

	return pool;

err_pool_init:
	setup->br.free(setup->br.usr, addr);

err_pool_alloc:
	free(pool);
	return NULL;
}

void wd_blkpool_destroy(void *pool)
{
	struct wd_blkpool *p = pool;

	if (!p) {
		WD_ERR("pool destroy err, pool is NULL.\n");
		return;
	}

	if (p->free_blk_num != p->setup.block_num) {
		WD_ERR("Can not destroy pool, as it's in use.\n");
	} else {
		if (p->setup.br.alloc)
			free(p->usr_mem_start);

		free(p);
	}
}

void *wd_alloc_blk(void *pool)
{
	struct wd_blkpool *p = pool;
	struct wd_blk_hd *hd;

	if (unlikely(!p)) {
		WD_ERR("blk alloc err, pool is NULL!\n");
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

	/* delete the blk from queue*/
	TAILQ_REMOVE(&p->head, hd, next);
	p->free_blk_num--;
	hd->blk_tag = TAG_USED;
	wd_unspinlock(&p->pool_lock);

	return hd + 1;
}

void wd_free_blk(void *pool, void *blk)
{
	struct wd_blkpool *p = pool;
	struct wd_blk_hd *hd;

	if (unlikely(!p || !blk)) {
		WD_ERR("blk free err, pool is NULL!\n");
		return;
	}

	hd = wd_blk_head(blk);
	if (unlikely(hd->blk_tag != TAG_USED)) {
		WD_ERR("Free block fail!\n");
	} else {
		wd_spinlock(&p->pool_lock);
		TAILQ_INSERT_TAIL(&p->head, hd, next);
		p->free_blk_num++;
		hd->blk_tag = TAG_FREE;
		wd_unspinlock(&p->pool_lock);
	}
}

void *wd_blk_iova_map(void *pool, void *blk)
{
	struct wd_blk_hd *hd;

	if (unlikely(!pool || !blk)) {
		WD_ERR("blk map err, pool is NULL!\n");
		return NULL;
	}

	hd = wd_blk_head(blk);
	if (unlikely(hd->blk_tag != TAG_USED)) {
		WD_ERR("dma map fail!\n");
		return NULL;
	}
	return hd->blk_dma;
}

void wd_blk_iova_unmap(void *pool, void *blk_dma, void *blk)
{
	/* do nothting, but the func should */
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

