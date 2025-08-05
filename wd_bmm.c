// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2025-2026 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2025-2026 Linaro ltd.
 */

/* Block Memory Management (lib): A block memory algorithm */
#include <asm/byteorder.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <pthread.h>

#include "wd.h"
#include "wd_bmm.h"

#define __ALIGN_MASK(x, mask)  (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) __ALIGN_MASK((uintptr_t)(x), (uintptr_t)(a)-1)

#define TAG_FREE	0x12345678	/* block is free */
#define TAG_USED	0x87654321	/* block is busy */
#define MAX_ALIGN_SIZE	0x1000		/* 4KB */
#define MAX_BLOCK_SIZE	0x10000000	/* 256MB */
#define BLK_BALANCE_SZ	0x100000ul
#define NUM_TIMES(x)	(87 * (x) / 100)

#define WD_UACCE_GRAN_SIZE		0x10000ull
#define WD_UACCE_GRAN_SHIFT		16
#define WD_UACCE_GRAN_NUM_MASK		0xfffull

#define DEFAULT_BLKSIZE_ALIGN 0x1000

/* the max sge num in one sgl */
#define SGE_NUM_IN_SGL 255

/* the max sge num in on BD, QM user it be the sgl pool size */
#define SGL_NUM_IN_BD 256

struct wd_blk_hd {
	unsigned int blk_tag;
	void *blk_dma;
	void *blk;

	TAILQ_ENTRY(wd_blk_hd) next;
};

TAILQ_HEAD(wd_blk_list, wd_blk_hd);

struct wd_ss_region {
	void *va;
	unsigned long long pa;
	size_t size;

	TAILQ_ENTRY(wd_ss_region) next;
};

TAILQ_HEAD(wd_ss_region_list, wd_ss_region);

struct wd_blkpool {
	pthread_spinlock_t lock;
	unsigned int free_blk_num;
	unsigned int blk_num;
	unsigned int alloc_failures;
	struct wd_blk_list head;
	void *act_start;
	unsigned int hd_sz;
	unsigned int blk_sz;
	struct wd_blkpool_setup setup;

	handle_t ctx;
	void *mem;
	unsigned long size;
	struct wd_ss_region_list ss_list;
	struct wd_ss_region_list *ss_head;
	struct hisi_sgl_pool *sgl_pool;
	void *sgl_mem;
	size_t sgl_size;
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
	/* the sgl src address array */
	void **sgl;
	/* the sgl pool stack depth */
	__u32 depth;
	__u32 top;
	__u32 sge_num;
	__u32 sgl_num;
	pthread_spinlock_t lock;
	void **phys;
};

static struct wd_blk_hd *wd_blk_head(struct wd_blkpool *pool, void *blk)
{
	unsigned long offset = (unsigned long)((uintptr_t)blk -
					       (uintptr_t)pool->act_start);
	unsigned long sz = pool->hd_sz + pool->blk_sz;
	unsigned long blk_idx = offset / sz;

	return (struct wd_blk_hd *)((uintptr_t)pool->act_start + blk_idx * sz);
}

static int pool_params_check(struct wd_blkpool_setup *setup)
{
	if (!setup->block_size ||
	    setup->block_size > MAX_BLOCK_SIZE) {
		WD_ERR("Invalid block_size (%x)!\n",
			setup->block_size);
		return -WD_EINVAL;
	}

	/* check parameters, and align_size must be 2^N */
	if (setup->align_size == 0x1 || setup->align_size > MAX_ALIGN_SIZE ||
	    setup->align_size & (setup->align_size - 0x1)) {
		WD_ERR("Invalid align_size.\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static inline int calculate_sgl_size(void)
{
	int sgl_size = sizeof(struct hisi_sgl) +
		       SGE_NUM_IN_SGL * sizeof(struct hisi_sge);

	return ALIGN(sgl_size, DEFAULT_ALIGN_SIZE);
}

static inline size_t calculate_extra_sgl_size(void)
{
	return SGL_NUM_IN_BD * calculate_sgl_size();
}

static int wd_pool_pre_layout(struct wd_blkpool *p,
			      struct wd_blkpool_setup *sp)
{
	size_t extra_sgl_size = calculate_extra_sgl_size();
	unsigned int asz;
	int ret;

	ret = pool_params_check(sp);
	if (ret)
		return ret;

	asz = sp->align_size;

	/* Get actual value by align */
	p->hd_sz = ALIGN(sizeof(struct wd_blk_hd), asz);
	p->blk_sz = ALIGN(sp->block_size, asz);

	if (p->size == 0 && !p->mem) {
		p->size = (p->hd_sz + p->blk_sz) *
			  (unsigned long)sp->block_num + asz +
			  extra_sgl_size;

		/* Make sure memory map granularity size align */
		if (wd_is_noiommu(p->ctx))
			p->size = ALIGN(p->size, WD_UACCE_GRAN_SIZE);
	}

	return WD_SUCCESS;
}

static void *wd_get_phys(struct wd_blkpool *pool, void *va)
{
	struct wd_ss_region *rgn;

	TAILQ_FOREACH(rgn, pool->ss_head, next) {
		if (rgn->va <= va && va < rgn->va + rgn->size)
			return (void *)(uintptr_t)(rgn->pa +
				((uintptr_t)va - (uintptr_t)rgn->va));
	}

	return NULL;
}

static int wd_pool_init(struct wd_blkpool *p)
{
	__u32 blk_size = p->setup.block_size;
	size_t extra_sgl_size = calculate_extra_sgl_size();
	void *dma_start, *dma_end, *va;
	struct wd_blk_hd *hd = NULL;
	unsigned int dma_num = 0;
	unsigned int i, act_num;
	unsigned long loss;

	p->act_start = (void *)ALIGN((uintptr_t)p->mem, p->setup.align_size);
	loss = p->act_start - p->mem;

	/* ignore sgl */
	act_num = (p->size - loss - extra_sgl_size) / (p->hd_sz + p->blk_sz);

	/* get dma address and initialize blocks */
	for (i = 0; i < act_num; i++) {
		va = (void *)((uintptr_t)p->act_start + p->hd_sz +
			      (unsigned long)(p->hd_sz +
			       p->blk_sz) * i);
		dma_start = wd_get_phys(p, va);
		dma_end = wd_get_phys(p, va + blk_size - 1);
		if (!dma_start || !dma_end) {
			WD_ERR("wd_get_phys err.\n");
			return -WD_ENOMEM;
		}

		if ((uintptr_t)dma_end - (uintptr_t)dma_start != blk_size - 1)
			continue;

		hd = (void *)((uintptr_t)va - p->hd_sz);
		hd->blk_dma = dma_start;
		hd->blk = va;
		hd->blk_tag = TAG_FREE;
		TAILQ_INSERT_TAIL(&p->head, hd, next);

		dma_num++;
	}

	p->free_blk_num = dma_num;
	p->blk_num = dma_num;

	return WD_SUCCESS;
}

static int usr_pool_init(struct wd_blkpool *p)
{
	struct wd_blkpool_setup *sp = &p->setup;
	size_t extra_sgl_size = calculate_extra_sgl_size();
	__u32 blk_size = sp->block_size;
	struct wd_blk_hd *hd = NULL;
	unsigned long loss;
	unsigned int i, act_num;

	p->act_start = (void *)ALIGN((uintptr_t)p->mem, sp->align_size);
	loss = p->act_start - p->mem;
	/* ignore sgl */
	act_num = (p->size - loss - extra_sgl_size) / (p->hd_sz + p->blk_sz);

	for (i = 0; i < act_num; i++) {
		hd = (void *)((uintptr_t)p->act_start + (p->hd_sz + p->blk_sz) * i);
		hd->blk = (void *)((uintptr_t)hd + p->hd_sz);
		hd->blk_dma = sp->br.iova_map(sp->br.usr, hd->blk, blk_size);
		if (!hd->blk_dma) {
			WD_ERR("failed to map usr blk.\n");
			return -WD_ENOMEM;
		}
		hd->blk_tag = TAG_FREE;
		TAILQ_INSERT_TAIL(&p->head, hd, next);
	}

	p->free_blk_num = act_num;
	p->blk_num = p->free_blk_num;

	return WD_SUCCESS;
}

static void drv_free_slice(struct wd_blkpool *p)
{
	struct wd_ss_region *rgn;

	while (true) {
		rgn = TAILQ_FIRST(&p->ss_list);
		if (!rgn)
			break;
		TAILQ_REMOVE(&p->ss_list, rgn, next);
		free(rgn);
	}
}

static void drv_add_slice(struct wd_blkpool *p, struct wd_ss_region *rgn)
{
	struct wd_ss_region *rg;

	rg = TAILQ_LAST(&p->ss_list, wd_ss_region_list);
	if (rg) {
		if (rg->pa + rg->size == rgn->pa) {
			rg->size += rgn->size;
			free(rgn);
			return;
		}
	}

	TAILQ_INSERT_TAIL(&p->ss_list, rgn, next);
}

static void *pool_reserve_mem(struct wd_blkpool *p, size_t size)
{
	struct wd_ss_region *rgn = NULL;
	unsigned long info = 0;
	size_t tmp = 0;
	unsigned long i = 0;
	void *ptr = NULL;
	int ret = 1;

	if (!p->ctx)
		return NULL;

	if (p->mem)
		return NULL;

	ptr = wd_reserve_mem(p->ctx, size);
	if (!ptr)
		return NULL;

	p->ss_head = &p->ss_list;
	TAILQ_INIT(&p->ss_list);

	while (ret > 0) {
		info = i;
		ret = wd_ctx_set_io_cmd(p->ctx, UACCE_CMD_GET_SS_DMA, &info);
		if (ret < 0) {
			WD_ERR("get DMA fail!\n");
			goto err_out;
		}
		rgn = malloc(sizeof(*rgn));
		if (!rgn) {
			WD_ERR("alloc ss region fail!\n");
			goto err_out;
		}
		memset(rgn, 0, sizeof(*rgn));

		if (wd_is_noiommu(p->ctx))
			rgn->size = (info & WD_UACCE_GRAN_NUM_MASK) <<
				WD_UACCE_GRAN_SHIFT;
		else
			rgn->size = p->size;
		rgn->pa = info & (~WD_UACCE_GRAN_NUM_MASK);
		rgn->va = ptr + tmp;
		tmp += rgn->size;
		drv_add_slice(p, rgn);
		i++;
	}

	return ptr;

err_out:
	drv_free_slice(p);
	munmap(p->mem, size);

	return NULL;
}

static int pool_init(struct wd_blkpool *pool,
		     struct wd_blkpool_setup *setup)
{
	void *addr = NULL;

	/* use user's memory, and its br alloc function */
	if (setup->br.alloc && setup->br.free) {
		if (!pool->mem) {
			addr = setup->br.alloc(setup->br.usr, pool->size);
			if (!addr) {
				WD_ERR("failed to allocate memory in user pool.\n");
				return -EINVAL;
			}
			pool->mem = addr;
		}
		if (usr_pool_init(pool)) {
			WD_ERR("failed to initialize user pool.\n");
			setup->br.free(setup->br.usr, addr);
			return -EINVAL;
		}
	} else {
		if (!pool->mem) {
			/* use wd to reserve memory */
			addr = pool_reserve_mem(pool, pool->size);
			if (!addr) {
				WD_ERR("wd pool failed to reserve memory.\n");
				return -EINVAL;
			}
			pool->mem = addr;
		}

		if (wd_pool_init(pool)) {
			WD_ERR("failed to initialize wd pool.\n");
			wd_blkpool_destroy_mem(pool);
			return -EINVAL;
		}
	}

	return 0;
}

void *wd_blkpool_new(handle_t h_ctx)
{
	struct wd_blkpool *pool;

	if (wd_is_sva(h_ctx))
		return NULL;

	pool = calloc(1, sizeof(*pool));
	if (!pool) {
		WD_ERR("failed to malloc pool.\n");
		return NULL;
	}
	pool->ctx = h_ctx;

	if (pthread_spin_init(&pool->lock, PTHREAD_PROCESS_SHARED) != 0) {
		free(pool);
		return NULL;
	}
	return pool;
}

int wd_blkpool_setup(void *pool, struct wd_blkpool_setup *setup)
{
	struct wd_blkpool *p = pool;
	int ret = 0;

	if (!p || !setup)
		return -EINVAL;

	pthread_spin_lock(&p->lock);
	if (p->mem && p->size != 0) {
		if (p->setup.block_size == setup->block_size ||
		    p->blk_sz == ALIGN(setup->block_size, setup->align_size))
			goto out;

		/* re-org blk_size, no need reserve mem */
		if (p->free_blk_num != p->blk_num) {
			WD_ERR("Can not reset blk pool, as it's in use.\n");
			ret = -EINVAL;
			goto out;
		}
	}

	memcpy(&p->setup, setup, sizeof(p->setup));

	ret = wd_pool_pre_layout(p, setup);
	if (ret)
		goto out;

	TAILQ_INIT(&p->head);

	ret = pool_init(p, setup);

out:
	pthread_spin_unlock(&p->lock);
	return ret;
}

void *wd_blkpool_alloc(void *pool, size_t size)
{
	struct wd_blkpool *p = pool;
	struct wd_blk_hd *hd;
	int ret;

	if (!p)
		return NULL;

	if (!p->mem || size > p->blk_sz) {
		struct wd_blkpool_setup setup;
		/*
		 * if empty pool, will reserve mem and init pool
		 * if size > blk_size, will re-org as align 4K if free pool
		 */

		memset(&setup, 0, sizeof(setup));
		setup.block_size = ALIGN(size, DEFAULT_BLKSIZE_ALIGN);
		setup.block_num = DEFAULT_BLOCK_NM;
		setup.align_size = DEFAULT_ALIGN_SIZE;
		ret = wd_blkpool_setup(p, &setup);
		if (ret)
			return NULL;
	}

	pthread_spin_lock(&p->lock);
	hd = TAILQ_LAST(&p->head, wd_blk_list);
	if (unlikely(!hd || hd->blk_tag != TAG_FREE)) {
		p->alloc_failures++;
		goto out;
	}

	/* Delete the block buffer from free list */
	TAILQ_REMOVE(&p->head, hd, next);
	p->free_blk_num--;
	hd->blk_tag = TAG_USED;
	pthread_spin_unlock(&p->lock);

	return hd->blk;

out:
	pthread_spin_unlock(&p->lock);
	WD_ERR("Failed to malloc blk.\n");

	return NULL;
}

void wd_blkpool_free(void *pool, void *va)
{
	struct wd_blkpool *p = pool;
	struct wd_blk_hd *hd;

	if (!p || !va)
		return;

	hd = wd_blk_head(p, va);
	if (unlikely(hd->blk_tag != TAG_USED)) {
		WD_ERR("free block fail!\n");
		return;
	}

	pthread_spin_lock(&p->lock);
	TAILQ_INSERT_TAIL(&p->head, hd, next);
	p->free_blk_num++;
	hd->blk_tag = TAG_FREE;
	pthread_spin_unlock(&p->lock);
}

void *wd_blkpool_phy(void *pool, void *va)
{
	struct wd_blkpool *p = pool;
	struct wd_blk_hd *hd;
	unsigned long off, idx;

	if (!pool || !va)
		return NULL;

	if (p->sgl_mem != 0 && va >= p->sgl_mem) {
		off = (unsigned long) (va - p->sgl_mem);
		idx = off / p->sgl_size;

		return p->sgl_pool->phys[idx];
	}

	hd = wd_blk_head(pool, va);
	if (hd->blk_tag != TAG_USED ||
	    (uintptr_t)va < (uintptr_t)hd->blk)
		return NULL;

	return (void *)((uintptr_t)hd->blk_dma + ((uintptr_t)va -
			(uintptr_t)hd->blk));
}

int wd_blkpool_get_free_blk_num(void *pool, __u32 *free_num)
{
	struct wd_blkpool *p = pool;

	if (!p || !free_num) {
		WD_ERR("get_free_blk_num err, parameter err!\n");
		return -WD_EINVAL;
	}

	*free_num = __atomic_load_n(&p->free_blk_num, __ATOMIC_RELAXED);

	return WD_SUCCESS;
}

int wd_blkpool_alloc_failures(void *pool, __u32 *fail_num)
{
	struct wd_blkpool *p = pool;

	if (!p || !fail_num) {
		WD_ERR("get_blk_alloc_failure err, pool is NULL!\n");
		return -WD_EINVAL;
	}

	*fail_num = __atomic_load_n(&p->alloc_failures, __ATOMIC_RELAXED);

	return WD_SUCCESS;
}

__u32 wd_blkpool_blksize(void *pool)
{
	struct wd_blkpool *p = pool;

	if (!p) {
		WD_ERR("get blk_size pool is null!\n");
		return 0;
	}

	return p->blk_sz;
}

void wd_blkpool_destroy_mem(void *pool)
{
	struct wd_blkpool_setup *setup;
	struct wd_blkpool *p = pool;

	if (!p) {
		WD_ERR("pool destroy err, pool is NULL.\n");
		return;
	}

	pthread_spin_lock(&p->lock);
	if (p->mem) {
		setup = &p->setup;
		if (setup->br.free) {
			setup->br.free(setup->br.usr, p->mem);
		} else {
			drv_free_slice(p);
			munmap(p->mem, p->size);
		}
		p->mem = NULL;
		p->size = 0;
	}
	pthread_spin_unlock(&p->lock);
}

void wd_blkpool_delete(void *pool)
{
	struct wd_blkpool *p = pool;

	if (!p)
		return;

	wd_blkpool_destroy_mem(pool);
	pthread_spin_destroy(&p->lock);
	free(p);
}

handle_t wd_blkpool_create_sglpool(void *pool)
{
	struct wd_blkpool *p = pool;
	struct hisi_sgl_pool *sgl_pool;
	struct hisi_sgl *sgl_align;
	size_t sgl_size = calculate_sgl_size();
	size_t extra_sgl_size = calculate_extra_sgl_size();
	struct wd_blkpool_setup *sp;
	void *base;

	if (!p)
		return 0;

	sgl_pool = calloc(1, sizeof(struct hisi_sgl_pool));
	if (!sgl_pool) {
		WD_ERR("failed to alloc memory for sgl_pool!\n");
		return 0;
	}

	sgl_pool->sgl_align = calloc(SGL_NUM_IN_BD, sizeof(void *));
	if (!sgl_pool->sgl_align) {
		WD_ERR("failed to alloc memory for sgl align!\n");
		goto err_out;
	}

	sgl_pool->phys = calloc(SGL_NUM_IN_BD, sizeof(void *));
	if (!sgl_pool->phys) {
		WD_ERR("failed to alloc memory for phys!\n");
		goto err_out;
	}

	base = (void *)((uintptr_t)p->mem + p->size - extra_sgl_size);
	sp = &p->setup;

	for (int i = 0; i < SGL_NUM_IN_BD; i++) {
		sgl_align = (struct hisi_sgl *)ALIGN(base + sgl_size * i, DEFAULT_ALIGN_SIZE);
		sgl_align->entry_sum_in_chain = SGE_NUM_IN_SGL;
		sgl_align->entry_sum_in_sgl = 0;
		sgl_align->entry_length_in_sgl = SGE_NUM_IN_SGL;
		sgl_align->next_dma = 0;
		sgl_pool->sgl_align[i] = sgl_align;
		if (sp->br.iova_map)
			sgl_pool->phys[i] = sp->br.iova_map(sp->br.usr, sgl_align, sgl_size);
		else
			sgl_pool->phys[i] = wd_get_phys(p, sgl_align);
	}

	if (pthread_spin_init(&sgl_pool->lock, PTHREAD_PROCESS_SHARED) != 0) {
		WD_ERR("failed to init sgl pool lock!\n");
		goto err_out;
	}

	sgl_pool->sgl_num = SGL_NUM_IN_BD;
	sgl_pool->sge_num = SGE_NUM_IN_SGL;
	sgl_pool->depth = SGL_NUM_IN_BD;
	sgl_pool->top = SGL_NUM_IN_BD;
	p->sgl_pool = sgl_pool;
	p->sgl_size = sgl_size;
	p->sgl_mem = (void *)ALIGN(base, DEFAULT_ALIGN_SIZE);

	return (handle_t)sgl_pool;

err_out:
	if (sgl_pool->phys)
		free(sgl_pool->phys);
	if (sgl_pool->sgl_align)
		free(sgl_pool->sgl_align);
	free(sgl_pool);
	return (handle_t)0;
}

void wd_blkpool_destroy_sglpool(void *pool, handle_t h_sgl_pool)
{
	struct hisi_sgl_pool *sgl_pool = (struct hisi_sgl_pool *)h_sgl_pool;

	if (!h_sgl_pool)
		return;

	pthread_spin_destroy(&sgl_pool->lock);
	if (sgl_pool->phys)
		free(sgl_pool->phys);
	if (sgl_pool->sgl_align)
		free(sgl_pool->sgl_align);
	free(sgl_pool);
}
