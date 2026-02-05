/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved.
 */

/* Block Memory Management (lib): Adapted for SVA mode */
#define _GNU_SOURCE
#include <dirent.h>
#include <numa.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "wd_internal.h"
#include "wd_bmm.h"
#include "uacce.h"
#include "wd.h"

#define __ALIGN_MASK(x, mask)  (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) __ALIGN_MASK(x, (typeof(x))(a)-1)
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))
#define UACCE_DEV_IOMMU		(1<<7)

#define TAG_FREE	0x12345678  /* block is free */
#define TAG_USED	0x87654321  /* block is busy */
#define MAX_ALIGN_SIZE	0x1000 /* 4KB */
#define MAX_BLOCK_SIZE	0x10000000 /* 256MB */
#define BLK_BALANCE_SZ	0x100000ul
#define NUM_TIMES(x)	(87 * (x) / 100)

#define BYTE_SIZE	8
#define BIT_SHIFT	3

struct wd_ss_region {
	unsigned long long pa;
	void *va;
	size_t size;
	TAILQ_ENTRY(wd_ss_region) next;
};
TAILQ_HEAD(wd_ss_region_list, wd_ss_region);

struct ctx_info {
	int fd;
	int iommu_type;
	void *ss_va;
	size_t ss_mm_size;
	struct wd_ss_region_list ss_list;
	struct wd_ss_region_list *head;
	unsigned long qfrs_offset[UACCE_QFRT_MAX];
};

struct wd_blk_hd {
	unsigned int blk_tag;
	unsigned int blk_num;
	void *blk_dma;
	void *blk;
};

struct wd_blkpool {
	pthread_spinlock_t pool_lock;
	unsigned int free_blk_num;
	unsigned int alloc_failures;
	struct ctx_info *cinfo;
	struct wd_blk_hd *blk_array; // memory blk array
	unsigned int total_blocks; // total blk numbers
	unsigned char *free_bitmap; // free blk bitmap, 0 mean unused
	unsigned int bitmap_size; // bitmap's memory size
	void *usr_mem_start;
	void *act_start;
	unsigned int act_hd_sz;
	unsigned int act_blk_sz;
	unsigned long act_mem_sz;
	unsigned int dev_id;
	struct wd_mempool_setup setup;

	/* SVA mode for Hugepage */
	bool sva_mode;
	handle_t hp_mempool;
	handle_t hp_blkpool;
};

struct mem_ctx_node {
	char alg_name[CRYPTO_MAX_ALG_NAME];
	handle_t h_ctx;
	int numa_id;
	bool used;
	TAILQ_ENTRY(mem_ctx_node) list_node;
};
static TAILQ_HEAD(, mem_ctx_node) g_mem_ctx_list = TAILQ_HEAD_INITIALIZER(g_mem_ctx_list);
static pthread_mutex_t g_mem_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;

handle_t wd_find_ctx(const char *alg_name)
{
	struct mem_ctx_node *close_node = NULL;
	struct mem_ctx_node *node;
	int min_distance = 0xFFFF;
	handle_t h_ctx = 0;
	unsigned int nid;
	int numa_dis;

	if (!alg_name) {
		WD_ERR("Invalid: alg_name is NULL!\n");
		return 0;
	}

	/* Under default conditions in a VM, the node value is 0 */
	if (getcpu(NULL, &nid) || nid == (unsigned int)NUMA_NO_NODE) {
		WD_ERR("invalid: failed to get numa node for memory pool!\n");
		return 0;
	}

	pthread_mutex_lock(&g_mem_ctx_mutex);
	TAILQ_FOREACH(node, &g_mem_ctx_list, list_node) {
		if (node->used == false && strstr(node->alg_name, alg_name)) {
			if (node->numa_id == (int)nid) {
				h_ctx = node->h_ctx;
				node->used = true;
				break;
			}

			/* Query the queue with the shortest NUMA distance */
			numa_dis = numa_distance((int)nid, node->numa_id);
			if (numa_dis < min_distance) {
				min_distance = numa_dis;
				close_node = node;
			}
		}
	}

	/* If no ctx matching the NUMA ID, use the shortest distance instead ctx */
	if (!h_ctx && close_node) {
		h_ctx = close_node->h_ctx;
		close_node->used = true;
	}
	pthread_mutex_unlock(&g_mem_ctx_mutex);

	if (!h_ctx)
		WD_ERR("Failed to find mem ctx for alg: %s\n", alg_name);

	return h_ctx;
}

void wd_remove_ctx_list(void)
{
	struct mem_ctx_node *node;

	pthread_mutex_lock(&g_mem_ctx_mutex);
	/* Free all list node */
	while ((node = TAILQ_FIRST(&g_mem_ctx_list)) != NULL) {
		/* Use TAILQ_REMOVE to remove list node */
		TAILQ_REMOVE(&g_mem_ctx_list, node, list_node);
		free(node);
	}

	pthread_mutex_unlock(&g_mem_ctx_mutex);
}

int wd_insert_ctx_list(handle_t h_ctx, char *alg_name)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;
	struct mem_ctx_node *new_node;
	int numa_id;

	if (!alg_name || !h_ctx) {
		WD_ERR("Invalid: input params is NULL!\n");
		return -WD_EINVAL;
	}

	/* A simple and efficient method to check the queue type */
	if (ctx->fd < 0 || ctx->fd > MAX_FD_NUM) {
		WD_INFO("Invalid ctx: this ctx not HW ctx.\n");
		return 0;
	}

	numa_id = ctx->dev->numa_id;
	new_node = malloc(sizeof(struct mem_ctx_node));
	if (new_node) {
		pthread_mutex_lock(&g_mem_ctx_mutex);
		strncpy(new_node->alg_name, alg_name, CRYPTO_MAX_ALG_NAME - 1);
		new_node->alg_name[CRYPTO_MAX_ALG_NAME - 1] = '\0';
		new_node->numa_id = numa_id;
		new_node->h_ctx = h_ctx;
		new_node->used = false;
		TAILQ_INSERT_TAIL(&g_mem_ctx_list, new_node, list_node);
		pthread_mutex_unlock(&g_mem_ctx_mutex);
		return 0;
	}

	return -WD_ENOMEM;
}

static void wd_free_slice(struct ctx_info *cinfo)
{
	struct wd_ss_region *rgn;

	while (true) {
		rgn = TAILQ_FIRST(&cinfo->ss_list);
		if (!rgn)
			break;
		TAILQ_REMOVE(&cinfo->ss_list, rgn, next);
		free(rgn);
	}
}

static void wd_add_slice(struct ctx_info *cinfo, struct wd_ss_region *rgn)
{
	struct wd_ss_region *rg;

	rg = TAILQ_LAST(&cinfo->ss_list, wd_ss_region_list);
	if (rg) {
		if (rg->pa + rg->size == rgn->pa) {
			rg->size += rgn->size;
			free(rgn);
			return;
		}
	}

	TAILQ_INSERT_TAIL(&cinfo->ss_list, rgn, next);
}

static void wd_show_ss_slices(struct ctx_info *cinfo)
{
	struct wd_ss_region *rgn;
	int i = 0;

	TAILQ_FOREACH(rgn, cinfo->head, next) {
		WD_ERR("slice-%d:size = 0x%lx\n", i, rgn->size);
		i++;
	}
}

static void bitmap_set_bit(unsigned char *bitmap, unsigned int bit_index)
{
	if (!bitmap)
		return;

	bitmap[bit_index >> BIT_SHIFT] |= (1 << (bit_index % BYTE_SIZE));
}

static void bitmap_clear_bit(unsigned char *bitmap, unsigned int bit_index)
{
	if (!bitmap)
		return;

	bitmap[bit_index >> BIT_SHIFT] &= ~(1 << (bit_index % BYTE_SIZE));
}

static bool bitmap_test_bit(const unsigned char *bitmap, unsigned int bit_index)
{
	if (!bitmap)
		return false;

	/* bit is 1, it indicates that the block has already been used and is not free */
	if ((bitmap[bit_index >> BIT_SHIFT] >> (bit_index % BYTE_SIZE)) & 0x1)
		return false;

	return true;
}

static int wd_parse_dev_id(char *dev_name)
{
	char *last_dash;
	char *endptr;
	int dev_id;

	if (!dev_name)
		return -WD_EINVAL;

	/* Find the last '-' in the string. */
	last_dash = strrchr(dev_name, '-');
	if (!last_dash || *(last_dash + 1) == '\0')
		return -WD_EINVAL;

	/* Parse the following number */
	dev_id = strtol(last_dash + 1, &endptr, DECIMAL_NUMBER);
	/* Check whether it is truly all digits */
	if (*endptr != '\0' || dev_id < 0)
		return -WD_EINVAL;

	return dev_id;
}

/*----------------------------------SVA Hugepage memory pool---------------------------------*/
static void *wd_hugepage_pool_create(handle_t h_ctx, struct wd_mempool_setup *setup)
{
	struct wd_ctx_h *ctx = (struct wd_ctx_h *)h_ctx;
	struct wd_blkpool *pool = NULL;
	size_t total_size;
	int numa_id, ret;

	pool = calloc(1, sizeof(*pool));
	if (!pool) {
		WD_ERR("failed to malloc pool.\n");
		return NULL;
	}

	pool->sva_mode = true;
	memcpy(&pool->setup, setup, sizeof(pool->setup));

	total_size = setup->block_size * setup->block_num;
	numa_id = ctx->dev->numa_id;

	ret = wd_parse_dev_id(ctx->dev_path);
	if (ret < 0) {
		WD_ERR("failed to parse device id.\n");
		goto error;
	}
	pool->dev_id = ret;

	/* Create hugepage memory pool */
	pool->hp_mempool = wd_mempool_create(total_size, numa_id);
	if (WD_IS_ERR(pool->hp_mempool)) {
		WD_ERR("failed to create hugepage mempool.\n");
		goto error;
	}

	/* Create memory blocks */
	pool->hp_blkpool = wd_blockpool_create(pool->hp_mempool,
					       setup->block_size,
					       setup->block_num);
	if (WD_IS_ERR(pool->hp_blkpool)) {
		WD_ERR("failed to create hugepage blockpool.\n");
		wd_mempool_destroy(pool->hp_mempool);
		goto error;
	}

	pool->free_blk_num = setup->block_num;
	pool->act_blk_sz = setup->block_size;

	return pool;
error:
	free(pool);
	return NULL;
}

static void wd_hugepage_pool_destroy(struct wd_blkpool *p)
{
	if (p->hp_blkpool) {
		wd_blockpool_destroy(p->hp_blkpool);
		p->hp_blkpool = 0;
	}

	if (p->hp_mempool) {
		wd_mempool_destroy(p->hp_mempool);
		p->hp_mempool = 0;
	}

	free(p);
}

static void *wd_hugepage_blk_alloc(struct wd_blkpool *p, size_t size)
{
	if (size > p->act_blk_sz) {
		WD_ERR("request size %zu > block size %u\n", size, p->act_blk_sz);
		return NULL;
	}

	void *addr = wd_block_alloc(p->hp_blkpool);
	if (!addr) {
		p->alloc_failures++;
		WD_ERR("failed to alloc block from hugepage pool.\n");
		return NULL;
	}

	__atomic_fetch_sub(&p->free_blk_num, 1, __ATOMIC_RELAXED);
	return addr;
}

static void wd_hugepage_blk_free(struct wd_blkpool *p, void *buf)
{
	/* The function call ensures that buf is not null */
	wd_block_free(p->hp_blkpool, buf);
	__atomic_fetch_add(&p->free_blk_num, 1, __ATOMIC_RELAXED);
}

/*----------------------------------No-SVA kernel memory pool--------------------------------*/
static void *wd_mmap_qfr(struct ctx_info *cinfo, enum uacce_qfrt qfrt, size_t size)
{
	off_t off;

	off = qfrt * getpagesize();

	return mmap(0, size, PROT_READ | PROT_WRITE,
		    MAP_SHARED, cinfo->fd, off);
}

static void wd_unmap_reserve_mem(void *addr, size_t size)
{
	int ret;

	if (!addr)
		return;

	ret = munmap(addr, size);
	if (ret)
		WD_ERR("wd qfr unmap failed!\n");
}

static void *wd_map_reserve_mem(struct wd_blkpool *pool, size_t size)
{
	struct ctx_info *cinfo = pool->cinfo;
	struct wd_ss_region *rgn;
	unsigned long info;
	size_t tmp = size;
	unsigned long i = 0;
	void *ptr;
	int ret = 1;

	if (!cinfo) {
		WD_ERR("ctx queue information is NULL!\n");
		return NULL;
	}

	/* Make sure memory map granularity size align */
	if (!cinfo->iommu_type)
		tmp = ALIGN(tmp, UACCE_GRAN_SIZE);

	ptr = wd_mmap_qfr(cinfo, UACCE_QFRT_SS, tmp);
	if (ptr == MAP_FAILED) {
		WD_ERR("wd drv mmap fail!(err = %d)\n", errno);
		return NULL;
	}

	cinfo->ss_va = ptr;
	cinfo->ss_mm_size = tmp;
	tmp = 0;
	while (ret > 0) {
		info = i;
		ret = ioctl(cinfo->fd, UACCE_CMD_GET_SS_DMA, &info);
		if (ret < 0) {
			wd_show_ss_slices(cinfo);
			WD_ERR("get DMA fail!\n");
			goto err_out;
		}

		rgn = malloc(sizeof(*rgn));
		if (!rgn) {
			WD_ERR("alloc ss region fail!\n");
			goto err_out;
		}
		memset(rgn, 0, sizeof(*rgn));

		if (cinfo->iommu_type)
			rgn->size = cinfo->ss_mm_size;
		else
			rgn->size = (info & UACCE_GRAN_NUM_MASK) <<
				UACCE_GRAN_SHIFT;
		rgn->pa = info & (~UACCE_GRAN_NUM_MASK);
		rgn->va = ptr + tmp;
		tmp += rgn->size;
		wd_add_slice(cinfo, rgn);

		i++;
	}

	return ptr;

err_out:
	wd_free_slice(cinfo);
	wd_unmap_reserve_mem(cinfo->ss_va, cinfo->ss_mm_size);

	return NULL;
}

static int wd_pool_params_check(struct wd_mempool_setup *setup)
{
	if (!setup->block_num || !setup->block_size ||
		setup->block_size > MAX_BLOCK_SIZE) {
		WD_ERR("Invalid: block_size or block_num(%x, %u)!\n",
			setup->block_size, setup->block_num);
		return -WD_EINVAL;
	}

	/* Check parameters, and align_size must be 2^N */
	if (setup->align_size <= 0x1 || setup->align_size > MAX_ALIGN_SIZE ||
	    (setup->align_size & (setup->align_size - 0x1))) {
		WD_ERR("Invalid align_size.\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_ctx_info_init(struct wd_ctx_h *ctx, struct wd_blkpool *p)
{
	struct ctx_info *cinfo;

	cinfo = calloc(1, sizeof(struct ctx_info));
	if (!cinfo) {
		WD_ERR("failed to alloc ctx info memory.\n");
		return -WD_ENOMEM;
	}

	cinfo->fd = ctx->fd;
	cinfo->iommu_type = (unsigned int)ctx->dev->flags & UACCE_DEV_IOMMU;
	cinfo->head = &cinfo->ss_list;
	TAILQ_INIT(&cinfo->ss_list);
	(void)memcpy(cinfo->qfrs_offset, ctx->qfrs_offs,
				sizeof(cinfo->qfrs_offset));
	p->cinfo = (void *)cinfo;

	return 0;
}

static int wd_pool_pre_layout(handle_t h_ctx,
			      struct wd_blkpool *p,
			      struct wd_mempool_setup *sp)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;
	struct ctx_info *cinfo = NULL;
	unsigned int asz;
	int ret;

	if (!ctx && !sp->ops.alloc) {
		WD_ERR("ctx is NULL!\n");
		return -WD_EINVAL;
	}

	if (!sp->ops.alloc) {
		ret = wd_ctx_info_init(ctx, p);
		if (ret) {
			WD_ERR("failed to init ctx info.\n");
			return ret;
		}
		cinfo = p->cinfo;
	}

	ret = wd_pool_params_check(sp);
	if (ret) {
		free(p->cinfo);
		p->cinfo = NULL;
		return ret;
	}

	asz = sp->align_size;

	/* Get actual value by align */
	p->act_hd_sz = ALIGN(sizeof(struct wd_blk_hd), asz);
	p->act_blk_sz = ALIGN(sp->block_size, asz);
	p->act_mem_sz = (p->act_hd_sz + p->act_blk_sz) *
			 (unsigned long)sp->block_num + asz;

	/*
	 * When we use WD reserve memory and the blk_sz is larger than 1M,
	 * in order to ensure the mem_pool to be success,
	 * ensure that the allocated memory is an integer multiple of 1M.
	 */
	if (!sp->ops.alloc && (cinfo && !cinfo->iommu_type))
		p->act_mem_sz = ((p->act_mem_sz + BLK_BALANCE_SZ - 1) & ~(BLK_BALANCE_SZ - 1)) << 1;

	return WD_SUCCESS;
}

/**
 * wd_iova_map - Map virtual address to physical address
 * @cinfo: context information
 * @va: virtual address to map
 * @sz: size of the mapping (not used in current implementation)
 *
 * When IOMMU is enabled, the PA is actually an IOVA; userspace still sees it
 * as consistent and contiguous with the VA.
 * When IOMMU is disabled, the PA refers to the kernel's physical address, which
 * must be physically contiguous to be allocated by the kernel.
 * Therefore, the PA address can be obtained from the offset of the VA.
 * 
 */
static void *wd_iova_map(struct ctx_info *cinfo, void *va, size_t sz)
{
	struct wd_ss_region *rgn;
	unsigned long offset;
	void *dma_addr;

	if (!cinfo || !va) {
		WD_ERR("wd iova map: parameter err!\n");
		return NULL;
	}

	/* Search through all memory regions to find where va belongs */
	TAILQ_FOREACH(rgn, cinfo->head, next) {
		if (rgn->va <= va && va < rgn->va + rgn->size) {
			/* Calculate offset within the region */
			offset = (uintptr_t)va - (uintptr_t)rgn->va;
			/* Add base physical address of the region */
			dma_addr = (void *)((uintptr_t)rgn->pa + offset);
			return dma_addr;
		}
	}

	WD_ERR("wd iova map: va not found in any region\n");
	return NULL;
}

/**
 * wd_iova_unmap - Unmap physical address (no-op in non-IOMMU mode)
 * @cinfo: context information
 * @va: virtual address
 * @dma: physical address
 * @sz: size of the mapping (not used in current implementation)
 *
 * In non-IOMMU mode, this function does nothing as there's no need to unmap.
 * In IOMMU mode, this would typically involve unmapping the DMA address.
 */
static void wd_iova_unmap(struct ctx_info *cinfo, void *va, void *dma, size_t sz)
{
	/* For no-iommu, dma-unmap doing nothing */
}

static void wd_pool_uninit(struct wd_blkpool *p)
{
	struct ctx_info *cinfo = p->cinfo;
	struct wd_blk_hd *fhd = NULL;
	unsigned long block_size;
	unsigned int i;

	block_size = (unsigned long)p->act_hd_sz + p->act_blk_sz;
	/* Clean up the allocated resources. */
    	for (i = 0; i < p->total_blocks; i++) {
			/* Release the previously allocated blocks. */
        	fhd = &p->blk_array[i];
       		wd_iova_unmap(cinfo, fhd->blk, fhd->blk_dma, block_size);
    	}

	free(p->free_bitmap);
	p->free_bitmap = NULL;
	free(p->blk_array);
	p->blk_array = NULL;
}

static int wd_pool_init(struct wd_blkpool *p)
{
	struct ctx_info *cinfo = p->cinfo;
	__u32 blk_size = p->setup.block_size;
	void *dma_start, *dma_end, *va;
	struct wd_blk_hd *fhd = NULL;
	struct wd_blk_hd *hd = NULL;
	unsigned int i, j, act_num;
	unsigned long block_size;
	unsigned int dma_num = 0;

	p->act_start = (void *)ALIGN((uintptr_t)p->usr_mem_start,
				     p->setup.align_size);

	/* Calculate the actual number of allocatable blocks */
	block_size = (unsigned long)(p->act_hd_sz + p->act_blk_sz);
	if (block_size == 0) {
		WD_ERR("Invalid block size with header.\n");
		return -WD_EINVAL;
	}
	act_num = p->act_mem_sz / block_size;
	if (!act_num) {
		WD_ERR("Invalid memory size.\n");
		return -WD_EINVAL;
	}

	/* Allocate block array */
	p->blk_array = (struct wd_blk_hd *)malloc(act_num * sizeof(struct wd_blk_hd));
	if (!p->blk_array) {
		WD_ERR("Failed to allocate block array.\n");
		return -WD_ENOMEM;
	}

	/* Allocate bitmap */
	p->total_blocks = act_num;
	p->bitmap_size = (act_num + BYTE_SIZE - 1) >> BIT_SHIFT;
	p->free_bitmap = (unsigned char *)calloc(1, p->bitmap_size);
	if (!p->free_bitmap) {
		WD_ERR("Failed to allocate free bitmap.\n");
		goto bitmap_error;
	}

	/* Initialize all blocks. */
	for (i = 0; i < act_num; i++) {
		/* Calculate the virtual address of the current block. */
		va = (void *)((uintptr_t)p->act_start + block_size * i);

		/* Get the physical address. */
		dma_start = wd_iova_map(cinfo, va, 0);
		dma_end = wd_iova_map(cinfo, va + blk_size - 1, 0);
		if (!dma_start || !dma_end) {
	    		WD_ERR("wd_iova_map err.\n");
		    	/* Clean up the allocated resources. */
		    	goto init_blk_error;
		}

		/* Check whether the physical addresses are contiguous. */
		if ((uintptr_t)dma_end - (uintptr_t)dma_start != blk_size - 1) {
			/* If OS kernel is not open SMMU, need to check dma address */
			WD_INFO("wd dma address not continuous.\n");
			/* Mark as unavailable, bit value is 1. */
			bitmap_set_bit(p->free_bitmap, i);
			continue;
		}

		/* Initialize the block. */
		hd = &p->blk_array[i];
		hd->blk_dma = dma_start;
		hd->blk = va;
		hd->blk_tag = TAG_FREE;
		hd->blk_num = 0;

		dma_num++;
	}

	/*
	 * if dma_num <= (1 / 1.15) * user's block_num, we think the pool
	 * is created with failure.
	 */
	if (dma_num <= NUM_TIMES(p->setup.block_num)) {
		WD_ERR("dma_num = %u, not enough.\n", dma_num);
		goto init_blk_error;
	}

	p->free_blk_num = dma_num;
	p->setup.block_num = dma_num;

	return WD_SUCCESS;

init_blk_error:
	/* Clean up the allocated resources. */
    	for (j = 0; j < i; j++) {
        	/* Release the previously allocated blocks. */
        	fhd = &p->blk_array[j];
       		wd_iova_unmap(cinfo, fhd->blk, fhd->blk_dma, block_size);
    	}
	free(p->free_bitmap);

bitmap_error:
	free(p->blk_array);

	return -WD_ENOMEM;
}

static int usr_pool_init(struct wd_blkpool *p)
{
	struct wd_mempool_setup *sp = &p->setup;
	__u32 blk_size = sp->block_size;
	struct wd_blk_hd *hd = NULL;
	__u32 i;

	p->act_start = (void *)ALIGN((uintptr_t)p->usr_mem_start,
				     sp->align_size);
	for (i = 0; i < sp->block_num; i++) {
		hd = (void *)((uintptr_t)p->act_start + (p->act_hd_sz + p->act_blk_sz) * i);
		hd->blk = (void *)((uintptr_t)hd + p->act_hd_sz);
		hd->blk_dma = sp->ops.iova_map(sp->ops.usr, hd->blk, blk_size);
		if (!hd->blk_dma) {
			WD_ERR("failed to map usr blk.\n");
			return -WD_ENOMEM;
		}
		hd->blk_tag = TAG_FREE;
	}

	p->free_blk_num = sp->block_num;

	return WD_SUCCESS;
}

static int wd_mempool_init(handle_t h_ctx, struct wd_blkpool *pool,
				  struct wd_mempool_setup *setup)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;
	struct ctx_info *cinfo = pool->cinfo;
	void *addr = NULL;
	int ret;

	/* Use user's memory, and its ops alloc function */
	if (setup->ops.alloc && setup->ops.free && setup->ops.iova_map) {
		addr = setup->ops.alloc(setup->ops.usr, pool->act_mem_sz);
		if (!addr) {
			WD_ERR("failed to allocate memory in user pool.\n");
			return -WD_EINVAL;
		}

		pool->usr_mem_start = addr;
		if (usr_pool_init(pool)) {
			WD_ERR("failed to initialize user pool.\n");
			setup->ops.free(setup->ops.usr, addr);
			return -WD_EINVAL;
		}
	} else {
		/* Use wd to reserve memory */
		addr = wd_map_reserve_mem(pool, pool->act_mem_sz);
		if (!addr) {
			WD_ERR("wd pool failed to reserve memory.\n");
			return -WD_ENOMEM;
		}

		pool->usr_mem_start = addr;
		if (wd_pool_init(pool)) {
			WD_ERR("failed to initialize wd pool.\n");
			goto err_out;
		}
		setup->block_num = pool->setup.block_num;
	}

	ret = wd_parse_dev_id(ctx->dev_path);
	if (ret < 0) {
		wd_pool_uninit(pool);
		goto err_out;
	}
	pool->dev_id = ret;

	return WD_SUCCESS;

err_out:
	if (pool->cinfo) {
		wd_free_slice(cinfo);
		wd_unmap_reserve_mem(cinfo->ss_va, cinfo->ss_mm_size);
		pool->cinfo = NULL;
	}
	return -WD_EINVAL;
}

void *wd_mempool_alloc(handle_t h_ctx, struct wd_mempool_setup *setup)
{
	struct wd_blkpool *pool = NULL;
	int ret;

	if (!setup || !h_ctx) {
		WD_ERR("Input param is NULL!\n");
		return NULL;
	}

	ret = wd_is_sva(h_ctx);
	if (ret < 0) {
		WD_ERR("failed to check device ctx!\n");
		return NULL;
	} else if (ret == UACCE_DEV_SVA) {
		WD_INFO("the device is SVA mode!\n");
		return wd_hugepage_pool_create(h_ctx, setup);
	}

	pool = calloc(1, sizeof(*pool));
	if (!pool) {
		WD_ERR("failed to malloc pool.\n");
		return NULL;
	}
	ret = pthread_spin_init(&pool->pool_lock, PTHREAD_PROCESS_PRIVATE);
	if (ret)
		goto err_pool_alloc;

	memcpy(&pool->setup, setup, sizeof(pool->setup));
	pool->sva_mode = false;

	ret = wd_pool_pre_layout(h_ctx, pool, setup);
	if (ret)
		goto err_pool_layout;

	ret = wd_mempool_init(h_ctx, pool, setup);
	if (ret)
		goto err_pool_init;

	return pool;

err_pool_init:
	if (pool->cinfo) {
		free(pool->cinfo);
		pool->cinfo = NULL;
	}
err_pool_layout:
	pthread_spin_destroy(&pool->pool_lock);
err_pool_alloc:
	free(pool);

	return NULL;
}

void wd_mempool_free(handle_t h_ctx, void *pool)
{
	struct wd_mempool_setup *setup;
	struct wd_blkpool *p = pool;

	if (!p || !h_ctx) {
		WD_ERR("pool destroy err, pool or ctx is NULL.\n");
		return;
	}

	if (p->sva_mode) {
		wd_hugepage_pool_destroy(p);
		return;
	}

	setup = &p->setup;
	if (p->free_blk_num != setup->block_num) {
		WD_ERR("Can not destroy blk pool, as it's in use.\n");
		return;
	}

	if (setup->ops.free)
		setup->ops.free(setup->ops.usr, p->usr_mem_start);

	if (p->cinfo) {
		/* Free block array memory */
		if (p->blk_array)
			free(p->blk_array);

		if (p->free_bitmap)
			free(p->free_bitmap);

		wd_free_slice(p->cinfo);
		wd_unmap_reserve_mem(p->cinfo->ss_va, p->cinfo->ss_mm_size);
		free(p->cinfo);
		p->cinfo = NULL;
	}

	pthread_spin_destroy(&p->pool_lock);
	free(p);
}

void wd_mem_free(void *pool, void *buf)
{
	struct wd_blkpool *p = pool;
	struct wd_blk_hd *current_hd;
	struct wd_blk_hd *hd;
	unsigned int current_idx;	
	unsigned int blk_idx;
	unsigned long offset;
	unsigned int i, num;
	unsigned long sz;

	if (unlikely(!p || !buf)) {
		WD_ERR("free blk parameters err!\n");
		return;
	}

	if (p->sva_mode) {
		wd_hugepage_blk_free(p, buf);
		return;
	}

	sz = p->act_hd_sz + p->act_blk_sz;
	if (!sz) {
		WD_ERR("memory pool blk size is zero!\n");
		return;
	}

	if ((uintptr_t)buf < (uintptr_t)p->act_start) {
		WD_ERR("free block addr is error.\n");
		return;
	}

	/* Calculate the block index. */
	offset = (unsigned long)((uintptr_t)buf - (uintptr_t)p->act_start);	
	blk_idx = offset / sz;

	/* Check if the index is valid. */
	if (blk_idx >= p->total_blocks) {
		WD_ERR("Invalid block index<%u>.\n", blk_idx);
		return;
	}

	/* Get the block header. */
	hd = &p->blk_array[blk_idx];
	num = hd->blk_num;

	pthread_spin_lock(&p->pool_lock);
	/* Release all related blocks. */
	for (i = 0; i < num; i++) {
		// Recalculate the index (since it is contiguous).
		current_idx = blk_idx + i;
		current_hd = &p->blk_array[current_idx];
		current_hd->blk_tag = TAG_FREE;
		current_hd->blk_num = 0;
		bitmap_clear_bit(p->free_bitmap, current_idx);
	}
	p->free_blk_num += num;
	pthread_spin_unlock(&p->pool_lock);
}

static int wd_find_contiguous_blocks(struct wd_blkpool *p,
				     unsigned int required_blocks,
				     unsigned int *start_block)
{
#define MAX_SKIP_ATTEMPTS 10
	unsigned int consecutive_count = 0;
	unsigned int skip_attempts = 0;
	struct wd_blk_hd *hd, *tl;
	unsigned int i;

	if (required_blocks == 0 || required_blocks > p->total_blocks)
		return -WD_EINVAL;

	for (i = 0; i < p->total_blocks; i++) {
		if (!bitmap_test_bit(p->free_bitmap, i)) {
			consecutive_count = 0;
			continue;
		}

		if (consecutive_count == 0)
			*start_block = i;
		consecutive_count++;

		if (consecutive_count < required_blocks)
			continue;

		/* Check DMA contiguity only if more than one block is needed */
		if (required_blocks > 1) {
			hd = &p->blk_array[*start_block];
			tl = &p->blk_array[*start_block + required_blocks - 1];

			if (((uintptr_t)tl->blk_dma - (uintptr_t)hd->blk_dma) !=
			    ((uintptr_t)tl->blk - (uintptr_t)hd->blk)) {
				/* Not contiguous, skip this start and try again */
				if (++skip_attempts > MAX_SKIP_ATTEMPTS)
					return -WD_ENOMEM;

				i = *start_block; // will be incremented by loop
				consecutive_count = 0;
				continue;
			}
		}

		/* Found and DMA is contiguous */
		return WD_SUCCESS;
	}

	return -WD_ENOMEM;
}

void *wd_mem_alloc(void *pool, size_t size)
{
	unsigned int required_blocks;
	unsigned int start_block = 0;
	struct wd_blk_hd *hd = NULL;
	struct wd_blkpool *p = pool;
	unsigned int j;
	int ret;

	if (unlikely(!p || !size)) {
		WD_ERR("blk alloc pool is null!\n");
		return NULL;
	}

	if (p->sva_mode)
		return wd_hugepage_blk_alloc(p, size);

	if (!p->act_blk_sz) {
		WD_ERR("blk pool is error!\n");
		return NULL;
	}

	/* Calculate the number of blocks required. */
	required_blocks = (size + p->act_blk_sz - 1) / p->act_blk_sz;
	if (required_blocks > p->free_blk_num) {
		p->alloc_failures++;
		WD_ERR("Not enough free blocks.\n");
		return NULL;
	}

	pthread_spin_lock(&p->pool_lock);
	/* Find contiguous free blocks. */
	ret = wd_find_contiguous_blocks(p, required_blocks, &start_block);
	if (ret != 0) {
		p->alloc_failures++;
		pthread_spin_unlock(&p->pool_lock);
		WD_ERR("Failed to find contiguous blocks.\n");
		return NULL;
	}

	/* Mark all required blocks as used */
	for (j = start_block; j < start_block + required_blocks; j++) {
		p->blk_array[j].blk_tag = TAG_USED;
		bitmap_set_bit(p->free_bitmap, j);
	}

	p->free_blk_num -= required_blocks;
	hd = &p->blk_array[start_block];
	hd->blk_num = required_blocks;
	pthread_spin_unlock(&p->pool_lock);

	return hd->blk;
}

void *wd_mem_map(void *pool, void *buf, size_t sz)
{
	struct wd_blkpool *p = pool;
	struct wd_blk_hd *hd;
	unsigned long offset;
	unsigned long blk_sz;
	unsigned long blk_idx;

	if (unlikely(!pool || !buf)) {
		WD_ERR("blk map err, pool is NULL!\n");
		return NULL;
	}

	/* VA == IOVA in SVA mode */
	if (p->sva_mode)
		return buf;

	if (!sz || (uintptr_t)buf < (uintptr_t)p->act_start) {
		WD_ERR("map buf addr is error.\n");
		return NULL;
	}
	/* Calculate the block index. */
	offset = (unsigned long)((uintptr_t)buf - (uintptr_t)p->act_start);
	blk_sz = p->act_hd_sz + p->act_blk_sz;
	blk_idx = offset / blk_sz;

	/* Check if the index is valid. */
	if (blk_idx >= p->total_blocks) {
		WD_ERR("Invalid block index<%lu> in map.\n", blk_idx);
		return NULL;
	}

	hd = &p->blk_array[blk_idx];
	if (unlikely(hd->blk_tag != TAG_USED ||
	    (uintptr_t)buf < (uintptr_t)hd->blk)) {
		WD_ERR("dma map fail!\n");
		return NULL;
	}

	return (void *)((uintptr_t)hd->blk_dma + ((uintptr_t)buf -
		(uintptr_t)hd->blk));
}

void wd_mem_unmap(void *pool, void *buf_dma, void *buf, size_t sz)
{
	/* do nothing at no-iommu mode */
}

int wd_get_free_num(void *pool, __u32 *free_num)
{
	struct wd_blkpool *p = pool;

	if (!p || !free_num) {
		WD_ERR("get_free_blk_num err, parameter err!\n");
		return -WD_EINVAL;
	}

	*free_num = __atomic_load_n(&p->free_blk_num, __ATOMIC_RELAXED);

	return WD_SUCCESS;
}

int wd_get_fail_num(void *pool, __u32 *fail_num)
{
	struct wd_blkpool *p = pool;

	if (!p || !fail_num) {
		WD_ERR("get_blk_alloc_failure err, pool is NULL!\n");
		return -WD_EINVAL;
	}

	*fail_num = __atomic_load_n(&p->alloc_failures, __ATOMIC_RELAXED);

	return WD_SUCCESS;
}

__u32 wd_get_bufsize(void *pool)
{
	struct wd_blkpool *p = pool;

	if (!p) {
		WD_ERR("get dev id is null!\n");
		return 0;
	}

	return p->act_blk_sz;
}

__u32 wd_get_dev_id(void *pool)
{
	struct wd_blkpool *p = pool;

	if (!p) {
		WD_ERR("failed to get dev id!\n");
		return 0;
	}

	return p->dev_id;
}

