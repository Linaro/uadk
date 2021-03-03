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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include "v1/test/bmm.h"
#include "v1/wd.h"
#include "v1/wd_util.h"

#define BITMAP_MAX_BYTE   32
#define BITMAP_BYTE_OFFSET   5
#define BITMAP_BIT_OFFSET   0x1F

#define __ALIGN_MASK(x, mask)  (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) __ALIGN_MASK(x, (typeof(x))(a)-1)

#define TAG 0x0a0b0c0d

struct mem_pool {
	unsigned int tag;
	void *base;
	unsigned int mem_size;
	unsigned int block_size;
	unsigned int block_num;
	unsigned int num_free;
	unsigned int index;
	unsigned long *bitmap;
};

/**
 * Initial a continue memory region to be managed by bmm.
 *
 * @addr_base: the first address of the managed memory region;
 * @mem_size: size of the region;
 * @block_size: size of evry block;
 * @align_size: size of block align;
 */
int bmm_init(void *addr_base, unsigned int mem_size,
			  unsigned int block_size, unsigned int align_size)
{
	struct mem_pool *mempool = (struct mem_pool *)addr_base;
	unsigned int act_blksize;
	unsigned int bitmap_sz;

	/* align_size must be 2^N */
	if ((align_size == 0) || (align_size & (align_size - 1)))
		return -EINVAL;

	if (((uintptr_t)addr_base & (align_size - 1)) != 0)
		return -EINVAL;

	/* actual_block_zise is determined by align_size and block_size de */
	act_blksize = ALIGN(block_size, align_size);
#ifndef NDEBUG
	printf("\nact_blksize = %d, 0x%x\n", act_blksize, act_blksize);
#endif
	if (mem_size <= act_blksize)
		return -ENOMEM;

	memset(mempool, 0, sizeof(*mempool));

	mempool->tag = TAG;
	mempool->mem_size = mem_size;
	mempool->block_size = act_blksize;
	mempool->block_num = mem_size / act_blksize;

	bitmap_sz = (((mempool->block_num - 1) >> BITMAP_BYTE_OFFSET) + 1) *
				sizeof(unsigned long);

	mempool->base = (void *)((uintptr_t)addr_base + bitmap_sz +
			sizeof(struct mem_pool) + align_size);

	mempool->num_free = mempool->block_num;
	mempool->bitmap = (unsigned long *)((uintptr_t)mempool->base +
			 (sizeof(struct mem_pool) + 1));
	if (bitmap_sz <= BITMAP_MAX_BYTE)
		memset(mempool->bitmap, 0, bitmap_sz);
	else
		return -ENOMEM;

	return 0;
}

void *bmm_alloc(void *pool)
{
	struct mem_pool *mempool = (struct mem_pool *)pool;
	unsigned long long index_tmp = mempool->index;
	unsigned long *bitmap_t = mempool->bitmap;
	unsigned short bit_pos;
	unsigned int byte_pos;

	ASSERT(mempool->tag == TAG);

	/* find the free block from the current index to the last one */
	for (; mempool->index < mempool->block_num; mempool->index++) {
		byte_pos = mempool->index >> BITMAP_BYTE_OFFSET;
		bit_pos = mempool->index & BITMAP_BIT_OFFSET;

		/* find the free block */
		if (((bitmap_t[byte_pos]) & (0x1 << bit_pos)) == 0) {
			mempool->index++;
			mempool->num_free--;
			bitmap_t[byte_pos] = bitmap_t[byte_pos] |
				(0x1 << bit_pos);
			mempool->bitmap = bitmap_t;
			pool = (void *)mempool;
			return (void *)((uintptr_t)mempool->base +
				(mempool->index - 1) * mempool->block_size);
		}
	}

	/* find the block from the first one to the current index */
	for (mempool->index = 0; mempool->index < index_tmp; mempool->index++) {
		byte_pos = mempool->index >> BITMAP_BYTE_OFFSET;
		bit_pos = mempool->index & BITMAP_BIT_OFFSET;

		/* find the free block */
		if (((bitmap_t[byte_pos]) & (0x1 << bit_pos)) == 0) {
			mempool->index++;
			mempool->num_free--;
			bitmap_t[byte_pos] = bitmap_t[byte_pos] |
				(0x01 << bit_pos);

			mempool->bitmap = bitmap_t;
			pool = (void *)mempool;
			return (void *)((uintptr_t)mempool->base +
				(mempool->index - 1) * mempool->block_size);
		}
	}

	return NULL;
}

void bmm_free(void *pool, const void *buf)
{
	struct mem_pool *mempool = (struct mem_pool *)pool;
	unsigned long long addr_offset;
	unsigned short bit_pos;
	unsigned int byte_pos;

	ASSERT(mempool->tag == TAG);

	addr_offset = ((uintptr_t)buf - (uintptr_t)mempool->base) /
		mempool->block_size;
	if ((addr_offset + 1) > mempool->block_num) {
		errno = EINVAL;
		return;
	}

	byte_pos = addr_offset >> BITMAP_BYTE_OFFSET;
	bit_pos = ~(1 << addr_offset & BITMAP_BIT_OFFSET);

	mempool->bitmap[byte_pos] = mempool->bitmap[byte_pos] & bit_pos;
	mempool->num_free++;
}
