/* SPDX-License-Identifier: Apache-2.0 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "wd.h"

struct blkpool {
	void **blk_elem; /* all the block unit addrs saved in blk_elem */
	size_t depth;    /* the block pool deph, stack depth */
	size_t top;      /* the stack top pos for blk_elem */
	size_t blk_size; /* the size of one block */
	handle_t mp;     /* record from which mempool */
};

struct mempool {
	void *addr;
	size_t size;
};

void *wd_blockpool_alloc(handle_t blockpool)
{
	struct blkpool *bp = (struct blkpool*)blockpool;
	
	if (!bp)
		return NULL;

	if (bp->top > 0) {
		bp->top--;
		return bp->blk_elem[bp->top];
	}
	
	return NULL;
}

void wd_blockpool_free(handle_t blockpool, void *addr)
{
	struct blkpool *bp = (struct blkpool*)blockpool;
	
	if (!bp || !addr)
		return;

	if (bp->top < bp->depth) {
		bp->blk_elem[bp->top] = addr;
		bp->top++;
	}
}

handle_t wd_blockpool_create(handle_t mempool, size_t block_size, size_t block_num)
{
	struct blkpool *bp;
	struct mempool *mp = (struct mempool*)mempool;
	size_t i;

	if (!mp) {
		WD_ERR("Mempool is NULL\n");
		return -EINVAL;
	}

	if (block_size * block_num > mp->size) {
		WD_ERR("block_size = %lu, block_num = %lu, mmp size = %lu\n", block_size, block_num, mp->size);
		return -EINVAL;
	}

	bp = malloc(sizeof(struct blkpool));
	if (!bp)
		return -ENOMEM;

	bp->blk_elem = malloc(sizeof(void*) * block_num);
		if (!bp->blk_elem) {
			free(bp);
			return -ENOMEM;
	}

	for (i = 0; i < block_num; i++) {
		bp->blk_elem[i] = mp->addr + block_size * i;
	}

	bp->top = block_num;
	bp->depth = block_num;
	bp->blk_size = block_size;
	bp->mp = mempool;

	return (handle_t)bp;
}

void wd_blockpool_destory(handle_t blockpool)
{
	struct blkpool *bp = (struct blkpool*)blockpool;

	if (bp) {
		if (bp->blk_elem)
			free(bp->blk_elem);

		free(bp);
	}

	/* Reserve : give back the mempool to the big pool */
	//wd_mempool_reback(bp->mp);
}
