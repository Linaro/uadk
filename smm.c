/* SPDX-License-Identifier: Apache-2.0 */
/* Simple Memory Memory (lib): A simple first fit memory algorithm */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include "smm.h"

#define SMM_HEAD_TAG 0xE5E5
#define SMMB_HEAD_FREE_TAG 0x5E5E
#define SMMB_HEAD_ALLOCED_TAG 0xAAAA

/* todo: free block need not to be the same as allocated block */
struct smmb_head {
	int tag;
	size_t size;
	struct smmb_head *next;
};

/* todo: make alignment */
struct smm_head {
	int tag;
	int align_mask;
	struct smmb_head *freelist;
};

static size_t __aligned_size(size_t sz, int align_mask)
{
	//printf("__aligned_size: %lx, %x, %x\n", sz, align_mask, ~align_mask);
	return (sz + align_mask) & ~align_mask;
}

/**
 * Initial a continue memory region to be managed by smm.
 *
 * @pt_addr the first address of the managed memory region
 * @size size of the region
 * @align_mask mask for address mask, 
 *             e.g. 0xFFF for aligning the memory block to 4K boundary
 */
int smm_init(void *pt_addr, size_t size, int align_mask)
{
	struct smm_head *h = pt_addr;
	struct smmb_head *bh;
	size_t hs = __aligned_size(sizeof(*h), align_mask);
	size_t bs = __aligned_size(sizeof(*bh), align_mask);

	if (size < hs + bs)
		return -ENOMEM;

	h->tag = SMM_HEAD_TAG;
	h->align_mask = align_mask;
	bh = h->freelist = pt_addr + hs;
	bh->tag = SMMB_HEAD_FREE_TAG;
	bh->next = NULL;
	bh->size = size - hs;
	
	return 0;
}

void *smm_alloc(void *pt_addr, size_t size)
{
	struct smm_head *h = pt_addr;
	struct smmb_head **bhp = &h->freelist;
	struct smmb_head *bh_new, *bh = h->freelist;
	size_t sz = __aligned_size(size + sizeof(*bh), h->align_mask);
	//printf("alloc 0x%lx for 0x%lx\n", sz, size);

	assert(h->tag == SMM_HEAD_TAG);

	while (bh) {
		assert(bh->tag == SMMB_HEAD_FREE_TAG);

		//printf("alloc try block(%p, %ld) for %ld\n", bh, bh->size, sz);
		if (bh->size >= sz) {
			/* gotcha */

			if (bh->size < sz + sizeof(*bh)) {
				//printf("use the whole block\n");
				*bhp = bh->next;
			} else {
				bh_new = (void *)bh + sz;
				bh_new->tag = SMMB_HEAD_FREE_TAG;
				bh_new->size = bh->size - sz;
				bh_new->next = bh->next;
				*bhp = bh_new;
				bh->size = sz;
				//printf("split block, new block %p(%ld)\n",
				//       bh_new, bh_new->size);
			}

			bh->tag = SMMB_HEAD_ALLOCED_TAG;
			return bh + 1;
		}

		bhp = &(bh->next);
		bh = bh->next;
	}

	return NULL;
}

static inline _Bool __merge_free_block(struct smmb_head *h1,
				      struct smmb_head *h2)
{
	if ((void *)h1 + h1->size == h2) {
		//printf("merge %p, %p\n", h1, h2);
		h1->size += h2->size;
		h1->next = h2->next;
		return true;
	}

	//printf("nomerge %p, %p\n", h1, h2);
	return false;
}

void smm_free(void *pt_addr, void *ptr)
{
	struct smm_head *h = pt_addr;
	struct smmb_head **bhp = &h->freelist;
	struct smmb_head *bh = h->freelist;
	struct smmb_head *bh_cur = ptr - sizeof(struct smmb_head);

	assert(h->tag == SMM_HEAD_TAG);
	//printf("bh_cur->tag= %x\n", bh_cur->tag);
	assert(bh_cur->tag == SMMB_HEAD_ALLOCED_TAG);

	if (!bh) {
		*bhp = bh_cur;
		bh_cur->tag = SMMB_HEAD_FREE_TAG;
		return;
	}

	while (bh) {
		assert(bh->tag == SMMB_HEAD_FREE_TAG);

		//printf("free: bh=%p, bh->size=%ld, bh_cur=%p\n", bh, bh->size, bh_cur);
		if (bh_cur < bh) {
			*bhp = bh_cur;
			bh_cur->tag = SMMB_HEAD_FREE_TAG;

			if (!__merge_free_block(bh_cur, bh))
				bh_cur->next = bh;

			return;
		} else if ((void *)bh + bh->size == bh_cur) {
			bh->size += bh_cur->size;
			(void)__merge_free_block(bh, bh->next);
			return;
		}

		bhp = &(bh->next);
		bh = bh->next;
	}

	assert(false);
}

void *smm_realloc(void *pt_addr, void *ptr, size_t size)
{
	/* there is no benefit to do reallocation in this algorithm */
	assert(false);
}

#ifndef NDEBUG
void smm_dump(void *pt_addr) {
	struct smm_head *h = pt_addr;
	struct smmb_head *bh = h->freelist;

	assert(h->tag == SMM_HEAD_TAG);

	printf("dump pt %p: align_mask = 0x%x\n", h, h->align_mask);
	while (bh) {
		assert(bh->tag == SMMB_HEAD_FREE_TAG);
		printf("freeblock(%p): sz=%ld\n", bh, bh->size);
		bh = bh->next;
	}
}

int smm_get_freeblock_num(void *pt_addr) {
	struct smm_head *h = pt_addr;
	struct smmb_head *bh = h->freelist;
	int ret = 0;

	assert(h->tag == SMM_HEAD_TAG);

	while (bh) {
		assert(bh->tag == SMMB_HEAD_FREE_TAG);
		bh = bh->next;
		ret++;
	}

	return ret;
}
#endif
