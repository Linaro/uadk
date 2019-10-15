/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _WD_BMM_H
#define _WD_BMM_H


/* Memory pool creating parameters */
struct wd_blkpool_setup {
	__u32 block_size;	/* Block buffer size */
	__u32 block_num;	/* Block buffer number */
	__u32 align_size;	/* Block buffer startging address align size */
	struct wd_mm_br br;	/* memory from user if don't use WD memory */
};

extern void *wd_blkpool_create(struct wd_queue *q,
			       struct wd_blkpool_setup *setup);
extern void wd_blkpool_destroy(void *pool);
extern void *wd_alloc_blk(void *pool);
extern void wd_free_blk(void *pool, void *blk);
extern int wd_get_free_blk_num(void *pool, __u32 *free_num);
extern int wd_blk_alloc_failures(void *pool, __u32 *fail_num);
extern void *wd_blk_iova_map(void *pool, void *blk);
extern void wd_blk_iova_unmap(void *pool, void *blk_dma, void *blk);
#endif
