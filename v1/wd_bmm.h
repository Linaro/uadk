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

#ifndef _WD_BMM_H
#define _WD_BMM_H

#ifdef __cplusplus
extern "C" {
#endif

/* Memory pool creating parameters */
struct wd_blkpool_setup {
	__u32 block_size;	/* Block buffer size */
	__u32 block_num;	/* Block buffer number */
	__u32 align_size;	/* Block buffer starting address align size */
	struct wd_mm_br br;	/* memory from user if don't use WD memory */
};

void *wd_blkpool_create(struct wd_queue *q,
			       struct wd_blkpool_setup *setup);
void wd_blkpool_destroy(void *pool);
void *wd_alloc_blk(void *pool);
void wd_free_blk(void *pool, void *blk);
int wd_get_free_blk_num(void *pool, __u32 *free_num);
int wd_blk_alloc_failures(void *pool, __u32 *fail_num);
void *wd_blk_iova_map(void *pool, void *blk);
void wd_blk_iova_unmap(void *pool, void *blk_dma, void *blk);
__u32 wd_blksize(void *pool);

#ifdef __cplusplus
}
#endif

#endif
