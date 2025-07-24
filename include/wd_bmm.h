/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2025-2026 Linaro ltd.
 */

#ifndef _WD_BMM_H
#define _WD_BMM_H

#include <asm/types.h>
#include "wd.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_BLOCK_NM 16384
#define DEFAULT_ALIGN_SIZE 0x40
#define DEFAULT_BLOCK_SIZE (1024 * 8)

/* memory APIs for Algorithm Layer */
typedef void *(*wd_alloc)(void *usr, size_t size);
typedef void (*wd_free)(void *usr, void *va);

 /* memory VA to DMA address map */
typedef void *(*wd_map)(void *usr, void *va, size_t sz);
typedef __u32 (*wd_bufsize)(void *usr);

/* Memory from user, it is given at ctx creating. */
struct wd_mm_br {
	wd_alloc alloc; /* Memory allocation */
	wd_free free; /* Memory free */
	wd_map iova_map; /* get iova from user space VA */
	void *usr; /* data for the above operations */
	wd_bufsize get_bufsize; /* optional */
};

/* Memory pool creating parameters */
struct wd_blkpool_setup {
	__u32 block_size;	/* Block buffer size */
	__u32 block_num;	/* Block buffer number */
	__u32 align_size;	/* Block buffer starting address align size */
	struct wd_mm_br br;	/* memory from user if don't use WD memory */
};


void *wd_blkpool_new(handle_t h_ctx);
void wd_blkpool_delete(void *pool);
int wd_blkpool_setup(void *pool, struct wd_blkpool_setup *setup);
void wd_blkpool_destroy_mem(void *pool);
void *wd_blkpool_alloc(void *pool, size_t size);
void wd_blkpool_free(void *pool, void *va);
void *wd_blkpool_phy(void *pool, void *va);
handle_t wd_blkpool_create_sglpool(void *pool);
void wd_blkpool_destroy_sglpool(void *pool, handle_t sgl_pool);

#ifdef __cplusplus
}
#endif

#endif
