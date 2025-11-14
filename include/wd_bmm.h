/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#ifndef _WD_SVA_BMM_H
#define _WD_SVA_BMM_H

#include <stdint.h>
#include "wd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Memory pool creating parameters */
struct wd_mempool_setup {
	__u32 block_size; /* Block buffer size */
	__u32 block_num; /* Block buffer number */
	__u32 align_size; /* Block buffer starting address align size */
	struct wd_mm_ops ops; /* memory from user if don't use UADK memory */
};

void *wd_mempool_alloc(handle_t h_ctx, struct wd_mempool_setup *setup);
void wd_mempool_free(handle_t h_ctx, void *pool);
void *wd_mem_alloc(void *pool, size_t size);
void wd_mem_free(void *pool, void *buf);

void *wd_mem_map(void *pool, void *buf, size_t sz);
void wd_mem_unmap(void *pool, void *buf_dma, void *buf, size_t sz);
int wd_get_free_num(void *pool, __u32 *free_num);
int wd_get_fail_num(void *pool, __u32 *fail_num);
__u32 wd_get_bufsize(void *pool);

handle_t wd_find_ctx(const char *alg_name);
void wd_remove_ctx_list(void);
int wd_insert_ctx_list(handle_t h_ctx, char *alg_name);
__u32 wd_get_dev_id(void *pool);

#ifdef __cplusplus
}
#endif

#endif /* _WD_SVA_BMM_H */
