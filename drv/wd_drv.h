/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2026 Huawei Technologies Co.,Ltd. All rights reserved. */
#ifndef __WD_DRV_H
#define __WD_DRV_H

#include <numa.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>

#include "wd.h"
#include "wd_alg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SOFT_QUEUE_LENGTH	1024U

/**
 * default queue length set to 1024
 */
struct wd_soft_sqe {
	__u8 used;
	__u8 result;
	__u8 complete;
	__u8 rsv;
	__u32 id;
};

struct wd_soft_ctx {
	__u8 ctx_type;
	__u8 rsv[3];
	pthread_spinlock_t slock;
	pthread_spinlock_t rlock;
	__u32 head;
	__u32 tail;
	__u32 run_num;
	int fd;
	void *priv;
	struct wd_soft_sqe qfifo[MAX_SOFT_QUEUE_LENGTH];
};

/* Public function declarations */
int wd_hw_alloc_ctx(char *alg_name,	void *params,	handle_t *ctx);
void wd_hw_free_ctx(handle_t ctx);

int wd_soft_alloc_ctx(char *alg_name, void *params, handle_t *ctx);
void wd_soft_free_ctx(handle_t ctx);

int wd_queue_is_busy(struct wd_soft_ctx *sctx);
int wd_get_sqe_from_queue(struct wd_soft_ctx *sctx, __u32 tag_id);
int wd_put_sqe_to_queue(struct wd_soft_ctx *sctx, __u32 *tag_id, __u8 *result);
struct uacce_dev_list *wd_get_usable_list(struct uacce_dev_list *list, int target_numa);

#ifdef __cplusplus
}
#endif

#endif /* __WD_DRV_H */
