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
#include <dirent.h>

#include "wd_util.h"

#define BYTE_TO_BIT		8

void wd_spinlock(struct wd_lock *lock)
{
	while (__atomic_test_and_set(&lock->lock, __ATOMIC_ACQUIRE))
		while (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED))
			;
}

void wd_unspinlock(struct wd_lock *lock)
{
	__atomic_clear(&lock->lock, __ATOMIC_RELEASE);
}

void *drv_iova_map(struct wd_queue *q, void *va, size_t sz)
{
	struct q_info *qinfo = q->qinfo;

	if (qinfo->br.iova_map)
		return (void *)qinfo->br.iova_map(qinfo->br.usr, va, sz);
	else
		return wd_iova_map(q, va, sz);
}

void drv_iova_unmap(struct wd_queue *q, void *va, void *dma, size_t sz)
{
	struct q_info *qinfo = q->qinfo;

	if (qinfo->br.iova_unmap)
		qinfo->br.iova_unmap(qinfo->br.usr, va, dma, sz);
	else
		wd_iova_unmap(q, va, dma, sz);
}

int wd_alloc_ctx_id(struct wd_queue *q, int max_num)
{
	struct q_info *qinfo = q->qinfo;
	int ctx_id = 0;
	int i = 0;
	int j = 0;

	if (max_num > CTX_ID_MAX_NUM * BYTE_TO_BIT) {
		WD_ERR("err: alloc ctx id max_num overflow!\n");
		return -WD_EINVAL;
	}

	while (qinfo->ctx_id[i] & 0x1 << j) {
		ctx_id++;

		if (ctx_id >= max_num)
			return -WD_ENOMEM;

		if (!(ctx_id % BYTE_TO_BIT))
			i++;

		j = ctx_id % BYTE_TO_BIT;
	}

	qinfo->ctx_id[i] |= 0x1u << j;

	return ctx_id + 1;
}

void wd_free_ctx_id(struct wd_queue *q, int ctx_id)
{
	struct q_info *qinfo = q->qinfo;
	int i, j;

	if (ctx_id < 1 || ctx_id > CTX_ID_MAX_NUM * BYTE_TO_BIT) {
		WD_ERR("err: free ctx id ctx_id %d err!\n", ctx_id);
		return;
	}

	ctx_id--;
	i = ctx_id / BYTE_TO_BIT;
	j = ctx_id % BYTE_TO_BIT;
	qinfo->ctx_id[i] &= ~(0x1u << j);
}
