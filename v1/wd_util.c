// SPDX-License-Identifier: Apache-2.0
#include <stdio.h>
#include <string.h>
#include <dirent.h>

#include "wd_util.h"

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
