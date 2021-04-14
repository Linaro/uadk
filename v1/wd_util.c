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

#include "v1/wd_util.h"

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

int wd_alloc_id(__u8 *buf, __u32 size, __u32 *id, __u32 last_id, __u32 id_max)
{
	__u32 idx = last_id;
	int cnt = 0;

	while (__atomic_test_and_set(&buf[idx], __ATOMIC_ACQUIRE)) {
		idx++;
		cnt++;
		if (idx == id_max)
			idx = 0;
		if (cnt == id_max)
			return -WD_EBUSY;
	}

	*id = idx;
	return 0;
}

void wd_free_id(__u8 *buf, __u32 size, __u32 id, __u32 id_max)
{
	if (unlikely(id >= id_max)) {
		WD_ERR("id error, id = %u!\n", id);
		return;
	}

	__atomic_clear(&buf[id], __ATOMIC_RELEASE);
}

int wd_init_cookie_pool(struct wd_cookie_pool *pool,
			__u32 cookies_size, __u32 cookies_num)
{
	pool->cookies = calloc(1, cookies_size * cookies_num + cookies_num);
	if (!pool->cookies)
		return -WD_ENOMEM;

	pool->cstatus = (void *)((uintptr_t)pool->cookies +
			cookies_num * cookies_size);
	pool->cookies_num = cookies_num;
	pool->cookies_size = cookies_size;
	pool->cid = 0;

	return 0;
}

void wd_uninit_cookie_pool(struct wd_cookie_pool *pool)
{
	if (pool->cookies) {
		free(pool->cookies);
		pool->cookies = NULL;
	}
}

static void put_cookie(struct wd_cookie_pool *pool, void *cookie)
{
	__u32 idx = ((uintptr_t)cookie - (uintptr_t)pool->cookies) /
		pool->cookies_size;

	wd_free_id(pool->cstatus, pool->cookies_num, idx, pool->cookies_num);
}

static void *get_cookie(struct wd_cookie_pool *pool)
{
	__u32 last = pool->cid % pool->cookies_num;
	__u32 id = 0;
	int ret;

	ret = wd_alloc_id(pool->cstatus, pool->cookies_num, &id, last,
			pool->cookies_num);
	if (ret)
		return NULL;

	pool->cid = id;
	return (void *)((uintptr_t)pool->cookies + id * pool->cookies_size);
}

void wd_put_cookies(struct wd_cookie_pool *pool, void **cookies, __u32 num)
{
	int i;

	for (i = 0; i < num; i++)
		put_cookie(pool, cookies[i]);

}

int wd_get_cookies(struct wd_cookie_pool *pool, void **cookies, __u32 num)
{
	int i ;

	for (i = 0; i < num; i++) {
		cookies[i] = get_cookie(pool);
		if (!cookies[i])
			goto put_cookies;
	}

	return 0;

put_cookies:
	wd_put_cookies(pool, cookies, i);
	return -WD_EBUSY;
}

int wd_burst_send(struct wd_queue *q, void **req, __u32 num)
{
	return drv_send(q, req, num);
}

int wd_burst_recv(struct wd_queue *q, void **resp, __u32 num)
{
	return drv_recv(q, resp, num);
}
