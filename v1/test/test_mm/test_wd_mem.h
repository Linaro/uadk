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

#ifndef __TEST_WD_MEM_H
#define __TEST_WD_MEM_H

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#define __USE_GNU
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <semaphore.h>

#include "../../wd.h"

#define MMT_PRT			printf
#define TEST_MAX_THRD		128
#define MAX_TRY_TIMES		10000
#define LOG_INTVL_NUM		8

struct mmt_queue_mempool *mmt_test_mempool_create(struct wd_queue *q,
	unsigned int block_size, unsigned int block_num);
void mmt_test_mempool_destroy(struct mmt_queue_mempool *pool);
void *mmt_test_alloc_buf(struct mmt_queue_mempool *pool);
void mmt_test_free_buf(struct mmt_queue_mempool *pool, void *buf);

typedef unsigned long long (*v2p)(void *v);
typedef void * (*p2v)(unsigned long long p);

struct mmt_queue_mempool {
	struct wd_queue *q;
	void *base;
	unsigned int *bitmap;
	unsigned int block_size;
	unsigned int block_num;
	unsigned int mem_size;
	unsigned int block_align_size;
	unsigned int free_num;
	unsigned int fail_times;
	unsigned long long index;
	sem_t	sem;
	int dev;
	v2p virt_to_phy;
	p2v phy_to_virt;
};

struct mmt_q_info {
	struct wd_queue *q;
	void *rmm;
	size_t size;
};

struct mmt_pthread_dt {
	int cpu_id;
	int thread_num;
	int thread_index;
	struct mmt_q_info qinfo1;
	struct mmt_q_info qinfo2;
};
#endif
