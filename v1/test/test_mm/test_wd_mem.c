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

#include "test_wd_mem.h"

/* This head file is not API for user, should be deleted in the next */
#include "v1/wd_util.h"

static int with_log = 0;
static pthread_t system_test_thrds[TEST_MAX_THRD];
static struct mmt_pthread_dt test_thrds_data[TEST_MAX_THRD];

static int thrd_mem_size = 15; /* 15M defaultly */

#define MMT_PTHRD_MM_SZ		(thrd_mem_size * 0x100000)

static inline int _get_cpu_id(int thr, __u64 core_mask)
{
	__u64 i;
	int cnt = 0;


	for (i = 1; i < 64; i ++) {
		if (core_mask & (0x1ull << i)) {
			if (thr == cnt)
				return i;
			cnt++;
		}
	}

	return 0;
}

static inline int _get_one_bits(__u64 val)
{
	int count = 0;

	while (val) {
		if (val % 2 == 1)
			count++;
		val = val / 2;
	}

	return count;
}

void mmt_show_ss_slices(struct wd_queue *q)
{
	struct wd_ss_region *rgn;
	struct q_info *qinfo = q->qinfo;
	int i = 0;

	TAILQ_FOREACH(rgn, qinfo->head, next) {
		MMT_PRT("slice-%d:va=%p,pa=0x%llx,size=0x%lx\n",
		       i, rgn->va, rgn->pa, rgn->size);
		i++;
	}
}

static inline unsigned long long va_to_pa(struct wd_queue *q, void *va)
{
	return (unsigned long long)wd_iova_map(q, va, 0);
}

static inline void *pa_to_va(struct wd_queue *q, unsigned long long pa)
{
	return wd_dma_to_va(q, (void *)pa);
}

struct mmt_queue_mempool *mmt_test_mempool_create(struct wd_queue *q,
				unsigned int block_size, unsigned int block_num)
{
	void *addr;
	unsigned long rsv_mm_sz;
	struct mmt_queue_mempool *pool;
	unsigned int bitmap_sz;

	if (block_size > 4096) {
		MMT_PRT("\ncurrent blk size is bellow 4k :)");
		return NULL;
	}
	rsv_mm_sz = block_size * block_num;
	addr = wd_reserve_memory(q, rsv_mm_sz);
	if (!addr) {
		MMT_PRT("\nrequest queue fail!");
		return NULL;
	}
	bitmap_sz = (block_num / 32 + 1) * sizeof(unsigned int);
	pool = malloc(sizeof(*pool) + bitmap_sz);
	if (!pool) {
		MMT_PRT("\nAlloc pool handle fail!");
		return NULL;
	}
	memset(pool, 0, sizeof(*pool) + bitmap_sz);
	pool->base = addr;
	memset(addr, 0, rsv_mm_sz);
	sem_init(&pool->sem, 0, 1);
	pool->block_size = block_size;
	pool->block_num = block_num;
	pool->free_num = block_num;
	pool->bitmap = (unsigned int *)(pool + 1);
	pool->mem_size = rsv_mm_sz;

	return pool;
}

void mmt_test_mempool_destroy(struct mmt_queue_mempool *pool)
{
	free(pool);
}

void *mmt_test_alloc_buf(struct mmt_queue_mempool *pool)
{
	__u64 i = 0;
	__u64 j = 0;
	__u64 tmp = 0;
	__u32 *pbm = NULL;

	(void)sem_wait(&pool->sem);
	pbm = pool->bitmap;
	tmp = pool->index;
	for (; pool->index < pool->block_num; pool->index++) {
		i = (pool->index >> 5);
		j = (pool->index & (32 - 1));
		if ((pbm[i] & ((__u32)0x1 << j)) == 0) {
			pbm[i] |= ((__u32)0x1 << j);
			tmp = pool->index;
			pool->index++;
			(void)sem_post(&pool->sem);
			return (void *)((char *)pool->base + (tmp *
					pool->block_size));
		}
	}
	for (pool->index = 0; pool->index < tmp; pool->index++) {
		i = (pool->index >> 5);
		j = (pool->index & (32 - 1));
		if ((pbm[i] & ((__u32)0x1 << j)) == 0) {
			pbm[i] |= ((__u32)0x1 << j);
			tmp = pool->index;
			pool->index++;
			(void)sem_post(&pool->sem);
			return (void *)((char *)pool->base +
					(tmp * pool->block_size));

		}
	}
	(void)sem_post(&pool->sem);

	return NULL;
}

void mmt_test_free_buf(struct mmt_queue_mempool *pool, void *pbuf)
{
	__u32 *pbm = pool->bitmap;
	__u64  offset  = 0;
	__u32  bit_mask = 0;

	offset = (__u64)((unsigned long)pbuf - (unsigned long)pool->base);
	offset = offset / pool->block_size;
	if (pool->block_num <= offset) {
		MMT_PRT("offset = %lld, virtual address err!\n", offset);
		return;
	}
	bit_mask = ~(0x1u << (offset & 31));
	(void)sem_wait(&pool->sem);
	pbm[(offset >> 5)] &= bit_mask;
	(void)sem_post(&pool->sem);
}

void *mmt_sys_test_thread(void *data)
{
	struct wd_queue rsa_q, zlib_q;
	int ret, cpuid;
	struct mmt_pthread_dt *pdata = data;
	cpu_set_t mask;
	int pid = getpid(), thread_index = pdata->thread_index;
	int thread_id = (int)syscall(__NR_gettid);
	void *rsa_thrd_rmm, *zlib_thrd_rmm;

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	CPU_SET(cpuid, &mask);
	if (cpuid) {
		ret = pthread_setaffinity_np(pthread_self(),
				sizeof(mask), &mask);
		if (ret < 0) {
			MMT_PRT("\nProc-%d, thrd-%d:set affinity fail!",
				     pid, thread_id);
			return NULL;
		}
		MMT_PRT("\nProc-%d, thrd-%d bind to cpu-%d!\n",
			     pid, thread_id, cpuid);
	}
	memset((void *)&rsa_q, 0, sizeof(struct wd_queue));
	rsa_q.capa.alg = "rsa";
	ret = wd_request_queue(&rsa_q);
	if (ret) {
		MMT_PRT("\nProc-%d, thrd-%d:request rsa queue fail!",
			     pid, thread_id);
		return NULL;
	}

	ret = wd_share_reserved_memory(pdata->qinfo1.q, &rsa_q);
	if (ret) {
		wd_release_queue(&rsa_q);
		MMT_PRT("Proc-%d, thrd-%d:share mem on rsa queue fail!\n",
			pid, thread_id);
		return NULL;
	}
	rsa_thrd_rmm = pdata->qinfo1.rmm;
	memset((void *)&zlib_q, 0, sizeof(struct wd_queue));
	zlib_q.capa.alg = "zlib";
	ret = wd_request_queue(&zlib_q);
	if (ret) {
		wd_release_queue(&rsa_q);
		MMT_PRT("Proc-%d, thrd-%d:request zlib queue fail!\n",
			pid, thread_id);

		return NULL;
	}
	ret = wd_share_reserved_memory(pdata->qinfo2.q, &zlib_q);
	if (ret) {
		MMT_PRT("Proc-%d, thrd-%d:share mem on zlib queue fail!\n",
			pid, thread_id);

		goto fail_release;
	}
	zlib_thrd_rmm = pdata->qinfo2.rmm;

	MMT_PRT("Proc-%d, thrd-%d,thrd_idx-%d:rsa_rmm=%p(pa=0x%llx), zlib_rmm=%p(pa=0x%llx)!\n",
		pid, thread_id, thread_index, rsa_thrd_rmm,va_to_pa(&rsa_q, rsa_thrd_rmm),
		zlib_thrd_rmm, va_to_pa(&zlib_q, zlib_thrd_rmm));

	memset(rsa_thrd_rmm, (char)thread_index, MMT_PTHRD_MM_SZ);
	memset(zlib_thrd_rmm, (char)thread_index, MMT_PTHRD_MM_SZ);

#ifdef RESERV_RELASE_TEST
	usleep(200000);
#endif

fail_release:
	wd_release_queue(&rsa_q);
	wd_release_queue(&zlib_q);
	printf("rsa share release\n");
	return NULL;
}

static int mmt_sys_test(int thread_num, __u64 lcore_mask,
			__u64 hcore_mask, struct mmt_q_info *q1,
			struct mmt_q_info *q2)
{
	int i, ret, cnt = 0;
	int h_cpuid;

	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		_get_one_bits(hcore_mask) == 0)
		cnt = thread_num;
	for (i = 0; i < cnt; i++) {
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].thread_index = i;
		test_thrds_data[i].cpu_id = _get_cpu_id(i, lcore_mask);
		test_thrds_data[i].qinfo1.q = q1->q;
		test_thrds_data[i].qinfo1.rmm = q1->rmm + i * MMT_PTHRD_MM_SZ;
		test_thrds_data[i].qinfo1.size = MMT_PTHRD_MM_SZ;

		test_thrds_data[i].qinfo2.q = q2->q;
		test_thrds_data[i].qinfo2.rmm = q2->rmm + i * MMT_PTHRD_MM_SZ;
		test_thrds_data[i].qinfo2.size = MMT_PTHRD_MM_SZ;


		ret = pthread_create(&system_test_thrds[i], NULL,
			  mmt_sys_test_thread, &test_thrds_data[i]);
		if (ret) {
			MMT_PRT("\nCreate %dth thread fail!", i);
			return ret;
		}
	}
	for (i = 0; i < thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;
		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].thread_index = i + cnt;
		test_thrds_data[i + cnt].cpu_id =  h_cpuid;

		test_thrds_data[i + cnt].qinfo1.q = q1->q;
		test_thrds_data[i + cnt].qinfo1.rmm = q1->rmm + (i + cnt) * MMT_PTHRD_MM_SZ;
		test_thrds_data[i + cnt].qinfo1.size = MMT_PTHRD_MM_SZ;

		test_thrds_data[i + cnt].qinfo2.q = q2->q;
		test_thrds_data[i + cnt].qinfo2.rmm = q2->rmm + (i + cnt) * MMT_PTHRD_MM_SZ;
		test_thrds_data[i + cnt].qinfo2.size = MMT_PTHRD_MM_SZ;

		ret = pthread_create(&system_test_thrds[i + cnt], NULL,
			  mmt_sys_test_thread, &test_thrds_data[i + cnt]);
		if (ret) {
			MMT_PRT("\nCreate %dth thread fail!", i);
			return ret;
		}
	}

	return 0;
}

struct wd_queue rsa_q;
void *rsa_q_rmm;

void *thrd_reserve_mm(void *data)
{
	struct mmt_q_info *pdata = data;
	size_t rmm_size = pdata->size;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	int ret;

	memset((void *)&rsa_q, 0, sizeof(struct wd_queue));
	rsa_q.capa.alg = "rsa";
	ret = wd_request_queue(&rsa_q);
	if (ret) {
		MMT_PRT("\nProc-%d, thrd-%d:request rsa queue fail!",
			pid, thread_id);
		return NULL;
	}

	pdata->rmm = wd_reserve_memory(&rsa_q, rmm_size);
	if (!pdata->rmm) {
		MMT_PRT("\nreserve mem on rsa queue fail!");
		goto reserve_fail;
	}
	rsa_q_rmm = pdata->rmm;
	MMT_PRT("rsa queue RMM info:\n");
	mmt_show_ss_slices(&rsa_q);

	MMT_PRT("Proc-%d, thrd-%d:total_rsa_rmm=%p(pa=0x%llx, size=0x%lx)\n,", \
		pid, thread_id, rsa_q_rmm,\
		va_to_pa(&rsa_q, rsa_q_rmm), rmm_size);

	usleep(90000);

reserve_fail:
	wd_release_queue(&rsa_q);
	printf("rsa_reserve release\n");
	return NULL;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	struct wd_queue zlib_q;
	struct mmt_q_info rsa_qinfo, zlib_qinfo;
	void *zlib_q_rmm;
	struct mmt_q_info rsa_data;
	pthread_t rsa_id;
	size_t rmm_size;
	int thread_num, bits;
	int i = 0;
	__u64 core_mask[2];
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(0, &mask);
	ret = pthread_setaffinity_np(pthread_self(),
			sizeof(mask), &mask);
	if (ret < 0) {
		MMT_PRT("\nProc-%d, thrd-%d:set affinity fail!",
			     pid, thread_id);
		return -EINVAL;
	}

	if (!argv[1] || !argv[4]) {
		MMT_PRT("please use ./test_wd_mem -t [thread_num] -c [core_mask] [-log]!\n");
		return -EINVAL;
	}

	if (!strcmp(argv[1], "-t")) {
		thread_num = strtoul((char *)argv[2], NULL, 10);
		if (thread_num <= 0 || thread_num > TEST_MAX_THRD) {
			MMT_PRT("Invalid threads num:%d!",
					thread_num);
			MMT_PRT("Now set threads num as 2\n");
			thread_num = 2;
		}
	} else {
		MMT_PRT("./test_wd_mem --help get details\n");
		return -EINVAL;
	}
	if (strcmp(argv[3], "-c")) {
		MMT_PRT("./test_hisi_hpre --help get details\n");
		return -EINVAL;
	}

	if (argv[4][0] != '0' || argv[4][1] != 'x') {
		MMT_PRT("Err:coremask should be hex!\n");
		return -EINVAL;
	}
	if (strlen(argv[4]) > 34) {
		MMT_PRT("Warning: coremask is cut!\n");
		argv[4][34] = 0;
	}
	if (strlen(argv[4]) <= 18) {
		core_mask[0] = strtoull(argv[4], NULL, 16);
		if (core_mask[0] & 0x1) {
			MMT_PRT("Warn:cannot bind to core 0,");
			MMT_PRT("now run without binding\n");
			core_mask[0] = 0x0; /* no binding */
		}
		core_mask[1] = 0;
	} else {
		int offset = 0;
		char *temp;

		offset = strlen(argv[4]) - 16;
		core_mask[0] = strtoull(&argv[4][offset], NULL, 16);
		if (core_mask[0] & 0x1) {
			MMT_PRT("Warn:cannot bind to core 0,");
			MMT_PRT("now run without binding\n");
			core_mask[0] = 0x0; /* no binding */
		}
		temp = malloc(64);
		strcpy(temp, argv[4]);
		temp[offset] = 0;
		core_mask[1] = strtoull(temp, NULL, 16);
		free(temp);
	}
	bits = _get_one_bits(core_mask[0]);
	bits += _get_one_bits(core_mask[1]);
	if (thread_num > bits) {
		MMT_PRT("Coremask not covers all thrds,");
		MMT_PRT("Bind first %d thrds!\n", bits);
	} else if (thread_num < bits) {
		MMT_PRT("Coremask overflow,");
		MMT_PRT("Just try to bind all thrds!\n");
	}
	if (!strcmp(argv[5], "-log"))
		with_log = 1;
	else
		with_log = 0;
	if (argv[6]) {
		thrd_mem_size = strtoul((char *)argv[6], NULL, 10);
		if (thrd_mem_size <= 0 || thrd_mem_size > 1000) {
			MMT_PRT("Invalid threads mem size %dMB!\n", thrd_mem_size);
			MMT_PRT("Now set threads num as 15MB\n");
			thrd_mem_size = 15;
		}
	} else
			thrd_mem_size = 15;
	MMT_PRT("Proc-%d: starts %d threads bind to %s",
			getpid(), thread_num, argv[4]);
	MMT_PRT(" lcoremask=0x%llx, hcoremask=0x%llx\n",
		core_mask[0], core_mask[1]);
	MMT_PRT("Threads algorithm mem size %dMB!\n", thrd_mem_size);
	memset((void *)&zlib_q, 0, sizeof(struct wd_queue));


	rmm_size = (thread_num + 1) * MMT_PTHRD_MM_SZ;
	rsa_data.size = rmm_size;

	/* reserve 150MB memory for every rsa_q in each thread */
	ret = pthread_create(&rsa_id, NULL, thrd_reserve_mm, &rsa_data);
	if (ret)
	{
		printf("create thread rsa_reserv mm fail\n");
		return ret;
	}
	zlib_q.capa.alg = "zlib";
	ret = wd_request_queue(&zlib_q);
	if (ret) {
		MMT_PRT("\nrequest zlib queue fail!");
		return ret;
	}

	/* reserve 150MB memory for every zlib_q in each thread */
	rmm_size = (thread_num + 1) * MMT_PTHRD_MM_SZ;
	zlib_q_rmm = wd_reserve_memory(&zlib_q, rmm_size);
	if (!zlib_q_rmm) {
		MMT_PRT("\nreserve mem on zlib queue fail!");
		goto exit_fail;
	}
	MMT_PRT("zlib queue RMM info:\n");
	mmt_show_ss_slices(&zlib_q);


	MMT_PRT("Proc-%d, thrd-%d:total_zlib_rmm=%p(pa=0x%llx, size=0x%lx)!\n",
		pid, thread_id,
		zlib_q_rmm, va_to_pa(&zlib_q, zlib_q_rmm), rmm_size);

	zlib_qinfo.q = &zlib_q;
	zlib_qinfo.size = rmm_size - MMT_PTHRD_MM_SZ;
	zlib_qinfo.rmm = zlib_q_rmm + MMT_PTHRD_MM_SZ;
	usleep(10000);

	rsa_qinfo.q = &rsa_q;
	rsa_qinfo.size = rmm_size - MMT_PTHRD_MM_SZ;
	rsa_qinfo.rmm = rsa_q_rmm + MMT_PTHRD_MM_SZ;


	ret = mmt_sys_test(thread_num, core_mask[0], core_mask[1], &rsa_qinfo, &zlib_qinfo);
	if (ret) {
		MMT_PRT("\nstart multiple thread memory test fail!");
		goto exit_fail;
	}


	memset(zlib_q_rmm, 0, MMT_PTHRD_MM_SZ);

	ret = pthread_join(rsa_id, NULL);
	if (ret) {
		MMT_PRT("\nJoin %dth thread fail!", i);
		goto exit_fail;
	}

	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			MMT_PRT("\nJoin %dth thread fail!", i);
			goto exit_fail;
		}
	}

exit_fail:

	wd_release_queue(&zlib_q);
	return ret;
}
