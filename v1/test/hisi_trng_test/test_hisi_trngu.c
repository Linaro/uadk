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
#include "../../wd_rng.h"

#define RNG_TST_PRT		printf
#define BN_ULONG		unsigned long
#define TEST_MAX_THRD		128
#define MAX_TRY_TIMES		10000
#define LOG_INTVL_NUM		8
#define TEST_CNT		10

static int q_num = 1;
static int ctx_num_per_q = 1;

enum alg_op_type {
	TRNG_GEN,
	TRNG_AGEN,
};

struct trng_user_tag_info {
	int pid;
	int thread_id;
};

struct test_trng_pthread_dt {
	int cpu_id;
	int thread_num;
	void *q;
};

static struct test_trng_pthread_dt test_thrds_data[TEST_MAX_THRD];
static pthread_t system_test_thrds[TEST_MAX_THRD];
static unsigned int g_input;


static inline int _get_cpu_id(int thr, __u64 core_mask)
{
	__u64 i;
	int cnt = 0;

	for (i = 1; i < 64; i++) {
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

void *_trng_sys_test_thread(void *data)
{
	int ret, cpuid, i = 0;
	struct test_trng_pthread_dt *pdata = data;
	struct wcrypto_rng_ctx_setup setup;
	struct wcrypto_rng_op_data opdata;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	struct wd_queue *q;
	int *out_data;
	void *ctx = NULL;
	void *tag = NULL;

	cpu_set_t mask;
	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	q = pdata->q;
	CPU_SET(cpuid, &mask);

	if (cpuid) {
		ret = pthread_setaffinity_np(pthread_self(),
					 sizeof(mask), &mask);
		if (ret < 0) {
			RNG_TST_PRT("Proc-%d, thrd-%d:set affinity fail!\n",
				 pid, thread_id);
			return NULL;
		}
		RNG_TST_PRT("Proc-%d, thrd-%d bind to cpu-%d!\n",
				pid, thread_id, cpuid);
	}

	memset(&setup, 0, sizeof(setup));
	memset(&opdata, 0, sizeof(opdata));
	ctx = wcrypto_create_rng_ctx(q, &setup);
	if (!ctx) {
		RNG_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
			     pid, thread_id, q->capa.alg);
		ret = -EINVAL;
		goto fail_release;
	}

	out_data = malloc(g_input);
	if(!out_data) {
		RNG_TST_PRT("malloc out_data memory fail!\n");
	}
	RNG_TST_PRT("request queue fail5!\n");

	while (1) {
		opdata.in_bytes = g_input;
		opdata.out = out_data;
		ret = wcrypto_do_rng(ctx, &opdata, tag);
		if (ret < 0) {
			RNG_TST_PRT("Proc-%d, T-%d:trng %d fail!\n", pid, thread_id, i);
			goto fail_release;
		}
		RNG_TST_PRT("the read data size %d!\n", opdata.out_bytes);
		i++;
	}
fail_release:
	if (opdata.out)
		free(opdata.out);
	if (ctx)
		wcrypto_del_rng_ctx(ctx);
	return NULL;
}


static int trng_sys_test(int thread_num, __u64 lcore_mask,
					 __u64 hcore_mask)
{
	int i, ret, cnt = 0, j;
	struct wd_queue *q;
	int h_cpuid, qidx;

	q = malloc(q_num * sizeof(struct wd_queue));
	if (!q) {
		RNG_TST_PRT("malloc q memory fail!\n");
		return -ENOMEM;
	}
	memset(q, 0, q_num * sizeof(struct wd_queue));

	for (j = 0; j < q_num; j++) {
		q[j].capa.alg = "trng";
		ret = wd_request_queue(&q[j]);
		if (ret) {
			RNG_TST_PRT("request queue %d fail!\n", j);
			return ret;
		}
	}
	RNG_TST_PRT("request queue fail!\n");
	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;
	
	for (i = 0; i < cnt; i++) {
		qidx = i / ctx_num_per_q;
		test_thrds_data[i].q = &q[qidx];
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].cpu_id = _get_cpu_id(i, lcore_mask);
		ret = pthread_create(&system_test_thrds[i], NULL,
				    _trng_sys_test_thread, &test_thrds_data[i]);
		if (ret) {
			RNG_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}
	RNG_TST_PRT("request queue fail2!\n");
	for (i = 0; i < thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;

		qidx = (i + cnt) / ctx_num_per_q;
		test_thrds_data[i + cnt].q = &q[qidx];
		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].cpu_id =  h_cpuid;
		ret = pthread_create(&system_test_thrds[i + cnt], NULL,
				_trng_sys_test_thread, &test_thrds_data[i + cnt]);
		if (ret) {
			RNG_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}
	RNG_TST_PRT("request queue fail3!\n");
	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			RNG_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
	}
	free(q);
	return 0;
}


static void _trng_cb(const void *message, void *tag)
{
	const struct wcrypto_rng_msg *msg = message;
	struct trng_user_tag_info* pSwData = (struct trng_user_tag_info*)tag;
	struct wcrypto_rng_op_data opdata;
	int pid, threadId;

	if (NULL == pSwData) {
		RNG_TST_PRT("pSwData NULL!\n");
		return;
	}
	memset(&opdata, 0, sizeof(opdata));

	opdata.out = (void *)msg->out;
	opdata.out_bytes = msg->out_bytes;
	pid = pSwData->pid;
	threadId = pSwData->thread_id;
	RNG_TST_PRT("Proc-%d, %d-TD trng\n", pid, threadId);
	RNG_TST_PRT("the random number size :%d\n", opdata.out_bytes);

	if (opdata.out)
		free(opdata.out);

	if (pSwData)
		free(pSwData);
}

static void *_trng_asys_test_thread(void *data)
{
	int ret, cpuid;
	struct test_trng_pthread_dt *pdata = data;
	struct wd_queue *q = NULL;
	cpu_set_t mask;
	struct wcrypto_rng_ctx_setup setup;
	struct wcrypto_rng_ctx *ctx = NULL;
	struct trng_user_tag_info *tag = NULL;
	struct wcrypto_rng_op_data opdata;
	int pid = getpid();
	int thread_id = (int)syscall(__NR_gettid);
	int *out_data;
	int i = 0;

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	q = (struct wd_queue *)pdata->q;
	CPU_SET(cpuid, &mask);
	
	if (!q) {
		RNG_TST_PRT("q null!\n");
		return NULL;
	}
	if (cpuid) {
		ret = pthread_setaffinity_np(pthread_self(),
									 sizeof(mask), &mask);
		if (ret < 0) {
			RNG_TST_PRT("Proc-%d, thrd-%d:set affinity fail!\n",
						 pid, thread_id);
			return NULL;
		}
		RNG_TST_PRT("Proc-%d, thrd-%d bind to cpu-%d!\n",
					 pid, thread_id, cpuid);
	}

	q->capa.alg = "trng";
	memset(&setup, 0, sizeof(setup));
	memset(&opdata, 0, sizeof(opdata));
	setup.cb = _trng_cb;
	ctx = wcrypto_create_rng_ctx(q, &setup);
	if (!ctx) {
		RNG_TST_PRT("Proc-%d, %d-TD:create %s ctx fail!\n",
					 pid, thread_id, q->capa.alg);
		goto fail_release;
	}

	while(1) {
		tag = malloc(sizeof(struct trng_user_tag_info));
		if (!tag) {
				RNG_TST_PRT("malloc tag fail!\n");
				goto fail_release;
		}

		tag->pid = pid;
		tag->thread_id = thread_id;
		
		out_data = malloc(g_input);
		if(!out_data) {
			RNG_TST_PRT("malloc fail\n");
			return 0;
		}

		opdata.in_bytes = g_input;
		opdata.out = out_data;
	try_again:
		ret = wcrypto_do_rng(ctx, &opdata, tag);
		if (ret == -WD_EBUSY) {
			usleep(100);
			goto try_again;
		} else if(ret) {
			RNG_TST_PRT("Proc-%d, T-%d:trng %d fail!\n", pid, thread_id, i);
			goto fail_release;
		}
		i++;
	}
fail_release:
	wcrypto_del_rng_ctx(ctx);
	return NULL;
}

static void* _trng_async_poll_test_thread(void *data)
{
	struct test_trng_pthread_dt *pdata = data;
	struct wd_queue *q = pdata->q;
	int ret, cpuid;
	int pid = getpid();
	cpu_set_t mask;
	int thread_id = (int)syscall(__NR_gettid);

	CPU_ZERO(&mask);
	cpuid = pdata->cpu_id;
	CPU_SET(cpuid, &mask);
	if (cpuid) {
		ret = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
		if (ret < 0) {
			RNG_TST_PRT("Proc-%d, thrd-%d:set affinity fail!\n",
						 pid, thread_id);
			return NULL;
		}
		RNG_TST_PRT("Proc-%d, poll thrd-%d bind to cpu-%d!\n",
					 pid, thread_id, cpuid);
	}

	while (1) {
		ret = wcrypto_rng_poll(q, 1);
		if (ret < 0) {
			break;
		}
	}

	return NULL;
}

static int trng_asys_test(int thread_num, __u64 lcore_mask, __u64 hcore_mask)
{
	int i, ret, cnt = 0;
	struct wd_queue q;
	int h_cpuid;

	memset(&q, 0, sizeof(q));

	q.capa.alg = "trng";
	ret = wd_request_queue(&q);
	if (ret) {
		RNG_TST_PRT("request queue fail!\n");
		return ret;
	}

	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;

	test_thrds_data[0].q= &q;
	test_thrds_data[0].thread_num = 1;
	test_thrds_data[0].cpu_id = _get_cpu_id(0, lcore_mask);
	ret = pthread_create(&system_test_thrds[0], NULL,
			     _trng_async_poll_test_thread, &test_thrds_data[0]);
	if (ret) {
		RNG_TST_PRT("Create poll thread fail!\n");
		return ret;
	}

	for (i = 1; i <= cnt; i++) {
		test_thrds_data[i].q = &q;
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].cpu_id = _get_cpu_id(i, lcore_mask);
		ret = pthread_create(&system_test_thrds[i], NULL,
				    _trng_asys_test_thread, &test_thrds_data[i]);
		if (ret) {
			RNG_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 1; i <= thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;
		test_thrds_data[i + cnt].q = &q;
		test_thrds_data[i + cnt].thread_num = thread_num;
		test_thrds_data[i + cnt].cpu_id = h_cpuid;
		ret = pthread_create(&system_test_thrds[i + cnt], NULL,
				 _trng_asys_test_thread, &test_thrds_data[i + cnt]);
		if (ret) {
			RNG_TST_PRT("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			RNG_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
	}
	
	wd_release_queue(&q);
	return 0;

}
int main(int argc, char *argv[])
{
	struct wcrypto_rng_ctx *ctx;
	struct wcrypto_rng_op_data opdata;
	struct wcrypto_rng_ctx_setup setup;
	enum alg_op_type alg_op_type = TRNG_GEN;
	int thread_num, bits;
	__u64 core_mask[2];
	struct wd_queue q;
	void *tag = NULL;
	int *data;
	int ret;
	int fd = -1;
	int fd_w = -1;
	if (!argv[1]) {
		RNG_TST_PRT("pls printf the size of the random data!\n");
		return -WD_EINVAL;
	}
	g_input = (unsigned int)strtoul(argv[1], NULL, 10);
	printf("g_input:%d\n",g_input);
	//if (g_input <= 0){
	//	printf("input error!\n");
 	//	return -WD_EINVAL;
	//}
	if (argv[2]) {
		if(!strcmp(argv[2], "-system-gen")) {
			alg_op_type = TRNG_GEN;
			RNG_TST_PRT("Now doing system random number gen test!\n");
		} else if(!strcmp(argv[2], "-system-agen")) {
			alg_op_type = TRNG_AGEN;
			RNG_TST_PRT("Now doing system random number agen test!\n");
		}
		
		thread_num = strtoul((char *)argv[3], NULL, 10);
		if (thread_num <= 0 || thread_num > TEST_MAX_THRD) {
			RNG_TST_PRT("Invalid threads num:%d!\n",
							 thread_num);
			RNG_TST_PRT("Now set threads num as 2\n");
			thread_num = 2;
		}
		 
		if (strcmp(argv[4], "-c")) {
			RNG_TST_PRT("./test_hisi_trng --help get details\n");
			return -EINVAL;
		}
		if (argv[5][0] != '0' || argv[5][1] != 'x') {
			RNG_TST_PRT("Err:coremask should be hex!\n");
			return -EINVAL;
		}
		
		if (strlen(argv[5]) > 34) {
			RNG_TST_PRT("Warning: coremask is cut!\n");
			argv[5][34] = 0;
		}
		
		if (strlen(argv[5]) <= 18) {
			core_mask[0] = strtoull(argv[5], NULL, 16);
			if (core_mask[0] & 0x1) {
				RNG_TST_PRT("Warn:cannot bind to core 0,\n");
				RNG_TST_PRT("now run without binding\n");
				core_mask[0] = 0x0; /* no binding */
			}
			core_mask[1] = 0;
		} else {
			int offset = 0;
			char *temp;

			offset = strlen(argv[5]) - 16;
			core_mask[0] = strtoull(&argv[5][offset], NULL, 16);
			if (core_mask[0] & 0x1) {
				RNG_TST_PRT("Warn:cannot bind to core 0,\n");
				RNG_TST_PRT("now run without binding\n");
				core_mask[0] = 0x0; /* no binding */
			}
			temp = malloc(64);
			strcpy(temp, argv[5]);
			temp[offset] = 0;
			core_mask[1] = strtoull(temp, NULL, 16);
			free(temp);
		}

		bits = _get_one_bits(core_mask[0]);
		bits += _get_one_bits(core_mask[1]);
		if (thread_num > bits) {
			RNG_TST_PRT("Coremask not covers all thrds,\n");
			RNG_TST_PRT("Bind first %d thrds!\n", bits);
		} else if (thread_num < bits) {
			RNG_TST_PRT("Coremask overflow,\n");
			RNG_TST_PRT("Just try to bind all thrds!\n");
		}

		if (argv[6]) {
			ctx_num_per_q = strtoul(argv[6], NULL, 10);
			if (ctx_num_per_q <= 0) {
				RNG_TST_PRT("Invalid ctx num per queue:%s!\n",
					     argv[6]);
				RNG_TST_PRT("Now ctx num per queue is set as 1!\n");
				ctx_num_per_q = 1;
			}
		} else {
			RNG_TST_PRT("Now  ctx num per queue is set as 1!\n");
			ctx_num_per_q = 1;
		}

		q_num = (thread_num - 1) / ctx_num_per_q + 1;

		RNG_TST_PRT("Proc-%d: starts %d threads bind to %s\n",
					 getpid(), thread_num, argv[5]);
		RNG_TST_PRT(" lcoremask=0x%llx, hcoremask=0x%llx\n",
					 core_mask[0], core_mask[1]);
		if(alg_op_type == TRNG_GEN)
			return trng_sys_test(thread_num, core_mask[0],
					     core_mask[1]);
		
		return trng_asys_test(thread_num, core_mask[0],
					     core_mask[1]);
	}

	RNG_TST_PRT("Now try to get %d bytes random number.\n", g_input);

	data = malloc(g_input);
	if (!data) {
		RNG_TST_PRT("malloc data failed.\n");
		return -1;
	}
	
	memset((void *)&q, 0, sizeof(q));
	memset(&setup, 0, sizeof(setup));
	memset(&opdata, 0, sizeof(opdata));
	
	q.capa.alg = "trng";
	ret = wd_request_queue(&q);
	if (ret) {
		RNG_TST_PRT("request queue fail!\n");
		return ret;
	}
	ctx = wcrypto_create_rng_ctx(&q, &setup);
	if (!ctx) {
		ret = -ENOMEM;
		RNG_TST_PRT("create trng ctx fail!\n");
		goto release_q;
	}

	opdata.in_bytes = g_input;
	opdata.out = data;
	ret = wcrypto_do_rng(ctx, &opdata, tag);
	if (ret != 1) {
		RNG_TST_PRT("a wd_do_trng fail!\n");
		goto del_ctx;
	}

	RNG_TST_PRT("random_data size= %d.\n", opdata.out_bytes);
	fd_w = open ("/root/trng_file", O_RDWR|O_CREAT|O_TRUNC,0777);
	if (fd_w <0 ) {
		printf("can not open trng_file\n");
 		return fd_w;
	}
	/*fd = open ("/dev/random", O_RDONLY);
	if (fd <0 ) {
		printf("can not open\n");
 		return fd;
	}*/
	/*ret = read(fd, data, g_input);
	if (ret < 0) {
        	printf("read error %d\n", ret);
        	return ret;
    }*/
	ret = write(fd_w,opdata.out,opdata.out_bytes);
	if (ret < 0) {
		printf("write error %d\n", ret);
		return ret;
	}
	close(fd);
	close(fd_w);
del_ctx:
	wcrypto_del_rng_ctx(ctx);

release_q:
	wd_release_queue(&q);
	free(data);
	return ret;
}
