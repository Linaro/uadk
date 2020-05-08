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
#define DEBUG_LOG

#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#define __USE_GNU
#include <pthread.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../../drv/hisi_qm_udrv.h"
#include "zlib.h"
#include "../smm.h"
#include "zip_alg.h"
#include "../../wd_comp.h"
#include "../../wd.h"
#include "../../wd_util.h"

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

static void get_core_mask(char *coremask, __u64* core_mask)
{
 if (strlen(coremask) <= 18) {
        core_mask[0] = strtoull(coremask, NULL, 16);
        if (core_mask[0] & 0x1) {
            core_mask[0] = 0x0; /* no binding */
        }
        core_mask[1] = 0;
    } else {
        int offset = 0;
        char *temp;
        offset = strlen(coremask) - 16;
        core_mask[0] = strtoull(&coremask[offset], NULL, 16);
        if (core_mask[0] & 0x1) {
            core_mask[0] = 0x0; /* no binding */
        }
        temp = malloc(64);
        strcpy(temp, coremask);
        temp[offset] = 0;
        core_mask[1] = strtoull(temp, NULL, 16);
        free(temp);
    }


}

enum mode {
	BLOCK,
	STREAM,
	ASYNC,
};

struct test_zip_pthread_dt {
	int cpu_id;
	int op_type;
	int hw_flag;
	int blksize;
	int alg_type;
	int iteration;
	int thread_num;
	void *src;
	void *dst;
	ulong src_len;
	ulong dst_len;
	float com_time;
	float decom_time;
	struct wcrypto_comp_ctx *ctx;
	struct wcrypto_comp_op_data *opdata;
	struct wcrypto_comp_ctx_setup *ctx_setup;
};

struct user_comp_tag_info {
	pid_t tid;
	int cpu_id;
	int alg_type;
};

#define TEST_MAX_THRD		2048
#define MAX_CORES		128
#define Q_MAX_CTX		1
#define MIN(a, b)		((a) < (b) ? (a) : (b))
#define CTX_NUM(a, b)		(((a / Q_MAX_CTX) >= (b + 1))		\
				? Q_MAX_CTX : (a % Q_MAX_CTX))

static struct test_zip_pthread_dt test_thrds_data[TEST_MAX_THRD];
static struct wd_queue q[TEST_MAX_THRD / Q_MAX_CTX];
static pthread_t system_test_thrds[TEST_MAX_THRD];

/* bytes of data for a request */
static int block_size = 512000;
static int q_num = 1;

pid_t gettid(void)
{
	return syscall(__NR_gettid);
}

void zip_callback(const void    *msg, void *tag)
{
	const struct wcrypto_comp_msg *respmsg = msg;
	const struct user_comp_tag_info *utag = tag;
	int i = utag->cpu_id;

	test_thrds_data[i].dst_len = respmsg->produced;
	memcpy(test_thrds_data[i].dst,
	       test_thrds_data[i].opdata->out,
	       test_thrds_data[i].dst_len);
	//dbg("%s %dth thrds produced %d!\n",  __func__, i, respmsg->produced);
}

void  *zip_sys_async_poll_thread(void *args)
{
	int *cnt = calloc(1, sizeof(int) * q_num);
	struct test_zip_pthread_dt *pdata = args;
	int thread_num = pdata->thread_num;
	int iter = pdata->iteration;
	int workq_num = q_num;
	int ret, i;

	pid_t tid = gettid();
	//dbg("%s poll thread_id=%d\n", __func__, (int)tid);

	for (i = 0; i < q_num; i++)
		cnt[i] = iter * CTX_NUM(thread_num, i);

	do {
		i = 0;
		for ( ; i < q_num; i++) {
			if (!cnt[i])
				continue;
			ret = wcrypto_comp_poll(&q[i], cnt[i]);
			if (ret < 0) {
				WD_ERR("poll fail! thread_id=%d, ret:%d\n",
						pdata->cpu_id, ret);
				break;
			}
			cnt[i] -= ret;
			if (!cnt[i])
				workq_num--;
		}
	} while (workq_num);

	return NULL;
}

void  *zip_sys_async_comp_thread(void *args)
{
	struct test_zip_pthread_dt *pdata = args;
	struct user_comp_tag_info *utag;
	int i = pdata->iteration;
	pid_t tid = gettid();
	int ret;
	int cpu_id = pdata->cpu_id;
	cpu_set_t mask;
	CPU_ZERO(&mask);
	if (cpu_id) {
		if (cpu_id <= 0 || cpu_id > MAX_CORES) {
			dbg("set cpu no affinity!\n");
			goto therad_no_affinity;
		}
		CPU_SET(cpu_id, &mask);
		if (pthread_setaffinity_np(pthread_self(),
		    sizeof(mask), &mask) < 0) {
			perror("pthread_setaffinity fail!\n");
			return NULL;
		}
	}

therad_no_affinity:
	utag = calloc(1, sizeof(struct user_comp_tag_info));
	utag->alg_type = pdata->alg_type;
	utag->cpu_id = pdata->cpu_id;
	utag->tid = tid;

	//dbg("%s entry thread_id=%d\n", __func__, (int)tid);
	do {
		ret = wcrypto_do_comp(pdata->ctx, pdata->opdata, utag);
		if (ret == -WD_EBUSY) {
			//WD_ERR("%s(): asynctest no cache!\n", __func__);
			i++;
		}
	} while (--i);
	//dbg("thread_id=%d do_comp is ok\n",  (int)tid);

	return NULL;
}

int zip_sys_async_init(int      thread_num,
				int alg_type, int op_type)
{
	size_t ss_region_size = 4096 + DMEMSIZE * 2 + HW_CTX_SIZE;
	struct test_zip_pthread_dt *pdata;
	struct wcrypto_paras *priv;
	void **ss_buf;
	int i, j, ret;

	q_num = (thread_num % Q_MAX_CTX > 0) ?
		(thread_num / Q_MAX_CTX + 1) :
		(thread_num / Q_MAX_CTX);

	ss_buf = calloc(1, sizeof(void *) * q_num);
	for (i = 0; i < q_num; i++) {
		switch (alg_type) {
		case 0:
			q[i].capa.alg = "zlib";
			break;
		case 1:
			q[i].capa.alg = "gzip";
			break;
		default:
			q[i].capa.alg = "zlib";
			break;
		}
		q[i].capa.latency = 0;
		q[i].capa.throughput = 0;
		priv = &q[i].capa.priv;
		priv->direction = op_type;
		ret = wd_request_queue(&q[i]);
		if (ret) {
			WD_ERR("request %dth q fail, ret =%d\n", i, ret);
			goto err_q_release;

		}
#ifdef CONFIG_IOMMU_SVA
		ss_buf[i] = calloc(1, ss_region_size * Q_MAX_CTX);
#else
		ss_buf[i] = wd_reserve_memory(&q[i],
			ss_region_size * Q_MAX_CTX);
#endif
		if (!ss_buf[i]) {
			WD_ERR("reserve %dth buf fail, ret =%d\n", i, ret);
			ret = -ENOMEM;
			goto err_q_release;
		}
		smm_init(ss_buf[i], ss_region_size * Q_MAX_CTX, 0xF);
		if (ret)
			goto err_q_release;
	}

	for (i = 0; i < thread_num; i++) {
		pdata = &test_thrds_data[i];
		pdata->ctx_setup = calloc(1,
			sizeof(struct wcrypto_comp_ctx_setup));
		if (!pdata->ctx_setup) {
			ret = -ENOMEM;
			WD_ERR("alloc %dth ctx_setup fail, ret = %d\n", i, ret);
			goto err_ctx_setup_free;
		}
		pdata->ctx_setup->stream_mode = WCRYPTO_COMP_STATELESS;
		pdata->ctx_setup->cb = zip_callback;
		pdata->ctx = wcrypto_create_comp_ctx(
			&q[i / Q_MAX_CTX], pdata->ctx_setup);
		if (!pdata->ctx)
			goto err_ctx_del;

		pdata->opdata = calloc(1, sizeof(struct wcrypto_comp_op_data));
		if (!pdata->opdata) {
			ret = -ENOMEM;
			WD_ERR("alloc %dth opdata fail, ret = %d\n", i, ret);
			goto err_opdata_free;
		}
		pdata->opdata->stream_pos = WCRYPTO_COMP_STREAM_NEW;
		pdata->opdata->avail_out = DMEMSIZE;
		pdata->opdata->in = smm_alloc(ss_buf[i / Q_MAX_CTX], DMEMSIZE);
		pdata->opdata->out = smm_alloc(ss_buf[i / Q_MAX_CTX], DMEMSIZE);
		if (pdata->opdata->in == NULL || pdata->opdata->out == NULL) {
			ret = -ENOMEM;
			WD_ERR("not enough data ss_region memory for cache (bs=%d)\n",
					DMEMSIZE);
			goto err_opdata_free;
		}
		pdata->opdata->in_len = pdata->src_len;
		memcpy(pdata->opdata->in, pdata->src, pdata->src_len);
	}

	return 0;

err_opdata_free:
	wcrypto_del_comp_ctx(test_thrds_data[i].ctx);
err_ctx_del:
	free(test_thrds_data[i].ctx_setup);
err_ctx_setup_free:
	for (j = 0; j < i; j++) {
		wcrypto_del_comp_ctx(test_thrds_data[j].ctx);
		free(test_thrds_data[j].ctx_setup);
		free(test_thrds_data[j].opdata);
	}
	i = q_num;
err_q_release:
	for (j = 0; j < i; j++)
		wd_release_queue(&q[j]);

	return ret;
}

void  *zip_sys_stream_thread(void *args)
{
	struct test_zip_pthread_dt *pdata = args;
	int i = pdata->iteration;
	pid_t tid = gettid();
	int ret;
	int cpu_id = pdata->cpu_id;
	cpu_set_t mask;
	CPU_ZERO(&mask);
	if (cpu_id) {
		if (cpu_id <= 0 || cpu_id > MAX_CORES) {
			dbg("set cpu no affinity!\n");
			goto therad_no_affinity;
		}
		CPU_SET(cpu_id, &mask);
		if (pthread_setaffinity_np(pthread_self(),
		    sizeof(mask), &mask) < 0) {
			perror("pthread_setaffinity fail!\n");
			return NULL;
		}
	}

	struct timeval start_tval, end_tval;

therad_no_affinity:
	gettimeofday(&start_tval, NULL);
	//dbg("%s entry thread_id=%d\n", __func__, (int)tid);
	do {
		ret = wcrypto_do_comp(pdata->ctx, pdata->opdata, NULL);
		if (ret == -WD_EBUSY)
			i++;

		pdata->dst_len = pdata->opdata->produced;
	} while (--i);
	//dbg("thread_id=%d do_comp is ok\n",  (int)tid);
	gettimeofday(&end_tval, NULL);

	float tc = (float)((end_tval.tv_sec-start_tval.tv_sec) * 1000000 +
		     end_tval.tv_usec - start_tval.tv_usec);
	//dbg("%s end, time = %f\n", __func__, tc);

	return NULL;
}

void  *zip_sys_block_thread(void *args)
{
	struct test_zip_pthread_dt *pdata = args;
	int i = pdata->iteration;
	pid_t tid = gettid();
	int ret;
	int cpu_id = pdata->cpu_id;
	cpu_set_t mask;
	CPU_ZERO(&mask);
	if (cpu_id) {
		if (cpu_id <= 0 || cpu_id > MAX_CORES) {
			dbg("set cpu no affinity!\n");
			goto therad_no_affinity;
		}
		CPU_SET(cpu_id, &mask);
		if (pthread_setaffinity_np(pthread_self(),
		    sizeof(mask), &mask) < 0) {
			perror("pthread_setaffinity fail!\n");
			return NULL;
		}
	}


	struct timeval start_tval, end_tval;
therad_no_affinity:

	gettimeofday(&start_tval, NULL);
	//dbg("%s entry thread_id=%d\n", __func__, (int)tid);
	do {
		ret = wcrypto_do_comp(pdata->ctx, pdata->opdata, NULL);
		if (ret == -WD_EBUSY)
			i++;

		pdata->dst_len = pdata->opdata->produced;
	} while (--i);
	//dbg("thread_id=%d do_comp is ok\n",  (int)tid);
	gettimeofday(&end_tval, NULL);

	float tc = (float)((end_tval.tv_sec-start_tval.tv_sec) * 1000000 +
		     end_tval.tv_usec - start_tval.tv_usec);
	//dbg("%s end, time = %f\n", __func__, tc);

	return NULL;
}

int zip_sys_stream_init(int      thread_num,
				int alg_type, int op_type)
{
	struct test_zip_pthread_dt *pdata;
	struct wcrypto_paras *priv;
	size_t ss_region_size = 4096 + DMEMSIZE * 2 + HW_CTX_SIZE;
	void **ss_buf;
	int i, j, ret;

	q_num = (thread_num % Q_MAX_CTX > 0) ?
		(thread_num / Q_MAX_CTX + 1) : (thread_num / Q_MAX_CTX);

	ss_buf = calloc(1, sizeof(void *) * q_num);
	for (i = 0; i < q_num; i++) {
		switch (alg_type) {
		case 0:
			q[i].capa.alg = "zlib";
			break;
		case 1:
			q[i].capa.alg = "gzip";
			break;
		default:
			q[i].capa.alg = "zlib";
			break;
		}
		q[i].capa.latency = 0;
		q[i].capa.throughput = 0;
		priv = &q[i].capa.priv;
		priv->direction = op_type;
		ret = wd_request_queue(&q[i]);
		if (ret) {
			WD_ERR("request %dth q fail, ret =%d\n", i, ret);
			goto err_q_release;

		}
#ifdef CONFIG_IOMMU_SVA
		ss_buf[i] = calloc(1, ss_region_size * Q_MAX_CTX);
#else
		ss_buf[i] = wd_reserve_memory(&q[i],
			ss_region_size * Q_MAX_CTX);
#endif
		if (!ss_buf[i]) {
			WD_ERR("reserve %dth buf fail, ret =%d\n", i, ret);
			ret = -ENOMEM;
			goto err_q_release;
		}
		smm_init(ss_buf[i], ss_region_size * Q_MAX_CTX, 0xF);
		if (ret)
			goto err_q_release;
	}

	for (i = 0; i < thread_num; i++) {
		pdata = &test_thrds_data[i];
		pdata->ctx_setup = calloc(1,
			sizeof(struct wcrypto_comp_ctx_setup));
		if (!pdata->ctx_setup) {
			ret = -ENOMEM;
			WD_ERR("alloc %dth ctx_setup fail, ret = %d\n", i, ret);
			goto err_ctx_setup_free;
		}
		pdata->ctx_setup->stream_mode = WCRYPTO_COMP_STATEFUL;
		pdata->ctx_setup->br.alloc = smm_alloc;
		pdata->ctx_setup->br.free = smm_free;
		pdata->ctx_setup->br.usr = ss_buf[i];
		pdata->ctx = wcrypto_create_comp_ctx(&q[i / Q_MAX_CTX],
						     pdata->ctx_setup);
		if (!pdata->ctx)
			goto err_ctx_del;

		pdata->opdata = calloc(1, sizeof(struct wcrypto_comp_op_data));
		if (!pdata->opdata) {
			ret = -ENOMEM;
			WD_ERR("alloc %dth opdata fail, ret = %d\n", i, ret);
			goto err_opdata_free;
		}
		pdata->opdata->stream_pos = WCRYPTO_COMP_STREAM_NEW;
		pdata->opdata->avail_out = DMEMSIZE;
		pdata->opdata->in = smm_alloc(ss_buf[i / Q_MAX_CTX], DMEMSIZE);
		pdata->opdata->out = smm_alloc(ss_buf[i / Q_MAX_CTX], DMEMSIZE);
		if (pdata->opdata->in == NULL ||
			pdata->opdata->out == NULL) {
			ret = -ENOMEM;
			WD_ERR("not enough data ss_region memory for cache (bs=%d)\n",
					DMEMSIZE);
			goto err_opdata_free;
		}
		pdata->opdata->in_len = pdata->src_len;			
		memcpy(pdata->opdata->in, pdata->src, pdata->src_len);
	}

	return 0;

err_opdata_free:
	wcrypto_del_comp_ctx(test_thrds_data[i].ctx);
err_ctx_del:
	free(test_thrds_data[i].ctx_setup);
err_ctx_setup_free:
	for (j = 0; j < i; j++) {
		wcrypto_del_comp_ctx(test_thrds_data[j].ctx);
		free(test_thrds_data[j].ctx_setup);
		free(test_thrds_data[j].opdata);
	}
	i = q_num;
err_q_release:
	for (j = 0; j < i; j++)
		wd_release_queue(&q[j]);

	return ret;
}

int zip_sys_block_init(int      thread_num,
				int alg_type, int op_type)
{
struct test_zip_pthread_dt *pdata;
	struct wcrypto_paras *priv;
	size_t ss_region_size = 4096 + DMEMSIZE * 2 + HW_CTX_SIZE;
	void **ss_buf;
	int i, j, ret;

	q_num = (thread_num % Q_MAX_CTX > 0) ?
		(thread_num / Q_MAX_CTX + 1) : (thread_num / Q_MAX_CTX);

	//dbg("%s init start\n", __func__);

	ss_buf = calloc(1, sizeof(void *) * q_num);
	for (i = 0; i < q_num; i++) {
		switch (alg_type) {
		case 0:
			q[i].capa.alg = "zlib";
			break;
		case 1:
			q[i].capa.alg = "gzip";
			break;
		default:
			q[i].capa.alg = "zlib";
			break;
		}
		q[i].capa.latency = 0;
		q[i].capa.throughput = 0;
		priv = &q[i].capa.priv;
		priv->direction = op_type;
		ret = wd_request_queue(&q[i]);
		if (ret) {
			WD_ERR("request %dth q fail, ret =%d\n", i, ret);
			goto err_q_release;

		}
#ifdef CONFIG_IOMMU_SVA
		ss_buf[i] = calloc(1, ss_region_size * Q_MAX_CTX);
#else
		ss_buf[i] = wd_reserve_memory(&q[i],
			ss_region_size * Q_MAX_CTX);
#endif
		if (!ss_buf[i]) {
			WD_ERR("reserve %dth buf fail, ret =%d\n", i, ret);
			ret = -ENOMEM;
			goto err_q_release;
		}
		smm_init(ss_buf[i], ss_region_size * Q_MAX_CTX, 0xF);
		if (ret)
			goto err_q_release;
	}

	for (i = 0; i < thread_num; i++) {
		pdata = &test_thrds_data[i];
		pdata->ctx_setup = calloc(1,
			sizeof(struct wcrypto_comp_ctx_setup));
		if (!pdata->ctx_setup) {
			ret = -ENOMEM;
			WD_ERR("alloc %dth ctx_setup fail, ret = %d\n", i, ret);
			goto err_ctx_setup_free;
		}
		pdata->ctx_setup->stream_mode = WCRYPTO_COMP_STATELESS;
		pdata->ctx_setup->br.alloc = smm_alloc;
		pdata->ctx_setup->br.free = smm_free;
		pdata->ctx_setup->br.usr = ss_buf[i];
		pdata->ctx = wcrypto_create_comp_ctx(
			&q[i / Q_MAX_CTX], pdata->ctx_setup);
		if (!pdata->ctx)
			goto err_ctx_del;

		pdata->opdata = calloc(1, sizeof(struct wcrypto_comp_op_data));
		if (!pdata->opdata) {
			ret = -ENOMEM;
			WD_ERR("alloc %dth opdata fail, ret = %d\n", i, ret);
			goto err_opdata_free;
		}
		pdata->opdata->stream_pos = WCRYPTO_COMP_STREAM_NEW;
		pdata->opdata->avail_out = DMEMSIZE;
		pdata->opdata->in =
			smm_alloc(ss_buf[i / Q_MAX_CTX], DMEMSIZE);
		pdata->opdata->out =
			smm_alloc(ss_buf[i / Q_MAX_CTX], DMEMSIZE);
		if (pdata->opdata->in == NULL ||
			pdata->opdata->out == NULL) {
			ret = -ENOMEM;
			WD_ERR("not enough data ss_region memory for cache (bs=%d)\n",
					DMEMSIZE);
			goto err_opdata_free;
		}
		pdata->opdata->in_len = pdata->src_len;
		memcpy(pdata->opdata->in, pdata->src, pdata->src_len);
	}
	//dbg("%s init end\n", __func__);

	return 0;

err_opdata_free:
	wcrypto_del_comp_ctx(test_thrds_data[i].ctx);
err_ctx_del:
	free(test_thrds_data[i].ctx_setup);
err_ctx_setup_free:
	for (j = 0; j < i; j++) {
		wcrypto_del_comp_ctx(test_thrds_data[j].ctx);
		free(test_thrds_data[j].ctx_setup);
		free(test_thrds_data[j].opdata);
	}
	i = q_num;
err_q_release:
	for (j = 0; j < i; j++)
		wd_release_queue(&q[j]);

	return ret;
}

void zip_sys_test_uninit(int thread_num)
{
	int i;

	for (i = 0; i < thread_num; i++) {
		wcrypto_del_comp_ctx(test_thrds_data[i].ctx);
		free(test_thrds_data[i].ctx_setup);
		free(test_thrds_data[i].opdata);
	}

	for (i = 0; i < q_num; i++)
		wd_release_queue(&q[i]);
}

static int hizip_thread_test(FILE *source, FILE *dest,
			     int thread_num, int alg_type, int op_type,
			     int mode, int hw_flag, int iteration, __u64 lcore_mask,
			 __u64 hcore_mask)
{
	int in_len, sz, fd, count, i, j, ret;
	struct timeval start_tval, end_tval, poll_tval;
	float total_out = 0;
	float total_in = 0;
	float tc, speed;
	void *file_buf;
	struct stat s;

	fd = fileno(source);
	SYS_ERR_COND(fstat(fd, &s) < 0, "fstat");
	in_len = s.st_size;
	SYS_ERR_COND(!in_len, "input file length zero");

	file_buf = calloc(1, in_len);

	sz = fread(file_buf, 1, in_len, source);
	if (sz != in_len)
		WD_ERR("read file sz != in_len!\n");
	count = in_len/block_size;

	if (!count)
		count = 1;

	//dbg("%s entry blocksize=%d, count=%d, threadnum= %d, in_len=%d\n",
	//   __func__, block_size, count, thread_num, in_len);
	int cnt;
	if (_get_one_bits(lcore_mask) > 0)
		cnt =  _get_one_bits(lcore_mask);
	else if (_get_one_bits(lcore_mask) == 0 &&
		 _get_one_bits(hcore_mask) == 0)
		cnt = thread_num;

	for (i = 0; i < thread_num; i++) {
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].iteration = iteration;
		test_thrds_data[i].blksize = block_size;
		test_thrds_data[i].alg_type = alg_type;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].hw_flag = hw_flag;
		//test_thrds_data[i].cpu_id = i;
		test_thrds_data[i].cpu_id = _get_cpu_id(i, lcore_mask);
		test_thrds_data[i].src_len = MIN(in_len, block_size);
		test_thrds_data[i].dst_len = test_thrds_data[i].src_len * 10;
		test_thrds_data[i].src = calloc(1, test_thrds_data[i].src_len);
		if (test_thrds_data[i].src == NULL)
			goto err_buf_free;
		memcpy(test_thrds_data[i].src, file_buf, test_thrds_data[i].src_len);
		test_thrds_data[i].dst = calloc(1, test_thrds_data[i].dst_len);
		if (test_thrds_data[i].dst == NULL)
			goto err_src_buf_free;
	}
	int h_cpuid;
	for (i = 0; i < thread_num - cnt; i++) {
		h_cpuid = _get_cpu_id(i, hcore_mask);
		if (h_cpuid > 0)
			h_cpuid += 64;
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].iteration = iteration;
		test_thrds_data[i].blksize = block_size;
		test_thrds_data[i].alg_type = alg_type;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].hw_flag = hw_flag;
		//test_thrds_data[i].cpu_id = i;
		test_thrds_data[i].cpu_id = h_cpuid;
		test_thrds_data[i].src_len = MIN(in_len, block_size);
		test_thrds_data[i].dst_len = test_thrds_data[i].src_len * 10;
		test_thrds_data[i].src = calloc(1, test_thrds_data[i].src_len);
		if (test_thrds_data[i].src == NULL)
			goto err_buf_free;
		memcpy(test_thrds_data[i].src, file_buf, test_thrds_data[i].src_len);
		test_thrds_data[i].dst = calloc(1, test_thrds_data[i].dst_len);
		if (test_thrds_data[i].dst == NULL)
			goto err_src_buf_free;
	}


	if (mode == ASYNC) {
		ret = zip_sys_async_init(thread_num, alg_type, op_type);
		if (ret) {
			WD_ERR("Init async fail!\n");
			goto err_src_buf_free;
		}
		ret = pthread_create(&system_test_thrds[thread_num], NULL,
				     zip_sys_async_poll_thread,
				     &test_thrds_data[0]);
		if (ret) {
			WD_ERR("Create poll thread fail!\n");
			goto err_src_buf_free;
		}
	} else if (mode == STREAM) {
		ret = zip_sys_stream_init(thread_num, alg_type, op_type);
	} else if (mode == BLOCK) {
		ret = zip_sys_block_init(thread_num, alg_type, op_type);
	}

	gettimeofday(&start_tval, NULL);
	for (i = 0; i < thread_num; i++) {
		if (mode == STREAM )
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zip_sys_stream_thread,
					     &test_thrds_data[i]);
		else if (mode == ASYNC)
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zip_sys_async_comp_thread,
					     &test_thrds_data[i]);
		else if (mode == BLOCK )
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zip_sys_block_thread,
					     &test_thrds_data[i]);
		else
			ret = 0;
		if (ret) {
			WD_ERR("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			WD_ERR("Join %dth thread fail!\n", i);
			return ret;
		}
	}

	gettimeofday(&poll_tval, NULL);
	if (mode == ASYNC) {
		ret = pthread_join(system_test_thrds[thread_num], NULL);
		if (ret) {
			WD_ERR("Join %dth thread fail!\n", thread_num);
			return ret;
		}
	}
	gettimeofday(&end_tval, NULL);

	float poll_time = (float)((end_tval.tv_sec-poll_tval.tv_sec) * 1000000 +
		     end_tval.tv_usec - poll_tval.tv_usec);
	tc = (float)((end_tval.tv_sec-start_tval.tv_sec) * 1000000 +
		     end_tval.tv_usec - start_tval.tv_usec);
	//dbg("%s end threadnum = %d,time = %f, poll time = %f\n",
	//    __func__, thread_num, tc, poll_time);

	sz = fwrite(test_thrds_data[0].opdata->out, 1,
		    test_thrds_data[0].dst_len, dest);

	for (i = 0; i < thread_num; i++) {
		total_in += test_thrds_data[i].src_len;
		total_out += test_thrds_data[i].dst_len;
	}
	if (op_type == WCRYPTO_DEFLATE) {
		speed = total_in / tc /
			1024 / 1024 * 1000 * 1000 * iteration,
		fprintf(stderr,
			"Compress bz=%d, threadnum= %d, qnum=%d, speed=%0.3f MB/s, timedelay=%0.1f us\n",
			block_size, thread_num, q_num, speed,
			tc / thread_num / count / iteration);
	} else {
		speed = total_out / tc /
			1024 / 1024 * 1000 * 1000 * iteration,
		fprintf(stderr,
			"Decompress bz=%d, threadnum= %d, qnum=%d, speed=%0.3f MB/s, timedelay=%0.1f us\n",
			block_size, thread_num, q_num, speed,
			tc / thread_num / count / iteration);
	}

	zip_sys_test_uninit(thread_num);

	for (i = 0; i < thread_num; i++) {
		free(test_thrds_data[i].src);
		free(test_thrds_data[i].dst);
	}

	free(file_buf);

	return 0;

err_src_buf_free:
	free(test_thrds_data[i].src);

err_buf_free:
	for (j = 0; j < i; j++) {
		free(test_thrds_data[j].src);
		free(test_thrds_data[j].dst);
	}

	free(file_buf);

	WD_ERR("thread malloc fail!ENOMEM!\n");

	return -ENOMEM;
}


int main(int argc, char *argv[])
{
	int op_type = WCRYPTO_DEFLATE;
	int alg_type = WCRYPTO_GZIP;
	int thread_num = 1;
	int iteration = 1;
	int show_help = 0;
	int hw_flag = 1;
	int mode = 0;
			__u64 core_mask[2] = {0}; 
			int small;
			int cpu_mask_c = 0;
	int opt;

	while ((opt = getopt(argc, argv, "mkazgdb:p:q:i:c:vh")) != -1) {
		switch (opt) {
			case 'm':
				mode = STREAM;
				break;
			case 'k':
				mode = BLOCK;
				break;
			case 'a':
				mode = ASYNC;
				break;
			case 'z':
				alg_type = WCRYPTO_ZLIB;
				break;
			case 'g':
				alg_type = WCRYPTO_GZIP;
				break;
			case 'd':
				op_type = WCRYPTO_INFLATE;
				break;
			case 'b':
				block_size = atoi(optarg);
				if (block_size  <= 0)
					show_help = 1;
				else if (block_size > 1024 * 1024)
					SYS_ERR_COND(1, "blocksize > 1M!\n");
				break;
			case 'p':
				thread_num = atoi(optarg);
				if (thread_num > TEST_MAX_THRD)
					SYS_ERR_COND(1, "thread_num > 2048!\n");
				break;
			case 'q':
				q_num = atoi(optarg);
				if (q_num <= 0)
					show_help = 1;
				break;
			case 'i':
				iteration = atoi(optarg);
				if (iteration <= 0)
					show_help = 1;
				break;
			case 'c':
				if (!(optarg[0] == '0' && optarg[1] == 'x'))
					show_help = 1;
			    if (strcmp(optarg, "0x0")) {
			    get_core_mask(optarg,core_mask);
			    cpu_mask_c += _get_one_bits(core_mask[0]);
			    cpu_mask_c += _get_one_bits(core_mask[1]);
			 dbg(" lcoremask=0x%llx, hcoremask=0x%llx\n", core_mask[0], core_mask[1]);
		     if(thread_num!=cpu_mask_c) 
                dbg("kthread:%d != cpu_mask:%d at %s", thread_num, cpu_mask_c, __func__);
            

			}
				
				break;
			default:
				show_help = 1;
				break;
		}
	}

	SYS_ERR_COND(show_help || optind > argc,
		     "version 2.00:test_hisi_zip_perf -[k/m/a] -[g|z] -d [-b block] [-p thread_num] [-i iteration] [-c 0xcoremask] < in > out");

	(void)hizip_thread_test(stdin, stdout, thread_num, alg_type,
			op_type, mode, hw_flag, iteration, core_mask[0],
			 core_mask[1]);

	return EXIT_SUCCESS;
}

