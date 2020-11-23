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
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#define __USE_GNU
#include <pthread.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include "wd.h"
#include "hisi_qm_udrv.h"
#include "test_lib.h"


struct test_zip_pthread_dt {
	int cpu_id;
	int thread_num;
	int alg_type;
	int op_type;
	int hw_flag;
	int blksize;
	int iteration;
	void *src;
	void *dst;
	__u32 src_len;
	__u32 dst_len;
	float com_time;
	float decom_time;
};

struct user_comp_param {
	int cpu_id;
	pid_t tid;
	int alg_type;
	__u32 out_len;
};

#define TEST_MAX_THRD		2048
#define MAX_CORES		128

static pthread_t system_test_thrds[TEST_MAX_THRD];
static pthread_t system_test_poll_thrds;
static struct test_zip_pthread_dt test_thrds_data[TEST_MAX_THRD];

/* bytes of data for a request */
static int block_size = 512000;
static int verify;

pid_t gettid(void)
{
	return syscall(__NR_gettid);
}

/* stream mode test thread */
void *zlib_sys_stream_test_thread(void *args)
{
	int cpu_id, ret;
	pid_t tid;
	cpu_set_t mask;
	struct test_zip_pthread_dt *pdata = args;
	int i = pdata->iteration;

	cpu_id = pdata->cpu_id;
	tid = gettid();

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

	dbg("%s entry thread_id=%d\n", __func__, (int)tid);
	do {
		if (pdata->op_type == WD_DIR_COMPRESS) {
			ret = hw_stream_compress(pdata->alg_type,
					pdata->blksize,
					pdata->dst,
					&pdata->dst_len,
					pdata->src,
					pdata->src_len);
			if (ret < 0)
				WD_ERR("comp fail! id=%d tid=%d ret=%d\n",
						cpu_id, (int)tid, ret);
		} else if (pdata->op_type == WD_DIR_DECOMPRESS) {
			ret = hw_stream_decompress(pdata->alg_type,
					pdata->blksize,
					pdata->dst,
					&pdata->dst_len,
					pdata->src,
					pdata->src_len);
			if (ret < 0)
				WD_ERR("decomp fail! id=%d tid=%d ret=%d\n",
						cpu_id, (int)tid, ret);
		}

		if (verify) {
			ret = hw_stream_decompress(pdata->alg_type,
						   pdata->blksize,
						   pdata->src,
						   &pdata->src_len,
						   pdata->dst,
						   pdata->dst_len);
			if (ret < 0)
				WD_ERR("loop verify fail! ret=%d, id=%d\n",
					ret, cpu_id);
			else
				dbg("loop verify success! id=%d\n", cpu_id);
		}

	} while (--i);
	dbg("%s end thread_id=%d\n", __func__, (int)tid);

	return NULL;

}

static int out_len;

void zip_callback(void *req, void *param)
{


	dbg("[%s],test entry \n", __func__);
	struct wd_comp_req *preq = req;

	if (!req || !param) {
		WD_ERR("callback input NULL!\n");
		return;

	}
	out_len = preq->dst_len;

	dbg("[%s], consume=%d, produce=%d\n",
	    __func__, preq->src_len, preq->dst_len);

}

#define MAX_POLL_COUNTS 10
void *zip_sys_async_test_poll_thread(void *args)
{
	int cpu_id;
	pid_t tid;
	struct test_zip_pthread_dt *pdata = args;
	__u32 count = 0;
	__u32 totalcount = 0;
	int recnt = 0;
	int ret = 0;

	cpu_id = pdata->cpu_id;
	tid = gettid();


	do {
		count = 0;
		dbg("poll start, expt =%d , have =%d!\n", pdata->iteration, totalcount);
		ret = wd_comp_poll(pdata->iteration, &count);
		if (ret < 0)
			WD_ERR("poll fail! thread_id=%d, tid=%d. ret:%d\n", cpu_id, (int)tid, ret);
		if (count > 0)
			recnt = 0;
		totalcount += count;
		if (totalcount < pdata->iteration * pdata->thread_num) {
			usleep(100000);
			dbg("poll thread now no task, expt =%d , have =%d!\n", pdata->iteration, totalcount);
			if (++recnt > MAX_POLL_COUNTS) {
				WD_ERR("poll thread  no task, 1s timeout, expt =%d , have =%d!\n", pdata->iteration * pdata->thread_num, totalcount);
				break;
			}
		}

	} while (totalcount < pdata->iteration * pdata->thread_num);

	WD_ERR("thread_id = %d, test poll end, count=%d\n", pdata->cpu_id, totalcount);

	pdata->dst_len = out_len;

	return NULL;
}

void *zip_sys_async_test_thread(void *args)
{
	int cpu_id;
	cpu_set_t mask;
	pid_t tid;
	struct test_zip_pthread_dt *pdata = args;
	struct user_comp_param u_param;
	int i = pdata->iteration;
	int loop;
	handle_t h_sess;
	struct wd_comp_sess_setup setup;
	struct wd_comp_req req;
	__u32 count = 0;
	int ret = 0;


	cpu_id = pdata->cpu_id;
	tid = gettid();

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

	setup.alg_type = pdata->alg_type;
	setup.mode = CTX_MODE_ASYNC;
	h_sess = wd_comp_alloc_sess(&setup);
	if (!h_sess) {
		fprintf(stderr,"fail to alloc comp sess!\n");
		return NULL;
	}

	u_param.alg_type = pdata->alg_type;
	u_param.cpu_id = cpu_id;
	u_param.tid = tid;

	req.src = pdata->src;
	req.src_len = pdata->src_len;
	req.dst = pdata->dst;
	req.dst_len = pdata->dst_len;
	req.op_type = pdata->op_type;
	req.cb = (void *)zip_callback;
	req.cb_param = &u_param;

	dbg("%s:input req: src:%p, dst:%p,src_len: %d, dst_len:%d\n",
	    __func__, req.src, req.dst, req.src_len, req.dst_len);

	loop = 1;
	dbg("%s entry thread_id=%d\n", __func__, (int)tid);
	do {
		i = pdata->iteration;
		count = 0;
		do {
			ret = wd_do_comp_async(h_sess, &req);
			if (ret == -EBUSY) {
				WD_ERR("%s(): async test no cache,wait 10ms!\n", __func__);
				usleep(10000);
				continue;
			}
			count++;

		} while (--i);

		WD_ERR("thread_id = %d, test send end, count=%d\n", pdata->cpu_id, count);

	} while (--loop);


	pdata->dst_len = u_param.out_len;

	dbg("%s:output req: src:%p, dst:%p,src_len: %d, dst_len:%d\n",
	    __func__, req.src, req.dst, req.src_len, pdata->dst_len);

	wd_comp_free_sess(h_sess);

	dbg("%s end thread_id=%d\n", __func__, pdata->cpu_id);

	return NULL;
}

void  *zip_sys_block_test_thread(void *args)
{
	int cpu_id, ret;
	cpu_set_t mask;
	pid_t tid;
	struct test_zip_pthread_dt *pdata = args;
	int i = pdata->iteration;

	cpu_id = pdata->cpu_id;
	tid = gettid();

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

	dbg("%s entry thread_id=%d\n", __func__, (int)tid);
	do {
		if (pdata->op_type == WD_DIR_COMPRESS) {
			ret = hw_blk_compress(pdata->alg_type, pdata->blksize,
					      pdata->dst, &pdata->dst_len,
					      pdata->src, pdata->src_len);
			if (ret < 0)
				WD_ERR("comp fail! thread_id=%d, tid=%d\n",
					cpu_id, (int)tid);
		} else if (pdata->op_type == WD_DIR_DECOMPRESS) {
			ret = hw_blk_decompress(pdata->alg_type, pdata->blksize,
						pdata->dst, &pdata->dst_len,
						pdata->src, pdata->src_len);
			if (ret < 0)
				WD_ERR("decomp fail! thread_id=%d, tid=%d\n",
					cpu_id, (int)tid);
		}
		if (verify) {
			ret = hw_blk_decompress(pdata->alg_type, pdata->blksize,
						pdata->src, &pdata->src_len,
						pdata->dst, pdata->dst_len);
			if (ret < 0)
				WD_ERR("loop verify fail! ret=%d, id=%d\n",
					ret, cpu_id);
			else
				dbg("loop verify success! id=%d\n", cpu_id);
		}
	} while (--i);
	dbg("%s end thread_id=%d\n", __func__, pdata->cpu_id);

	return NULL;
}

#define MAX_LEN (~0U)

int comp_file_test(FILE *source, FILE *dest, struct priv_options *opts)
{
	int fd;
	struct stat s;
	int i, j, ret;
	int cnt = 0;
	void *file_buf;
	__u32 in_len, sz;
	float tc = 0;
	float speed;
	ulong dstlen = 0;
	float total_in = 0;
	float total_out = 0;
	int count = 0;
	struct wd_sched *sched = NULL;
	struct hizip_test_info info = {0};
	struct timeval start_tval, end_tval;
	struct test_options *copts = &opts->common;
	int mode = copts->sync_mode;
	int thread_num = copts->thread_num;

	fd = fileno(source);
	SYS_ERR_COND(fstat(fd, &s) < 0, "fstat");
	in_len = s.st_size;

	file_buf = calloc(1, in_len);

	sz = fread(file_buf, 1, in_len, source);
	if (sz != in_len)
		WD_ERR("read file sz != in_len!\n");
	count = in_len/block_size;

	if (!count)
		count = 1;

	dbg("%s entry blocksize=%d, count=%d, threadnum= %d, in_len=%d\n",
	    __func__, block_size, count, thread_num, in_len);

	ret = init_ctx_config(copts, &info, &sched);
	if (ret)
		return ret;

	dstlen = (ulong)in_len * 2;
	if (copts->block_size != 512000)
		dstlen = copts->block_size; /* just for user configure dest size test*/

	dstlen = dstlen > MAX_LEN ? MAX_LEN : dstlen;

	cnt = copts->thread_num;
	for (i = 0; i < cnt; i++) {
		test_thrds_data[i].thread_num = cnt;
		test_thrds_data[i].cpu_id = i;
		test_thrds_data[i].alg_type = copts->alg_type;
		test_thrds_data[i].op_type = copts->op_type;
		test_thrds_data[i].blksize = copts->block_size;
		test_thrds_data[i].iteration = copts->run_num;
		test_thrds_data[i].src = file_buf;
		test_thrds_data[i].src_len = in_len;
		test_thrds_data[i].dst_len = dstlen;
		test_thrds_data[i].src = calloc(1, test_thrds_data[i].src_len);
		if (test_thrds_data[i].src == NULL)
			goto buf_free;
		memcpy(test_thrds_data[i].src, file_buf, in_len);
		test_thrds_data[i].dst = calloc(1, test_thrds_data[i].dst_len);
		if (test_thrds_data[i].dst == NULL)
			goto src_buf_free;
	}

	gettimeofday(&start_tval, NULL);
	for (i = 0; i < cnt; i++) {
		if (mode == CTX_MODE_ASYNC) {
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zip_sys_async_test_thread,
					     &test_thrds_data[i]);
		} else {
			if (copts->is_stream == MODE_STREAM)
				ret = pthread_create(&system_test_thrds[i], NULL,
						     zlib_sys_stream_test_thread,
						     &test_thrds_data[i]);
			else
				ret = pthread_create(&system_test_thrds[i], NULL,
						     zip_sys_block_test_thread,
						     &test_thrds_data[i]);
		}
		if (ret) {
			WD_ERR("Create %dth thread fail!\n", i);
			return ret;
		}
	}

	if (mode == CTX_MODE_ASYNC)
			ret = pthread_create(&system_test_poll_thrds, NULL,
					     zip_sys_async_test_poll_thread,
					     &test_thrds_data[0]);

	for (i = 0; i < copts->thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			WD_ERR("Join %dth thread fail!\n", i);
			return ret;
		}
	}

	if (mode == CTX_MODE_ASYNC) {
		ret = pthread_join(system_test_poll_thrds, NULL);
		if (ret) {
			WD_ERR("Join poll thread fail!\n");
			return ret;
		}
	}

	gettimeofday(&end_tval, NULL);
	for (i = 0; i < copts->thread_num; i++) {
		total_in += test_thrds_data[i].src_len;
		total_out += test_thrds_data[i].dst_len;
	}
	tc = (float)((end_tval.tv_sec-start_tval.tv_sec) * 1000000 +
		     end_tval.tv_usec - start_tval.tv_usec);
	dbg("%s end threadnum= %d, out_len=%u\n",
	    __func__, thread_num, test_thrds_data[thread_num-1].dst_len);


	if (mode == CTX_MODE_ASYNC) {
		sz = fwrite(test_thrds_data[thread_num - 1].dst, 1,
			    out_len, dest);

	} else {
		sz = fwrite(test_thrds_data[thread_num - 1].dst, 1,
			    test_thrds_data[thread_num - 1].dst_len, dest);
	}
	for (i = 0; i < thread_num; i++) {
		dbg("%s:free src[%d]:%p\n", __func__, i, test_thrds_data[i].src);

		free(test_thrds_data[i].src);

		dbg("%s:free dst[%d]:%p\n", __func__, i, test_thrds_data[i].dst);

		free(test_thrds_data[i].dst);
	}
	if (copts->op_type == WD_DIR_COMPRESS) {
		speed = total_in / tc /
			1024 / 1024 * 1000 * 1000 * copts->run_num,
		fprintf(stderr,
			"Compress bz=%d, threadnum= %d, speed=%0.3f MB/s, timedelay=%0.1f us\n",
			block_size, thread_num, speed,
			tc / thread_num / count / copts->run_num);
	} else {
		speed = total_out / tc /
			1024 / 1024 * 1000 * 1000 * copts->run_num,
		fprintf(stderr,
			"Decompress bz=%d, threadnum= %d, speed=%0.3f MB/s, timedelay=%0.1f us\n",
			block_size, thread_num, speed,
			tc / thread_num / count / copts->run_num);
	}

	free(file_buf);
	uninit_config(&info, sched);

	return 0;

src_buf_free:
	free(test_thrds_data[i].src);

buf_free:
	for (j = 0; j < i; j++) {
		free(test_thrds_data[i].src);
		free(test_thrds_data[i].dst);
	}

	free(file_buf);

	WD_ERR("thread malloc fail!ENOMEM!\n");

	return -ENOMEM;
}

