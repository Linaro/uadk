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

#include "v1/wd.h"
#include "zip_alg.h"
#include "v1/wd_util.h"
#include "v1/wd_comp.h"
#include "v1/drv/hisi_qm_udrv.h"
#include "v1/wd_bmm.h"
enum mode {
	MODE_BLOCK,
	MODE_STREAM,
	ASYNC,
};

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
	ulong src_len;
	ulong dst_len;
	float com_time;
	float decom_time;
	void *pool;
};

struct user_comp_tag_info {
	int cpu_id;
	pid_t tid;
	int alg_type;
};

#define TEST_MAX_THRD		2048
#define MAX_CORES		128
#define WD_WAIT_MS		1000
#define MAX_DMEMSIZE		8 * 1024 * 1024 	/* 8M */

static pthread_t system_test_thrds[TEST_MAX_THRD];
static struct test_zip_pthread_dt test_thrds_data[TEST_MAX_THRD];

/* bytes of data for a request */
static int block_size = 512000;
static int req_cache_num = 4;
static int q_num = 1;
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
		if (pdata->op_type == WCRYPTO_DEFLATE) {
			if (pdata->hw_flag) {
				ret = hw_stream_compress(pdata->alg_type,
							 pdata->blksize,
							 pdata->dst,
							 &pdata->dst_len,
							 pdata->src,
							 pdata->src_len);
				if (ret < 0)
					WD_ERR("comp fail! id=%d tid=%d ret=%d\n",
						cpu_id, (int)tid, ret);
			} 		
		} else if (pdata->op_type == WCRYPTO_INFLATE) {
			if (pdata->hw_flag) {
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

void zip_callback(const void *msg, void *tag)
{
	const struct wcrypto_comp_msg *respmsg = msg;

	out_len = respmsg->produced;

	dbg("[%s], cpu_id =%d consume=%d, produce=%d\n",
	    __func__, ((struct user_comp_tag_info *)tag)->cpu_id,
	    respmsg->in_cons, respmsg->produced);

}

void *zip_sys_async_test_thread(void *args)
{
	int cpu_id, ret;
	cpu_set_t mask;
	pid_t tid;
	struct test_zip_pthread_dt *pdata = args;
	struct user_comp_tag_info u_tag;
	int i = pdata->iteration;
	struct wcrypto_paras *priv;
	struct wd_queue *q;
	void *zip_ctx;
	struct wcrypto_comp_ctx_setup ctx_setup;
	struct wd_blkpool_setup blk_setup = { 0 };
	struct wcrypto_comp_op_data *opdata;
	int loop;

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

	q = calloc(1, sizeof(struct wd_queue));
	if (!q) {
		ret = -ENOMEM;
		fprintf(stderr, "alloc q fail, ret =%d\n", ret);
		goto hw_q_free;
	}
	memset(&ctx_setup, 0, sizeof(ctx_setup));

	switch (pdata->alg_type) {
	case 0:
		ctx_setup.alg_type = WCRYPTO_ZLIB;
		q->capa.alg = "zlib";
		break;
	case 1:
		ctx_setup.alg_type = WCRYPTO_GZIP;
		q->capa.alg = "gzip";
		break;
	default:
		ctx_setup.alg_type = WCRYPTO_ZLIB;
		q->capa.alg = "zlib";
	}
	q->capa.latency = 0;
	q->capa.throughput = 0;
	priv = &q->capa.priv;
	priv->direction = pdata->op_type;
	priv->is_poll = 1;
	ret = wd_request_queue(q);
	if (ret) {
		fprintf(stderr, "wd_request_queue fail, ret =%d\n", ret);
		goto hw_q_free;
	}
	SYS_ERR_COND(ret, "wd_request_queue");

	blk_setup.block_size = MAX_DMEMSIZE;
	blk_setup.block_num = 3;
	blk_setup.align_size = 128;
	pdata->pool = wd_blkpool_create(q, &blk_setup);
	if (!pdata->pool) {
		ret = -ENOMEM;
		WD_ERR("%s create pool fail!, ret =%d\n", __func__, ret);
		goto release_q;
	}

	ctx_setup.br.alloc = (void *)wd_alloc_blk;
	ctx_setup.br.free = (void *)wd_free_blk;
	ctx_setup.br.iova_map = (void *)wd_blk_iova_map;
	ctx_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	ctx_setup.br.get_bufsize = (void *)wd_blksize;
	ctx_setup.win_size = WCRYPTO_COMP_WS_8K;
	ctx_setup.br.usr = pdata->pool;
	ctx_setup.cb = zip_callback;
	ctx_setup.stream_mode = WCRYPTO_COMP_STATELESS;
	zip_ctx = wcrypto_create_comp_ctx(q, &ctx_setup);
	if (!zip_ctx) {
		ret = -ENOMEM;
		fprintf(stderr, "zip_alloc_comp_ctx fail, ret =%d\n", ret);
		goto blkpool_free;
	}

	opdata = calloc(1, sizeof(struct wcrypto_comp_op_data));
	if (!opdata) {
		ret = -ENOMEM;
		fprintf(stderr, "alloc opdata fail, ret =%d\n", ret);
		goto comp_ctx_free;
	}
	opdata->in = wd_alloc_blk(pdata->pool);
	opdata->out = wd_alloc_blk(pdata->pool);
	if (!opdata->in || !opdata->out) {
		ret = -ENOMEM;
		WD_ERR("%s not enough data memory for cache (bs=%d), ret =%d\n",
			__func__, block_size, ret);
		goto buf_free;
	}
	opdata->stream_pos = WCRYPTO_COMP_STREAM_NEW;

	memcpy(opdata->in, pdata->src, pdata->src_len);

	opdata->in_len = pdata->src_len;
	opdata->avail_out = MAX_DMEMSIZE;

	u_tag.alg_type = ctx_setup.alg_type;
	u_tag.cpu_id = cpu_id;
	u_tag.tid = tid;
	loop = 10;
	dbg("%s entry thread_id=%d\n", __func__, (int)tid);
	do {
		i = pdata->iteration;
		do {
			ret = wcrypto_do_comp(zip_ctx, opdata, &u_tag);
			if (ret == -WD_EBUSY) {
				WD_ERR("%s(): asynctest no cache!\n", __func__);
				break;
			}

		} while (--i);

		ret = wd_wait(q, WD_WAIT_MS);
		if(likely(ret > 0)) {
			ret = wcrypto_comp_poll(q, pdata->iteration);
			if (ret < 0)
				WD_ERR("poll fail! thread_id=%d, tid=%d. ret:%d\n",
					cpu_id, (int)tid, ret);
		}

	} while (--loop);

	opdata->produced = out_len;
	dbg("%s(): test !,produce=%d\n", __func__, opdata->produced);

	memcpy(pdata->dst, opdata->out, opdata->produced);
	pdata->dst_len = opdata->produced;

	dbg("%s end thread_id=%d\n", __func__, pdata->cpu_id);

	wd_free_blk(pdata->pool, opdata->in);
	wd_free_blk(pdata->pool, opdata->out);
	free(opdata);
	wcrypto_del_comp_ctx(zip_ctx);
	wd_blkpool_destroy(pdata->pool);
	wd_release_queue(q);
	free(q);

	return NULL;

comp_ctx_free:
		wcrypto_del_comp_ctx(zip_ctx);
buf_free:
		free(opdata);
blkpool_free:
		wd_blkpool_destroy(pdata->pool);
release_q:
		wd_release_queue(q);
hw_q_free:
		free(q);

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
		if (pdata->op_type == WCRYPTO_DEFLATE) {
			ret = hw_blk_compress(pdata->alg_type, pdata->blksize,
					      pdata->dst, &pdata->dst_len,
					      pdata->src, pdata->src_len);
			if (ret < 0)
				WD_ERR("comp fail! thread_id=%d, tid=%d\n",
					cpu_id, (int)tid);
		} else if (pdata->op_type == WCRYPTO_INFLATE) {
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

static int hizip_thread_test(FILE *source, FILE *dest,
			     int thread_num, int alg_type, int op_type,
			     int mode, int hw_flag, int iteration)
{
	int fd;
	struct stat s;
	int i, j, ret;
	int cnt = 0;
	void *file_buf;
	int in_len, sz;
	float tc = 0;
	float speed;
	float total_in = 0;
	float total_out = 0;
	int count = 0;
	struct timeval start_tval, end_tval;

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

	dbg("%s entry blocksize=%d, count=%d, threadnum= %d, in_len=%d\n",
	    __func__, block_size, count, thread_num, in_len);

	cnt = thread_num;
	for (i = 0; i < cnt; i++) {
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].cpu_id = i;
		test_thrds_data[i].alg_type = alg_type;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].hw_flag = hw_flag;
		test_thrds_data[i].blksize = block_size;
		test_thrds_data[i].iteration = iteration;
		test_thrds_data[i].src = file_buf;
		test_thrds_data[i].src_len = in_len;
		test_thrds_data[i].dst_len = test_thrds_data[i].src_len * 8;
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
		if (mode == MODE_STREAM || hw_flag == 0)
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zlib_sys_stream_test_thread,
					     &test_thrds_data[i]);
		else if (mode == ASYNC)
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zip_sys_async_test_thread,
					     &test_thrds_data[i]);
		else
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zip_sys_block_test_thread,
					     &test_thrds_data[i]);
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
	gettimeofday(&end_tval, NULL);
	for (i = 0; i < thread_num; i++) {
		total_in += test_thrds_data[i].src_len;
		total_out += test_thrds_data[i].dst_len;
	}
	tc = (float)((end_tval.tv_sec-start_tval.tv_sec) * 1000000 +
		     end_tval.tv_usec - start_tval.tv_usec);
	dbg("%s end threadnum= %d, out_len=%ld\n",
	    __func__, thread_num, test_thrds_data[thread_num-1].dst_len);
	sz = fwrite(test_thrds_data[thread_num-1].dst, 1,
		    test_thrds_data[thread_num-1].dst_len, dest);

	for (i = 0; i < thread_num; i++) {
		free(test_thrds_data[i].src);
		free(test_thrds_data[i].dst);
	}
	if (op_type == WCRYPTO_DEFLATE) {
		speed = total_in / tc /
			1024 / 1024 * 1000 * 1000 * iteration,
		fprintf(stderr,
			"Compress bz=%d, threadnum= %d, speed=%0.3f MB/s, timedelay=%0.1f us\n",
			block_size, thread_num, speed,
			tc / thread_num / count / iteration);
	} else {
		speed = total_out / tc /
			1024 / 1024 * 1000 * 1000 * iteration,
		fprintf(stderr,
			"Decompress bz=%d, threadnum= %d, speed=%0.3f MB/s, timedelay=%0.1f us\n",
			block_size, thread_num, speed,
			tc / thread_num / count / iteration);
	}

	free(file_buf);

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

int main(int argc, char *argv[])
{
	int alg_type = WCRYPTO_GZIP;
	int op_type = WCRYPTO_DEFLATE;
	int opt;
	int show_help = 0;
	int thread_num = 1;
	int mode = 0;
	int hw_flag = 1;
	int iteration = 1;

	while ((opt = getopt(argc, argv, "zghq:ab:dvc:kmsp:i:")) != -1) {
		switch (opt) {
		case 'z':
			alg_type = WCRYPTO_ZLIB;
			break;
		case 'g':
			alg_type = WCRYPTO_GZIP;
			break;
		case 'q':
			q_num = atoi(optarg);
			if (q_num <= 0)
				show_help = 1;
			break;
		case 'b':
			block_size = atoi(optarg);
			if (block_size  <= 0)
				show_help = 1;
			else if (block_size > 1024 * 1024)
				SYS_ERR_COND(1, "blocksize > 1M!\n");
			break;
		case 'c':
			req_cache_num = atoi(optarg);
			if (req_cache_num <= 0)
				show_help = 1;
			break;
		case 'd':
			op_type = WCRYPTO_INFLATE;
			break;
		case 'k':
			mode = MODE_BLOCK;
			break;
		case 'm':
			mode = MODE_STREAM;
			break;
		case 'a':
			mode = ASYNC;
			break;
		case 'p':
			thread_num = atoi(optarg);
			if (thread_num > TEST_MAX_THRD)
				SYS_ERR_COND(1, "thread_num > 2048!\n");
			break;
		case 's':
			hw_flag = 0;
			break;
		case 'v':
			verify = 1;
			break;
		case 'i':
			iteration = atoi(optarg);
			if (iteration <= 0)
				show_help = 1;
			break;
		default:
			show_help = 1;
			break;
		}
	}

	SYS_ERR_COND(show_help || optind > argc,
		     "version 1.00:wd_test_zip -[k/m/s] -[g|z] -d [-b block][-p thread_num] [-i iteration] < in > out");

	(void)hizip_thread_test(stdin, stdout, thread_num, alg_type,
				op_type, mode, hw_flag, iteration);

	return EXIT_SUCCESS;
}
