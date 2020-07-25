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

//#define DEBUG_LOG

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
#include "../smm.h"
#include "../../wd.h"
#include "../../wd_comp.h"
#include "../../wd_util.h"
#include "zip_alg.h"

enum mode {
	MODE_BLOCK,
	MODE_ASYNC,
};

struct test_zip_pthread_dt {
	int thread_id;
	int thread_num;
	int alg_type;
	int op_type;
	int iteration;
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
	int alg_type;
	int op_type;
	int tag;
};

#define HZIP_ZLIB_HEAD_SIZE		2
#define HZIP_GZIP_HEAD_SIZE		10

#define TEST_MAX_THRD			2048
#define MAX_CORES			128

static struct test_zip_pthread_dt test_thrds_data[TEST_MAX_THRD];
static pthread_t system_test_thrds[TEST_MAX_THRD];
static struct wd_queue q[TEST_MAX_THRD];

/* bytes of data for a request */
static int window_size;
static int q_num = 1;

static const unsigned char zlib_head[HZIP_ZLIB_HEAD_SIZE] = {0x78, 0x9c};
static const unsigned char gzip_head[HZIP_GZIP_HEAD_SIZE] = {
	0x1f, 0x8b, 0x08, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x03
};

#define TO_HEAD_SIZE(req_type)					\
	(((req_type) == WCRYPTO_ZLIB) ? sizeof(zlib_head) :	\
	 ((req_type) == WCRYPTO_GZIP) ? sizeof(gzip_head) : 0)

#define TO_HEAD(req_type)					\
	(((req_type) == WCRYPTO_ZLIB) ? zlib_head :		\
	 ((req_type) == WCRYPTO_GZIP) ? gzip_head : NULL)

pid_t gettid(void)
{
	return syscall(__NR_gettid);
}

void zip_callback(const void *msg, void *tag)
{
	const struct wcrypto_comp_msg *respmsg = msg;
	const struct user_comp_tag_info *utag = tag;
	int head_size = 0;
	int i = utag->tag;
	struct test_zip_pthread_dt *pdata = &test_thrds_data[i];


	dbg("%s start!\n", __func__);

	pdata->dst_len = respmsg->produced;

	if (pdata->op_type == WCRYPTO_DEFLATE) {
		memcpy(pdata->dst, TO_HEAD(pdata->alg_type),
		       TO_HEAD_SIZE(pdata->alg_type));
		head_size = TO_HEAD_SIZE(pdata->alg_type);
		pdata->dst_len += head_size;
	}
	memcpy(pdata->dst + head_size,
	       pdata->opdata->out,
	       respmsg->produced);

	dbg("%s succeed!\n", __func__);
}

void *zip_sys_async_poll_thread(void *args)
{
	int *cnt = calloc(1, sizeof(int) * q_num);
	struct test_zip_pthread_dt *pdata = args;
	int iter = pdata->iteration;
	int workq_num = q_num;
	int ret, i;

	dbg("%s start!\n", __func__);

	for (i = 0; i < q_num; i++)
		cnt[i] = iter;

	do {
		for (i = 0; i < q_num; i++) {
			if (!cnt[i])
				continue;
			ret = wcrypto_comp_poll(&q[i], cnt[i]);
			if (ret < 0) {
				WD_ERR("poll fail! thread_id=%d, ret:%d\n",
				       pdata->thread_id, ret);
				break;
			}
			cnt[i] -= ret;
			if (!cnt[i])
				workq_num--;
		}
	} while (workq_num);

	dbg("%s succeed!\n", __func__);

	return NULL;
}

void *zip_sys_async_comp_thread(void *args)
{
	struct test_zip_pthread_dt *pdata = args;
	struct user_comp_tag_info *utag;
	int i = pdata->iteration;
	int ret;

	dbg("%s start!\n", __func__);

	utag = calloc(1, sizeof(struct user_comp_tag_info));
	utag->alg_type = pdata->alg_type;
	utag->op_type = pdata->op_type;
	utag->tag = pdata->thread_id;

	do {
		ret = wcrypto_do_comp(pdata->ctx, pdata->opdata, utag);
		if (ret == -WD_EBUSY)
			i++;
		else if (ret != 0)
			return (void *) ret;
	} while (--i);

	dbg("%s succeed!\n", __func__);

	return NULL;
}

void *zip_sys_block_test_thread(void *args)
{
	struct test_zip_pthread_dt *pdata = args;
	int alg_type = pdata->alg_type;
	int i = pdata->iteration;
	int head_size = 0;
	int ret;

	dbg("%s start!\n", __func__);

	do {
		ret = wcrypto_do_comp(pdata->ctx, pdata->opdata, NULL);
		if (ret == -WD_EBUSY)
			i++;
		else if (ret != 0)
			return (void *) ret;

		pdata->dst_len = pdata->opdata->produced;

		if (pdata->op_type == WCRYPTO_DEFLATE) {
			memcpy(pdata->dst, TO_HEAD(alg_type),
			       TO_HEAD_SIZE(alg_type));
			head_size = TO_HEAD_SIZE(alg_type);
			pdata->dst_len += head_size;
		}
		memcpy(pdata->dst + head_size,
		       pdata->opdata->out,
		       pdata->opdata->produced);

	} while (--i);

	dbg("%s succeed!\n", __func__);

	return NULL;
}

int zip_sys_block_init(int thread_num, int alg_type, int op_type, int mode)
{
	size_t ss_region_size = 4096 + DMEMSIZE * 2 + HW_CTX_SIZE;
	struct test_zip_pthread_dt *pdata;
	struct wcrypto_paras *priv;
	void **ss_buf;
	int i, j, ret;

	dbg("%s start!\n", __func__);

	q_num = thread_num;

	ss_buf = calloc(1, sizeof(void *) * q_num);

	for (i = 0; i < q_num; i++) {
		switch (alg_type) {
		case WCRYPTO_ZLIB:
			q[i].capa.alg = "zlib";
			break;
		case WCRYPTO_GZIP:
			q[i].capa.alg = "gzip";
			break;
		case WCRYPTO_RAW_DEFLATE:
			q[i].capa.alg = "deflate";
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

		ss_buf[i] = wd_reserve_memory(&q[i], ss_region_size);
		if (!ss_buf[i]) {
			WD_ERR("reserve %dth buf fail, ret =%d\n", i, ret);
			ret = -ENOMEM;
			goto err_q_release;
		}
		smm_init(ss_buf[i], ss_region_size, 0xF);
		if (ret)
			goto err_q_release;
	}

	for (i = 0; i < thread_num; i++) {
		pdata = &test_thrds_data[i];
		pdata->ctx_setup = calloc(1, sizeof(*pdata->ctx_setup));
		if (!pdata->ctx_setup) {
			ret = -ENOMEM;
			WD_ERR("alloc %dth ctx_setup fail, ret = %d\n", i, ret);
			goto err_ctx_setup_free;
		}
		pdata->ctx_setup->alg_type = alg_type;
		pdata->ctx_setup->op_type = op_type;
		pdata->ctx_setup->stream_mode = WCRYPTO_COMP_STATELESS;
		pdata->ctx_setup->cb = mode ? zip_callback : NULL;
		pdata->ctx_setup->win_size = window_size;
		pdata->ctx = wcrypto_create_comp_ctx(&q[i],
						     pdata->ctx_setup);
		if (!pdata->ctx)
			goto err_ctx_del;

		pdata->opdata = calloc(1, sizeof(*pdata->opdata));
		if (!pdata->opdata) {
			ret = -ENOMEM;
			WD_ERR("alloc %dth opdata fail, ret = %d\n", i, ret);
			goto err_opdata_free;
		}
		pdata->opdata->stream_pos = WCRYPTO_COMP_STREAM_NEW;
		pdata->opdata->avail_out = DMEMSIZE;
		pdata->opdata->in = smm_alloc(ss_buf[i], DMEMSIZE);
		pdata->opdata->out = smm_alloc(ss_buf[i], DMEMSIZE);
		if (pdata->opdata->in == NULL || pdata->opdata->out == NULL) {
			ret = -ENOMEM;
			WD_ERR("not enough data ss_region memory for cache (bs=%d)\n",
			       DMEMSIZE);
			goto err_opdata_free;
		}
		pdata->opdata->in_len = pdata->src_len;
		memcpy(pdata->opdata->in, pdata->src, pdata->src_len);
	}

	dbg("%s succeed!\n", __func__);

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

static int hizip_thread_test(FILE *source, FILE *dest, int thread_num,
			     int alg_type, int op_type, int mode, int iteration)
{
	struct timeval start_tval, end_tval;
	float total_out = 0;
	float total_in = 0;
	int in_len, sz, fd;
	int head_size = 0;
	void *file_buf;
	struct stat s;
	int i, j, ret;
	float tc = 0;
	float speed;

	fd = fileno(source);
	SYS_ERR_COND(fstat(fd, &s) < 0, "fstat");
	in_len = s.st_size;
	SYS_ERR_COND(!in_len, "input file length zero");

	file_buf = calloc(1, in_len);

	sz = fread(file_buf, 1, in_len, source);
	if (sz != in_len)
		WD_ERR("read file sz != in_len!\n");

	if (op_type == WCRYPTO_INFLATE)
		head_size = TO_HEAD_SIZE(alg_type);

	dbg("%s entry threadnum= %d, in_len=%d\n",
	    __func__, thread_num, in_len);

	for (i = 0; i < thread_num; i++) {
		test_thrds_data[i].thread_id = i;
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].alg_type = alg_type;
		test_thrds_data[i].op_type = op_type;
		test_thrds_data[i].iteration = iteration;
		test_thrds_data[i].src = file_buf;
		test_thrds_data[i].src_len = in_len;
		test_thrds_data[i].dst_len = test_thrds_data[i].src_len * 10;
		test_thrds_data[i].src = calloc(1, test_thrds_data[i].src_len);
		if (test_thrds_data[i].src == NULL)
			goto buf_free;
		memcpy(test_thrds_data[i].src,
		       (unsigned char *)file_buf + head_size,
		       in_len - head_size);
		test_thrds_data[i].dst = calloc(1, test_thrds_data[i].dst_len);
		if (test_thrds_data[i].dst == NULL)
			goto src_buf_free;
	}

	ret = zip_sys_block_init(thread_num, alg_type, op_type, mode);
	if (ret) {
		WD_ERR("Init fail!\n");
		goto all_buf_free;
	}

	gettimeofday(&start_tval, NULL);
	for (i = 0; i < thread_num; i++) {
		if (mode == MODE_ASYNC)
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zip_sys_async_comp_thread,
					     &test_thrds_data[i]);
		else
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zip_sys_block_test_thread,
					     &test_thrds_data[i]);
		if (ret) {
			WD_ERR("Create %dth thread fail!\n", i);
			goto all_buf_free;
		}
	}
	if (mode == MODE_ASYNC) {
		ret = pthread_create(&system_test_thrds[thread_num], NULL,
				     zip_sys_async_poll_thread,
				     &test_thrds_data[0]);
		if (ret) {
			WD_ERR("Create poll thread fail!\n");
			goto all_buf_free;
		}
	}

	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			WD_ERR("Join %dth thread fail!\n", i);
			goto all_buf_free;
		}
	}

	if (mode == MODE_ASYNC) {
		ret = pthread_join(system_test_thrds[thread_num], NULL);
		if (ret) {
			WD_ERR("Join %dth thread fail!\n", thread_num);
			goto all_buf_free;
		}
	}
	gettimeofday(&end_tval, NULL);

	for (i = 0; i < thread_num; i++) {
		total_in += test_thrds_data[i].src_len;
		total_out += test_thrds_data[i].dst_len;
	}

	tc = (float)((end_tval.tv_sec - start_tval.tv_sec) * 1000000 +
		     end_tval.tv_usec - start_tval.tv_usec);

	dbg("%s end threadnum= %d, out_len=%ld\n",
	    __func__, thread_num, test_thrds_data[thread_num-1].dst_len);

	sz = fwrite(test_thrds_data[thread_num-1].dst, 1,
		    test_thrds_data[thread_num-1].dst_len, dest);

	if (op_type == WCRYPTO_DEFLATE) {
		speed = total_in / tc / 1024 / 1024 *
			1000 * 1000 * iteration,
		fprintf(stderr,
			"Compress threadnum= %d, speed=%0.3f MB/s, timedelay=%0.1f us\n",
			thread_num, speed, tc / thread_num / iteration);
	} else {
		speed = total_out / tc / 1024 / 1024 *
			1000 * 1000 * iteration,
		fprintf(stderr,
			"Decompress threadnum= %d, speed=%0.3f MB/s, timedelay=%0.1f us\n",
			thread_num, speed, tc / thread_num / iteration);
	}

all_buf_free:
	for (i = 0; i < thread_num; i++) {
		free(test_thrds_data[i].src);
		free(test_thrds_data[i].dst);
	}

	free(file_buf);

	return ret;

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
	int op_type = WCRYPTO_DEFLATE;
	int alg_type = WCRYPTO_GZIP;
	int mode = MODE_BLOCK;
	int thread_num = 1;
	int iteration = 1;
	int show_help = 0;
	int opt;

	while ((opt = getopt(argc, argv, "zgfw:dap:i:h")) != -1) {
		switch (opt) {
		case 'z':
			alg_type = WCRYPTO_ZLIB;
			break;
		case 'g':
			alg_type = WCRYPTO_GZIP;
			break;
		case 'f':
			alg_type = WCRYPTO_RAW_DEFLATE;
			break;
		case 'w':
			window_size = atoi(optarg);
			break;
		case 'd':
			op_type = WCRYPTO_INFLATE;
			break;
		case 'a':
			mode = MODE_ASYNC;
			break;
		case 'p':
			thread_num = atoi(optarg);
			if (thread_num > TEST_MAX_THRD)
				SYS_ERR_COND(1, "thread_num > 2048!\n");
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
		     "version 2.00:wd_test_zip -[g|z|f] [-w window size] -d -a [-p thread_num] [-i iteration] < in > out");

	hizip_thread_test(stdin, stdout, thread_num, alg_type,
			  op_type, mode, iteration);

	return EXIT_SUCCESS;
}
