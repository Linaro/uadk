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
#include <math.h>

#include "wd.h"
#include "hisi_qm_udrv.h"
#include "test_lib.h"


struct test_zip_pthread_dt {
	__u8 data_fmt;
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
	void *priv;
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
					pdata->data_fmt,
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
					pdata->data_fmt,
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
						   pdata->data_fmt,
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

	WD_ERR("%s start\n", __func__);

	do {
		count = 0;
		dbg("poll start, expt =%d , have =%d!\n",
		    pdata->iteration, totalcount);
		ret = wd_comp_poll(pdata->iteration, &count);
		if (ret < 0)
			WD_ERR("poll fail! thread_id=%d, tid=%d. ret:%d\n",
			       cpu_id, (int)tid, ret);
		if (count > 0)
			recnt = 0;
		totalcount += count;
		if (totalcount < pdata->iteration * pdata->thread_num) {
			usleep(100000);
			dbg("poll thread now no task, expt =%d , have =%d!\n",
			    pdata->iteration, totalcount);
			if (++recnt > MAX_POLL_COUNTS) {
				WD_ERR("poll thread  no task, 1s timeout, expt =%d , have =%d!\n", pdata->iteration * pdata->thread_num, totalcount);
				break;
			}
		}

	} while (totalcount < pdata->iteration * pdata->thread_num);

	WD_ERR("thread_id = %d, test poll end, count=%d\n",
	       pdata->cpu_id, totalcount);

	pdata->dst_len = out_len;

	return NULL;
}

static struct wd_datalist *get_datalist(void *addr, __u32 size)
{
	int count = (int)ceil((double)size / SGE_SIZE);
	struct wd_datalist *head, *cur, *tmp;
	int i;

	head = calloc(1, sizeof(struct wd_datalist));
	if (!head) {
		WD_ERR("failed to alloc datalist head\n");
		return NULL;
	}

	cur = head;

	for (i = 0; i < count; i++) {
		cur->data = addr;
		cur->len = (size > SGE_SIZE) ? SGE_SIZE : size;
		addr += SGE_SIZE;
		size -= SGE_SIZE;
		if (i != count - 1) {
			tmp = calloc(1, sizeof(struct wd_datalist));
			cur->next = tmp;
			cur = tmp;
		}
	}

	return head;
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
	struct wd_datalist *list;
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

	if (pdata->data_fmt) {
		WD_ERR("now sge size is %u\n", SGE_SIZE);
		list = get_datalist(pdata->src, pdata->src_len);
		req.list_src = list;
		list = get_datalist(pdata->dst, pdata->dst_len);
		req.list_dst = list;
	} else {
		req.src = pdata->src;
		req.dst = pdata->dst;
	}

	req.src_len = pdata->src_len;
	req.dst_len = pdata->dst_len;
	req.op_type = pdata->op_type;
	req.cb = (void *)zip_callback;
	req.cb_param = &u_param;
	req.data_fmt = pdata->data_fmt;
	req.priv = pdata->priv;

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
				WD_ERR("%s(): async test no cache,wait 10ms!\n",
				       __func__);
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
					      pdata->data_fmt, pdata->priv,
					      pdata->dst, &pdata->dst_len,
					      pdata->src, pdata->src_len);
			if (ret < 0)
				WD_ERR("comp fail! thread_id=%d, tid=%d\n",
				       cpu_id, (int)tid);
		} else if (pdata->op_type == WD_DIR_DECOMPRESS) {
			ret = hw_blk_decompress(pdata->alg_type, pdata->blksize,
					        pdata->data_fmt,
						pdata->dst, &pdata->dst_len,
						pdata->src, pdata->src_len);
			if (ret < 0)
				WD_ERR("decomp fail! thread_id=%d, tid=%d\n",
				       cpu_id, (int)tid);
		}
		if (verify) {
			ret = hw_blk_decompress(pdata->alg_type, pdata->blksize,
					        pdata->data_fmt,
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

struct seqdef {
	__u32 offset;
	__u16 litlen;
	__u16 matchlen;
};

static int write_zstd_file(struct wd_lz77_zstd_data *output_format,
			   __u8 data_fmt)
{
	struct wd_lz77_zstd_data *format = output_format;
	struct wd_datalist *sgl;
	int write_size = 0;
	FILE *fout;
	int ret;

	dbg("%s start!\n", __func__);

	fout = fopen("./zstd_lz77", "wb+");
	if (fout == NULL) {
		WD_ERR("file open failed\n");
		return -1;
	}

	dbg("%s overflow cnt is %d\n", __func__, format->lit_length_overflow_cnt);
	ret = fwrite(&format->lit_length_overflow_cnt, sizeof(__u32), 1, fout);
	write_size += ret * sizeof(__u32);

	dbg("%s overflow pos is %d\n", __func__, format->lit_length_overflow_pos);
	ret = fwrite(&format->lit_length_overflow_pos, sizeof(__u32), 1, fout);
	write_size += ret * sizeof(__u32);

	dbg("%s literals number is %d\n", __func__, format->lit_num);
	ret = fwrite(&format->lit_num, sizeof(__u32), 1, fout);
	write_size += ret * sizeof(__u32);

	if (data_fmt == WD_FLAT_BUF) {
		dbg("%s literals address is %p\n", __func__, format->literals_start);
		ret = fwrite(format->literals_start, sizeof(__u8), format->lit_num, fout);
		write_size += ret * sizeof(__u8);
	} else {
		sgl = format->literals_start;
		dbg("%s literals ori address is %p\n", __func__, sgl->data);
		ret = fwrite(sgl->data, sizeof(__u8), format->lit_num, fout);
		write_size += ret * sizeof(__u8);
	}

	dbg("%s sequences number is %d\n", __func__, format->seq_num);
	ret = fwrite(&format->seq_num, sizeof(__u32), 1, fout);
	write_size += ret * sizeof(__u32);

	if (data_fmt == WD_FLAT_BUF) {
		dbg("%s sequences address is %p\n", __func__, format->sequences_start);
		ret = fwrite(format->sequences_start, sizeof(__u64), format->seq_num, fout);
		write_size += ret * sizeof(__u64);
	} else {
		sgl = format->sequences_start;
		dbg("%s sequences ori address is %p\n", __func__, sgl->data);
		ret = fwrite(sgl->data, sizeof(__u64), format->seq_num, fout);
		write_size += ret * sizeof(__u8);
	}

	dbg("%s write size is %d\n", __func__, write_size);

	fclose(fout);

	dbg("%s succeed!\n", __func__);

	return write_size;
}

int comp_file_test(FILE *source, FILE *dest, struct test_options *opts)
{
	struct timeval start_tval, end_tval;
	int thread_num = opts->thread_num;
	struct hizip_test_info info = {0};
	struct wd_sched *sched = NULL;
	int mode = opts->sync_mode;
	__u64 src_len, dst_len, sz;
	float total_in = 0;
	float total_out = 0;
	void *file_buf;
	int count = 0;
	struct stat s;
	int i, j, ret;
	float tc = 0;
	float speed;
	int fd;

	fd = fileno(source);
	SYS_ERR_COND(fstat(fd, &s) < 0, "fstat");
	src_len = s.st_size;

	file_buf = calloc(1, src_len);

	sz = fread(file_buf, 1, src_len, source);
	if (sz != src_len)
		WD_ERR("read file sz != src_len!\n");

	count = src_len/block_size;
	if (!count)
		count = 1;

	dbg("%s entry blocksize=%d, count=%d, threadnum= %d, src_len=%d\n",
	    __func__, block_size, count, thread_num, src_len);

	info.list = get_dev_list(opts, 1);
	if (!info.list)
		return -EINVAL;

	ret = init_ctx_config(opts, &info, &sched);
	if (ret)
		goto out;

	dst_len = (ulong)src_len * 10;
	if (opts->block_size != 512000)
		dst_len = opts->block_size; /* just for user configure dest size test*/

	dst_len = dst_len > MAX_LEN ? MAX_LEN : dst_len;

	for (i = 0; i < thread_num; i++) {
		test_thrds_data[i].thread_num = thread_num;
		test_thrds_data[i].cpu_id = i;
		test_thrds_data[i].alg_type = opts->alg_type;
		test_thrds_data[i].op_type = opts->op_type;
		test_thrds_data[i].blksize = opts->block_size;
		test_thrds_data[i].iteration = opts->run_num;
		test_thrds_data[i].data_fmt = opts->data_fmt;
		test_thrds_data[i].src = file_buf;
		test_thrds_data[i].src_len = src_len;
		test_thrds_data[i].dst_len = dst_len;
		test_thrds_data[i].src = calloc(1, test_thrds_data[i].src_len);
		if (test_thrds_data[i].src == NULL)
			goto out_src;
		memcpy(test_thrds_data[i].src, file_buf, src_len);
		test_thrds_data[i].dst = calloc(1, test_thrds_data[i].dst_len);
		if (test_thrds_data[i].dst == NULL)
			goto out_dst;
		if (opts->alg_type == WD_LZ77_ZSTD)
			test_thrds_data[i].priv = calloc(1,
				sizeof(struct wd_lz77_zstd_data));
	}

	gettimeofday(&start_tval, NULL);

	for (i = 0; i < thread_num; i++) {
		if (mode == CTX_MODE_ASYNC)
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zip_sys_async_test_thread,
					     &test_thrds_data[i]);
		else if (opts->is_stream == MODE_STREAM)
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zlib_sys_stream_test_thread,
					     &test_thrds_data[i]);
		else
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zip_sys_block_test_thread,
					     &test_thrds_data[i]);
		if (ret) {
			WD_ERR("Create %dth thread fail!\n", i);
			goto out_thr;
		}
	}

	if (mode == CTX_MODE_ASYNC)
		ret = pthread_create(&system_test_poll_thrds, NULL,
				     zip_sys_async_test_poll_thread,
				     &test_thrds_data[0]);

	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			WD_ERR("Join %dth thread fail!\n", i);
			goto out_thr;
		}
	}

	if (mode == CTX_MODE_ASYNC) {
		ret = pthread_join(system_test_poll_thrds, NULL);
		if (ret) {
			WD_ERR("Join poll thread fail!\n");
			goto out_thr;
		}
	}

	gettimeofday(&end_tval, NULL);

	for (i = 0; i < thread_num; i++) {
		total_in += test_thrds_data[i].src_len;
		total_out += test_thrds_data[i].dst_len;
	}

	tc = (float)((end_tval.tv_sec-start_tval.tv_sec) * 1000000 +
		     end_tval.tv_usec - start_tval.tv_usec);
	dbg("%s end threadnum= %d, out_len=%u\n",
	    __func__, thread_num, test_thrds_data[thread_num-1].dst_len);


	if (opts->alg_type == WD_LZ77_ZSTD)
		sz = write_zstd_file(test_thrds_data[thread_num-1].priv,
				     opts->data_fmt);
	else if (mode == CTX_MODE_ASYNC)
		sz = fwrite(test_thrds_data[thread_num - 1].dst, 1,
			    out_len, dest);

	else
		sz = fwrite(test_thrds_data[thread_num - 1].dst, 1,
			    test_thrds_data[thread_num - 1].dst_len, dest);

	for (i = 0; i < thread_num; i++) {
		dbg("%s:free src[%d]:%p\n", __func__, i, test_thrds_data[i].src);

		free(test_thrds_data[i].src);

		dbg("%s:free dst[%d]:%p\n", __func__, i, test_thrds_data[i].dst);

		free(test_thrds_data[i].dst);
	}
	if (opts->op_type == WD_DIR_COMPRESS) {
		speed = total_in / tc /
			1024 / 1024 * 1000 * 1000 * opts->run_num,
		fprintf(stderr,
			"Compress bz=%d, threadnum= %d, speed=%0.3f MB/s, timedelay=%0.1f us\n",
			block_size, thread_num, speed,
			tc / thread_num / count / opts->run_num);
	} else {
		speed = total_out / tc /
			1024 / 1024 * 1000 * 1000 * opts->run_num,
		fprintf(stderr,
			"Decompress bz=%d, threadnum= %d, speed=%0.3f MB/s, timedelay=%0.1f us\n",
			block_size, thread_num, speed,
			tc / thread_num / count / opts->run_num);
	}

	wd_free_list_accels(info.list);
	free(file_buf);
	uninit_config(&info, sched);

	return 0;

out_thr:
	free(test_thrds_data[i].dst);
out_dst:
	free(test_thrds_data[i].src);

out_src:
	for (j = 0; j < i; j++) {
		free(test_thrds_data[i].src);
		free(test_thrds_data[i].dst);
	}

out:
	wd_free_list_accels(info.list);
	free(file_buf);

	return ret;
}
