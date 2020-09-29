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
#include <getopt.h>
#define __USE_GNU
#include <pthread.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../../drv/hisi_qm_udrv.h"
#include "../../wd.h"
#include "../../wd_bmm.h"
#include "../../wd_comp.h"
#include "../../wd_util.h"

typedef unsigned int u32;
typedef unsigned char u8;

enum mode {
	MODE_BLOCK,
	MODE_STREAM,
	MODE_ASYNC,
};

struct zip_test_pthread_dt {
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
	void *pool;
	struct wcrypto_comp_ctx *ctx;
	struct wcrypto_comp_op_data *opdata;
};

struct user_comp_tag_info {
	int alg_type;
	int op_type;
	int tag;
};

struct seq_def {
	__u32 offset;
	__u16 litlen;
	__u16 matlen;
};

#define HZIP_ZLIB_HEAD_SIZE		2
#define HZIP_GZIP_HEAD_SIZE		10

#define TEST_MAX_THRD			2048UL
#define MAX_CORES			128
#define DMEMSIZE			(1024 * 4)	/* 4K */

#define MAX(a, b)			((a) > (b) ? (a) : (b))
#define MIN(a, b)			((a) < (b) ? (a) : (b))

#define SYS_ERR_COND(cond, msg, ...) \
do { \
	if (cond) { \
		if (errno) \
			perror(msg); \
		else \
			fprintf(stderr, msg, ##__VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} \
} while (0)

static struct zip_test_pthread_dt test_thrds_data[TEST_MAX_THRD];
static pthread_t system_test_thrds[TEST_MAX_THRD];
static struct wd_queue q[TEST_MAX_THRD];

/* bytes of data for a request */
static int block_size = 1024 * 1024;
static int thread_num = 1;
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

static void zip_test_callback(const void *msg, void *tag)
{
	const struct wcrypto_comp_msg *respmsg = msg;
	const struct user_comp_tag_info *utag = tag;
	int i = utag->tag;
	struct zip_test_pthread_dt *pdata = &test_thrds_data[i];
	const u8 *head = TO_HEAD(pdata->alg_type);
	int head_size = 0;


	dbg("%s start!\n", __func__);

	pdata->dst_len = respmsg->produced;

	if (pdata->op_type == WCRYPTO_DEFLATE) {
		head_size = TO_HEAD_SIZE(pdata->alg_type);
		memcpy(pdata->dst, head, head_size);
		pdata->dst_len += head_size;
	}
	memcpy(pdata->dst + head_size,
	       pdata->opdata->out,
	       respmsg->produced);

	dbg("%s succeed!\n", __func__);
}

static void *zip_test_async_poll_thread(void *args)
{
	int *cnt = calloc(1, sizeof(int) * q_num);
	struct zip_test_pthread_dt *pdata = args;
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

static void *zip_test_async_thread(void *args)
{
	struct zip_test_pthread_dt *pdata = args;
	struct user_comp_tag_info *utag;
	int i = pdata->iteration;
	int ret;

	dbg("%s start!\n", __func__);

	utag = calloc(1, sizeof(struct user_comp_tag_info));
	utag->alg_type = pdata->alg_type;
	utag->op_type = pdata->op_type;
	utag->tag = pdata->thread_id;

	memcpy(pdata->opdata->in, pdata->src, pdata->src_len);
	pdata->opdata->in_len = pdata->src_len;
	pdata->opdata->avail_out = block_size;

	do {
		ret = wcrypto_do_comp(pdata->ctx, pdata->opdata, utag);
		if (ret == -WD_EBUSY)
			i++;
		else if (ret != 0)
			return NULL;
	} while (--i);

	dbg("%s succeed!\n", __func__);

	return NULL;
}

static void *zip_test_stream_thread(void *args)
{
	struct zip_test_pthread_dt *pdata = args;
	struct wcrypto_comp_op_data *opdata = pdata->opdata;
	unsigned char *src = pdata->src;
	unsigned char *dst = pdata->dst;
	unsigned char *ori = opdata->in;
	int alg_type = pdata->alg_type;
	const u8 *head = TO_HEAD(alg_type);
	int srclen = pdata->src_len;
	int head_size = 0;
	int ret, have;

	dbg("%s start!\n", __func__);

	pdata->dst_len = 0;

	if (pdata->op_type == WCRYPTO_DEFLATE) {
		head_size = TO_HEAD_SIZE(alg_type);
		memcpy(dst, head, head_size);
		pdata->dst_len += head_size;
		dst += head_size;
	}

	do {
		opdata->in = ori;
		if (srclen > block_size) {
			memcpy(pdata->opdata->in, src, block_size);
			opdata->in_len = block_size;
			src += block_size;
			srclen -= block_size;
		} else {
			memcpy(pdata->opdata->in, src, srclen);
			opdata->in_len = srclen;
			srclen = 0;
		}
		opdata->flush = srclen ? WCRYPTO_SYNC_FLUSH : WCRYPTO_FINISH;
		do {
			opdata->avail_out = block_size;
			ret = wcrypto_do_comp(pdata->ctx, opdata, NULL);
			if (ret) {
				WD_ERR("%s failed to do request! ret = %d\n",
				       __func__, ret);
				return NULL;
			}

			opdata->stream_pos = WCRYPTO_COMP_STREAM_OLD;
			have = opdata->produced;
			memcpy(dst, opdata->out, have);
			dst += have;
			pdata->dst_len += have;
			opdata->in_len -= opdata->consumed;
			if (opdata->in_len) {
				dbg("%s avail out no enough!\n", __func__);
				opdata->in += opdata->consumed;
			}
		} while (opdata->in_len > 0);
	} while (srclen);

	dbg("%s succeed!\n", __func__);

	return NULL;
}

static void *zip_test_block_thread(void *args)
{
	struct zip_test_pthread_dt *pdata = args;
	int alg_type = pdata->alg_type;
	const u8 *head = TO_HEAD(alg_type);
	int i = pdata->iteration;
	int head_size = 0;
	int ret;

	dbg("%s start!\n", __func__);

	memcpy(pdata->opdata->in, pdata->src, pdata->src_len);
	pdata->opdata->in_len = pdata->src_len;
	pdata->opdata->avail_out = block_size;

	do {
		ret = wcrypto_do_comp(pdata->ctx, pdata->opdata, NULL);
		if (ret) {
			WD_ERR("%s failed to do request! ret = %d\n",
			       __func__, ret);
			return NULL;
		}

		pdata->dst_len = pdata->opdata->produced;

		if (pdata->op_type == WCRYPTO_DEFLATE) {
			head_size = TO_HEAD_SIZE(alg_type);
			memcpy(pdata->dst, head, head_size);
			pdata->dst_len += head_size;
		}
		memcpy(pdata->dst + head_size,
		       pdata->opdata->out,
		       pdata->opdata->produced);

	} while (--i);

	dbg("%s succeed!\n", __func__);

	return NULL;
}

static void zip_test_release_q(int n)
{
	int i;

	dbg("%s start!\n", __func__);

	for (i = 0; i < n; i++)
		wd_release_queue(&q[i]);

	dbg("%s succeed!\n", __func__);
}

static int zip_test_request_q(int alg_type, int op_type)
{
	struct wcrypto_paras *priv;
	int ret = 0;
	int i;

	dbg("%s start!\n", __func__);

	q_num = thread_num;

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
		case WCRYPTO_LZ77_ZSTD:
			q[i].capa.alg = "lz77_zstd";
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
			WD_ERR("%s request %dth q fail, ret =%d\n",
			       __func__, i, ret);
			zip_test_release_q(i);
		}
	}

	dbg("%s succeed!\n", __func__);

	return ret;
}

static int zip_test_create_ctx(int alg_type, int window_size,
			       int op_type,  int mode)
{
	struct wcrypto_comp_ctx_setup ctx_setup = { 0 };
	struct wd_blkpool_setup blk_setup = { 0 };
	struct zip_test_pthread_dt *pdata;
	int i, j, ret;

	dbg("%s start!\n", __func__);

	block_size = MAX(block_size, DMEMSIZE);
	blk_setup.block_size = block_size;
	blk_setup.block_num = 3;
	blk_setup.align_size = 128;

	ctx_setup.br.alloc = (void *)wd_alloc_blk;
	ctx_setup.br.free = (void *)wd_free_blk;
	ctx_setup.br.iova_map = (void *)wd_blk_iova_map;
	ctx_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
	ctx_setup.br.get_bufsize = (void *)wd_blksize;
	ctx_setup.alg_type = alg_type;
	ctx_setup.op_type = op_type;
	ctx_setup.stream_mode = (mode == MODE_STREAM) ?
				 WCRYPTO_COMP_STATEFUL :
				 WCRYPTO_COMP_STATELESS;
	ctx_setup.cb = (mode == MODE_ASYNC) ? zip_test_callback : NULL;
	ctx_setup.win_size = window_size;

	for (i = 0; i < thread_num; i++) {
		pdata = &test_thrds_data[i];

		pdata->pool = wd_blkpool_create(&q[i], &blk_setup);
		if (!pdata->pool) {
			ret = -ENOMEM;
			WD_ERR("%s create %dth pool fail!\n", __func__, i);
			goto err_pool_destory;
		}

		ctx_setup.br.usr = pdata->pool;
		pdata->ctx = wcrypto_create_comp_ctx(&q[i], &ctx_setup);
		if (!pdata->ctx)  {
			ret = -ENOMEM;
			WD_ERR("%s create %dth ctx fail!\n", __func__, i);
			goto err_ctx_delete;
		}

		pdata->opdata = calloc(1, sizeof(*pdata->opdata));
		if (!pdata->opdata) {
			ret = -ENOMEM;
			WD_ERR("%s alloc %dth opdata fail!\n", __func__, i);
			goto err_opdata_free;
		}

		pdata->opdata->alg_type = alg_type;
		pdata->opdata->avail_out = block_size;
		pdata->opdata->stream_pos = WCRYPTO_COMP_STREAM_NEW;
		pdata->opdata->in = wd_alloc_blk(pdata->pool);
		pdata->opdata->out = wd_alloc_blk(pdata->pool);
		if (pdata->opdata->in == NULL || pdata->opdata->out == NULL) {
			ret = -ENOMEM;
			WD_ERR("%s not enough data memory for cache (bs=%d)\n",
			       __func__, block_size);
			goto err_buffer_free;
		}

		if (pdata->alg_type == WCRYPTO_LZ77_ZSTD) {
			pdata->opdata->priv = calloc(1, sizeof(struct wcrypto_lz77_zstd_format));
			if (pdata->opdata->priv == NULL) {
				WD_ERR("%s alloc %d format fail!\n", __func__, i);
				goto err_format_free;
			}
		}
	}

	dbg("%s succeed!\n", __func__);

	return 0;

err_format_free:
	wd_free_blk(test_thrds_data[i].pool,
		    test_thrds_data[i].opdata->in);
	wd_free_blk(test_thrds_data[i].pool,
		    test_thrds_data[i].opdata->out);

err_buffer_free:
	free(test_thrds_data[i].opdata);

err_opdata_free:
	wcrypto_del_comp_ctx(test_thrds_data[i].ctx);

err_ctx_delete:
	wd_blkpool_destroy(test_thrds_data[i].pool);

err_pool_destory:
	for (j = 0; j < i; j++) {
		wd_free_blk(test_thrds_data[j].pool,
			    test_thrds_data[j].opdata->in);
		wd_free_blk(test_thrds_data[j].pool,
			    test_thrds_data[j].opdata->out);
		wcrypto_del_comp_ctx(test_thrds_data[j].ctx);
		wd_blkpool_destroy(test_thrds_data[j].pool);
		free(test_thrds_data[j].opdata);
	}

	return ret;
}

static int zip_test_init(int alg_type, int window_size, int op_type, int mode)
{
	int ret;

	dbg("%s start!\n", __func__);

	ret = zip_test_request_q(alg_type, op_type);
	if (ret) {
		WD_ERR("%s request q failed!\n", __func__);
		return ret;
	}

	ret = zip_test_create_ctx(alg_type, window_size, op_type, mode);
	if (ret) {
		WD_ERR("%s create ctx failed!\n", __func__);
		zip_test_release_q(q_num);
	}

	dbg("%s succeed!\n", __func__);

	return ret;
}

static void zip_test_exit(void)
{
	int i;

	for (i = 0; i < thread_num; i++) {
		wd_free_blk(test_thrds_data[i].pool,
			    test_thrds_data[i].opdata->in);
		wd_free_blk(test_thrds_data[i].pool,
			    test_thrds_data[i].opdata->out);
		if (test_thrds_data[i].alg_type == WCRYPTO_LZ77_ZSTD)
			free(test_thrds_data[i].opdata->priv);
		wcrypto_del_comp_ctx(test_thrds_data[i].ctx);
		wd_blkpool_destroy(test_thrds_data[i].pool);
		free(test_thrds_data[i].opdata);
	}

	zip_test_release_q(q_num);
}

static void dump_lz77_zstd_format(struct wcrypto_lz77_zstd_format *format)
{
#ifdef DEBUG_LOG

	struct seq_def *seq;
	int i;

	dbg("%s start!\n", __func__);

	dbg("%s literals number: %u\n", __func__, format->lit_num);

	dbg("%s literals: ", __func__);
	for (i = 0; i < format->lit_num; i++) {
		dbg("%hhx", *(__u8 *)(format->literals_start + i));
	}
	dbg("\n");

	dbg("%s sequences number: %u\n", __func__, format->seq_num);
	seq = format->sequences_start;
	dbg("%s sequences: \n", __func__);
	for (i = 0; i < format->seq_num; i++) {
		dbg("sequence[%d]: offset %u, litlen %hu, matlen %hu\n", i,
		    seq[i].offset, seq[i].litlen, seq[i].matlen);
	}

	dbg("%s succeed!\n", __func__);

#endif
}

static int write_zstd_file(struct wcrypto_lz77_zstd_format *output_format)
{
	struct wcrypto_lz77_zstd_format *format = output_format;
	int write_size = 0;
	FILE *fout;
	int ret;

	dbg("%s start!\n", __func__);

	dump_lz77_zstd_format(format);
	fout = fopen("./zstd_lz77", "wb+");
	if (fout == NULL) {
		WD_ERR("file open failed\n");
		return -1;
	}

	ret = fwrite(&format->lit_num, sizeof(__u32), 1, fout);
	write_size += ret * sizeof(__u32);

	ret = fwrite(format->literals_start, sizeof(__u8), format->lit_num, fout);
	write_size += ret * sizeof(__u8);

	ret = fwrite(&format->seq_num, sizeof(__u32), 1, fout);
	write_size += ret * sizeof(__u32);

	ret = fwrite(format->sequences_start, sizeof(__u64), format->seq_num, fout);
	write_size += ret * sizeof(__u64);

	dbg("write size is %d\n", write_size);

	fclose(fout);

	dbg("%s succeed!\n", __func__);

	return write_size;
}

static int hizip_thread_test(FILE *source, FILE *dest, int alg_type, int mode,
			     int op_type, int window_size, int iteration)
{
	struct timeval start_tval, end_tval;
	struct zip_test_pthread_dt *pdata;
	int in_len, sz, fd;
	float total_in = 0;
	float total_out = 0;
	int head_size = 0;
	void *file_buf;
	struct stat s;
	int i, j, ret;
	float tc = 0;
	float speed;

	fd = fileno(source);
	SYS_ERR_COND(fstat(fd, &s) < 0, "%s fstat error!\n", __func__);
	in_len = s.st_size;
	SYS_ERR_COND(!in_len, "%s input file length zero!\n", __func__);

	file_buf = calloc(1, in_len);

	sz = fread(file_buf, 1, in_len, source);
	if (sz != in_len)
		WD_ERR("%s read file sz != in_len!\n", __func__);

	if (op_type == WCRYPTO_INFLATE)
		head_size = TO_HEAD_SIZE(alg_type);

	dbg("%s entry threadnum= %d, in_len=%d\n",
	    __func__, thread_num, in_len);

	for (i = 0; i < thread_num; i++) {
		pdata = &test_thrds_data[i];
		pdata->thread_id = i;
		pdata->thread_num = thread_num;
		pdata->alg_type = alg_type;
		pdata->op_type = op_type;
		pdata->iteration = iteration;
		pdata->src = file_buf;
		pdata->src_len = in_len - head_size;
		pdata->dst_len = pdata->src_len * 10;
		pdata->src = calloc(1, pdata->src_len);
		if (pdata->src == NULL)
			goto buf_free;
		memcpy(pdata->src, (unsigned char *)file_buf + head_size,
		       pdata->src_len);
		pdata->dst = calloc(1, pdata->dst_len);
		if (pdata->dst == NULL)
			goto src_buf_free;
	}

	ret = zip_test_init(alg_type, window_size, op_type, mode);
	if (ret) {
		WD_ERR("%s init fail!\n", __func__);
		goto all_buf_free;
	}

	gettimeofday(&start_tval, NULL);
	for (i = 0; i < thread_num; i++) {
		if (mode == MODE_ASYNC)
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zip_test_async_thread,
					     &test_thrds_data[i]);
		else if (mode == MODE_STREAM)
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zip_test_stream_thread,
					     &test_thrds_data[i]);
		else
			ret = pthread_create(&system_test_thrds[i], NULL,
					     zip_test_block_thread,
					     &test_thrds_data[i]);
		if (ret) {
			WD_ERR("%s create %dth thread fail!\n", __func__, i);
			goto all_buf_free;
		}
	}

	if (mode == MODE_ASYNC) {
		ret = pthread_create(&system_test_thrds[thread_num], NULL,
				     zip_test_async_poll_thread,
				     &test_thrds_data[0]);
		if (ret) {
			WD_ERR("%s create poll thread fail!\n", __func__);
			goto all_buf_free;
		}
	}

	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			WD_ERR("%s join %dth thread fail!\n", __func__, i);
			goto all_buf_free;
		}
	}

	if (mode == MODE_ASYNC) {
		ret = pthread_join(system_test_thrds[thread_num], NULL);
		if (ret) {
			WD_ERR("%s join poll thread fail!\n", __func__);
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

	if (alg_type == WCRYPTO_LZ77_ZSTD)
		sz = write_zstd_file(test_thrds_data[thread_num-1].opdata->priv);
	else
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

	zip_test_exit();

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

	WD_ERR("%s thread malloc fail!ENOMEM!\n", __func__);

	return -ENOMEM;
}

int main(int argc, char *argv[])
{
	int window_size = WCRYPTO_COMP_WS_8K;
	int op_type = WCRYPTO_DEFLATE;
	int alg_type = WCRYPTO_GZIP;
	int mode = MODE_BLOCK;
	int iteration = 1;
	int show_help = 0;
	int opt;

	while ((opt = getopt(argc, argv, "zgflw:dasb:t:i:h")) != -1) {
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
		case 'l':
			alg_type = WCRYPTO_LZ77_ZSTD;
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
		case 's':
			mode = MODE_STREAM;
			break;
		case 'b':
			block_size = atoi(optarg);
			break;
		case 't':
			thread_num = atoi(optarg);
			if (thread_num > TEST_MAX_THRD)
				SYS_ERR_COND(1, "thread_num > 2048!\n");
			else if (!thread_num)
				SYS_ERR_COND(1, "thread_num can't be 0!\n");
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
		     "version 3.00:wd_test_zip -[g|z|f|l algorithm] "
		     "[-w window size] [-d decompress] [-b block size] "
		     "-[a|s mode] [-t thread num] [-i iteration] < in > out\n");

	hizip_thread_test(stdin, stdout, alg_type, mode, op_type, window_size,
			  iteration);

	return EXIT_SUCCESS;
}
