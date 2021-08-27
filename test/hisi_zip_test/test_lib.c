// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#include <pthread.h>
#include <signal.h>
#include <math.h>
#include <sys/mman.h>
#include <zlib.h>

#include "hisi_qm_udrv.h"
#include "wd_sched.h"
#include "test_lib.h"

#define SCHED_RR_NAME	"sched_rr"

struct check_rand_ctx {
	int off;
	unsigned long global_off;
	__u32 last;
	unsigned short state[3];
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_spinlock_t lock;
static int count = 0;

static struct wd_ctx_config *g_conf;

int sum_pend = 0, sum_thread_end = 0;

__attribute__((constructor))
void lock_constructor(void)
{
	if (pthread_spin_init(&lock, PTHREAD_PROCESS_SHARED) != 0)
		exit(1);
}

__attribute__((destructor))
void lock_destructor(void)
{
	if (pthread_spin_destroy(&lock) != 0)
		exit(1);
}

void *mmap_alloc(size_t len)
{
	void *p;
	long page_size = sysconf(_SC_PAGESIZE);

	if (len % page_size)
		return malloc(len);

	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
		 -1, 0);
	if (p == MAP_FAILED)
		WD_ERR("Failed to allocate %zu bytes\n", len);

	return p == MAP_FAILED ? NULL : p;
}

int mmap_free(void *addr, size_t len)
{
	long page_size = sysconf(_SC_PAGESIZE);

	if (len % page_size) {
		free(addr);
		return 0;
	}

	return munmap(addr, len);
}

static int hizip_check_rand(unsigned char *buf, unsigned int size, void *opaque)
{
	int i;
	int *j;
	__u32 n;
	struct check_rand_ctx *rand_ctx = opaque;

	j = &rand_ctx->off;
	for (i = 0; i < size; i += 4) {
		if (*j) {
			/* Something left from a previous run */
			n = rand_ctx->last;
		} else {
			n = nrand48(rand_ctx->state);
			rand_ctx->last = n;
		}
		for (; *j < 4 && i + *j < size; (*j)++) {
			char expected = (n >> (8 * *j)) & 0xff;
			char actual = buf[i + *j];

			if (expected != actual) {
				WD_ERR("Invalid decompressed char at offset %lu: expected 0x%x != 0x%x\n",
				       rand_ctx->global_off + i + *j, expected,
				       actual);
				return -EINVAL;
			}
		}
		if (*j == 4)
			*j = 0;
	}
	rand_ctx->global_off += size;
	return 0;
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

/**
 * compress() - compress memory buffer.
 * @alg_type: alg_type.
 *
 * This function compress memory buffer.
 */
int hw_blk_compress(int alg_type, int blksize, __u8 data_fmt, void *priv,
		    unsigned char *dst, __u32 *dstlen,
		    unsigned char *src, __u32 srclen)
{
	handle_t h_sess;
	struct wd_comp_sess_setup setup;
	struct wd_datalist *list;
	struct wd_comp_req req;
	int ret = 0;

	setup.alg_type = alg_type;
	setup.op_type = WD_DIR_COMPRESS;
	setup.numa = 0;
	h_sess = wd_comp_alloc_sess(&setup);
	if (!h_sess) {
		fprintf(stderr,"fail to alloc comp sess!\n");
		return -EINVAL;
	}

	if (data_fmt) {
		WD_ERR("now sge size is %u\n", SGE_SIZE);
		list = get_datalist(src, (__u32)srclen);
		req.list_src = list;
		list = get_datalist(dst, (__u32)*dstlen);
		req.list_dst = list;
	} else {
		req.src = src;
		req.dst = dst;
	}

	req.src_len = srclen;
	req.dst_len = *dstlen;
	req.op_type = WD_DIR_COMPRESS;
	req.cb = NULL;
	req.data_fmt = data_fmt;
	req.priv = priv;
	req.win_sz = WD_COMP_WS_32K;
	req.comp_lv = WD_COMP_L8;

	dbg("%s:input req: src_len: %d, dst_len:%d, data_fmt:%d\n",
	    __func__, req.src_len, req.dst_len, req.data_fmt);

	ret = wd_do_comp_sync(h_sess, &req);
	if (ret < 0) {
		fprintf(stderr,"fail to do comp sync(ret = %d)!\n", ret);
		return ret;
	}

	if (req.status) {
		fprintf(stderr,"fail to do comp sync(status = %d)!\n",
		req.status);
		wd_comp_free_sess(h_sess);
		return req.status;
	}
	*dstlen = req.dst_len;

	dbg("%s:input req: src_len: %d, dst_len:%d, data_fmt:%d\n",
	    __func__, req.src_len, req.dst_len, req.data_fmt);

	wd_comp_free_sess(h_sess);

	return ret;
}

int hw_blk_decompress(int alg_type, int blksize, __u8 data_fmt,
		      unsigned char *dst, __u32 *dstlen,
		      unsigned char *src, __u32 srclen)
{
	handle_t h_sess;
	struct wd_comp_sess_setup setup;
	struct wd_datalist *list;
	struct wd_comp_req req;
	int ret = 0;

	setup.alg_type = alg_type;
	setup.op_type = WD_DIR_DECOMPRESS;
	setup.numa = 0;
	h_sess = wd_comp_alloc_sess(&setup);
	if (!h_sess) {
		fprintf(stderr,"fail to alloc comp sess!\n");
		return -EINVAL;
	}

	if (data_fmt) {
		WD_ERR("now sge size is %u\n", SGE_SIZE);
		list = get_datalist(src, (__u32)srclen);
		req.list_src = list;
		list = get_datalist(dst, (__u32)*dstlen);
		req.list_dst = list;
	} else {
		req.src = src;
		req.dst = dst;
	}

	req.src_len = srclen;
	req.dst_len = *dstlen;
	req.op_type = WD_DIR_DECOMPRESS;
	req.cb = NULL;
	req.data_fmt = data_fmt;

	dbg("%s:input req: src:%p, dst:%p,src_len: %d, dst_len:%d\n",
	    __func__, req.src, req.dst, req.src_len, req.dst_len);


	ret = wd_do_comp_sync(h_sess, &req);
	if (ret < 0) {
		fprintf(stderr,"fail to do comp sync(ret = %d)!\n", ret);
		return ret;
	}

	if (req.status) {
		fprintf(stderr,"fail to do comp sync(status = %d)!\n",
		req.status);
		wd_comp_free_sess(h_sess);
		return req.status;
	}
	*dstlen = req.dst_len;

	dbg("%s:output req: src:%p, dst:%p,src_len: %d, dst_len:%d\n",
	    __func__, req.src, req.dst, req.src_len, req.dst_len);

	wd_comp_free_sess(h_sess);

	return ret;
}

int hw_stream_compress(int alg_type, int blksize, __u8 data_fmt,
		       unsigned char *dst, __u32 *dstlen,
		       unsigned char *src, __u32 srclen)
{
	handle_t h_sess;
	struct wd_comp_sess_setup setup;
	struct wd_comp_req req;
	int ret = 0;

	setup.alg_type = alg_type;
	setup.op_type = WD_DIR_COMPRESS;
	setup.numa = 0;
	h_sess = wd_comp_alloc_sess(&setup);
	if (!h_sess) {
		fprintf(stderr,"fail to alloc comp sess!\n");
		return -EINVAL;
	}
	req.src = src;
	req.src_len = srclen;
	req.dst = dst;
	req.dst_len = *dstlen;
	req.op_type = WD_DIR_COMPRESS;
	req.cb = NULL;
	req.data_fmt = data_fmt;
	req.win_sz = WD_COMP_WS_32K;
	req.comp_lv = WD_COMP_L8;

	dbg("%s:input req: src:%p, dst:%p,src_len: %d, dst_len:%d\n",
	    __func__, req.src, req.dst, req.src_len, req.dst_len);

	ret = wd_do_comp_sync2(h_sess, &req);
	if (ret < 0) {
		fprintf(stderr,"fail to do comp sync(ret = %d)!\n", ret);
		return ret;
	}

	if (req.status) {
		fprintf(stderr,"fail to do comp sync(status = %d)!\n",
		req.status);
		wd_comp_free_sess(h_sess);
		return req.status;
	}
	*dstlen = req.dst_len;

	dbg("%s:output req: src:%p, dst:%p,src_len: %d, dst_len:%d\n",
	    __func__, req.src, req.dst, req.src_len, req.dst_len);

	wd_comp_free_sess(h_sess);

	return ret;
}


int hw_stream_decompress(int alg_type, int blksize, __u8 data_fmt,
		       unsigned char *dst, __u32 *dstlen,
		       unsigned char *src, __u32 srclen)
{
	handle_t h_sess;
	struct wd_comp_sess_setup setup;
	struct wd_comp_req req;
	int ret = 0;


	setup.alg_type = alg_type;
	setup.op_type = WD_DIR_DECOMPRESS;
	setup.numa = 0;
	h_sess = wd_comp_alloc_sess(&setup);
	if (!h_sess) {
		fprintf(stderr,"fail to alloc comp sess!\n");
		return -EINVAL;
	}
	req.src = src;
	req.src_len = srclen;
	req.dst = dst;
	req.dst_len = *dstlen;
	req.op_type = WD_DIR_DECOMPRESS;
	req.cb = NULL;
	req.data_fmt = data_fmt;

	dbg("%s:input req: src:%p, dst:%p,src_len: %d, dst_len:%d\n",
	    __func__, req.src, req.dst, req.src_len, req.dst_len);


	ret = wd_do_comp_sync2(h_sess, &req);
	if (ret < 0) {
		fprintf(stderr,"fail to do comp sync(ret = %d)!\n", ret);
		return ret;
	}

	if (req.status) {
		fprintf(stderr,"fail to do comp sync(status = %d)!\n",
		req.status);
		wd_comp_free_sess(h_sess);
		return req.status;
	}
	*dstlen = req.dst_len;

	dbg("%s:output req: src:%p, dst:%p,src_len: %d, dst_len:%d\n",
	    __func__, req.src, req.dst, req.src_len, req.dst_len);

	wd_comp_free_sess(h_sess);

	return ret;
}

void hizip_prepare_random_input_data(char *buf, size_t len, size_t block_size)
{
	__u32 seed = 0;
	unsigned short rand_state[3] = {(seed >> 16) & 0xffff, seed & 0xffff, 0x330e};

	unsigned long remain_size;
	__u32 size;
	size_t i, j;

	/*
	 * TODO: change state for each buffer, to make sure there is no TLB
	 * aliasing.
	 */
	remain_size = len;

	while (remain_size > 0) {
		if (remain_size > block_size)
			size = block_size;
		else
			size = remain_size;
		/*
		 * Prepare the input buffer with a reproducible sequence of
		 * numbers. nrand48() returns a pseudo-random number in the
		 * interval [0; 2^31). It's not really possible to compress a
		 * pseudo-random stream using deflate, since it can't find any
		 * string repetition. As a result the output size is bigger,
		 * with a ratio of 1.041.
		 */
		for (i = 0; i < size; i += 4) {
			__u64 n = nrand48(rand_state);

			for (j = 0; j < 4 && i + j < size; j++)
				buf[i + j] = (n >> (8 * j)) & 0xff;
		}

		buf += size;
		remain_size -= size;
	}
}

int hizip_prepare_random_compressed_data(char *buf, size_t out_len, size_t in_len,
					 size_t *produced,
					 struct test_options *opts)
{
	off_t off;
	int ret = -EINVAL;
	void *init_buf = mmap_alloc(in_len);
	size_t in_block_size = opts->block_size;
	size_t out_block_size = 2 * in_block_size;

	if (!init_buf)
		return -ENOMEM;

	hizip_prepare_random_input_data(init_buf, in_len, opts->block_size);

	/* Compress each chunk separately since we're working in stateless mode */
	for (off = 0; off < in_len; off += in_block_size) {
		ret = zlib_deflate(buf, out_block_size, init_buf + off,
				   in_block_size, produced, opts->alg_type);
		if (ret)
			break;
		buf += out_block_size;
	}

	munmap(init_buf, in_len);
	return ret;
}

int hizip_verify_random_output(struct test_options *opts,
			       struct hizip_test_info *info,
			       size_t out_sz)
{
	int ret;
	int seed = 0;
	off_t off = 0;
	size_t checked = 0;
	size_t total_checked = 0;
	struct check_rand_ctx rand_ctx = {
		.state = {(seed >> 16) & 0xffff, seed & 0xffff, 0x330e},
	};

	if (!opts->verify)
		return 0;

	if (opts->op_type == WD_DIR_DECOMPRESS)
		/* Check plain output */
		return hizip_check_rand((void *)info->out_buf, out_sz,
					&rand_ctx);

	do {
		ret = hizip_check_output(info->out_buf + off, out_sz,
					 &checked, hizip_check_rand, &rand_ctx);
		if (ret) {
			WD_ERR("Check output failed with %d\n", ret);
			return ret;
		}
		total_checked += checked;
		off += opts->block_size * EXPANSION_RATIO;
	} while (!ret && total_checked < opts->total_len);

	if (rand_ctx.global_off != opts->total_len) {
		WD_ERR("Invalid output size %lu != %lu\n",
		       rand_ctx.global_off, opts->total_len);
		return -EINVAL;
	}
	return 0;
}

static void *async_cb(struct wd_comp_req *req, void *data)
{
	return NULL;
}

void *send_thread_func(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	size_t src_block_size, dst_block_size;
	struct wd_comp_sess_setup setup;
	handle_t h_sess;
	int j, ret;
	size_t left;

	if (opts->op_type == WD_DIR_COMPRESS) {
		src_block_size = opts->block_size;
		dst_block_size = opts->block_size * EXPANSION_RATIO;
	} else {
		src_block_size = opts->block_size * EXPANSION_RATIO;
		dst_block_size = opts->block_size;
	}

	memset(&setup, 0, sizeof(struct wd_comp_sess_setup));
	setup.alg_type = opts->alg_type;
	setup.op_type = opts->op_type;
	setup.numa = 0;
	h_sess = wd_comp_alloc_sess(&setup);
	if (!h_sess)
		return NULL;

	for (j = 0; j < opts->compact_run_num; j++) {
		if (opts->option & TEST_ZLIB) {
			ret = zlib_deflate(info->out_buf, info->out_size,
					   info->in_buf, info->in_size,
					   &tdata->sum, opts->alg_type);
			continue;
		}
		/* not TEST_ZLIB */
		left = opts->total_len;
		tdata->req.op_type = opts->op_type;
		tdata->req.src = info->in_buf;
		tdata->req.dst = info->out_buf;
		tdata->sum = 0;
		tdata->req.win_sz = WD_COMP_WS_32K;
		tdata->req.comp_lv = WD_COMP_L8;
		while (left > 0) {
			tdata->req.src_len = src_block_size;
			tdata->req.dst_len = dst_block_size;
			tdata->req.cb_param = &tdata->req;
			if (opts->sync_mode) {
				tdata->req.cb = async_cb;
				count++;
				ret = wd_do_comp_async(h_sess, &tdata->req);
			} else {
				tdata->req.cb = NULL;
				ret = wd_do_comp_sync(h_sess, &tdata->req);
				if (info->opts->faults & INJECT_SIG_WORK)
					kill(getpid(), SIGTERM);
			}
			if (ret < 0) {
				WD_ERR("do comp test fail with %d\n", ret);
				return (void *)(uintptr_t)ret;
			} else if (tdata->req.status) {
				return (void *)(uintptr_t)tdata->req.status;
			}
			if (opts->op_type == WD_DIR_COMPRESS)
				left -= src_block_size;
			else
				left -= dst_block_size;
			tdata->req.src += src_block_size;
			/*
			 * It's BLOCK (STATELESS) mode, so user needs to
			 * combine output buffer by himself.
			 */
			tdata->req.dst += dst_block_size;
			tdata->sum += tdata->req.dst_len;
			if (tdata->sum > info->out_size) {
				fprintf(stderr,
					"%s: exceed OUT limits (%ld > %ld)\n",
					__func__,
					tdata->sum, info->out_size);
				break;
			}
		}
		/* info->total_out are accessed by multiple threads */
		__atomic_add_fetch(&info->total_out, tdata->sum,
				   __ATOMIC_RELEASE);
	}
	wd_comp_free_sess(h_sess);
	return NULL;
}

int lib_poll_func(__u32 pos, __u32 expect, __u32 *count)
{
	int ret;

	ret = wd_comp_poll_ctx(pos, expect, count);
	if (ret < 0)
		return ret;
	return 0;
}

void *poll_thread_func(void *arg)
{
	struct hizip_test_info *info = (struct hizip_test_info *)arg;
	int ret = 0, total = 0;
	__u32 expected = 0, received;

	if (!info->opts->sync_mode)
		return NULL;
	while (1) {
		if (info->opts->faults & INJECT_SIG_WORK)
			kill(getpid(), SIGTERM);

		pthread_mutex_lock(&mutex);
		if (!expected)
			expected = 1;
		if (count == 0) {
			pthread_mutex_unlock(&mutex);
			usleep(10);
			continue;
		}
		expected = 1;
		received = 0;
		ret = wd_comp_poll(expected, &received);
		if (ret == 0)
			total += received;
		if (count == total) {
			pthread_mutex_unlock(&mutex);
			break;
		} else {
			if (count > total)
				expected = count - total;
			pthread_mutex_unlock(&mutex);
			usleep(10);
		}
	}
	pthread_exit(NULL);
}

int create_send_threads(struct test_options *opts,
			struct hizip_test_info *info,
			void *(*send_thread_func)(void *arg))
{
	pthread_attr_t attr;
	thread_data_t *tdatas;
	int i, j, num, ret;

	num = opts->thread_num;
	info->send_tds = calloc(1, sizeof(pthread_t) * num);
	if (!info->send_tds)
		return -ENOMEM;
	info->send_tnum = num;
	tdatas = calloc(1, sizeof(thread_data_t) * num);
	if (!tdatas) {
		ret = -ENOMEM;
		goto out;
	}
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	for (i = 0; i < num; i++) {
		tdatas[i].info = info;
		ret = pthread_create(&info->send_tds[i], &attr,
				     send_thread_func, &tdatas[i]);
		if (ret < 0) {
			fprintf(stderr, "Fail to create send thread %d (%d)\n",
				i, ret);
			goto out_thd;
		}
	}
	pthread_attr_destroy(&attr);
	g_conf = &info->ctx_conf;
	return 0;
out_thd:
	for (j = 0; j < i; j++)
		pthread_cancel(info->send_tds[j]);
	free(tdatas);
out:
	free(info->send_tds);
	return ret;
}

int create_poll_threads(struct hizip_test_info *info,
			void *(*poll_thread_func)(void *arg),
			int num)
{
	struct test_options *opts = info->opts;
	pthread_attr_t attr;
	int i, ret;

	if (!opts->sync_mode)
		return 0;
	info->poll_tds = calloc(1, sizeof(pthread_t) * num);
	if (!info->poll_tds)
		return -ENOMEM;
	info->poll_tnum = num;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	for (i = 0; i < num; i++) {
		ret = pthread_create(&info->poll_tds[i], &attr,
				     poll_thread_func, info);
		if (ret < 0) {
			fprintf(stderr, "Fail to create send thread %d (%d)\n",
				i, ret);
			goto out;
		}
	}
	pthread_attr_destroy(&attr);
	count = 0;
	return 0;
out:
	free(info->poll_tds);
	return ret;
}

void free_threads(struct hizip_test_info *info)
{
	if (info->send_tds)
		free(info->send_tds);
	if (info->poll_tds)
		free(info->poll_tds);
}

int attach_threads(struct test_options *opts, struct hizip_test_info *info)
{
	int i, ret;
	void *tret;

	if (opts->sync_mode) {
		for (i = 0; i < info->poll_tnum; i++) {
			ret = pthread_join(info->poll_tds[i], NULL);
			if (ret < 0)
				fprintf(stderr, "Fail on poll thread with %d\n",
					ret);
		}
	}
	for (i = 0; i < info->send_tnum; i++) {
		ret = pthread_join(info->send_tds[i], &tret);
		if (ret < 0)
			fprintf(stderr, "Fail on send thread with %d\n", ret);
	}
	return (int)(uintptr_t)tret;
}

void gen_random_data(void *buf, size_t len)
{
	int i;
	uint32_t seed = 0;
	unsigned short rand_state[3] = {(seed >> 16) & 0xffff,
					seed & 0xffff,
					0x330e};

	for (i = 0; i < len >> 3; i++)
		*((uint64_t *)buf + i) = nrand48(rand_state);
}

int calculate_md5(comp_md5_t *md5, const void *buf, size_t len)
{
	if (!md5 || !buf || !len)
		return -EINVAL;
	MD5_Init(&md5->md5_ctx);
	MD5_Update(&md5->md5_ctx, buf, len);
	MD5_Final(md5->md, &md5->md5_ctx);
	return 0;
}

void dump_md5(comp_md5_t *md5)
{
	int i;

	for (i = 0; i < MD5_DIGEST_LENGTH - 1; i++)
		printf("%02x-", md5->md[i]);
	printf("%02x\n", md5->md[i]);
}

int cmp_md5(comp_md5_t *orig, comp_md5_t *final)
{
	int i;

	if (!orig || !final)
		return -EINVAL;
	for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
		if (orig->md[i] != final->md[i]) {
			printf("Original MD5: ");
			dump_md5(orig);
			printf("Final MD5: ");
			dump_md5(final);
			return -EINVAL;
		}
	}
	return 0;
}

static void *async2_cb(struct wd_comp_req *req, void *data)
{
	sem_t *sem = (sem_t *)data;

	if (sem)
		sem_post(sem);
	return NULL;
}

/* used in BATCH mode */
static void *async5_cb(struct wd_comp_req *req, void *data)
{
	thread_data_t *tdata = (thread_data_t *)data;

	pthread_spin_lock(&lock);
	tdata->pcnt++;
	if (tdata->batch_flag && (tdata->pcnt == tdata->bcnt)) {
		tdata->pcnt = 0;
		tdata->bcnt = 0;
		tdata->batch_flag = 0;
		pthread_spin_unlock(&lock);
		sem_post(&tdata->sem);
	} else
		pthread_spin_unlock(&lock);
	return NULL;
}

void init_chunk_list(chunk_list_t *list, void *buf, size_t buf_sz,
		     size_t chunk_sz)
{
	chunk_list_t *p = NULL;
	int i, count;
	size_t sum;

	count = (buf_sz + chunk_sz - 1) / chunk_sz;
	for (i = 0, sum = 0, p = list; i < count && sum <= buf_sz; i++, p++) {
		p->addr = buf + sum;
		p->size = MIN(buf_sz - sum, chunk_sz);
		if (i == count - 1)
			p->next = NULL;
		else
			p->next = p + 1;
		sum += p->size;
	}
}

chunk_list_t *create_chunk_list(void *buf, size_t buf_sz, size_t chunk_sz)
{
	chunk_list_t *list;
	int count;

	count = (buf_sz + chunk_sz - 1) / chunk_sz;
	if (count > HIZIP_CHUNK_LIST_ENTRIES)
		count = HIZIP_CHUNK_LIST_ENTRIES;
	if (buf_sz / chunk_sz > count)
		return NULL;
	/* allocate entries with additional one */
	list = malloc(sizeof(chunk_list_t) * (count + 1));
	if (!list)
		return NULL;
	init_chunk_list(list, buf, buf_sz, chunk_sz);
	return list;
}

void free_chunk_list(chunk_list_t *list)
{
	free(list);
}

/*
 * Deflate a data block with compressed header.
 */
static int chunk_deflate2(void *in, size_t in_sz, void *out, size_t *out_sz,
			  struct test_options *opts)
{
	int alg_type = opts->alg_type;
	z_stream strm;
	int windowBits;
	int ret;

	switch (alg_type) {
	case WD_ZLIB:
		windowBits = 15;
		break;
	case WD_DEFLATE:
		windowBits = -15;
		break;
	case WD_GZIP:
		windowBits = 15 + 16;
		break;
	default:
		printf("algorithm %d unsupported by zlib\n", alg_type);
		return -EINVAL;
	}
	memset(&strm, 0, sizeof(z_stream));
	strm.next_in = in;
	strm.avail_in = in_sz;
	strm.next_out = out;
	strm.avail_out = *out_sz;

	ret = deflateInit2(&strm, Z_BEST_SPEED, Z_DEFLATED, windowBits,
			   8, Z_DEFAULT_STRATEGY);
	if (ret != Z_OK) {
		printf("deflateInit2: %d\n", ret);
		return -EINVAL;
	}

	do {
		ret = deflate(&strm, Z_FINISH);
		if ((ret == Z_STREAM_ERROR) || (ret == Z_BUF_ERROR)) {
			printf("defalte error %d - %s\n", ret, strm.msg);
			ret = -ENOSR;
			break;
		} else if (!strm.avail_in) {
			if (ret != Z_STREAM_END)
				printf("deflate unexpected return: %d\n", ret);
			ret = 0;
			break;
		} else if (!strm.avail_out) {
			printf("deflate out of memory\n");
			ret = -ENOSPC;
			break;
		}
	} while (ret == Z_OK);

	deflateEnd(&strm);
	*out_sz = *out_sz - strm.avail_out;
	return ret;
}


/*
 * This function is used in BLOCK mode. Each compressing in BLOCK mode
 * produces compression header.
 */
static int chunk_inflate2(void *in, size_t in_sz, void *out, size_t *out_sz,
			  struct test_options *opts)
{
	z_stream strm;
	int ret;

	memset(&strm, 0, sizeof(z_stream));
	/* Window size of 15, +32 for auto-decoding gzip/zlib */
	ret = inflateInit2(&strm, 15 + 32);
	if (ret != Z_OK) {
		printf("zlib inflateInit: %d\n", ret);
		return -EINVAL;
	}

	strm.next_in = in;
	strm.avail_in = in_sz;
	strm.next_out = out;
	strm.avail_out = *out_sz;
	do {
		ret = inflate(&strm, Z_NO_FLUSH);
		if ((ret < 0) || (ret == Z_NEED_DICT)) {
			printf("zlib error %d - %s\n", ret, strm.msg);
			goto out;
		}
		if (!strm.avail_out) {
			if (!strm.avail_in || (ret == Z_STREAM_END))
				break;
			printf("%s: avail_out is empty!\n", __func__);
			goto out;
		}
	} while (strm.avail_in && (ret != Z_STREAM_END));
	inflateEnd(&strm);
	*out_sz = *out_sz - strm.avail_out;
	return 0;
out:
	inflateEnd(&strm);
	ret = -EINVAL;
	return ret;
}

/*
 * Compress a list of chunk data and produce a list of chunk data by software.
 * in_list & out_list should be formated first.
 */
int sw_deflate2(chunk_list_t *in_list,
		chunk_list_t *out_list,
		struct test_options *opts)
{
	chunk_list_t *p, *q;
	int ret = -EINVAL;

	for (p = in_list, q = out_list; p && q; p = p->next, q = q->next) {
		ret = chunk_deflate2(p->addr, p->size, q->addr, &q->size,
				     opts);
		if (ret)
			return ret;
	}
	return ret;
}

/*
 * Compress a list of chunk data and produce a list of chunk data by software.
 * in_list & out_list should be formated first.
 */
int sw_inflate2(chunk_list_t *in_list, chunk_list_t *out_list,
		struct test_options *opts)
{
	chunk_list_t *p, *q;
	int ret = -EINVAL;

	for (p = in_list, q = out_list; p && q; p = p->next, q = q->next) {
		ret = chunk_inflate2(p->addr, p->size, q->addr, &q->size,
				     opts);
		if (ret)
			return ret;
	}
	return ret;
}

int hw_deflate4(handle_t h_dfl,
		chunk_list_t *in_list,
		chunk_list_t *out_list,
		struct test_options *opts,
		sem_t *sem)
{
	struct wd_comp_req *reqs;
	chunk_list_t *p = in_list, *q = out_list;
	int i, ret;

	if (!in_list || !out_list || !opts || !sem)
		return -EINVAL;
	/* reqs array could make async operations in parallel */
	reqs = calloc(1, sizeof(struct wd_comp_req) * HIZIP_CHUNK_LIST_ENTRIES);
	if (!reqs)
		return -ENOMEM;
	for (i = 0; p && q; p = p->next, q = q->next, i++) {
		reqs[i].src = p->addr;
		reqs[i].src_len = p->size;
		reqs[i].dst = q->addr;
		reqs[i].dst_len = q->size;
		reqs[i].op_type = WD_DIR_COMPRESS;
		reqs[i].win_sz = WD_COMP_WS_32K;
		reqs[i].comp_lv = WD_COMP_L8;

		if (opts->sync_mode) {
			reqs[i].cb = async2_cb;
			reqs[i].cb_param = sem;
		}
		do {
			if (opts->sync_mode) {
				ret = wd_do_comp_async(h_dfl, &reqs[i]);
				if (!ret) {
					__atomic_add_fetch(&sum_pend, 1,
							   __ATOMIC_ACQ_REL);
					sem_wait(sem);
				}
			} else
				ret = wd_do_comp_sync(h_dfl, &reqs[i]);
		} while (ret == -WD_EBUSY);
		if (ret)
			goto out;
		q->size = reqs[i].dst_len;
		/* make sure olist has the same length with ilist */
		if (!p->next)
			q->next = NULL;
		i++;
	}
	free(reqs);
	return 0;
out:
	free(reqs);
	return ret;
}

int hw_inflate4(handle_t h_ifl,
		chunk_list_t *in_list,
		chunk_list_t *out_list,
		struct test_options *opts,
		sem_t *sem)
{
	struct wd_comp_req *reqs;
	chunk_list_t *p, *q;
	int i = 0, ret;

	/* reqs array could make async operations in parallel */
	reqs = calloc(1, sizeof(struct wd_comp_req) * HIZIP_CHUNK_LIST_ENTRIES);
	if (!reqs)
		return -ENOMEM;
	for (p = in_list, q = out_list; p && q; p = p->next, q = q->next) {
		reqs[i].src = p->addr;
		reqs[i].src_len = p->size;
		reqs[i].dst = q->addr;
		reqs[i].dst_len = q->size;
		reqs[i].op_type = WD_DIR_DECOMPRESS;
		if (opts->sync_mode) {
			reqs[i].cb = async2_cb;
			reqs[i].cb_param = sem;
		}
		do {
			if (opts->sync_mode) {
				ret = wd_do_comp_async(h_ifl, &reqs[i]);
				if (!ret) {
					__atomic_add_fetch(&sum_pend, 1,
							   __ATOMIC_ACQ_REL);
					sem_wait(sem);
				}
			} else
				ret = wd_do_comp_sync(h_ifl, &reqs[i]);
		} while (ret == -WD_EBUSY);
		if (ret)
			goto out;
		q->size = reqs[i].dst_len;
		/* make sure olist has the same length with ilist */
		if (!p->next)
			q->next = NULL;
		i++;
	}
	free(reqs);
	return 0;
out:
	free(reqs);
	return ret;
}

/* used in BATCH mode */
int hw_deflate5(handle_t h_dfl,
		chunk_list_t *in_list,
		chunk_list_t *out_list,
		thread_data_t *tdata)
{
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_req *reqs = tdata->reqs;
	chunk_list_t *p = in_list, *q = out_list;
	int i = 0, ret = 0;

	if (!in_list || !out_list || !opts)
		return -EINVAL;
	for (p = in_list, q = out_list; p && q; p = p->next, q = q->next) {
		reqs[i].src = p->addr;
		reqs[i].src_len = p->size;
		reqs[i].dst = q->addr;
		reqs[i].dst_len = q->size;
		reqs[i].op_type = WD_DIR_COMPRESS;
		reqs[i].data_fmt = opts->data_fmt;
		reqs[i].win_sz = WD_COMP_WS_32K;
		reqs[i].comp_lv = WD_COMP_L8;
		if (opts->sync_mode) {
			reqs[i].cb = async5_cb;
			reqs[i].cb_param = tdata;
		} else {
			reqs[i].cb = NULL;
			reqs[i].cb_param = NULL;
		}
		if (opts->sync_mode) {
			do {
				ret = wd_do_comp_async(h_dfl, &reqs[i]);
			} while (ret == -WD_EBUSY);
			if (ret < 0)
				goto out;
			__atomic_add_fetch(&sum_pend, 1, __ATOMIC_ACQ_REL);
			pthread_spin_lock(&lock);
			tdata->bcnt++;
			if (((i + 1) == opts->batch_num) || !p->next) {
				tdata->batch_flag = 1;
				pthread_spin_unlock(&lock);
				sem_wait(&tdata->sem);
			} else
				pthread_spin_unlock(&lock);
		} else {
			do {
				ret = wd_do_comp_sync(h_dfl, &reqs[i]);
			} while (ret == -WD_EBUSY);
			if (ret)
				goto out;
		}
		q->size = reqs[i].dst_len;
		i = (i + 1) % opts->batch_num;
		/* make sure olist has the same length with ilist */
		if (!p->next)
			q->next = NULL;
	}
	return 0;
out:
	return ret;
}

/* used in BATCH mode */
int hw_inflate5(handle_t h_ifl,
		chunk_list_t *in_list,
		chunk_list_t *out_list,
	        thread_data_t *tdata)
{
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_req *reqs = tdata->reqs;
	chunk_list_t *p = in_list, *q = out_list;
	int ret = 0, i = 0;

	if (!in_list || !out_list || !opts)
		return -EINVAL;
	for (p = in_list, q = out_list; p && q; p = p->next, q = q->next) {
		reqs[i].src = p->addr;
		reqs[i].src_len = p->size;
		reqs[i].dst = q->addr;
		reqs[i].dst_len = q->size;
		reqs[i].op_type = WD_DIR_DECOMPRESS;
		reqs[i].data_fmt = opts->data_fmt;
		if (opts->sync_mode) {
			reqs[i].cb = async5_cb;
			reqs[i].cb_param = tdata;
		} else {
			reqs[i].cb = NULL;
			reqs[i].cb_param = NULL;
		}
		if (opts->sync_mode) {
			do {
				ret = wd_do_comp_async(h_ifl, &reqs[i]);
			} while (ret == -WD_EBUSY);
			if (ret < 0)
				goto out;
			__atomic_add_fetch(&sum_pend, 1, __ATOMIC_ACQ_REL);
			pthread_spin_lock(&lock);
			tdata->bcnt++;
			if (((i + 1) == opts->batch_num) || !p->next) {
				tdata->batch_flag = 1;
				pthread_spin_unlock(&lock);
				sem_wait(&tdata->sem);
			} else
				pthread_spin_unlock(&lock);
		} else {
			do {
				ret = wd_do_comp_sync(h_ifl, &reqs[i]);
			} while (ret == -WD_EBUSY);
			if (ret)
				goto out;
		}
		q->size = reqs[i].dst_len;
		i = (i + 1) % opts->batch_num;
		/* make sure olist has the same length with ilist */
		if (!p->next)
			q->next = NULL;
	}
	return 0;
out:
	return ret;
}

/*
 * info->in_buf & info->out_buf should be allocated first.
 * Thread 0 shares info->out_buf. Other threads need to create its own
 * dst buffer.
 */
int create_send_tdata(struct test_options *opts,
		      struct hizip_test_info *info)
{
	thread_data_t *tdata;
	chunk_list_t *in_list, *out_list;
	int i, j, num, ret;

	if (!opts || !info || !info->in_chunk_sz || !info->out_chunk_sz)
		return -EINVAL;
	num = opts->thread_num;
	info->send_tds = calloc(1, sizeof(pthread_t) * num);
	if (!info->send_tds)
		return -ENOMEM;
	info->send_tnum = num;
	info->tdatas = calloc(1, sizeof(thread_data_t) * num);
	if (!info->tdatas) {
		ret = -ENOMEM;
		goto out;
	}
	if (!opts->batch_num)
		opts->batch_num = 1;
	else if (opts->batch_num > HIZIP_CHUNK_LIST_ENTRIES)
		opts->batch_num = HIZIP_CHUNK_LIST_ENTRIES;
	if (opts->is_stream) {
		in_list = create_chunk_list(info->in_buf, info->in_size,
					    info->in_size);
	} else {
		in_list = create_chunk_list(info->in_buf, info->in_size,
					    info->in_chunk_sz);
	}
	if (!in_list) {
		ret = -EINVAL;
		goto out_in;
	}
	for (i = 0; i < num; i++) {
		tdata = &info->tdatas[i];
		/* src address is shared among threads */
		tdata->tid = i;
		tdata->src_sz = info->in_size;
		tdata->src = info->in_buf;
		tdata->in_list = in_list;
		tdata->dst_sz = info->out_size;
		tdata->dst = mmap_alloc(tdata->dst_sz);
		if (!tdata->dst) {
			ret = -ENOMEM;
			goto out_dst;
		}
		/*
		 * Without memset, valgrind reports uninitialized buf
		 * for writing to file.
		 */
		memset(tdata->dst, 0, tdata->dst_sz);
		if (opts->is_stream) {
			out_list = create_chunk_list(tdata->dst,
						     tdata->dst_sz,
						     tdata->dst_sz);
		} else {
			out_list = create_chunk_list(tdata->dst,
						     tdata->dst_sz,
						     info->out_chunk_sz);
		}
		tdata->out_list = out_list;
		if (!tdata->out_list) {
			ret = -EINVAL;
			goto out_list;
		}
		calculate_md5(&tdata->md5, tdata->src, tdata->src_sz);
		tdata->reqs = malloc(sizeof(struct wd_comp_req) *
				     opts->batch_num);
		if (!tdata->reqs)
			goto out_list;
		sem_init(&tdata->sem, 0, 0);
		tdata->info = info;
	}
	return 0;
out_list:
	mmap_free(tdata->dst, tdata->dst_sz);
out_dst:
	for (j = 0; j < i; j++) {
		pthread_cancel(info->send_tds[j]);
		free_chunk_list(info->tdatas[j].out_list);
		mmap_free(info->tdatas[j].dst, info->tdatas[j].dst_sz);
	}
	free_chunk_list(in_list);
out_in:
	free(info->tdatas);
out:
	free(info->send_tds);
	return ret;
}

int create_poll_tdata(struct test_options *opts,
		      struct hizip_test_info *info,
		      int poll_num)
{
	thread_data_t *tdatas;
	int i, ret;

	if (opts->sync_mode == 0)
		return 0;
	else if (poll_num <= 0)
		return -EINVAL;
	info->poll_tnum = poll_num;
	info->poll_tds = calloc(1, sizeof(pthread_t) * poll_num);
	if (!info->poll_tds)
		return -ENOMEM;
	info->p_tdatas = calloc(1, sizeof(thread_data_t) * poll_num);
	if (!info->p_tdatas) {
		ret = -ENOMEM;
		goto out;
	}
	tdatas = info->p_tdatas;
	for (i = 0; i < poll_num; i++) {
		tdatas[i].tid = i;
		tdatas[i].info = info;
	}
	return 0;
out:
	free(info->poll_tds);
	return ret;
}

/*
 * Free source and destination buffer contained in sending threads.
 * Free sending threads and polling threads.
 */
void free2_threads(struct hizip_test_info *info)
{
	thread_data_t *tdatas = info->tdatas;
	int i;

	if (info->send_tds)
		free(info->send_tds);
	if (info->poll_tds) {
		free(info->poll_tds);
		free(info->p_tdatas);
	}
	free_chunk_list(tdatas[0].in_list);
	for (i = 0; i < info->send_tnum; i++) {
		free_chunk_list(tdatas[i].out_list);
		free(tdatas[i].reqs);
	}
	/* info->out_buf is bound to tdatas[0].dst */
	for (i = 0; i < info->send_tnum; i++)
		mmap_free(tdatas[i].dst, tdatas[i].dst_sz);
	free(info->tdatas);
	mmap_free(info->in_buf, info->in_size);
}

int attach2_threads(struct test_options *opts,
		    struct hizip_test_info *info,
		    void *(*send_thread_func)(void *arg),
		    void *(*poll_thread_func)(void *arg))
{
	int i, j, ret, num;
	void *tret;
	pthread_attr_t attr;

	num = opts->thread_num;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	for (i = 0; i < num; i++) {
		ret = pthread_create(&info->send_tds[i], &attr,
				     send_thread_func, &info->tdatas[i]);
		if (ret < 0) {
			printf("Fail to create send thread %d (%d)\n", i, ret);
			goto out;
		}
	}
	if (opts->sync_mode && !opts->use_env) {
		for (i = 0; i < opts->poll_num; i++) {
			ret = pthread_create(&info->poll_tds[i], &attr,
					     poll_thread_func,
					     &info->tdatas[i]);
			if (ret < 0) {
				printf("Fail to create poll thread %d (%d)\n",
					i, ret);
				goto out_poll;
			}
		}
		for (i = 0; i < info->poll_tnum; i++) {
			ret = pthread_join(info->poll_tds[i], NULL);
			if (ret < 0)
				fprintf(stderr, "Fail on poll thread with %d\n",
					ret);
		}
	}
	for (i = 0; i < info->send_tnum; i++) {
		ret = pthread_join(info->send_tds[i], &tret);
		if (ret < 0)
			fprintf(stderr, "Fail on send thread with %d\n", ret);
	}
	pthread_attr_destroy(&attr);
	return (int)(uintptr_t)tret;
out_poll:
	for (j = 0; j < i; j++)
		pthread_cancel(info->poll_tds[j]);
	i = opts->thread_num;
out:
	for (j = 0; j < i; j++)
		pthread_cancel(info->send_tds[j]);
	pthread_attr_destroy(&attr);
	return ret;
}

void *poll2_thread_func(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	__u32 received;
	int ret = 0;
	struct timeval start_tvl, end_tvl;
	int pending;
	int end_threads;

	gettimeofday(&start_tvl, NULL);
	while (1) {
		end_threads = __atomic_load_n(&sum_thread_end,
					      __ATOMIC_ACQUIRE);
		pending = __atomic_load_n(&sum_pend, __ATOMIC_ACQUIRE);
		if ((end_threads == info->send_tnum) && (pending == 0))
			break;
		else if (pending == 0)
			continue;
		received = 0;
		ret = wd_comp_poll(pending, &received);
		if (ret == 0) {
			__atomic_sub_fetch(&sum_pend,
					   received,
					   __ATOMIC_ACQ_REL);
		}
	}
	gettimeofday(&end_tvl, NULL);
	timersub(&end_tvl, &start_tvl, &start_tvl);
	pthread_exit(NULL);
}

/*
 * Choose a device and check whether it can afford the requested contexts.
 * Return a list whose the first device is chosen.
 */
struct uacce_dev_list *get_dev_list(struct test_options *opts,
				    int children)
{
	struct uacce_dev_list *list, *p, *head = NULL, *prev = NULL;
	int max_q_num;

	list = wd_get_accel_list("zlib");
	if (!list)
		return NULL;

	p = list;
	/* Find one device matching the requested contexts. */
	while (p) {
		max_q_num = wd_get_avail_ctx(p->dev);
		/*
		 * Check whether there's enough contexts.
		 * There may be multiple taskes running together.
		 * The number of multiple taskes is specified in children.
		 */
		if (max_q_num < 4 * opts->q_num * children) {
			if (!head)
				head = p;
			prev = p;
			p = p->next;
		} else
			break;
	}

	if (!p) {
		WD_ERR("Request too much contexts: %d\n",
		       opts->q_num * 4 * children);
		goto out;
	}

	/* Adjust p to the head of list if p is in the middle. */
	if (p && (p != list)) {
		prev->next = p->next;
		p->next = head;
		return p;
	}
	return list;
out:
	wd_free_list_accels(list);
	return NULL;
}

/*
 * Initialize context numbers by the four times of opts->q_num.
 * [sync, async] * [compress, decompress] = 4
 */
int init_ctx_config(struct test_options *opts, void *priv,
		    struct wd_sched **sched)
{
	struct hizip_test_info *info = priv;
	struct wd_ctx_config *ctx_conf = &info->ctx_conf;
	int i, j, ret = -EINVAL;
	int q_num = opts->q_num;


	__atomic_store_n(&sum_pend, 0, __ATOMIC_RELEASE);
	__atomic_store_n(&sum_thread_end, 0, __ATOMIC_RELEASE);
	*sched = sample_sched_alloc(SCHED_POLICY_RR, 2, 2, lib_poll_func);
	if (!*sched) {
		WD_ERR("sample_sched_alloc fail\n");
		goto out_sched;
	}

	(*sched)->name = SCHED_RR_NAME;

	memset(ctx_conf, 0, sizeof(struct wd_ctx_config));
	ctx_conf->ctx_num = q_num * 4;
	ctx_conf->ctxs = calloc(1, q_num * 4 * sizeof(struct wd_ctx));
	if (!ctx_conf->ctxs) {
		WD_ERR("Not enough memory to allocate contexts.\n");
		ret = -ENOMEM;
		goto out_ctx;
	}
	for (i = 0; i < ctx_conf->ctx_num; i++) {
		ctx_conf->ctxs[i].ctx = wd_request_ctx(info->list->dev);
		if (!ctx_conf->ctxs[i].ctx) {
			WD_ERR("Fail to allocate context #%d\n", i);
			ret = -EINVAL;
			goto out_req;
		}
	}
	/*
	 * All contexts for 2 modes & 2 types.
	 * The test only uses one kind of contexts at the same time.
	 */
	for (i = 0; i < q_num; i++) {
		ctx_conf->ctxs[i].ctx_mode = 0;
		ctx_conf->ctxs[i].op_type = 0;
	}
	ret = sample_sched_fill_data((const struct wd_sched*)*sched, 0, 0, 0,
				     0, q_num - 1);
	if (ret < 0) {
		WD_ERR("Fail to fill sched region.\n");
		goto out_fill;
	}
	for (i = q_num; i < q_num * 2; i++) {
		ctx_conf->ctxs[i].ctx_mode = 0;
		ctx_conf->ctxs[i].op_type = 1;
	}
	ret = sample_sched_fill_data((const struct wd_sched*)*sched, 0, 0, 1,
				     q_num, q_num * 2 - 1);
	if (ret < 0) {
		WD_ERR("Fail to fill sched region.\n");
		goto out_fill;
	}
	for (i = q_num * 2; i < q_num * 3; i++) {
		ctx_conf->ctxs[i].ctx_mode = 1;
		ctx_conf->ctxs[i].op_type = 0;
	}
	ret = sample_sched_fill_data((const struct wd_sched*)*sched, 0, 1, 0,
				     q_num * 2, q_num * 3 - 1);
	if (ret < 0) {
		WD_ERR("Fail to fill sched region.\n");
		goto out_fill;
	}
	for (i = q_num * 3; i < q_num * 4; i++) {
		ctx_conf->ctxs[i].ctx_mode = 1;
		ctx_conf->ctxs[i].op_type = 1;
	}
	ret = sample_sched_fill_data((const struct wd_sched*)*sched, 0, 1, 1,
				     q_num * 3, q_num * 4 - 1);
	if (ret < 0) {
		WD_ERR("Fail to fill sched region.\n");
		goto out_fill;
	}

	ret = wd_comp_init(ctx_conf, *sched);
	if (ret)
		goto out_fill;
	return ret;

out_fill:
	for (i = 0; i < ctx_conf->ctx_num; j++)
		wd_release_ctx(ctx_conf->ctxs[i].ctx);
out_req:
	free(ctx_conf->ctxs);
out_ctx:
	sample_sched_release(*sched);
out_sched:
	return ret;
}

void uninit_config(void *priv, struct wd_sched *sched)
{
	struct hizip_test_info *info = priv;
	struct wd_ctx_config *ctx_conf = &info->ctx_conf;
	int i;

	wd_comp_uninit();
	for (i = 0; i < ctx_conf->ctx_num; i++)
		wd_release_ctx(ctx_conf->ctxs[i].ctx);
	free(ctx_conf->ctxs);
	sample_sched_release(sched);
}


int parse_common_option(const char opt, const char *optarg,
			struct test_options *opts)
{
	switch (opt) {
	case 'b':
		opts->block_size = strtol(optarg, NULL, 0);
		if (opts->block_size <= 0)
			return 1;
		break;
	case 'l':
		opts->compact_run_num = strtol(optarg, NULL, 0);
		if (opts->compact_run_num <= 0)
			return 1;
		break;
	case 'n':
		opts->run_num = strtol(optarg, NULL, 0);
		SYS_ERR_COND(opts->run_num > MAX_RUNS,
			     "No more than %d runs supported\n", MAX_RUNS);
		if (opts->run_num <= 0)
			return 1;
		break;
	case 'q':
		opts->q_num = strtol(optarg, NULL, 0);
		if (opts->q_num <= 0)
			return 1;
		break;
	case 'd':
		opts->op_type = WD_DIR_DECOMPRESS;
		break;
	case 'F':
		opts->is_file = true;
		break;
	case 'S':
		opts->is_stream = MODE_STREAM;
		break;
	case 's':
		opts->total_len = strtol(optarg, NULL, 0);
		SYS_ERR_COND(opts->total_len <= 0, "invalid size '%s'\n",
			     optarg);
		break;
	case 't':
		opts->thread_num = strtol(optarg, NULL, 0);
		SYS_ERR_COND(opts->thread_num < 0, "invalid thread num '%s'\n",
			     optarg);
		break;
	case 'm':
		opts->sync_mode = strtol(optarg, NULL, 0);
		SYS_ERR_COND(opts->sync_mode < 0 || opts->sync_mode > 1,
			     "invalid sync mode '%s'\n", optarg);
		break;
	case 'V':
		opts->verify = true;
		break;
	case 'v':
		opts->verbose = true;
		break;
	case 'a':
		opts->alg_type = WD_DEFLATE;
		break;
	case 'z':
		opts->alg_type = WD_ZLIB;
		break;
	case 'L':
		opts->data_fmt = WD_SGL_BUF;
		break;
	case 'Z':
		opts->alg_type = WD_LZ77_ZSTD;
		break;
	default:
		return 1;
	}

	return 0;
}

#ifdef HAVE_ZLIB

#include <zlib.h>

/*
 * Try to decompress a buffer using zLib's inflate(). Call compare_output with
 * the decompressed stream as argument
 *
 * Return 0 on success, or an error.
 */
int hizip_check_output(void *buf, size_t size, size_t *checked,
		       check_output_fn compare_output, void *opaque)
{
	int ret, ret2;
	unsigned char *out_buffer;
	const size_t out_buf_size = 0x100000;
	z_stream stream = {
		.next_in	= buf,
		.avail_in	= size,
	};

	out_buffer = calloc(1, out_buf_size);
	if (!out_buffer)
		return -ENOMEM;

	stream.next_out = out_buffer;
	stream.avail_out = out_buf_size;

	/* Window size of 15, +32 for auto-decoding gzip/zlib */
	ret = inflateInit2(&stream, 15 + 32);
	if (ret != Z_OK) {
		WD_ERR("zlib inflateInit: %d\n", ret);
		ret = -EINVAL;
		goto out_free_buf;
	}

	do {
		ret = inflate(&stream, Z_NO_FLUSH);
		if (ret < 0 || ret == Z_NEED_DICT) {
			WD_ERR("zlib error %d - %s\n", ret, stream.msg);
			ret = -ENOSR;
			break;
		}

		ret2 = compare_output(out_buffer, out_buf_size -
				      stream.avail_out, opaque);
		/* compare_output should print diagnostic messages. */
		if (ret2) {
			ret = Z_STREAM_ERROR;
			break;
		}

		if (!stream.avail_out) {
			stream.next_out = out_buffer;
			stream.avail_out = out_buf_size;
		}
	} while (ret != Z_STREAM_END);

	if (ret == Z_STREAM_END || ret == Z_OK) {
		*checked = stream.total_out;
		ret = 0;
	}

	inflateEnd(&stream);
out_free_buf:
	free(out_buffer);
	return ret;
}

int zlib_deflate(void *output, unsigned int out_size,
		 void *input, unsigned int in_size,
		 unsigned long *produced, int alg_type)
{
	int ret;
	int windowBits;
	z_stream stream = {
		.next_in	= input,
		.avail_in	= in_size,
		.next_out	= output,
		.avail_out	= out_size,
	};

	switch (alg_type) {
	case WD_ZLIB:
		windowBits = 15;
		break;
	case WD_DEFLATE:
		windowBits = -15;
		break;
	case WD_GZIP:
		windowBits = 15 + 16;
		break;
	default:
		WD_ERR("algorithm %d unsupported by zlib\n", alg_type);
		return -EINVAL;
	}

	ret = deflateInit2(&stream, Z_BEST_SPEED, Z_DEFLATED, windowBits, 9,
			   Z_DEFAULT_STRATEGY);
	if (ret != Z_OK) {
		WD_ERR("zlib deflateInit: %d\n", ret);
		return -EINVAL;
	}

	do {
		ret = deflate(&stream, Z_FINISH);
		if (ret == Z_STREAM_ERROR || ret == Z_BUF_ERROR) {
			WD_ERR("zlib error %d - %s\n", ret, stream.msg);
			ret = -ENOSR;
			break;
		} else if (!stream.avail_in) {
			if (ret != Z_STREAM_END)
				WD_ERR("unexpected deflate return value %d\n", ret);
			*produced = stream.total_out;
			ret = 0;
			break;
		} else if (!stream.avail_out) {
			WD_ERR("No more output available\n");
			ret = -ENOSPC;
			break;
		}
	} while (ret == Z_OK);

	deflateEnd(&stream);

	return ret;
}
#endif
