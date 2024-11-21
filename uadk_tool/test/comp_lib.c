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

#include "comp_lib.h"

#define SCHED_RR_NAME	"sched_rr"

struct check_rand_ctx {
	int off;
	unsigned long global_off;
	__u32 last;
	unsigned short state[3];
};

static pthread_spinlock_t lock;

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
		COMP_TST_PRT("Failed to allocate %zu bytes\n", len);

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

static struct wd_datalist *get_datalist(void *addr, __u32 size)
{
	int count = (int)ceil((double)size / SGE_SIZE);
	struct wd_datalist *head, *cur, *tmp;
	int i;

	head = calloc(1, sizeof(struct wd_datalist));
	if (!head) {
		COMP_TST_PRT("failed to alloc datalist head\n");
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
 * hw_blk_compress() - compress memory buffer.
 */
int hw_blk_compress(struct test_options *opts, void *priv,
		    unsigned char *dst, __u32 *dstlen,
		    unsigned char *src, __u32 srclen)
{
	handle_t h_sess;
	struct wd_comp_sess_setup setup;
	struct sched_params param = {0};
	struct wd_datalist *list;
	struct wd_comp_req req = {0};
	int ret = 0;

	setup.alg_type = opts->alg_type;
	setup.op_type = opts->op_type;
	setup.comp_lv = WD_COMP_L8;
	setup.win_sz = WD_COMP_WS_8K;
	param.type = setup.op_type;
	param.numa_id = 0;
	setup.sched_param = &param;
	h_sess = wd_comp_alloc_sess(&setup);
	if (!h_sess) {
		COMP_TST_PRT("fail to alloc comp sess!\n");
		return -EINVAL;
	}

	if (opts->data_fmt) {
		COMP_TST_PRT("now sge size is %d\n", SGE_SIZE);
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
	req.op_type = opts->op_type;
	req.cb = NULL;
	req.data_fmt = opts->data_fmt;
	req.priv = priv;

	dbg("%s:input req: src:%p, dst:%p, src_len: %u, dst_len:%u\n",
	    __func__, req.src, req.dst, req.src_len, req.dst_len);

	ret = wd_do_comp_sync(h_sess, &req);
	if (ret < 0) {
		COMP_TST_PRT("fail to do comp sync(ret = %d)!\n", ret);
		wd_comp_free_sess(h_sess);
		return ret;
	}
	if (req.status) {
		COMP_TST_PRT("fail to do comp sync(status = %u)!\n",
		req.status);
		wd_comp_free_sess(h_sess);
		return req.status;
	}
	*dstlen = req.dst_len;

	dbg("%s:output req: src:%p, dst:%p,src_len: %u, dst_len:%u\n",
	    __func__, req.src, req.dst, req.src_len, req.dst_len);

	wd_comp_free_sess(h_sess);

	return ret;
}

/**
 * hw_stream_compress() - compress memory buffer.
 */
int hw_stream_compress(struct test_options *opts,
		       unsigned char *dst, __u32 *dstlen,
		       unsigned char *src, __u32 srclen)
{
	handle_t h_sess;
	struct wd_comp_sess_setup setup;
	struct sched_params param = {0};
	struct wd_comp_req req = {0};
	int ret = 0;

	setup.alg_type = opts->alg_type;
	setup.op_type = opts->op_type;
	setup.comp_lv = WD_COMP_L8;
	setup.win_sz = WD_COMP_WS_8K;
	param.type = setup.op_type;
	param.numa_id = 0;
	setup.sched_param = &param;
	h_sess = wd_comp_alloc_sess(&setup);
	if (!h_sess) {
		COMP_TST_PRT("fail to alloc comp sess!\n");
		return -EINVAL;
	}
	req.src = src;
	req.src_len = srclen;
	req.dst = dst;
	req.dst_len = *dstlen;
	req.op_type = opts->op_type;
	req.cb = NULL;
	req.data_fmt = opts->data_fmt;

	dbg("%s:input req: src:%p, dst:%p, src_len: %u, dst_len:%u\n",
	    __func__, req.src, req.dst, req.src_len, req.dst_len);

	ret = wd_do_comp_sync2(h_sess, &req);
	if (ret < 0) {
		COMP_TST_PRT("fail to do comp sync(ret = %d)!\n", ret);
		wd_comp_free_sess(h_sess);
		return ret;
	}
	if (req.status) {
		COMP_TST_PRT("fail to do comp sync(status = %u)!\n",
		req.status);
		wd_comp_free_sess(h_sess);
		return req.status;
	}

	if (opts->faults & INJECT_SIG_WORK)
		kill(getpid(), SIGTERM);

	*dstlen = req.dst_len;

	dbg("%s:output req: src:%p, dst:%p,src_len: %u, dst_len:%u\n",
	    __func__, req.src, req.dst, req.src_len, req.dst_len);

	wd_comp_free_sess(h_sess);

	return ret;
}

static int lib_poll_func(__u32 pos, __u32 expect, __u32 *count)
{
	int ret;

	ret = wd_comp_poll_ctx(pos, expect, count);
	if (ret < 0)
		return ret;
	return 0;
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

static void dump_md5(comp_md5_t *md5)
{
	int i;

	for (i = 0; i < MD5_DIGEST_LENGTH - 1; i++)
		COMP_TST_PRT("%02x-", md5->md[i]);
	COMP_TST_PRT("%02x\n", md5->md[i]);
}

int cmp_md5(comp_md5_t *orig, comp_md5_t *final)
{
	int i;

	if (!orig || !final)
		return -EINVAL;
	for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
		if (orig->md[i] != final->md[i]) {
			COMP_TST_PRT("Original MD5: ");
			dump_md5(orig);
			COMP_TST_PRT("Final MD5: ");
			dump_md5(final);
			return -EINVAL;
		}
	}
	return 0;
}

static void *async_cb(struct wd_comp_req *req, void *data)
{
	sem_t *sem = (sem_t *)data;

	if (sem)
		sem_post(sem);
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
static int chunk_deflate(void *in, size_t in_sz, void *out, size_t *out_sz,
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
		COMP_TST_PRT("algorithm %d unsupported by zlib\n", alg_type);
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
		COMP_TST_PRT("deflateInit2: %d\n", ret);
		return -EINVAL;
	}

	do {
		ret = deflate(&strm, Z_FINISH);
		if ((ret == Z_STREAM_ERROR) || (ret == Z_BUF_ERROR)) {
			COMP_TST_PRT("defalte error %d - %s\n", ret, strm.msg);
			ret = -ENOSR;
			break;
		} else if (!strm.avail_in) {
			if (ret != Z_STREAM_END)
				COMP_TST_PRT("deflate unexpected return: %d\n", ret);
			ret = 0;
			break;
		} else if (!strm.avail_out) {
			COMP_TST_PRT("deflate out of memory\n");
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
static int chunk_inflate(void *in, size_t in_sz, void *out, size_t *out_sz,
			  struct test_options *opts)
{
	z_stream strm;
	int ret;

	memset(&strm, 0, sizeof(z_stream));
	/* Window size of 15, +32 for auto-decoding gzip/zlib */
	ret = inflateInit2(&strm, 15 + 32);
	if (ret != Z_OK) {
		COMP_TST_PRT("zlib inflateInit: %d\n", ret);
		return -EINVAL;
	}

	strm.next_in = in;
	strm.avail_in = in_sz;
	strm.next_out = out;
	strm.avail_out = *out_sz;
	do {
		ret = inflate(&strm, Z_NO_FLUSH);
		if ((ret < 0) || (ret == Z_NEED_DICT)) {
			COMP_TST_PRT("zlib error %d - %s\n", ret, strm.msg);
			goto out;
		}
		if (!strm.avail_out) {
			if (!strm.avail_in || (ret == Z_STREAM_END))
				break;
			COMP_TST_PRT("%s: avail_out is empty!\n", __func__);
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
int sw_deflate(chunk_list_t *in_list,
		chunk_list_t *out_list,
		struct test_options *opts)
{
	chunk_list_t *p, *q;
	int ret = -EINVAL;

	for (p = in_list, q = out_list; p && q; p = p->next, q = q->next) {
		ret = chunk_deflate(p->addr, p->size, q->addr, &q->size,
				     opts);
		if (ret)
			return ret;
	}
	return ret;
}

/*
 * Deompress a list of chunk data and produce a list of chunk data by software.
 * in_list & out_list should be formated first.
 */
int sw_inflate(chunk_list_t *in_list, chunk_list_t *out_list,
		struct test_options *opts)
{
	chunk_list_t *p, *q;
	int ret = -EINVAL;

	for (p = in_list, q = out_list; p && q; p = p->next, q = q->next) {
		ret = chunk_inflate(p->addr, p->size, q->addr, &q->size,
				     opts);
		if (ret)
			return ret;
	}
	return ret;
}

/*
 * Compress a list of chunk data and produce a list of chunk data by hardware.
 * in_list & out_list should be formated first.
 */
int hw_deflate(handle_t h_dfl,
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
	reqs = malloc(sizeof(struct wd_comp_req) * HIZIP_CHUNK_LIST_ENTRIES);
	if (!reqs)
		return -ENOMEM;

	for (i = 0; p && q; p = p->next, q = q->next, i++) {
		reqs[i].src = p->addr;
		reqs[i].src_len = p->size;
		reqs[i].dst = q->addr;
		reqs[i].dst_len = q->size;
		reqs[i].op_type = WD_DIR_COMPRESS;

		if (opts->sync_mode) {
			reqs[i].cb = async_cb;
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
			} else {
				ret = wd_do_comp_sync(h_dfl, &reqs[i]);
				if (opts->faults & INJECT_SIG_WORK)
					kill(getpid(), SIGTERM);
			}
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

/*
 * Decompress a list of chunk data and produce a list of chunk data by hardware.
 * in_list & out_list should be formated first.
 */
int hw_inflate(handle_t h_ifl,
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
			reqs[i].cb = async_cb;
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
	int i, j, ret;

	if (!opts || !info || !info->in_chunk_sz || !info->out_chunk_sz)
		return -EINVAL;

	info->send_tds = calloc(1, sizeof(pthread_t) * opts->thread_num);
	if (!info->send_tds)
		return -ENOMEM;
	info->send_tnum = opts->thread_num;
	info->tdatas = calloc(1, sizeof(thread_data_t) * opts->thread_num);
	if (!info->tdatas) {
		ret = -ENOMEM;
		goto out;
	}

	info->in_buf = mmap_alloc(info->in_size);
	if (!info->in_buf) {
		ret = -ENOMEM;
		goto out_in;
	}

	if (opts->is_stream)
		in_list = create_chunk_list(info->in_buf, info->in_size, info->in_size);
	else
		in_list = create_chunk_list(info->in_buf, info->in_size, info->in_chunk_sz);
	if (!in_list) {
		ret = -EINVAL;
		goto out_ilist;
	}

	if (opts->option & TEST_THP) {
		ret = madvise(info->in_buf, info->in_size, MADV_HUGEPAGE);
		if (ret) {
			COMP_TST_PRT("madvise(MADV_HUGEPAGE)");
			goto out_ilist;
		}
	}
	for (i = 0; i < opts->thread_num; i++) {
		tdata = &info->tdatas[i];
		tdata->tid = i;
		tdata->src_sz = info->in_size;
		tdata->src = info->in_buf;	/* src address is shared among threads */
		tdata->in_list = in_list;
		tdata->dst_sz = info->out_size;
		tdata->dst = mmap_alloc(tdata->dst_sz);
		if (!tdata->dst) {
			ret = -ENOMEM;
			goto out_dst;
		}
		if (opts->option & TEST_THP) {
			ret = madvise(tdata->dst, tdata->dst_sz, MADV_HUGEPAGE);
			if (ret) {
				COMP_TST_PRT("madvise(MADV_HUGEPAGE)");
				goto out_dst;
			}
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
			goto out_olist;
		}
		calculate_md5(&tdata->md5, tdata->src, tdata->src_sz);
		tdata->reqs = malloc(sizeof(struct wd_comp_req));
		if (!tdata->reqs)
			goto out_olist;
		sem_init(&tdata->sem, 0, 0);
		tdata->info = info;
	}

	return 0;
out_olist:
	mmap_free(tdata->dst, tdata->dst_sz);
out_dst:
	for (j = 0; j < i; j++) {
		free_chunk_list(info->tdatas[j].out_list);
		mmap_free(info->tdatas[j].dst, info->tdatas[j].dst_sz);
	}
	free_chunk_list(in_list);
out_ilist:
	mmap_free(info->in_buf, info->in_size);
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
void free_threads_tdata(struct hizip_test_info *info)
{
	thread_data_t *tdatas = info->tdatas;
	int i;

	if (info->send_tds)
		free(info->send_tds);

	if (info->poll_tds) {
		free(info->poll_tds);
		free(info->p_tdatas);
	}

	free_chunk_list(tdatas[0].in_list);	/* src address is shared among threads */
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

int attach_threads(struct test_options *opts,
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
			COMP_TST_PRT("Fail to create send thread %d (%d)\n", i, ret);
			goto out;
		}
	}
	if (opts->sync_mode && !opts->use_env) {
		for (i = 0; i < opts->poll_num; i++) {
			ret = pthread_create(&info->poll_tds[i], &attr,
					     poll_thread_func,
					     &info->tdatas[i]);
			if (ret < 0) {
				COMP_TST_PRT("Fail to create poll thread %d (%d)\n",
					i, ret);
				goto out_poll;
			}
		}
		for (i = 0; i < info->poll_tnum; i++) {
			ret = pthread_join(info->poll_tds[i], &tret);
			if (ret < 0) {
				COMP_TST_PRT( "Fail on poll thread with %d\n",
					ret);
				goto out_poll;
			}
		}
	}
	for (i = 0; i < info->send_tnum; i++) {
		ret = pthread_join(info->send_tds[i], &tret);
		if (ret < 0) {
			COMP_TST_PRT( "Fail on send thread with %d\n", ret);
			goto out_poll;
		}
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

void *poll_thread_func(void *arg)
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
		if (info->opts->faults & INJECT_SIG_WORK)
			kill(getpid(), SIGTERM);

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
		COMP_TST_PRT("Request too much contexts: %d\n",
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
	struct sched_params param;
	int i, j, ret = -EINVAL;
	int q_num = opts->q_num;


	__atomic_store_n(&sum_pend, 0, __ATOMIC_RELEASE);
	__atomic_store_n(&sum_thread_end, 0, __ATOMIC_RELEASE);
	*sched = wd_sched_rr_alloc(SCHED_POLICY_RR, 2, 2, lib_poll_func);
	if (!*sched) {
		COMP_TST_PRT("wd_sched_rr_alloc fail\n");
		goto out_sched;
	}

	(*sched)->name = SCHED_RR_NAME;

	memset(ctx_conf, 0, sizeof(struct wd_ctx_config));
	ctx_conf->ctx_num = q_num * 4;
	ctx_conf->ctxs = calloc(1, q_num * 4 * sizeof(struct wd_ctx));
	if (!ctx_conf->ctxs) {
		COMP_TST_PRT("Not enough memory to allocate contexts.\n");
		ret = -ENOMEM;
		goto out_ctx;
	}
	for (i = 0; i < ctx_conf->ctx_num; i++) {
		ctx_conf->ctxs[i].ctx = wd_request_ctx(info->list->dev);
		if (!ctx_conf->ctxs[i].ctx) {
			COMP_TST_PRT("Fail to allocate context #%d\n", i);
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
	param.numa_id = 0;
	param.mode = 0;
	param.type = 0;
	param.begin = 0;
	param.end = q_num - 1;
	ret = wd_sched_rr_instance((const struct wd_sched *)*sched, &param);
	if (ret < 0) {
		COMP_TST_PRT("Fail to fill sched region.\n");
		goto out_fill;
	}
	for (i = q_num; i < q_num * 2; i++) {
		ctx_conf->ctxs[i].ctx_mode = 0;
		ctx_conf->ctxs[i].op_type = 1;
	}
	param.mode = 0;
	param.type = 1;
	param.begin = q_num;
	param.end = q_num * 2 - 1;
	ret = wd_sched_rr_instance((const struct wd_sched *)*sched, &param);
	if (ret < 0) {
		COMP_TST_PRT("Fail to fill sched region.\n");
		goto out_fill;
	}
	for (i = q_num * 2; i < q_num * 3; i++) {
		ctx_conf->ctxs[i].ctx_mode = 1;
		ctx_conf->ctxs[i].op_type = 0;
	}
	param.mode = 1;
	param.type = 0;
	param.begin = q_num * 2;
	param.end = q_num * 3 - 1;
	ret = wd_sched_rr_instance((const struct wd_sched *)*sched, &param);
	if (ret < 0) {
		COMP_TST_PRT("Fail to fill sched region.\n");
		goto out_fill;
	}
	for (i = q_num * 3; i < q_num * 4; i++) {
		ctx_conf->ctxs[i].ctx_mode = 1;
		ctx_conf->ctxs[i].op_type = 1;
	}
	param.mode = 1;
	param.type = 1;
	param.begin = q_num * 3;
	param.end = q_num * 4 - 1;
	ret = wd_sched_rr_instance((const struct wd_sched *)*sched, &param);
	if (ret < 0) {
		COMP_TST_PRT("Fail to fill sched region.\n");
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
	wd_sched_rr_release(*sched);
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
	wd_sched_rr_release(sched);
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
	case 'q':
		opts->q_num = strtol(optarg, NULL, 0);
		if (opts->q_num <= 0)
			return 1;
		break;
	case 'd':
		opts->op_type = WD_DIR_DECOMPRESS;
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
		COMP_TST_PRT("zlib inflateInit: %d\n", ret);
		ret = -EINVAL;
		goto out_free_buf;
	}

	do {
		ret = inflate(&stream, Z_NO_FLUSH);
		if (ret < 0 || ret == Z_NEED_DICT) {
			COMP_TST_PRT("zlib error %d - %s\n", ret, stream.msg);
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
		COMP_TST_PRT("algorithm %d unsupported by zlib\n", alg_type);
		return -EINVAL;
	}

	ret = deflateInit2(&stream, Z_BEST_SPEED, Z_DEFLATED, windowBits, 9,
			   Z_DEFAULT_STRATEGY);
	if (ret != Z_OK) {
		COMP_TST_PRT("zlib deflateInit: %d\n", ret);
		return -EINVAL;
	}

	do {
		ret = deflate(&stream, Z_FINISH);
		if (ret == Z_STREAM_ERROR || ret == Z_BUF_ERROR) {
			COMP_TST_PRT("zlib error %d - %s\n", ret, stream.msg);
			ret = -ENOSR;
			break;
		} else if (!stream.avail_in) {
			if (ret != Z_STREAM_END)
				COMP_TST_PRT("unexpected deflate return value %d\n", ret);
			*produced = stream.total_out;
			ret = 0;
			break;
		} else if (!stream.avail_out) {
			COMP_TST_PRT("No more output available\n");
			ret = -ENOSPC;
			break;
		}
	} while (ret == Z_OK);

	deflateEnd(&stream);

	return ret;
}
#endif
