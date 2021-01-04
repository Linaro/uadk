// SPDX-License-Identifier: Apache-2.0
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>

#include "hisi_qm_udrv.h"
#include "sched_sample.h"
#include "test_lib.h"

#define SCHED_RR_NAME	"sched_rr"

enum alg_type {
	HW_ZLIB  = 0x02,
	HW_GZIP,
};

struct check_rand_ctx {
	int off;
	unsigned long global_off;
	__u32 last;
	unsigned short state[3];
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int count = 0;

static struct wd_ctx_config *g_conf;

void *mmap_alloc(size_t len)
{
	void *p;
	long page_size = sysconf(_SC_PAGESIZE);

	if (len % page_size) {
		WD_ERR("unaligned allocation must use malloc\n");
		return NULL;
	}

	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
		 -1, 0);
	if (p == MAP_FAILED)
		WD_ERR("Failed to allocate %zu bytes\n", len);

	return p == MAP_FAILED ? NULL : p;
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
			/* Somthing left from a previous run */
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

/**
 * compress() - compress memory buffer.
 * @alg_type: alg_type.
 *
 * This function compress memory buffer.
 */
int hw_blk_compress(int alg_type, int blksize,
		    unsigned char *dst, __u32 *dstlen,
		    unsigned char *src, __u32 srclen)
{
	handle_t h_sess;
	struct wd_comp_sess_setup setup;
	struct wd_comp_req req;
	int ret = 0;

	setup.alg_type = alg_type;
	setup.mode = CTX_MODE_SYNC;
	setup.op_type = WD_DIR_COMPRESS;
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

int hw_blk_decompress(int alg_type, int blksize,
		      unsigned char *dst, __u32 *dstlen,
		      unsigned char *src, __u32 srclen)
{
	handle_t h_sess;
	struct wd_comp_sess_setup setup;
	struct wd_comp_req req;
	int ret = 0;


	setup.alg_type = alg_type;
	setup.mode = CTX_MODE_SYNC;
	setup.op_type = WD_DIR_DECOMPRESS;
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

int hw_stream_compress(int alg_type, int blksize,
		       unsigned char *dst, __u32 *dstlen,
		       unsigned char *src, __u32 srclen)
{
	handle_t h_sess;
	struct wd_comp_sess_setup setup;
	struct wd_comp_req req;
	int ret = 0;

	setup.alg_type = alg_type;
	setup.mode = CTX_MODE_SYNC;
	setup.op_type = WD_DIR_COMPRESS;
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


int hw_stream_decompress(int alg_type, int blksize,
		       unsigned char *dst, __u32 *dstlen,
		       unsigned char *src, __u32 srclen)
{
	handle_t h_sess;
	struct wd_comp_sess_setup setup;
	struct wd_comp_req req;
	int ret = 0;


	setup.alg_type = alg_type;
	setup.mode = CTX_MODE_SYNC;
	setup.op_type = WD_DIR_DECOMPRESS;
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

void hizip_prepare_random_input_data(struct hizip_test_info *info)
{
	__u32 seed = 0;
	unsigned short rand_state[3] = {(seed >> 16) & 0xffff, seed & 0xffff, 0x330e};

	unsigned long remain_size;
	__u32 block_size, size;
	char *in_buf;
	size_t i, j;

	/*
	 * TODO: change state for each buffer, to make sure there is no TLB
	 * aliasing. Can we store the seed into priv_info?
	 */
	//__u32 seed = info->state++;
	block_size = info->opts->block_size;
	remain_size = info->total_len;
	in_buf = info->in_buf;

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
				in_buf[i + j] = (n >> (8 * j)) & 0xff;
		}

		in_buf += size;
		remain_size -= size;
	}
}

int hizip_verify_random_output(char *out_buf, struct test_options *opts,
			       struct hizip_test_info *info)
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

	do {
		ret = hizip_check_output(out_buf + off, info->total_out,
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
	struct hizip_test_info *info = (struct hizip_test_info *)arg;
	struct test_options *copts = info->opts;
	struct priv_options *opts = info->popts;
	handle_t h_sess = info->h_sess;
	int j, ret;
	size_t left;

	stat_start(info);

	for (j = 0; j < copts->compact_run_num; j++) {
		if (opts->option & TEST_ZLIB) {
			ret = zlib_deflate(info->out_buf, info->total_len *
					   EXPANSION_RATIO, info->in_buf,
					   info->total_len, &info->total_out);
			continue;
		}
		/* not TEST_ZLIB */
		left = copts->total_len;
		info->req.src = info->in_buf;
		info->req.dst = info->out_buf;
		while (left > 0) {
			info->req.src_len = copts->block_size;
			info->req.dst_len = copts->block_size * EXPANSION_RATIO;
			info->req.cb = async_cb;
			info->req.cb_param = &info->req;
			if (copts->sync_mode) {
				count++;
				ret = wd_do_comp_async(h_sess, &info->req);
			} else {
				ret = wd_do_comp_sync(h_sess, &info->req);
			}
			if (ret < 0) {
				WD_ERR("do comp test fail with %d\n", ret);
				return NULL;
			}
			left -= copts->block_size;
			info->req.src += copts->block_size;
			/*
			 * It's BLOCK (STATELESS) mode, so user needs to
			 * combine output buffer by himself.
			 */
			info->req.dst += copts->block_size * EXPANSION_RATIO;
			info->total_out += info->req.dst_len;
		}
	}

	stat_end(info);
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

static void *poll_thread_func(void *arg)
{
	struct hizip_test_info *info = (struct hizip_test_info *)arg;
	int ret = 0, total = 0;
	__u32 expected = 0, received;

	if (!info->opts->sync_mode)
		return NULL;
	while (1) {
		if (info->faults & INJECT_SIG_WORK)
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
	stat_end(info);
	pthread_exit(NULL);
}

int create_threads(struct hizip_test_info *info)
{
	pthread_attr_t attr;
	int ret;

	count = 0;
	info->thread_attached = 0;
	info->thread_nums = 2;
	info->threads = calloc(1, info->thread_nums * sizeof(pthread_t));
	if (!info->threads)
		return -ENOMEM;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	/* polling thread is the first one */
	ret = pthread_create(&info->threads[0], &attr, poll_thread_func, info);
	if (ret < 0) {
		WD_ERR("fail to create poll thread (%d)\n", ret);
		return ret;
	}
	ret = pthread_create(&info->threads[1], &attr, send_thread_func, info);
	if (ret < 0)
		return ret;
	pthread_attr_destroy(&attr);
	g_conf = &info->ctx_conf;
	return 0;
}

int attach_threads(struct hizip_test_info *info)
{
	int ret;

	if (info->thread_attached)
		return 0;
	ret = pthread_join(info->threads[1], NULL);
	if (ret < 0)
		WD_ERR("Fail on send thread with %d\n", ret);
	ret = pthread_join(info->threads[0], NULL);
	if (ret < 0)
		WD_ERR("Fail on poll thread with %d\n", ret);
	info->thread_attached = 1;
	return 0;
}

/*
 * Choose a device and check whether it can afford the requested contexts.
 * Return a list whose the first device is chosen.
 */
struct uacce_dev_list *get_dev_list(struct priv_options *opts,
				    int children)
{
	struct uacce_dev_list *list, *p, *head = NULL, *prev = NULL;
	struct test_options *copts = &opts->common;
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
		if (max_q_num < 4 * copts->q_num * children) {
			if (!head)
				head = p;
			prev = p;
			p = p->next;
		} else
			break;
	}

	if (!p) {
		WD_ERR("Request too much contexts: %d\n",
		       copts->q_num * 4 * children);
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
	struct wd_comp_sess_setup setup;
	struct hizip_test_info *info = priv;
	struct wd_ctx_config *ctx_conf = &info->ctx_conf;
	int i, j, ret = -EINVAL;
	int q_num;


	*sched = sample_sched_alloc(SCHED_POLICY_RR, 2, 2, lib_poll_func);
	if (!*sched) {
		WD_ERR("sample_sched_alloc fail\n");
		goto out_sched;
	}
	q_num = opts->q_num;

	(*sched)->name = SCHED_RR_NAME;

	/*
	 * All contexts for 2 modes & 2 types.
	 * The test only uses one kind of contexts at the same time.
	 */
	ret = sample_sched_fill_data((const struct wd_sched*)*sched, 0, 0, 0,
				     0, q_num - 1);
	if (ret < 0) {
		WD_ERR("Fail to fill sched region.\n");
		goto out_fill;
	}
	ret = sample_sched_fill_data((const struct wd_sched*)*sched, 0, 0, 1,
				     q_num, q_num * 2 - 1);
	if (ret < 0) {
		WD_ERR("Fail to fill sched region.\n");
		goto out_fill;
	}
	ret = sample_sched_fill_data((const struct wd_sched*)*sched, 0, 1, 0,
				     q_num * 2, q_num * 3 - 1);
	if (ret < 0) {
		WD_ERR("Fail to fill sched region.\n");
		goto out_fill;
	}
	ret = sample_sched_fill_data((const struct wd_sched*)*sched, 0, 1, 1,
				     q_num * 3, q_num * 4 - 1);
	if (ret < 0) {
		WD_ERR("Fail to fill sched region.\n");
		goto out_fill;
	}

	memset(ctx_conf, 0, sizeof(struct wd_ctx_config));
	ctx_conf->ctx_num = q_num * 4;
	ctx_conf->ctxs = calloc(1, q_num * 4 * sizeof(struct wd_ctx));
	if (!ctx_conf->ctxs) {
		WD_ERR("Not enough memory to allocate contexts.\n");
		ret = -ENOMEM;
		goto out_fill;
	}
	for (i = 0; i < ctx_conf->ctx_num; i++) {
		ctx_conf->ctxs[i].ctx = wd_request_ctx(info->list->dev);
		if (!ctx_conf->ctxs[i].ctx) {
			WD_ERR("Fail to allocate context #%d\n", i);
			ret = -EINVAL;
			goto out_ctx;
		}
		ctx_conf->ctxs[i].op_type = opts->op_type;
		ctx_conf->ctxs[i].ctx_mode = opts->sync_mode;
	}
	wd_comp_init(ctx_conf, *sched);

	/* allocate a wd_comp session */
	memset(&setup, 0, sizeof(struct wd_comp_sess_setup));
	setup.alg_type = opts->alg_type;
	setup.mode = opts->sync_mode;
	setup.op_type = opts->op_type;
	info->h_sess = wd_comp_alloc_sess(&setup);
	if (!info->h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}

	return ret;

out_sess:
	wd_comp_uninit();
	i = ctx_conf->ctx_num;
out_ctx:
	for (j = 0; j < i; j++)
		wd_release_ctx(ctx_conf->ctxs[j].ctx);
	free(ctx_conf->ctxs);
out_fill:
	sample_sched_release(*sched);
out_sched:
	return ret;
}

void uninit_config(void *priv, struct wd_sched *sched)
{
	struct hizip_test_info *info = priv;
	struct wd_ctx_config *ctx_conf = &info->ctx_conf;
	int i;

	wd_comp_free_sess(info->h_sess);
	wd_comp_uninit();
	for (i = 0; i < ctx_conf->ctx_num; i++)
		wd_release_ctx(ctx_conf->ctxs[i].ctx);
	free(ctx_conf->ctxs);
	sample_sched_release(sched);
}

int hizip_test_sched(struct wd_sched *sched,
		     struct test_options *opts,
		     struct hizip_test_info *info
		     )
{
	handle_t h_sess = info->h_sess;
	//struct sched_key key;
	int ret;

	//key.numa_id = 0;
	//key.mode = opts->sync_mode;
	//key.type = 0;
	if (opts->sync_mode) {
		/* async */
		create_threads(info);
	} else {
		ret = wd_do_comp_sync(h_sess, &info->req);
		if (ret < 0)
			return ret;
		if (info->faults & INJECT_SIG_WORK)
			kill(getpid(), SIGTERM);
	}
	info->total_out = info->req.dst_len;
	return 0;
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
		 unsigned long *produced)
{
	int ret;
	z_stream stream = {
		.next_in	= input,
		.avail_in	= in_size,
		.next_out	= output,
		.avail_out	= out_size,
	};

	/* Window size of 15 for zlib */
	ret = deflateInit2(&stream, Z_BEST_SPEED, Z_DEFLATED, 15, 9,
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
