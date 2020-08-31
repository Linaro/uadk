#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "wd_comp.h"
#include "wd_sched.h"

#define TEST_WORD_LEN	4096
#define BUF_8MB		(1 << 23)
#define BUF_16MB	(1 << 24)
#define BUF_32MB	(1 << 25)
#define BUF_64MB	(1 << 26)

#define	NUM_THREADS	10

#define FLAG_ZLIB	(1 << 0)
#define FLAG_GZIP	(1 << 1)

#define SCHED_SINGLE		"sched_single"
#define SCHED_NULL_CTX_SIZE	4	// sched_ctx_size can't be set as 0

#define RUN_TEST(func, name, flag, ret)			\
	do {						\
		char	str[60];			\
							\
		str[0] = '\0';				\
		strcpy(str, name);			\
		strcat(str, " with");			\
		if (flag & FLAG_ZLIB)			\
			strcat(str, " ZLIB.\n");	\
		else					\
			strcat(str, " GZIP.\n");	\
		ret = func(flag);			\
		if (ret < 0) {				\
			printf("Fail to run %s", str);	\
			return ret;			\
		}					\
		printf("Pass %s", str);			\
	} while (0)


struct getcpu_cache {
	unsigned long blob[128/sizeof(long)];
};

typedef struct _thread_data_t {
	int     tid;
	int     flag;
	int	mode;	// BLOCK or STREAM
	struct wd_comp_req	*req;
} thread_data_t;

static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int count = 0;

static char word[] = "go to test.";

static struct wd_ctx_config ctx_conf;
static struct wd_sched sched;

#if 0
/* get CPU and NUMA node information */
static int getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache)
{
	return syscall(SYS_getcpu, cpu, node, tcache);
}
#endif

/* only 1 context is used */
static handle_t sched_single_pick_next(const struct wd_ctx_config *cfg,
				       const void *req,
				       const struct sched_key *key)
{
	return ctx_conf.ctxs[0].ctx;
}

static int sched_single_poll_policy(const struct wd_ctx_config *cfg,
				    __u32 expect,
				    __u32 *count)
{
	int ret;

	*count = 0;
	ret = wd_comp_poll_ctx(ctx_conf.ctxs[0].ctx, 1, count);
	if (ret < 0)
		return ret;

	return 0;
}

/* init config for single context */
static int init_single_ctx_config(int op_type, int ctx_mode,
				  struct wd_sched *sched)
{
	struct uacce_dev_list *list;
	int ret;

	list = wd_get_accel_list("zlib");
	if (!list)
		return -ENODEV;

	memset(&ctx_conf, 0, sizeof(struct wd_ctx_config));
	ctx_conf.ctx_num = 1;
	ctx_conf.ctxs = calloc(1, sizeof(struct wd_ctx));
	if (!ctx_conf.ctxs)
		return -ENOMEM;

	/* Just use first found dev to test here */
	ctx_conf.ctxs[0].ctx = wd_request_ctx(list->dev);
	if (!ctx_conf.ctxs[0].ctx) {
		ret = -EINVAL;
		goto out;
	}
	ctx_conf.ctxs[0].op_type = op_type;
	ctx_conf.ctxs[0].ctx_mode = ctx_mode;

	sched->name = SCHED_SINGLE;
	sched->pick_next_ctx = sched_single_pick_next;
	sched->poll_policy = sched_single_poll_policy;
	wd_comp_init(&ctx_conf, sched);

	wd_free_list_accels(list);

	return 0;
out:
	free(ctx_conf.ctxs);
	return ret;
}

static void uninit_config(void)
{
	int i;

	wd_comp_uninit();
	for (i = 0; i < ctx_conf.ctx_num; i++)
		wd_release_ctx(ctx_conf.ctxs[i].ctx);
	free(ctx_conf.ctxs);
}

static handle_t alloc_sess(int flag, enum wd_comp_mode mode)
{
	struct wd_comp_sess_setup	setup;

	memset(&setup, 0, sizeof(struct wd_comp_sess_setup));
	if (flag & FLAG_ZLIB)
		setup.alg_type = WD_ZLIB;
	else if (flag & FLAG_GZIP)
		setup.alg_type = WD_GZIP;
	setup.mode = mode;
	return wd_comp_alloc_sess(&setup);
}

static int comp_sync(handle_t h_sess,
		     struct wd_comp_req *req,
		     int src_step,
		     int dst_step,
		     int src_len,
		     int *dst_len
		     )
{
	int templen = src_step;
	int i = 0, ret;

	if (!dst_len || !src_step || !dst_step || !src_len)
		return -EINVAL;
	*dst_len = 0;
	while (1) {
		req->flag = 0;
		req->status = 0;
		req->dst_len = dst_step;
		if (i + templen >= src_len) {
			templen = src_len - i;
			req->src_len = templen;
		} else if (i >= src_len)
			req->src_len = 0;
		else
			req->src_len = templen;
		if (!req->src_len)
			req->flag |= FLAG_INPUT_FINISH;

		ret = wd_do_comp_sync(h_sess, req);
		if (ret < 0)
			goto out;
		if (req->status & (STATUS_IN_EMPTY | STATUS_IN_PART_USE)) {
			if (i < src_len) {
				i += req->src_len;
				req->src += req->src_len;
				templen = src_step;
			} else {
				templen = 0;
			}
		}
		if (req->status & STATUS_OUT_READY) {
			req->dst += req->dst_len;
			*dst_len += req->dst_len;
		}
		if ((req->status & STATUS_OUT_DRAINED) &&
		    (req->status & STATUS_IN_EMPTY) &&
		    (req->flag & FLAG_INPUT_FINISH))
			return 0;
	}
out:
	return ret;
}

/*
 * Test to compress and decompress on IN & OUT buffer.
 * Data are filled in IN and OUT buffer only once.
 */
int test_comp_sync_once_1(int flag)
{
	struct wd_comp_req	req;
	handle_t	h_sess;
	void	*src, *dst;
	int	ret = 0, t, len;

	init_single_ctx_config(CTX_TYPE_COMP, CTX_MODE_SYNC, &sched);

	memset(&req, 0, sizeof(struct wd_comp_req));
	req.dst_len = sizeof(char) * TEST_WORD_LEN;
	req.src = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!req.src)
		return -ENOMEM;
	req.dst = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!req.dst) {
		ret = -ENOMEM;
		goto out;
	}
	src = req.src;
	dst = req.dst;
	memcpy(req.src, word, sizeof(char) * strlen(word));
	req.src_len = strlen(word);
	t = 0;

	h_sess = alloc_sess(flag, CTX_MODE_SYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	ret = comp_sync(h_sess,
			&req,
			TEST_WORD_LEN,
			TEST_WORD_LEN,
			strlen(word),
			&t
			);
	if (ret < 0)
		goto out_comp;
	wd_comp_free_sess(h_sess);
	uninit_config();

	/* prepare to decompress */
	req.src = src;
	memcpy(req.src, dst, t);
	req.src_len = t;
	req.dst = dst;
	len = 0;
	init_single_ctx_config(CTX_TYPE_DECOMP, CTX_MODE_SYNC, &sched);

	h_sess = alloc_sess(flag, CTX_MODE_SYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	ret = comp_sync(h_sess,
			&req,
			TEST_WORD_LEN,
			TEST_WORD_LEN,
			t,
			&len
			);
	if (ret < 0)
		goto out_comp;
	wd_comp_free_sess(h_sess);
	uninit_config();

	if (memcmp(dst, word, strlen(word))) {
		printf("match failure! word:%s, dst:%s\n", word, (char *)dst);
		ret = -EFAULT;
	}

	free(src);
	free(dst);
	return ret;
out_comp:
	wd_comp_free_sess(h_sess);
out_sess:
	free(req.src);
out:
	return ret;
}

int test_comp_sync_once_2(int flag)
{
	struct wd_comp_req	req;
	handle_t	h_sess;
	void	*src, *dst, *buf;
	int	ret = 0, t, len;

	init_single_ctx_config(CTX_TYPE_COMP, CTX_MODE_SYNC, &sched);

	memset(&req, 0, sizeof(struct wd_comp_req));
	src = calloc(1, sizeof(char) * BUF_64MB);
	if (!src)
		return -ENOMEM;
	dst = calloc(1, sizeof(char) * BUF_64MB);
	if (!dst) {
		ret = -ENOMEM;
		goto out;
	}
	buf = calloc(1, sizeof(char) * BUF_64MB);
	if (!buf) {
		ret = -ENOMEM;
		goto out_buf;
	}
	req.src = src;
	req.dst = buf;
	memcpy(req.src, word, sizeof(char) * strlen(word));
	t = 0;

	h_sess = alloc_sess(flag, CTX_MODE_SYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	ret = comp_sync(h_sess,
			&req,
			BUF_64MB,
			BUF_64MB,
			BUF_64MB,
			&t
			);
	if (ret < 0)
		goto out_comp;
	wd_comp_free_sess(h_sess);
	uninit_config();

	/* prepare to decompress */
	req.src = buf;
	req.src_len = t;
	req.dst = dst;
	len = 0;
	init_single_ctx_config(CTX_TYPE_DECOMP, CTX_MODE_SYNC, &sched);

	h_sess = alloc_sess(flag, CTX_MODE_SYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	ret = comp_sync(h_sess,
			&req,
			BUF_64MB,
			BUF_64MB,
			t,
			&len
			);
	if (ret < 0)
		goto out_comp;
	wd_comp_free_sess(h_sess);
	uninit_config();

	if (memcmp(dst, src, BUF_64MB)) {
		printf("match failure!\n");
		ret = -EFAULT;
	}
	free(buf);
	free(src);
	free(dst);

	return ret;
out_comp:
	wd_comp_free_sess(h_sess);
out_sess:
	free(buf);
out_buf:
	free(dst);
out:
	free(src);
	return ret;
}

int test_comp_sync_multi_1(int flag)
{
	struct wd_comp_req	req;
	handle_t	h_sess;
	void	*src, *dst;
	int	ret = 0, t, len;

	init_single_ctx_config(CTX_TYPE_COMP, CTX_MODE_SYNC, &sched);

	memset(&req, 0, sizeof(struct wd_comp_req));
	req.dst_len = sizeof(char) * TEST_WORD_LEN;
	req.src = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!req.src)
		return -ENOMEM;
	req.dst = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!req.dst) {
		ret = -ENOMEM;
		goto out;
	}
	src = req.src;
	dst = req.dst;
	memcpy(req.src, word, sizeof(char) * strlen(word));
	req.src_len = strlen(word);
	t = 0;

	h_sess = alloc_sess(flag, CTX_MODE_SYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	ret = comp_sync(h_sess,
			&req,
			1,
			TEST_WORD_LEN,
			strlen(word),
			&t
			);
	if (ret < 0)
		goto out_comp;
	wd_comp_free_sess(h_sess);
	uninit_config();

	/* prepare to decompress */
	req.src = src;
	memcpy(req.src, dst, t);
	req.src_len = t;
	req.dst = dst;
	len = 0;
	init_single_ctx_config(CTX_TYPE_DECOMP, CTX_MODE_SYNC, &sched);

	h_sess = alloc_sess(flag, CTX_MODE_SYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	ret = comp_sync(h_sess,
			&req,
			1,
			TEST_WORD_LEN,
			t,
			&len
			);
	if (ret < 0)
		goto out_comp;
	wd_comp_free_sess(h_sess);
	uninit_config();

	if (memcmp(dst, word, strlen(word))) {
		printf("match failure! word:%s, dst:%s\n", word, (char *)dst);
		ret = -EFAULT;
	}

	free(src);
	free(dst);
	return ret;
out_comp:
	wd_comp_free_sess(h_sess);
out_sess:
	free(req.src);
out:
	return ret;
}

int test_comp_sync_multi_2(int flag)
{
	struct wd_comp_req	req;
	handle_t	h_sess;
	void	*src, *dst;
	int	ret = 0, t, len;

	init_single_ctx_config(CTX_TYPE_COMP, CTX_MODE_SYNC, &sched);

	memset(&req, 0, sizeof(struct wd_comp_req));
	req.dst_len = sizeof(char) * TEST_WORD_LEN;
	req.src = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!req.src)
		return -ENOMEM;
	req.dst = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!req.dst) {
		ret = -ENOMEM;
		goto out;
	}
	src = req.src;
	dst = req.dst;
	memcpy(req.src, word, sizeof(char) * strlen(word));
	req.src_len = strlen(word);
	t = 0;

	h_sess = alloc_sess(flag, CTX_MODE_SYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	ret = comp_sync(h_sess,
			&req,
			TEST_WORD_LEN,
			1,
			strlen(word),
			&t
			);
	if (ret < 0)
		goto out_comp;
	wd_comp_free_sess(h_sess);
	uninit_config();

	/* prepare to decompress */
	req.src = src;
	memcpy(req.src, dst, t);
	req.src_len = t;
	req.dst = dst;
	len = 0;
	init_single_ctx_config(CTX_TYPE_DECOMP, CTX_MODE_SYNC, &sched);

	h_sess = alloc_sess(flag, CTX_MODE_SYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	ret = comp_sync(h_sess,
			&req,
			TEST_WORD_LEN,
			1,
			t,
			&len
			);
	if (ret < 0)
		goto out_comp;
	wd_comp_free_sess(h_sess);
	uninit_config();

	if (memcmp(dst, word, strlen(word))) {
		printf("match failure! word:%s, dst:%s\n", word, (char *)dst);
		ret = -EFAULT;
	}

	free(src);
	free(dst);
	return ret;
out_comp:
	wd_comp_free_sess(h_sess);
out_sess:
	free(req.src);
out:
	return ret;
}

int test_comp_sync_multi_3(int flag)
{
	struct wd_comp_req	req;
	handle_t	h_sess;
	void	*src, *dst;
	int	ret = 0, t, len;

	init_single_ctx_config(CTX_TYPE_COMP, CTX_MODE_SYNC, &sched);

	memset(&req, 0, sizeof(struct wd_comp_req));
	req.dst_len = sizeof(char) * TEST_WORD_LEN;
	req.src = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!req.src)
		return -ENOMEM;
	req.dst = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!req.dst) {
		ret = -ENOMEM;
		goto out;
	}
	src = req.src;
	dst = req.dst;
	memcpy(req.src, word, sizeof(char) * strlen(word));
	req.src_len = strlen(word);
	t = 0;

	h_sess = alloc_sess(flag, CTX_MODE_SYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	ret = comp_sync(h_sess,
			&req,
			1,
			1,
			strlen(word),
			&t
			);
	if (ret < 0)
		goto out_comp;
	wd_comp_free_sess(h_sess);
	uninit_config();

	/* prepare to decompress */
	req.src = src;
	memcpy(req.src, dst, t);
	req.src_len = t;
	req.dst = dst;
	len = 0;
	init_single_ctx_config(CTX_TYPE_DECOMP, CTX_MODE_SYNC, &sched);

	h_sess = alloc_sess(flag, CTX_MODE_SYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	ret = comp_sync(h_sess,
			&req,
			1,
			1,
			t,
			&len
			);
	if (ret < 0)
		goto out_comp;
	wd_comp_free_sess(h_sess);
	uninit_config();

	if (memcmp(dst, word, strlen(word))) {
		printf("match failure! word:%s, dst:%s\n", word, (char *)dst);
		ret = -EFAULT;
	}

	free(src);
	free(dst);
	return ret;
out_comp:
	wd_comp_free_sess(h_sess);
out_sess:
	free(req.src);
out:
	return ret;
}

/*
 * Test to compress and decompress steram.
 * long buffer can spilt to small package.
 */
int test_comp_stream(int flag)
{
	struct wd_comp_req	req;
	handle_t	h_sess;
	char	buf[TEST_WORD_LEN];
	void	*src, *dst;
	int	ret = 0, t;

	init_single_ctx_config(CTX_TYPE_COMP, CTX_MODE_SYNC, &sched);

	memset(&req, 0, sizeof(struct wd_comp_req));
	req.dst_len = sizeof(char) * TEST_WORD_LEN;
	req.src = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!req.src)
		return -ENOMEM;
	req.dst = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!req.dst) {
		ret = -ENOMEM;
		goto out;
	}
	src = req.src;
	dst = req.dst;
	memcpy(req.src, word, sizeof(char) * strlen(word));
	req.src_len = strlen(word);
	t = 0;

	h_sess = alloc_sess(flag, CTX_MODE_SYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	while (1) {
		req.status = 0;
		req.dst_len = TEST_WORD_LEN;
		req.op_type = CTX_TYPE_COMP;
		req.last = 1;
		//req.flag = FLAG_DEFLATE | FLAG_INPUT_FINISH;
		ret = wd_do_comp_strm(h_sess, &req);
		if (ret) {
			printf("err, do_comp_strm ret =%d\n", ret);
			break;
		}
		if (!req.status ) {
			memcpy(buf + t, req.dst, req.dst_len);
			t += req.dst_len;
			req.dst = dst;
			break;
		}
	}
	wd_comp_free_sess(h_sess);
	uninit_config();

	/* prepare to decompress */
	req.src = src;
	memcpy(req.src, buf, t);
	req.src_len = t;
	req.dst = dst;
	t = 0;
	init_single_ctx_config(CTX_TYPE_DECOMP, CTX_MODE_SYNC, &sched);

	h_sess = alloc_sess(flag, CTX_MODE_SYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	while (1) {
		req.status = 0;
		req.dst_len = TEST_WORD_LEN;
		req.op_type = CTX_TYPE_DECOMP;
		req.last = 1;
		//req.flag = FLAG_INPUT_FINISH;
		ret = wd_do_comp_strm(h_sess, &req);
		if (ret < 0) {
			printf("err, do_comp_strm ret =%d\n", ret);
			goto out_comp;
		}
		if (!ret) {
			memcpy(buf + t, req.dst, req.dst_len);
			t += req.dst_len;
			req.dst = dst;
			break;
		}
	}
	wd_comp_free_sess(h_sess);
	uninit_config();

	if (memcmp(buf, word, strlen(word))) {
		printf("stream match failure! word:%s, buf:%s\n", word, buf);
		ret = -EFAULT;
	} else {
		printf("Pass compress stream test!\n");
	}

	free(src);
	free(dst);
	return ret;
out_comp:
	wd_comp_free_sess(h_sess);
out_sess:
	free(req.src);
out:
	return ret;
}

static void *async_cb(struct wd_comp_req *req, void *data)
{
	thread_data_t *thr = (thread_data_t *)data;
	struct wd_comp_req *thr_req = thr->req;

	thr_req->status = req->status;
	thr_req->src_len = req->src_len;
	thr_req->dst_len = req->dst_len;

	return NULL;
}

int test_comp_async1_once(int flag)
{
	struct wd_comp_req req;
	handle_t	h_sess;
	char	buf[TEST_WORD_LEN];
	void	*src, *dst;
	int	ret = 0, t;
	__u32	expected = 1;
	thread_data_t	data;

	memset(&data, 0, sizeof(thread_data_t));
	data.req = &req;
	data.tid = 0;

	init_single_ctx_config(CTX_TYPE_COMP, CTX_MODE_ASYNC, &sched);

	memset(&req, 0, sizeof(struct wd_comp_req));
	req.dst_len = sizeof(char) * TEST_WORD_LEN;
	req.src = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!req.src)
		return -ENOMEM;
	req.dst = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!req.dst) {
		ret = -ENOMEM;
		goto out;
	}
	src = req.src;
	dst = req.dst;
	memcpy(req.src, word, sizeof(char) * strlen(word));
	req.src_len = strlen(word);
	t = 0;

	h_sess = alloc_sess(flag, CTX_MODE_ASYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	while (1) {
		req.status = 0;
		req.dst_len = TEST_WORD_LEN;
		req.flag = FLAG_DEFLATE | FLAG_INPUT_FINISH;
		req.cb = async_cb;
		req.cb_param = &data;
		ret = wd_do_comp_async(h_sess, &req);
		if (ret < 0)
			goto out_comp;
		/* 1 block */
		expected = 1;
		ret = wd_comp_poll(&expected);
		if (ret < 0)
			goto out_comp;
		if (req.status & STATUS_OUT_READY) {
			memcpy(buf + t, req.dst, req.dst_len);
			t += req.dst_len;
			req.dst = dst;
		}
		if ((req.status & STATUS_OUT_DRAINED) &&
		    (req.status & STATUS_IN_EMPTY) &&
		    (req.flag & FLAG_INPUT_FINISH))
			break;
	}
	wd_comp_free_sess(h_sess);
	uninit_config();

	/* prepare to decompress */
	req.src = src;
	memcpy(req.src, buf, t);
	req.src_len = t;
	req.dst = dst;
	t = 0;
	init_single_ctx_config(CTX_TYPE_DECOMP, CTX_MODE_ASYNC, &sched);

	h_sess = alloc_sess(flag, CTX_MODE_ASYNC);
	if (!h_sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	while (1) {
		req.status = 0;
		req.dst_len = TEST_WORD_LEN;
		req.flag = FLAG_INPUT_FINISH;
		req.cb = async_cb;
		req.cb_param = &data;
		ret = wd_do_comp_async(h_sess, &req);
		if (ret < 0)
			goto out_comp;
		/* 1 block */
		expected = 1;
		ret = wd_comp_poll(&expected);
		if (ret < 0)
			goto out_comp;
		if (req.status & STATUS_OUT_READY) {
			memcpy(buf + t, req.dst, req.dst_len);
			t += req.dst_len;
			req.dst = dst;
		}
		if ((req.status & STATUS_OUT_DRAINED) &&
		    (req.status & STATUS_IN_EMPTY) &&
		    (req.flag & FLAG_INPUT_FINISH))
			break;
	}
	wd_comp_free_sess(h_sess);
	uninit_config();

	if (memcmp(buf, word, strlen(word))) {
		printf("match failure! word:%s, buf:%s\n", word, buf);
		ret = -EFAULT;
	}

	free(src);
	free(dst);
	return ret;
out_comp:
	wd_comp_free_sess(h_sess);
out_sess:
	free(req.src);
out:
	return ret;
}

static void *poll_func(void *arg)
{
	int i, ret = 0, received = 0;
	__u32 expected = 0;

	usleep(200);
	while (1) {
		pthread_mutex_lock(&mutex);
		if (!expected)
			expected = 1;
		if (count == 0) {
			pthread_cond_broadcast(&cond);
			pthread_mutex_unlock(&mutex);
			usleep(10);
			continue;
		}
		for (i = 0; i < ctx_conf.ctx_num; i++) {
			expected = 1;
			ret = wd_comp_poll(&expected);
			if (ret == 0)
				received += expected;
		}
		pthread_cond_broadcast(&cond);
		if (count == received) {
			pthread_mutex_unlock(&mutex);
			break;
		} else {
			if (count > received)
				expected = count - received;
			pthread_mutex_unlock(&mutex);
			usleep(10);
		}
	}
	pthread_exit(NULL);
}

static void *wait_func(void *arg)
{
	thread_data_t *data = (thread_data_t *)arg;
	struct wd_comp_req	*req = data->req;
	handle_t	h_sess;
	int	ret = 0;

	h_sess = alloc_sess(data->flag, CTX_MODE_ASYNC);
	if (!h_sess)
		goto out;

	pthread_mutex_lock(&mutex);
	pthread_cond_wait(&cond, &mutex);
	ret = wd_do_comp_async(h_sess, req);
	if (ret < 0)
		goto out_comp;
	/* count means data block numbers */
	count++;

out_comp:
	pthread_mutex_unlock(&mutex);
	/* wait to avoid data broken */
	usleep(10);

	wd_comp_free_sess(h_sess);
out:
	pthread_exit(NULL);
}

/*
 * Create threads for (wait_thr_num + 1) times.
 * 1 is for polling HW, and the others are sending data to HW.
 * The size of args[] equals to wait_thr_num.
 */
static int create_threads(int flag, int wait_thr_num, struct wd_comp_req *reqs)
{
	pthread_t thr[NUM_THREADS];
	pthread_attr_t attr;
	thread_data_t thr_data[NUM_THREADS];
	int i, ret;

	if (wait_thr_num > NUM_THREADS - 1) {
		printf("Can't create %d threads.\n", wait_thr_num + 1);
		return -EINVAL;
	}

	count = 0;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	for (i = 0; i < wait_thr_num; i++) {
		reqs[i].cb_param = &thr_data[i];
		thr_data[i].tid = i;
		thr_data[i].req = &reqs[i];
		thr_data[i].flag = flag;
		ret = pthread_create(&thr[i], &attr, wait_func, &thr_data[i]);
		if (ret) {
			printf("Failed to create thread, ret:%d\n", ret);
			return ret;
		}
	}
	/* polling thread */
	thr_data[i].tid = i;
	ret = pthread_create(&thr[i], &attr, poll_func, &thr_data[i]);
	if (ret) {
		printf("Failed to create thread, ret:%d\n", ret);
		return ret;
	}
	pthread_attr_destroy(&attr);
	for (i = 0; i < wait_thr_num + 1; i++) {
		pthread_join(thr[i], NULL);
	}
	return 0;
}

/*
 * Create ten threads. Nine threads are compressing/decompressing, and the other
 * is polling.
 */
int test_comp_async2_once(int flag)
{
	struct wd_comp_req	req[NUM_THREADS];
	void	*src, *dst;
	char	*buf;
	int	ret = 0, step, i;
	/* parallel means the number of sending threads */
	int	parallel = NUM_THREADS - 1;

	if (NUM_THREADS < 2)
		return -EINVAL;

	step = sizeof(char) * TEST_WORD_LEN;
	src = calloc(1, step * NUM_THREADS);
	if (!src)
		return -ENOMEM;
	dst = calloc(1, step * NUM_THREADS);
	if (!dst) {
		ret = -ENOMEM;
		goto out;
	}
	memset(&req, 0, sizeof(struct wd_comp_req) * NUM_THREADS);
	for (i = 0; i < parallel; i++) {
		req[i].src = src + (step * i);
		req[i].dst = dst + (step * i);
		memcpy(req[i].src, word, strlen(word));
		req[i].src_len = strlen(word);
		req[i].dst_len = step;
		req[i].cb = async_cb;
		req[i].cb_param = NULL;	// updated in create_threads()
		req[i].status = 0;
		req[i].flag = FLAG_INPUT_FINISH;
	}

	init_single_ctx_config(CTX_TYPE_COMP, CTX_MODE_ASYNC, &sched);

	/* 9 threads for sending data, BLOCK mode */
	ret = create_threads(flag, parallel, req);
	if (ret < 0) {
		goto out_thr;
	}
	for (i = 0; i < parallel; i++) {
		if (req[i].status & STATUS_OUT_READY) {
			/* use compressed data */
			memcpy(req[i].src, req[i].dst, req[i].dst_len);
			req[i].src_len = req[i].dst_len;
			req[i].dst_len = step;
		} else {
			ret = -EFAULT;
			goto out_thr;
		}
	}

	uninit_config();

	/* prepare to decompress */
	init_single_ctx_config(CTX_TYPE_DECOMP, CTX_MODE_ASYNC, &sched);
	/* 9 thread for sending data, BLOCK mode */
	ret = create_threads(flag, parallel, req);
	if (ret < 0) {
		goto out_thr;
	}
	for (i = 0; i < parallel; i++) {
		if ((req[i].status & STATUS_OUT_READY) == 0) {
			ret = -EFAULT;
			goto out_thr;
		}
		buf = (char *)req[i].dst;
		if (memcmp(buf, word, strlen(word))) {
			ret = -EFAULT;
			printf("match failure! word:%s, out:%s\n", word, buf);
			goto out_thr;
		}
	}

	uninit_config();

	free(src);
	free(dst);
	return 0;
out_thr:
	uninit_config();
	free(dst);
	free(src);
out:
	return ret;
}

int main(int argc, char **argv)
{
	int ret;

	RUN_TEST(test_comp_sync_once_1, "sync_once #1", FLAG_ZLIB, ret);
	RUN_TEST(test_comp_stream, "stream_once #1", FLAG_ZLIB, ret);
#if 0
	RUN_TEST(test_comp_sync_multi_1, "sync_multi 1", FLAG_ZLIB, ret);
	RUN_TEST(test_comp_sync_multi_2, "sync_multi 2", FLAG_ZLIB, ret);
	RUN_TEST(test_comp_sync_multi_3, "sync_multi 3", FLAG_ZLIB, ret);
#endif
	RUN_TEST(test_comp_async1_once, "async 1", FLAG_ZLIB, ret);
	RUN_TEST(test_comp_async2_once, "async 2", FLAG_ZLIB, ret);
	RUN_TEST(test_comp_sync_once_2, "sync_once #2", FLAG_ZLIB, ret);
	
	return 0;
}
