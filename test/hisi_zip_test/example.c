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

#define TEST_WORD_LEN	64

#define	NUM_THREADS	10

#define HISI_DEV_NODE	"/dev/hisi_zip-0"

#define FLAG_ZLIB	(1 << 0)
#define FLAG_GZIP	(1 << 1)

#define SCHED_SINGLE		"sched_single"
#define SCHED_NULL_CTX_SIZE	4	// sched_ctx_size can't be set as 0

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
static handle_t sched_single_pick_next(struct wd_ctx_config *cfg,
				       void *sched_ctx,
				       struct wd_comp_req *req, int numa_id)
{
	return ctx_conf.ctxs[0].ctx;
}

static __u32 sched_single_poll_policy(struct wd_ctx_config *cfg,
				      void *sched_ctx)
{
	return 0;
}

/* init config for single context */
static int init_single_ctx_config(int op_type, int ctx_mode,
				  struct wd_sched *sched)
{
	int ret;

	memset(&ctx_conf, 0, sizeof(struct wd_ctx_config));
	ctx_conf.ctx_num = 1;
	ctx_conf.ctxs = calloc(1, sizeof(struct wd_ctx));
	if (!ctx_conf.ctxs)
		return -ENOMEM;
	ctx_conf.ctxs[0].ctx = wd_request_ctx(HISI_DEV_NODE);
	if (!ctx_conf.ctxs[0].ctx) {
		ret = -EINVAL;
		goto out;
	}
	ctx_conf.ctxs[0].op_type = op_type;
	ctx_conf.ctxs[0].ctx_mode = ctx_mode;

	sched->name = SCHED_SINGLE;
	sched->sched_ctx_size = SCHED_NULL_CTX_SIZE;
	sched->pick_next_ctx = sched_single_pick_next;
	sched->poll_policy = sched_single_poll_policy;
	wd_comp_init(&ctx_conf, sched);
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

/*
 * Test to compress and decompress on IN & OUT buffer.
 * Data are filled in IN and OUT buffer only once.
 */
int test_comp_sync_once(int flag, int mode)
{
	struct wd_comp_sess_setup	setup;
	struct wd_comp_req	req;
	handle_t	sess;
	char	algs[60];
	char	buf[TEST_WORD_LEN];
	void	*src, *dst;
	int	ret = 0, t;

	if (flag & FLAG_ZLIB)
		sprintf(algs, "zlib");
	else if (flag & FLAG_GZIP)
		sprintf(algs, "gzip");

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

	memset(&setup, 0, sizeof(struct wd_comp_sess_setup));
	setup.mode = mode & MODE_STREAM;
	sess = wd_comp_alloc_sess(&setup);
	if (!sess) {
		ret = -EINVAL;
		goto out_sess;
	}
#if 0
	while (1) {
		req.status = 0;
		req.dst_len = TEST_WORD_LEN;
		req.flag = FLAG_DEFLATE | FLAG_INPUT_FINISH;
		ret = wd_do_comp(sess, &req);
		if (req.status & STATUS_OUT_READY) {
			memcpy(buf + t, req.dst - req.dst_len,
				req.dst_len);
			t += req.dst_len;
			req.dst = dst;
		}
		if ((req.status & STATUS_OUT_DRAINED) &&
		    (req.status & STATUS_IN_EMPTY) &&
		    (req.flag & FLAG_INPUT_FINISH))
			break;
	}
#else
		req.status = 0;
		req.dst_len = TEST_WORD_LEN;
		req.flag = FLAG_DEFLATE | FLAG_INPUT_FINISH;
		ret = wd_do_comp(sess, &req);
#endif
	wd_comp_free_sess(sess);
	uninit_config();

	/* prepare to decompress */
	req.src = src;
	memcpy(req.src, buf, t);
	req.src_len = t;
	req.dst = dst;
	t = 0;
	init_single_ctx_config(CTX_TYPE_DECOMP, CTX_MODE_SYNC, &sched);

	memset(&setup, 0, sizeof(struct wd_comp_sess_setup));
	setup.mode = mode & MODE_STREAM;
	sess = wd_comp_alloc_sess(&setup);
	if (!sess) {
		ret = -EINVAL;
		goto out_sess;
	}
#if 0
	while (1) {
		req.status = 0;
		req.dst_len = TEST_WORD_LEN;
		req.flag = FLAG_INPUT_FINISH;
		ret = wd_do_comp(sess, &req);
		if (ret < 0)
			goto out_comp;
		if (req.status & STATUS_OUT_READY) {
			memcpy(buf + t, req.dst - req.dst_len,
				req.dst_len);
			t += req.dst_len;
			req.dst = dst;
		}
		if ((req.status & STATUS_OUT_DRAINED) &&
		    (req.status & STATUS_IN_EMPTY) &&
		    (req.flag & FLAG_INPUT_FINISH))
			break;
	}
#else
		req.status = 0;
		req.dst_len = TEST_WORD_LEN;
		req.flag = FLAG_INPUT_FINISH;
		ret = wd_do_comp(sess, &req);
		if (ret < 0)
			goto out_comp;
#endif
	wd_comp_free_sess(sess);
	uninit_config();

	if (memcmp(buf, word, strlen(word))) {
		printf("match failure! word:%s, buf:%s\n", word, buf);
	} else {
		if (mode & MODE_STREAM)
			snprintf(buf, TEST_WORD_LEN, "with STREAM mode.");
		else
			snprintf(buf, TEST_WORD_LEN, "with BLOCK mode.");
		printf("Pass compress test in single buffer %s\n", buf);
	}

	free(src);
	free(dst);
	return 0;
out_comp:
	wd_comp_free_sess(sess);
out_sess:
	free(req.src);
out:
	return ret;
}

int test_comp_async1_once(int flag, int mode)
{
	struct wd_comp_sess_setup	setup;
	struct wd_comp_req req;
	handle_t	sess;
	char	algs[60];
	char	buf[TEST_WORD_LEN];
	void	*src, *dst;
	int	ret = 0, t;

	if (flag & FLAG_ZLIB)
		sprintf(algs, "zlib");
	else if (flag & FLAG_GZIP)
		sprintf(algs, "gzip");

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

	memset(&setup, 0, sizeof(struct wd_comp_sess_setup));
	setup.mode = mode & MODE_STREAM;
	sess = wd_comp_alloc_sess(&setup);
	if (!sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	while (1) {
		req.status = 0;
		req.dst_len = TEST_WORD_LEN;
		req.flag = FLAG_DEFLATE | FLAG_INPUT_FINISH;
		ret = wd_do_comp_async(sess, &req);
		if (ret < 0)
			goto out_comp;
		if (req.status & STATUS_OUT_READY) {
			memcpy(buf + t, req.dst - req.dst_len,
				req.dst_len);
			t += req.dst_len;
			req.dst = dst;
		}
		/* 1 block */
		ret = wd_comp_poll_ctx(ctx_conf.ctxs[0].ctx, 1);
		if (ret != 1) {
			ret = -EFAULT;
			goto out_comp;
		}
		if ((req.status & STATUS_OUT_DRAINED) &&
		    (req.status & STATUS_IN_EMPTY) &&
		    (req.flag & FLAG_INPUT_FINISH))
			break;
	}
	wd_comp_free_sess(sess);
	uninit_config();

	/* prepare to decompress */
	req.src = src;
	memcpy(req.src, buf, t);
	req.src_len = t;
	req.dst = dst;
	t = 0;
	init_single_ctx_config(CTX_TYPE_DECOMP, CTX_MODE_SYNC, &sched);

	memset(&setup, 0, sizeof(struct wd_comp_sess_setup));
	setup.mode = mode & MODE_STREAM;
	sess = wd_comp_alloc_sess(&setup);
	if (!sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	while (1) {
		req.status = 0;
		req.dst_len = TEST_WORD_LEN;
		req.flag = FLAG_INPUT_FINISH;
		ret = wd_do_comp_async(sess, &req);
		if (ret < 0)
			goto out_comp;
		if (req.status & STATUS_OUT_READY) {
			memcpy(buf + t, req.dst - req.dst_len,
				req.dst_len);
			t += req.dst_len;
			req.dst = dst;
		}
		/* 1 block */
		ret = wd_comp_poll_ctx(ctx_conf.ctxs[0].ctx, 1);
		if (ret != 1) {
			ret = -EFAULT;
			goto out_comp;
		}
		if ((req.status & STATUS_OUT_DRAINED) &&
		    (req.status & STATUS_IN_EMPTY) &&
		    (req.flag & FLAG_INPUT_FINISH))
			break;
	}
	wd_comp_free_sess(sess);

	if (memcmp(buf, word, strlen(word))) {
		printf("match failure! word:%s, buf:%s\n", word, buf);
	} else {
		if (mode & MODE_STREAM)
			snprintf(buf, TEST_WORD_LEN, "with STREAM mode.");
		else
			snprintf(buf, TEST_WORD_LEN, "with BLOCK mode.");
		printf("Pass compress test in single buffer %s\n", buf);
	}

	free(src);
	free(dst);
	return 0;
out_comp:
	wd_comp_free_sess(sess);
out_sess:
	free(req.src);
out:
	return ret;
}

static void *poll_func(void *arg)
{
	int i, ret = 0, received = 0, expected = 0;

	while (1) {
		if (!expected)
			expected = 1;
		for (i = 0; i < ctx_conf.ctx_num; i++) {
			ret = wd_comp_poll_ctx(ctx_conf.ctxs[i].ctx, expected);
			if (ret > 0)
				received += ret;
		}
		pthread_mutex_lock(&mutex);
		pthread_cond_broadcast(&cond);
		if (count == received) {
			pthread_mutex_unlock(&mutex);
			break;
		} else {
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
	struct wd_comp_sess_setup	setup;
	handle_t	sess;
	int	ret = 0;

	memset(&setup, 0, sizeof(struct wd_comp_sess_setup));
	setup.mode = data->mode & MODE_STREAM;
	sess = wd_comp_alloc_sess(&setup);
	if (!sess)
		goto out;

	data->req->status = 0;
	data->req->dst_len = TEST_WORD_LEN;
	data->req->flag = FLAG_INPUT_FINISH;
	ret = wd_do_comp_async(sess, data->req);
	if (ret < 0)
		goto out_comp;
	pthread_mutex_lock(&mutex);
	pthread_cond_wait(&cond, &mutex);
	/* count means data block numbers */
	count++;
	pthread_mutex_unlock(&mutex);

out_comp:
	wd_comp_free_sess(sess);
out:
	pthread_exit(NULL);
}

/*
 * Create threads for (wait_thr_num + 1) times.
 * 1 is for polling HW, and the others are sending data to HW.
 * The size of args[] equals to wait_thr_num.
 */
static int create_threads(int mode, int wait_thr_num, struct wd_comp_req *reqs)
{
	pthread_t thr[NUM_THREADS];
	pthread_attr_t attr;
	thread_data_t thr_data[NUM_THREADS];
	int i, ret;

	if (wait_thr_num >= NUM_THREADS - 1) {
		printf("Can't create %d threads.\n", wait_thr_num + 1);
		return -EINVAL;
	}

	count = 0;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	for (i = 0; i < wait_thr_num; i++) {
		thr_data[i].tid = i;
		thr_data[i].req = &reqs[i];
		thr_data[i].mode = mode & MODE_STREAM;
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
	for (i = 0; i < NUM_THREADS; i++) {
		pthread_join(thr[i], NULL);
	}
	return 0;
}

/*
 * Create two threads. One is compressing/decompressing, and the other
 * is polling.
 */
int test_comp_async2_once(int flag, int mode)
{
	struct wd_comp_req	*req;
	char	algs[60];
	char	buf[TEST_WORD_LEN];
	void	*src, *dst;
	int	ret = 0, t;

	if (flag & FLAG_ZLIB)
		sprintf(algs, "zlib");
	else if (flag & FLAG_GZIP)
		sprintf(algs, "gzip");

	src = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!src) {
		ret = -ENOMEM;
		goto out;
	}
	dst = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!dst) {
		ret = -ENOMEM;
		goto out_dst;
	}

	req = calloc(1, sizeof(struct wd_comp_req));
	if (!req) {
		ret = -ENOMEM;
		goto out_req;
	}
	req->src_len = strlen(word);
	req->dst_len = sizeof(char) * TEST_WORD_LEN;
	req->src = src;
	req->dst = dst;
	memcpy(req->src, word, sizeof(char) * strlen(word));

	t = 0;

	init_single_ctx_config(CTX_TYPE_COMP, CTX_MODE_SYNC, &sched);

	/* 1 thread for sending data, BLOCK mode */
	ret = create_threads(0, 1, req);
	if (ret < 0) {
		goto out_thr;
	}
	if (req->status & STATUS_OUT_READY) {
		memcpy(buf + t, req->dst - req->dst_len,
			req->dst_len);
		t += req->dst_len;
		req->dst = dst;
	}

	uninit_config();

	/* prepare to decompress */
	req->src = src;
	req->dst = dst;
	memcpy(req->src, buf, t);
	req->src_len = t;
	req->dst_len = TEST_WORD_LEN;
	t = 0;
	init_single_ctx_config(CTX_TYPE_DECOMP, CTX_MODE_SYNC, &sched);
	ctx_conf.ctxs[0].op_type = CTX_TYPE_DECOMP;

	/* 1 thread for sending data, BLOCK mode */
	ret = create_threads(0, 1, req);
	if (ret < 0) {
		goto out_thr;
	}
	if (req->status & STATUS_OUT_READY) {
		memcpy(buf + t, req->dst - req->dst_len,
			req->dst_len);
		t += req->dst_len;
		req->dst = dst;
	}

	uninit_config();

	if (memcmp(buf, word, strlen(word))) {
		printf("match failure! word:%s, buf:%s\n", word, buf);
	} else {
		if (mode & MODE_STREAM)
			snprintf(buf, TEST_WORD_LEN, "with STREAM mode.");
		else
			snprintf(buf, TEST_WORD_LEN, "with BLOCK mode.");
		printf("Pass compress test in single buffer %s\n", buf);
	}

	free(src);
	free(dst);
	return 0;
out_thr:
	uninit_config();
out_req:
	free(dst);
out_dst:
	free(src);
out:
	return ret;
}

int main(int argc, char **argv)
{
	int ret;

	ret = test_comp_sync_once(FLAG_ZLIB, 0);
	if (ret < 0) {
		printf("Fail to run test_comp_sync_once() with ZLIB in "
			"BLOCK mode.\n");
		return ret;
	}
	ret = test_comp_async1_once(FLAG_ZLIB, 0);
	if (ret < 0) {
		printf("Fail to run test_comp_async1_once() with ZLIB in "
			"BLOCK mode.\n");
		return ret;
	}
	ret = test_comp_async2_once(FLAG_ZLIB, 0);
	if (ret < 0) {
		printf("Fail to run test_comp_async2_once() with ZLIB in "
			"BLOCK mode.\n");
		return ret;
	}
	return 0;
}
