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

struct getcpu_cache {
	unsigned long blob[128/sizeof(long)];
};

typedef struct _thread_data_t {
	int     tid;
	int     flag;
	int	mode;	// BLOCK or STREAM
	struct wd_comp_arg	*arg;
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

static int init_config(int ctx_num, struct wd_sched *sched)
{
	int	ret, i;

	if (ctx_num <= 0)
		return -EINVAL;
	memset(&ctx_conf, 0, sizeof(struct wd_ctx_config));
	ctx_conf.ctx_num = ctx_num;
	ctx_conf.ctxs = calloc(1, sizeof(struct wd_comp_ctx) * ctx_num);
	if (!ctx_conf.ctxs)
		return -ENOMEM;
	for (i = 0; i < ctx_num; i++) {
		/* related ctx type is defined in testcase */
		ctx_conf.ctxs[i].ctx = wd_request_ctx(HISI_DEV_NODE);
		if (!ctx_conf.ctxs[i].ctx) {
			ret = -EINVAL;
			goto out;
		}
	}
	wd_comp_init(&ctx_conf, sched);
	return 0;
out:
	for (; i > 0; i--)
		wd_release_ctx(ctx_conf.ctxs[i].ctx);
	free(ctx_conf.ctxs);
	return ret;
}

static void uninit_config(void)
{
	int i;

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
	struct wd_comp_arg	wd_arg;
	handle_t	sess;
	char	algs[60];
	char	buf[TEST_WORD_LEN];
	void	*src, *dst;
	int	ret = 0, t;

	if (flag & FLAG_ZLIB)
		sprintf(algs, "zlib");
	else if (flag & FLAG_GZIP)
		sprintf(algs, "gzip");

	init_config(1, &sched);
	ctx_conf.ctxs[0].type = CTX_TYPE_COMP;

	memset(&wd_arg, 0, sizeof(struct wd_comp_arg));
	wd_arg.dst_len = sizeof(char) * TEST_WORD_LEN;
	wd_arg.src = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!wd_arg.src)
		return -ENOMEM;
	wd_arg.dst = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!wd_arg.dst) {
		ret = -ENOMEM;
		goto out;
	}
	src = wd_arg.src;
	dst = wd_arg.dst;
	memcpy(wd_arg.src, word, sizeof(char) * strlen(word));
	wd_arg.src_len = strlen(word);
	t = 0;

	memset(&setup, 0, sizeof(struct wd_comp_sess_setup));
	setup.mode = mode & MODE_STREAM;
	sess = wd_comp_alloc_sess(&setup);
	if (!sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	while (1) {
		wd_arg.status = 0;
		wd_arg.dst_len = TEST_WORD_LEN;
		wd_arg.flag = FLAG_DEFLATE | FLAG_INPUT_FINISH;
		ret = wd_comp_scompress(sess, &wd_arg);
		if (wd_arg.status & STATUS_OUT_READY) {
			memcpy(buf + t, wd_arg.dst - wd_arg.dst_len,
				wd_arg.dst_len);
			t += wd_arg.dst_len;
			wd_arg.dst = dst;
		}
		if ((wd_arg.status & STATUS_OUT_DRAINED) &&
		    (wd_arg.status & STATUS_IN_EMPTY) &&
		    (wd_arg.flag & FLAG_INPUT_FINISH))
			break;
	}
	wd_comp_free_sess(sess);
	uninit_config();

	/* prepare to decompress */
	wd_arg.src = src;
	memcpy(wd_arg.src, buf, t);
	wd_arg.src_len = t;
	wd_arg.dst = dst;
	t = 0;
	init_config(1, &sched);
	ctx_conf.ctxs[0].type = CTX_TYPE_DECOMP;

	memset(&setup, 0, sizeof(struct wd_comp_sess_setup));
	setup.mode = mode & MODE_STREAM;
	sess = wd_comp_alloc_sess(&setup);
	if (!sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	while (1) {
		wd_arg.status = 0;
		wd_arg.dst_len = TEST_WORD_LEN;
		wd_arg.flag = FLAG_INPUT_FINISH;
		ret = wd_comp_scompress(sess, &wd_arg);
		if (ret < 0)
			goto out_comp;
		if (wd_arg.status & STATUS_OUT_READY) {
			memcpy(buf + t, wd_arg.dst - wd_arg.dst_len,
				wd_arg.dst_len);
			t += wd_arg.dst_len;
			wd_arg.dst = dst;
		}
		if ((wd_arg.status & STATUS_OUT_DRAINED) &&
		    (wd_arg.status & STATUS_IN_EMPTY) &&
		    (wd_arg.flag & FLAG_INPUT_FINISH))
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
	free(wd_arg.src);
out:
	return ret;
}

int test_comp_async1_once(int flag, int mode)
{
	struct wd_comp_sess_setup	setup;
	struct wd_comp_arg	wd_arg;
	handle_t	sess;
	char	algs[60];
	char	buf[TEST_WORD_LEN];
	void	*src, *dst;
	int	ret = 0, t;

	if (flag & FLAG_ZLIB)
		sprintf(algs, "zlib");
	else if (flag & FLAG_GZIP)
		sprintf(algs, "gzip");

	init_config(1, &sched);
	ctx_conf.ctxs[0].type = CTX_TYPE_COMP;

	memset(&wd_arg, 0, sizeof(struct wd_comp_arg));
	wd_arg.dst_len = sizeof(char) * TEST_WORD_LEN;
	wd_arg.src = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!wd_arg.src)
		return -ENOMEM;
	wd_arg.dst = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!wd_arg.dst) {
		ret = -ENOMEM;
		goto out;
	}
	src = wd_arg.src;
	dst = wd_arg.dst;
	memcpy(wd_arg.src, word, sizeof(char) * strlen(word));
	wd_arg.src_len = strlen(word);
	t = 0;

	memset(&setup, 0, sizeof(struct wd_comp_sess_setup));
	setup.mode = mode & MODE_STREAM;
	sess = wd_comp_alloc_sess(&setup);
	if (!sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	while (1) {
		wd_arg.status = 0;
		wd_arg.dst_len = TEST_WORD_LEN;
		wd_arg.flag = FLAG_DEFLATE | FLAG_INPUT_FINISH;
		ret = wd_comp_acompress(sess, &wd_arg);
		if (ret < 0)
			goto out_comp;
		if (wd_arg.status & STATUS_OUT_READY) {
			memcpy(buf + t, wd_arg.dst - wd_arg.dst_len,
				wd_arg.dst_len);
			t += wd_arg.dst_len;
			wd_arg.dst = dst;
		}
		/* 1 block */
		ret = wd_comp_poll_ctx(ctx_conf.ctxs[0].ctx, 1);
		if (ret != 1) {
			ret = -EFAULT;
			goto out_comp;
		}
		if ((wd_arg.status & STATUS_OUT_DRAINED) &&
		    (wd_arg.status & STATUS_IN_EMPTY) &&
		    (wd_arg.flag & FLAG_INPUT_FINISH))
			break;
	}
	wd_comp_free_sess(sess);
	uninit_config();

	/* prepare to decompress */
	wd_arg.src = src;
	memcpy(wd_arg.src, buf, t);
	wd_arg.src_len = t;
	wd_arg.dst = dst;
	t = 0;
	init_config(1, &sched);
	ctx_conf.ctxs[0].type = CTX_TYPE_DECOMP;

	memset(&setup, 0, sizeof(struct wd_comp_sess_setup));
	setup.mode = mode & MODE_STREAM;
	sess = wd_comp_alloc_sess(&setup);
	if (!sess) {
		ret = -EINVAL;
		goto out_sess;
	}
	while (1) {
		wd_arg.status = 0;
		wd_arg.dst_len = TEST_WORD_LEN;
		wd_arg.flag = FLAG_INPUT_FINISH;
		ret = wd_comp_acompress(sess, &wd_arg);
		if (ret < 0)
			goto out_comp;
		if (wd_arg.status & STATUS_OUT_READY) {
			memcpy(buf + t, wd_arg.dst - wd_arg.dst_len,
				wd_arg.dst_len);
			t += wd_arg.dst_len;
			wd_arg.dst = dst;
		}
		/* 1 block */
		ret = wd_comp_poll_ctx(ctx_conf.ctxs[0].ctx, 1);
		if (ret != 1) {
			ret = -EFAULT;
			goto out_comp;
		}
		if ((wd_arg.status & STATUS_OUT_DRAINED) &&
		    (wd_arg.status & STATUS_IN_EMPTY) &&
		    (wd_arg.flag & FLAG_INPUT_FINISH))
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
	free(wd_arg.src);
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

	data->arg->status = 0;
	data->arg->dst_len = TEST_WORD_LEN;
	data->arg->flag = FLAG_INPUT_FINISH;
	ret = wd_comp_acompress(sess, data->arg);
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
static int create_threads(int mode, int wait_thr_num, struct wd_comp_arg *args)
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
		thr_data[i].arg = &args[i];
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
	struct wd_comp_arg	*arg;
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

	arg = calloc(1, sizeof(struct wd_comp_arg));
	if (!arg) {
		ret = -ENOMEM;
		goto out_arg;
	}
	arg->src_len = strlen(word);
	arg->dst_len = sizeof(char) * TEST_WORD_LEN;
	arg->src = src;
	arg->dst = dst;
	memcpy(arg->src, word, sizeof(char) * strlen(word));

	t = 0;

	init_config(1, &sched);
	ctx_conf.ctxs[0].type = CTX_TYPE_COMP;

	/* 1 thread for sending data, BLOCK mode */
	ret = create_threads(0, 1, arg);
	if (ret < 0) {
		goto out_thr;
	}
	if (arg->status & STATUS_OUT_READY) {
		memcpy(buf + t, arg->dst - arg->dst_len,
			arg->dst_len);
		t += arg->dst_len;
		arg->dst = dst;
	}

	uninit_config();

	/* prepare to decompress */
	arg->src = src;
	arg->dst = dst;
	memcpy(arg->src, buf, t);
	arg->src_len = t;
	arg->dst_len = TEST_WORD_LEN;
	t = 0;
	init_config(1, &sched);
	ctx_conf.ctxs[0].type = CTX_TYPE_DECOMP;

	/* 1 thread for sending data, BLOCK mode */
	ret = create_threads(0, 1, arg);
	if (ret < 0) {
		goto out_thr;
	}
	if (arg->status & STATUS_OUT_READY) {
		memcpy(buf + t, arg->dst - arg->dst_len,
			arg->dst_len);
		t += arg->dst_len;
		arg->dst = dst;
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
out_arg:
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
