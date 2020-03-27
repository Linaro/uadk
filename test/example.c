#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "wd_comp.h"

#define PATHLEN		256

#define FLAG_ZLIB	(1 << 0)
#define FLAG_GZIP	(1 << 1)
#define FLAG_DECMPS	(1 << 2)
#define FLAG_STREAM	(1 << 3)

#define	NUM_THREADS	32

#define TEST_WORD_LEN	64
#define TEST_LARGE_BUF_LEN	((1 << 21) | (1 << 20))
#define LARGE_BUF_SIZE	(1 << 20)

typedef struct _thread_data_t {
	int	tid;
	int	flag;
	struct wd_comp_arg	wd_arg;
} thread_data_t;

static char word[] = "go to test.";

static int thread_fail = 0;

/*
 * Test input buffer as 1-byte long, and output buffer is large.
 * TODO: Set output buffer as 1-byte long, too.
 */
int test_small_buffer(int flag, int mode)
{
	handler_t	handle;
	struct wd_comp_arg wd_arg;
	char	algs[60];
	char	buf[TEST_WORD_LEN];
	int	ret = 0, i, len;

	if (flag & FLAG_ZLIB)
		sprintf(algs, "zlib");
	else if (flag & FLAG_GZIP)
		sprintf(algs, "gzip");
	memset(&wd_arg, 0, sizeof(struct wd_comp_arg));
	wd_arg.dst_len = sizeof(char) * TEST_WORD_LEN;
	wd_arg.src = malloc(sizeof(char) * TEST_WORD_LEN);
	wd_arg.flag = FLAG_DEFLATE;
	if (!wd_arg.src) {
		ret = -ENOMEM;
		goto out;
	}
	wd_arg.dst = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!wd_arg.dst) {
		ret = -ENOMEM;
		goto out_dst;
	}
	handle = wd_alg_comp_alloc_sess(algs, mode & MODE_STREAM, NULL);
	for (i = 0; i < strlen(word); i++) {
		memcpy(wd_arg.src, &word[i], sizeof(char));
		wd_arg.src_len = 1;
		wd_arg.dst_len = sizeof(char) * TEST_WORD_LEN;
		if (i == (strlen(word) - 1))
			wd_arg.flag |= FLAG_INPUT_FINISH;
		ret = wd_alg_compress(handle, &wd_arg);
		if (ret < 0)
			goto out_comp;
		if ((i != strlen(word) - 1) && wd_arg.dst_len) {
			fprintf(stderr, "err on dst_len:%ld\n", wd_arg.dst_len);
			ret = -EFAULT;
			goto out_comp;
		}
	}
	wd_alg_comp_free_sess(handle);

	/* prepare for decompress */
	memcpy(buf, wd_arg.dst, sizeof(char) * TEST_WORD_LEN);
	len = wd_arg.dst_len;
	wd_arg.flag = 0;

	handle = wd_alg_comp_alloc_sess(algs, mode & MODE_STREAM, NULL);
	for (i = 0; i < len; i++) {
		memcpy(wd_arg.src, &buf[i], sizeof(char));
		wd_arg.src_len = 1;
		wd_arg.dst_len = sizeof(char) * TEST_WORD_LEN;
		if (i == len - 1)
			wd_arg.flag = FLAG_INPUT_FINISH;
		ret = wd_alg_decompress(handle, &wd_arg);
		if (ret < 0)
			goto out_comp;
		if ((i != len - 1) && wd_arg.dst_len) {
			fprintf(stderr, "err on dst_len:%ld\n", wd_arg.dst_len);
			ret = -EFAULT;
			goto out_comp;
		}
	}
	if (strncmp(word, wd_arg.dst, strlen(word))) {
		fprintf(stderr, "fail to match, dst:%s, word:%s\n",
			(char *)wd_arg.dst, word);
		ret = -EFAULT;
		goto out_comp;
	} else {
		printf("Pass small buffer case for %s algorithm.\n",
			(flag == FLAG_ZLIB) ? "zlib" : "gzip");
	}
	wd_alg_comp_free_sess(handle);
	free(wd_arg.src);
	free(wd_arg.dst);
	return 0;
out_comp:
	wd_alg_comp_free_sess(handle);
	free(wd_arg.dst);
out_dst:
	free(wd_arg.src);
out:
	return ret;
}

int test_large_buffer(int flag)
{
	handler_t	handle;
	struct wd_comp_arg wd_arg;
	char	algs[60];
	char	*buf, *dst;
	int	ret = 0, i, len = 0;
	int	dst_idx = 0;

	buf = malloc(sizeof(char) * TEST_LARGE_BUF_LEN);
	if (!buf)
		return -ENOMEM;
	dst = malloc(sizeof(char) * TEST_LARGE_BUF_LEN);
	if (!dst) {
		ret = -ENOMEM;
		goto out;
	}
	if (flag & FLAG_ZLIB)
		sprintf(algs, "zlib");
	else if (flag & FLAG_GZIP)
		sprintf(algs, "gzip");
	memset(&wd_arg, 0, sizeof(struct wd_comp_arg));
	wd_arg.dst_len = sizeof(char) * TEST_LARGE_BUF_LEN;
	wd_arg.src = malloc(sizeof(char) * TEST_LARGE_BUF_LEN);
	wd_arg.flag = FLAG_DEFLATE;
	if (!wd_arg.src) {
		ret = -ENOMEM;
		goto out_src;
	}
	wd_arg.dst = malloc(sizeof(char) * TEST_LARGE_BUF_LEN);
	if (!wd_arg.dst) {
		ret = -ENOMEM;
		goto out_dst;
	}
	dst_idx = 0;
	handle = wd_alg_comp_alloc_sess(algs, MODE_STREAM, NULL);
	for (i = 0; i < TEST_LARGE_BUF_LEN; i += LARGE_BUF_SIZE) {
		memset(wd_arg.src, 0, LARGE_BUF_SIZE);
		memcpy(wd_arg.src + i, word, strlen(word));
		wd_arg.src_len = LARGE_BUF_SIZE;
		wd_arg.dst_len = sizeof(char) * TEST_LARGE_BUF_LEN;
		if (i + LARGE_BUF_SIZE >= TEST_LARGE_BUF_LEN)
			wd_arg.flag |= FLAG_INPUT_FINISH;
		ret = wd_alg_compress(handle, &wd_arg);
		if (ret < 0)
			goto out_comp;
		memcpy(buf + dst_idx, wd_arg.dst, wd_arg.dst_len);
		dst_idx += wd_arg.dst_len;
	}
	wd_alg_comp_free_sess(handle);

	/* prepare for decompress */
	memcpy(buf, wd_arg.dst, sizeof(char) * TEST_LARGE_BUF_LEN);
	len = dst_idx;
	wd_arg.flag = 0;
	dst_idx = 0;

	handle = wd_alg_comp_alloc_sess(algs, MODE_STREAM, NULL);
	for (i = 0; i < len; i += LARGE_BUF_SIZE) {
		memcpy(wd_arg.src + i, buf + i, LARGE_BUF_SIZE);
		wd_arg.src_len = LARGE_BUF_SIZE;
		wd_arg.dst_len = sizeof(char) * TEST_LARGE_BUF_LEN;
		if (i + LARGE_BUF_SIZE >= len) {
			wd_arg.src_len -= i + LARGE_BUF_SIZE - len;
			wd_arg.flag = FLAG_INPUT_FINISH;
		}
		ret = wd_alg_decompress(handle, &wd_arg);
		if (ret < 0)
			goto out_comp;
		memcpy(dst + dst_idx, wd_arg.dst, wd_arg.dst_len);
		dst_idx += wd_arg.dst_len;
	}
	if (dst_idx != TEST_LARGE_BUF_LEN) {
		fprintf(stderr, "failed on dst size:%d, expected size:%d\n",
			dst_idx, TEST_LARGE_BUF_LEN);
		goto out_comp;
	}
	for (i = 0; i < TEST_LARGE_BUF_LEN; i += LARGE_BUF_SIZE) {
		memset(buf + i, 0, LARGE_BUF_SIZE);
		memcpy(buf + i, word, strlen(word));
		ret = memcmp(buf + i, dst + i, LARGE_BUF_SIZE);
		if (ret) {
			fprintf(stderr, "fail to match in %s\n", __func__);
			goto out_comp;
		}
	}
	printf("Pass large buffer case for %s algorithm.\n",
		(flag == FLAG_ZLIB) ? "zlib" : "gzip");
	wd_alg_comp_free_sess(handle);
	free(wd_arg.src);
	free(wd_arg.dst);
	free(dst);
	free(buf);
	return 0;
out_comp:
	wd_alg_comp_free_sess(handle);
	free(wd_arg.dst);
out_dst:
	free(wd_arg.src);
out_src:
	free(dst);
out:
	free(buf);
	return ret;
}

void *thread_func(void *arg)
{
	thread_data_t	*data = (thread_data_t *)arg;
	handler_t	handle;
	struct wd_comp_arg *wd_arg = &data->wd_arg;
	char	algs[60];
	int	ret;

	if (data->flag & FLAG_ZLIB)
		sprintf(algs, "zlib");
	else if (data->flag & FLAG_GZIP)
		sprintf(algs, "gzip");
	handle = wd_alg_comp_alloc_sess(algs, 0, NULL);
	wd_arg->flag = FLAG_INPUT_FINISH | FLAG_DEFLATE;
	ret = wd_alg_compress(handle, wd_arg);
	if (ret) {
		fprintf(stderr, "fail to compress (%d)\n", ret);
	}
	wd_alg_comp_free_sess(handle);

	/* prepare to uncompress */
	memset(wd_arg->src, 0, sizeof(char) * TEST_WORD_LEN);
	wd_arg->src_len = wd_arg->dst_len;
	memcpy(wd_arg->src, wd_arg->dst, wd_arg->dst_len);
	memset(wd_arg->dst, 0, sizeof(char) * TEST_WORD_LEN);
	wd_arg->dst_len = TEST_WORD_LEN;
	wd_arg->flag = FLAG_INPUT_FINISH & ~FLAG_DEFLATE;

	handle = wd_alg_comp_alloc_sess(algs, 0, NULL);
	ret = wd_alg_decompress(handle, wd_arg);
	if (ret) {
		fprintf(stderr, "fail to decompress (%d)\n", ret);
	}
	if (strncmp(word, wd_arg->dst, strlen(word))) {
		thread_fail = 1;
	}
	wd_alg_comp_free_sess(handle);
	free(wd_arg->src);
	free(wd_arg->dst);
	pthread_exit(NULL);
}

int test_concurrent(int flag)
{
	pthread_t thread[NUM_THREADS];
	thread_data_t thread_data[NUM_THREADS];
	struct wd_comp_arg	*arg;
	int i, j, ret;

	for (i = 0; i < NUM_THREADS; i++) {
		thread_data[i].tid = i;
		thread_data[i].flag = flag;
		arg = &thread_data[i].wd_arg;
		memset(arg, 0, sizeof(struct wd_comp_arg));
		arg->src_len = strlen(word) + 1;
		arg->src = calloc(1, sizeof(char) * TEST_WORD_LEN);
		if (!arg->src) {
			ret = -ENOMEM;
			goto out_src;
		}
		memcpy(arg->src, word, strlen(word));
		arg->dst_len = TEST_WORD_LEN;
		arg->dst = calloc(1, sizeof(char) * arg->dst_len);
		if (!arg->dst) {
			ret = -ENOMEM;
			goto out_dst;
		}
		ret = pthread_create(&thread[i], NULL,
				thread_func, &thread_data[i]);
		if (ret) {
			printf("fail to create pthread, ret:%d\n", ret);
			goto out_creat;
		}
	}
	for (i = 0; i < NUM_THREADS; i++) {
		pthread_join(thread[i], NULL);
	}
	return 0;
out_creat:
	free(arg->dst);
out_dst:
	free(arg->src);
out_src:
	for (j = 0; j < i; j++) {
		free(arg->dst);
		free(arg->src);
		pthread_cancel(thread[i]);
	}
	return ret;
}

int main(int argc, char **argv)
{
	test_small_buffer(FLAG_ZLIB, 0);
	test_small_buffer(FLAG_GZIP, 0);
	test_small_buffer(FLAG_ZLIB, MODE_STREAM);
	test_small_buffer(FLAG_GZIP, MODE_STREAM);
/*
	test_large_buffer(FLAG_ZLIB);
	thread_fail = 0;
	test_concurrent(FLAG_ZLIB);
	if (thread_fail)
		fprintf(stderr, "fail to run ZLIB cases concurrently\n");
	thread_fail = 0;
	test_concurrent(FLAG_GZIP);
	if (thread_fail)
		fprintf(stderr, "fail to run GZIP cases concurrently\n");
*/
	return 0;
}
