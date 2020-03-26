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

typedef struct _thread_data_t {
	int	tid;
	int	flag;
	struct wd_comp_arg	wd_arg;
} thread_data_t;

static char word[] = "go to test.";

static int thread_fail = 0;

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
		arg->dst_len = TEST_WORD_LEN;	// for decompress
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
	return EXIT_SUCCESS;
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
	thread_fail = 0;
	test_concurrent(FLAG_ZLIB);
	if (thread_fail)
		fprintf(stderr, "fail to run ZLIB cases concurrently\n");
	thread_fail = 0;
	test_concurrent(FLAG_GZIP);
	if (thread_fail)
		fprintf(stderr, "fail to run GZIP cases concurrently\n");
	return 0;
}
