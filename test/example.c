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
 * Test to compress and decompress on IN & OUT buffer.
 * Data are filled in IN and OUT buffer only once.
 */
int test_comp_once(int flag, int mode)
{
	handler_t	handle;
	struct wd_comp_arg wd_arg;
	char	algs[60];
	char	buf[TEST_WORD_LEN];
	int	ret = 0, t;
	void	*src;

	if (flag & FLAG_ZLIB)
		sprintf(algs, "zlib");
	else if (flag & FLAG_GZIP)
		sprintf(algs, "gzip");
	memset(&wd_arg, 0, sizeof(struct wd_comp_arg));
	wd_arg.dst_len = sizeof(char) * TEST_WORD_LEN;
	wd_arg.src = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!wd_arg.src) {
		ret = -ENOMEM;
		goto out;
	}
	/*
	 * wd_arg.src & wd_arg.src_len & wd_arg.dst_len will be updated by
	 * wd_alg_compress() and wd_alg_decompress().
	 */
	src = wd_arg.src;
	wd_arg.dst = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!wd_arg.dst) {
		ret = -ENOMEM;
		goto out_dst;
	}
	memcpy(wd_arg.src, word, sizeof(char) * strlen(word));
	wd_arg.src_len = strlen(word);
	t = 0;
	handle = wd_alg_comp_alloc_sess(algs, mode & MODE_STREAM, NULL);
	while (1) {
		wd_arg.status = 0;
		wd_arg.dst_len = TEST_WORD_LEN;
		wd_arg.flag = FLAG_DEFLATE | FLAG_INPUT_FINISH;
		ret = wd_alg_compress(handle, &wd_arg);
		if (ret < 0)
			goto out_comp;
		if (wd_arg.status & STATUS_OUT_READY) {
			memcpy(buf + t, wd_arg.dst, wd_arg.dst_len);
			t += wd_arg.dst_len;
		}
		if ((wd_arg.status & STATUS_OUT_DRAINED) &&
		    (wd_arg.status & STATUS_IN_EMPTY) &&
		    (wd_arg.flag & FLAG_INPUT_FINISH))
			break;
	}
	wd_alg_comp_free_sess(handle);


	/* prepare to decompress */
	wd_arg.src = src;
	memcpy(wd_arg.src, buf, t);
	wd_arg.src_len = t;
	t = 0;

	handle = wd_alg_comp_alloc_sess(algs, mode & MODE_STREAM, NULL);
	while (1) {
		wd_arg.status = 0;
		wd_arg.dst_len = TEST_WORD_LEN;
		wd_arg.flag = FLAG_INPUT_FINISH;
		ret = wd_alg_decompress(handle, &wd_arg);
		if (ret < 0)
			goto out_comp;
		if (wd_arg.status & STATUS_OUT_READY) {
			memcpy(buf + t, wd_arg.dst, wd_arg.dst_len);
			t += wd_arg.dst_len;
		}
		if ((wd_arg.status & STATUS_OUT_DRAINED) &&
		    (wd_arg.status & STATUS_IN_EMPTY) &&
		    (wd_arg.flag & FLAG_INPUT_FINISH))
			break;
	}
	wd_alg_comp_free_sess(handle);

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
	free(wd_arg.dst);
	return 0;
out_comp:
	wd_alg_comp_free_sess(handle);
	free(wd_arg.dst);
out_dst:
	free(src);
out:
	return ret;
}

/*
 * Both IN and OUT buffer are 1-byte long.
 * Compress and decompress on IN and OUT buffer.
 */
int test_small_buffer(int flag, int mode)
{
	handler_t	handle;
	struct wd_comp_arg wd_arg;
	char	algs[60];
	char	buf[TEST_WORD_LEN];
	char	fin[TEST_WORD_LEN];
	int	ret = 0, i, len, t;
	void	*src;

	if (flag & FLAG_ZLIB)
		sprintf(algs, "zlib");
	else if (flag & FLAG_GZIP)
		sprintf(algs, "gzip");
	memset(&wd_arg, 0, sizeof(struct wd_comp_arg));
	wd_arg.dst_len = sizeof(char) * TEST_WORD_LEN;
	wd_arg.src = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!wd_arg.src) {
		ret = -ENOMEM;
		goto out;
	}
	src = wd_arg.src;
	wd_arg.dst = malloc(sizeof(char) * TEST_WORD_LEN);
	if (!wd_arg.dst) {
		ret = -ENOMEM;
		goto out_dst;
	}
	handle = wd_alg_comp_alloc_sess(algs, mode & MODE_STREAM, NULL);
	i = 0;
	t = 0;
	len = strlen(word);
	while (1) {
		wd_arg.flag = FLAG_DEFLATE;
		wd_arg.status = 0;
		wd_arg.src = &word[i];
		wd_arg.src_len = 1;
		wd_arg.dst_len = 1;
		if (i == len - 1)
			wd_arg.flag |= FLAG_INPUT_FINISH;
		else if (i == len) {
			wd_arg.flag |= FLAG_INPUT_FINISH;
			wd_arg.src_len = 0;
		}
		ret = wd_alg_compress(handle, &wd_arg);
		if (ret < 0)
			goto out_comp;
		if (wd_arg.status & STATUS_OUT_READY) {
			memcpy(buf + t, wd_arg.dst, wd_arg.dst_len);
			t += wd_arg.dst_len;
		}
		if ((wd_arg.status & STATUS_IN_EMPTY) && (i < len))
			i++;
		if ((wd_arg.status & STATUS_OUT_DRAINED) &&
		    (wd_arg.status & STATUS_IN_EMPTY) &&
		    (wd_arg.flag & FLAG_INPUT_FINISH))
			break;
	}
	wd_alg_comp_free_sess(handle);


	/* prepare for decompress */
	len = t;

	handle = wd_alg_comp_alloc_sess(algs, mode & MODE_STREAM, NULL);
	i = 0;
	t = 0;
	while (1) {
		wd_arg.flag = 0;
		wd_arg.status = 0;
		wd_arg.src = &buf[i];
		wd_arg.src_len = 1;
		wd_arg.dst_len = 1;
		if (i == len - 1)
			wd_arg.flag |= FLAG_INPUT_FINISH;
		else if (i == len) {
			wd_arg.flag |= FLAG_INPUT_FINISH;
			wd_arg.src_len = 0;
		}
		ret = wd_alg_decompress(handle, &wd_arg);
		if (ret < 0)
			goto out_comp;
		if (wd_arg.status & STATUS_OUT_READY) {
			memcpy(fin + t, wd_arg.dst, wd_arg.dst_len);
			t += wd_arg.dst_len;
		}
		if ((wd_arg.status & STATUS_IN_EMPTY) && (i < len))
			i++;
		if ((wd_arg.status & STATUS_OUT_DRAINED) &&
		    (wd_arg.status & STATUS_IN_EMPTY) &&
		    (wd_arg.flag & FLAG_INPUT_FINISH))
			break;
	}

	if (strncmp(word, fin, strlen(word))) {
		fprintf(stderr, "fail to match, fin:%s, word:%s\n", fin, word);
		ret = -EFAULT;
		goto out_comp;
	} else {
		if (mode & MODE_STREAM)
			snprintf(buf, TEST_WORD_LEN, "with STREAM mode.");
		else
			snprintf(buf, TEST_WORD_LEN, "with BLOCK mode.");
		printf("Pass small buffer case for %s algorithm %s\n",
			(flag == FLAG_ZLIB) ? "zlib" : "gzip", buf);
	}
	wd_alg_comp_free_sess(handle);
	free(src);
	free(wd_arg.dst);
	return 0;
out_comp:
	wd_alg_comp_free_sess(handle);
	free(wd_arg.dst);
out_dst:
	free(src);
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
	int	total_in, templen;
	void	*src;

	buf = malloc(sizeof(char) * TEST_LARGE_BUF_LEN + LARGE_BUF_SIZE);
	if (!buf)
		return -ENOMEM;
	dst = malloc(sizeof(char) * TEST_LARGE_BUF_LEN + LARGE_BUF_SIZE);
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
	if (!wd_arg.src) {
		ret = -ENOMEM;
		goto out_src;
	}
	src = wd_arg.src;
	i = 0;
	dst_idx = 0;
	total_in = 0;
	wd_arg.src = src;
	wd_arg.dst = buf;
	handle = wd_alg_comp_alloc_sess(algs, MODE_STREAM, NULL);
	while (1) {
		total_in += LARGE_BUF_SIZE;
		if (total_in > TEST_LARGE_BUF_LEN)
			templen = LARGE_BUF_SIZE -
				  (total_in - TEST_LARGE_BUF_LEN);
		else
			templen = LARGE_BUF_SIZE;
		memset(wd_arg.src, 0, templen);
		memcpy(wd_arg.src + i, word, strlen(word));
		wd_arg.flag = FLAG_DEFLATE;
		wd_arg.status = 0;
		wd_arg.src_len = templen;
		wd_arg.dst_len = sizeof(char) * TEST_LARGE_BUF_LEN;
		if (i + LARGE_BUF_SIZE >= TEST_LARGE_BUF_LEN)
			wd_arg.flag |= FLAG_INPUT_FINISH;
		else if (i >= TEST_LARGE_BUF_LEN) {
			wd_arg.flag |= FLAG_INPUT_FINISH;
			wd_arg.src_len = 0;
		}
		ret = wd_alg_compress(handle, &wd_arg);
		if (ret < 0)
			goto out_comp;
		if (wd_arg.status & STATUS_OUT_READY)
			dst_idx += wd_arg.dst_len;
		if ((wd_arg.status & STATUS_IN_EMPTY) &&
		    (i < TEST_LARGE_BUF_LEN)) {
			i += LARGE_BUF_SIZE;
			// Don't touch arg->src since it points to next buffer.
		}
		if ((wd_arg.status & STATUS_OUT_DRAINED) &&
		    (wd_arg.status & STATUS_IN_EMPTY) &&
		    (wd_arg.flag & FLAG_INPUT_FINISH))
			break;
	}
	wd_alg_comp_free_sess(handle);

	/* prepare for decompress */
	len = dst_idx;
	dst_idx = 0;
	total_in = 0;
	wd_arg.src = buf;
	wd_arg.dst = dst;

	handle = wd_alg_comp_alloc_sess(algs, MODE_STREAM, NULL);
	while (1) {
		total_in += LARGE_BUF_SIZE;
		if (total_in > len)
			templen = LARGE_BUF_SIZE - (total_in - len);
		else
			templen = LARGE_BUF_SIZE;
		wd_arg.flag = 0;
		wd_arg.status = 0;
		wd_arg.src_len = templen;
		wd_arg.dst_len = sizeof(char) * TEST_LARGE_BUF_LEN;
		if (i + LARGE_BUF_SIZE >= TEST_LARGE_BUF_LEN)
			wd_arg.flag |= FLAG_INPUT_FINISH;
		else if (i >= TEST_LARGE_BUF_LEN) {
			wd_arg.flag |= FLAG_INPUT_FINISH;
			wd_arg.src_len = 0;
		}
		ret = wd_alg_decompress(handle, &wd_arg);
		if (ret < 0)
			goto out_comp;
		if (wd_arg.status & STATUS_OUT_READY)
			dst_idx += wd_arg.dst_len;
		if ((wd_arg.status & STATUS_IN_EMPTY) && (i < len))
			i += LARGE_BUF_SIZE;
		if ((wd_arg.status & STATUS_OUT_DRAINED) &&
		    (wd_arg.status & STATUS_IN_EMPTY) &&
		    (wd_arg.flag & FLAG_INPUT_FINISH))
			break;
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
	test_comp_once(FLAG_ZLIB, MODE_STREAM);
	//test_small_buffer(FLAG_ZLIB, 0);
	//test_small_buffer(FLAG_GZIP, 0);
	test_small_buffer(FLAG_ZLIB, MODE_STREAM);
//	test_small_buffer(FLAG_GZIP, MODE_STREAM);
	test_large_buffer(FLAG_ZLIB);
/*
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
