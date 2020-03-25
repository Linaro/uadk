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

typedef struct _thread_data_t {
	int	tid;
	int	flag;
	struct wd_comp_arg	wd_arg;
} thread_data_t;

void *thread_func(void *arg)
{
	thread_data_t	*data = (thread_data_t *)arg;
	handler_t	handle;
	char	algs[60];
	int	ret;

	if (data->flag & FLAG_ZLIB)
		sprintf(algs, "zlib");
	else if (data->flag & FLAG_GZIP)
		sprintf(algs, "gzip");
	handle = wd_alg_comp_alloc_sess(algs, 0, NULL);
	if (data->flag & FLAG_DECMPS) {
		ret = wd_alg_decompress(handle, &data->wd_arg);
		if (ret) {
			fprintf(stderr, "fail to decompress (%d)\n", ret);
		}
	} else {
		ret = wd_alg_compress(handle, &data->wd_arg);
		if (ret) {
			fprintf(stderr, "fail to compress (%d)\n", ret);
		}
	}
	wd_alg_comp_free_sess(handle);
	pthread_exit(NULL);
}

int test_concurrent(char *src, int flag)
{
	pthread_t thread[NUM_THREADS];
	thread_data_t thread_data[NUM_THREADS];
	struct wd_comp_arg	*arg;
	struct stat st;
	int	sfd;
	int i, ret;

	sfd = open(src, O_RDONLY);
	fstat(sfd, &st);
	for (i = 0; i < NUM_THREADS; i++) {
		thread_data[i].tid = i;
		thread_data[i].flag = flag;
		arg = &thread_data[i].wd_arg;
		memset(arg, 0, sizeof(struct wd_comp_arg));
		arg->src_len = st.st_size;
		arg->src = malloc(sizeof(char) * arg->src_len);
		if (!arg->src) {
			ret = -ENOMEM;
			goto out_src;
		}
		arg->dst_len = arg->src_len << 2;	// for decompress
		arg->dst = malloc(sizeof(char) * arg->dst_len);
		if (!arg->dst) {
			ret = -ENOMEM;
			goto out_dst;
		}
		lseek(sfd, 0, SEEK_SET);
		ret = read(sfd, arg->src, arg->src_len);
		if ((ret < 0) || (ret != arg->src_len)) {
			fprintf(stderr, "fail to load data (%d)\n", ret);
			goto out_read;
		}
		ret = pthread_create(&thread[i], NULL,
				thread_func, &thread_data[i]);
		if (ret) {
			printf("fail to create pthread, ret:%d\n", ret);
			return EXIT_FAILURE;
		}
	}
	for (i = 0; i < NUM_THREADS; i++) {
		pthread_join(thread[i], NULL);
	}
	return EXIT_SUCCESS;
out_read:
	free(arg->dst);
out_dst:
	free(arg->src);
out_src:
	close(sfd);
	return ret;
}

int main(int argc, char **argv)
{
	int	opt;
	int	flag = 0;
	char	src[PATHLEN+1];

	while ((opt = getopt(argc, argv, "i:hdgsz")) != -1) {
		switch (opt) {
		case 'i':
			snprintf(src, PATHLEN, "%s", optarg);
			break;
		case 'd':
			flag |= FLAG_DECMPS;
			break;
		case 'g':
			flag |= FLAG_GZIP;
			break;
		case 's':
			flag |= FLAG_STREAM;
			break;
		case 'z':
			flag |= FLAG_ZLIB;
			break;
		case 'h':
			printf("./test_comp -i <src> [-d] [-z] [-g]\n");
			break;
		default:
			fprintf(stderr, "Unrecognized option!\n");
			break;
		}
	}
	return test_concurrent(src, FLAG_ZLIB);
}
