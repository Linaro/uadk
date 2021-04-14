// SPDX-License-Identifier: Apache-2.0
#ifndef TEST_LIB_H_
#define TEST_LIB_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/stat.h>
#include "wd_comp.h"

#define SYS_ERR_COND(cond, msg, ...) \
do { \
	if (cond) { \
		if (errno) \
			perror(msg); \
		else \
			fprintf(stderr, msg, ##__VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} \
} while (0)

enum mode {
	MODE_BLOCK,
	MODE_STREAM,
};

/*
 * I observed a worst case of 1.041x expansion with random data, but let's say 2
 * just in case. TODO: reduce this
 */
#define EXPANSION_RATIO	2

#define SGE_SIZE	(8 * 1024)

struct test_options {
	int alg_type;
	int op_type;

	/* bytes of data for a request */
	int block_size;
	int q_num;
	unsigned long total_len;

#define MAX_RUNS	1024
	int run_num;
	/* tasks running in parallel */
	int compact_run_num;

	int thread_num;
	/* 0: sync mode, 1: async mode */
	int sync_mode;

	/* 0: pbuffer, 1: sgl */
	__u8 data_fmt;

	bool verify;
	bool verbose;
	bool is_decomp;
	bool is_stream;
	bool is_file;

	int warmup_num;

#define PERFORMANCE		(1UL << 0)
#define TEST_ZLIB		(1UL << 1)
#define TEST_THP		(1UL << 2)
	unsigned long option;

#define STATS_NONE		0
#define STATS_PRETTY		1
#define STATS_CSV		2
	unsigned long display_stats;

	/* bind test case related below */
	int children;

#define INJECT_SIG_BIND		(1UL << 0)
#define INJECT_SIG_WORK		(1UL << 1)
#define INJECT_TLB_FAULT	(1UL << 2)
	unsigned long faults;

};

struct hizip_test_info {
	struct test_options *opts;
	char *in_buf, *out_buf;
	size_t in_size, out_size;
	size_t total_out;
	struct uacce_dev_list *list;
	handle_t h_sess;
	struct wd_ctx_config ctx_conf;
	pthread_t *send_tds;
	int send_tnum;
	pthread_t *poll_tds;
	int poll_tnum;
	struct hizip_stats *stats;
	struct {
		struct timespec setup_time;
		struct timespec start_time;
		struct timespec end_time;
		struct timespec setup_cputime;
		struct timespec start_cputime;
		struct timespec end_cputime;
		struct rusage setup_rusage;
		struct rusage start_rusage;
		struct rusage end_rusage;
	} tv;
};

typedef struct _thread_data_t {
	struct hizip_test_info *info;
	struct wd_comp_req req;
	size_t sum;
} thread_data_t;

void *send_thread_func(void *arg);
void *poll_thread_func(void *arg);
int create_send_threads(struct test_options *opts,
			struct hizip_test_info *info,
			void *(*send_thread_func)(void *arg)
			);
int create_poll_threads(struct hizip_test_info *info,
			void *(*poll_thread_func)(void *arg),
			int num);
void free_threads(struct hizip_test_info *info);
int attach_threads(struct test_options *opts,
		   struct hizip_test_info *info);
int init_ctx_config(struct test_options *opts,
		    void *priv,
		    struct wd_sched **sched
		    );
void uninit_config(void *priv, struct wd_sched *sched);
struct uacce_dev_list *get_dev_list(struct test_options *opts, int children);

void hizip_prepare_random_input_data(char *buf, size_t len, size_t block_size);
int hizip_prepare_random_compressed_data(char *buf, size_t out_len,
					 size_t in_len, size_t *produced,
					 struct test_options *opts);

int hizip_verify_random_output(struct test_options *opts,
			       struct hizip_test_info *info,
			       size_t out_sz);

void *mmap_alloc(size_t len);
int lib_poll_func(__u32 pos, __u32 expect, __u32 *count);
typedef int (*check_output_fn)(unsigned char *buf, unsigned int size, void *opaque);

/* for block interface */
int hw_blk_compress(int alg_type, int blksize, __u8 data_fmt, void *priv,
		    unsigned char *dst, __u32 *dstlen,
		    unsigned char *src, __u32 srclen);

int hw_blk_decompress(int alg_type, int blksize, __u8 data_fmt,
		      unsigned char *dst, __u32 *dstlen,
		      unsigned char *src, __u32 srclen);

/* for stream memory interface */
int hw_stream_compress(int alg_type, int blksize, __u8 data_fmt,
		       unsigned char *dst, __u32 *dstlen,
		       unsigned char *src, __u32 srclen);

int hw_stream_decompress(int alg_type, int blksize, __u8 data_fmt,
		         unsigned char *dst, __u32 *dstlen,
		         unsigned char *src, __u32 srclen);

int comp_file_test(FILE *source, FILE *dest, struct test_options *opts);

#ifdef USE_ZLIB
int hizip_check_output(void *buf, size_t size, size_t *checked,
		       check_output_fn check_output, void *opaque);
int zlib_deflate(void *output, unsigned int out_size,
		 void *input, unsigned int in_size, unsigned long *produced,
		 int alg_type);
#else
static inline int hizip_check_output(void *buf, size_t size, size_t *checked,
				     check_output_fn check_output,
				     void *opaque)
{
	static bool printed = false;

	if (!printed) {
		WD_ERR("no zlib available, output buffer won't be checked\n");
		printed = true;
	}
	return -ENOSYS;
}
static inline int zlib_deflate(void *output, unsigned int out_size, void *input,
			       unsigned int in_size, unsigned long *produced,
			       int alg_type)
{
	WD_ERR("no zlib available\n");
	return -ENOSYS;
}
#endif

static inline void hizip_test_adjust_len(struct test_options *opts)
{
	/*
	 * Align size to the next block. We allow non-power-of-two block sizes.
	 */
	opts->total_len = (opts->total_len + opts->block_size - 1) /
		opts->block_size * opts->block_size;
}

#define COMMON_OPTSTRING "hb:n:q:l:FSs:Vvzt:m:dacLZ"

#define COMMON_HELP "%s [opts]\n"					\
	"  -b <size>     block size\n"					\
	"  -n <num>      number of runs\n"				\
	"  -q <num>      number of queues\n"				\
	"  -l <num>      number of compact runs\n"			\
	"  -F            input file, default no input\n"		\
	"  -S            stream mode, default block mode\n"		\
	"  -s <size>     total size\n"					\
	"  -V            verify output\n"				\
	"  -v            display detailed performance information\n"	\
	"  -a            test deflate algorithm, default gzip\n"	\
	"  -z            test zlib algorithm, default gzip\n"		\
	"  -t <num>      number of thread per process\n"		\
	"  -m <mode>     mode of queues: 0 sync, 1 async\n"		\
	"  -d		 test decompression, default compression\n"	\
	"  -c		 use cpu to do zlib\n"				\
	"  -L		 test sgl type buffer, default pbuffer\n"	\
	"  -Z		 test lz77_zstd algorithm, default gzip\n"	\
	"\n\n"

int parse_common_option(const char opt, const char *optarg,
			struct test_options *opts);
#endif /* TEST_LIB_H_ */
