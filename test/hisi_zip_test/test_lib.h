// SPDX-License-Identifier: Apache-2.0
#ifndef TEST_LIB_H_
#define TEST_LIB_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

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

/*
 * I observed a worst case of 1.041x expansion with random data, but let's say 2
 * just in case. TODO: reduce this
 */
#define EXPANSION_RATIO	2

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

	bool verify;
	bool verbose;
	bool is_decomp;
};

struct hizip_test_info {
	struct test_options *opts;
	char *in_buf;
	char *out_buf;
	unsigned long total_len;
	int is_nosva;
	size_t total_out;
	struct uacce_dev_list *list;
	handle_t h_sess;
	struct wd_ctx_config ctx_conf;
	struct wd_comp_req req;
	/* statistic */
	struct {
		int send;
		int send_retries;
		int recv;
		int recv_retries;
	} *stat;
	/* Test is expected to fail */
	bool faulting;
};

int hizip_test_sched(struct wd_sched *sched,
		     struct test_options *opts,
		     struct hizip_test_info *info
		     );
int init_ctx_config(struct test_options *opts,
		    struct wd_sched *sched,
		    void *priv
		    );
void uninit_config(void *priv);

void hizip_prepare_random_input_data(struct hizip_test_info *info);
int hizip_verify_random_output(char *out_buf, struct test_options *opts,
			       struct hizip_test_info *info);

void *mmap_alloc(size_t len);
int lib_poll_func(__u32 pos, __u32 expect, __u32 *count);
typedef int (*check_output_fn)(unsigned char *buf, unsigned int size, void *opaque);
#ifdef USE_ZLIB
int hizip_check_output(void *buf, size_t size, size_t *checked,
		       check_output_fn check_output, void *opaque);
int zlib_deflate(void *output, unsigned int out_size,
		 void *input, unsigned int in_size, unsigned long *produced);
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
			       unsigned int in_size, unsigned long *produced)
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

#define COMMON_OPTSTRING "hb:n:q:c:l:s:Vvzt:m:d"

#define COMMON_HELP "%s [opts]\n"					\
	"  -b <size>     block size\n"					\
	"  -n <num>      number of runs\n"				\
	"  -q <num>      number of queues\n"				\
	"  -c <num>      number of caches\n"				\
	"  -l <num>      number of compact runs\n"			\
	"  -s <size>     total size\n"					\
	"  -V            verify output\n"				\
	"  -v            display detailed performance information\n"	\
	"  -z            test zlib algorithm, default gzip\n"		\
	"  -t <num>      number of thread per process\n"		\
	"  -m <mode>     mode of queues: 0 sync, 1 async\n"		\
	"  -d		 test decompression, default compression\n"	\
	"\n\n"

int parse_common_option(const char opt, const char *optarg,
			struct test_options *opts);
#endif /* TEST_LIB_H_ */
