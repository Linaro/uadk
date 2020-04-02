// SPDX-License-Identifier: GPL-2.0+
#ifndef TEST_LIB_H_
#define TEST_LIB_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "wd.h"
#include "wd_sched.h"
#include "zip_usr_if.h"

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
#define ZLIB 0
#define GZIP 1
	int alg_type;

#define DEFLATE 0
#define INFLATE 1
	int op_type;

	/* bytes of data for a request */
	int block_size;
	int req_cache_num;
	int q_num;
	unsigned long total_len;

#define MAX_RUNS	1024
	int run_num;
	int compact_run_num;

	bool verify;
	bool verbose;
};

struct hizip_test_context {
	struct test_options *opts;
	char *in_buf;
	char *out_buf;
	unsigned long total_len;
	struct hisi_zip_sqe *msgs;
	int flags;
	size_t total_out;
	/* Test is expected to fail */
	bool faulting;
};

/* Default ops */
void hizip_test_default_init_cache(struct wd_scheduler *sched, int i,
				   void *priv);
int hizip_test_default_input(struct wd_msg *msg, void *priv);
int hizip_test_default_output(struct wd_msg *msg, void *priv);

struct test_ops {
	void (*init_cache)(struct wd_scheduler *sched, int i, void *priv);
	int (*input)(struct wd_msg *msg, void *priv);
	int (*output)(struct wd_msg *msg, void *priv);
};

extern struct test_ops default_test_ops;

int hizip_test_init(struct wd_scheduler *sched, struct test_options *opts,
		    struct test_ops *ops, void *priv);
int hizip_test_sched(struct wd_scheduler *sched, struct test_options *opts,
		     struct hizip_test_context *priv);
void hizip_test_fini(struct wd_scheduler *sched, struct test_options *opts);

void hizip_prepare_random_input_data(struct hizip_test_context *ctx);
int hizip_verify_random_output(char *out_buf, struct test_options *opts,
			       struct hizip_test_context *ctx);

void *mmap_alloc(size_t len);

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
	return 0;
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

#define COMMON_OPTSTRING "hb:n:q:c:l:s:Vvz"

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
	"\n\n"

int parse_common_option(const char opt, const char *optarg,
			struct test_options *opts);
#endif /* TEST_LIB_H_ */
