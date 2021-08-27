// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#ifndef TEST_LIB_H_
#define TEST_LIB_H_

#include <errno.h>
#include <openssl/md5.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
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

enum mode {
	MODE_BLOCK,
	MODE_STREAM,
};

#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define ALIGN(x, a)		__ALIGN_MASK(x, (typeof(x))(a)-1)
#define MIN(a, b)		((a < b) ? a : b)

/*
 * I observed a worst case of 1.041x expansion with random data, but let's say 2
 * just in case. TODO: reduce this
 */
#define EXPANSION_RATIO	2
/* The INFLATION_RATIO is high for text file. */
#define INFLATION_RATIO	24

#define SGE_SIZE	(8 * 1024)

#define HIZIP_CHUNK_LIST_ENTRIES	32768

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

	/* send thread number */
	int thread_num;
	/* poll thread number -- ASYNC */
	int poll_num;
	/* 0: sync mode, 1: async mode */
	int sync_mode;
	/*
	 * positive value: the number of messages are sent at a time.
	 * 0: batch mode is disabled.
	 * batch mode is only valid for ASYNC operations.
	 */
	int batch_num;
	/* input file */
	int fd_in;
	/* output file */
	int fd_out;
	/* inlist file */
	int fd_ilist;
	/* outlist file */
	int fd_olist;

	/* 0: pbuffer, 1: sgl */
	__u8 data_fmt;

	bool verify;
	bool verbose;
	bool is_decomp;
	bool is_stream;
	bool is_file;
	bool use_env;

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

typedef struct _comp_md5_t {
	MD5_CTX		md5_ctx;
	unsigned char	md[MD5_DIGEST_LENGTH];
} comp_md5_t;

typedef struct hizip_chunk_list {
	void *addr;
	size_t size;
	struct hizip_chunk_list *next;
} chunk_list_t;

typedef struct _thread_data_t {
	struct hizip_test_info *info;
	struct wd_comp_req req;
	comp_md5_t md5;
	void *src;
	void *dst;
	size_t src_sz;
	size_t dst_sz;
	size_t sum;	/* produced bytes for OUT */
	int tid;	/* thread ID */
	int bcnt;	/* batch mode: count */
	int pcnt;	/* batch mode: poll count */
	int flush_bcnt;	/* batch mode: flush count that is less batch_num */
	/*
	 * batch mode: set flag and wait batch end in sending thread.
	 * Clear batch flag if pcnt == bcnt in polling thread.
	 * batch_flag could replace flush_bcnt.
	 */
	int batch_flag;
	sem_t sem;
	chunk_list_t *in_list;
	chunk_list_t *out_list;
	struct wd_comp_req *reqs;
} thread_data_t;

struct hizip_test_info {
	struct test_options *opts;
	char *in_buf, *out_buf;
	size_t in_size, out_size;
	/* in_chunk_sz & out_chunk_sz are used to format entries in list */
	size_t in_chunk_sz, out_chunk_sz;
	size_t total_out;
	struct uacce_dev_list *list;
	handle_t h_sess;
	struct wd_ctx_config ctx_conf;
	pthread_t *send_tds;
	int send_tnum;
	pthread_t *poll_tds;
	int poll_tnum;
	/* tdatas: send thread data array, p_tdatas: poll thread data array */
	thread_data_t *tdatas;
	thread_data_t *p_tdatas;
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

extern int sum_pend, sum_thread_end;

void *send_thread_func(void *arg);
void *poll_thread_func(void *arg);
void *sw_dfl_sw_ifl(void *arg);
int create_send_threads(struct test_options *opts,
			struct hizip_test_info *info,
			void *(*send_thread_func)(void *arg));
int create_poll_threads(struct hizip_test_info *info,
			void *(*poll_thread_func)(void *arg),
			int num);
void free_threads(struct hizip_test_info *info);
int attach_threads(struct test_options *opts,
		   struct hizip_test_info *info);

void gen_random_data(void *buf, size_t len);
int calculate_md5(comp_md5_t *md5, const void *buf, size_t len);
void dump_md5(comp_md5_t *md5);
int cmp_md5(comp_md5_t *orig, comp_md5_t *final);
void init_chunk_list(chunk_list_t *list, void *buf, size_t buf_sz,
		     size_t chunk_sz);
chunk_list_t *create_chunk_list(void *buf, size_t buf_sz, size_t chunk_sz);
void free_chunk_list(chunk_list_t *list);
int sw_deflate2(chunk_list_t *in_list,
		chunk_list_t *out_list,
		struct test_options *opts);
int sw_inflate2(chunk_list_t *in_list,
		chunk_list_t *out_list,
		struct test_options *opts);
int hw_deflate4(handle_t h_dfl,
		chunk_list_t *in_list,
		chunk_list_t *out_list,
		struct test_options *opts,
		sem_t *sem);
int hw_inflate4(handle_t h_ifl,
		chunk_list_t *in_list,
		chunk_list_t *out_list,
		struct test_options *opts,
		sem_t *sem);
int hw_deflate5(handle_t h_dfl,
		chunk_list_t *in_list,
		chunk_list_t *out_list,
		thread_data_t *tdata);
int hw_inflate5(handle_t h_ifl,
		chunk_list_t *in_list,
		chunk_list_t *out_list,
		thread_data_t *tdata);
int create_send_tdata(struct test_options *opts,
		      struct hizip_test_info *info);
int create_poll_tdata(struct test_options *opts,
		      struct hizip_test_info *info,
		      int poll_num);
void free2_threads(struct hizip_test_info *info);
int attach2_threads(struct test_options *opts,
		    struct hizip_test_info *info,
		    void *(*send_thread_func)(void *arg),
		    void *(*poll_thread_func)(void *arg));
void *poll2_thread_func(void *arg);
int run_self_test(struct test_options *opts);
int run_cmd(struct test_options *opts);
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
int mmap_free(void *addr, size_t len);

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
