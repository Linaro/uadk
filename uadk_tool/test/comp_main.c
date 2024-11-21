// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */
#include <linux/perf_event.h>
#include <asm/unistd.h>	/* For __NR_perf_event_open */
#include <fenv.h>
#include <getopt.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "comp_lib.h"

#define POLL_STRING_LEN		128

enum hizip_stats_variable {
	ST_SETUP_TIME,
	ST_RUN_TIME,
	ST_CPU_TIME,

	/* CPU usage */
	ST_USER_TIME,
	ST_SYSTEM_TIME,

	/* Faults */
	ST_MINFLT,
	ST_MAJFLT,

	/* Context switches */
	ST_INVCTX,
	ST_VCTX,

	/* Signals */
	ST_SIGNALS,

	/* Aggregated */
	ST_SPEED,
	ST_TOTAL_SPEED,
	ST_CPU_IDLE,
	ST_FAULTS,
	ST_IOPF,

	ST_COMPRESSION_RATIO,

	NUM_STATS
};

struct hizip_stats {
	double v[NUM_STATS];
};

extern int perf_event_open(struct perf_event_attr *attr,
			   pid_t pid, int cpu, int group_fd,
			   unsigned long flags);
extern int perf_event_get(const char *event_name, int **perf_fds, int *nr_fds);
extern unsigned long long perf_event_put(int *perf_fds, int nr_fds);
extern void stat_setup(struct hizip_test_info *info);
extern void stat_start(struct hizip_test_info *info);
extern void stat_end(struct hizip_test_info *info);

static size_t count_chunk_list_sz(chunk_list_t *list)
{
	size_t sum = 0;
	chunk_list_t *p;

	for (p = list; p; p = p->next)
		sum += p->size;
	return sum;
}

static void *sw_dfl_hw_ifl(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_sess_setup setup = {0};
	struct sched_params param = {0};
	handle_t h_ifl;
	void *tbuf;
	size_t tbuf_sz;
	chunk_list_t *tlist;
	comp_md5_t final_md5 = {{0}};
	int i, ret;
	__u32 tout_sz;

	tbuf_sz = tdata->src_sz * EXPANSION_RATIO;
	tbuf = mmap_alloc(tbuf_sz);
	if (!tbuf)
		return (void *)(uintptr_t)(-ENOMEM);
	tlist = create_chunk_list(tbuf, tbuf_sz,
				  info->in_chunk_sz * EXPANSION_RATIO);
	if (!tlist) {
		ret = -ENOMEM;
		goto out;
	}
	if (opts->option & PERFORMANCE) {
		/* hack:
		 * memset buffer and trigger page fault early in the cpu
		 * instead of later in the SMMU
		 * Enhance performance in sva case
		 * no impact to non-sva case
		 */
		memset(tbuf, 5, tbuf_sz);
	}
	if (opts->is_stream) {
		/* STREAM mode: only one entry in the list */
		init_chunk_list(tdata->in_list, tdata->src,
				tdata->src_sz, tdata->src_sz);
		for (i = 0; i < opts->compact_run_num; i++) {
			init_chunk_list(tlist, tbuf, tbuf_sz, tbuf_sz);
			init_chunk_list(tdata->out_list, tdata->dst,
					tdata->dst_sz, tdata->dst_sz);
			ret = sw_deflate(tdata->in_list, tlist, opts);
			if (ret) {
				COMP_TST_PRT("Fail to deflate by zlib: %d\n", ret);
				goto out_strm;
			}
			tout_sz = tdata->dst_sz;
			ret = hw_stream_compress(opts,
						 tdata->dst,
						 &tout_sz,
						 tlist->addr,
						 tlist->size);
			if (ret) {
				COMP_TST_PRT("Fail to inflate by HW: %d\n", ret);
				goto out_strm;
			}
			ret = calculate_md5(&tdata->md5, tdata->in_list->addr,
					    tdata->in_list->size);
			if (ret) {
				COMP_TST_PRT("Fail to generate MD5 (%d)\n", ret);
				goto out_strm;
			}
			ret = calculate_md5(&final_md5, tdata->out_list->addr,
					    tout_sz);
			if (ret) {
				COMP_TST_PRT("Fail to generate MD5 (%d)\n", ret);
				goto out_strm;
			}
			ret = cmp_md5(&tdata->md5, &final_md5);
			if (ret) {
				COMP_TST_PRT("MD5 is unmatched (%d) at %dth times on "
					"thread %d\n", ret, i, tdata->tid);
				goto out_strm;
			}
		}
		free_chunk_list(tlist);
		mmap_free(tbuf, tbuf_sz);
		return NULL;
	}

	/* BLOCK mode */
        setup.alg_type = opts->alg_type;
        setup.op_type = WD_DIR_DECOMPRESS;

	param.type = setup.op_type;
	param.numa_id = 0;
	setup.sched_param = &param;
	h_ifl = wd_comp_alloc_sess(&setup);
	if (!h_ifl) {
		ret = -EINVAL;
		goto out_strm;
	}

	init_chunk_list(tdata->in_list, tdata->src, tdata->src_sz,
			info->in_chunk_sz);
	for (i = 0; i < opts->compact_run_num; i++) {
		init_chunk_list(tlist, tbuf, tbuf_sz,
			        info->in_chunk_sz * EXPANSION_RATIO);
		init_chunk_list(tdata->out_list, tdata->dst, tdata->dst_sz,
				info->out_chunk_sz);
		ret = sw_deflate(tdata->in_list, tlist, opts);
		if (ret) {
			COMP_TST_PRT("Fail to deflate by zlib: %d\n", ret);
			goto out_run;
		}
		ret = hw_inflate(h_ifl, tlist, tdata->out_list, opts,
				  &tdata->sem);
		if (ret) {
			COMP_TST_PRT("Fail to inflate by HW: %d\n", ret);
			goto out_run;
		}
		ret = calculate_md5(&tdata->md5, tdata->src, tdata->src_sz);
		if (ret) {
			COMP_TST_PRT("Fail to generate MD5 (%d)\n", ret);
			goto out_run;
		}
		ret = calculate_md5(&final_md5, tdata->dst, tdata->dst_sz);
		if (ret) {
			COMP_TST_PRT("Fail to generate MD5 (%d)\n", ret);
			goto out_run;
		}
		ret = cmp_md5(&tdata->md5, &final_md5);
		if (ret) {
			COMP_TST_PRT("MD5 is unmatched (%d) at %dth times on "
				"thread %d\n", ret, i, tdata->tid);
			goto out_run;
		}
	}
	wd_comp_free_sess(h_ifl);
	free_chunk_list(tlist);
	mmap_free(tbuf, tbuf_sz);
	/* mark sending thread to end */
	__atomic_add_fetch(&sum_thread_end, 1, __ATOMIC_ACQ_REL);
	return NULL;
out_run:
	wd_comp_free_sess(h_ifl);
out_strm:
	free_chunk_list(tlist);
out:
	mmap_free(tbuf, tbuf_sz);
	return (void *)(uintptr_t)(ret);
}

static void *hw_dfl_sw_ifl(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_sess_setup setup = {0};
	struct sched_params param = {0};
	handle_t h_dfl;
	void *tbuf;
	size_t tbuf_sz;
	chunk_list_t *tlist;
	comp_md5_t final_md5 = {{0}};
	int i, ret;
	__u32 tmp_sz;

	tbuf_sz = tdata->src_sz * EXPANSION_RATIO;
	tbuf = mmap_alloc(tbuf_sz);
	if (!tbuf)
		return (void *)(uintptr_t)(-ENOMEM);
	tlist = create_chunk_list(tbuf, tbuf_sz,
				  opts->block_size * EXPANSION_RATIO);
	if (!tlist) {
		ret = -ENOMEM;
		goto out;
	}
	if (opts->option & PERFORMANCE) {
		/* hack:
		 * memset buffer and trigger page fault early in the cpu
		 * instead of later in the SMMU
		 * Enhance performance in sva case
		 * no impact to non-sva case
		 */
		memset(tbuf, 5, tbuf_sz);
	}
	if (opts->is_stream) {
		/* STREAM mode: only one entry in the list */
		init_chunk_list(tdata->in_list, tdata->src,
				tdata->src_sz, tdata->src_sz);
		for (i = 0; i < opts->compact_run_num; i++) {
			init_chunk_list(tlist, tbuf, tbuf_sz, tbuf_sz);
			init_chunk_list(tdata->out_list, tdata->dst,
					tdata->dst_sz, tdata->dst_sz);
			tmp_sz = tbuf_sz;
			ret = hw_stream_compress(opts,
						 tlist->addr,
						 &tmp_sz,
						 tdata->src,
						 tdata->src_sz);
			if (ret) {
				COMP_TST_PRT("Fail to deflate by HW: %d\n", ret);
				goto out_strm;
			}
			tlist->size = tmp_sz;	// write back
			ret = sw_inflate(tlist, tdata->out_list, opts);
			if (ret) {
				COMP_TST_PRT("Fail to inflate by zlib: %d\n", ret);
				goto out_strm;
			}
			ret = calculate_md5(&tdata->md5, tdata->in_list->addr,
					    tdata->in_list->size);
			if (ret) {
				COMP_TST_PRT("Fail to generate MD5 (%d)\n", ret);
				goto out_strm;
			}
			ret = calculate_md5(&final_md5, tdata->out_list->addr,
					    tdata->out_list->size);
			if (ret) {
				COMP_TST_PRT("Fail to generate MD5 (%d)\n", ret);
				goto out_strm;
			}
			ret = cmp_md5(&tdata->md5, &final_md5);
			if (ret) {
				COMP_TST_PRT("MD5 is unmatched (%d) at %dth times on "
					"thread %d\n", ret, i, tdata->tid);
				goto out_strm;
			}
		}
		free_chunk_list(tlist);
		mmap_free(tbuf, tbuf_sz);
		return NULL;
	}

	/* BLOCK mode */
        setup.alg_type = opts->alg_type;
        setup.op_type = WD_DIR_COMPRESS;
	param.type = setup.op_type;
	param.numa_id = 0;
	setup.sched_param = &param;
	h_dfl = wd_comp_alloc_sess(&setup);
	if (!h_dfl) {
		ret = -EINVAL;
		goto out_strm;
	}

	init_chunk_list(tdata->in_list, tdata->src, tdata->src_sz,
			info->in_chunk_sz);
	for (i = 0; i < opts->compact_run_num; i++) {
		init_chunk_list(tlist, tbuf, tbuf_sz,
			        opts->block_size * EXPANSION_RATIO);
		init_chunk_list(tdata->out_list, tdata->dst, tdata->dst_sz,
				info->out_chunk_sz);
		ret = hw_deflate(h_dfl, tdata->in_list, tlist, opts,
				  &tdata->sem);
		if (ret) {
			COMP_TST_PRT("Fail to deflate by HW: %d\n", ret);
			goto out_run;
		}
		ret = sw_inflate(tlist, tdata->out_list, opts);
		if (ret) {
			COMP_TST_PRT("Fail to inflate by zlib: %d\n", ret);
			goto out_run;
		}
		ret = calculate_md5(&tdata->md5, tdata->src, tdata->src_sz);
		if (ret) {
			COMP_TST_PRT("Fail to generate MD5 (%d)\n", ret);
			goto out_run;
		}
		ret = calculate_md5(&final_md5, tdata->dst, tdata->dst_sz);
		if (ret) {
			COMP_TST_PRT("Fail to generate MD5 (%d)\n", ret);
			goto out_run;
		}
		ret = cmp_md5(&tdata->md5, &final_md5);
		if (ret) {
			COMP_TST_PRT("MD5 is unmatched (%d) at %dth times on "
				"thread %d\n", ret, i, tdata->tid);
			goto out_run;
		}
	}
	wd_comp_free_sess(h_dfl);
	free_chunk_list(tlist);
	mmap_free(tbuf, tbuf_sz);
	/* mark sending thread to end */
	__atomic_add_fetch(&sum_thread_end, 1, __ATOMIC_ACQ_REL);
	return NULL;
out_run:
	wd_comp_free_sess(h_dfl);
out_strm:
	free_chunk_list(tlist);
out:
	mmap_free(tbuf, tbuf_sz);
	return (void *)(uintptr_t)(ret);
}

static void *hw_dfl_hw_ifl(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_sess_setup setup = {0};
	struct sched_params param = {0};
	handle_t h_dfl, h_ifl;
	void *tbuf;
	size_t tbuf_sz;
	chunk_list_t *tlist;
	comp_md5_t final_md5 = {{0}};
	int i, ret;
	__u32 tmp_sz, tout_sz;

	tbuf_sz = tdata->src_sz * EXPANSION_RATIO;
	tbuf = mmap_alloc(tbuf_sz);
	if (!tbuf)
		return (void *)(uintptr_t)(-ENOMEM);
	if (opts->option & PERFORMANCE) {
		/* hack:
		 * memset buffer and trigger page fault early in the cpu
		 * instead of later in the SMMU
		 * Enhance performance in sva case
		 * no impact to non-sva case
		 */
		memset(tbuf, 5, tbuf_sz);
	}
	if (opts->is_stream) {
		for (i = 0; i < opts->compact_run_num; i++) {
			tmp_sz = tbuf_sz;
			ret = hw_stream_compress(opts,
						 tbuf,
						 &tmp_sz,
						 tdata->src,
						 tdata->src_sz);
			if (ret) {
				COMP_TST_PRT("Fail to deflate by HW: %d\n", ret);
				goto out;
			}
			tout_sz = tdata->dst_sz;
			ret = hw_stream_compress(opts,
						 tdata->dst,
						 &tout_sz,
						 tbuf,
						 tmp_sz);
			if (ret) {
				COMP_TST_PRT("Fail to inflate by HW: %d\n", ret);
				goto out;
			}
			ret = calculate_md5(&tdata->md5, tdata->in_list->addr,
					    tdata->in_list->size);
			if (ret) {
				COMP_TST_PRT("Fail to generate MD5 (%d)\n", ret);
				goto out;
			}
			ret = calculate_md5(&final_md5, tdata->dst, tout_sz);
			if (ret) {
				COMP_TST_PRT("Fail to generate MD5 (%d)\n", ret);
				goto out;
			}
			ret = cmp_md5(&tdata->md5, &final_md5);
			if (ret) {
				COMP_TST_PRT("MD5 is unmatched (%d) at %dth times on "
					"thread %d\n", ret, i, tdata->tid);
				goto out;
			}
		}
		mmap_free(tbuf, tbuf_sz);
		return NULL;
	}

	/* BLOCK mode */
	tlist = create_chunk_list(tbuf, tbuf_sz,
				  opts->block_size * EXPANSION_RATIO);
	if (!tlist) {
		ret = -ENOMEM;
		goto out;
	}

        setup.alg_type = opts->alg_type;
        setup.op_type = WD_DIR_COMPRESS;
	param.type = setup.op_type;
	param.numa_id = 0;
	setup.sched_param = &param;
	h_dfl = wd_comp_alloc_sess(&setup);
	if (!h_dfl) {
		ret = -EINVAL;
		goto out_dfl;
	}

	setup.op_type = WD_DIR_DECOMPRESS;
	param.type = setup.op_type;
	setup.sched_param = &param;
	h_ifl = wd_comp_alloc_sess(&setup);
	if (!h_ifl) {
		ret = -EINVAL;
		goto out_ifl;
	}

	for (i = 0; i < opts->compact_run_num; i++) {
		init_chunk_list(tlist, tbuf, tbuf_sz,
			        opts->block_size * EXPANSION_RATIO);
		init_chunk_list(tdata->out_list, tdata->dst,
				tdata->dst_sz,
				info->out_chunk_sz);
		ret = hw_deflate(h_dfl, tdata->in_list, tlist, opts,
				  &tdata->sem);
		if (ret) {
			COMP_TST_PRT("Fail to deflate by HW: %d\n", ret);
			goto out_run;
		}
		ret = hw_inflate(h_ifl, tlist, tdata->out_list, opts,
				  &tdata->sem);
		if (ret) {
			COMP_TST_PRT("Fail to inflate by HW: %d\n", ret);
			goto out_run;
		}
		ret = calculate_md5(&tdata->md5, tdata->src, tdata->src_sz);
		if (ret) {
			COMP_TST_PRT("Fail to generate MD5 (%d)\n", ret);
			goto out_run;
		}
		ret = calculate_md5(&final_md5, tdata->dst, tdata->dst_sz);
		if (ret) {
			COMP_TST_PRT("Fail to generate MD5 (%d)\n", ret);
			goto out_run;
		}
		ret = cmp_md5(&tdata->md5, &final_md5);
		if (ret) {
			COMP_TST_PRT("MD5 is unmatched (%d) at %dth times on "
				"thread %d\n", ret, i, tdata->tid);
			goto out_run;
		}
	}
	wd_comp_free_sess(h_ifl);
	wd_comp_free_sess(h_dfl);
	free_chunk_list(tlist);
	mmap_free(tbuf, tbuf_sz);
	/* mark sending thread to end */
	__atomic_add_fetch(&sum_thread_end, 1, __ATOMIC_ACQ_REL);
	return NULL;
out_run:
	wd_comp_free_sess(h_ifl);
out_ifl:
	wd_comp_free_sess(h_dfl);
out_dfl:
	free_chunk_list(tlist);
out:
	mmap_free(tbuf, tbuf_sz);
	return (void *)(uintptr_t)(ret);
}

static void *hw_dfl_perf(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_sess_setup setup = {0};
	struct sched_params param = {0};
	handle_t h_dfl;
	int i, ret;
	uint32_t tout_sz;

	if (opts->is_stream) {
		for (i = 0; i < opts->compact_run_num; i++) {
			tout_sz = tdata->dst_sz;
			if (opts->option & TEST_ZLIB) {
				ret = zlib_deflate(info->out_buf, info->out_size,
						   info->in_buf, info->in_size,
						   &tdata->sum, opts->alg_type);
				continue;
			}
			ret = hw_stream_compress(opts,
						 tdata->dst,
						 &tout_sz,
						 tdata->src,
						 tdata->src_sz);
			if (ret) {
				COMP_TST_PRT("Fail to deflate by HW(stm): %d\n", ret);
				return (void *)(uintptr_t)ret;
			}
		}
		tdata->out_list->addr = tdata->dst;
		tdata->out_list->size = tout_sz;
		tdata->out_list->next = NULL;
		return NULL;
	}

        setup.alg_type = opts->alg_type;
        setup.op_type = WD_DIR_COMPRESS;
	param.type = setup.op_type;
	param.numa_id = 0;
	setup.sched_param = &param;
	h_dfl = wd_comp_alloc_sess(&setup);
	if (!h_dfl)
		return (void *)(uintptr_t)(-EINVAL);

	for (i = 0; i < opts->compact_run_num; i++) {
		init_chunk_list(tdata->out_list, tdata->dst,
				tdata->dst_sz,
				info->out_chunk_sz);
		ret = hw_deflate(h_dfl, tdata->in_list, tdata->out_list, opts,
				  &tdata->sem);
		if (ret) {
			COMP_TST_PRT("Fail to deflate by HW(blk): %d\n", ret);
			goto out;
		}
	}
	wd_comp_free_sess(h_dfl);
	/* mark sending thread to end */
	__atomic_add_fetch(&sum_thread_end, 1, __ATOMIC_ACQ_REL);
	return NULL;
out:
	wd_comp_free_sess(h_dfl);
	return (void *)(uintptr_t)(ret);
}

static void *hw_ifl_perf(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	struct hizip_test_info *info = tdata->info;
	struct test_options *opts = info->opts;
	struct wd_comp_sess_setup setup = {0};
	struct sched_params param = {0};
	handle_t h_ifl;
	int i, ret;
	uint32_t tout_sz;

	if (opts->is_stream) {
		for (i = 0; i < opts->compact_run_num; i++) {
			tout_sz = tdata->dst_sz;
			if (opts->option & TEST_ZLIB) {
				ret = zlib_deflate(info->out_buf, info->out_size,
						   info->in_buf, info->in_size,
						   &tdata->sum, opts->alg_type);
				continue;
			}
			ret = hw_stream_compress(opts,
						 tdata->dst,
						 &tout_sz,
						 tdata->in_list->addr,
						 tdata->in_list->size);
			if (ret) {
				COMP_TST_PRT("Fail to inflate by HW: %d\n", ret);
				return (void *)(uintptr_t)ret;
			}
			tdata->out_list->addr = tdata->dst;
			tdata->out_list->size = tout_sz;
			tdata->out_list->next = NULL;
		}
		return NULL;
	}

        setup.alg_type = opts->alg_type;
        setup.op_type = WD_DIR_DECOMPRESS;
	param.type = setup.op_type;
	param.numa_id = 0;
	setup.sched_param = &param;
	h_ifl = wd_comp_alloc_sess(&setup);
	if (!h_ifl)
		return (void *)(uintptr_t)(-EINVAL);

	for (i = 0; i < opts->compact_run_num; i++) {
		init_chunk_list(tdata->out_list, tdata->dst,
				tdata->dst_sz,
				info->out_chunk_sz);
		ret = hw_inflate(h_ifl, tdata->in_list, tdata->out_list, opts,
				  &tdata->sem);
		if (ret) {
			COMP_TST_PRT("Fail to inflate by HW: %d\n", ret);
			goto out;
		}
	}
	wd_comp_free_sess(h_ifl);
	/* mark sending thread to end */
	__atomic_add_fetch(&sum_thread_end, 1, __ATOMIC_ACQ_REL);
	return NULL;
out:
	wd_comp_free_sess(h_ifl);
	return (void *)(uintptr_t)(ret);
}

/*
 * Load compression/decompression content.
 */
int load_file_data(struct hizip_test_info *info)
{
	struct test_options *opts = info->opts;
	size_t file_sz;

	file_sz = read(opts->fd_in, info->in_buf, info->in_size);
	if (file_sz < info->in_size) {
		COMP_TST_PRT("Expect to read %ld bytes. "
		       "But only read %ld bytes!\n",
		       info->in_size, file_sz);
		return -EFAULT;
	}
	return (int)file_sz;
}

/*
 * Store both output file. opts->is_file must be enabled first.
 */
int store_file(struct hizip_test_info *info, char *model)
{
	struct test_options *opts = info->opts;
	thread_data_t *tdata = &info->tdatas[0];
	chunk_list_t *p;
	size_t sum = 0;
	ssize_t file_sz = 0;

	if (!opts->is_stream) {
		COMP_TST_PRT("Invalid, file need stream mode!\n");
		return -EINVAL;
	} else {
		p = tdata->out_list;
		file_sz = write(opts->fd_out, p->addr, p->size);
		if (file_sz < p->size)
			return -EFAULT;
		sum = file_sz;
	}
	return (int)sum;
}

static int nonenv_resource_init(struct test_options *opts,
				struct hizip_test_info *info,
				struct wd_sched **sched)
{
	int ret;

	info->list = get_dev_list(opts, 1);
	if (!info->list)
		return -EINVAL;
	ret = init_ctx_config(opts, info, sched);
	if (ret < 0) {
		wd_free_list_accels(info->list);
		return ret;
	}
	return 0;
}

static void nonenv_resource_uninit(struct test_options *opts,
				   struct hizip_test_info *info,
				   struct wd_sched *sched)
{
	uninit_config(info, sched);
	wd_free_list_accels(info->list);
}

static bool event_unavailable = false;

int test_hw(struct test_options *opts, char *model)
{
	struct hizip_test_info info = {0};
	struct wd_sched *sched = NULL;
	double ilen, usec, speed;
	char zbuf[120];
	int ret, zbuf_idx, ifl_flag = 0;
	void *(*func)(void *);
	size_t tbuf_sz = 0;
	void *tbuf = NULL;
	struct stat statbuf;
	chunk_list_t *tlist = NULL;
	__u32 num;
	__u8 enable;
	int nr_fds = 0;
	int *perf_fds = NULL;
	struct hizip_stats stats;

	if (!opts || !model) {
		ret = -EINVAL;
		goto out;
	}
	info.opts = opts;
	info.stats = &stats;

	if (!event_unavailable &&
	    perf_event_get("iommu/dev_fault", &perf_fds, &nr_fds)) {
		COMP_TST_PRT("IOPF statistic unavailable\n");
		/* No need to retry and print an error on every run */
		event_unavailable = true;
	}
	stat_setup(&info);

	memset(zbuf, 0, 120);
	if (!strcmp(model, "sw_dfl_hw_ifl")) {
		func = sw_dfl_hw_ifl;
		info.in_size = opts->total_len;
		if (opts->is_stream)
			info.out_size = opts->total_len;
		else
			info.out_size = opts->total_len;
		info.in_chunk_sz = opts->block_size;
		info.out_chunk_sz = opts->block_size;
		zbuf_idx = sprintf(zbuf, "Mix SW deflate and HW %s %s inflate",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK");
	} else if (!strcmp(model, "hw_dfl_sw_ifl")) {
		func = hw_dfl_sw_ifl;
		info.in_size = opts->total_len;
		info.out_size = opts->total_len;
		info.in_chunk_sz = opts->block_size;
		info.out_chunk_sz = opts->block_size;
		zbuf_idx = sprintf(zbuf, "Mix HW %s %s deflate and SW inflate",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK");
	} else if (!strcmp(model, "hw_dfl_hw_ifl")) {
		func = hw_dfl_hw_ifl;
		info.in_size = opts->total_len;
		if (opts->is_stream)
			info.out_size = opts->total_len;
		else
			info.out_size = opts->total_len;
		info.in_chunk_sz = opts->block_size;
		info.out_chunk_sz = opts->block_size;
		zbuf_idx = sprintf(zbuf,
				   "Mix HW %s %s deflate and HW %s %s inflate",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK");
	} else if (!strcmp(model, "hw_dfl_perf")) {
		func = hw_dfl_perf;
		info.in_size = opts->total_len;
		info.out_size = opts->total_len * EXPANSION_RATIO;
		info.in_chunk_sz = opts->block_size;
		info.out_chunk_sz = opts->block_size * EXPANSION_RATIO;
		zbuf_idx = sprintf(zbuf, "HW %s %s deflate",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK");
	} else if (!strcmp(model, "hw_ifl_perf")) {
		func = hw_ifl_perf;
		info.in_size = opts->total_len;
		info.out_size = opts->total_len * INFLATION_RATIO;
		info.in_chunk_sz = opts->block_size;
		info.out_chunk_sz = opts->block_size * INFLATION_RATIO;
		zbuf_idx = sprintf(zbuf, "HW %s %s inflate",
				   opts->sync_mode ? "ASYNC" : "SYNC",
				   opts->is_stream ? "STREAM" : "BLOCK");
		ifl_flag = 1;
	} else {
		COMP_TST_PRT("Wrong model is specified:%s\n", model);
		ret = -EINVAL;
		goto out;
	}

	if (opts->use_env)
		ret = wd_comp_env_init(NULL);
	else
		ret = nonenv_resource_init(opts, &info, &sched);
	if (ret < 0)
		goto out;

	if (opts->faults & INJECT_SIG_BIND)
		kill(getpid(), SIGTERM);

	if (opts->use_env) {
		ret = wd_comp_get_env_param(0, opts->op_type, opts->sync_mode, &num, &enable);
		if (ret < 0)
			goto out;
	}

	if (opts->is_file) {
		ret = fstat(opts->fd_in, &statbuf);
		if (ret < 0)
			goto out_src;
		opts->total_len = statbuf.st_size;
		info.in_size = opts->total_len;
		if (ifl_flag)
			info.out_size = opts->total_len * INFLATION_RATIO;
		else
			info.out_size = opts->total_len * EXPANSION_RATIO;
	}
	info.in_buf = mmap_alloc(info.in_size);
	if (!info.in_buf) {
		ret = -ENOMEM;
		goto out_src;
	}
	ret = create_send_tdata(opts, &info);
	if (ret)
		goto out_send;
	ret = create_poll_tdata(opts, &info, opts->poll_num);
	if (ret)
		goto out_poll;
	if (opts->is_file) {
		/* in_list is created by create_send3_threads(). */
		ret = load_file_data(&info);
		if (ret < 0)
			goto out_buf;
	} else {
		if (ifl_flag) {
			thread_data_t *tdata = info.tdatas;
			tbuf_sz = info.in_size / EXPANSION_RATIO;
			tbuf = mmap_alloc(tbuf_sz);
			if (!tbuf) {
				ret = -ENOMEM;
				goto out_buf;
			}
			tlist = create_chunk_list(tbuf, tbuf_sz,
						  opts->block_size /
						  EXPANSION_RATIO);
			init_chunk_list(tlist, tbuf, tbuf_sz,
					opts->block_size / EXPANSION_RATIO);
			gen_random_data(tbuf, tbuf_sz);
			ret = sw_deflate(tlist, tdata[0].in_list, opts);
			if (ret) {
				free_chunk_list(tlist);
				mmap_free(tbuf, tbuf_sz);
				goto out_buf;
			}
			free_chunk_list(tlist);
			mmap_free(tbuf, tbuf_sz);
		} else
			gen_random_data(info.in_buf, info.in_size);
	}
	if (opts->faults & INJECT_TLB_FAULT) {
		/*
		 * Now unmap the buffers and retry the access. Normally we
		 * should get an access fault, but if the TLB wasn't properly
		 * invalidated, the access succeeds and corrupts memory!
		 * This test requires small jobs, to make sure that we reuse
		 * the same TLB entry between the tests. Run for example with
		 * "-s 0x1000 -b 0x1000".
		 */
		ret = munmap(info.in_buf, info.in_size);
		if (ret) {
			COMP_TST_PRT("Failed to unmap.");
			goto out_buf;
		}
		/* A warning if the parameters might produce false positives */
		if (opts->total_len > 0x54000)
			COMP_TST_PRT( "NOTE: test might trash the TLB\n");
	}
	stat_start(&info);
	ret = attach_threads(opts, &info, func, poll_thread_func);
	if (ret)
		goto out_buf;
	stat_end(&info);
	info.stats->v[ST_IOPF] = perf_event_put(perf_fds, nr_fds);
	if (opts->is_file)
		(void)store_file(&info, model);

	usec = info.stats->v[ST_RUN_TIME] / 1000;
	if (opts->op_type == WD_DIR_DECOMPRESS)
		ilen = (float)count_chunk_list_sz(info.tdatas[0].out_list);
	else
		ilen = opts->total_len;
	ilen *= opts->thread_num * opts->compact_run_num;
	speed = ilen * 1000 * 1000 / 1024 / 1024 / usec;
	if (opts->sync_mode) {
		zbuf_idx += sprintf(zbuf + zbuf_idx,
				    " with %d send + %d poll threads",
				    opts->thread_num,
				    opts->poll_num);
	} else {
		zbuf_idx += sprintf(zbuf + zbuf_idx,
				    " with %d send threads",
				    opts->thread_num);
	}
	if (!strcmp(model, "hw_dfl_perf") || !strcmp(model, "hw_ifl_perf")) {
		COMP_TST_PRT("%s at %.2fMB/s in %f usec (BLK:%d).\n",
		       zbuf, speed, usec, opts->block_size);
	} else {
		COMP_TST_PRT("%s in %f usec (BLK:%d).\n",
		       zbuf, usec, opts->block_size);
	}
	free_threads_tdata(&info);
	if (opts->use_env)
		wd_comp_env_uninit();
	else
		nonenv_resource_uninit(opts, &info, sched);
	usleep(1000);
	return 0;
out_buf:
out_poll:
	free_threads_tdata(&info);
	if (opts->use_env)
		wd_comp_env_uninit();
	else
		nonenv_resource_uninit(opts, &info, sched);
	COMP_TST_PRT("Fail to run %s() (%d)!\n", model, ret);
	return ret;
out_send:
	mmap_free(info.in_buf, info.in_size);
out_src:
	if (opts->use_env)
		wd_comp_env_uninit();
	else
		nonenv_resource_uninit(opts, &info, sched);
out:
	COMP_TST_PRT("Fail to run %s() (%d)!\n", model, ret);
	return ret;
}

int run_self_test(struct test_options *opts)
{
	int i, f_ret = 0;
	char poll_str[POLL_STRING_LEN];

	COMP_TST_PRT("Start to run self test!\n");
	opts->alg_type = WD_ZLIB;
	opts->data_fmt = WD_FLAT_BUF;
	opts->sync_mode = 0;
	opts->q_num = 16;
	for (i = 0; i < 10; i++) {
		opts->sync_mode = 0;
		switch (i) {
		case 0:
			opts->thread_num = 1;
			break;
		case 1:
			opts->thread_num = 2;
			break;
		case 2:
			opts->thread_num = 4;
			break;
		case 3:
			opts->thread_num = 8;
			break;
		case 4:
			opts->thread_num = 16;
			break;
		case 5:
			opts->thread_num = 1;
			opts->is_stream = 1;
			break;
		case 6:
			opts->thread_num = 2;
			opts->is_stream = 1;
			break;
		case 7:
			opts->thread_num = 4;
			opts->is_stream = 1;
			break;
		case 8:
			opts->thread_num = 8;
			opts->is_stream = 1;
			break;
		case 9:
			opts->thread_num = 16;
			opts->is_stream = 1;
			break;
		}
		f_ret |= test_hw(opts, "hw_dfl_perf");
		f_ret |= test_hw(opts, "hw_ifl_perf");
	}
	opts->is_stream = 0;	/* restore to BLOCK mode */
	for (i = 0; i < 5; i++) {
		opts->thread_num = 8;
		switch (i) {
		case 0:
			opts->sync_mode = 0;
			break;
		case 1:
			opts->sync_mode = 1;	opts->poll_num = 1;
			break;
		case 2:
			opts->sync_mode = 1;	opts->poll_num = 2;
			break;
		case 3:
			opts->sync_mode = 1;	opts->poll_num = 4;
			break;
		case 4:
			opts->sync_mode = 1;	opts->poll_num = 8;
			break;
		default:
			return -EINVAL;
		}
		if (opts->use_env && opts->poll_num) {
			memset(poll_str, 0, POLL_STRING_LEN);
			sprintf(poll_str,
				"sync-comp:8@0,sync-decomp:8@0,"
				"async-comp:8@0,async-decomp:8@0");
			setenv("WD_COMP_CTX_NUM", poll_str, 1);
			memset(poll_str, 0, POLL_STRING_LEN);
			sprintf(poll_str, "%d@0", opts->poll_num),
			setenv("WD_COMP_ASYNC_POLL_NUM", poll_str, 1);
		}
		f_ret |= test_hw(opts, "sw_dfl_hw_ifl");
		f_ret |= test_hw(opts, "hw_dfl_sw_ifl");
		f_ret |= test_hw(opts, "hw_dfl_hw_ifl");
		f_ret |= test_hw(opts, "hw_dfl_perf");
		f_ret |= test_hw(opts, "hw_ifl_perf");
	}
	if (!f_ret)
		COMP_TST_PRT("Run self test successfully!\n");
	return f_ret;
}

static int set_default_opts(struct test_options *opts)
{
	if (!opts->block_size)
		opts->block_size = 8192;
	if (!opts->total_len) {
		if (opts->block_size)
			opts->total_len = opts->block_size * 10;
		else
			opts->total_len = 8192 * 10;
	}
	if (!opts->thread_num)
		opts->thread_num = 1;
	if (!opts->q_num)
		opts->q_num = opts->thread_num;
	if (!opts->compact_run_num)
		opts->compact_run_num = 1;
	if (!opts->poll_num)
		opts->poll_num = 1;
	if (opts->alg_type == WD_COMP_ALG_MAX)
		opts->alg_type = WD_GZIP;
	return 0;
}

static int run_one_cmd(struct test_options *opts)
{
	int ret;

	if (opts->op_type == WD_DIR_COMPRESS) {
		if (opts->verify)
			ret = test_hw(opts, "hw_dfl_sw_ifl");
		else
			ret = test_hw(opts, "hw_dfl_perf");
	} else {
		if (opts->verify)
			ret = test_hw(opts, "sw_dfl_hw_ifl");
		else
			ret = test_hw(opts, "hw_ifl_perf");
	}
	return ret;
}

int run_cmd(struct test_options *opts)
{
	int ret = 0, i;
	int nr_children = 0, status;
	pid_t pid, *pids = NULL;
	bool success = true;

	set_default_opts(opts);
	if (opts->children) {
		pids = calloc(opts->children, sizeof(pid_t));
		if (!pids)
			return -ENOMEM;
		for (i = 0; i < opts->children; i++) {
			pid = fork();
			if (pid < 0) {
				COMP_TST_PRT("cannot fork: %d\n", errno);
				success = false;
				break;
			} else if (pid > 0) {
				/* Parent */
				pids[nr_children++] = pid;
				continue;
			}
			/* Child */
			ret = run_one_cmd(opts);
			return ret;
		}
		for (i = 0; i < nr_children; i++) {
			pid = pids[i];
			ret = waitpid(pid, &status, 0);
			if (ret < 0) {
				COMP_TST_PRT("wait(pid=%d) error %d\n", pid, errno);
				success = false;
				continue;
			}
			if (WIFEXITED(status)) {
				ret = WEXITSTATUS(status);
				if (ret) {
					COMP_TST_PRT("child %d returned with %d\n",
					       pid, ret);
					success = false;
				}
			} else if (WIFSIGNALED(status)) {
				ret = WTERMSIG(status);
				COMP_TST_PRT("child %d killed by sig %d\n", pid, ret);
				success = false;
			} else {
				COMP_TST_PRT("unexpected status for child %d\n", pid);
				success = false;
			}
		}
		if (success == false) {
			COMP_TST_PRT("Failed to run spawn test!\n");
			if (!ret)
				ret = -EINVAL;
		}
	} else
		ret = run_one_cmd(opts);
	return ret;
}

int perf_event_open(struct perf_event_attr *attr,
			   pid_t pid, int cpu, int group_fd,
			   unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

unsigned long long perf_event_put(int *perf_fds, int nr_fds);

int perf_event_get(const char *event_name, int **perf_fds, int *nr_fds)
{
	int ret;
	int cpu;
	FILE *fd;
	int nr_cpus;
	unsigned int event_id;
	char event_id_file[256];
	struct perf_event_attr event = {
		.type		= PERF_TYPE_TRACEPOINT,
		.size		= sizeof(event),
		.disabled	= true,
	};

	*perf_fds = NULL;
	*nr_fds = 0;

	nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (nr_cpus <= 0) {
		WD_ERR("invalid number of CPUs\n");
		return nr_cpus;
	}

	ret = snprintf(event_id_file, sizeof(event_id_file),
		       "/sys/kernel/debug/tracing/events/%s/id", event_name);
	if (ret >= sizeof(event_id_file)) {
		WD_ERR("event_id buffer overflow\n");
		return -EOVERFLOW;
	}
	fd = fopen(event_id_file, "r");
	if (fd == NULL) {
		ret = -errno;
		WD_ERR("Couldn't open file %s\n", event_id_file);
		return ret;
	}

	if (fscanf(fd, "%d", &event_id) != 1) {
		WD_ERR("Couldn't parse file %s\n", event_id_file);
		return -EINVAL;
	}
	fclose(fd);
	event.config = event_id;

	*perf_fds = calloc(nr_cpus, sizeof(int));
	if (!*perf_fds)
		return -ENOMEM;
	*nr_fds = nr_cpus;

	/*
	 * An event is bound to either a CPU or a PID. If we want both, we need
	 * to open the event on all CPUs. Note that we can't use a perf group
	 * since they have to be on the same CPU.
	 */
	for (cpu = 0; cpu < nr_cpus; cpu++) {
		int fd = perf_event_open(&event, -1, cpu, -1, 0);

		if (fd < 0) {
			WD_ERR("Couldn't get perf event %s on CPU%d: %d\n",
			       event_name, cpu, errno);
			perf_event_put(*perf_fds, cpu);
			return fd;
		}

		ioctl(fd, PERF_EVENT_IOC_RESET, 0);
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
		(*perf_fds)[cpu] = fd;
	}

	return 0;
}

/*
 * Closes the perf fd and return the sample count. If it wasn't open, return 0.
 */
unsigned long long perf_event_put(int *perf_fds, int nr_fds)
{
	int ret;
	int cpu;
	uint64_t count, total = 0;

	if (!perf_fds)
		return 0;

	for (cpu = 0; cpu < nr_fds; cpu++) {
		int fd = perf_fds[cpu];

		if (fd <= 0) {
			WD_ERR("Invalid perf fd %d\n", cpu);
			continue;
		}

		ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

		ret = read(fd, &count, sizeof(count));
		if (ret < sizeof(count))
			WD_ERR("Couldn't read perf event for CPU%d\n", cpu);

		total += count;
		close(fd);

	}

	free(perf_fds);
	return total;
}

static void set_thp(struct test_options *opts)
{
	char *p;
	char s[14];
	FILE *file;

	file = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "r");
	if (!file)
		goto out_err;
	p = fgets(s, 14, file);
	fclose(file);
	if (!p)
		goto out_err;

	if (strcmp(s, "never") == 0) {
		COMP_TST_PRT("Cannot test THP with enable=never\n");
		return;
	}

	file = fopen("/sys/kernel/mm/transparent_hugepage/defrag", "r");
	if (!file)
		goto out_err;
	p = fgets(s, 14, file);
	fclose(file);
	if (!p)
		goto out_err;

	if (strcmp(s, "defer") == 0 || strcmp(s, "never") == 0) {
		COMP_TST_PRT("Cannot test THP with defrag=%s\n", s);
		return;
	}

	return;
out_err:
	COMP_TST_PRT("THP unsupported?\n");
}

void stat_setup(struct hizip_test_info *info)
{
	clock_gettime(CLOCK_MONOTONIC_RAW, &info->tv.setup_time);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &info->tv.setup_cputime);
	getrusage(RUSAGE_SELF, &info->tv.setup_rusage);
}

void stat_start(struct hizip_test_info *info)
{
	clock_gettime(CLOCK_MONOTONIC_RAW, &info->tv.start_time);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &info->tv.start_cputime);
	getrusage(RUSAGE_SELF, &info->tv.start_rusage);
}

void stat_end(struct hizip_test_info *info)
{
	struct test_options *opts = info->opts;
	struct hizip_stats *stats = info->stats;
	double v;
	size_t total_out;
	unsigned long total_len;

	total_out = __atomic_load_n(&info->total_out, __ATOMIC_ACQUIRE);
	clock_gettime(CLOCK_MONOTONIC_RAW, &info->tv.end_time);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &info->tv.end_cputime);
	getrusage(RUSAGE_SELF, &info->tv.end_rusage);

	stats->v[ST_SETUP_TIME] = (info->tv.start_time.tv_sec -
				   info->tv.setup_time.tv_sec) * 1000000000 +
				  info->tv.start_time.tv_nsec -
				  info->tv.setup_time.tv_nsec;
	stats->v[ST_RUN_TIME] = (info->tv.end_time.tv_sec -
				 info->tv.start_time.tv_sec) * 1000000000 +
				info->tv.end_time.tv_nsec -
				info->tv.start_time.tv_nsec;

	stats->v[ST_CPU_TIME] = (info->tv.end_cputime.tv_sec -
				 info->tv.setup_cputime.tv_sec) * 1000000000 +
				info->tv.end_cputime.tv_nsec -
				info->tv.setup_cputime.tv_nsec;
	stats->v[ST_USER_TIME] = (info->tv.end_rusage.ru_utime.tv_sec -
				  info->tv.setup_rusage.ru_utime.tv_sec) *
				 1000000 +
				 info->tv.end_rusage.ru_utime.tv_usec -
				 info->tv.setup_rusage.ru_utime.tv_usec;
	stats->v[ST_SYSTEM_TIME] = (info->tv.end_rusage.ru_stime.tv_sec -
				    info->tv.setup_rusage.ru_stime.tv_sec) *
				   1000000 +
				   info->tv.end_rusage.ru_stime.tv_usec -
				   info->tv.setup_rusage.ru_stime.tv_usec;

	stats->v[ST_MINFLT] = info->tv.end_rusage.ru_minflt -
			      info->tv.setup_rusage.ru_minflt;
	stats->v[ST_MAJFLT] = info->tv.end_rusage.ru_majflt -
			      info->tv.setup_rusage.ru_majflt;

	stats->v[ST_VCTX] = info->tv.end_rusage.ru_nvcsw -
			    info->tv.setup_rusage.ru_nvcsw;
	stats->v[ST_INVCTX] = info->tv.end_rusage.ru_nivcsw -
			      info->tv.setup_rusage.ru_nivcsw;

	stats->v[ST_SIGNALS] = info->tv.end_rusage.ru_nsignals -
			       info->tv.setup_rusage.ru_nsignals;

	/* check last loop is enough, same as below hizip_verify_output */
	stats->v[ST_COMPRESSION_RATIO] = (double)opts->total_len /
					 total_out * 100;

	total_len = opts->total_len * opts->compact_run_num;
	/* ST_RUN_TIME records nanoseconds */
	stats->v[ST_SPEED] = (total_len * opts->thread_num * 1000) /
				(1.024 * 1.024 * stats->v[ST_RUN_TIME]);

	stats->v[ST_TOTAL_SPEED] = (total_len * opts->thread_num * 1000) /
				   ((stats->v[ST_RUN_TIME] +
				    stats->v[ST_SETUP_TIME]) * 1.024 * 1.024);

	v = stats->v[ST_RUN_TIME] + stats->v[ST_SETUP_TIME];
	stats->v[ST_CPU_IDLE] = (v - stats->v[ST_CPU_TIME]) / v * 100;
	stats->v[ST_FAULTS] = stats->v[ST_MAJFLT] + stats->v[ST_MINFLT];
}

static void handle_sigbus(int sig)
{
	    COMP_TST_PRT("SIGBUS!\n");
	        _exit(0);
}

int test_comp_entry(int argc, char *argv[])
{
	struct test_options opts = {
		.alg_type		= WD_GZIP,
		.op_type		= WD_DIR_COMPRESS,
		.q_num			= 1,
		.compact_run_num	= 1,
		.thread_num		= 1,
		.sync_mode		= 0,
		.block_size		= 512000,
		.total_len		= opts.block_size * 10,
		.verify			= false,
		.is_decomp		= false,
		.is_stream		= false,
		.is_file		= false,
		.display_stats		= STATS_PRETTY,
		.children		= 0,
		.faults			= 0,
		.data_fmt		= 0,
	};
	struct option long_options[] = {
		{"self",	no_argument,	0, 0 },
		{"in",		required_argument,	0, 0 },
		{"out",		required_argument,	0, 0 },
		{"env",		no_argument,	0, 0 },
		{0,		0,		0, 0 },
	};
	int show_help = 0;
	int opt, option_idx;
	int self = 0;

	opts.fd_in = -1;
	opts.fd_out = -1;
	opts.alg_type = WD_COMP_ALG_MAX;
	while ((opt = getopt_long(argc, argv, COMMON_OPTSTRING "f:o:w:k:r:",
				  long_options, &option_idx)) != -1) {
		switch (opt) {
		case 0:
			switch (option_idx) {
			case 0:		/* self */
				self = 1;
				break;
			case 1:		/* in */
				if (optarg) {
					opts.fd_in = open(optarg, O_RDONLY);
					if (opts.fd_in < 0) {
						COMP_TST_PRT("Fail to open %s\n",
							optarg);
						show_help = 1;
					} else
						opts.is_file = true;
				} else {
					COMP_TST_PRT("Input file is missing!\n");
					show_help = 1;
				}
				if (lseek(opts.fd_in, 0, SEEK_SET) < 0) {
					COMP_TST_PRT("Fail on lseek()!\n");
					show_help = 1;
				}
				break;
			case 2:		/* out */
				if (optarg) {
					opts.fd_out = open(optarg,
							   O_CREAT | O_WRONLY,
							   S_IWUSR | S_IRGRP |
							   S_IROTH);
					if (opts.fd_out < 0) {
						COMP_TST_PRT("Fail to open %s\n",
							optarg);
						show_help = 1;
					} else
						opts.is_file = true;
				} else {
					COMP_TST_PRT("Output file is missing!\n");
					show_help = 1;
				}
				if (lseek(opts.fd_out, 0, SEEK_SET) < 0) {
					COMP_TST_PRT("Fail on lseek()!\n");
					show_help = 1;
				}
				break;
			case 3:		/* env */
				opts.use_env = true;
				break;
			default:
				show_help = 1;
				break;
			}
			break;
		case 'f':
			if (strcmp(optarg, "none") == 0) {
				opts.display_stats = STATS_NONE;
			} else if (strcmp(optarg, "csv") == 0) {
				opts.display_stats = STATS_CSV;
			} else if (strcmp(optarg, "pretty") == 0) {
				opts.display_stats = STATS_PRETTY;
			} else {
				SYS_ERR_COND(1, "invalid argument to -f: '%s'\n", optarg);
				break;
			}
			break;
		case 'o':
			switch (optarg[0]) {
			case 'p':
				opts.option |= PERFORMANCE;
				break;
			case 't':
				opts.option |= TEST_THP;
				set_thp(&opts);
				break;
			default:
				SYS_ERR_COND(1, "invalid argument to -o: '%s'\n", optarg);
				break;
			}
			break;
		case 'c':
			opts.option |= TEST_ZLIB;
			break;
		case 'r':
			opts.children = strtol(optarg, NULL, 0);
			if (opts.children < 0)
				show_help = 1;
			break;
		case 'k':
			switch (optarg[0]) {
			case 'b':
				opts.faults |= INJECT_SIG_BIND;
				break;
			case 't':
				opts.faults |= INJECT_TLB_FAULT;
				break;
			case 'w':
				opts.faults |= INJECT_SIG_WORK;
				break;
			default:
				SYS_ERR_COND(1, "invalid argument to -k: '%s'\n", optarg);
				break;
			}
			break;
		default:
			show_help = parse_common_option(opt, optarg, &opts);
			break;
		}
	}

	signal(SIGBUS, handle_sigbus);

	if (!show_help) {
		if (self)
			return run_self_test(&opts);
		return run_cmd(&opts);
	}

	SYS_ERR_COND(show_help || optind > argc,
		     COMMON_HELP
		     "  -f <format>   output format for the statistics\n"
		     "                  'none'   do not output statistics\n"
		     "                  'pretty' human readable format\n"
		     "                  'csv'    raw, machine readable\n"
		     "  -o <mode>     options\n"
		     "                  'perf' prefaults the output pages\n"
		     "                  'thp' try to enable transparent huge pages\n"
		     "                  'zlib' use zlib instead of the device\n"
		     "  -r <children> number of children to create\n"
		     "  -k <mode>     kill thread\n"
		     "                  'bind' kills the process after bind\n"
		     "                  'tlb' tries to access an unmapped buffer\n"
		     "                  'work' kills the process while the queue is working\n",
		     argv[0]
		    );
	return 0;
}
