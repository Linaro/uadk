// SPDX-License-Identifier: GPL-2.0+
/*
 * Test the IOMMU SVA infrastructure of the Linux kernel.
 * - what happens when a process bound to a device is killed
 * - what happens on fork
 * - multiple threads binding to the same device
 * - multiple processes
 */
#include <fenv.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "test_lib.h"

#define MAX_RUNS	1024

static void *mmap_alloc(size_t len)
{
	void *p;
	long page_size = sysconf(_SC_PAGESIZE);

	if (len % page_size) {
		WD_ERR("unaligned allocation must use malloc\n");
		return NULL;
	}

	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
		 -1, 0);

	madvise(p, len, MADV_WILLNEED);

	return p == MAP_FAILED ? NULL : p;
}

static int run_one_test(struct test_options *opts)
{
	int ret = 0;
	void *in_buf, *out_buf;
	struct wd_scheduler sched = {0};
	struct hizip_test_context ctx = {0};

	ctx.opts = opts;
	ctx.msgs = calloc(opts->req_cache_num, sizeof(*ctx.msgs));
	if (!ctx.msgs)
		return -ENOMEM;

	ctx.total_len = opts->total_len;

	in_buf = ctx.in_buf = mmap_alloc(ctx.total_len);
	if (!in_buf) {
		ret = -ENOMEM;
		goto out_with_msgs;
	}

	out_buf = ctx.out_buf = mmap_alloc(ctx.total_len * EXPANSION_RATIO);
	if (!out_buf) {
		ret = -ENOMEM;
		goto out_with_in_buf;
	}

	hizip_prepare_random_input_data(&ctx);

	ret = hizip_test_init(&sched, opts, &test_ops, &ctx);
	if (ret) {
		WD_ERR("hizip init fail with %d\n", ret);
		goto out_with_out_buf;
	}
	if (sched.qs)
		ctx.flags = sched.qs[0].dev_flags;

	if (opts->faults & INJECT_SIG_BIND)
		kill(0, SIGTERM);

	ret = hizip_test_sched(&sched, opts, &ctx);

	hizip_test_fini(&sched, opts);

	ret = hizip_verify_random_output(out_buf, opts, &ctx);

out_with_out_buf:
	munmap(out_buf, ctx.total_len * EXPANSION_RATIO);
out_with_in_buf:
	munmap(in_buf, ctx.total_len);
out_with_msgs:
	free(ctx.msgs);
	return ret;
}

static int run_test(struct test_options *opts)
{
	int i;
	int ret;
	int n = opts->run_num;

	for (i = 0; i < n; i++) {
		ret = run_one_test(opts);
		if (ret < 0)
			return ret;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int opt;
	int show_help = 0;
	struct test_options opts = {
		.alg_type	= GZIP,
		.op_type	= DEFLATE,
		.req_cache_num	= 4,
		.q_num		= 1,
		.run_num	= 1,
		.block_size	= 512000,
		.total_len	= opts.block_size * 10,
		.verify		= false,
		.display_stats	= STATS_PRETTY,
	};

	while ((opt = getopt(argc, argv, "hb:k:s:q:n:c:V")) != -1) {
		switch (opt) {
		case 'b':
			opts.block_size = strtol(optarg, NULL, 0);
			if (opts.block_size <= 0)
				show_help = 1;
			break;
		case 'k':
			switch (optarg[0]) {
			case 'b':
				opts.faults |= INJECT_SIG_BIND;
				break;
			case 'w':
				opts.faults |= INJECT_SIG_WORK;
				break;
			default:
				SYS_ERR_COND(1, "invalid argument to -k: '%s'\n", optarg);
				break;
			}
			break;
		case 'c':
			opts.req_cache_num = strtol(optarg, NULL, 0);
			if (opts.req_cache_num <= 0)
				show_help = 1;
			break;
		case 'n':
			opts.run_num = strtol(optarg, NULL, 0);
			SYS_ERR_COND(opts.run_num > MAX_RUNS,
				     "No more than %d runs supported\n", MAX_RUNS);
			if (opts.run_num <= 0)
				show_help = 1;
			break;
		case 'q':
			opts.q_num = strtol(optarg, NULL, 0);
			if (opts.q_num <= 0)
				show_help = 1;
			break;
		case 's':
			opts.total_len = strtol(optarg, NULL, 0);
			SYS_ERR_COND(opts.total_len <= 0, "invalid size '%s'\n", optarg);
			break;
		case 'V':
			opts.verify = true;
			break;
		default:
			show_help = 1;
			break;
		}
	}

	hizip_test_adjust_len(&opts);

	SYS_ERR_COND(show_help || optind > argc,
		     "test_bind_api [opts]\n"
		     "  -b <size>     block size\n"
		     "  -k <mode>     kill thread\n"
		     "                  'bind' kills the process after bind\n"
		     "                  'work' kills the process while the queue is working\n"
		     "  -n <num>      number of runs\n"
		     "  -q <num>      number of queues\n"
		     "  -c <num>      number of caches\n"
		     "  -s <size>     total size\n"
		     "  -V            verify output\n"
		    );

	return run_test(&opts);
}
