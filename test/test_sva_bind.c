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
#include <sys/wait.h>
#include <unistd.h>

#include "test_lib.h"

struct priv_options {
	struct test_options common;
	int children;

#define INJECT_SIG_BIND		(1UL << 0)
#define INJECT_SIG_WORK		(1UL << 1)
	unsigned long faults;
};

struct priv_context {
	struct hizip_test_context ctx;
	struct priv_options *opts;
};

static void hizip_test_init_cache(struct wd_scheduler *sched, int i, void *priv)
{
	struct priv_context *priv_ctx = priv;

	return hizip_test_default_init_cache(sched, i, &priv_ctx->ctx);
}

static int hizip_test_input(struct wd_msg *msg, void *priv)
{
	struct priv_context *priv_ctx = priv;

	return hizip_test_default_input(msg, &priv_ctx->ctx);
}

static int hizip_test_output(struct wd_msg *msg, void *priv)
{
	struct priv_context *priv_ctx = priv;

	if (priv_ctx->opts->faults & INJECT_SIG_WORK)
		kill(getpid(), SIGTERM);

	return hizip_test_default_output(msg, &priv_ctx->ctx);
}

static struct test_ops test_ops = {
	.init_cache = hizip_test_init_cache,
	.input = hizip_test_input,
	.output = hizip_test_output,
};

static int run_one_child(struct priv_options *opts)
{
	int i;
	int ret = 0;
	void *in_buf, *out_buf;
	struct wd_scheduler sched = {0};
	struct priv_context priv_ctx = {
		.ctx = {0},
		.opts = opts,
	};
	struct hizip_test_context save_ctx;
	struct hizip_test_context *ctx = &priv_ctx.ctx;
	struct test_options *copts = &opts->common;

	ctx->opts = copts;
	ctx->msgs = calloc(copts->req_cache_num, sizeof(*ctx->msgs));
	if (!ctx->msgs)
		return ENOMEM;

	ctx->total_len = copts->total_len;

	in_buf = ctx->in_buf = mmap_alloc(copts->total_len);
	if (!in_buf) {
		ret = -ENOMEM;
		goto out_with_msgs;
	}

	out_buf = ctx->out_buf = mmap_alloc(copts->total_len * EXPANSION_RATIO);
	if (!out_buf) {
		ret = -ENOMEM;
		goto out_with_in_buf;
	}

	hizip_prepare_random_input_data(ctx);

	ret = hizip_test_init(&sched, copts, &test_ops, &priv_ctx);
	if (ret) {
		WD_ERR("hizip init fail with %d\n", ret);
		goto out_with_out_buf;
	}
	if (sched.qs)
		ctx->flags = sched.qs[0].dev_flags;

	if (opts->faults & INJECT_SIG_BIND)
		kill(getpid(), SIGTERM);

	save_ctx = *ctx;
	for (i = 0; i < copts->compact_run_num; i++) {
		*ctx = save_ctx;

		ret = hizip_test_sched(&sched, copts, ctx);
		if (ret < 0) {
			WD_ERR("hizip test fail with %d\n", ret);
			break;
		}
	}

	hizip_test_fini(&sched, copts);

	ret = hizip_verify_random_output(out_buf, copts, ctx);

out_with_out_buf:
	munmap(out_buf, copts->total_len * EXPANSION_RATIO);
out_with_in_buf:
	munmap(in_buf, copts->total_len);
out_with_msgs:
	free(ctx->msgs);
	return ret;
}

static int run_one_test(struct priv_options *opts)
{
	pid_t pid;
	int i, ret;
	pid_t *pids;
	int nr_children = 0;
	bool success = true;

	if (!opts->children)
		return run_one_child(opts);

	pids = calloc(opts->children, sizeof(pid_t));
	if (!pids)
		return -ENOMEM;

	for (i = 0; i < opts->children; i++) {
		pid = fork();
		if (pid < 0) {
			WD_ERR("cannot fork: %d\n", errno);
			success = false;
			break;
		} else if (pid > 0) {
			/* Parent */
			pids[nr_children++] = pid;
			continue;
		}

		/* Child */
		exit(run_one_child(opts));
	}

	dbg("%d children spawned\n", nr_children);
	for (i = 0; i < nr_children; i++) {
		int status;

		pid = pids[i];

		ret = waitpid(pid, &status, 0);
		if (ret < 0) {
			WD_ERR("wait(pid=%d) error %d\n", pid, errno);
			success = false;
			continue;
		}

		if (WIFEXITED(status)) {
			ret = WEXITSTATUS(status);
			if (ret) {
				WD_ERR("child %d returned with %d\n",
				       pid, ret);
				success = false;
			}
		} else if (WIFSIGNALED(status)) {
			ret = WTERMSIG(status);
			WD_ERR("child %d killed by sig %d\n", pid, ret);
			success = false;
		} else {
			WD_ERR("unexpected status for child %d\n", pid);
			success = false;
		}
	}

	free(pids);
	return success ? 0 : -EFAULT;
}

static int run_test(struct priv_options *opts)
{
	int i, ret;

	for (i = 0; i < opts->common.run_num; i++) {
		ret = run_one_test(opts);
		if (ret < 0)
			return ret;
	}
	printf("SUCCESS\n");
	return 0;
}

int main(int argc, char **argv)
{
	int opt;
	int show_help = 0;
	struct priv_options opts = {
		.common	= {
			.alg_type	= GZIP,
			.op_type	= DEFLATE,
			.req_cache_num	= 4,
			.q_num		= 1,
			.run_num	= 1,
			.compact_run_num = 1,
			.block_size	= 512000,
			.total_len	= opts.common.block_size * 10,
			.verify		= true,
		},
		.children		= 0,
	};

	while ((opt = getopt(argc, argv, COMMON_OPTSTRING "f:k:")) != -1) {
		switch (opt) {
		case 'f':
			opts.children = strtol(optarg, NULL, 0);
			if (opts.children < 0)
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
		default:
			show_help = parse_common_option(opt, optarg,
							&opts.common);
			break;
		}
	}

	hizip_test_adjust_len(&opts.common);

	SYS_ERR_COND(show_help || optind > argc,
		     COMMON_HELP
		     "  -f <children> number of children to create\n"
		     "  -k <mode>     kill thread\n"
		     "                  'bind' kills the process after bind\n"
		     "                  'work' kills the process while the queue is working\n",
		     argv[0]
		    );

	return run_test(&opts);
}
