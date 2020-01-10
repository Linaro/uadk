// SPDX-License-Identifier: GPL-2.0+
/*
 * Test the IOMMU SVA infrastructure of the Linux kernel.
 * - what happens when a process bound to a device is killed
 * - what happens on fork
 * - multiple threads binding to the same device
 */
#include <fenv.h>
#include <math.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>

#include "test_lib.h"

#define MAX_RUNS	1024

enum hizip_stats_variable {
	ST_SEND,
	ST_RECV,
	ST_SEND_RETRY,
	ST_RECV_RETRY,

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

	ST_COMPRESSION_RATIO,

	NUM_STATS
};

struct hizip_stats {
	double v[NUM_STATS];
};

struct hizip_priv {
	struct test_options *opts;
	char *in_buf;
	char *out_buf;
	unsigned long total_len;
	struct hisi_zip_sqe *msgs;
	int flags;
	size_t total_out;
};

struct check_rand_ctx {
	int off;
	unsigned long global_off;
	__u32 last;
	unsigned short state[3];
};

static void hizip_wd_sched_init_cache(struct wd_scheduler *sched, int i)
{
	struct wd_msg *wd_msg = &sched->msgs[i];
	struct hisi_zip_sqe *msg;
	struct hizip_priv *priv = sched->priv;

	msg = wd_msg->msg = &priv->msgs[i];

	if (priv->opts->alg_type == ZLIB)
		msg->dw9 = HW_ZLIB;
	else
		msg->dw9 = HW_GZIP;
	msg->dest_avail_out = sched->msg_data_size;

	/*
	 * This test doesn't use the data_in and data_out prepared by
	 * wd_sched_init. Instead we ask the zip device to directly work on our
	 * buffers to avoid a memcpy.
	 * TODO: don't alloc buffers
	 */

	if (!(priv->flags & UACCE_DEV_SVA)) {
		void *data_in, *data_out;

		data_in = wd_get_pa_from_va(&sched->qs[0], wd_msg->data_in);
		data_out = wd_get_pa_from_va(&sched->qs[0], wd_msg->data_out);

		msg->source_addr_l = (__u64)data_in & 0xffffffff;
		msg->source_addr_h = (__u64)data_in >> 32;
		msg->dest_addr_l = (__u64)data_out & 0xffffffff;
		msg->dest_addr_h = (__u64)data_out >> 32;
	}
}

#ifdef DEBUG_LOG
static void dbg_sqe(const char *head, struct hisi_zip_sqe *m)
{
	fprintf(stderr,
		"=== %s ===\n"
		"cons=0x%x prod=0x%x in=0x%x out=0x%x comp=0x%x\n"
		"lba=0x%08x 0x%08x\n"
		"dw3=0x%x dw7=0x%x dw8=0x%x dw9=0x%x dw10=0x%x dw12=0x%x\n"
		"priv=0x%x tag=0x%x\n"
		"ctx dw0=0x%x dw1=0x%x dw2=0x%x\n"
		"comp head addr=0x%08x 0x%08x\n"
		"source addr=0x%08x 0x%08x\n"
		"dest addr=0x%08x 0x%08x\n"
		"stream ctx addr=0x%08x 0x%08x\n"
		"cipher key1 addr=0x%08x 0x%08x\n"
		"cipher key2 addr=0x%08x 0x%08x\n"
		"isize=0x%x checksum=0x%x\n"
		"=== === === ===\n",

		head,
		m->consumed, m->produced, m->input_data_length,
		m->dest_avail_out, m->comp_data_length,
		m->lba_h, m->lba_l,
		m->dw3, m->dw7, m->dw8, m->dw9, m->dw10, m->dw12,
		m->priv_info, m->tag,
		m->ctx_dw0, m->ctx_dw1, m->ctx_dw2,
		m->comp_head_addr_h, m->comp_head_addr_l,
		m->source_addr_h, m->source_addr_l,
		m->dest_addr_h, m->dest_addr_l,
		m->stream_ctx_addr_h, m->stream_ctx_addr_l,
		m->cipher_key1_addr_h, m->cipher_key1_addr_l,
		m->cipher_key2_addr_h, m->cipher_key2_addr_l,
		m->isize, m->checksum
	       );
}
#else
#define dbg_sqe(...)
#endif

static int hizip_wd_sched_input(struct wd_msg *msg, void *priv)
{
	size_t ilen;
	char *in_buf, *out_buf;
	struct hisi_zip_sqe *m = msg->msg;
	struct hizip_priv *hizip_priv = priv;
	struct test_options *opts = hizip_priv->opts;

	ilen = hizip_priv->total_len > opts->block_size ?
		opts->block_size : hizip_priv->total_len;

	in_buf = hizip_priv->in_buf;
	out_buf = hizip_priv->out_buf;

	if (!(hizip_priv->flags & UACCE_DEV_SVA)) {
		memcpy(msg->data_in, in_buf, ilen);
	} else {
		msg->data_in = in_buf;
		msg->data_out = out_buf;

		m->source_addr_l = (__u64)in_buf & 0xffffffff;
		m->source_addr_h = (__u64)in_buf >> 32;
		m->dest_addr_l = (__u64)out_buf & 0xffffffff;
		m->dest_addr_h = (__u64)out_buf >> 32;

		hizip_priv->out_buf += ilen * EXPANSION_RATIO;
	}

	m->input_data_length = ilen;
	hizip_priv->in_buf += ilen;
	hizip_priv->total_len -= ilen;

	dbg_sqe("zip input", m);

	return 0;
}

static int hizip_wd_sched_output(struct wd_msg *msg, void *priv)
{
	struct hizip_priv *hizip_priv = priv;
	struct test_options *opts = hizip_priv->opts;
	struct hisi_zip_sqe *m = msg->msg;
	__u32 status = m->dw3 & 0xff;
	__u32 type = m->dw9 & 0xff;

	if (opts->option & PERFORMANCE) {
		if (!(hizip_priv->flags & UACCE_DEV_SVA)) {
			/* for performance test, simulate mmecpy in non-sva mode */
			memcpy(hizip_priv->out_buf, msg->data_out, m->produced);
			hizip_priv->out_buf += opts->block_size * EXPANSION_RATIO;
		}
	}

	if (hizip_priv->opts->faults & INJECT_SIG_WORK)
		kill(0, SIGTERM);

	dbg_sqe("zip output", m);

	SYS_ERR_COND(status != 0 && status != 0x0d, "bad status (s=%d, t=%d)\n",
		     status, type);

	hizip_priv->total_out += m->produced;
	return 0;
}

static struct test_ops test_ops = {
	.init_cache = hizip_wd_sched_init_cache,
	.input = hizip_wd_sched_input,
	.output = hizip_wd_sched_output,
};

static void hizip_prepare_input_data(struct hizip_priv *hizip_priv)
{
	__u32 seed = 0;
	unsigned short rand_state[3] = {(seed >> 16) & 0xffff, seed & 0xffff, 0x330e};

	unsigned long remain_size;
	__u32 block_size, size;
	char *in_buf;
	size_t i, j;

	/*
	 * TODO: change state for each buffer, to make sure there is no TLB
	 * aliasing. Can we store the seed into priv_info?
	 */
	//__u32 seed = hizip_priv->state++;
	block_size = hizip_priv->opts->block_size;
	remain_size = hizip_priv->total_len;
	in_buf = hizip_priv->in_buf;

	while (remain_size > 0) {
		if (remain_size > block_size)
			size = block_size;
		else
			size = remain_size;
		/*
		 * Prepare the input buffer with a reproducible sequence of
		 * numbers. nrand48() returns a pseudo-random number in the
		 * interval [0; 2^31). It's not really possible to compress a
		 * pseudo-random stream using deflate, since it can't find any
		 * string repetition. As a result the output size is bigger,
		 * with a ratio of 1.041.
		 */
		for (i = 0; i < size; i += 4) {
			__u64 n = nrand48(rand_state);

			for (j = 0; j < 4 && i + j < size; j++)
				in_buf[i + j] = (n >> (8 * j)) & 0xff;
		}

		in_buf += size;
		remain_size -= size;
	}
}

static int hizip_test_sched(struct wd_scheduler *sched,
			    struct test_options *opts, struct hizip_priv *priv)
{
	int ret = 0;

	if (opts->option & TEST_ZLIB)
		return zlib_deflate(priv->out_buf, priv->total_len *
				    EXPANSION_RATIO, priv->in_buf,
				    priv->total_len, &priv->total_out);

	while (priv->total_len || !wd_sched_empty(sched)) {
		dbg("request loop: total_len=%d\n", priv->total_len);
		ret = wd_sched_work(sched, priv->total_len);
		if (ret < 0) {
			WD_ERR("wd_sched_work: %d\n", ret);
			break;
		}
	}

	return ret;
}

static int hizip_check_rand(unsigned char *buf, unsigned int size, void *opaque)
{
	int i;
	int *j;
	__u32 n;
	struct check_rand_ctx *rand_ctx = opaque;

	j = &rand_ctx->off;
	for (i = 0; i < size; i += 4) {
		if (*j) {
			/* Somthing left from a previous run */
			n = rand_ctx->last;
		} else {
			n = nrand48(rand_ctx->state);
			rand_ctx->last = n;
		}
		for (; *j < 4 && i + *j < size; (*j)++) {
			char expected = (n >> (8 * *j)) & 0xff;
			char actual = buf[i + *j];

			if (expected != actual) {
				WD_ERR("Invalid decompressed char at offset %lu: expected 0x%x != 0x%x\n",
				       rand_ctx->global_off + i + *j, expected,
				       actual);
				return -EINVAL;
			}
		}
		if (*j == 4)
			*j = 0;
	}
	rand_ctx->global_off += size;
	return 0;
}

static int hizip_verify_output(char *out_buf, struct test_options *opts,
			       struct hizip_priv *priv)
{
	int ret;
	int seed = 0;
	off_t off = 0;
	size_t checked = 0;
	size_t total_checked = 0;
	struct check_rand_ctx rand_ctx = {
		.state = {(seed >> 16) & 0xffff, seed & 0xffff, 0x330e},
	};

	if (!opts->verify)
		return 0;

	do {
		ret = hizip_check_output(out_buf + off, priv->total_out,
					 &checked, hizip_check_rand, &rand_ctx);
		if (ret) {
			WD_ERR("Check output failed with %d\n", ret);
			return ret;
		}
		total_checked += checked;
		off += opts->block_size * EXPANSION_RATIO;
	} while (!ret && total_checked < opts->total_len);

	if (rand_ctx.global_off != opts->total_len) {
		WD_ERR("Invalid output size %lu != %lu\n",
		       rand_ctx.global_off, opts->total_len);
		return -EINVAL;
	}
	return 0;
}

static int run_one_test(struct test_options *opts, struct hizip_stats *stats)
{
	int i, j;
	double v;
	int ret = 0;
	void *in_buf, *out_buf;
	struct wd_scheduler sched = {0};
	struct hizip_priv hizip_priv = {0}, hizip_save;
	struct timespec setup_time, start_time, end_time;
	struct timespec setup_cputime, start_cputime, end_cputime;
	struct rusage setup_rusage, start_rusage, end_rusage;
	int stat_size = sizeof(*sched.stat) * opts->q_num;

	stats->v[ST_SEND] = stats->v[ST_RECV] = stats->v[ST_SEND_RETRY] =
			    stats->v[ST_RECV_RETRY] = 0;

	hizip_priv.opts = opts;
	hizip_priv.msgs = calloc(opts->req_cache_num, sizeof(*hizip_priv.msgs));
	if (!hizip_priv.msgs)
		return -ENOMEM;

	hizip_priv.total_len = opts->total_len;

	in_buf = hizip_priv.in_buf = malloc(hizip_priv.total_len);
	if (!in_buf) {
		ret = -ENOMEM;
		goto out_with_msgs;
	}

	out_buf = hizip_priv.out_buf = malloc(hizip_priv.total_len * EXPANSION_RATIO);
	if (!out_buf) {
		ret = -ENOMEM;
		goto out_with_in_buf;
	}

	hizip_prepare_input_data(&hizip_priv);

	clock_gettime(CLOCK_MONOTONIC_RAW, &setup_time);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &setup_cputime);
	getrusage(RUSAGE_SELF, &setup_rusage);

	if (opts->option & PERFORMANCE) {
		/* hack:
		 * memset buffer and trigger page fault early in the cpu
		 * instead of later in the SMMU
		 * Enhance performance in sva case
		 * no impact to non-sva case
		 */
		memset(out_buf, 5, hizip_priv.total_len * EXPANSION_RATIO);
		memset(out_buf, 0, hizip_priv.total_len * EXPANSION_RATIO);
	}

	ret = hizip_test_init(&sched, opts, &test_ops, &hizip_priv);
	if (ret) {
		WD_ERR("hizip init fail with %d\n", ret);
		goto out_with_out_buf;
	}
	if (sched.qs)
		hizip_priv.flags = sched.qs[0].dev_flags;

	hizip_save = hizip_priv;

	if (opts->faults & INJECT_SIG_BIND)
		kill(0, SIGTERM);

	clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_cputime);
	getrusage(RUSAGE_SELF, &start_rusage);

	for (j = 0; j < opts->compact_run_num; j++) {
		hizip_priv = hizip_save;

		ret = hizip_test_sched(&sched, opts, &hizip_priv);
		if (ret < 0) {
			WD_ERR("hizip test fail with %d\n", ret);
			goto out_with_fini;
		}

		for (i = 0; i < opts->q_num && sched.stat; i++) {
			stats->v[ST_SEND] += sched.stat[i].send;
			stats->v[ST_RECV] += sched.stat[i].recv;
			stats->v[ST_SEND_RETRY] += sched.stat[i].send_retries;
			stats->v[ST_RECV_RETRY] += sched.stat[i].recv_retries;
			memset(sched.stat, 0, stat_size);
		}
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_cputime);
	getrusage(RUSAGE_SELF, &end_rusage);

	stats->v[ST_SETUP_TIME] = (start_time.tv_sec - setup_time.tv_sec) *
		1000000000 + start_time.tv_nsec - setup_time.tv_nsec;
	stats->v[ST_RUN_TIME] = (end_time.tv_sec - start_time.tv_sec) *
		1000000000 + end_time.tv_nsec - start_time.tv_nsec;

	stats->v[ST_CPU_TIME] = (end_cputime.tv_sec - setup_cputime.tv_sec) *
		1000000000 + end_cputime.tv_nsec - setup_cputime.tv_nsec;
	stats->v[ST_USER_TIME] = (end_rusage.ru_utime.tv_sec -
				  setup_rusage.ru_utime.tv_sec) * 1000000 +
		end_rusage.ru_utime.tv_usec - setup_rusage.ru_utime.tv_usec;
	stats->v[ST_SYSTEM_TIME] = (end_rusage.ru_stime.tv_sec -
				    setup_rusage.ru_stime.tv_sec) * 1000000 +
		end_rusage.ru_stime.tv_usec - setup_rusage.ru_stime.tv_usec;

	stats->v[ST_MINFLT] = end_rusage.ru_minflt - setup_rusage.ru_minflt;
	stats->v[ST_MAJFLT] = end_rusage.ru_majflt - setup_rusage.ru_majflt;

	stats->v[ST_VCTX] = end_rusage.ru_nvcsw - setup_rusage.ru_nvcsw;
	stats->v[ST_INVCTX] = end_rusage.ru_nivcsw - setup_rusage.ru_nivcsw;

	stats->v[ST_SIGNALS] = end_rusage.ru_nsignals - setup_rusage.ru_nsignals;

	/* check last loop is enough, same as below hizip_verify_output */
	stats->v[ST_COMPRESSION_RATIO] = (double)opts->total_len /
					 hizip_priv.total_out * 100;

	stats->v[ST_SPEED] = opts->compact_run_num * opts->total_len /
		(stats->v[ST_RUN_TIME] / 1000) / 1024 / 1024 * 1000 * 1000;

	stats->v[ST_TOTAL_SPEED] = opts->compact_run_num * opts->total_len /
		((stats->v[ST_RUN_TIME] + stats->v[ST_SETUP_TIME]) / 1000) /
		1024 / 1024 * 1000 * 1000;

	v = stats->v[ST_RUN_TIME] + stats->v[ST_SETUP_TIME];
	stats->v[ST_CPU_IDLE] = (v - stats->v[ST_CPU_TIME]) / v * 100;
	stats->v[ST_FAULTS] = stats->v[ST_MAJFLT] + stats->v[ST_MINFLT];

	ret = hizip_verify_output(out_buf, opts, &hizip_priv);

out_with_fini:
	hizip_test_fini(&sched, opts);
out_with_out_buf:
	free(out_buf);
out_with_in_buf:
	free(in_buf);
out_with_msgs:
	free(hizip_priv.msgs);
	return ret;
}

static int add_avg(struct hizip_stats *avg, struct hizip_stats *new)
{
	int i;

	for (i = 0; i < NUM_STATS; i++)
		/* TODO: overflow */
		avg->v[i] += new->v[i];
	return 0;
}

static int comp_avg(struct hizip_stats *avg, unsigned long n)
{
	int i;

	for (i = 0; i < NUM_STATS; i++)
		avg->v[i] /= n;
	return 0;
}

static int add_std(struct hizip_stats *std, struct hizip_stats *avg,
		   struct hizip_stats *new)
{
	int i;
	double v;

	for (i = 0; i < NUM_STATS; i++) {
		v = new->v[i] - avg->v[i];
		std->v[i] = v * v;
	}
	return 0;
}

static int comp_std(struct hizip_stats *std, struct hizip_stats *variation,
		    struct hizip_stats *avg, unsigned long n)
{
	int i;

	errno = 0;
	feclearexcept(FE_ALL_EXCEPT);

	for (i = 0; i < NUM_STATS; i++) {
		std->v[i] = sqrt(std->v[i] / (n + 1));
		variation->v[i] = std->v[i] / avg->v[i] * 100;
	}

	if (errno) {
		fprintf(stderr, "math error %d\n", errno);
		return 1;
	} else if (fetestexcept(FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW |
				FE_UNDERFLOW)) {
		feraiseexcept(FE_ALL_EXCEPT);
		return 1;
	}
	return 0;
}

static const int csv_format_version = 1;

static void output_csv_header(void)
{
	/* Keep in sync with output_csv_stats() */

	/* Version number for this output format */
	printf("fmt_version;");

	/* Number of queue send/recv/wait */
	printf("send;recv;send_retry;recv_retry;");

	/* Time in ns */
	printf("setup_time;run_time;cpu_time;");
	printf("user_time;system_time;");

	/* Number of faults, context switches, signals */
	printf("minor_faults;major_faults;");
	printf("involuntary_context_switches;voluntary_context_switches;");
	printf("signals;");

	/* Speed in MB/s */
	printf("speed;total_speed;");
	/* Percent of CPU idle time */
	printf("cpu_idle;");
	/* Compression ratio (output / input) in percent */
	printf("compression_ratio");
	printf("\n");
}

static void output_csv_stats(struct hizip_stats *s)
{
	/* Keep in sync with output_csv_header() */

	printf("%d;", csv_format_version);
	printf("%.0f;%.0f;%.0f;%.0f;", s->v[ST_SEND], s->v[ST_RECV],
	       s->v[ST_SEND_RETRY], s->v[ST_RECV_RETRY]);
	printf("%.0f;%.0f;%.0f;", s->v[ST_SETUP_TIME], s->v[ST_RUN_TIME],
	       s->v[ST_CPU_TIME]);
	printf("%.0f;%.0f;", s->v[ST_USER_TIME] * 1000,
	       s->v[ST_SYSTEM_TIME] * 1000);
	printf("%.0f;%.0f;", s->v[ST_MINFLT], s->v[ST_MAJFLT]);
	printf("%.0f;%.0f;", s->v[ST_INVCTX], s->v[ST_VCTX]);
	printf("%.0f;", s->v[ST_SIGNALS]);
	printf("%.3f;%.3f;", s->v[ST_SPEED], s->v[ST_TOTAL_SPEED]);
	printf("%.3f;", s->v[ST_CPU_IDLE]);
	printf("%.1f;", s->v[ST_COMPRESSION_RATIO]);
	printf("\n");
}

static int run_test(struct test_options *opts)
{
	int i;
	int ret;
	int n = opts->run_num;
	int w = opts->warmup_num;
	struct hizip_stats avg = {0};
	struct hizip_stats std = {0};
	struct hizip_stats variation = {0};
	struct hizip_stats stats[n];

	if (opts->display_stats == STATS_CSV)
		output_csv_header();

	for (i = 0; i < w; i++) {
		ret = run_one_test(opts, &stats[0]);
		if (ret < 0)
			return ret;
	}
	for (i = 0; i < n; i++) {
		ret = run_one_test(opts, &stats[i]);
		if (ret < 0)
			return ret;

		if (opts->display_stats == STATS_PRETTY)
			add_avg(&avg, &stats[i]);
		else if (opts->display_stats == STATS_CSV)
			output_csv_stats(&stats[i]);
	}

	if (opts->display_stats != STATS_PRETTY)
		return 0;

	comp_avg(&avg, n);

	/* Sum differences from mean */
	for (i = 0; i < n; i++)
		add_std(&std, &avg, &stats[i]);

	/* Compute standard deviation, and variation coefficient */
	comp_std(&std, &variation, &avg, n);

	fprintf(stderr,
		"Compress bz=%d nb=%lu, speed=%.1f MB/s (±%0.1f%% N=%d) overall=%.1f MB/s (±%0.1f%%)\n",
		opts->block_size, opts->total_len / opts->block_size,
		avg.v[ST_SPEED], variation.v[ST_SPEED], n,
		avg.v[ST_TOTAL_SPEED], variation.v[ST_TOTAL_SPEED]);

	if (opts->verbose)
		fprintf(stderr,
		" send          %12.0f     ±%0.1f%%\n"
		" recv          %12.0f     ±%0.1f%%\n"
		" send retry    %12.0f     ±%0.1f%%\n"
		" recv retry    %12.0f     ±%0.1f%%\n"
		" setup time    %12.2f us  ±%0.1f%%\n"
		" run time      %12.2f us  ±%0.1f%%\n"
		" CPU time      %12.2f us  ±%0.1f%%\n"
		" CPU idle      %12.2f %%   ±%0.1f%%\n"
		" user time     %12.2f us  ±%0.1f%%\n"
		" system time   %12.2f us  ±%0.1f%%\n"
		" faults        %12.0f     ±%0.1f%%\n"
		" voluntary cs  %12.0f     ±%0.1f%%\n"
		" invol cs      %12.0f     ±%0.1f%%\n"
		" compression   %12.0f %%   ±%0.1f%%\n",
		avg.v[ST_SEND],			variation.v[ST_SEND],
		avg.v[ST_RECV],			variation.v[ST_RECV],
		avg.v[ST_SEND_RETRY],		variation.v[ST_SEND_RETRY],
		avg.v[ST_RECV_RETRY],		variation.v[ST_RECV_RETRY],
		avg.v[ST_SETUP_TIME] / 1000,	variation.v[ST_SETUP_TIME],
		avg.v[ST_RUN_TIME] / 1000,	variation.v[ST_RUN_TIME],
		avg.v[ST_CPU_TIME] / 1000,	variation.v[ST_CPU_TIME],
		avg.v[ST_CPU_IDLE],		variation.v[ST_CPU_IDLE],
		avg.v[ST_USER_TIME],		variation.v[ST_USER_TIME],
		avg.v[ST_SYSTEM_TIME],		variation.v[ST_SYSTEM_TIME],
		avg.v[ST_FAULTS],		variation.v[ST_FAULTS],
		avg.v[ST_VCTX],			variation.v[ST_VCTX],
		avg.v[ST_INVCTX],		variation.v[ST_INVCTX],
		avg.v[ST_COMPRESSION_RATIO],	variation.v[ST_COMPRESSION_RATIO]);

	return 0;
}

int main(int argc, char **argv)
{
	int opt;
	int show_help = 0;
	struct test_options opts = {
		.alg_type		= GZIP,
		.op_type		= DEFLATE,
		.req_cache_num		= 4,
		.q_num			= 1,
		.run_num		= 1,
		.warmup_num		= 0,
		.compact_run_num	= 1,
		.block_size		= 512000,
		.total_len		= opts.block_size * 10,
		.verify			= false,
		.verbose		= false,
		.display_stats		= STATS_PRETTY,
	};

	while ((opt = getopt(argc, argv, "hb:f:k:s:q:n:o:c:Vw:l:vz")) != -1) {
		switch (opt) {
		case 'b':
			opts.block_size = strtol(optarg, NULL, 0);
			if (opts.block_size <= 0)
				show_help = 1;
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
		case 'o':
			switch (optarg[0]) {
			case 'p':
				opts.option |= PERFORMANCE;
				break;
			case 'z':
				opts.option |= TEST_ZLIB;
				break;
			default:
				SYS_ERR_COND(1, "invalid argument to -o: '%s'\n", optarg);
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
		case 'w':
			opts.warmup_num = strtol(optarg, NULL, 0);
			SYS_ERR_COND(opts.warmup_num > MAX_RUNS,
				     "No more than %d warmup runs supported\n",
				     MAX_RUNS);
			if (opts.warmup_num < 0)
				show_help = 1;
			break;
		case 'l':
			opts.compact_run_num = strtol(optarg, NULL, 0);
			if (opts.compact_run_num <= 0)
				show_help = 1;
			break;
		case 'v':
			opts.verbose = true;
			break;
		case 'z':
			opts.alg_type = ZLIB;
			break;
		default:
			show_help = 1;
			break;
		}
	}

	/*
	 * Align size to the next block. We allow non-power-of-two block sizes.
	 */
	opts.total_len = (opts.total_len + opts.block_size - 1) /
			 opts.block_size * opts.block_size;

	SYS_ERR_COND(show_help || optind > argc,
		     "test_bind_api [opts]\n"
		     "  -f <format>   output format for the statistics\n"
		     "                  'none'   do not output statistics\n"
		     "                  'pretty' human readable format\n"
		     "                  'csv'    raw, machine readable\n"
		     "  -b <size>     block size\n"
		     "  -k <mode>     kill thread\n"
		     "                  'bind' kills the process after bind\n"
		     "                  'work' kills the process while the queue is working\n"
		     "  -n <num>      number of runs\n"
		     "  -o <mode>     options\n"
		     "                  'perf' prefaults the output pages\n"
		     "                  'zlib' use zlib instead of the device\n"
		     "  -q <num>      number of queues\n"
		     "  -c <num>      number of caches\n"
		     "  -s <size>     total size\n"
		     "  -V            verify output\n"
		     "  -w <num>      number of warmup runs\n"
		     "  -l <num>      number of compact runs\n"
		     "  -v            display detailed performance information\n"
		     "  -z            test zlib algorithm, default gzip\n"
		    );

	return run_test(&opts);
}
