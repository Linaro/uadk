// SPDX-License-Identifier: GPL-2.0+
/*
 * Test performance of the SVA API
 */
#include <asm/unistd.h>	/* For __NR_perf_event_open */
#include <fenv.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/perf_event.h>

#include "test_lib.h"

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
	ST_IOPF,

	ST_COMPRESSION_RATIO,

	NUM_STATS
};

struct hizip_stats {
	double v[NUM_STATS];
};

struct priv_options {
	struct test_options common;

	int warmup_num;
	int compact_run_num;

#define PERFORMANCE		(1UL << 0)
#define TEST_ZLIB		(1UL << 1)
	unsigned long option;

#define STATS_NONE		0
#define STATS_PRETTY		1
#define STATS_CSV		2
	unsigned long display_stats;
};

static int perf_event_open(struct perf_event_attr *attr,
			   pid_t pid, int cpu, int group_fd,
			   unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static unsigned long long perf_event_put(int *perf_fds, int nr_fds);

static int perf_event_get(const char *event_name, int **perf_fds, int *nr_fds)
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
static unsigned long long perf_event_put(int *perf_fds, int nr_fds)
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

static int run_one_test(struct priv_options *opts, struct hizip_stats *stats)
{
	int i, j;
	double v;
	int nr_fds;
	int ret = 0;
	int *perf_fds;
	void *in_buf, *out_buf;
	unsigned long total_len;
	struct wd_scheduler sched = {0};
	struct hizip_test_context ctx = {0}, ctx_save;
	struct test_options *copts = &opts->common;
	struct timespec setup_time, start_time, end_time;
	struct timespec setup_cputime, start_cputime, end_cputime;
	struct rusage setup_rusage, start_rusage, end_rusage;
	int stat_size = sizeof(*sched.stat) * copts->q_num;

	stats->v[ST_SEND] = stats->v[ST_RECV] = stats->v[ST_SEND_RETRY] =
			    stats->v[ST_RECV_RETRY] = 0;

	ctx.opts = copts;
	ctx.msgs = calloc(copts->req_cache_num, sizeof(*ctx.msgs));
	if (!ctx.msgs)
		return -ENOMEM;

	ctx.total_len = copts->total_len;

	in_buf = ctx.in_buf = mmap_alloc(copts->total_len);
	if (!in_buf) {
		ret = -ENOMEM;
		goto out_with_msgs;
	}

	out_buf = ctx.out_buf = mmap_alloc(copts->total_len * EXPANSION_RATIO);
	if (!out_buf) {
		ret = -ENOMEM;
		goto out_with_in_buf;
	}

	hizip_prepare_random_input_data(&ctx);

	perf_event_get("iommu/dev_fault", &perf_fds, &nr_fds);

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
		memset(out_buf, 0, copts->total_len * EXPANSION_RATIO);
	}

	if (!(opts->option & TEST_ZLIB)) {
		ret = hizip_test_init(&sched, copts, &test_ops, &ctx);
		if (ret) {
			WD_ERR("hizip init fail with %d\n", ret);
			goto out_with_out_buf;
		}
	}
	if (sched.qs)
		ctx.flags = sched.qs[0].dev_flags;

	ctx_save = ctx;

	clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_cputime);
	getrusage(RUSAGE_SELF, &start_rusage);

	for (j = 0; j < opts->compact_run_num; j++) {
		ctx = ctx_save;

		ret = hizip_test_sched(&sched, copts, &ctx);
		if (ret < 0) {
			WD_ERR("hizip test fail with %d\n", ret);
			goto out_with_fini;
		}

		for (i = 0; i < copts->q_num && sched.stat; i++) {
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
	stats->v[ST_COMPRESSION_RATIO] = (double)copts->total_len /
					 ctx.total_out * 100;

	total_len = copts->total_len * opts->compact_run_num;
	stats->v[ST_SPEED] = total_len / (stats->v[ST_RUN_TIME] / 1000) /
		1024 / 1024 * 1000 * 1000;

	stats->v[ST_TOTAL_SPEED] = total_len /
		((stats->v[ST_RUN_TIME] + stats->v[ST_SETUP_TIME]) / 1000) /
		1024 / 1024 * 1000 * 1000;

	stats->v[ST_IOPF] = perf_event_put(perf_fds, nr_fds);

	v = stats->v[ST_RUN_TIME] + stats->v[ST_SETUP_TIME];
	stats->v[ST_CPU_IDLE] = (v - stats->v[ST_CPU_TIME]) / v * 100;
	stats->v[ST_FAULTS] = stats->v[ST_MAJFLT] + stats->v[ST_MINFLT];

	ret = hizip_verify_random_output(out_buf, copts, &ctx);

out_with_fini:
	if (!(opts->option & TEST_ZLIB))
		hizip_test_fini(&sched, copts);
out_with_out_buf:
	munmap(out_buf, copts->total_len * EXPANSION_RATIO);
out_with_in_buf:
	munmap(in_buf, copts->total_len);
out_with_msgs:
	free(ctx.msgs);
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

static const int csv_format_version = 4;

static void output_csv_header(void)
{
	/* Keep in sync with output_csv_stats() */

	/* Version number for this output format */
	printf("fmt_version;");

	/* Job size, block size */
	printf("total_size;block_size;");

	/* Compact runs */
	printf("repeat;");

	/* Number of queue send/recv/wait */
	printf("send;recv;send_retry;recv_retry;");

	/* Time in ns */
	printf("setup_time;run_time;cpu_time;");
	printf("user_time;system_time;");

	/* Number of I/O page faults */
	printf("iopf;");

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

static void output_csv_stats(struct hizip_stats *s, struct priv_options *opts)
{
	/* Keep in sync with output_csv_header() */

	printf("%d;", csv_format_version);
	printf("%lu;%u;", opts->common.total_len, opts->common.block_size);
	printf("%u;", opts->compact_run_num);
	printf("%.0f;%.0f;%.0f;%.0f;", s->v[ST_SEND], s->v[ST_RECV],
	       s->v[ST_SEND_RETRY], s->v[ST_RECV_RETRY]);
	printf("%.0f;%.0f;%.0f;", s->v[ST_SETUP_TIME], s->v[ST_RUN_TIME],
	       s->v[ST_CPU_TIME]);
	printf("%.0f;%.0f;", s->v[ST_USER_TIME] * 1000,
	       s->v[ST_SYSTEM_TIME] * 1000);
	printf("%.0f;", s->v[ST_IOPF]);
	printf("%.0f;%.0f;", s->v[ST_MINFLT], s->v[ST_MAJFLT]);
	printf("%.0f;%.0f;", s->v[ST_INVCTX], s->v[ST_VCTX]);
	printf("%.0f;", s->v[ST_SIGNALS]);
	printf("%.3f;%.3f;", s->v[ST_SPEED], s->v[ST_TOTAL_SPEED]);
	printf("%.3f;", s->v[ST_CPU_IDLE]);
	printf("%.1f", s->v[ST_COMPRESSION_RATIO]);
	printf("\n");
}

static int run_test(struct priv_options *opts)
{
	int i;
	int ret;
	int n = opts->common.run_num;
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
			output_csv_stats(&stats[i], opts);
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
		"Compress bz=%d nb=%u×%lu, speed=%.1f MB/s (±%0.1f%% N=%d) overall=%.1f MB/s (±%0.1f%%)\n",
		opts->common.block_size, opts->compact_run_num,
		opts->common.total_len / opts->common.block_size,
		avg.v[ST_SPEED], variation.v[ST_SPEED], n,
		avg.v[ST_TOTAL_SPEED], variation.v[ST_TOTAL_SPEED]);

	if (opts->common.verbose)
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
		" iopf          %12.0f     ±%0.1f%%\n"
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
		avg.v[ST_IOPF],			variation.v[ST_IOPF],
		avg.v[ST_VCTX],			variation.v[ST_VCTX],
		avg.v[ST_INVCTX],		variation.v[ST_INVCTX],
		avg.v[ST_COMPRESSION_RATIO],	variation.v[ST_COMPRESSION_RATIO]);

	return 0;
}

int main(int argc, char **argv)
{
	int opt;
	int show_help = 0;
	struct priv_options opts = {
		.common = {
			.alg_type	= GZIP,
			.op_type	= DEFLATE,
			.req_cache_num	= 4,
			.q_num		= 1,
			.run_num	= 1,
			.block_size	= 512000,
			.total_len	= opts.common.block_size * 10,
			.verify		= false,
			.verbose	= false,
		},
		.compact_run_num	= 1,
		.warmup_num		= 0,
		.display_stats		= STATS_PRETTY,
	};

	while ((opt = getopt(argc, argv, COMMON_OPTSTRING "f:l:o:w:")) != -1) {
		switch (opt) {
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
			case 'z':
				opts.option |= TEST_ZLIB;
				break;
			default:
				SYS_ERR_COND(1, "invalid argument to -o: '%s'\n", optarg);
				break;
			}
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
		default:
			show_help = parse_common_option(opt, optarg,
							&opts.common);
			break;
		}
	}

	hizip_test_adjust_len(&opts.common);

	SYS_ERR_COND(show_help || optind > argc,
		     COMMON_HELP
		     "  -f <format>   output format for the statistics\n"
		     "                  'none'   do not output statistics\n"
		     "                  'pretty' human readable format\n"
		     "                  'csv'    raw, machine readable\n"
		     "  -o <mode>     options\n"
		     "                  'perf' prefaults the output pages\n"
		     "                  'zlib' use zlib instead of the device\n"
		     "  -l <num>      number of compact runs\n"
		     "  -w <num>      number of warmup runs\n",
		     argv[0]
		    );

	return run_test(&opts);
}
