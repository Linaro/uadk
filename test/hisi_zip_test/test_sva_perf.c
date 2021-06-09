// SPDX-License-Identifier: Apache-2.0
/*
 * Test performance of the SVA API
 */
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

#include <linux/perf_event.h>

#include "test_lib.h"
#include "sched_sample.h"

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

static void enable_thp(struct test_options *opts,
		       struct hizip_test_info *info)
{
	int ret;
	char *p;
	char s[14];
	FILE *file;

	if (!(opts->option & TEST_THP))
		return;

	file = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "r");
	if (!file)
		goto out_err;
	p = fgets(s, 14, file);
	fclose(file);
	if (!p)
		goto out_err;

	if (strcmp(s, "never") == 0) {
		printf("Cannot test THP with enable=never\n");
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
		printf("Cannot test THP with defrag=%s\n", s);
		return;
	}

	ret = madvise(info->in_buf, info->in_size, MADV_HUGEPAGE);
	if (ret) {
		perror("madvise(MADV_HUGEPAGE)");
		return;
	}

	ret = madvise(info->out_buf, info->out_size, MADV_HUGEPAGE);
	if (ret) {
		perror("madvise(MADV_HUGEPAGE)");
	}

	return;
out_err:
	WD_ERR("THP unsupported?\n");
}

static void stat_setup(struct hizip_test_info *info)
{
	clock_gettime(CLOCK_MONOTONIC_RAW, &info->tv.setup_time);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &info->tv.setup_cputime);
	getrusage(RUSAGE_SELF, &info->tv.setup_rusage);
}

static void stat_start(struct hizip_test_info *info)
{
	clock_gettime(CLOCK_MONOTONIC_RAW, &info->tv.start_time);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &info->tv.start_cputime);
	getrusage(RUSAGE_SELF, &info->tv.start_rusage);
}

static void stat_end(struct hizip_test_info *info)
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

static int run_one_test(struct test_options *opts, struct hizip_stats *stats)
{
	static bool event_unavailable;

	int ret = 0;
	int nr_fds = 0;
	int *perf_fds = NULL;
	void *defl_buf, *infl_buf;
	size_t defl_size, infl_size;
	struct hizip_test_info info = {0};
	struct wd_sched *sched = NULL;

	info.stats = stats;
	info.opts = opts;

	info.list = get_dev_list(opts, 1);
	if (!info.list)
		return -EINVAL;

	infl_size = opts->total_len;
	infl_buf = mmap_alloc(infl_size);
	if (!infl_buf) {
		ret = -ENOMEM;
		goto out_list;
	}

	/*
	 * Counter-intuitive: defl_size > infl_size, because random data is
	 * incompressible and deflate may add a header. See comment in
	 * hizip_prepare_random_input_data().
	 */
	defl_size = opts->total_len * EXPANSION_RATIO;
	defl_buf = mmap_alloc(defl_size);
	if (!defl_buf) {
		ret = -ENOMEM;
		goto out_with_infl_buf;
	}

	if (opts->op_type == WD_DIR_COMPRESS) {
		hizip_prepare_random_input_data(infl_buf, infl_size,
						opts->block_size);
		info.in_buf = infl_buf;
		info.in_size = infl_size;
		info.out_buf = defl_buf;
		info.out_size = defl_size;
	} else {
		size_t produced;

		/* Prepare a buffer of compressed data */
		ret = hizip_prepare_random_compressed_data(defl_buf, defl_size,
							   infl_size, &produced,
							   opts);
		if (ret)
			goto out_with_defl_buf;
		info.in_buf = defl_buf;
		info.in_size = defl_size;
		info.out_buf = infl_buf;
		info.out_size = infl_size;
	}

	enable_thp(opts, &info);

	if (!event_unavailable &&
	    perf_event_get("iommu/dev_fault", &perf_fds, &nr_fds)) {
		WD_ERR("IOPF statistic unavailable\n");
		/* No need to retry and print an error on every run */
		event_unavailable = true;
	}

	stat_setup(&info);

	if (opts->option & PERFORMANCE) {
		/* hack:
		 * memset buffer and trigger page fault early in the cpu
		 * instead of later in the SMMU
		 * Enhance performance in sva case
		 * no impact to non-sva case
		 */
		memset(info.out_buf, 5, info.out_size);
	}

	if (!(opts->option & TEST_ZLIB)) {
		ret = init_ctx_config(opts, &info, &sched);
		if (ret) {
			WD_ERR("hizip init fail with %d\n", ret);
			goto out_with_defl_buf;
		}
		if (opts->faults & INJECT_SIG_BIND)
			kill(getpid(), SIGTERM);
	}

	stat_start(&info);
	create_send_threads(opts, &info, send_thread_func);
	create_poll_threads(&info, poll_thread_func, 1);
	attach_threads(opts, &info);

	stat_end(&info);
	stats->v[ST_IOPF] = perf_event_put(perf_fds, nr_fds);

	if (opts->faults & INJECT_TLB_FAULT) {
		/*
		 * Now unmap the buffers and retry the access. Normally we
		 * should get an access fault, but if the TLB wasn't properly
		 * invalidated, the access succeeds and corrupts memory!
		 * This test requires small jobs, to make sure that we reuse
		 * the same TLB entry between the tests. Run for example with
		 * "-s 0x1000 -b 0x1000".
		 */
		ret = munmap(infl_buf, infl_size);
		if (ret)
			perror("unmap()");

		/* A warning if the parameters might produce false positives */
		if (opts->total_len > 0x54000)
			fprintf(stderr, "NOTE: test might trash the TLB\n");

		create_send_threads(opts, &info, send_thread_func);
		create_poll_threads(&info, poll_thread_func, 1);
		ret = attach_threads(opts, &info);
		if (!ret) {
			WD_ERR("TLB test failed, broken invalidate! "
			       "VA=%p-%p\n", infl_buf, infl_buf +
			       opts->total_len * EXPANSION_RATIO - 1);
			ret = -EFAULT;
		} else {
			printf("TLB test success, returned %d\n", ret);
			ret = 0;
		}
		infl_buf = NULL;
	} else {
		ret = hizip_verify_random_output(opts, &info, info.out_size);
	}

	usleep(10);
	if (!(opts->option & TEST_ZLIB))
		uninit_config(&info, sched);
	free_threads(&info);
out_with_defl_buf:
	munmap(defl_buf, defl_size);
out_with_infl_buf:
	munmap(infl_buf, infl_size);
out_list:
	wd_free_list_accels(info.list);
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
		std->v[i] += v * v;
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

static void output_csv_stats(struct hizip_stats *s, struct test_options *opts)
{
	/* Keep in sync with output_csv_header() */

	printf("%d;", csv_format_version);
	printf("%lu;%u;", opts->total_len, opts->block_size);
	printf("%u;", opts->compact_run_num);
	/* Send/recv are deprecated */
	printf("0;0;0;0;");
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

static int run_fork_tests(struct test_options *opts)
{
	pid_t pid;
	int i, ret;
	pid_t *pids;
	int nr_children = 0;
	bool success = true;

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
		return 0;
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
	return success ? 1 : -EFAULT;
}

static int run_test(struct test_options *opts, FILE *source, FILE *dest)
{
	int i;
	int ret;
	int n = opts->run_num;
	struct hizip_stats avg;
	struct hizip_stats std;
	struct hizip_stats variation;
	struct hizip_stats stats[n];

	if(opts->is_file) {
		return comp_file_test(source, dest, opts);
	}
	memset(&avg , 0, sizeof(avg));
	memset(&std , 0, sizeof(std));
	memset(&variation , 0, sizeof(variation));

	if (opts->children) {
		opts->display_stats = STATS_NONE;
		ret = run_fork_tests(opts);
		if (ret) {
			/* Parent */
			if (ret > 0) {
				printf("SUCCESS\n");
				ret = 0;
			}
			return ret;
		}
		/* Child */
	}

	if (opts->display_stats == STATS_CSV)
		output_csv_header();

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
		opts->block_size, opts->compact_run_num,
		opts->total_len / opts->block_size,
		avg.v[ST_SPEED], variation.v[ST_SPEED], n,
		avg.v[ST_TOTAL_SPEED], variation.v[ST_TOTAL_SPEED]);

	if (opts->verbose)
		fprintf(stderr,
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

static void handle_sigbus(int sig)
{
	    printf("SIGBUS!\n");
	        _exit(0);
}

int main(int argc, char **argv)
{
	struct test_options opts = {
		.alg_type		= WD_GZIP,
		.op_type		= WD_DIR_COMPRESS,
		.q_num			= 1,
		.run_num		= 1,
		.compact_run_num	= 1,
		.thread_num		= 1,
		.sync_mode		= 0,
		.block_size		= 512000,
		.total_len		= opts.block_size * 10,
		.verify			= false,
		.verbose		= false,
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
		{"ilist",	required_argument,	0, 0 },
		{"olist",	required_argument,	0, 0 },
		{0,		0,		0, 0 },
	};
	int show_help = 0;
	int opt, option_idx;

	opts.fd_in = -1;
	opts.fd_out = -1;
	opts.fd_ilist = -1;
	opts.fd_olist = -1;
	opts.alg_type = WD_COMP_ALG_MAX;
	while ((opt = getopt_long(argc, argv, COMMON_OPTSTRING "f:o:w:k:r:",
				  long_options, &option_idx)) != -1) {
		switch (opt) {
		case 0:
			switch (option_idx) {
			case 0:
				return run_self_test();
			case 1:
				if (optarg) {
					opts.fd_in = open(optarg, O_RDONLY);
					if (opts.fd_in < 0) {
						printf("Fail to open %s\n",
							optarg);
						show_help = 1;
					} else
						opts.is_file = true;
				} else {
					printf("Input file is missing!\n");
					show_help = 1;
				}
				if (lseek(opts.fd_in, 0, SEEK_SET) < 0) {
					printf("Fail on lseek()!\n");
					show_help = 1;
				}
				break;
			case 2:
				if (optarg) {
					opts.fd_out = open(optarg,
							   O_CREAT | O_WRONLY,
							   S_IWUSR | S_IRGRP |
							   S_IROTH);
					if (opts.fd_out < 0) {
						printf("Fail to open %s\n",
							optarg);
						show_help = 1;
					} else
						opts.is_file = true;
				} else {
					printf("Output file is missing!\n");
					show_help = 1;
				}
				if (lseek(opts.fd_out, 0, SEEK_SET) < 0) {
					printf("Fail on lseek()!\n");
					show_help = 1;
				}
				break;
			case 3:
				if (!optarg) {
					printf("IN list file is missing!\n");
					show_help = 1;
					break;
				}
				opts.fd_ilist = open(optarg, O_RDONLY);
				if (opts.fd_ilist < 0) {
					printf("Fail to open %s\n", optarg);
					show_help = 1;
					break;
				}
				opts.is_file = true;
				if (lseek(opts.fd_ilist, 0, SEEK_SET) < 0) {
					printf("Fail on lseek()!\n");
					show_help = 1;
					break;
				}
				break;
			case 4:
				if (!optarg) {
					printf("OUT list file is missing!\n");
					show_help = 1;
					break;
				}
				opts.fd_olist = open(optarg,
						     O_CREAT | O_WRONLY,
						     S_IWUSR | S_IRGRP |
						     S_IROTH);
				if (opts.fd_olist < 0) {
					printf("Fail to open %s\n", optarg);
					show_help = 1;
					break;
				}
				opts.is_file = true;
				if (lseek(opts.fd_olist, 0, SEEK_SET) < 0) {
					printf("Fail on lseek()!\n");
					show_help = 1;
					break;
				}
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

	if (!show_help)
		return run_cmd(&opts);

	hizip_test_adjust_len(&opts);

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

	return run_test(&opts, stdin, stdout);
}
