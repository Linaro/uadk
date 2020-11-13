// SPDX-License-Identifier: Apache-2.0
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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/perf_event.h>

#include "test_lib.h"
#include "sched_sample.h"

struct priv_context {
	struct hizip_test_info info;
	struct priv_options *opts;
};

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

static void enable_thp(struct priv_options *opts,
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

	ret = madvise(info->in_buf, info->total_len, MADV_HUGEPAGE);
	if (ret) {
		perror("madvise(MADV_HUGEPAGE)");
		return;
	}

	ret = madvise(info->out_buf, info->total_len * EXPANSION_RATIO,
		      MADV_HUGEPAGE);
	if (ret) {
		perror("madvise(MADV_HUGEPAGE)");
	}

	return;
out_err:
	WD_ERR("THP unsupported?\n");
}

void stat_start(struct hizip_test_info *info)
{
	struct hizip_stats *stats = info->stats;

	stats->v[ST_SEND] = 0;
	stats->v[ST_RECV] = 0;
	stats->v[ST_SEND_RETRY] = 0;
	stats->v[ST_RECV_RETRY] = 0;

	clock_gettime(CLOCK_MONOTONIC_RAW, &info->tv.start_time);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &info->tv.start_cputime);
	getrusage(RUSAGE_SELF, &info->tv.start_rusage);
}

void stat_end(struct hizip_test_info *info)
{
	struct test_options *copts = info->opts;
	struct hizip_stats *stats = info->stats;
	int nr_fds = 0;
	int *perf_fds = NULL;
	double v;
	unsigned long total_len;

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
	stats->v[ST_COMPRESSION_RATIO] = (double)copts->total_len /
					 info->total_out * 100;

	total_len = copts->total_len * copts->compact_run_num;
	stats->v[ST_SPEED] = (total_len * 1000) /
				(1.024 * 1.024 * stats->v[ST_RUN_TIME]);

	stats->v[ST_TOTAL_SPEED] = (total_len * 1000) /
				   ((stats->v[ST_RUN_TIME] +
				    stats->v[ST_SETUP_TIME]) * 1.024 * 1.024);

	stats->v[ST_IOPF] = perf_event_put(perf_fds, nr_fds);

	v = stats->v[ST_RUN_TIME] + stats->v[ST_SETUP_TIME];
	stats->v[ST_CPU_IDLE] = (v - stats->v[ST_CPU_TIME]) / v * 100;
	stats->v[ST_FAULTS] = stats->v[ST_MAJFLT] + stats->v[ST_MINFLT];
}

static int run_one_test(struct priv_options *opts, struct hizip_stats *stats)
{
	int nr_fds;
	int ret = 0;
	int *perf_fds;
	void *in_buf, *out_buf;
	struct hizip_test_info info = {0};
	struct test_options *copts = &opts->common;
	struct wd_sched *sched = NULL;

	stats->v[ST_SEND] = stats->v[ST_RECV] = stats->v[ST_SEND_RETRY] =
			    stats->v[ST_RECV_RETRY] = 0;

	info.stats = stats;
	info.opts = copts;
	info.popts = opts;
	info.total_len = copts->total_len;

	info.list = get_dev_list(opts, 1);
	if (!info.list)
		return -EINVAL;

	in_buf = info.in_buf = mmap_alloc(copts->total_len);
	if (!in_buf) {
		ret = -ENOMEM;
		goto out_list;
	}

	out_buf = info.out_buf = mmap_alloc(copts->total_len * EXPANSION_RATIO);
	if (!out_buf) {
		ret = -ENOMEM;
		goto out_with_in_buf;
	}
	info.req.src = in_buf;
	info.req.dst = out_buf;
	info.req.src_len = copts->total_len;
	info.req.dst_len = copts->total_len * EXPANSION_RATIO;

	enable_thp(opts, &info);

	hizip_prepare_random_input_data(&info);

	perf_event_get("iommu/dev_fault", &perf_fds, &nr_fds);

	clock_gettime(CLOCK_MONOTONIC_RAW, &info.tv.setup_time);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &info.tv.setup_cputime);
	getrusage(RUSAGE_SELF, &info.tv.setup_rusage);

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
		ret = init_ctx_config(copts, &info, &sched);
		if (ret) {
			WD_ERR("hizip init fail with %d\n", ret);
			goto out_with_out_buf;
		}
	}

	info.stats = stats;
	create_threads(&info);
	attach_threads(&info);

	ret = hizip_verify_random_output(out_buf, copts, &info);

	usleep(10);
	if (!(opts->option & TEST_ZLIB))
		uninit_config(&info, sched);
	free(info.threads);
out_with_out_buf:
	munmap(out_buf, copts->total_len * EXPANSION_RATIO);
out_with_in_buf:
	munmap(in_buf, copts->total_len);
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

static void output_csv_stats(struct hizip_stats *s, struct priv_options *opts)
{
	/* Keep in sync with output_csv_header() */

	printf("%d;", csv_format_version);
	printf("%lu;%u;", opts->common.total_len, opts->common.block_size);
	printf("%u;", opts->common.compact_run_num);
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

static int run_one_child(struct priv_options *opts, struct uacce_dev_list *list)
{
	int i;
	int ret = 0;
	void *in_buf, *out_buf;
	struct priv_context priv_ctx;
	struct hizip_test_info save_info;
	struct hizip_test_info *info = &priv_ctx.info;
	struct test_options *copts = &opts->common;
	struct wd_sched *sched;

	memset(&priv_ctx, 0, sizeof(struct priv_context));
	priv_ctx.opts = opts;

	info->faults = opts->faults;

	info->opts = copts;
	info->list = list;

	info->total_len = copts->total_len;

	in_buf = info->in_buf = mmap_alloc(copts->total_len);
	if (!in_buf)
		return -ENOMEM;

	out_buf = info->out_buf = mmap_alloc(copts->total_len * EXPANSION_RATIO);
	if (!out_buf) {
		ret = -ENOMEM;
		goto out_with_in_buf;
	}

	info->req.src = in_buf;
	info->req.dst = out_buf;
	info->req.src_len = copts->total_len;
	info->req.dst_len = copts->total_len * EXPANSION_RATIO;
	hizip_prepare_random_input_data(info);

	sched = sample_sched_alloc(SCHED_POLICY_RR, 2, 2, lib_poll_func);
	if (!sched) {
		WD_ERR("sample_sched_alloc fail\n");
		goto out_ctx;
	}

	ret = init_ctx_config(copts, info, &sched);
	if (ret < 0) {
		WD_ERR("hizip init fail with %d\n", ret);
		goto out_ctx;
	}

	if (opts->faults & INJECT_SIG_BIND)
		kill(getpid(), SIGTERM);

	save_info = *info;
	for (i = 0; i < copts->compact_run_num; i++) {
		*info = save_info;

		ret = hizip_test_sched(sched, copts, info);
		if (ret < 0) {
			WD_ERR("hizip test sched fail with %d\n", ret);
			break;
		}
	}

	if (ret >= 0 && opts->faults & INJECT_TLB_FAULT) {
		/*
		 * Now unmap the buffers and retry the access. Normally we
		 * should get an access fault, but if the TLB wasn't properly
		 * invalidated, the access succeeds and corrupts memory!
		 * This test requires small jobs, to make sure that we reuse
		 * the same TLB entry between the tests. Run for example with
		 * "-s 0x1000 -b 0x1000".
		 */
		ret = munmap(out_buf, copts->total_len * EXPANSION_RATIO);
		if (ret)
			perror("unmap()");

		/* A warning if the parameters might produce false positives */
		if (copts->total_len > 0x54000)
			fprintf(stderr, "NOTE: test might trash the TLB\n");

		*info = save_info;
		info->faulting = true;

		ret = hizip_test_sched(sched, copts, info);
		if (ret >= 0) {
			WD_ERR("TLB test failed, broken invalidate! "
			       "VA=%p-%p\n", out_buf, out_buf +
			       copts->total_len * EXPANSION_RATIO - 1);
			ret = -EFAULT;
		} else {
			printf("TLB test success\n");
			ret = 0;
		}
		out_buf = NULL;
	}

	/* to do: wd_comp_uninit */

	if (out_buf)
		ret = hizip_verify_random_output(out_buf, copts, info);

	uninit_config(info, sched);

out_ctx:
	if (out_buf)
		munmap(out_buf, copts->total_len * EXPANSION_RATIO);
out_with_in_buf:
	munmap(in_buf, copts->total_len);
	return ret;
}

static int run_bind_test(struct priv_options *opts)
{
	pid_t pid;
	int i, ret, count;
	pid_t *pids;
	int nr_children = 0;
	bool success = true;
	struct uacce_dev_list *list;

	if (!opts->children)
		count = 1;
	else
		count = opts->children;
	list = get_dev_list(opts, count);
	if (!list)
		return -EINVAL;

	if (!opts->children) {
		ret = run_one_child(opts, list);
		wd_free_list_accels(list);
		return ret;
	}

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
		exit(run_one_child(opts, list));
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
	wd_free_list_accels(list);
	return success ? 0 : -EFAULT;
}

static int run_test(struct priv_options *opts, FILE *source, FILE *dest)
{
	int i;
	int ret;
	int n = opts->common.run_num;
	int w = opts->warmup_num;
	struct hizip_stats avg;
	struct hizip_stats std;
	struct hizip_stats variation;
	struct hizip_stats stats[n];

	if(opts->common.is_file) {
		return comp_file_test(source, dest, opts);
	}
	memset(&avg , 0, sizeof(avg));
	memset(&std , 0, sizeof(std));
	memset(&variation , 0, sizeof(variation));

	if (opts->children || opts->faults) {
		for (i = 0; i < opts->common.run_num; i++) {
			ret = run_bind_test(opts);
			if (ret < 0)
				return ret;
		}

		printf("SUCCESS\n");

		return 0;
	}

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
		opts->common.block_size, opts->common.compact_run_num,
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

static void handle_sigbus(int sig)
{
	    printf("SIGBUS!\n");
	        _exit(0);
}

int main(int argc, char **argv)
{
	struct priv_options opts = {
		.common = {
			.alg_type	= WD_GZIP,
			.op_type	= WD_DIR_COMPRESS,
			.q_num		= 1,
			.run_num	= 1,
			.compact_run_num = 1,
			.thread_num	= 1,
			.sync_mode	= 0,
			.block_size	= 512000,
			.total_len	= opts.common.block_size * 10,
			.verify		= false,
			.verbose	= false,
			.is_decomp	= false,
			.is_stream	= false,
			.is_file	= false,
		},
		.warmup_num		= 0,
		.display_stats		= STATS_PRETTY,
		.children		= 0,
		.faults			= 0,
	};
	int show_help = 0;
	int opt;

	while ((opt = getopt(argc, argv, COMMON_OPTSTRING "f:o:w:k:r:")) != -1) {
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
			case 't':
				opts.option |= TEST_THP;
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
			show_help = parse_common_option(opt, optarg,
							&opts.common);
			break;
		}
	}

	signal(SIGBUS, handle_sigbus);

	hizip_test_adjust_len(&opts.common);

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
		     "  -w <num>      number of warmup runs\n"
		     "  -r <children> number of children to create\n"
		     "  -k <mode>     kill thread\n"
		     "                  'bind' kills the process after bind\n"
		     "                  'tlb' tries to access an unmapped buffer\n"
		     "                  'work' kills the process while the queue is working\n",
		     argv[0]
		    );

	return run_test(&opts, stdin, stdout);
}
