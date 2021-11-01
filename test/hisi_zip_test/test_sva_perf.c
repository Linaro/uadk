// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

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
#include "wd_sched.h"

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

	return;
out_err:
	printf("THP unsupported?\n");
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
		{"env",		no_argument,	0, 0 },
		{0,		0,		0, 0 },
	};
	int show_help = 0;
	int opt, option_idx;
	int self = 0;

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
			case 0:		/* self */
				self = 1;
				break;
			case 1:		/* in */
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
			case 2:		/* out */
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
			case 3:		/* ilist */
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
			case 4:		/* olist */
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
				break;
			case 5:		/* env */
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
	return 0;
}
