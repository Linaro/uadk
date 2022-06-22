/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <limits.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "include/wd.h"
#include "uadk_dfx.h"

#define uadk_build_date()	printf("built on: %s %s\n", __DATE__, __TIME__)
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))
#define PRIVILEGE_FLAG		666

struct uadk_env_var {
	const char *module;
	const char *alg;
	const char *ctx_num_var;
	const char *epoll_en_var;
};

struct uadk_env_table {
	int sync_ctx_num;
	int sync_numa;
	int async_ctx_num;
	int async_numa;
	int poll_en;
};

enum dfx_op_type {
	DISPLAY_VERSION = 2,
	DISPLAY_DATE,
	DISPLAY_DIR,
	DISPLAY_ENV,
	DISPLAY_COUNT,
	DISPLAY_HELP,
};

const char *uadk_modules[] = {"sec", "hpre", "zip"};

const struct uadk_env_var env_vars[] = {
	{.module = "sec", .alg = "CIPHER", .ctx_num_var = "WD_CIPHER_CTX_NUM",
	 .epoll_en_var = "WD_CIPHER_EPOLL_EN"},
	{.module = "sec", .alg = "AEAD", .ctx_num_var = "WD_AEAD_CTX_NUM",
	 .epoll_en_var = "WD_AEAD_EPOLL_EN"},
	{.module = "sec", .alg = "DIGEST", .ctx_num_var = "WD_DIGEST_CTX_NUM",
	 .epoll_en_var = "WD_DIGEST_EPOLL_EN"},
	{.module = "hpre", .alg = "DH", .ctx_num_var = "WD_DH_CTX_NUM",
	 .epoll_en_var = "WD_DH_EPOLL_EN"},
	{.module = "hpre", .alg = "RSA", .ctx_num_var = "WD_RSA_CTX_NUM",
	 .epoll_en_var = "WD_RSA_EPOLL_EN"},
	{.module = "hpre", .alg = "ECC", .ctx_num_var = "WD_ECC_CTX_NUM",
	 .epoll_en_var = "WD_ECC_EPOLL_EN"},
	{.module = "zip", .alg = "COMP", .ctx_num_var = "WD_COMP_CTX_NUM",
	 .epoll_en_var = "WD_COMP_EPOLL_EN"},
};

static void dump_ctx_count(unsigned long *count)
{
	__u32 idx = 0;
	int i;

	if (!count)
		return;

	printf("displays the ctx counter value...\n");
	for (i = 0; i < WD_CTX_CNT_NUM; i++) {
		if (count[i]) {
			printf("ctx-[%d]:%lu \t", i, count[i]);
			idx++;
		} else {
			continue;
		}

		if ((idx & 0x3) == 0)
			printf("\n");
	}
	printf("\n");
}

static int get_shared_id(void)
{
	int shm;

	shm = shmget(WD_IPC_KEY, sizeof(unsigned long) * WD_CTX_CNT_NUM,
		     IPC_CREAT | PRIVILEGE_FLAG);
	if (shm < 0) {
		printf("failed to get the shared memory id.\n");
		return -EINVAL;
	}

	return shm;
}

static int uadk_shared_read(void)
{
	unsigned long *shared;
	void *ptr;
	int shm;

	shm = get_shared_id();
	if (shm < 0)
		return -EINVAL;

	ptr = (int *)shmat(shm, NULL, 0);
	if (ptr < 0) {
		printf("failed to get the shared memory addr.\n");
		return -EINVAL;
	}

	shared = (unsigned long *)ptr;

	printf("get the shared memory addr successful.\n");
	dump_ctx_count(shared);

	shmdt(ptr);

	return 0;
}

bool uadk_check_module(const char *module)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(uadk_modules); i++) {
		if (!strncmp(module, uadk_modules[i], strlen(module)))
			return true;
	}

	return false;
}

static void uadk_ctx_env_config(const char *s)
{
	char *env_setion;

	if (!s) {
		printf("input ctx env config is NULL.\n");
		return;
	}

	env_setion = getenv(s);
	if (!env_setion) {
		printf("not found the %s env config!\n", s);
		return;
	}

	printf("%s=%s\n", s, env_setion);
}

static void uadk_parse_env_config(const char *module)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(env_vars); i++) {
		if (!strncmp(module, env_vars[i].module, strlen(module))) {
			uadk_ctx_env_config(env_vars[i].ctx_num_var);
			uadk_ctx_env_config(env_vars[i].epoll_en_var);
		}
	}
}

static void uadk_exe_path(void)
{
	char dir[PATH_MAX] = {0};
	int n;

	n = readlink("/proc/self/exe", dir, PATH_MAX);
	if (n < 0 || n >= PATH_MAX)
		printf("uadk tool failed to get the exe path.\n");

	dir[PATH_MAX - 1] = '\0';
	printf("exe path: %s\n", dir);
}

void print_dfx_help(void)
{
	printf("NAME\n");
	printf("    uadk_tool dfx : uadk library dfx function, etc\n");
	printf("USAGE\n");
	printf("    uadk_tool dfx [--version] = Show library version\n");
	printf("    uadk_tool dfx [--date]    = Show build date\n");
	printf("    uadk_tool dfx [--dir]     = Show library dir\n");
	printf("    uadk_tool dfx [--env]     = Show environment variables\n");
	printf("    uadk_tool dfx [--count]   = Show the ctx message count\n");
	printf("    uadk_tool dfx [--help]    = usage\n");
	printf("Example\n");
	printf("    uadk_tool dfx --version\n");
	printf("    uadk_tool dfx --env sec\n");
	printf("    uadk_tool dfx --count\n");
}

void dfx_cmd_parse(int argc, char *argv[])
{
	bool check_module = false;
	char *input_module = NULL;
	int option_index = 0;
	int opt;

	static struct option long_options[] = {
		{"version", no_argument, 0,  2},
		{"date",    no_argument, 0,  3},
		{"dir",     no_argument, 0,  4},
		{"env",     required_argument, 0,  5},
		{"count",   no_argument, 0,  6},
		{"help",    no_argument, 0,  7},
		{0, 0, 0, 0}
	};

	while (1) {
		opt = getopt_long(argc, argv, "", long_options, &option_index);
		if (opt == -1)
			break;

		switch (opt) {
		case DISPLAY_VERSION:
			wd_get_version();
			break;
		case DISPLAY_DATE:
			uadk_build_date();
			break;
		case DISPLAY_DIR:
			uadk_exe_path();
			break;
		case DISPLAY_ENV:
			input_module = optarg;
			check_module = uadk_check_module(input_module);
			if (check_module) {
				uadk_parse_env_config(input_module);
			} else {
				print_dfx_help();
				printf("failed to parse module parameter!\n");
			}
			break;
		case DISPLAY_COUNT:
			uadk_shared_read();
			break;
		case DISPLAY_HELP:
			print_dfx_help();
			break;
		default:
			printf("bad input parameter, exit!\n");
			print_dfx_help();
			break;
		}
	}
}
