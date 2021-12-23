/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <limits.h>
#include "uadk_dfx.h"

#define print_date()	printf("built on: %s %s\n", __DATE__, __TIME__)

static void print_version(void)
{
	printf("%s\n", UADK_VERSION_TEXT);
	printf("%s\n", UADK_VERSION_TAG);
}

static void print_exe_path(void)
{
	char dir[PATH_MAX] = {0};
	int n;

	n = readlink("/proc/self/exe", dir, PATH_MAX);
	if (n < 0 || n >= PATH_MAX)
		printf("uadk tool failed to get the exe path.\n");

	printf("exe path: %s\n", dir);
}

void print_dfx_help(void)
{
	printf("NAME\n");
	printf("    uadk_tool --dfx : uadk library dfx function, etc\n");
	printf("USAGE\n");
	printf("        uadk_tool --dfx [--version] = Show library version\n");
	printf("        uadk_tool --dfx [--date]    = Show build date\n");
	printf("        uadk_tool --dfx [--dir]     = Show library dir\n");
	printf("        uadk_tool --dfx [--help]    = usage\n");
}

void dfx_cmd_parse(int argc, char *argv[])
{
	int option_index = 0;
	int c;

	static struct option long_options[] = {
		{"version", no_argument, 0,  2},
		{"date",    no_argument, 0,  3},
		{"dir",     no_argument, 0,  4},
		{"help",    no_argument, 0,  5},
		{0, 0, 0, 0}
	};

	while (1) {
		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 2:
			print_version();
			break;
		case 3:
			print_date();
			break;
		case 4:
			print_exe_path();
			break;
		case 5:
			print_dfx_help();
			break;
		default:
			printf("bad input parameter, exit\n");
			exit(-1);
		}
	}
}
