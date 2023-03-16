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

#include "test_sec.h"

enum uadk_test_op_type {
	DISPLAY_MODULE = 22,
	DISPLAY_HELP,
};

int test_hpre_entry(int argc, char *argv[])
{
	return 0;
}

int test_zip_entry(int argc, char *argv[])
{
	return 0;
}

void print_test_help(void)
{
	printf("NAME\n");
	printf("    uadk_tool test : Test the correctness of the acc algorithm, etc\n");
	printf("USAGE\n");
	printf("    uadk_tool test [--m] = module name\n");
	printf("                          hpre, sec, zip\n");
	printf("    uadk_tool test [--help]    = usage\n");
	printf("Example\n");
	printf("    uadk_tool test --m hpre --xx\n");
	printf("    uadk_tool test --m sec --xx\n");
	printf("    uadk_tool test --m zip --xx\n");
}

void acc_test_run(int argc, char *argv[])
{
	char *input_module = NULL;
	int option_index = 0;
	int opt;

	static struct option long_options[] = {
		{"m", required_argument, 0,  22},
		{"help",    no_argument, 0,  23},
		{0, 0, 0, 0}
	};

	while (1) {
		opt = getopt_long(argc, argv, "", long_options, &option_index);
		if (opt == -1)
			break;

		switch (opt) {
		case DISPLAY_MODULE:
			input_module = optarg;
			if (!strcmp(input_module, "hpre")) {
				(void)test_hpre_entry(argc, argv);
			} else if (!strcmp(input_module, "sec")) {
				(void)test_sec_entry(argc, argv);
			} else if (!strcmp(input_module, "zip")) {
				(void)test_zip_entry(argc, argv);
			} else {
				print_test_help();
				printf("failed to parse module parameter!\n");
			}
			break;
		case DISPLAY_HELP:
			print_test_help();
			break;
		default:
			printf("bad input parameter, exit!\n");
			print_test_help();
			break;
		}
	}
}

