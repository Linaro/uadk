/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include "uadk_dfx.h"
#include "uadk_benchmark.h"

static void print_tool_help(void)
{
	printf("NAME\n");
	printf("uadk_tool dfx : Show some information for library.\n");
	printf("uadk_tool benchmark : Test UADK acc performance.\n");
}

int main(int argc, char **argv)
{
	struct acc_option option = {0};
	int ret;

	if (argc > 1) {
		if (!strcmp("dfx", argv[1])) {
			dfx_cmd_parse(argc, argv);
		} else if (!strcmp("benchmark", argv[1])) {
			printf("start UADK benchmark test.\n");
			if (!argv[2])
				acc_default_case(&option);

			benchmark_cmd_parse(argc, argv, &option);
			ret = acc_option_convert(&option);
			if (ret)
				return ret;
			(void)acc_benchmark_run(&option);
		} else {
			print_tool_help();
		}
	} else {
		print_tool_help();
	}

	return 0;
}
