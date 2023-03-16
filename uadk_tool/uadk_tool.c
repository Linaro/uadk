/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <string.h>
#include "benchmark/uadk_benchmark.h"
#include "dfx/uadk_dfx.h"
#include "test/uadk_test.h"

static void print_tool_help(void)
{
	printf("NAME\n");
	printf("uadk_tool dfx : Show some information for library.\n");
	printf("uadk_tool benchmark : Test UADK acc performance.\n");
	printf("uadk_tool test : Test the correctness of the acc algorithm.\n");
}

int main(int argc, char **argv)
{
	struct acc_option option = {0};
	int index = 1;
	int ret;

	if (argc > index) {
		if (!strcmp("dfx", argv[index])) {
			dfx_cmd_parse(argc, argv);
		} else if (!strcmp("benchmark", argv[index])) {
			printf("start UADK benchmark test.\n");
			if (!argv[++index])
				acc_default_case(&option);

			ret = acc_cmd_parse(argc, argv, &option);
			if (ret)
				return ret;

			ret = acc_option_convert(&option);
			if (ret)
				return ret;
			(void)acc_benchmark_run(&option);
		} else if (!strcmp("test", argv[index])) {
			printf("start UADK acc algorithm test.\n");
			acc_test_run(argc, argv);
		} else {
			print_tool_help();
		}
	} else {
		print_tool_help();
	}

	return 0;
}
