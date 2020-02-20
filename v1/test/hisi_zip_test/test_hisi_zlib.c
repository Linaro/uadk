/*
 * Copyright 2019 Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <assert.h>
#include "zip_alg.h"
#include "../wd_comp.h"

int main(int argc, char *argv[])
{
	int ret;
	int alg_type = WCRYPTO_GZIP;
	int op_type = WCRYPTO_DEFLATE;
	int opt;
	int show_help = 0;

	if (!argv[1]) {
		fputs("<<use ./test_hisi_zlib -h get more details>>\n", stderr);
		goto EXIT;
	}

	while ((opt = getopt(argc, argv, "zgdh")) != -1) {
		switch (opt) {
		case 'z':
			alg_type = WCRYPTO_ZLIB;
			break;
		case 'g':
			alg_type = WCRYPTO_GZIP;
			break;
		case 'd':
			op_type = WCRYPTO_INFLATE;
			SYS_ERR_COND(0, "decompress function to be added\n");
			break;
		default:
			show_help = 1;
			break;
		}
	}

	SYS_ERR_COND(show_help || optind > argc,
		     "test_hisi_zlib -[g|z] [-d] < in > out\n");

	switch (op_type) {
	case WCRYPTO_DEFLATE:
		ret = hw_stream_def(stdin, stdout, alg_type);
		if (ret)
			fputs("hw_stream_deflate error!\n", stderr);
		break;
	case WCRYPTO_INFLATE:
		ret = hw_stream_inf(stdin, stdout, alg_type);
		if (ret)
			fputs("hw_stream_inflate error!\n", stderr);
		break;
	default:
		fputs("default cmd!\n", stderr);
	}
EXIT:
	return EXIT_SUCCESS;
}
