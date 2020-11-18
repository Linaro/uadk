// SPDX-License-Identifier: GPL-2.0+
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
