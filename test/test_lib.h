// SPDX-License-Identifier: GPL-2.0+
#ifndef TEST_LIB_H_
#define TEST_LIB_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define SYS_ERR_COND(cond, msg, ...) \
do { \
	if (cond) { \
		if (errno) \
			perror(msg); \
		else \
			fprintf(stderr, msg, ##__VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} \
} while (0)

#define ZLIB 0
#define GZIP 1

#define DEFLATE 0
#define INFLATE 1

#endif /* TEST_LIB_H_ */
