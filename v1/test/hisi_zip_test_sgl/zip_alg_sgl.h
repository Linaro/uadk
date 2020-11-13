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

#ifndef __WD_ZIP_ALG_SGL__H__
#define __WD_ZIP_ALG_SGL_H__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

//#define DEFLATE 0
//#define INFLATE 1

#define DMEMSIZE (1024 * 1024)	/* 1M */
#define HW_CTX_SIZE (64 * 1024)

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


/* for block interface */
extern int hw_blk_compress(int alg_type, int blksize,
			   unsigned char *dst, ulong *dstlen,
			   unsigned char *src, ulong srclen, int data_fmt);

extern int hw_blk_decompress(int alg_type, int blksize,
			     unsigned char *dst, ulong *dstlen,
			     unsigned char *src, ulong srclen, int data_fmt);

/* for stream memory interface */
extern int hw_stream_compress(int alg_type, int blksize,
			      unsigned char *dst, ulong *dstlen,
			      unsigned char *src, ulong srclen, int data_fmt);

extern int hw_stream_decompress(int alg_type, int blksize,
				unsigned char *dst, ulong *dstlen,
				unsigned char *src, ulong srclen, int data_fmt);

/* for stream file interface */
extern int hw_stream_def(FILE *source, FILE *dest,  int alg_type);
extern int hw_stream_inf(FILE *source, FILE *dest,  int alg_type);

#endif

