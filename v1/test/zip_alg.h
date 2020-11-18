/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_ZIP_ALG_H__
#define __WD_ZIP_ALG_H__

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
			   unsigned char *src, ulong srclen);

extern int hw_blk_decompress(int alg_type, int blksize,
			     unsigned char *dst, ulong *dstlen,
			     unsigned char *src, ulong srclen);

/* for stream memory interface */
extern int hw_stream_compress(int alg_type, int blksize,
			      unsigned char *dst, ulong *dstlen,
			      unsigned char *src, ulong srclen);

extern int hw_stream_decompress(int alg_type, int blksize,
				unsigned char *dst, ulong *dstlen,
				unsigned char *src, ulong srclen);

/* for stream file interface */
extern int hw_stream_def(FILE *source, FILE *dest,  int alg_type);
extern int hw_stream_inf(FILE *source, FILE *dest,  int alg_type);

#endif

