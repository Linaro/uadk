/* SPDX-License-Identifier: Apache-2.0 */

#ifndef ZSTD_LZ77_FSE_H
#define ZSTD_LZ77_FSE_H

#include <limits.h>
#include <stddef.h>

typedef struct ZSTD_CCtx_s ZSTD_CCtx;

typedef struct seqDef_s {
	unsigned int offset;
	unsigned short litLength;
	unsigned short matchLength;
} seqDef;

typedef struct COMP_4TUPLE_TAG_S {
	char *litStart;                             /* literal start address */
	seqDef *sequencesStart;                     /* sequences start address */
	unsigned int litlen;                        /* literal effective data length */
	unsigned int seqnum;                        /* sequences array's elements numbers */
	unsigned int longLengthID;                  /* litlen overflow flag */
	unsigned int longLengthPos;                 /* litlen overflow index */
	char *additional_p;                         /* start address of additional data */
} COMP_TUPLE_TAG;

typedef struct ZSTD_inBuffer_s {
	const void* src;    /* < start of input buffer */
	size_t size;        /* < size of input buffer */
	size_t pos;         /* < position where reading stopped. Will be updated. Necessarily 0 <= pos <= size */
} ZSTD_inBuffer;

typedef struct ZSTD_outBuffer_s {
	void*  dst;         /* < start of output buffer */
	size_t size;        /* < size of output buffer */
	size_t pos;         /* < position where writing stopped. Will be updated. Necessarily 0 <= pos <= size */
} ZSTD_outBuffer;

typedef enum {
	ZSTD_e_continue = 0, /* collect more data, encoder decides when to output compressed result, for optimal compression ratio */
	ZSTD_e_flush = 1,    /* flush any data provided so far */
	ZSTD_e_end = 2       /* flush any remaining data _and_ close current frame. */
} ZSTD_EndDirective;

/* the complete implementation code in libfse */
#ifdef ZLIB_FSE
ZSTD_CCtx* zstd_soft_fse_init(unsigned    int level);
int zstd_soft_fse(void *Ftuple, ZSTD_inBuffer *input, ZSTD_outBuffer *output, ZSTD_CCtx * cctx, ZSTD_EndDirective cmode);
#endif

#endif
