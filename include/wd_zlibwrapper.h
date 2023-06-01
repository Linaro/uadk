/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2022 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#ifndef UADK_ZLIBWRAPPER_H
#define UADK_ZLIBWRAPPER_H

/*
 * These APIs are used to replace the ZLIB library. So if you don't use them.
 * Please do not use these. These APIs provide limited function, while the
 * wd_comp.h provide full function.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Allowed flush values; the same as zlib library */
#define Z_NO_FLUSH		0
#define Z_PARTIAL_FLUSH		1
#define Z_SYNC_FLUSH		2
#define Z_FULL_FLUSH		3
#define Z_FINISH		4

/*
 * Return codes for the compression/decompression functions. Negative values
 * are errors, positive values are used for special but normal events.
 */
#define Z_OK			0
#define Z_STREAM_END		1
#define Z_NEED_DICT		2
#define Z_ERRNO			(-1)
#define Z_STREAM_ERROR		(-2)
#define Z_DATA_ERROR		(-3)
#define Z_MEM_ERROR		(-4)
#define Z_BUF_ERROR		(-5)
#define Z_VERSION_ERROR		(-6)

#define Z_DEFLATED		0
#define MAX_WBITS		15
#define DEF_MEM_LEVEL		0
#define Z_DEFAULT_STRATEGY	0

struct internal_state {};

typedef void (*alloc_func) (void *opaque, __u32 items, __u32 size);
typedef void (*free_func) (void *opaque, void *address);

typedef struct z_stream_s {
	/* next input byte */
	const __u8 *next_in;
	/* number of bytes available at next_in */
	__u32 avail_in;
	/* total number of input bytes read so far */
	__u64 total_in;

	/* next output byte will go here */
	__u8 *next_out;
	/* remaining free space at next_out */
	__u32 avail_out;
	/* total number of bytes output so far */
	__u64 total_out;

	/* last error message, NULL if no error */
	const char *msg;
	/* not visible by applications */
	struct internal_state *state;

	/* used to allocate the internal state */
	alloc_func zalloc;
	/* used to free the internal state */
	free_func zfree;
	/* private data object passed to zalloc and zfree */
	void *opaque;

	/*
	 * Best guess about the data type: binary or text
	 * for deflate, or the decoding state for inflate.
	 */
	int data_type;
	/* Adler-32 or CRC-32 value of the uncompressed data */
	__u64 adler;
	/* reserved the wd_comp_sess */
	__u64 reserved;
} z_stream;

typedef z_stream * z_streamp;

int wd_deflate_init(z_streamp strm, int level, int windowbits);
/*
 * The flush support Z_SYNC_FLUSH and Z_FINISH only.
 */
int wd_deflate(z_streamp strm, int flush);
int wd_deflate_reset(z_streamp strm);
int wd_deflate_end(z_streamp strm);

int wd_inflate_init(z_streamp strm, int  windowbits);
int wd_inflate(z_streamp strm, int flush);
int wd_inflate_reset(z_streamp strm);
int wd_inflate_end(z_streamp strm);

#endif /* UADK_ZLIBWRAPPER_H */
