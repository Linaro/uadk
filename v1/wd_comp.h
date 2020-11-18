/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2019. Hisilicon Tech Co. Ltd. All Rights Reserved. */
#ifndef __WCRYPTO_COMP_H
#define __WCRYPTO_COMP_H

#include <stdlib.h>
#include <errno.h>
#include "wd.h"

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define ZIP_LOG(format, args...) fprintf(stderr, format, ##args)

/* now hw not support config */
enum wcrypto_comp_level {
	WCRYPTO_COMP_L1 = 1,		/* Compression level 1 */
	WCRYPTO_COMP_L2,		/* Compression level 2 */
	WCRYPTO_COMP_L3,		/* Compression level 3 */
	WCRYPTO_COMP_L4,		/* Compression level 4 */
	WCRYPTO_COMP_L5,		/* Compression level 5 */
	WCRYPTO_COMP_L6,		/* Compression level 6 */
	WCRYPTO_COMP_L7,		/* Compression level 7 */
	WCRYPTO_COMP_L8,		/* Compression level 8 */
	WCRYPTO_COMP_L9,		/* Compression level 9 */
};

/* now hw not support config */
enum wcrypto_comp_win_type {
	WCRYPTO_COMP_WS_4K, /* 4k bytes window size */
	WCRYPTO_COMP_WS_8K, /* 8k bytes window size */
	WCRYPTO_COMP_WS_16K, /* 16k bytes window size */
	WCRYPTO_COMP_WS_32K, /* 32k bytes window size */
};

/* Flush types */
enum wcrypto_comp_flush {
	WCRYPTO_INVALID_FLUSH,

	/* output as much data as we can to improve performance */
	WCRYPTO_NO_FLUSH,

	/* output as bytes aligning or some other conditions satisfied */
	WCRYPTO_SYNC_FLUSH,

	/* indicates the end of the file/data */
	WCRYPTO_FINISH,
};

enum wcrypto_comp_alg_type {
	WCRYPTO_ZLIB  = 0x00,
	WCRYPTO_GZIP,
};

/* Operational types for COMP */
enum wcrypto_comp_optype {
	WCRYPTO_DEFLATE,
	WCRYPTO_INFLATE,
};

enum wcrypto_op_result {
	WCRYPTO_STATUS_NULL,
	WCRYPTO_COMP_END,
	WCRYPTO_DECOMP_END,
};

enum wcrypto_comp_state {
	WCRYPTO_COMP_STATELESS,
	WCRYPTO_COMP_STATEFUL,
};

enum wcrypto_stream_status {
	WCRYPTO_COMP_STREAM_OLD,
	WCRYPTO_COMP_STREAM_NEW,
};

/**
 * different contexts for different users/threads
 * @alg_type:compressing algorithm type zlib/gzip
 * @op_type:operational types deflate/inflate
 * @stream_mode:stateless(block)/statefull
 * @comp_lv: compressing level;maybe support later
 * @win_size: window size of algorithm;maybe support later
 * @cb: call back functions of user
 * @ss_buf:field for user to alloc dma buffer
 * @next_in: next input byte
 * @next_out: next output byte should be put there
 * @ctx_buf: need extra memory for hw
 */
struct wcrypto_comp_ctx_setup {
	__u8 alg_type;
	__u8 op_type;
	__u8 stream_mode;
	__u8 comp_lv;
	__u32 win_size;
	wcrypto_cb cb;
	void *ss_buf;
	void *next_in;
	void *next_out;
	void *ctx_buf;
};

/**
 * operational data per I/O operation
 * @alg_type:compressing algorithm type zlib/gzip
 * @flush:input and output, denotes flush type or data status
 * @stream_pos: denotes stream start
 * @in:input data address
 * @in_len:input data size
 * @out:output data address
 * @in_temp:stash for in
 * @consumed:output, denotes how many bytes are consumed this time
 * @produced:output, denotes how many bytes are produced this time
 */
struct wcrypto_comp_op_data {
	__u8 alg_type;
	__u8 flush;
	__u8 stream_pos;
	__u8 status;
	__u32 in_len;
	__u32 avail_out;
	__u32 consumed;
	__u32 produced;
	__u8 *in;
	__u8 *out;
	__u8 *in_temp;
	__u32 isize;
	__u32 checksum;
	struct wd_queue *q;
	void *ctx;
};

struct wcrypto_comp_msg {
	__u32 alg_type;
	__u32 in_size;
	__u32 avail_out;
	__u32 in_cons; /* consumed bytes of input data */
	__u32 produced; /* produced bytes of current operation */
	__u8 *src;
	__u8 *dst;
	__u32 tag;
	__u8 comp_lv;
	__u8 file_type;
	__u8 humm_type;
	__u8 op_type;
	__u32 win_size;
	/* This flag indicates the output mode, from enum wcrypto_comp_flush */
	__u8 flush_type;
	__u8 stream_mode;
	__u8 stream_pos;
	__u32 status;
	__u64 udata;
	__u32 isize;
	__u32 checksum;
	__u32 ctx_priv0;
	__u32 ctx_priv1;
	__u32 ctx_priv2;
	void *ctx_buf;
};

/**
 * wcrypto_create_comp_ctx() - create a compress context on the wrapdrive queue.
 * @q: wrapdrive queue, need requested by user.
 * @setup:setup data of user
 */
void *wcrypto_create_comp_ctx(struct wd_queue *q, struct wcrypto_comp_ctx_setup *setup);

/**
 * wcrypto_do_comp() - syn/asynchronous compressing/decompressing operation
 * @ctx: context of user
 * @opdata: operational data
 * @tag: asynchronous:uesr_tag; synchronous:NULL.
 */
int wcrypto_do_comp(void *ctx, struct wcrypto_comp_op_data *opdata, void *tag);

/**
 * wcrypto_comp_poll() - poll operation for asynchronous operation
 * @q:wrapdrive queue
 * @num:how many respondings this poll has to get, 0 means get all finishings
 */
int wcrypto_comp_poll(struct wd_queue *q, int num);

/**
 * wcrypto_del_comp_ctx() - free compress context
 * @ctx: the context to be free
 */
void wcrypto_del_comp_ctx(void *ctx);

#endif
