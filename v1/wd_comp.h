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

#ifndef __WCRYPTO_COMP_H
#define __WCRYPTO_COMP_H

#include <stdlib.h>
#include <errno.h>
#include "wd.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define ZIP_LOG(format, args...) fprintf(stderr, format, ##args)

/* now hw not support config */
enum wcrypto_comp_level {
	WCRYPTO_COMP_L1 = 1, /* Compression level 1 */
	WCRYPTO_COMP_L2,     /* Compression level 2 */
	WCRYPTO_COMP_L3,     /* Compression level 3 */
	WCRYPTO_COMP_L4,     /* Compression level 4 */
	WCRYPTO_COMP_L5,     /* Compression level 5 */
	WCRYPTO_COMP_L6,     /* Compression level 6 */
	WCRYPTO_COMP_L7,     /* Compression level 7 */
	WCRYPTO_COMP_L8,     /* Compression level 8 */
	WCRYPTO_COMP_L9,     /* Compression level 9 */
};

/* now hw not support config */
enum wcrypto_comp_win_type {
	WCRYPTO_COMP_WS_4K,  /* 4k bytes window size */
	WCRYPTO_COMP_WS_8K,  /* 8k bytes window size */
	WCRYPTO_COMP_WS_16K, /* 16k bytes window size */
	WCRYPTO_COMP_WS_32K, /* 32k bytes window size */
};

/* Flush types */
enum wcrypto_comp_flush_type {
	WCRYPTO_INVALID_FLUSH,

	/* output as much data as we can to improve performance */
	WCRYPTO_NO_FLUSH,

	/* output as bytes aligning or some other conditions satisfied */
	WCRYPTO_SYNC_FLUSH,

	/* indicates the end of the file/data */
	WCRYPTO_FINISH,
};

enum wcrypto_comp_alg_type {
	WCRYPTO_ZLIB,
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
	WCRYPTO_DECOMP_END_NOSPACE,
	WCRYPTO_DECOMP_NO_CRC,
	WCRYPTO_DECOMP_BLK_NOSTART,
	WCRYPTO_SRC_DIF_ERR,
	WCRYPTO_DST_DIF_ERR,
	WCRYPTO_NEGTIVE_COMP_ERR,
};

enum wcrypto_comp_state {
	WCRYPTO_COMP_STATELESS,
	WCRYPTO_COMP_STATEFUL,
};

enum wcrypto_stream_status {
	WCRYPTO_COMP_STREAM_OLD,
	WCRYPTO_COMP_STREAM_NEW, /* indicates first packet */
};

/**
 * different contexts for different users/threads
 * @cb: call back functions of user
 * @alg_type:compressing algorithm type zlib/gzip
 * @op_type:operational types deflate/inflate
 * @stream_mode:stateless(block)/statefull
 * @comp_lv: compressing level;now reserved
 * @win_size: window size of algorithm; now reserved
 * @data_fmt: buffer format
 * @br: memory operations from user
 */
struct wcrypto_comp_ctx_setup {
	wcrypto_cb cb;
	__u8 alg_type;
	__u8 op_type;
	__u8 stream_mode;
	__u8 comp_lv;
	__u16 win_size;
	__u16 data_fmt;
	struct wd_mm_br br;
};

/**
 * operational data per I/O operation
 * @alg_type:compressing algorithm type zlib/gzip
 * @flush:input and output, denotes flush type or data status
 * @stream_pos: denotes stream start
 * @status:task status current time
 * @in:input data address
 * @out:output data address
 * @in_len:input data size
 * @avail_out:avail output size for hw
 * @consumed:output, denotes how many bytes are consumed this time
 * @produced:output, denotes how many bytes are produced this time
 * @isize:gzip isize
 * @checksum: protocol checksum
 * @priv: private field for extend
 */
struct wcrypto_comp_op_data {
	__u8 alg_type;
	__u8 flush;
	__u8 stream_pos;
	__u8 status;
	__u8 *in;
	__u8 *out;
	__u32 in_len;
	__u32 avail_out;
	__u32 consumed;
	__u32 produced;
	__u32 isize;
	__u32 checksum;
	void *priv;
};

struct wcrypto_comp_msg {
	__u8 alg_type;   /* Denoted by enum wcrypto_comp_alg_type */
	__u8 op_type;    /* Denoted by enum wcrypto_comp_op_type */
	__u8 flush_type; /* Denoted by enum wcrypto_comp_flush_type */
	__u8 stream_mode;/* Denoted by enum wcrypto_comp_state */
	__u8 stream_pos; /* Denoted by enum wcrypto_stream_status */
	__u8 comp_lv;    /* Denoted by enum wcrypto_comp_level */
	__u8 data_fmt;   /* Data format, denoted by enum wd_buff_type */
	__u8 win_sz;     /* Denoted by enum wcrypto_comp_win_type */
	__u32 in_size;   /* Input data bytes */
	__u32 avail_out; /* Output buffer size */
	__u32 in_cons;   /* consumed bytes of input data */
	__u32 produced;  /* produced bytes of current operation */
	__u8 *src;       /* Input data VA, buf should be DMA-able. */
	__u8 *dst;       /* Output data VA pointer */
	__u32 tag;       /* User-defined request identifier */
	__u32 win_size;  /* Denoted by enum wcrypto_comp_win_type */
	__u32 status;    /* Denoted by error code and enum wcrypto_op_result */
	__u32 isize;	 /* Denoted by gzip isize */
	__u32 checksum;  /* Denoted by zlib/gzip CRC */
	__u32 ctx_priv0; /* Denoted HW priv */
	__u32 ctx_priv1; /* Denoted HW priv */
	__u32 ctx_priv2; /* Denoted HW priv */
	void *ctx_buf;   /* Denoted HW ctx cache, for stream mode */
	__u64 udata;     /* Input user tag, indentify data of stream/user */
};

/**
 * wcrypto_create_comp_ctx() - create a compress context on the wrapdrive queue.
 * @q: wrapdrive queue, need requested by user.
 * @setup:setup data of user
 */
void *wcrypto_create_comp_ctx(struct wd_queue *q,
			      struct wcrypto_comp_ctx_setup *setup);

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
int wcrypto_comp_poll(struct wd_queue *q, unsigned int num);

/**
 * wcrypto_del_comp_ctx() - free compress context
 * @ctx: the context to be free
 */
void wcrypto_del_comp_ctx(void *ctx);

#ifdef __cplusplus
}
#endif

#endif
