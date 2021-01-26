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

#ifndef __WD_DIGEST_H
#define __WD_DIGEST_H

#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>
#include "wd.h"

#ifdef __cplusplus
extern "C" {
#endif

enum wcrypto_digest_alg {
	WCRYPTO_SM3,
	WCRYPTO_MD5,
	WCRYPTO_SHA1,
	WCRYPTO_SHA256,
	WCRYPTO_SHA224,
	WCRYPTO_SHA384,
	WCRYPTO_SHA512,
	WCRYPTO_SHA512_224,
	WCRYPTO_SHA512_256,
	WCRYPTO_MAX_DIGEST_TYPE,
};

enum wcrypto_digest_mode {
	WCRYPTO_DIGEST_NORMAL,
	WCRYPTO_DIGEST_HMAC,
};

/**
 * different contexts for different users/threads
 * @cb: call back functions of user
 * @alg: digest algorithm type; denoted by enum wcrypto_digest_alg
 * @mode:digest algorithm mode; denoted by enum wcrypto_digest_mode
 * @br: memory from user, it is given at ctx creating
 * @data_fmt: data format, denoted by enum wcrypto_buff_type
 */
struct wcrypto_digest_ctx_setup {
	wcrypto_cb cb;
	enum wcrypto_digest_alg alg;
	enum wcrypto_digest_mode mode;
	struct wd_mm_br br;
	__u16 data_fmt;
};

/**
 * operational data per I/O operation
 * @in: input data address
 * @out:output data address
 * @in_bytes: input data size
 * @out_bytes:output data size
 * @priv:reserved data field segment
 * @status:I/O operation return status
 * @has_next: is there next data block
 */
struct wcrypto_digest_op_data {
	void *in;
	void *out;
	__u32 in_bytes;
	__u32 out_bytes;
	void *priv;
	int status;
	bool has_next;
};

/* Digest message format of Warpdrive */
struct wcrypto_digest_msg {
	__u8 alg_type;	/* Denoted by enum wcrypto_type */
	__u8 alg:4;		/* Denoted by enum wcrypto_digest_alg */
	__u8 has_next:1;	/* is there next block data */
	__u8 mode:3;		/* Denoted by enum wcrypto_digest_mode */
	__u8 data_fmt;		/* Data format, denoted by enum wcrypto_buff_type */
	__u8 result;		/* Operation result, denoted by WD error code */
	__u16 key_bytes;	/* Key bytes */
	__u16 iv_bytes;		/* IV bytes */

	__u8 *key;		/* Input key VA pointer, should be DMA buffer */
	__u8 *iv;		/* Input IV VA pointer, should be DMA buffer */
	__u8 *in;		/* Input data VA pointer, should be DMA buffer */
	__u8 *out;		/* Output data VA pointer, should be DMA buffer */
	__u32 in_bytes;		/* Input data bytes */
	__u32 out_bytes;	/* Output data bytes */
	__u64 usr_data;		/* user identifier: struct wcrypto_cb_tag */
};

/**
 * wcrypto_create_digest_ctx() - create a digest context on the wrapdrive queue.
 * @q: wrapdrive queue, need requested by user.
 * @setup:setup data of user
 */
void *wcrypto_create_digest_ctx(struct wd_queue *q,
		struct wcrypto_digest_ctx_setup *setup);

/**
 * wcrypto_set_digest_key() - set auth key to digest context.
 * @ctx: digest context, created by wcrypto_create_digest_ctx.
 * @key: auth key addr
 * @key_len: auth key length
 */
int wcrypto_set_digest_key(void *ctx, __u8 *key, __u16 key_len);

/**
 * wcrypto_do_digest() - syn/asynchronous digest operation
 * @ctx: context of user, created by wcrypto_create_digest_ctx.
 * @opdata: operational data
 * @tag: asynchronous:user_tag; synchronous:NULL.
 */
int wcrypto_do_digest(void *ctx, struct wcrypto_digest_op_data *opdata,
		void *tag);

/**
 * wcrypto_digest_poll() - poll operation for asynchronous operation
 * @q:wrapdrive queue
 * @num:how many respondences this poll has to get, 0 means get all finishings
 */
int wcrypto_digest_poll(struct wd_queue *q, unsigned int num);

/**
 * wcrypto_del_digest_ctx() - free digest context
 * @ctx: the context to be free
 */
void wcrypto_del_digest_ctx(void *ctx);

/**
 * wcrypto_burst_digest() - (a)synchronous multiple digest operations
 * @ctx: context of user, created by wcrypto_create_digest_ctx.
 * @opdata: operational data
 * @tag: asynchronous:user_tag; synchronous:NULL.
 * @num: operations number per calling, maximum number is WCRYPTO_MAX_BURST_NUM.
 */
int wcrypto_burst_digest(void *ctx, struct wcrypto_digest_op_data **opdata,
			 void **tag, __u32 num);

#ifdef __cplusplus
}
#endif

#endif

