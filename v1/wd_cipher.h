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

#ifndef __WD_CIPHER_H
#define __WD_CIPHER_H

#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>
#include "wd.h"

#ifdef __cplusplus
extern "C" {
#endif

enum wcrypto_cipher_op_type {
	WCRYPTO_CIPHER_ENCRYPTION,
	WCRYPTO_CIPHER_DECRYPTION,
};

enum wcrypto_cipher_alg {
	WCRYPTO_CIPHER_SM4,
	WCRYPTO_CIPHER_AES,
	WCRYPTO_CIPHER_DES,
	WCRYPTO_CIPHER_3DES,
};

enum wcrypto_cipher_mode {
	WCRYPTO_CIPHER_ECB,
	WCRYPTO_CIPHER_CBC,
	WCRYPTO_CIPHER_CTR,
	WCRYPTO_CIPHER_XTS,
	WCRYPTO_CIPHER_OFB,
};

/**
 * different contexts for different users/threads
 * @cb: call back functions of user
 * @alg: cipher algorithm type; denoted by enum wcrypto_cipher_alg
 * @mode:cipher algorithm mode; denoted by enum wcrypto_cipher_mode
 * @br: memory from user, it is given at ctx creating
 * @data_fmt: data format, denoted by enum wcrypto_buff_type
 */
struct wcrypto_cipher_ctx_setup {
	wcrypto_cb cb;
	enum wcrypto_cipher_alg alg;
	enum wcrypto_cipher_mode mode;
	struct wd_mm_br br;
	__u16 data_fmt;
};

/**
 * operational data per I/O operation
 * @op_type:cipher operation type, denoted by enum wcrypto_cipher_op_type
 * @status:I/O operation return status
 * @in: input data address
 * @out:output data address
 * @iv:initializtion verctor data address
 * @in_bytes: input data size
 * @out_bytes:output data size
 * @iv_bytes:initializtion verctor data size
 * @priv:private information for data extension
 */
struct wcrypto_cipher_op_data {
	enum wcrypto_cipher_op_type op_type;
	int status;
	void *in;
	void *out;
	void *iv;
	__u32 in_bytes;
	__u32 out_bytes;
	__u32 iv_bytes;
	void *priv;
};

/* Cipher message format of Warpdrive */
struct wcrypto_cipher_msg {
	__u8 alg_type:4;	/* Denoted by enum wcrypto_type */
	__u8 alg:4;		/* Denoted by enum wcrypto_cipher_alg*/
	__u8 op_type:4;		/* Denoted by enum wcrypto_cipher_op_type */
	__u8 mode:4;		/* Denoted by enum wcrypto_cipher_mode */
	__u8 data_fmt;		/* Data format, denoted by enum wcrypto_buff_type */
	__u8 result;		/* Operation result, denoted by WD error code */

	__u16 key_bytes;	/* Key bytes */
	__u16 iv_bytes;		/* IV bytes */
	__u32 in_bytes;		/* Input data bytes */
	__u32 out_bytes;	/* Output data bytes */

	__u8 *key;		/* Input key VA pointer, should be DMA buffer */
	__u8 *iv;		/* Input IV VA pointer, should be DMA buffer */
	__u8 *in;		/* Input data VA pointer, should be DMA buffer */
	__u8 *out;		/* Output data VA pointer, should be DMA buffer */
	__u64 usr_data;	/* user identifier: struct wcrypto_cb_tag */
};


/**
 * wcrypto_create_cipher_ctx() - create a cipher context on the wrapdrive queue.
 * @q: wrapdrive queue, need requested by user.
 * @setup:setup data of user
 */
void *wcrypto_create_cipher_ctx(struct wd_queue *q,
		struct wcrypto_cipher_ctx_setup *setup);

/**
 * wcrypto_set_cipher_key() - set cipher key to cipher context.
 * @ctx: cipher context, created by wcrypto_create_cipher_ctx.
 * @key: cipher key addr
 * @key_len: cipher key length
 */
int wcrypto_set_cipher_key(void *ctx, __u8 *key, __u16 key_len);

/**
 * wcrypto_do_cipher() - syn/asynchronous cipher operation
 * @ctx: context of user, created by wcrypto_create_cipher_ctx.
 * @opdata: operational data
 * @tag: asynchronous:uesr_tag; synchronous:NULL.
 */
int wcrypto_do_cipher(void *ctx, struct wcrypto_cipher_op_data *opdata,
		void *tag);

/**
 * wcrypto_cipher_poll() - poll operation for asynchronous operation
 * @q:wrapdrive queue
 * @num:how many respondings this poll has to get, 0 means get all finishings
 */
int wcrypto_cipher_poll(struct wd_queue *q, unsigned int num);

/**
 * wcrypto_del_cipher_ctx() - free cipher context
 * @ctx: the context to be free
 */
void wcrypto_del_cipher_ctx(void *ctx);

#ifdef __cplusplus
}
#endif

#endif

