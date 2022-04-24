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

#ifndef __WD_AEAD_H
#define __WD_AEAD_H

#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>
#include "wd.h"
#include "wd_cipher.h"
#include "wd_digest.h"

#ifdef __cplusplus
extern "C" {
#endif

enum wcrypto_aead_op_type {
	WCRYPTO_CIPHER_ENCRYPTION_DIGEST,
	WCRYPTO_CIPHER_DECRYPTION_DIGEST,
	WCRYPTO_DIGEST_CIPHER_ENCRYPTION,
	WCRYPTO_DIGEST_CIPHER_DECRYPTION,
};

enum wcrypto_aead_mac_len {
	WCRYPTO_CCM_GCM_LEN	= 16,
	WCRYPTO_SM3_LEN	= 32,
	WCRYPTO_MD5_LEN	= 16,
	WCRYPTO_SHA1_LEN	= 20,
	WCRYPTO_SHA256_LEN	= 32,
	WCRYPTO_SHA224_LEN	= 28,
	WCRYPTO_SHA384_LEN	= 48,
	WCRYPTO_SHA512_LEN	= 64,
	WCRYPTO_SHA512_224_LEN	= 28,
	WCRYPTO_SHA512_256_LEN	= 32
};

/**
 * different contexts for different users/threads
 * @cb: call back functions of user
 * @calg: cipher algorithm type; denoted by enum wcrypto_cipher_alg
 * @cmode: cipher algorithm mode; denoted by enum wcrypto_cipher_mode
 * @dalg: digest algorithm type; denoted by enum wcrypto_digest_alg
 * @dmode: digest algorithm mode; denoted by enum wcrypto_digest_mode
 * @br: memory from user, it is given at ctx creating
 * @data_fmt: denoted by enum wcrypto_buff_type
 */
struct wcrypto_aead_ctx_setup {
	wcrypto_cb cb;
	enum wcrypto_cipher_alg calg;
	enum wcrypto_cipher_mode cmode;
	enum wcrypto_digest_alg dalg;
	enum wcrypto_digest_mode dmode;
	struct wd_mm_br br;
	__u16 data_fmt;
};

/**
 * operational data per I/O operation
 * AEAD encryption input:    assoc data  || plaintext
 * AEAD encryption output: assoc data  || ciphertext || auth tag
 * AEAD decryption input:    assoc data || ciphertext   || auth tag
 * AEAD decryption output: assoc data || plaintext
 * @op_type:aead operation type, denoted by enum wcrypto_aead_op_type
 * @status:I/O operation return status
 * @in: input data address
 * @out:output data address
 * @iv:initialization verctor data address
 * @in_bytes: input data size
 * @out_bytes:output data size
 * @out_buf_bytes:output buffer size
 * @iv_bytes:initialization verctor data size
 * @assoc_size: aead associated data size
 * @priv:reserved data field segment
 */
struct wcrypto_aead_op_data {
	enum wcrypto_aead_op_type op_type;
	int status;
	void *in;
	void *out;
	void *iv;
	__u32 in_bytes;
	__u32 out_bytes;
	__u32 out_buf_bytes;
	__u16 iv_bytes;
	__u16 assoc_size;
	void *priv;
};

/* AEAD message format of Warpdrive */
struct wcrypto_aead_msg {
	__u8 alg_type:4; 	/* Denoted by enum wcrypto_type */
	__u8 op_type:4;		/* Denoted by enum wcrypto_aead_op_type */
	__u8 calg:4;		/* Denoted by enum wcrypto_cipher_type */
	__u8 cmode:4;		/* Denoted by enum wcrypto_cipher_mode */
	__u8 dalg:4;		/* Denoted by enum wcrypto_digest_type */
	__u8 dmode:4;		/* Denoted by enum wcrypto_digest_mode */
	__u8 data_fmt;		/* Data format, denoted by enum wcrypto_buff_type */
	__u8 result;		/* Operation result, denoted by WD error code */

	__u16 ckey_bytes;	/* Key bytes */
	__u16 akey_bytes;	/* Key bytes */
	__u16 assoc_bytes;	/* Input associated data bytes */
	__u16 auth_bytes;	/* Output authentication bytes */
	__u16 iv_bytes;		/* IV bytes */
	__u32 in_bytes;		/* Input data bytes */
	__u32 out_bytes; 	/* Output data bytes */

	__u8 *ckey;		/* Input key VA pointer, should be DMA buffer */
	__u8 *akey;		/* Input authenticate key VA pointer, should be DMA buffer */
	__u8 *iv;		/* Input IV VA pointer, should be DMA buffer */
	__u8 *aiv;		/* Input auth IV VA pointer, should be DMA buffer */
	__u8 *in;		/* Input data VA pointer, should be DMA buffer */
	__u8 *out;		/* Output data VA pointer, should be DMA buffer */
	__u64 usr_data;		/* user identifier: struct wcrypto_cb_tag */
};

/**
 * wcrypto_create_aead_ctx() - create a aead context on the wrapdrive queue.
 * @q: wrapdrive queue, need requested by user.
 * @setup:setup data of user
 */
void *wcrypto_create_aead_ctx(struct wd_queue *q,
		struct wcrypto_aead_ctx_setup *setup);

/**
 * wcrypto_set_aead_ckey() - set cipher key to aead context.
 * @ctx: aead context, created by wcrypto_create_aead_ctx.
 * @key: cipher key addr
 * @key_len: cipher key length
 */
int wcrypto_set_aead_ckey(void *ctx, __u8 *key, __u16 key_len);

/**
 * wcrypto_set_aead_akey() - set authenticate key to aead context.
 * @ctx: aead context, created by wcrypto_create_aead_ctx.
 * @key: authenticate key addr
 * @key_len: authenticate key length
 */
int wcrypto_set_aead_akey(void *ctx, __u8 *key, __u16 key_len);

/**
 * wcrypto_aead_setauthsize() - set aead authsize to aead context.
 * @ctx: aead context, created by wcrypto_create_aead_ctx.
 * @authsize: aead authsize
 */
int wcrypto_aead_setauthsize(void *ctx, __u16 authsize);

/**
 * wcrypto_aead_getauthsize() - obtain maximum authentication data size
 * @ctx: aead context, created by wcrypto_create_aead_ctx.
 * Return: authentication data size / tag size in bytes
 */
int wcrypto_aead_getauthsize(void *ctx);

/**
 * wcrypto_aead_getmaxauthsize() - obtain maximum authentication data size
 * @ctx: aead context, created by wcrypto_create_aead_ctx.
 * Return: max authentication data size
 */
int wcrypto_aead_get_maxauthsize(void *ctx);

/**
 * wcrypto_do_aead() - syn/asynchronous aead operation
 * @ctx: context of user, created by wcrypto_create_aead_ctx.
 * @opdata: operational data
 * @tag: asynchronous:user_tag; synchronous:NULL.
 */
int wcrypto_do_aead(void *ctx, struct wcrypto_aead_op_data *opdata,
		void *tag);

/**
 * wcrypto_burst_aead() - (a)synchronous multiple aead operations
 * @a_ctx: context of user, created by wcrypto_create_aead_ctx.
 * @opdata: operational data
 * @tag: asynchronous:user_tag; synchronous:NULL.
 * @num: operations number per calling, maximum number is WCRYPTO_MAX_BURST_NUM.
 */
int wcrypto_burst_aead(void *a_ctx, struct wcrypto_aead_op_data **opdata,
		       void **tag, __u32 num);

/**
 * wcrypto_aead_poll() - poll operation for asynchronous operation
 * @q:wrapdrive queue
 * @num:how many respondences this poll has to get, 0 means get all finishings
 */
int wcrypto_aead_poll(struct wd_queue *q, unsigned int num);

/**
 * wcrypto_del_aead_ctx() - free aead context
 * @ctx: the context to be free
 */
void wcrypto_del_aead_ctx(void *ctx);

#ifdef __cplusplus
}
#endif

#endif

