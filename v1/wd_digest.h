/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_DIGEST_H
#define __WD_DIGEST_H

#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>
#include "wd.h"


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
 * @ops: memory from user, it is given at ctx creating
 * @data_fmt: data format, denoted by enum wcrypto_buff_type
 */
struct wcrypto_digest_ctx_setup {
	wcrypto_cb cb;
	enum wcrypto_digest_alg alg;
	enum wcrypto_digest_mode mode;
	struct wd_mm_ops ops;
	__u16 data_fmt;
};

/**
 * operational data per I/O operation
 * @in: input data address
 * @out:output data address
 * @in_bytes: input data size
 * @out_bytes:output data size
 * @priv:private information for data extension
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
 * @tag: asynchronous:uesr_tag; synchronous:NULL.
 */
int wcrypto_do_digest(void *ctx, struct wcrypto_digest_op_data *opdata,
		void *tag);

/**
 * wcrypto_digest_poll() - poll operation for asynchronous operation
 * @q:wrapdrive queue
 * @num:how many respondings this poll has to get, 0 means get all finishings
 */
int wcrypto_digest_poll(struct wd_queue *q, unsigned int num);

/**
 * wcrypto_del_digest_ctx() - free digest context
 * @ctx: the context to be free
 */
void wcrypto_del_digest_ctx(void *ctx);
#endif

