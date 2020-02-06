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

#ifndef __WD_RNG_H
#define __WD_RNG_H

#include "wd.h"
#include "wd_digest.h"
#include "wd_cipher.h"

#define WD_RNG_CTX_MSG_NUM	256

struct wcrypto_rng_ctx_setup {
	wcrypto_cb cb;
	__u16 data_fmt;	/* Data format, denoted by enum wd_buff_type */
	enum wcrypto_type type;	/* Please refer to the definition of enum */
	enum wcrypto_cipher_alg calg;	/* DRBG cipher algorithm */
	enum wcrypto_cipher_mode cmode; /* DRBG cipher mode */
	enum wcrypto_digest_alg dalg;	/* DRBG digest algorithm */
	enum wcrypto_digest_mode dmode; /* DRBG digest mode */
};

struct wcrypto_rng_msg {
	__u8 alg_type;		/* Denoted by enum wcrypto_type */
	__u8 op_type;		/* Denoted by enum wcrypto_rng_op_type */
	__u8 data_fmt;	/* Data format, denoted by enum wd_buff_type */
	__u8 result;		/* Data format, denoted by WD error code */
	__u8 *out;		/* Result address */
	__u8 *in;		/* Input address */
	__u32 out_bytes;	/* output bytes */
	__u32 in_bytes;		/* input bytes */
	__u64 usr_tag;		/* user identifier */
};

enum wcrypto_rng_op_type {
	WCRYPTO_RNG_INVALID,	/* Invalid RNG operational type */
	WCRYPTO_DRBG_RESEED,	/* seed operation */
	WCRYPTO_DRBG_GEN,	/* deterministic random number generation */
	WCRYPTO_TRNG_GEN,	/* true random number generation */
};

struct wcrypto_rng_op_data {
	enum wcrypto_rng_op_type op_type;
	__u32 status;		/* Operation result status */
	void *in;		/* input */
	void *out;		/* output */
	__u32 in_bytes;		/* input bytes */
	__u32 out_bytes;	/* output bytes */
};

void *wcrypto_create_rng_ctx(struct wd_queue *q,
				struct wcrypto_rng_ctx_setup *setup);
void wcrypto_del_rng_ctx(void *ctx);
int wcrypto_do_rng(void *ctx, struct wcrypto_rng_op_data *opdata, void *tag);
int wcrypto_rng_poll(struct wd_queue *q, unsigned int num);

#endif
