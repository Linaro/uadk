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

#ifndef __WD_RSA_H
#define __WD_RSA_H

#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>
#include "wd.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wcrypto_rsa_kg_in; /* rsa key generation input parameters */
struct wcrypto_rsa_kg_out; /* rsa key generation output parameters */
struct wcrypto_rsa_pubkey; /* rsa public key */
struct wcrypto_rsa_prikey; /* rsa private key */

/* RSA operational types */
enum wcrypto_rsa_op_type  {
	WCRYPTO_RSA_INVALID, /* invalid rsa operation */
	WCRYPTO_RSA_SIGN, /* RSA sign */
	WCRYPTO_RSA_VERIFY, /* RSA verify */
	WCRYPTO_RSA_GENKEY, /* RSA key generation */
};

/* RSA key types */
enum wcrypto_rsa_key_type {
	WCRYPTO_RSA_INVALID_KEY, /* invalid rsa key type */
	WCRYPTO_RSA_PUBKEY, /* rsa public key type */
	WCRYPTO_RSA_PRIKEY1, /* invalid rsa private common key type */
	WCRYPTO_RSA_PRIKEY2, /* invalid rsa private CRT key type */
};

/* RSA context setting up input parameters from user */
struct wcrypto_rsa_ctx_setup {
	wcrypto_cb cb; /* call back function from user */
	__u16 data_fmt; /* data format denoted by enum wd_buff_type */
	__u16 key_bits; /* RSA key bits */
	bool is_crt; /* CRT mode or not */
	struct wd_mm_br br; /* memory operations from user */
};

struct wcrypto_rsa_op_data {
	enum wcrypto_rsa_op_type op_type; /* rsa operation type */
	int status; /* rsa operation status */
	void *in; /* rsa operation input address, should be DMA-able */
	void *out; /* rsa operation output address, should be DMA-able */
	__u32 in_bytes; /* rsa operation input bytes */
	__u32 out_bytes; /* rsa operation output bytes */
};

/* RSA message format of Warpdrive */
struct wcrypto_rsa_msg {
	__u8 alg_type:3; /* Denoted by enum wcrypto_type */
	__u8 op_type:2; /* Denoted by enum wcrypto_rsa_op_type  */
	__u8 key_type:2; /* Denoted by enum wcrypto_rsa_key_type */
	__u8 data_fmt:1; /* Data format, denoted by enum wd_buff_type */
	__u8 result; /* Data format, denoted by WD error code */
	__u16 in_bytes; /* Input data bytes */
	__u16 out_bytes; /* Output data bytes */
	__u16 key_bytes; /* Input key bytes */
	__u8 *in; /* Input data VA, buf should be DMA buffer. */
	__u8 *out; /* Output data VA pointer, should be DMA buffer */
	__u8 *key; /* Input key VA pointer, should be DMA buffer */

	/*
	 * Input user tag, used for identify data stream/user:
	 * struct wcrypto_cb_tag
	 */
	__u64 usr_data;
};

bool wcrypto_rsa_is_crt(const void *ctx);
int wcrypto_rsa_key_bits(const void *ctx);
void *wcrypto_create_rsa_ctx(struct wd_queue *q, struct wcrypto_rsa_ctx_setup *setup);
void wcrypto_get_rsa_pubkey(void *ctx, struct wcrypto_rsa_pubkey **pubkey);
void wcrypto_get_rsa_prikey(void *ctx, struct wcrypto_rsa_prikey **prikey);
int wcrypto_set_rsa_pubkey_params(void *ctx, struct wd_dtb *e, struct wd_dtb *n);
void wcrypto_get_rsa_pubkey_params(struct wcrypto_rsa_pubkey *pbk,
			struct wd_dtb **e, struct wd_dtb **n);
int wcrypto_set_rsa_prikey_params(void *ctx, struct wd_dtb *d, struct wd_dtb *n);
void wcrypto_get_rsa_prikey_params(struct wcrypto_rsa_prikey *pvk, struct wd_dtb **d,
			struct wd_dtb **n);
int wcrypto_set_rsa_crt_prikey_params(void *ctx, struct wd_dtb *dq,
			struct wd_dtb *dp,
			struct wd_dtb *qinv,
			struct wd_dtb *q,
			struct wd_dtb *p);
void wcrypto_get_rsa_crt_prikey_params(struct wcrypto_rsa_prikey *pvk,
			struct wd_dtb **dq, struct wd_dtb **dp,
			struct wd_dtb **qinv, struct wd_dtb **q,
			struct wd_dtb **p);

/* APIs For RSA key generate  */
struct wcrypto_rsa_kg_in *wcrypto_new_kg_in(void *ctx, struct wd_dtb *e,
			struct wd_dtb *p, struct wd_dtb *q);
void wcrypto_del_kg_in(void *ctx, struct wcrypto_rsa_kg_in *ki);
void wcrypto_get_rsa_kg_in_params(struct wcrypto_rsa_kg_in *kin, struct wd_dtb *e,
			struct wd_dtb *q, struct wd_dtb *p);

struct wcrypto_rsa_kg_out *wcrypto_new_kg_out(void *ctx);
void wcrypto_del_kg_out(void *ctx,  struct wcrypto_rsa_kg_out *kout);
void wcrypto_get_rsa_kg_out_params(struct wcrypto_rsa_kg_out *kout,
			struct wd_dtb *d,
			struct wd_dtb *n);
void wcrypto_get_rsa_kg_out_crt_params(struct wcrypto_rsa_kg_out *kout,
			struct wd_dtb *qinv,
			struct wd_dtb *dq, struct wd_dtb *dp);

int wcrypto_rsa_kg_in_data(struct wcrypto_rsa_kg_in *ki, char **data);
int wcrypto_rsa_kg_out_data(struct wcrypto_rsa_kg_out *ko, char **data);
void wcrypto_set_rsa_kg_out_crt_psz(struct wcrypto_rsa_kg_out *kout,
				    size_t qinv_sz,
				    size_t dq_sz,
				    size_t dp_sz);
void wcrypto_set_rsa_kg_out_psz(struct wcrypto_rsa_kg_out *kout,
				size_t d_sz,
				size_t n_sz);

/**
 * This is a pair of asynchronous mode RSA API as tag is not NULL,
 * or it is synchronous mode
 */
int wcrypto_do_rsa(void *ctx, struct wcrypto_rsa_op_data *opdata, void *tag);
int wcrypto_rsa_poll(struct wd_queue *q, unsigned int num);
void wcrypto_del_rsa_ctx(void *ctx);

#ifdef __cplusplus
}
#endif

#endif
