/*
 * Copyright 2020 Huawei Technologies Co.,Ltd.All rights reserved.
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
#ifndef __WD_ECC_H
#define __WD_ECC_H

#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>
#include "wd.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wcrypto_ecc_in; /* ecc input parameters */
struct wcrypto_ecc_key; /* ecc key parameters */
struct wcrypto_ecc_out; /* ecc output parameters */

struct wcrypto_ecc_point {
	struct wd_dtb x;
	struct wd_dtb y;
};

/* ECC operational types */
enum wcrypto_ecc_op_type {
	WCRYPTO_EC_OP_INVALID, /* invalid ecc operation */
	WCRYPTO_ECDH_GEN_KEY, /* ECDH generate pubkey */
	WCRYPTO_ECDH_COMPUTE_KEY, /* ECDH compute share key */
	WCRYPTO_ECDSA_SIGN, /* ECDSA sign */
	WCRYPTO_ECDSA_VERIFY, /* ECDSA verify */
	WCRYPTO_SM2_SIGN, /* SM2 sign */
	WCRYPTO_SM2_VERIFY, /* SM2 verify */
	WCRYPTO_SM2_ENCRYPT, /* SM2 encrypt */
	WCRYPTO_SM2_DECRYPT /* SM2 decrypt */
};

/* ECC operational types */
enum wcrypto_ecc_curve_id {
	WCRYPTO_X448 = 0x1,
	WCRYPTO_X25519 = 0x2,
	WCRYPTO_SECP128R1 = 0x10, // SECG 128 bit prime field
	WCRYPTO_SECP192K1 = 0x11, // SECG 192 bit prime field
	WCRYPTO_SECP256K1 = 0x12, // SECG 256 bit prime field
	WCRYPTO_BRAINPOOLP320R1 = 0x13, // RFC5639 320 bit prime field
	WCRYPTO_BRAINPOOLP384R1 = 0x14, // RFC5639 384 bit prime field
	WCRYPTO_SECP521R1 = 0x15, // NIST/SECG 521 bit prime field
	WCRYPTO_SM2P256V1 = 0x40,
};

struct wcrypto_ecc_curve {
	struct wd_dtb p;
	struct wd_dtb a;
	struct wd_dtb b;
	struct wcrypto_ecc_point g;
	struct wd_dtb n;
};

enum wcrypto_ecc_curve_cfg_type {
	WCRYPTO_CV_CFG_ID, // set curve param by denote curve ID
	WCRYPTO_CV_CFG_PARAM // set curve param by denote curve param
};

struct wcrypto_ecc_curve_cfg {
	__u32 type; // denoted by enum wcrypto_ecc_curve_cfg_type
	union {
		enum wcrypto_ecc_curve_id id; // if WCRYPTO_CV_CFG_ID
		struct wcrypto_ecc_curve *pparam; // if WCRYPTO_CV_CFG_PARAM
	} cfg;
};

/* ECC context setting up input parameters from user */
struct wcrypto_ecc_ctx_setup {
	wcrypto_cb cb; /* call back function from user */
	__u16 data_fmt; /* data format denoted by enum wd_buff_type */
	__u16 key_bits; /* ECC key bits */
	struct wcrypto_ecc_curve_cfg cv; /* curve config denoted by user */
	struct wd_mm_br br; /* memory operations from user */
};

struct wcrypto_ecc_op_data {
	enum wcrypto_ecc_op_type op_type; /* ecc operation type */
	int status; /* ecc operation status */
	void *in; /* ecc operation input address, should be DMA-able */
	void *out; /* ecc operation output address, should be DMA-able */
	__u32 in_bytes; /* ecc operation input bytes */
	__u32 out_bytes; /* ecc operation output bytes */
};

/* ECC message format of Warpdrive */
struct wcrypto_ecc_msg {
	__u8 alg_type:4; /* Denoted by enum wd_alg_type */
	__u8 op_type:4; /* Denoted by enum wcrypto_ecc_op_type */
	__u8 curve_id:7; /* Ec curve denoted by enum wcrypto_ecc_curve_type */
	__u8 data_fmt:1; /* Data format, denoted by enum wd_buff_type */
	__u8 mtype; /* not used, reserve */
	__u8 result; /* Data format, denoted by enum wd_op_result */
	__u16 key_bytes; /* key bytes */
	__u16 in_bytes; /* Input data bytes */
	__u16 out_bytes; /* Output data bytes */
	__u8 *in; /* Input data VA, should be DMA buffer */
	__u8 *out; /* Output data VA, should be DMA buffer */
	__u8 *key; /* Input key VA, should be DMA buffer */
	/*
	 * Input user tag, used for indentify data stream/user:
	 * struct wcrypto_cb_tag
	 */
	__u64 usr_data;
};

int wcrypto_get_ecc_key_bits(void *ctx);
void *wcrypto_create_ecc_ctx(struct wd_queue *q,
			     struct wcrypto_ecc_ctx_setup *setup);
void wcrypto_del_ecc_ctx(void *ctx);
struct wcrypto_ecc_key *wcrypto_get_ecc_key(void *ctx);
int wcrypto_set_ecc_prikey(struct wcrypto_ecc_key *ecc_key,
			   struct wd_dtb *prikey);
int wcrypto_get_ecc_prikey(struct wcrypto_ecc_key *ecc_key,
			   struct wd_dtb **prikey);
int wcrypto_set_ecc_pubkey(struct wcrypto_ecc_key *ecc_key,
			   struct wcrypto_ecc_point *pubkey);
int wcrypto_get_ecc_pubkey(struct wcrypto_ecc_key *ecc_key,
			   struct wcrypto_ecc_point **pubkey);
int wcrypto_del_ecc_in(void *ctx, struct wcrypto_ecc_in *in);
int wcrypto_del_ecc_out(void *ctx,  struct wcrypto_ecc_out *out);
void wcrypto_get_ecc_prikey_params(struct wcrypto_ecc_key *key,
				   struct wd_dtb **p, struct wd_dtb **a,
				   struct wd_dtb **b, struct wd_dtb **n,
				   struct wcrypto_ecc_point **g,
				   struct wd_dtb **d);
void wcrypto_get_ecc_pubkey_params(struct wcrypto_ecc_key *key,
				   struct wd_dtb **p, struct wd_dtb **a,
				   struct wd_dtb **b, struct wd_dtb **n,
				   struct wcrypto_ecc_point **g,
				   struct wcrypto_ecc_point **pub);

/* APIs For ECDH */
void wcrypto_get_ecxdh_in_params(struct wcrypto_ecc_in *in,
				 struct wcrypto_ecc_point **pbk);
void wcrypto_get_ecxdh_out_params(struct wcrypto_ecc_out *out,
				  struct wcrypto_ecc_point **key);
struct wcrypto_ecc_in *wcrypto_new_ecxdh_in(void *ctx,
					    struct wcrypto_ecc_point *in);
struct wcrypto_ecc_out *wcrypto_new_ecxdh_out(void *ctx);
/**
 * This is a pair of asynchronous mode ECDH/ECDSA/SM2 API as tag is not NULL,
 * or it is synchronous mode
 */
int wcrypto_do_ecxdh(void *ctx, struct wcrypto_ecc_op_data *opdata, void *tag);
int wcrypto_ecxdh_poll(struct wd_queue *q, unsigned int num);

#ifdef __cplusplus
}
#endif

#endif
