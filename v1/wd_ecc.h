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

typedef int (*wcrypto_rand)(char *out, size_t out_len, void *usr);
typedef int (*wcrypto_hash)(const char *in, size_t in_len,
			    char *out, size_t out_len, void *usr);

struct wcrypto_ecc_in; /* ecc input parameters */
struct wcrypto_ecc_key; /* ecc key parameters */
struct wcrypto_ecc_out; /* ecc output parameters */

struct wcrypto_ecc_point {
	struct wd_dtb x; /* x affine coordinates */
	struct wd_dtb y; /* y affine coordinates */
};

/* ECC operational types */
enum wcrypto_ecc_op_type {
	WCRYPTO_EC_OP_INVALID, /* invalid ecc operation */
	WCRYPTO_ECXDH_GEN_KEY, /* ECDH/X448/X25519 generate pubkey */
	WCRYPTO_ECXDH_COMPUTE_KEY, /* ECDH/X448/X25519 compute share key */
	WCRYPTO_ECDSA_SIGN, /* ECDSA sign */
	WCRYPTO_ECDSA_VERIFY, /* ECDSA verify */
	WCRYPTO_SM2_SIGN, /* SM2 sign */
	WCRYPTO_SM2_VERIFY, /* SM2 verify */
	WCRYPTO_SM2_ENCRYPT, /* SM2 encrypt */
	WCRYPTO_SM2_DECRYPT, /* SM2 decrypt */
	WCRYPTO_SM2_KG /* SM2 key generate */
};

/* ECC operational types */
enum wcrypto_ecc_curve_id {
	WCRYPTO_SECP128R1 = 0x10, /* SECG 128 bit prime field */
	WCRYPTO_SECP192K1 = 0x11, /* SECG 192 bit prime field */
	WCRYPTO_SECP256K1 = 0x12, /* SECG 256 bit prime field */
	WCRYPTO_BRAINPOOLP320R1 = 0x13, /* RFC5639 320 bit prime field */
	WCRYPTO_BRAINPOOLP384R1 = 0x14, /* RFC5639 384 bit prime field */
	WCRYPTO_SECP521R1 = 0x15, /* NIST/SECG 521 bit prime field */
};

/* ECC hash callback func types */
enum wcrypto_ecc_hash_type {
	WCRYPTO_HASH_SM3,
	WCRYPTO_HASH_SHA1,
	WCRYPTO_HASH_SHA224,
	WCRYPTO_HASH_SHA256,
	WCRYPTO_HASH_SHA384,
	WCRYPTO_HASH_SHA512,
	WCRYPTO_HASH_MD4,
	WCRYPTO_HASH_MD5,
	WCRYPTO_HASH_MAX
};

struct wcrypto_ecc_curve {
	struct wd_dtb p; /* Prime field p */
	struct wd_dtb a; /* Elliptic curve equation a parameter */
	struct wd_dtb b; /* Elliptic curve equation b parameter */
	struct wcrypto_ecc_point g; /* Elliptic curve G point */
	struct wd_dtb n; /* Elliptic curve order */
};

enum wcrypto_ecc_curve_cfg_type {
	WCRYPTO_CV_CFG_ID, /* set curve param by denote curve ID */
	WCRYPTO_CV_CFG_PARAM /* set curve param by denote curve param */
};

struct wcrypto_ecc_curve_cfg {
	__u32 type; /* denoted by enum wcrypto_ecc_curve_cfg_type */
	union {
		enum wcrypto_ecc_curve_id id; /* if WCRYPTO_CV_CFG_ID */
		struct wcrypto_ecc_curve *pparam; /* if WCRYPTO_CV_CFG_PARAM */
	} cfg;
	__u8 resv[4]; /* reserve */
};

struct wcrypto_rand_mt {
	wcrypto_rand cb; /* rand callback */
	void *usr; /* user private param */
};

struct wcrypto_hash_mt {
	wcrypto_hash cb; /* hash callback */
	void *usr; /* user private param */
	__u8 type; /* hash type, denoted by enum wcrypto_ecc_hash_type */
	__u8 rsv[3]; /* reserve */
};

/* ECC context setting up input parameters from user */
struct wcrypto_ecc_ctx_setup {
	wcrypto_cb cb; /* call back function from user */
	__u16 data_fmt; /* data format denoted by enum wd_buff_type */
	__u16 key_bits; /* ECC key bits */
	struct wcrypto_ecc_curve_cfg cv; /* curve config denoted by user */
	struct wd_mm_br br; /* memory operations from user */
	struct wcrypto_rand_mt rand; /* rand method from user */
	struct wcrypto_hash_mt hash; /* hash method from user */
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
	__u8 alg_type:4; /* Denoted by enum wcrypto_type */
	__u8 op_type:4; /* Denoted by enum wcrypto_ecc_op_type */
	__u8 curve_id:7; /* Ec curve denoted by enum wcrypto_ecc_curve_type */
	__u8 data_fmt:1; /* Data format, denoted by enum wd_buff_type */
	__u8 mtype; /* not used, reserve */
	__u8 result; /* alg op error code */
	__u16 key_bytes; /* key bytes */
	__u16 in_bytes; /* Input data bytes */
	__u16 out_bytes; /* Output data bytes */
	__u8 hash_type; /* hash method denoted by enum wcrypto_ecc_hash_type */
	__u8 *in; /* Input data VA, should be DMA buffer */
	__u8 *out; /* Output data VA, should be DMA buffer */
	__u8 *key; /* Input key VA, should be DMA buffer */
	/*
	 * Input user tag, used for indentify data stream/user:
	 * struct wcrypto_cb_tag
	 */
	__u64 usr_data;
};

int wcrypto_get_ecc_key_bits(const void *ctx);
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
void wcrypto_del_ecc_in(void *ctx, struct wcrypto_ecc_in *in);
void wcrypto_del_ecc_out(void *ctx,  struct wcrypto_ecc_out *out);
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


/* APIs For ECDSA sign/verf */
struct wcrypto_ecc_in *wcrypto_new_ecdsa_sign_in(void *ctx,
						 struct wd_dtb *dgst,
						 struct wd_dtb *k);
struct wcrypto_ecc_in *wcrypto_new_ecdsa_verf_in(void *ctx,
						 struct wd_dtb *dgst,
						 struct wd_dtb *r,
						 struct wd_dtb *s);
struct wcrypto_ecc_out *wcrypto_new_ecdsa_sign_out(void *ctx);
void wcrypto_get_ecdsa_sign_in_params(struct wcrypto_ecc_in *in,
				      struct wd_dtb **dgst,
				      struct wd_dtb **k);
void wcrypto_get_ecdsa_verf_in_params(struct wcrypto_ecc_in *in,
				      struct wd_dtb **dgst,
				      struct wd_dtb **r,
				      struct wd_dtb **s);
void wcrypto_get_ecdsa_sign_out_params(struct wcrypto_ecc_out *out,
				       struct wd_dtb **r,
				       struct wd_dtb **s);

/**
 * This is a pair of asynchronous mode ECDSA API as tag is not NULL,
 * or it is synchronous mode
 */
int wcrypto_do_ecdsa(void *ctx, struct wcrypto_ecc_op_data *opdata, void *tag);
int wcrypto_ecdsa_poll(struct wd_queue *q, unsigned int num);

/* APIs For SM2 sign/verf/kg */
struct wcrypto_ecc_in *wcrypto_new_sm2_sign_in(void *ctx,
					       struct wd_dtb *e,
					       struct wd_dtb *k,
					       struct wd_dtb *id,
					       __u8 is_dgst);
struct wcrypto_ecc_in *wcrypto_new_sm2_verf_in(void *ctx,
					       struct wd_dtb *e,
					       struct wd_dtb *r,
					       struct wd_dtb *s,
					       struct wd_dtb *id,
					       __u8 is_dgst);
struct wcrypto_ecc_out *wcrypto_new_sm2_sign_out(void *ctx);

void wcrypto_get_sm2_sign_out_params(struct wcrypto_ecc_out *out,
				       struct wd_dtb **r,
				       struct wd_dtb **s);

struct wcrypto_ecc_in *wcrypto_new_sm2_enc_in(void *ctx,
					      struct wd_dtb *k,
					      struct wd_dtb *plaintext);
struct wcrypto_ecc_in *wcrypto_new_sm2_dec_in(void *ctx,
					      struct wcrypto_ecc_point *c1,
					      struct wd_dtb *c2,
					      struct wd_dtb *c3);
struct wcrypto_ecc_out *wcrypto_new_sm2_enc_out(void *ctx, __u32 plaintext_len);
struct wcrypto_ecc_out *wcrypto_new_sm2_dec_out(void *ctx, __u32 plaintext_len);
struct wcrypto_ecc_out *wcrypto_new_sm2_kg_out(void *ctx);
void wcrypto_get_sm2_kg_out_params(struct wcrypto_ecc_out *out,
				   struct wd_dtb **privkey,
				   struct wcrypto_ecc_point **pubkey);
void wcrypto_get_sm2_enc_out_params(struct wcrypto_ecc_out *out,
				    struct wcrypto_ecc_point **c1,
				    struct wd_dtb **c2,
				    struct wd_dtb **c3);
void wcrypto_get_sm2_dec_out_params(struct wcrypto_ecc_out *out,
				    struct wd_dtb **plaintext);


/**
 * This is a pair of asynchronous mode SM2 API as tag is not NULL,
 * or it is synchronous mode
 */
int wcrypto_do_sm2(void *ctx, struct wcrypto_ecc_op_data *opdata, void *tag);
int wcrypto_sm2_poll(struct wd_queue *q, unsigned int num);
#ifdef __cplusplus
}
#endif

#endif
