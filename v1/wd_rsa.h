/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_RSA_H
#define __WD_RSA_H

#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>
#include "wd.h"

struct wcrypto_rsa_kg_in;
struct wcrypto_rsa_kg_out;
struct wcrypto_rsa_pubkey;
struct wcrypto_rsa_prikey;

enum wcrypto_rsa_op_type  {
	WCRYPTO_RSA_INVALID,
	WCRYPTO_RSA_SIGN,
	WCRYPTO_RSA_VERIFY,
	WCRYPTO_RSA_GENKEY,
};

/* RSA key types */
enum wcrypto_rsa_key_type {
	WCRYPTO_RSA_INVALID_KEY,
	WCRYPTO_RSA_PUBKEY,
	WCRYPTO_RSA_PRIKEY1,
	WCRYPTO_RSA_PRIKEY2,
};

struct wcrypto_rsa_ctx_setup {
	wcrypto_cb cb;
	__u16 data_fmt;
	__u16 key_bits;
	bool is_crt;
	struct wd_mm_ops  ops;
};

struct wcrypto_rsa_op_data {
	enum wcrypto_rsa_op_type  op_type;
	int status;
	void *in;
	void *out;
	__u32 in_bytes;
	__u32 out_bytes;
};

/* RSA message format of Warpdrive */
struct wcrypto_rsa_msg {
	__u8 alg_type:3;	 /* Denoted by enum wcrypto_type */
	__u8 op_type:2;	/* Denoted by enum wcrypto_rsa_op_type  */
	__u8 key_type:2;	/* Denoted by enum wcrypto_rsa_key_type */
	__u8 data_fmt:1;	/* Data format, denoted by enum wd_buff_type */
	__u8 result;	/* Data format, denoted by enum wcrypto_op_result */
	__u16 in_bytes;	/* Input data bytes */
	__u16 out_bytes;	/* Output data bytes */
	__u16 key_bytes;	/* Input key bytes */
	/**
	 * Input data VA, buf should be from section 1.3.2,
	 * the same in the following.
	 */
	__u8 *in;
	__u8 *out;	/* Output data VA pointer */
	__u8 *key;	/* Input key VA pointer */
	/* Input user tag,which is used for ndentify data stream/user */
	__u64 usr_data;
};

bool wcrypto_rsa_is_crt(void *ctx);
int wcrypto_rsa_key_bits(void *ctx);
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

/**
 * This is a pair of asynchronous mode RSA API as tag is not NULL,
 * or it is synchronous mode
 */
int wcrypto_do_rsa(void *ctx, struct wcrypto_rsa_op_data *opdata, void *tag);
int wcrypto_rsa_poll(struct wd_queue *q, unsigned int num);
void wcrypto_del_rsa_ctx(void *ctx);
#endif
