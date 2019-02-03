// SPDX-License-Identifier: GPL-2.0
#ifndef __HISI_TEST_HPRE_H
#define __HISI_TEST_HPRE_H

/* BD size of HPRE engine */
#define HPRE_SQE_SIZE		64

enum hpre_alg_type {
	HPRE_ALG_NC_NCRT = 0x0,
	HPRE_ALG_NC_CRT = 0x1,
	HPRE_ALG_KG_STD = 0x2,
	HPRE_ALG_KG_CRT = 0x3,
	HPRE_ALG_DH_G2 = 0x4,
	HPRE_ALG_DH = 0x5,
	HPRE_ALG_PRIME = 0x6,
	HPRE_ALG_MOD = 0x7,
	HPRE_ALG_MOD_INV = 0x8,
	HPRE_ALG_MUL = 0x9,
	HPRE_ALG_COPRIME = 0xA
};

enum wd_rsa_op {
	WD_RSA_INVALID,
	WD_RSA_SIGN,
	WD_RSA_VERIFY,
	WD_RSA_GENKEY,
};

enum wd_rsa_prikey_type {
	WD_RSA_PRIKEY1 = 1,
	WD_RSA_PRIKEY2 = 2,
};

typedef void (*wd_rsa_cb)(void *tag, int status, void *opdata);

struct wd_rsa_ctx_setup {
	char  *alg;
	wd_rsa_cb cb;
	__u16 aflags;
	__u16 key_bits;
	__u32 is_crt;
};

struct wd_rsa_pubkey {
	__u8 *n;
	__u8 *e;
	__u32 bytes;
};

struct wd_rsa_prikey1 {
	__u8 *n;
	__u8 *d;
	__u32 bytes;
};

struct wd_rsa_prikey2 {
	__u8 *p;
	__u8 *q;
	__u8 *dp;
	__u8 *dq;
	__u8 *qinv;
	__u32 bytes;
};

struct wd_rsa_prikey {
	struct wd_rsa_prikey1 pkey1;
	struct wd_rsa_prikey2 pkey2;
};

struct wd_rsa_op_data {
	enum wd_rsa_op op_type;
	int status;
	void *in;
	void *out;
	__u32 in_bytes;
	__u32 out_bytes;
};

struct wd_rsa_msg {

	/* First 8 bytes of the message must indicate algorithm */
	union {
		char  *alg;
		__u64 pading;
	};

	/* address type */
	__u16 aflags;
	__u8 op_type;
	__u8 prikey_type;
	__u32 status;

	__u64 in;
	__u64 out;
	__u64 pubkey;

	/* private key */
	__u64 prikey;

	__u16 nbytes;
	__u16 inbytes;
	__u16 outbytes;
	__u16 pad;

	__u64 udata;
};

int wd_rsa_is_crt(void *ctx);
int wd_rsa_key_bits(void *ctx);
void *wd_create_rsa_ctx(struct wd_queue *q, struct wd_rsa_ctx_setup *setup);
int wd_set_rsa_pubkey(void *ctx, struct wd_rsa_pubkey *pubkey);
void wd_get_rsa_pubkey(void *ctx, struct wd_rsa_pubkey **pubkey);
int wd_set_rsa_prikey(void *ctx, struct wd_rsa_prikey *prikey);
void wd_get_rsa_prikey(void *ctx, struct wd_rsa_prikey **prikey);

/* this is a synchronous mode RSA API */
int wd_do_rsa(void *ctx, struct wd_rsa_op_data *opdata);

/* this is a pair of asynchronous mode RSA APIs */
int wd_rsa_op(void *ctx, struct wd_rsa_op_data *opdata, void *tag);
int wd_rsa_poll(void *ctx, int num);
void wd_del_rsa_ctx(void *ctx);

#endif
