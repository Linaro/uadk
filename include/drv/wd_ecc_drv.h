/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_ECC_DRV_H
#define __WD_ECC_DRV_H

#include <stdint.h>
#include <asm/types.h>

#include "../wd.h"
#include "../wd_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ECC */
#define ECDH_IN_PARAM_NUM		2
#define ECDH_OUT_PARAM_NUM		2
#define ECC_SIGN_IN_PARAM_NUM		2
#define ECC_SIGN_OUT_PARAM_NUM		2
#define ECC_VERF_IN_PARAM_NUM		3
#define ECC_PRIKEY_PARAM_NUM		7
#define ECDH_HW_KEY_PARAM_NUM		5
#define ECC_PUBKEY_PARAM_NUM		8
#define SM2_KG_OUT_PARAM_NUM		3
#define ECC_POINT_PARAM_NUM		2
#define ECDH_HW_KEY_SZ(hsz)		((hsz) * ECDH_HW_KEY_PARAM_NUM)
#define ECC_PRIKEY_SZ(hsz)		((hsz) * ECC_PRIKEY_PARAM_NUM)
#define ECC_PUBKEY_SZ(hsz)		((hsz) * ECC_PUBKEY_PARAM_NUM)
#define ECDH_OUT_PARAMS_SZ(hsz)		((hsz) * ECDH_OUT_PARAM_NUM)

/* x25519/x448 */
#define X_DH_OUT_PARAM_NUM		1
#define X_DH_HW_KEY_PARAM_NUM		3

#define X_DH_OUT_PARAMS_SZ(hsz)		((hsz) * X_DH_OUT_PARAM_NUM)
#define X_DH_HW_KEY_SZ(hsz)		((hsz) * X_DH_HW_KEY_PARAM_NUM)
#define ECC_SIGN_IN_PARAMS_SZ(hsz)	((hsz) * ECC_SIGN_IN_PARAM_NUM)
#define ECC_SIGN_OUT_PARAMS_SZ(hsz)	((hsz) * ECC_SIGN_OUT_PARAM_NUM)
#define ECC_VERF_IN_PARAMS_SZ(hsz)	((hsz) * ECC_VERF_IN_PARAM_NUM)
#define ECC_VERF_OUT_PARAMS_SZ		1

#define WD_X25519			0x1
#define WD_X448				0x2
#define WD_SM2P256			0x3

/* ECC message format */
struct wd_ecc_msg {
	struct wd_ecc_req req;
	struct wd_hash_mt hash;
	__u32 tag; /* User-defined request identifier */
	__u8 *key; /* Input key VA, should be DMA buffer */
	__u16 key_bytes; /* key bytes */
	__u8 curve_id; /* Ec curve denoted by enum wd_ecc_curve_type */
	__u8 result; /* alg op error code */
};

struct wd_ecc_pubkey {
	struct wd_dtb p;
	struct wd_dtb a;
	struct wd_dtb b;
	struct wd_dtb n;
	struct wd_ecc_point g;
	struct wd_ecc_point pub;
	__u32 size;
	void *data;
};

struct wd_ecc_prikey {
	struct wd_dtb p;
	struct wd_dtb a;
	struct wd_dtb d;
	struct wd_dtb b;
	struct wd_dtb n;
	struct wd_ecc_point g;
	__u32 size;
	void *data;
};

struct wd_ecc_key {
	struct wd_ecc_pubkey *pubkey;
	struct wd_ecc_prikey *prikey;
	struct wd_ecc_curve *cv;
	struct wd_ecc_point *pub;
	struct wd_dtb *d;
};

struct wd_ecc_dh_in {
	struct wd_ecc_point pbk;
};

struct wd_ecc_sign_in {
	struct wd_dtb dgst; /* hash msg */
	struct wd_dtb k; /* random */
	struct wd_dtb plaintext; /* original text before hash */
	__u8 k_set; /* 1 - k parameter set  0 - not set */
	__u8 dgst_set; /* 1 - dgst parameter set  0 - not set */
};

struct wd_ecc_verf_in {
	struct wd_dtb dgst; /* hash msg */
	struct wd_dtb s; /* signature s parameter */
	struct wd_dtb r; /* signature r parameter */
	struct wd_dtb plaintext; /* original text before hash */
	__u8 dgst_set; /* 1 - dgst parameter set  0 - not set */
};

struct wd_ecc_dh_out {
	struct wd_ecc_point out;
};

struct wd_ecc_sign_out {
	struct wd_dtb r; /* signature r parameter */
	struct wd_dtb s; /* signature s parameter */
};

struct wd_sm2_enc_in {
	struct wd_dtb k; /* random */
	struct wd_dtb plaintext; /* original text */
	__u8 k_set; /* 0 - not set 1 - set */
};

struct wd_sm2_enc_out {
	struct wd_ecc_point c1;
	struct wd_dtb c2;
	struct wd_dtb c3;
};

struct wd_sm2_dec_in {
	struct wd_ecc_point c1;
	struct wd_dtb c2;
	struct wd_dtb c3;
};

struct wd_sm2_kg_in {
	struct wd_ecc_point g;
};

struct wd_sm2_dec_out {
	struct wd_dtb plaintext;
};

struct wd_sm2_kg_out {
	struct wd_ecc_point pub;
	struct wd_dtb priv;
};

typedef union {
	struct wd_ecc_dh_in dh_in;
	struct wd_ecc_sign_in sin;
	struct wd_ecc_verf_in vin;
	struct wd_sm2_enc_in ein;
	struct wd_sm2_dec_in din;
	struct wd_sm2_kg_in kin;
} wd_ecc_in_param;

typedef union {
	struct wd_ecc_dh_out dh_out;
	struct wd_ecc_sign_out sout;
	struct wd_sm2_enc_out eout;
	struct wd_sm2_dec_out dout;
	struct wd_sm2_kg_out kout;
} wd_ecc_out_param;

struct wd_ecc_in {
	wd_ecc_in_param param;
	__u64 size;
	char data[];
};

struct wd_ecc_out {
	wd_ecc_out_param param;
	__u64 size;
	char data[];
};

struct wd_ecc_driver {
	const char *drv_name;
	const char *alg_name;
	__u32 drv_ctx_size;
	int (*init)(struct wd_ctx_config_internal *config, void *priv,
		    const char *alg_name);
	void (*exit)(void *priv);
	int (*send)(handle_t sess, void *ecc_msg);
	int (*recv)(handle_t sess, void *ecc_msg);
};

void wd_ecc_set_driver(struct wd_ecc_driver *drv);
struct wd_ecc_driver *wd_ecc_get_driver(void);

#ifdef WD_STATIC_DRV
#define WD_ECC_SET_DRIVER(drv)						\
struct wd_ecc_driver *wd_ecc_get_driver(void)				\
{									\
	return &drv;							\
}
#else
#define WD_ECC_SET_DRIVER(drv)						\
static void __attribute__((constructor)) set_driver_ecc(void)		\
{									\
	wd_ecc_set_driver(&(drv));					\
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* __WD_ECC_DRV_H */
