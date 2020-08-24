/* SPDX-License-Identifier: Apache-2.0 */
#ifndef	__HISI_HPRE_H
#define	__HISI_HPRE_H

#include "hisi_qm_udrv.h"
#include "include/hpre_usr_if.h"
#include "smm.h"
#include "wd.h"
#include "wd_sched.h"

#define BYTE_BITS			8
#define BYTE_BITS_SHIFT		3
#define CRT_PARAMS_SZ(key_size)		((5 * (key_size)) >> 1)
#define CRT_GEN_PARAMS_SZ(key_size)	((7 * (key_size)) >> 1)
#define GEN_PARAMS_SZ(key_size)		((key_size) << 1)
#define CRT_PARAM_SZ(key_size)		((key_size) >> 1)
#define GET_NEGATIVE(val)	(0 - (val))
#define XTS_MODE_KEY_DIVISOR	2
#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32
#define CTX_ID_MAX_NUM		64

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
	HPRE_ALG_COPRIME = 0xA,
	HPRE_ALG_ECC_CURVE_TEST = 0xB,
	HPRE_ALG_ECDH_PLUS = 0xC,
	HPRE_ALG_ECDH_MULTIPLY = 0xD,
	HPRE_ALG_ECDSA_SIGN = 0xE,
	HPRE_ALG_ECDSA_VERF = 0xF,
	HPRE_ALG_X_DH_MULTIPLY = 0x10,
	HPRE_ALG_SM2_KEY_GEN = 0x11,
	HPRE_ALG_SM2_SIGN = 0x12,
	HPRE_ALG_SM2_VERF = 0x13,
	HPRE_ALG_SM2_ENC = 0x14,
	HPRE_ALG_SM2_DEC = 0x15
};

#endif	/* __HISI_HPRE_H */
