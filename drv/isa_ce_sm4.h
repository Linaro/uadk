/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __SM4_CE_DRV_H
#define __SM4_CE_DRV_H

#pragma once
#include <stdint.h>
#include "wd_alg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SM4_KEY_SCHEDULE	32

struct SM4_KEY {
	__u32 rk[SM4_KEY_SCHEDULE];
};

struct sm4_ce_drv_ctx {
	struct wd_ctx_config_internal config;
};


void sm4_v8_set_encrypt_key(const unsigned char *userKey, struct SM4_KEY *key);
void sm4_v8_set_decrypt_key(const unsigned char *userKey, struct SM4_KEY *key);
void sm4_v8_cbc_encrypt(const unsigned char *in, unsigned char *out,
			size_t length, const struct SM4_KEY *key,
			unsigned char *ivec, const int enc);
void sm4_v8_ecb_encrypt(const unsigned char *in, unsigned char *out,
			size_t length, const struct SM4_KEY *key, const int enc);
void sm4_v8_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
			size_t len, const void *key, const unsigned char ivec[16]);

void sm4_v8_cfb_encrypt_blocks(const unsigned char *in, unsigned char *out,
		       size_t length, const struct SM4_KEY *key, unsigned char *ivec);
void sm4_v8_cfb_decrypt_blocks(const unsigned char *in, unsigned char *out,
		       size_t length, const struct SM4_KEY *key, unsigned char *ivec);
void sm4_v8_crypt_block(const unsigned char *in, unsigned char *out,
		       const struct SM4_KEY *key);

int sm4_v8_xts_encrypt(const unsigned char *in, unsigned char *out, size_t length,
				const struct SM4_KEY *key, unsigned char *ivec,
				const struct SM4_KEY *key2);
int sm4_v8_xts_decrypt(const unsigned char *in, unsigned char *out, size_t length,
				const struct SM4_KEY *key, unsigned char *ivec,
				const struct SM4_KEY *key2);

#ifdef __cplusplus
}
#endif

#endif /* __SM4_CE_DRV_H */
