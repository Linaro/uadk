/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */
#ifndef __ISA_CE_SM3_H
#define __ISA_CE_SM3_H

#include "wd_alg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SM3_DIGEST_SIZE		32
#define SM3_BLOCK_SIZE		64
#define SM3_STATE_WORDS		8
#define HMAC_BLOCK_SIZE		64
#define WORD_TO_CHAR_OFFSET	4
#define SM3_PADDING_BYTE	0x80
#define NH_OFFSET		23
#define BIT_TO_BLOCK_OFFSET	9
#define BIT_TO_BYTE_OFFSET	3
#define IPAD_DATA		0x36
#define OPAD_DATA		0x5c
#define KEY_BLOCK_NUM		1

#define SM3_IVA		0x7380166f
#define SM3_IVB		0x4914b2b9
#define SM3_IVC		0x172442d7
#define SM3_IVD		0xda8a0600
#define SM3_IVE		0xa96f30bc
#define SM3_IVF		0x163138aa
#define SM3_IVG		0xe38dee4d
#define SM3_IVH		0xb0fb0e4e

#define PUTU32_TO_U8(dst, src) \
	((dst)[0] = (__u8)((src) >> 24), \
	 (dst)[1] = (__u8)((src) >> 16), \
	 (dst)[2] = (__u8)((src) >>  8), \
	 (dst)[3] = (__u8)(src))

#define PUTU8_TO_U32(dst, src) \
	((dst) = (((__u32)(src)[0]) << 24) + \
		 (((__u32)(src)[1]) << 16) + \
		 (((__u32)(src)[2]) << 8) + \
		 ((__u32)(src)[3]))

struct sm3_ce_ctx {
	/*
	 * Use an array to represent the eight 32-bits word registers,
	 * SM3_IVA, SM3_IVB, ..., SM3_IVH, save IV and the final digest.
	 */
	__u32 word_reg[SM3_STATE_WORDS];
	/*
	 * The length (in bits) of all the msg fragments, the length of the
	 * whole msg should less than 2^64 bit, a msg block is 512-bits,
	 * make a 64-bits number in two parts, low 32-bits - 'Nl' and
	 * high 32-bits - 'Nh'.
	 */
	__u64 nblocks;
	/*
	 * Message block, a msg block is 512-bits, use sixteen __u32 type
	 * element to store it, used in B(i) = W0||W1||W2||...||W15.
	 * Use a __u8 array to replace the 32-bit array.
	 */
	__u8 block[SM3_BLOCK_SIZE];
	/* The number of msg that need to compute in current cycle or turn. */
	size_t num;
};

struct hmac_sm3_ctx {
	struct sm3_ce_ctx sctx;
	/* Save user key */
	__u8 key[SM3_BLOCK_SIZE];
};

struct sm3_ce_drv_ctx {
	struct wd_ctx_config_internal config;
};

void sm3_ce_block_compress(__u32 word_reg[SM3_STATE_WORDS],
			   const __u8 *src, size_t blocks);

#ifdef __cplusplus
}
#endif

#endif /* __ISA_CE_SM3_H */
