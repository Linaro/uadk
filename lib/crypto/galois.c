// SPDX-License-Identifier: Apache-2.0
/* Copyright 2023 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <string.h>
#include "crypto/galois.h"

#define GF_LSB1_MASK	0x1
#define GF_R		0xe1000000
#define GALOIS_BITS	128
#define UINT_BITS	(sizeof(unsigned int) * 8)

#define GALOIS_UL_COUNT		4
#define GALOIS_UL_COUNT_H	12

#define GALOIS_PARA_TRANS_S(S, i)	(((unsigned int)(S)[(i) + 3] << 24) | \
					 ((unsigned int)(S)[(i) + 2] << 16) | \
					 ((unsigned int)(S)[(i) + 1] <<  8) | \
					 ((unsigned int)(S)[(i)]))
#define GALOIS_PARA_TRANS_H(H, i)	(((unsigned int)(H)[(i)] << 24)		| \
					 ((unsigned int)(H)[(i) + 1] << 16)	| \
					 ((unsigned int)(H)[(i) + 2] <<  8)	| \
					 ((unsigned int)(H)[(i) + 3]))

#define GALOIS_UINT_TRANS_CHAR(src_addr)					\
	do {									\
		unsigned int temp = *(src_addr);				\
		*(src_addr) = ((temp & 0xff) << 24) | ((temp & 0xff00) << 8)	\
		| ((temp & 0xff0000) >> 8) | ((temp & 0xff000000) >> 24);	\
	} while (0)

static void galois_xtime_128(unsigned int *src, unsigned int *dst)
{
	unsigned int tmp;
	__u8 i;

	/* Based the NIST Special Publication 800-38D */
	for (i = 0; i < GALOIS_UL_COUNT; i++) {
		tmp = src[i] >> 0x1;
		dst[i] = tmp | (src[i + 1] << (UINT_BITS - 1));
		if (i == GALOIS_UL_COUNT - 1) {
			if (src[0] & GF_LSB1_MASK)
				dst[i] = tmp ^ GF_R;
			else
				dst[i] = tmp;
		}
	}
}

static void galois_multi(unsigned int *input_a, unsigned int *input_b,
			 unsigned int *mul, unsigned int array_size)
{
	/* 4 * (unsigned int), 4 * 32bit = 128bit */
	unsigned int gf_V[GALOIS_BITS][GALOIS_UL_COUNT] = {0};
	unsigned int *gf_Z = mul;
	__u8 i, j, k;

	memcpy(gf_V[0], input_a, sizeof(unsigned int) * array_size);

	for (i = 1; i < GALOIS_BITS; i++)
		galois_xtime_128(gf_V[i - 1], gf_V[i]);

	for (i = 0; i < GALOIS_BITS; i++) {
		k = GALOIS_BITS - i - 1;
		if ((input_b[(k / UINT_BITS)] >> (k % UINT_BITS)) & 0x1) {
			for (j = 0; j < array_size; j++)
				gf_Z[j] ^= gf_V[i][j];
		}
	}
}

void galois_compute(__u8 *S, __u8 *H, __u8 *g, __u32 len)
{
	unsigned int SL[GALOIS_UL_COUNT] = {0};
	unsigned int HL[GALOIS_UL_COUNT] = {0};
	unsigned int G[GALOIS_UL_COUNT] = {0};
	__u8 i, j;

	/* Do galois multiplication operation on blocks: G = S x H */
	for (i = 0; i < GALOIS_UL_COUNT; i++) {
		j = i * GALOIS_UL_COUNT;
		SL[i] = GALOIS_PARA_TRANS_S(S, j);
		j = GALOIS_UL_COUNT_H - j;
		HL[i] = GALOIS_PARA_TRANS_H(H, j);
	}

	galois_multi(SL, HL, G, GALOIS_UL_COUNT);

	j = len - GALOIS_UL_COUNT;
	for (i = 0; i < GALOIS_UL_COUNT; i++) {
		GALOIS_UINT_TRANS_CHAR(&G[i]);
		memcpy(&g[j], &G[i], sizeof(unsigned int));
		j -= GALOIS_UL_COUNT;
	}
}
