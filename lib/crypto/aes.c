// SPDX-License-Identifier: Apache-2.0
/* Copyright 2023 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <string.h>
#include "crypto/aes.h"

#define WORD(n) (0x##n##n##n##n)
#define LONG(n) (0x##n##n##n##n##n##n##n##n)

#define STATE_CNT	2

static void xtimeword(__u32 *w)
{
	__u32 a, b;

	a = *w;
	b = a & WORD(80);
	a ^= b;
	b -= b >> 0x7;
	b &= WORD(1B);
	b ^= a << 0x1;
	*w = b;
}

static void xtimelong(__u64 *w)
{
	__u64 a, b;

	a = *w;
	b = a & LONG(80);
	a ^= b;
	b -= b >> 0x7;
	b &= LONG(1B);
	b ^= a << 0x1;
	*w = b;
}

static __u32 caculate_x_final(__u32 x_1)
{
	__u32 x, y;

	x = x_1;
	y = ((x & WORD(FE)) >> 0x1) | ((x & WORD(01)) << 0x7);
	x &= WORD(39);
	x ^= y & WORD(3F);
	y = ((y & WORD(FC)) >> 0x2) | ((y & WORD(03)) << 0x6);
	x ^= y & WORD(97);
	y = ((y & WORD(FE)) >> 0x1) | ((y & WORD(01)) << 0x7);
	x ^= y & WORD(9B);
	y = ((y & WORD(FE)) >> 0x1) | ((y & WORD(01)) << 0x7);
	x ^= y & WORD(3C);
	y = ((y & WORD(FE)) >> 0x1) | ((y & WORD(01)) << 0x7);
	x ^= y & WORD(DD);
	y = ((y & WORD(FE)) >> 0x1) | ((y & WORD(01)) << 0x7);
	x ^= y & WORD(72);
	x ^= WORD(63);

	return x;
}

static __u32 caculate_x(__u32 *w)
{
	__u32 x, y;

	x = *w;
	y = ((x & WORD(FE)) >> 0x1) | ((x & WORD(01)) << 0x7);
	x &= WORD(DD);
	x ^= y & WORD(57);
	y = ((y & WORD(FE)) >> 0x1) | ((y & WORD(01)) << 0x7);
	x ^= y & WORD(1C);
	y = ((y & WORD(FE)) >> 0x1) | ((y & WORD(01)) << 0x7);
	x ^= y & WORD(4A);
	y = ((y & WORD(FE)) >> 0x1) | ((y & WORD(01)) << 0x7);
	x ^= y & WORD(42);
	y = ((y & WORD(FE)) >> 0x1) | ((y & WORD(01)) << 0x7);
	x ^= y & WORD(64);
	y = ((y & WORD(FE)) >> 0x1) | ((y & WORD(01)) << 0x7);
	x ^= y & WORD(E0);
	return x;
}

static void subword(__u32 *w)
{
#define SPECIAL_WORD	0x0A0A0A0A0Au
	__u32 x, a1, a2, a3, a4, a5, a6;

	x = caculate_x(w);
	a1 = x ^ (x & WORD(F0)) >> 0x4;
	a2 = ((x & WORD(CC)) >> 0x2) | ((x & WORD(33)) << 0x2);
	a3 = (x & a1) ^ ((x & a1) & WORD(AA)) >> 0x1;
	a3 ^= (((x << 0x1) & a1) ^ ((a1 << 0x1) & x)) & WORD(AA);
	a4 = (a2 & a1)  ^ ((a2 & a1) & WORD(AA)) >> 0x1;
	a4 ^= (((a2 << 0x1) & a1) ^ ((a1 << 0x1) & a2)) & WORD(AA);
	a5 = (a3 & WORD(CC)) >> 0x2;
	a3 ^= ((a4 << 0x2) ^ a4) & WORD(CC);
	a4 = (a5 & WORD(22)) | (a5 & WORD(22)) >> 0x1;
	a4 ^= (a5 << 0x1) & WORD(22);
	a3 ^= a4;
	a5 = (a3 & WORD(A0)) | (a3 & WORD(A0)) >> 0x1;
	a5 ^= (a3 << 0x1) & WORD(A0);
	a4 = a5 & WORD(C0);
	a6 = a4 >> 0x2;
	a4 ^= (a5 << 0x2) & WORD(C0);
	a5 = (a6 & WORD(20)) | (a6 & WORD(20)) >> 0x1;
	a5 ^= (a6 << 0x1) & WORD(20);
	a4 |= a5;
	a3 ^= a4 >> 0x4;
	a3 &= WORD(0F);
	a2 = a3 ^ (a3 & WORD(0C)) >> 0x2;
	a4 = a3 & a2;
	a4 ^= (a4 & SPECIAL_WORD) >> 0x1;
	a4 ^= (((a3 << 0x1) & a2) ^ ((a2 << 0x1) & a3)) & WORD(0A);
	a5 = (a4 & WORD(08)) | (a4 & WORD(08)) >> 0x1;
	a5 ^= (a4 << 0x1) & WORD(08);
	a4 ^= a5 >> 0x2;
	a4 &= WORD(03);
	a4 ^= (a4 & WORD(02)) >> 0x1;
	a4 |= a4 << 0x2;
	a3 = (a2 & a4) ^ ((a2 & a4) & WORD(0A)) >> 0x1;
	a3 ^= (((a2 << 0x1) & a4) ^ ((a4 << 0x1) & a2)) & WORD(0A);
	a3 |= a3 << 0x4;
	a2 = ((a1 & WORD(CC)) >> 0x2) | ((a1 & WORD(33)) << 0x2);
	x = (a1 & a3) ^ ((a1 & a3) & WORD(AA)) >> 0x1;
	x ^= (((a1 << 0x1) & a3) ^ ((a3 << 0x1) & a1)) & WORD(AA);
	a4 = (a2 & a3) ^ ((a2 & a3) & WORD(AA)) >> 0x1;
	a4 ^= (((a2 << 0x1) & a3) ^ ((a3 << 0x1) & a2)) & WORD(AA);
	a5 = (x & WORD(CC)) >> 0x2;
	x ^= ((a4 << 0x2) ^ a4) & WORD(CC);
	a4 = (a5 & WORD(22)) | (a5 & WORD(22)) >> 0x1;
	a4 ^= (a5 << 0x1) & WORD(22);
	*w = caculate_x_final(x ^ a4);
}

static __u64 caculate_long_x_final(__u64 x_1)
{
	__u64 x, y;

	x = x_1;
	y = ((x & LONG(FE)) >> 0x1) | ((x & LONG(01)) << 0x7);
	x &= LONG(39);
	x ^= y & LONG(3F);
	y = ((y & LONG(FC)) >> 0x2) | ((y & LONG(03)) << 0x6);
	x ^= y & LONG(97);
	y = ((y & LONG(FE)) >> 0x1) | ((y & LONG(01)) << 0x7);
	x ^= y & LONG(9B);
	y = ((y & LONG(FE)) >> 0x1) | ((y & LONG(01)) << 0x7);
	x ^= y & LONG(3C);
	y = ((y & LONG(FE)) >> 0x1) | ((y & LONG(01)) << 0x7);
	x ^= y & LONG(DD);
	y = ((y & LONG(FE)) >> 0x1) | ((y & LONG(01)) << 0x7);
	x ^= y & LONG(72);
	x ^= LONG(63);

	return x;
}

static __u64 caculate_long_x(__u64 *w)
{
	__u64 x, y;

	x = *w;
	y = ((x & LONG(FE)) >> 0x1) | ((x & LONG(01)) << 0x7);
	x &= LONG(DD);
	x ^= y & LONG(57);
	y = ((y & LONG(FE)) >> 0x1) | ((y & LONG(01)) << 0x7);
	x ^= y & LONG(1C);
	y = ((y & LONG(FE)) >> 0x1) | ((y & LONG(01)) << 0x7);
	x ^= y & LONG(4A);
	y = ((y & LONG(FE)) >> 0x1) | ((y & LONG(01)) << 0x7);
	x ^= y & LONG(42);
	y = ((y & LONG(FE)) >> 0x1) | ((y & LONG(01)) << 0x7);
	x ^= y & LONG(64);
	y = ((y & LONG(FE)) >> 0x1) | ((y & LONG(01)) << 0x7);
	x ^= y & LONG(E0);

	return x;
}

static void sublong(__u64 *w)
{
	__u64 x, a1, a2, a3, a4, a5, a6;

	x = caculate_long_x(w);
	a1 = x ^ (x & LONG(F0)) >> 0x4;
	a2 = ((x & LONG(CC)) >> 0x2) | ((x & LONG(33)) << 0x2);
	a3 = (x & a1) ^ ((x & a1) & LONG(AA)) >> 0x1;
	a3 ^= (((x << 0x1) & a1) ^ ((a1 << 0x1) & x)) & LONG(AA);
	a4 = (a2 & a1)  ^ ((a2 & a1) & LONG(AA)) >> 0x1;
	a4 ^= (((a2 << 0x1) & a1) ^ ((a1 << 0x1) & a2)) & LONG(AA);
	a5 = (a3 & LONG(CC)) >> 0x2;
	a3 ^= ((a4 << 0x2) ^ a4) & LONG(CC);
	a4 = (a5 & LONG(22)) | (a5 & LONG(22)) >> 0x1;
	a4 ^= (a5 << 0x1) & LONG(22);
	a3 ^= a4;
	a5 = (a3 & LONG(A0)) | (a3 & LONG(A0)) >> 0x1;
	a5 ^= (a3 << 0x1) & LONG(A0);
	a4 = a5 & LONG(C0);
	a6 = a4 >> 0x2;
	a4 ^= (a5 << 0x2) & LONG(C0);
	a5 = (a6 & LONG(20)) | (a6 & LONG(20)) >> 0x1;
	a5 ^= (a6 << 0x1) & LONG(20);
	a4 |= a5;
	a3 ^= a4 >> 0x4;
	a3 &= LONG(0F);
	a2 = a3 ^ (a3 & LONG(0C)) >> 0x2;
	a4 = a3 & a2;
	a4 ^= (a4 & LONG(0A)) >> 0x1;
	a4 ^= (((a3 << 0x1) & a2) ^ ((a2 << 0x1) & a3)) & LONG(0A);
	a5 = (a4 & LONG(08)) | (a4 & LONG(08)) >> 0x1;
	a5 ^= (a4 << 0x1) & LONG(08);
	a4 ^= a5 >> 0x2;
	a4 &= LONG(03);
	a4 ^= (a4 & LONG(02)) >> 0x1;
	a4 |= a4 << 0x2;
	a3 = (a2 & a4) ^ ((a2 & a4) & LONG(0A)) >> 0x1;
	a3 ^= (((a2 << 0x1) & a4) ^ ((a4 << 0x1) & a2)) & LONG(0A);
	a3 |= a3 << 0x4;
	a2 = ((a1 & LONG(CC)) >> 0x2) | ((a1 & LONG(33)) << 0x2);
	x = (a1 & a3) ^ ((a1 & a3) & LONG(AA)) >> 0x1;
	x ^= (((a1 << 0x1) & a3) ^ ((a3 << 0x1) & a1)) & LONG(AA);
	a4 = (a2 & a3) ^ ((a2 & a3) & LONG(AA)) >> 0x1;
	a4 ^= (((a2 << 0x1) & a3) ^ ((a3 << 0x1) & a2)) & LONG(AA);
	a5 = (x & LONG(CC)) >> 0x2;
	x ^= ((a4 << 0x2) ^ a4) & LONG(CC);
	a4 = (a5 & LONG(22)) | (a5 & LONG(22)) >> 0x1;
	a4 ^= (a5 << 0x1) & LONG(22);
	*w = caculate_long_x_final(x ^ a4);
}

static void shift_rows(__u64 *state)
{
#define S_CNT		4
	unsigned char s[S_CNT];
	unsigned char *s0;
	__u8 r, i;

	s0 = (unsigned char *)state;
	for (r = 0; r < S_CNT; r++) {
		for (i = 0; i < S_CNT; i++)
			s[i] = s0[i * S_CNT + r];

		for (i = 0; i < S_CNT; i++)
			s0[i * S_CNT + r] = s[(r + i) % S_CNT];
	}
}

static void mix_columns(__u64 *state)
{
#define REVERT_OFFSET	0x3
#define A		0xFFFF0000FFFF0000uLL
#define B		0xFF00FF00FF00FF00uLL
	union uni s1;
	union uni s;
	__u8 c, i;

	for (c = 0; c < STATE_CNT; c++) {
		s1.d = state[c];
		s.d = s1.d;
		s.d ^= ((s.d & A) >> 0x10)
			| ((s.d & ~A) << 0x10);
		s.d ^= ((s.d & B) >> 0x8)
			| ((s.d & ~B) << 0x8);
		s.d ^= s1.d;
		xtimelong(&s1.d);
		s.d ^= s1.d;
		for (i = 0; i < UINT_B_CNT; i++) {
			if (i == UINT_B_CNT - 1 || i ==  (UINT_B_CNT >> 0x1) - 1)
				s.b[i] ^= s1.b[i - REVERT_OFFSET];
			else
				s.b[i] ^= s1.b[i + 1];
		}
		state[c] = s.d;
	}
}

static void add_round_key(__u64 *state, const __u64 *w)
{
	state[0] ^= w[0];
	state[1] ^= w[1];
}

static void cipher(const unsigned char *in, unsigned char *out,
		   const __u64 *w, __u8 nr)
{
#define STATE_BYTE	16
	__u64 state[STATE_CNT];
	__u8 i;

	memcpy(state, in, STATE_BYTE);

	add_round_key(state, w);

	for (i = 1; i < nr; i++) {
		sublong(&state[0]);
		sublong(&state[1]);
		shift_rows(state);
		mix_columns(state);
		add_round_key(state, w + i * STATE_CNT);
	}

	sublong(&state[0]);
	sublong(&state[1]);
	shift_rows(state);
	add_round_key(state, w + nr * STATE_CNT);

	memcpy(out, state, STATE_BYTE);
}

static void rotword(__u32 *x)
{
#define WORDBYTE	4
	unsigned char *w0;
	unsigned char tmp;
	__u8 i;

	w0 = (unsigned char *)x;
	tmp = w0[0];
	for (i = 0; i < WORDBYTE - 1; i++)
		w0[i] = w0[i + 1];

	w0[WORDBYTE - 1] = tmp;
}

static void key_expansion(const unsigned char *key, __u64 *w, __u8 nr, __u8 nk)
{
#define RCON_LEN	4
#define N		2
#define NK		6
	__u32 rcon;
	union uni prev;
	__u32 temp;
	__u8 i, n, m;

	memcpy(w, key, nk * RCON_LEN);
	memcpy(&rcon, "\1\0\0\0", RCON_LEN);
	n = nk / N;
	m = (nr + 1) * N;
	prev.d = w[n - 1];
	for (i = n; i < m; i++) {
		temp = prev.w[1];
		if (i % n == 0) {
			rotword(&temp);
			subword(&temp);
			temp ^= rcon;
			xtimeword(&rcon);
		} else if (nk > NK && i % n == N) {
			subword(&temp);
		}
		prev.d = w[i - n];
		prev.w[0] ^= temp;
		prev.w[1] ^= prev.w[0];
		w[i] = prev.d;
	}
}

static int aes_set_encrypt_key(const unsigned char *userkey, const int bits,
			       struct aes_key *key)
{
#define AES_128_BIT	128
#define AES_192_BIT	192
#define AES_256_BIT	256
#define AES_128_ROUNDS	10
#define AES_192_ROUNDS	12
#define AES_256_ROUNDS	14
#define KEY_NK		32
	__u64 *rk;

	if (!userkey || !key)
		return -1;
	if (bits != AES_128_BIT && bits != AES_192_BIT && bits != AES_256_BIT)
		return -1;

	rk = (__u64 *)key->rd_key;

	if (bits == AES_128_BIT)
		key->rounds = AES_128_ROUNDS;
	else if (bits == AES_192_BIT)
		key->rounds = AES_192_ROUNDS;
	else
		key->rounds = AES_256_ROUNDS;

	key_expansion(userkey, rk, key->rounds, bits / KEY_NK);
	return 0;
}

static void aes_encrypt_(const __u8 *in, __u8 *out, const struct aes_key *key)
{
	const __u64 *rk;

	rk = (__u64 *)key->rd_key;

	cipher(in, out, rk, key->rounds);
}

void aes_encrypt(__u8 *key, __u32 key_len, __u8 *src, __u8 *dst)
{
	struct aes_key local_key;
	int ret;

	ret = aes_set_encrypt_key(key, key_len << 0x3, &local_key);
	if (ret)
		return;

	aes_encrypt_(src, dst, &local_key);
}
