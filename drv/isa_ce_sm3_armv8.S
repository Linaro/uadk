/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2011-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../include/drv/arm_arch_ce.h"

.arch	armv8.2-a
.text
.globl	sm3_ce_block_compress
.type	sm3_ce_block_compress,%function
.align	5
sm3_ce_block_compress:
	AARCH64_VALID_CALL_TARGET
/* Loads state */
	/*
	 * Loads multiple single-element structures from memory(X0 register) and
	 * writes result to two SIMD&FP registers(v5.4s and v6.4s).
	 */
	ld1	{v5.4s,v6.4s}, [x0]  /* 4s -- 4 * 32bit */
	/*
	 * Reverses the order of 32-bit(type:s) elements in each doubleword of the
	 * vector in the src SIMD&FP register(v5), places the result into a vector
	 * and writes the vector to the dst SIDM&FP register(v5).
	 */
	rev64	v5.4s, v5.4s
	rev64	v6.4s, v6.4s
	/*
	 * Extracts the lowest vector elements from the second src SIMD&FP register,
	 * and highest vector elements from the first source SIMD&FP register,
	 * concatenates the result into a vector, and writes the vector to the
	 * dst SIMD&FP register vector. #8 means the numbered byte element to be extracted.
	 * Format: ext <dst register>, <first src register>, <second src register>, <index>
	 * #imm: immediate data.
	 */
	ext	v5.16b, v5.16b, v5.16b, #8 /* 16b -- 16 * 8bit */
	ext	v6.16b, v6.16b, v6.16b, #8
	/* From PC-relative address adds an immediate value to form a PC-relative
	 * address, and writes the result to the dst register.
	 */
	adr	x8, .Tj /* 'Tj' is the constant defined in SM3 protocol */
	/* Loads pair of register calculates an address from a base register value
	 * and an immediate offset, loads two 32-bit words from memory, and writes
	 * them to two registers. */
	ldp	s16, s17, [x8] /* 'sn' is the scalar register, 'vn' is the vector register */

.Loop:
/* Loads input */
	/*
	 * Loads multipule single-element structrue to four registers.
	 * #64 is the immediate offset variant, it is the post-index immediate offset.
	 * Loads the input src data, msg to be hashed.
	 */
	ld1	{v0.16b,v1.16b,v2.16b,v3.16b}, [x1], #64
	/*
	 * Substracts an optionally-shifted immediate value from a register value,
	 * and writes the result to the dst register.
	 */
	sub	w2, w2, #1

	/* Copies the value in a src register to the dst register. */
	mov	v18.16b, v5.16b
	mov	v19.16b, v6.16b

#ifndef __ARMEB__
	rev32	v0.16b, v0.16b
	rev32	v1.16b, v1.16b
	rev32	v2.16b, v2.16b
	rev32	v3.16b, v3.16b
#endif

	ext	v20.16b, v16.16b, v16.16b, #4
	/* s4 = w7  | w8  | w9  | w10 */
	ext	v4.16b, v1.16b, v2.16b, #12
	/* vtmp1 = w3  | w4  | w5  | w6 */
	ext	v22.16b, v0.16b, v1.16b, #12
	/* vtmp2 = w10 | w11 | w12 | w13 */
	ext	v23.16b, v2.16b, v3.16b, #8
	/* sm3partw1 v4.4s, v0.4s, v3.4s */
.inst	0xce63c004
	/* sm3partw2 v4.4s, v23.4s, v22.4s */
.inst	0xce76c6e4
	eor	v22.16b, v0.16b, v1.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5682e5
	/* sm3tt2a v6.4s, v23.4s, v0.4s[0] */
.inst	0xce408ae6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5692e5
	/* sm3tt2a v6.4s, v23.4s, v0.4s[1] */
.inst	0xce409ae6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a2e5
	/* sm3tt2a v6.4s, v23.4s, v0.4s[2] */
.inst	0xce40aae6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b2e5
	/* sm3tt2a v6.4s, v23.4s, v0.4s[3] */
.inst	0xce40bae6
	/* s4 = w7  | w8  | w9  | w10 */
	ext	v0.16b, v2.16b, v3.16b, #12
	/* vtmp1 = w3  | w4  | w5  | w6 */
	ext	v22.16b, v1.16b, v2.16b, #12
	/* vtmp2 = w10 | w11 | w12 | w13 */
	ext	v23.16b, v3.16b, v4.16b, #8
	/* sm3partw1 v0.4s, v1.4s, v4.4s */
.inst	0xce64c020
	/* sm3partw2 v0.4s, v23.4s, v22.4s */
.inst	0xce76c6e0
	eor	v22.16b, v1.16b, v2.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5682e5
	/* sm3tt2a v6.4s, v23.4s, v1.4s[0] */
.inst	0xce418ae6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5692e5
	/* sm3tt2a v6.4s, v23.4s, v1.4s[1] */
.inst	0xce419ae6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a2e5
	/* sm3tt2a v6.4s, v23.4s, v1.4s[2] */
.inst	0xce41aae6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b2e5
	/* sm3tt2a v6.4s, v23.4s, v1.4s[3] */
.inst	0xce41bae6
	/* s4 = w7  | w8  | w9  | w10 */
	ext	v1.16b, v3.16b, v4.16b, #12
	/* vtmp1 = w3  | w4  | w5  | w6 */
	ext	v22.16b, v2.16b, v3.16b, #12
	/* vtmp2 = w10 | w11 | w12 | w13 */
	ext	v23.16b, v4.16b, v0.16b, #8
	/* sm3partw1 v1.4s, v2.4s, v0.4s */
.inst	0xce60c041
	/* sm3partw2 v1.4s, v23.4s, v22.4s */
.inst	0xce76c6e1
	eor	v22.16b, v2.16b, v3.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5682e5
	/* sm3tt2a v6.4s, v23.4s, v2.4s[0] */
.inst	0xce428ae6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5692e5
	/* sm3tt2a v6.4s, v23.4s, v2.4s[1] */
.inst	0xce429ae6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a2e5
	/* sm3tt2a v6.4s, v23.4s, v2.4s[2] */
.inst	0xce42aae6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b2e5
	/* sm3tt2a v6.4s, v23.4s, v2.4s[3] */
.inst	0xce42bae6
	/* s4 = w7  | w8  | w9  | w10 */
	ext	v2.16b, v4.16b, v0.16b, #12
	/* vtmp1 = w3  | w4  | w5  | w6 */
	ext	v22.16b, v3.16b, v4.16b, #12
	/* vtmp2 = w10 | w11 | w12 | w13 */
	ext	v23.16b, v0.16b, v1.16b, #8
	/* sm3partw1 v2.4s, v3.4s, v1.4s */
.inst	0xce61c062
	/* sm3partw2 v2.4s, v23.4s, v22.4s */
.inst	0xce76c6e2
	eor	v22.16b, v3.16b, v4.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5682e5
	/* sm3tt2a v6.4s, v23.4s, v3.4s[0] */
.inst	0xce438ae6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5692e5
	/* sm3tt2a v6.4s, v23.4s, v3.4s[1] */
.inst	0xce439ae6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a2e5
	/* sm3tt2a v6.4s, v23.4s, v3.4s[2] */
.inst	0xce43aae6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1a v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b2e5
	/* sm3tt2a v6.4s, v23.4s, v3.4s[3] */
.inst	0xce43bae6
	ext	v20.16b, v17.16b, v17.16b, #4
	/* s4 = w7  | w8  | w9  | w10 */
	ext	v3.16b, v0.16b, v1.16b, #12
	/* vtmp1 = w3  | w4  | w5  | w6 */
	ext	v22.16b, v4.16b, v0.16b, #12
	/* vtmp2 = w10 | w11 | w12 | w13 */
	ext	v23.16b, v1.16b, v2.16b, #8
	/* sm3partw1 v3.4s, v4.4s, v2.4s */
.inst	0xce62c083
	/* sm3partw2 v3.4s, v23.4s, v22.4s */
.inst	0xce76c6e3
	eor	v22.16b, v4.16b, v0.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5686e5
	/* sm3tt2b v6.4s, v23.4s, v4.4s[0] */
.inst	0xce448ee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5696e5
	/* sm3tt2b v6.4s, v23.4s, v4.4s[1] */
.inst	0xce449ee6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a6e5
	/* sm3tt2b v6.4s, v23.4s, v4.4s[2] */
.inst	0xce44aee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b6e5
	/* sm3tt2b v6.4s, v23.4s, v4.4s[3] */
.inst	0xce44bee6
	/* s4 = w7  | w8  | w9  | w10 */
	ext	v4.16b, v1.16b, v2.16b, #12
	/* vtmp1 = w3  | w4  | w5  | w6 */
	ext	v22.16b, v0.16b, v1.16b, #12
	/* vtmp2 = w10 | w11 | w12 | w13 */
	ext	v23.16b, v2.16b, v3.16b, #8
	/* sm3partw1 v4.4s, v0.4s, v3.4s */
.inst	0xce63c004
	/* sm3partw2 v4.4s, v23.4s, v22.4s */
.inst	0xce76c6e4
	eor	v22.16b, v0.16b, v1.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5686e5
	/* sm3tt2b v6.4s, v23.4s, v0.4s[0] */
.inst	0xce408ee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5696e5
	/* sm3tt2b v6.4s, v23.4s, v0.4s[1] */
.inst	0xce409ee6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a6e5
	/* sm3tt2b v6.4s, v23.4s, v0.4s[2] */
.inst	0xce40aee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b6e5
	/* sm3tt2b v6.4s, v23.4s, v0.4s[3] */
.inst	0xce40bee6
	/* s4 = w7  | w8  | w9  | w10 */
	ext	v0.16b, v2.16b, v3.16b, #12
	/* vtmp1 = w3  | w4  | w5  | w6 */
	ext	v22.16b, v1.16b, v2.16b, #12
	/* vtmp2 = w10 | w11 | w12 | w13 */
	ext	v23.16b, v3.16b, v4.16b, #8
	/* sm3partw1 v0.4s, v1.4s, v4.4s */
.inst	0xce64c020
	/* sm3partw2 v0.4s, v23.4s, v22.4s */
.inst	0xce76c6e0
	eor	v22.16b, v1.16b, v2.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5686e5
	/* sm3tt2b v6.4s, v23.4s, v1.4s[0] */
.inst	0xce418ee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5696e5
	/* sm3tt2b v6.4s, v23.4s, v1.4s[1] */
.inst	0xce419ee6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a6e5
	/* sm3tt2b v6.4s, v23.4s, v1.4s[2] */
.inst	0xce41aee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b6e5
	/* sm3tt2b v6.4s, v23.4s, v1.4s[3] */
.inst	0xce41bee6
	/* s4 = w7  | w8  | w9  | w10 */
	ext	v1.16b, v3.16b, v4.16b, #12
	/* vtmp1 = w3  | w4  | w5  | w6 */
	ext	v22.16b, v2.16b, v3.16b, #12
	/* vtmp2 = w10 | w11 | w12 | w13 */
	ext	v23.16b, v4.16b, v0.16b, #8
	/* sm3partw1 v1.4s, v2.4s, v0.4s */
.inst	0xce60c041
	/* sm3partw2 v1.4s, v23.4s, v22.4s */
.inst	0xce76c6e1
	eor	v22.16b, v2.16b, v3.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5686e5
	/* sm3tt2b v6.4s, v23.4s, v2.4s[0] */
.inst	0xce428ee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5696e5
	/* sm3tt2b v6.4s, v23.4s, v2.4s[1] */
.inst	0xce429ee6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a6e5
	/* sm3tt2b v6.4s, v23.4s, v2.4s[2] */
.inst	0xce42aee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b6e5
	/* sm3tt2b v6.4s, v23.4s, v2.4s[3] */
.inst	0xce42bee6
	/* s4 = w7  | w8  | w9  | w10 */
	ext	v2.16b, v4.16b, v0.16b, #12
	/* vtmp1 = w3  | w4  | w5  | w6 */
	ext	v22.16b, v3.16b, v4.16b, #12
	/* vtmp2 = w10 | w11 | w12 | w13 */
	ext	v23.16b, v0.16b, v1.16b, #8
	/* sm3partw1 v2.4s, v3.4s, v1.4s */
.inst	0xce61c062
	/* sm3partw2 v2.4s, v23.4s, v22.4s */
.inst	0xce76c6e2
	eor	v22.16b, v3.16b, v4.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5686e5
	/* sm3tt2b v6.4s, v23.4s, v3.4s[0] */
.inst	0xce438ee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5696e5
	/* sm3tt2b v6.4s, v23.4s, v3.4s[1] */
.inst	0xce439ee6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a6e5
	/* sm3tt2b v6.4s, v23.4s, v3.4s[2] */
.inst	0xce43aee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b6e5
	/* sm3tt2b v6.4s, v23.4s, v3.4s[3] */
.inst	0xce43bee6
	/* s4 = w7  | w8  | w9  | w10 */
	ext	v3.16b, v0.16b, v1.16b, #12
	/* vtmp1 = w3  | w4  | w5  | w6 */
	ext	v22.16b, v4.16b, v0.16b, #12
	/* vtmp2 = w10 | w11 | w12 | w13 */
	ext	v23.16b, v1.16b, v2.16b, #8
	/* sm3partw1 v3.4s, v4.4s, v2.4s */
.inst	0xce62c083
	/* sm3partw2 v3.4s, v23.4s, v22.4s */
.inst	0xce76c6e3
	eor	v22.16b, v4.16b, v0.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5686e5
	/* sm3tt2b v6.4s, v23.4s, v4.4s[0] */
.inst	0xce448ee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5696e5
	/* sm3tt2b v6.4s, v23.4s, v4.4s[1] */
.inst	0xce449ee6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a6e5
	/* sm3tt2b v6.4s, v23.4s, v4.4s[2] */
.inst	0xce44aee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b6e5
	/* sm3tt2b v6.4s, v23.4s, v4.4s[3] */
.inst	0xce44bee6
	/* s4 = w7  | w8  | w9  | w10 */
	ext	v4.16b, v1.16b, v2.16b, #12
	/* vtmp1 = w3  | w4  | w5  | w6 */
	ext	v22.16b, v0.16b, v1.16b, #12
	/* vtmp2 = w10 | w11 | w12 | w13 */
	ext	v23.16b, v2.16b, v3.16b, #8
	/* sm3partw1 v4.4s, v0.4s, v3.4s */
.inst	0xce63c004
	/* sm3partw2 v4.4s, v23.4s, v22.4s */
.inst	0xce76c6e4
	eor	v22.16b, v0.16b, v1.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5686e5
	/* sm3tt2b v6.4s, v23.4s, v0.4s[0] */
.inst	0xce408ee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5696e5
	/* sm3tt2b v6.4s, v23.4s, v0.4s[1] */
.inst	0xce409ee6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a6e5
	/* sm3tt2b v6.4s, v23.4s, v0.4s[2] */
.inst	0xce40aee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b6e5
	/* sm3tt2b v6.4s, v23.4s, v0.4s[3] */
.inst	0xce40bee6
	/* s4 = w7  | w8  | w9  | w10 */
	ext	v0.16b, v2.16b, v3.16b, #12
	/* vtmp1 = w3  | w4  | w5  | w6 */
	ext	v22.16b, v1.16b, v2.16b, #12
	/* vtmp2 = w10 | w11 | w12 | w13 */
	ext	v23.16b, v3.16b, v4.16b, #8
	/* sm3partw1 v0.4s, v1.4s, v4.4s */
.inst	0xce64c020
	/* sm3partw2 v0.4s, v23.4s, v22.4s */
.inst	0xce76c6e0
	eor	v22.16b, v1.16b, v2.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5686e5
	/* sm3tt2b v6.4s, v23.4s, v1.4s[0] */
.inst	0xce418ee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5696e5
	/* sm3tt2b v6.4s, v23.4s, v1.4s[1] */
.inst	0xce419ee6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a6e5
	/* sm3tt2b v6.4s, v23.4s, v1.4s[2] */
.inst	0xce41aee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b6e5
	/* sm3tt2b v6.4s, v23.4s, v1.4s[3] */
.inst	0xce41bee6
	/* s4 = w7  | w8  | w9  | w10 */
	ext	v1.16b, v3.16b, v4.16b, #12
	/* vtmp1 = w3  | w4  | w5  | w6 */
	ext	v22.16b, v2.16b, v3.16b, #12
	/* vtmp2 = w10 | w11 | w12 | w13 */
	ext	v23.16b, v4.16b, v0.16b, #8
	/* sm3partw1 v1.4s, v2.4s, v0.4s */
.inst	0xce60c041
	/* sm3partw2 v1.4s, v23.4s, v22.4s */
.inst	0xce76c6e1
	eor	v22.16b, v2.16b, v3.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5686e5
	/* sm3tt2b v6.4s, v23.4s, v2.4s[0] */
.inst	0xce428ee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5696e5
	/* sm3tt2b v6.4s, v23.4s, v2.4s[1] */
.inst	0xce429ee6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a6e5
	/* sm3tt2b v6.4s, v23.4s, v2.4s[2] */
.inst	0xce42aee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b6e5
	/* sm3tt2b v6.4s, v23.4s, v2.4s[3] */
.inst	0xce42bee6
	eor	v22.16b, v3.16b, v4.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5686e5
	/* sm3tt2b v6.4s, v23.4s, v3.4s[0] */
.inst	0xce438ee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5696e5
	/* sm3tt2b v6.4s, v23.4s, v3.4s[1] */
.inst	0xce439ee6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a6e5
	/* sm3tt2b v6.4s, v23.4s, v3.4s[2] */
.inst	0xce43aee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b6e5
	/* sm3tt2b v6.4s, v23.4s, v3.4s[3] */
.inst	0xce43bee6
	eor	v22.16b, v4.16b, v0.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5686e5
	/* sm3tt2b v6.4s, v23.4s, v4.4s[0] */
.inst	0xce448ee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5696e5
	/* sm3tt2b v6.4s, v23.4s, v4.4s[1] */
.inst	0xce449ee6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a6e5
	/* sm3tt2b v6.4s, v23.4s, v4.4s[2] */
.inst	0xce44aee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b6e5
	/* sm3tt2b v6.4s, v23.4s, v4.4s[3] */
.inst	0xce44bee6
	eor	v22.16b, v0.16b, v1.16b
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[0] */
.inst	0xce5686e5
	/* sm3tt2b v6.4s, v23.4s, v0.4s[0] */
.inst	0xce408ee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[1] */
.inst	0xce5696e5
	/* sm3tt2b v6.4s, v23.4s, v0.4s[1] */
.inst	0xce409ee6
	/* sm3ss1 v23.4s, v5.4s, v20.4s, v6.4s */
.inst	0xce5418b7
	shl	v21.4s, v20.4s, #1
	sri	v21.4s, v20.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[2] */
.inst	0xce56a6e5
	/* sm3tt2b v6.4s, v23.4s, v0.4s[2] */
.inst	0xce40aee6
	/* sm3ss1 v23.4s, v5.4s, v21.4s, v6.4s */
.inst	0xce5518b7
	shl	v20.4s, v21.4s, #1
	sri	v20.4s, v21.4s, #31
	/* sm3tt1b v5.4s, v23.4s, v22.4s[3] */
.inst	0xce56b6e5
	/* sm3tt2b v6.4s, v23.4s, v0.4s[3] */
.inst	0xce40bee6
	eor	v5.16b, v5.16b, v18.16b
	eor	v6.16b, v6.16b, v19.16b
	/*
	 * cbnz: compare and branch on Nonzero, compares the value in a register
	 * with zero, and conditionally branches to a label at a PC-relative offset
	 * if the comparison is not equal.
	 * 'w2' is the 32-bit name of the general-purpose register to be tested.
	 * '.Loop' is the program label to be conditionally branched to.
	 */
	cbnz	w2, .Loop

	/* save state, it is the result of one cycle */
	rev64	v5.4s, v5.4s
	rev64	v6.4s, v6.4s
	ext	v5.16b, v5.16b, v5.16b, #8
	ext	v6.16b, v6.16b, v6.16b, #8
	st1	{v5.4s,v6.4s}, [x0]
	ret
.size	sm3_ce_block_compress,.-sm3_ce_block_compress

.align	3
.Tj:
/*
 * Inserts a list of 32-bit values as data into the assembly.
 * In SM3 protocol:
 * 	when 0 <= j <= 15, Tj = 0x79cc4519,
 * 	when 16 <= j <= 63, Tj = 0x9d8a7a87.
 */
.word	0x79cc4519, 0x9d8a7a87
