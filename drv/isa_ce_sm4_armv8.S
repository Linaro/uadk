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

.arch	armv8-a+crypto

.irp b, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, \
		16, 17, 18, 19, 20, 21, 22, 23 24, 25, 26, 27, 28, 29, 30, 31
	.set .Lv\b\().4s, \b
.endr

.macro sm4e, vd, vn
	.inst 0xcec08400 | (.L\vn << 5) | .L\vd
.endm

.macro sm4ekey, vd, vn, vm
	.inst 0xce60c800 | (.L\vm << 16) | (.L\vn << 5) | .L\vd
.endm

.text
.align	6
.Lck:
.long	0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269
.long	0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9
.long	0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249
.long	0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9
.long	0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229
.long	0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299
.long	0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209
.long	0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
.Lfk:
.long	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
.align 4
.cts_permute_table:
.byte	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
.byte	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
.byte	0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7
.byte	0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf
.byte	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
.byte	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
.globl	sm4_v8_set_encrypt_key
.type	sm4_v8_set_encrypt_key,%function
.align	5
sm4_v8_set_encrypt_key:
	AARCH64_VALID_CALL_TARGET
	ld1	{v0.4s},[x0]
	adr	x2,.Lfk
	ld1	{v24.4s},[x2]
	adr	x2,.Lck
	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[x2],64
#ifndef __ARMEB__
	rev32	v0.16b,v0.16b
#endif
	ld1	{v20.4s,v21.4s,v22.4s,v23.4s},[x2]
	eor	v0.16b,v0.16b,v24.16b;
	sm4ekey	v0.4s,v0.4s,v16.4s;
	sm4ekey	v1.4s,v0.4s,v17.4s;
	sm4ekey	v2.4s,v1.4s,v18.4s;
	sm4ekey	v3.4s,v2.4s,v19.4s;
	sm4ekey	v4.4s,v3.4s,v20.4s;
	st1	{v0.4s,v1.4s,v2.4s,v3.4s},[x1],64
	sm4ekey	v5.4s,v4.4s,v21.4s;
	sm4ekey	v6.4s,v5.4s,v22.4s;
	sm4ekey	v7.4s,v6.4s,v23.4s;
	st1	{v4.4s,v5.4s,v6.4s,v7.4s},[x1]
	ret
.size	sm4_v8_set_encrypt_key,.-sm4_v8_set_encrypt_key
.globl	sm4_v8_set_decrypt_key
.type	sm4_v8_set_decrypt_key,%function
.align	5
sm4_v8_set_decrypt_key:
	AARCH64_VALID_CALL_TARGET
	ld1	{v7.4s},[x0]
	adr	x2,.Lfk
	ld1	{v24.4s},[x2]
	adr	x2, .Lck
	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[x2],64
#ifndef __ARMEB__
	rev32	v7.16b,v7.16b
#endif
	ld1	{v20.4s,v21.4s,v22.4s,v23.4s},[x2]
	eor	v7.16b, v7.16b,v24.16b;
	sm4ekey	v7.4s,v7.4s,v16.4s;
	sm4ekey	v6.4s,v7.4s,v17.4s;
	sm4ekey	v5.4s,v6.4s,v18.4s;
	rev64	v7.4s,v7.4s
	rev64	v6.4s,v6.4s
	ext	v7.16b,v7.16b,v7.16b,#8
	ext	v6.16b,v6.16b,v6.16b,#8
	sm4ekey	v4.4s,v5.4s,v19.4s;
	sm4ekey	v3.4s,v4.4s,v20.4s;
	rev64	v5.4s,v5.4s
	rev64	v4.4s,v4.4s
	ext	v5.16b,v5.16b,v5.16b,#8
	ext	v4.16b,v4.16b,v4.16b,#8
	sm4ekey	v2.4s,v3.4s,v21.4s;
	sm4ekey	v1.4s,v2.4s,v22.4s;
	rev64	v3.4s,v3.4s
	rev64	v2.4s,v2.4s
	ext	v3.16b,v3.16b,v3.16b,#8
	ext	v2.16b,v2.16b,v2.16b,#8
	sm4ekey	v0.4s,v1.4s,v23.4s;
	rev64	v1.4s, v1.4s
	rev64	v0.4s, v0.4s
	ext	v1.16b,v1.16b,v1.16b,#8
	ext	v0.16b,v0.16b,v0.16b,#8
	st1	{v0.4s,v1.4s,v2.4s,v3.4s},[x1],64
	st1	{v4.4s,v5.4s,v6.4s,v7.4s},[x1]
	ret
.size	sm4_v8_set_decrypt_key,.-sm4_v8_set_decrypt_key
.globl	sm4_v8_cbc_encrypt
.type	sm4_v8_cbc_encrypt,%function
.align	5
sm4_v8_cbc_encrypt:
	AARCH64_VALID_CALL_TARGET
	stp	d8,d9,[sp, #-16]!

	ld1	{v0.4s,v1.4s,v2.4s,v3.4s},[x3],#64
	ld1	{v4.4s,v5.4s,v6.4s,v7.4s},[x3]
	ld1	{v8.4s},[x4]
	cmp	w5,#0
	b.eq	.Ldec
1:
	cmp	x2, #64
	b.lt	1f
	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[x0],#64
	eor	v16.16b,v16.16b,v8.16b
#ifndef __ARMEB__
	rev32	v17.16b,v17.16b
#endif
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
#ifndef __ARMEB__
	rev32	v18.16b,v18.16b
#endif
#ifndef __ARMEB__
	rev32	v19.16b,v19.16b
#endif
	sm4e	v16.4s,v0.4s;
	sm4e	v16.4s,v1.4s;
	sm4e	v16.4s,v2.4s;
	sm4e	v16.4s,v3.4s;
	sm4e	v16.4s,v4.4s;
	sm4e	v16.4s,v5.4s;
	sm4e	v16.4s,v6.4s;
	sm4e	v16.4s,v7.4s;
	rev64	v16.4s,v16.4s
	ext	v16.16b,v16.16b,v16.16b,#8
	eor	v17.16b,v17.16b,v16.16b
	sm4e	v17.4s,v0.4s;
	sm4e	v17.4s,v1.4s;
	sm4e	v17.4s,v2.4s;
	sm4e	v17.4s,v3.4s;
	sm4e	v17.4s,v4.4s;
	sm4e	v17.4s,v5.4s;
	sm4e	v17.4s,v6.4s;
	sm4e	v17.4s,v7.4s;
	rev64	v17.4s,v17.4s
	ext	v17.16b,v17.16b,v17.16b,#8
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
	eor	v18.16b,v18.16b,v17.16b
	sm4e	v18.4s,v0.4s;
	sm4e	v18.4s,v1.4s;
	sm4e	v18.4s,v2.4s;
	sm4e	v18.4s,v3.4s;
	sm4e	v18.4s,v4.4s;
	sm4e	v18.4s,v5.4s;
	sm4e	v18.4s,v6.4s;
	sm4e	v18.4s,v7.4s;
	rev64	v18.4s,v18.4s
	ext	v18.16b,v18.16b,v18.16b,#8
#ifndef __ARMEB__
	rev32	v17.16b,v17.16b
#endif
	eor	v19.16b,v19.16b,v18.16b
	sm4e	v19.4s,v0.4s;
	sm4e	v19.4s,v1.4s;
	sm4e	v19.4s,v2.4s;
	sm4e	v19.4s,v3.4s;
	sm4e	v19.4s,v4.4s;
	sm4e	v19.4s,v5.4s;
	sm4e	v19.4s,v6.4s;
	sm4e	v19.4s,v7.4s;
	rev64	v19.4s,v19.4s
	ext	v19.16b,v19.16b,v19.16b,#8
#ifndef __ARMEB__
	rev32	v18.16b,v18.16b
#endif
#ifndef __ARMEB__
	rev32	v19.16b,v19.16b
#endif
	mov	v8.16b,v19.16b
	st1	{v16.4s,v17.4s,v18.4s,v19.4s},[x1],#64
	subs	x2,x2,#64
	b.ne	1b
1:
	subs	x2,x2,#16
	b.lt	3f
	ld1	{v16.4s},[x0],#16
	eor	v8.16b,v8.16b,v16.16b
#ifndef __ARMEB__
	rev32	v8.16b,v8.16b
#endif
	sm4e	v8.4s,v0.4s;
	sm4e	v8.4s,v1.4s;
	sm4e	v8.4s,v2.4s;
	sm4e	v8.4s,v3.4s;
	sm4e	v8.4s,v4.4s;
	sm4e	v8.4s,v5.4s;
	sm4e	v8.4s,v6.4s;
	sm4e	v8.4s,v7.4s;
	rev64	v8.4s,v8.4s
	ext	v8.16b,v8.16b,v8.16b,#8
#ifndef __ARMEB__
	rev32	v8.16b,v8.16b
#endif
	st1	{v8.16b},[x1],#16
	b.ne	1b
	b	3f
.Ldec:
1:
	cmp	x2, #64
	b.lt	1f
	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[x0]
	ld1	{v24.4s,v25.4s,v26.4s,v27.4s},[x0],#64
	cmp	x2,#128
	b.lt	2f
	// 8 blocks mode
	ld1	{v20.4s,v21.4s,v22.4s,v23.4s},[x0]
	ld1	{v28.4s,v29.4s,v30.4s,v31.4s},[x0],#64
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
#ifndef __ARMEB__
	rev32	v17.16b,v17.16b
#endif
#ifndef __ARMEB__
	rev32	v18.16b,v18.16b
#endif
#ifndef __ARMEB__
	rev32	v19.16b,v19.16b
#endif
#ifndef __ARMEB__
	rev32	v20.16b,v20.16b
#endif
#ifndef __ARMEB__
	rev32	v21.16b,v21.16b
#endif
#ifndef __ARMEB__
	rev32	v22.16b,v22.16b
#endif
#ifndef __ARMEB__
	rev32	v23.16b,v23.16b
#endif
	sm4e	v16.4s,v0.4s;
	sm4e	v17.4s,v0.4s;
	sm4e	v18.4s,v0.4s;
	sm4e	v19.4s,v0.4s;

	sm4e	v16.4s,v1.4s;
	sm4e	v17.4s,v1.4s;
	sm4e	v18.4s,v1.4s;
	sm4e	v19.4s,v1.4s;

	sm4e	v16.4s,v2.4s;
	sm4e	v17.4s,v2.4s;
	sm4e	v18.4s,v2.4s;
	sm4e	v19.4s,v2.4s;

	sm4e	v16.4s,v3.4s;
	sm4e	v17.4s,v3.4s;
	sm4e	v18.4s,v3.4s;
	sm4e	v19.4s,v3.4s;

	sm4e	v16.4s,v4.4s;
	sm4e	v17.4s,v4.4s;
	sm4e	v18.4s,v4.4s;
	sm4e	v19.4s,v4.4s;

	sm4e	v16.4s,v5.4s;
	sm4e	v17.4s,v5.4s;
	sm4e	v18.4s,v5.4s;
	sm4e	v19.4s,v5.4s;

	sm4e	v16.4s,v6.4s;
	sm4e	v17.4s,v6.4s;
	sm4e	v18.4s,v6.4s;
	sm4e	v19.4s,v6.4s;

	sm4e	v16.4s,v7.4s;
	rev64	v16.4s,v16.4s
	sm4e	v17.4s,v7.4s;
	ext	v16.16b,v16.16b,v16.16b,#8
	rev64	v17.4s,v17.4s
	sm4e	v18.4s,v7.4s;
	ext	v17.16b,v17.16b,v17.16b,#8
	rev64	v18.4s,v18.4s
	sm4e	v19.4s,v7.4s;
	ext	v18.16b,v18.16b,v18.16b,#8
	rev64	v19.4s,v19.4s
	ext	v19.16b,v19.16b,v19.16b,#8
	sm4e	v20.4s,v0.4s;
	sm4e	v21.4s,v0.4s;
	sm4e	v22.4s,v0.4s;
	sm4e	v23.4s,v0.4s;

	sm4e	v20.4s,v1.4s;
	sm4e	v21.4s,v1.4s;
	sm4e	v22.4s,v1.4s;
	sm4e	v23.4s,v1.4s;

	sm4e	v20.4s,v2.4s;
	sm4e	v21.4s,v2.4s;
	sm4e	v22.4s,v2.4s;
	sm4e	v23.4s,v2.4s;

	sm4e	v20.4s,v3.4s;
	sm4e	v21.4s,v3.4s;
	sm4e	v22.4s,v3.4s;
	sm4e	v23.4s,v3.4s;

	sm4e	v20.4s,v4.4s;
	sm4e	v21.4s,v4.4s;
	sm4e	v22.4s,v4.4s;
	sm4e	v23.4s,v4.4s;

	sm4e	v20.4s,v5.4s;
	sm4e	v21.4s,v5.4s;
	sm4e	v22.4s,v5.4s;
	sm4e	v23.4s,v5.4s;

	sm4e	v20.4s,v6.4s;
	sm4e	v21.4s,v6.4s;
	sm4e	v22.4s,v6.4s;
	sm4e	v23.4s,v6.4s;

	sm4e	v20.4s,v7.4s;
	rev64	v20.4s,v20.4s
	sm4e	v21.4s,v7.4s;
	ext	v20.16b,v20.16b,v20.16b,#8
	rev64	v21.4s,v21.4s
	sm4e	v22.4s,v7.4s;
	ext	v21.16b,v21.16b,v21.16b,#8
	rev64	v22.4s,v22.4s
	sm4e	v23.4s,v7.4s;
	ext	v22.16b,v22.16b,v22.16b,#8
	rev64	v23.4s,v23.4s
	ext	v23.16b,v23.16b,v23.16b,#8
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
#ifndef __ARMEB__
	rev32	v17.16b,v17.16b
#endif
#ifndef __ARMEB__
	rev32	v18.16b,v18.16b
#endif
#ifndef __ARMEB__
	rev32	v19.16b,v19.16b
#endif
#ifndef __ARMEB__
	rev32	v20.16b,v20.16b
#endif
#ifndef __ARMEB__
	rev32	v21.16b,v21.16b
#endif
#ifndef __ARMEB__
	rev32	v22.16b,v22.16b
#endif
#ifndef __ARMEB__
	rev32	v23.16b,v23.16b
#endif
	eor	v16.16b,v16.16b,v8.16b
	eor	v17.16b,v17.16b,v24.16b
	eor	v18.16b,v18.16b,v25.16b
	mov	v8.16b,v31.16b
	eor	v19.16b,v19.16b,v26.16b
	eor	v20.16b,v20.16b,v27.16b
	eor	v21.16b,v21.16b,v28.16b
	eor	v22.16b,v22.16b,v29.16b
	eor	v23.16b,v23.16b,v30.16b
	st1	{v16.4s,v17.4s,v18.4s,v19.4s},[x1],#64
	st1	{v20.4s,v21.4s,v22.4s,v23.4s},[x1],#64
	subs	x2,x2,128
	b.gt	1b
	b	3f
	// 4 blocks mode
2:
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
#ifndef __ARMEB__
	rev32	v17.16b,v17.16b
#endif
#ifndef __ARMEB__
	rev32	v18.16b,v18.16b
#endif
#ifndef __ARMEB__
	rev32	v19.16b,v19.16b
#endif
	sm4e	v16.4s,v0.4s;
	sm4e	v17.4s,v0.4s;
	sm4e	v18.4s,v0.4s;
	sm4e	v19.4s,v0.4s;

	sm4e	v16.4s,v1.4s;
	sm4e	v17.4s,v1.4s;
	sm4e	v18.4s,v1.4s;
	sm4e	v19.4s,v1.4s;

	sm4e	v16.4s,v2.4s;
	sm4e	v17.4s,v2.4s;
	sm4e	v18.4s,v2.4s;
	sm4e	v19.4s,v2.4s;

	sm4e	v16.4s,v3.4s;
	sm4e	v17.4s,v3.4s;
	sm4e	v18.4s,v3.4s;
	sm4e	v19.4s,v3.4s;

	sm4e	v16.4s,v4.4s;
	sm4e	v17.4s,v4.4s;
	sm4e	v18.4s,v4.4s;
	sm4e	v19.4s,v4.4s;

	sm4e	v16.4s,v5.4s;
	sm4e	v17.4s,v5.4s;
	sm4e	v18.4s,v5.4s;
	sm4e	v19.4s,v5.4s;

	sm4e	v16.4s,v6.4s;
	sm4e	v17.4s,v6.4s;
	sm4e	v18.4s,v6.4s;
	sm4e	v19.4s,v6.4s;

	sm4e	v16.4s,v7.4s;
	rev64	v16.4s,v16.4s
	sm4e	v17.4s,v7.4s;
	ext	v16.16b,v16.16b,v16.16b,#8
	rev64	v17.4s,v17.4s
	sm4e	v18.4s,v7.4s;
	ext	v17.16b,v17.16b,v17.16b,#8
	rev64	v18.4s,v18.4s
	sm4e	v19.4s,v7.4s;
	ext	v18.16b,v18.16b,v18.16b,#8
	rev64	v19.4s,v19.4s
	ext	v19.16b,v19.16b,v19.16b,#8
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
#ifndef __ARMEB__
	rev32	v17.16b,v17.16b
#endif
#ifndef __ARMEB__
	rev32	v18.16b,v18.16b
#endif
#ifndef __ARMEB__
	rev32	v19.16b,v19.16b
#endif
	eor	v16.16b,v16.16b,v8.16b
	eor	v17.16b,v17.16b,v24.16b
	mov	v8.16b,v27.16b
	eor	v18.16b,v18.16b,v25.16b
	eor	v19.16b,v19.16b,v26.16b
	st1	{v16.4s,v17.4s,v18.4s,v19.4s},[x1],#64
	subs	x2,x2,#64
	b.gt	1b
1:
	subs	x2,x2,#16
	b.lt	3f
	ld1	{v16.4s},[x0],#16
	mov	v24.16b,v16.16b
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
	sm4e	v16.4s,v0.4s;
	sm4e	v16.4s,v1.4s;
	sm4e	v16.4s,v2.4s;
	sm4e	v16.4s,v3.4s;
	sm4e	v16.4s,v4.4s;
	sm4e	v16.4s,v5.4s;
	sm4e	v16.4s,v6.4s;
	sm4e	v16.4s,v7.4s;
	rev64	v16.4s,v16.4s
	ext	v16.16b,v16.16b,v16.16b,#8
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
	eor	v16.16b,v16.16b,v8.16b
	mov	v8.16b,v24.16b
	st1	{v16.16b},[x1],#16
	b.ne	1b
3:
	// save back IV
	st1	{v8.16b},[x4]
	ldp	d8,d9,[sp],#16
	ret
.size	sm4_v8_cbc_encrypt,.-sm4_v8_cbc_encrypt

.globl	sm4_v8_cbc_cts_encrypt
.type	sm4_v8_cbc_cts_encrypt,%function
.align	5
sm4_v8_cbc_cts_encrypt:
	AARCH64_VALID_CALL_TARGET
	ld1	{v0.4s,v1.4s,v2.4s,v3.4s}, [x3], #64
	ld1	{v4.4s,v5.4s,v6.4s,v7.4s}, [x3]
	sub	x5, x2, #16

	ld1	{v8.4s}, [x4]

	ld1	{v10.4s}, [x0]
	eor	v8.16b, v8.16b, v10.16b
	rev32	v8.16b, v8.16b;
	sm4e	v8.4s, v0.4s;
	sm4e	v8.4s, v1.4s;
	sm4e	v8.4s, v2.4s;
	sm4e	v8.4s, v3.4s;
	sm4e	v8.4s, v4.4s;
	sm4e	v8.4s, v5.4s;
	sm4e	v8.4s, v6.4s;
	sm4e	v8.4s, v7.4s;
	rev64	v8.4s, v8.4s;
	ext	v8.16b, v8.16b, v8.16b, #8;
	rev32	v8.16b, v8.16b;

	/* load permute table */
	adr	x6, .cts_permute_table
	add	x7, x6, #32
	add	x6, x6, x5
	sub	x7, x7, x5
	ld1	{v13.4s}, [x6]
	ld1	{v14.4s}, [x7]

	/* overlapping loads */
	add	x0, x0, x5
	ld1	{v11.4s}, [x0]

	/* create Cn from En-1 */
	tbl	v10.16b, {v8.16b}, v13.16b
	/* padding Pn with zeros */
	tbl	v11.16b, {v11.16b}, v14.16b

	eor	v11.16b, v11.16b, v8.16b
	rev32	v11.16b, v11.16b;
	sm4e	v11.4s, v0.4s;
	sm4e	v11.4s, v1.4s;
	sm4e	v11.4s, v2.4s;
	sm4e	v11.4s, v3.4s;
	sm4e	v11.4s, v4.4s;
	sm4e	v11.4s, v5.4s;
	sm4e	v11.4s, v6.4s;
	sm4e	v11.4s, v7.4s;
	rev64	v11.4s, v11.4s;
	ext	v11.16b, v11.16b, v11.16b, #8;
	rev32	v11.16b, v11.16b;

	/* overlapping stores */
	add	x5, x1, x5
	st1	{v10.16b}, [x5]
	st1	{v11.16b}, [x1]

	ret
.size	sm4_v8_cbc_cts_encrypt,.-sm4_v8_cbc_cts_encrypt

.globl	sm4_v8_cbc_cts_decrypt
.type	sm4_v8_cbc_cts_decrypt,%function
.align	5
sm4_v8_cbc_cts_decrypt:
	AARCH64_VALID_CALL_TARGET
	ld1	{v0.4s,v1.4s,v2.4s,v3.4s}, [x3], #64
	ld1	{v4.4s,v5.4s,v6.4s,v7.4s}, [x3]

	sub	x5, x2, #16

	ld1	{v8.4s}, [x4]

	/* load permute table */
	adr	x6, .cts_permute_table
	add	x7, x6, #32
	add	x6, x6, x5
	sub	x7, x7, x5
	ld1	{v13.4s}, [x6]
	ld1	{v14.4s}, [x7]

	/* overlapping loads */
	ld1	{v10.16b}, [x0], x5
	ld1	{v11.16b}, [x0]

	rev32	v10.16b, v10.16b;
	sm4e	v10.4s, v0.4s;
	sm4e	v10.4s, v1.4s;
	sm4e	v10.4s, v2.4s;
	sm4e	v10.4s, v3.4s;
	sm4e	v10.4s, v4.4s;
	sm4e	v10.4s, v5.4s;
	sm4e	v10.4s, v6.4s;
	sm4e	v10.4s, v7.4s;
	rev64	v10.4s, v10.4s;
	ext	v10.16b, v10.16b, v10.16b, #8;
	rev32	v10.16b, v10.16b;

	/* select the first Ln bytes of Xn to create Pn */
	tbl	v12.16b, {v10.16b}, v13.16b
	eor	v12.16b, v12.16b, v11.16b

	/* overwrite the first Ln bytes with Cn to create En-1 */
	tbx	v10.16b, {v11.16b}, v14.16b

	rev32	v10.16b, v10.16b;
	sm4e	v10.4s, v0.4s;
	sm4e	v10.4s, v1.4s;
	sm4e	v10.4s, v2.4s;
	sm4e	v10.4s, v3.4s;
	sm4e	v10.4s, v4.4s;
	sm4e	v10.4s, v5.4s;
	sm4e	v10.4s, v6.4s;
	sm4e	v10.4s, v7.4s;
	rev64	v10.4s, v10.4s;
	ext	v10.16b, v10.16b, v10.16b, #8;
	rev32	v10.16b, v10.16b;

	eor	v10.16b, v10.16b, v8.16b

	/* overlapping stores */
	add	x5, x1, x5
	st1	{v12.16b}, [x5]
	st1	{v10.16b}, [x1]

	ret
.size	sm4_v8_cbc_cts_decrypt,.-sm4_v8_cbc_cts_decrypt

.globl	sm4_v8_ecb_encrypt
.type	sm4_v8_ecb_encrypt,%function
.align	5
sm4_v8_ecb_encrypt:
	AARCH64_VALID_CALL_TARGET
	ld1	{v0.4s,v1.4s,v2.4s,v3.4s},[x3],#64
	ld1	{v4.4s,v5.4s,v6.4s,v7.4s},[x3]
1:
	cmp	x2,#64
	b.lt	1f
	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[x0],#64
	cmp	x2,#128
	b.lt	2f
	ld1	{v20.4s,v21.4s,v22.4s,v23.4s},[x0],#64
	// 8 blocks
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
#ifndef __ARMEB__
	rev32	v17.16b,v17.16b
#endif
#ifndef __ARMEB__
	rev32	v18.16b,v18.16b
#endif
#ifndef __ARMEB__
	rev32	v19.16b,v19.16b
#endif
#ifndef __ARMEB__
	rev32	v20.16b,v20.16b
#endif
#ifndef __ARMEB__
	rev32	v21.16b,v21.16b
#endif
#ifndef __ARMEB__
	rev32	v22.16b,v22.16b
#endif
#ifndef __ARMEB__
	rev32	v23.16b,v23.16b
#endif
	sm4e v16.4s,v0.4s;
	sm4e v17.4s,v0.4s;
	sm4e v18.4s,v0.4s;
	sm4e v19.4s,v0.4s;

	sm4e v16.4s,v1.4s;
	sm4e v17.4s,v1.4s;
	sm4e v18.4s,v1.4s;
	sm4e v19.4s,v1.4s;

	sm4e v16.4s,v2.4s;
	sm4e v17.4s,v2.4s;
	sm4e v18.4s,v2.4s;
	sm4e v19.4s,v2.4s;

	sm4e v16.4s,v3.4s;
	sm4e v17.4s,v3.4s;
	sm4e v18.4s,v3.4s;
	sm4e v19.4s,v3.4s;

	sm4e v16.4s,v4.4s;
	sm4e v17.4s,v4.4s;
	sm4e v18.4s,v4.4s;
	sm4e v19.4s,v4.4s;

	sm4e v16.4s,v5.4s;
	sm4e v17.4s,v5.4s;
	sm4e v18.4s,v5.4s;
	sm4e v19.4s,v5.4s;

	sm4e v16.4s,v6.4s;
	sm4e v17.4s,v6.4s;
	sm4e v18.4s,v6.4s;
	sm4e v19.4s,v6.4s;

	sm4e v16.4s,v7.4s;
	rev64	v16.4S,v16.4S
	sm4e v17.4s,v7.4s;
	ext	v16.16b,v16.16b,v16.16b,#8
	rev64	v17.4S,v17.4S
	sm4e v18.4s,v7.4s;
	ext	v17.16b,v17.16b,v17.16b,#8
	rev64	v18.4S,v18.4S
	sm4e v19.4s,v7.4s;
	ext	v18.16b,v18.16b,v18.16b,#8
	rev64	v19.4S,v19.4S
	ext	v19.16b,v19.16b,v19.16b,#8
	sm4e v20.4s,v0.4s;
	sm4e v21.4s,v0.4s;
	sm4e v22.4s,v0.4s;
	sm4e v23.4s,v0.4s;

	sm4e v20.4s,v1.4s;
	sm4e v21.4s,v1.4s;
	sm4e v22.4s,v1.4s;
	sm4e v23.4s,v1.4s;

	sm4e v20.4s,v2.4s;
	sm4e v21.4s,v2.4s;
	sm4e v22.4s,v2.4s;
	sm4e v23.4s,v2.4s;

	sm4e v20.4s,v3.4s;
	sm4e v21.4s,v3.4s;
	sm4e v22.4s,v3.4s;
	sm4e v23.4s,v3.4s;

	sm4e v20.4s,v4.4s;
	sm4e v21.4s,v4.4s;
	sm4e v22.4s,v4.4s;
	sm4e v23.4s,v4.4s;

	sm4e v20.4s,v5.4s;
	sm4e v21.4s,v5.4s;
	sm4e v22.4s,v5.4s;
	sm4e v23.4s,v5.4s;

	sm4e v20.4s,v6.4s;
	sm4e v21.4s,v6.4s;
	sm4e v22.4s,v6.4s;
	sm4e v23.4s,v6.4s;

	sm4e v20.4s,v7.4s;
	rev64	v20.4S,v20.4S
	sm4e v21.4s,v7.4s;
	ext	v20.16b,v20.16b,v20.16b,#8
	rev64	v21.4S,v21.4S
	sm4e v22.4s,v7.4s;
	ext	v21.16b,v21.16b,v21.16b,#8
	rev64	v22.4S,v22.4S
	sm4e v23.4s,v7.4s;
	ext	v22.16b,v22.16b,v22.16b,#8
	rev64	v23.4S,v23.4S
	ext	v23.16b,v23.16b,v23.16b,#8
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
#ifndef __ARMEB__
	rev32	v17.16b,v17.16b
#endif
#ifndef __ARMEB__
	rev32	v18.16b,v18.16b
#endif
#ifndef __ARMEB__
	rev32	v19.16b,v19.16b
#endif
#ifndef __ARMEB__
	rev32	v20.16b,v20.16b
#endif
#ifndef __ARMEB__
	rev32	v21.16b,v21.16b
#endif
	st1	{v16.4s,v17.4s,v18.4s,v19.4s},[x1],#64
#ifndef __ARMEB__
	rev32	v22.16b,v22.16b
#endif
#ifndef __ARMEB__
	rev32	v23.16b,v23.16b
#endif
	st1	{v20.4s,v21.4s,v22.4s,v23.4s},[x1],#64
	subs	x2,x2,#128
	b.gt	1b
	ret
	// 4 blocks
2:
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
#ifndef __ARMEB__
	rev32	v17.16b,v17.16b
#endif
#ifndef __ARMEB__
	rev32	v18.16b,v18.16b
#endif
#ifndef __ARMEB__
	rev32	v19.16b,v19.16b
#endif
	sm4e v16.4s,v0.4s;
	sm4e v17.4s,v0.4s;
	sm4e v18.4s,v0.4s;
	sm4e v19.4s,v0.4s;

	sm4e v16.4s,v1.4s;
	sm4e v17.4s,v1.4s;
	sm4e v18.4s,v1.4s;
	sm4e v19.4s,v1.4s;

	sm4e v16.4s,v2.4s;
	sm4e v17.4s,v2.4s;
	sm4e v18.4s,v2.4s;
	sm4e v19.4s,v2.4s;

	sm4e v16.4s,v3.4s;
	sm4e v17.4s,v3.4s;
	sm4e v18.4s,v3.4s;
	sm4e v19.4s,v3.4s;

	sm4e v16.4s,v4.4s;
	sm4e v17.4s,v4.4s;
	sm4e v18.4s,v4.4s;
	sm4e v19.4s,v4.4s;

	sm4e v16.4s,v5.4s;
	sm4e v17.4s,v5.4s;
	sm4e v18.4s,v5.4s;
	sm4e v19.4s,v5.4s;

	sm4e v16.4s,v6.4s;
	sm4e v17.4s,v6.4s;
	sm4e v18.4s,v6.4s;
	sm4e v19.4s,v6.4s;

	sm4e v16.4s,v7.4s;
	rev64	v16.4S,v16.4S
	sm4e v17.4s,v7.4s;
	ext	v16.16b,v16.16b,v16.16b,#8
	rev64	v17.4S,v17.4S
	sm4e v18.4s,v7.4s;
	ext	v17.16b,v17.16b,v17.16b,#8
	rev64	v18.4S,v18.4S
	sm4e v19.4s,v7.4s;
	ext	v18.16b,v18.16b,v18.16b,#8
	rev64	v19.4S,v19.4S
	ext	v19.16b,v19.16b,v19.16b,#8
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
#ifndef __ARMEB__
	rev32	v17.16b,v17.16b
#endif
#ifndef __ARMEB__
	rev32	v18.16b,v18.16b
#endif
#ifndef __ARMEB__
	rev32	v19.16b,v19.16b
#endif
	st1	{v16.4s,v17.4s,v18.4s,v19.4s},[x1],#64
	subs	x2,x2,#64
	b.gt	1b
1:
	subs	x2,x2,#16
	b.lt	1f
	ld1	{v16.4s},[x0],#16
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
	sm4e v16.4s,v0.4s;
	sm4e v16.4s,v1.4s;
	sm4e v16.4s,v2.4s;
	sm4e v16.4s,v3.4s;
	sm4e v16.4s,v4.4s;
	sm4e v16.4s,v5.4s;
	sm4e v16.4s,v6.4s;
	sm4e v16.4s,v7.4s;
	rev64	v16.4S,v16.4S
	ext	v16.16b,v16.16b,v16.16b,#8
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
	st1	{v16.4s},[x1],#16
	b.ne	1b
1:
	ret
.size	sm4_v8_ecb_encrypt,.-sm4_v8_ecb_encrypt
.globl	sm4_v8_ctr32_encrypt_blocks
.type	sm4_v8_ctr32_encrypt_blocks,%function
.align	5
sm4_v8_ctr32_encrypt_blocks:
	AARCH64_VALID_CALL_TARGET
	stp	d8,d9,[sp, #-16]!

	ld1	{v8.4s},[x4]
	ld1	{v0.4s,v1.4s,v2.4s,v3.4s},[x3],64
	ld1	{v4.4s,v5.4s,v6.4s,v7.4s},[x3]
#ifndef __ARMEB__
	rev32	v8.16b,v8.16b
#endif
	mov	w5,v8.s[3]
1:
	cmp	x2,#4
	b.lt	1f
	ld1	{v24.4s,v25.4s,v26.4s,v27.4s},[x0],#64
	mov	v16.16b,v8.16b
	mov	v17.16b,v8.16b
	mov	v18.16b,v8.16b
	mov	v19.16b,v8.16b
	add	w5,w5,#1
	mov	v17.s[3],w5
	add	w5,w5,#1
	mov	v18.s[3],w5
	add	w5,w5,#1
	mov	v19.s[3],w5
	cmp	x2,#8
	b.lt	2f
	ld1	{v28.4s,v29.4s,v30.4s,v31.4s},[x0],#64
	mov	v20.16b,v8.16b
	mov	v21.16b,v8.16b
	mov	v22.16b,v8.16b
	mov	v23.16b,v8.16b
	add	w5,w5,#1
	mov	v20.s[3],w5
	add	w5,w5,#1
	mov	v21.s[3],w5
	add	w5,w5,#1
	mov	v22.s[3],w5
	add	w5,w5,#1
	mov	v23.s[3],w5
	sm4e	v16.4s,v0.4s;
	sm4e	v17.4s,v0.4s;
	sm4e	v18.4s,v0.4s;
	sm4e	v19.4s,v0.4s;

	sm4e	v16.4s,v1.4s;
	sm4e	v17.4s,v1.4s;
	sm4e	v18.4s,v1.4s;
	sm4e	v19.4s,v1.4s;

	sm4e	v16.4s,v2.4s;
	sm4e	v17.4s,v2.4s;
	sm4e	v18.4s,v2.4s;
	sm4e	v19.4s,v2.4s;

	sm4e	v16.4s,v3.4s;
	sm4e	v17.4s,v3.4s;
	sm4e	v18.4s,v3.4s;
	sm4e	v19.4s,v3.4s;

	sm4e	v16.4s,v4.4s;
	sm4e	v17.4s,v4.4s;
	sm4e	v18.4s,v4.4s;
	sm4e	v19.4s,v4.4s;

	sm4e	v16.4s,v5.4s;
	sm4e	v17.4s,v5.4s;
	sm4e	v18.4s,v5.4s;
	sm4e	v19.4s,v5.4s;

	sm4e	v16.4s,v6.4s;
	sm4e	v17.4s,v6.4s;
	sm4e	v18.4s,v6.4s;
	sm4e	v19.4s,v6.4s;

	sm4e	v16.4s,v7.4s;
	rev64	v16.4s,v16.4s
	sm4e	v17.4s,v7.4s;
	ext	v16.16b,v16.16b,v16.16b,#8
	rev64	v17.4s,v17.4s
	sm4e	v18.4s,v7.4s;
	ext	v17.16b,v17.16b,v17.16b,#8
	rev64	v18.4s,v18.4s
	sm4e	v19.4s,v7.4s;
	ext	v18.16b,v18.16b,v18.16b,#8
	rev64	v19.4s,v19.4s
	ext	v19.16b,v19.16b,v19.16b,#8
	sm4e	v20.4s,v0.4s;
	sm4e	v21.4s,v0.4s;
	sm4e	v22.4s,v0.4s;
	sm4e	v23.4s,v0.4s;

	sm4e	v20.4s,v1.4s;
	sm4e	v21.4s,v1.4s;
	sm4e	v22.4s,v1.4s;
	sm4e	v23.4s,v1.4s;

	sm4e	v20.4s,v2.4s;
	sm4e	v21.4s,v2.4s;
	sm4e	v22.4s,v2.4s;
	sm4e	v23.4s,v2.4s;

	sm4e	v20.4s,v3.4s;
	sm4e	v21.4s,v3.4s;
	sm4e	v22.4s,v3.4s;
	sm4e	v23.4s,v3.4s;

	sm4e	v20.4s,v4.4s;
	sm4e	v21.4s,v4.4s;
	sm4e	v22.4s,v4.4s;
	sm4e	v23.4s,v4.4s;

	sm4e	v20.4s,v5.4s;
	sm4e	v21.4s,v5.4s;
	sm4e	v22.4s,v5.4s;
	sm4e	v23.4s,v5.4s;

	sm4e	v20.4s,v6.4s;
	sm4e	v21.4s,v6.4s;
	sm4e	v22.4s,v6.4s;
	sm4e	v23.4s,v6.4s;

	sm4e	v20.4s,v7.4s;
	rev64	v20.4s,v20.4s
	sm4e	v21.4s,v7.4s;
	ext	v20.16b,v20.16b,v20.16b,#8
	rev64	v21.4s,v21.4s
	sm4e	v22.4s,v7.4s;
	ext	v21.16b,v21.16b,v21.16b,#8
	rev64	v22.4s,v22.4s
	sm4e	v23.4s,v7.4s;
	ext	v22.16b,v22.16b,v22.16b,#8
	rev64	v23.4s,v23.4s
	ext	v23.16b,v23.16b,v23.16b,#8
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
#ifndef __ARMEB__
	rev32	v17.16b,v17.16b
#endif
#ifndef __ARMEB__
	rev32	v18.16b,v18.16b
#endif
#ifndef __ARMEB__
	rev32	v19.16b,v19.16b
#endif
#ifndef __ARMEB__
	rev32	v20.16b,v20.16b
#endif
#ifndef __ARMEB__
	rev32	v21.16b,v21.16b
#endif
#ifndef __ARMEB__
	rev32	v22.16b,v22.16b
#endif
#ifndef __ARMEB__
	rev32	v23.16b,v23.16b
#endif
	eor	v16.16b,v16.16b,v24.16b
	eor	v17.16b,v17.16b,v25.16b
	eor	v18.16b,v18.16b,v26.16b
	eor	v19.16b,v19.16b,v27.16b
	eor	v20.16b,v20.16b,v28.16b
	eor	v21.16b,v21.16b,v29.16b
	eor	v22.16b,v22.16b,v30.16b
	eor	v23.16b,v23.16b,v31.16b
	st1	{v16.4s,v17.4s,v18.4s,v19.4s},[x1],#64
	st1	{v20.4s,v21.4s,v22.4s,v23.4s},[x1],#64
	subs	x2,x2,#8
	b.eq	3f
	add	w5,w5,#1
	mov	v8.s[3],w5
	b	1b
2:
	sm4e	v16.4s,v0.4s;
	sm4e	v17.4s,v0.4s;
	sm4e	v18.4s,v0.4s;
	sm4e	v19.4s,v0.4s;

	sm4e	v16.4s,v1.4s;
	sm4e	v17.4s,v1.4s;
	sm4e	v18.4s,v1.4s;
	sm4e	v19.4s,v1.4s;

	sm4e	v16.4s,v2.4s;
	sm4e	v17.4s,v2.4s;
	sm4e	v18.4s,v2.4s;
	sm4e	v19.4s,v2.4s;

	sm4e	v16.4s,v3.4s;
	sm4e	v17.4s,v3.4s;
	sm4e	v18.4s,v3.4s;
	sm4e	v19.4s,v3.4s;

	sm4e	v16.4s,v4.4s;
	sm4e	v17.4s,v4.4s;
	sm4e	v18.4s,v4.4s;
	sm4e	v19.4s,v4.4s;

	sm4e	v16.4s,v5.4s;
	sm4e	v17.4s,v5.4s;
	sm4e	v18.4s,v5.4s;
	sm4e	v19.4s,v5.4s;

	sm4e	v16.4s,v6.4s;
	sm4e	v17.4s,v6.4s;
	sm4e	v18.4s,v6.4s;
	sm4e	v19.4s,v6.4s;

	sm4e	v16.4s,v7.4s;
	rev64	v16.4s,v16.4s
	sm4e	v17.4s,v7.4s;
	ext	v16.16b,v16.16b,v16.16b,#8
	rev64	v17.4s,v17.4s
	sm4e	v18.4s,v7.4s;
	ext	v17.16b,v17.16b,v17.16b,#8
	rev64	v18.4s,v18.4s
	sm4e	v19.4s,v7.4s;
	ext	v18.16b,v18.16b,v18.16b,#8
	rev64	v19.4s,v19.4s
	ext	v19.16b,v19.16b,v19.16b,#8
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
#ifndef __ARMEB__
	rev32	v17.16b,v17.16b
#endif
#ifndef __ARMEB__
	rev32	v18.16b,v18.16b
#endif
#ifndef __ARMEB__
	rev32	v19.16b,v19.16b
#endif
	eor	v16.16b,v16.16b,v24.16b
	eor	v17.16b,v17.16b,v25.16b
	eor	v18.16b,v18.16b,v26.16b
	eor	v19.16b,v19.16b,v27.16b
	st1	{v16.4s,v17.4s,v18.4s,v19.4s},[x1],#64
	subs	x2,x2,#4
	b.eq	3f
	add	w5,w5,#1
	mov	v8.s[3],w5
	b	1b
1:
	subs	x2,x2,#1
	b.lt	3f
	mov	v16.16b,v8.16b
	ld1	{v24.4s},[x0],#16
	sm4e	v16.4s,v0.4s;
	sm4e	v16.4s,v1.4s;
	sm4e	v16.4s,v2.4s;
	sm4e	v16.4s,v3.4s;
	sm4e	v16.4s,v4.4s;
	sm4e	v16.4s,v5.4s;
	sm4e	v16.4s,v6.4s;
	sm4e	v16.4s,v7.4s;
	rev64	v16.4s,v16.4s
	ext	v16.16b,v16.16b,v16.16b,#8
#ifndef __ARMEB__
	rev32	v16.16b,v16.16b
#endif
	eor	v16.16b,v16.16b,v24.16b
	st1	{v16.4s},[x1],#16
	b.eq	3f
	add	w5,w5,#1
	mov	v8.s[3],w5
	b	1b
3:
	ldp	d8,d9,[sp],#16
	ret
.size	sm4_v8_ctr32_encrypt_blocks,.-sm4_v8_ctr32_encrypt_blocks

.globl	sm4_v8_crypt_block
.type	sm4_v8_crypt_block,%function
.align	5
sm4_v8_crypt_block:
	/* parameters:
	 *   x0: src
	 *   x1: dst
	 *   x2: key
	 */
	AARCH64_VALID_CALL_TARGET

	ld1	{v0.16b-v3.16b}, [x2], #64
	ld1	{v4.16b-v7.16b}, [x2]

	ld1	{v16.4s},[x0]

	rev32 v16.16b, v16.16b
	sm4e v16.4s, v0.4s
	sm4e v16.4s, v1.4s
	sm4e v16.4s, v2.4s
	sm4e v16.4s, v3.4s
	sm4e v16.4s, v4.4s
	sm4e v16.4s, v5.4s
	sm4e v16.4s, v6.4s
	sm4e v16.4s, v7.4s
	rev64 v16.4s, v16.4s
	ext v16.16b, v16.16b, v16.16b, #8
	rev32 v16.16b, v16.16b

	st1	{v16.16b}, [x1];

	ret
.size	sm4_v8_crypt_block,.-sm4_v8_crypt_block

.globl	sm4_v8_cfb_encrypt_blocks
.type	sm4_v8_cfb_encrypt_blocks,%function
.align	5
sm4_v8_cfb_encrypt_blocks:
	/* parameters:
	 *   x0: src
	 *   x1: dst
	 *   w2: nblocks
	 *   x3: key
	 *   x4: iv
	 */
	AARCH64_VALID_CALL_TARGET
	stp	d8,d9,[sp, #-16]!

	ld1	{v0.4s-v3.4s}, [x3], #64
	ld1	{v4.4s-v7.4s}, [x3]

	ld1	{v8.4s},[x4]

.loop_cfb_enc_4block:
	cmp	w2, #4
	blt	.loob_cfb_enc_1block

	sub	w2, w2, #4

	ld1	{v16.4s-v19.4s}, [x0], #64

	rev32 v8.16b, v8.16b
	sm4e v8.4s, v0.4s
	sm4e v8.4s, v1.4s
	sm4e v8.4s, v2.4s
	sm4e v8.4s, v3.4s
	sm4e v8.4s, v4.4s
	sm4e v8.4s, v5.4s
	sm4e v8.4s, v6.4s
	sm4e v8.4s, v7.4s
	rev64 v8.4s, v8.4s
	ext v8.16b, v8.16b, v8.16b, #8
	rev32 v8.16b, v8.16b
	eor	v16.16b, v16.16b, v8.16b

	rev32 v8.16b, v16.16b
	sm4e v8.4s, v0.4s
	sm4e v8.4s, v1.4s
	sm4e v8.4s, v2.4s
	sm4e v8.4s, v3.4s
	sm4e v8.4s, v4.4s
	sm4e v8.4s, v5.4s
	sm4e v8.4s, v6.4s
	sm4e v8.4s, v7.4s
	rev64 v8.4s, v8.4s
	ext v8.16b, v8.16b, v8.16b, #8
	rev32 v8.16b, v8.16b
	eor	v17.16b, v17.16b, v8.16b

	rev32 v8.16b, v17.16b
	sm4e v8.4s, v0.4s
	sm4e v8.4s, v1.4s
	sm4e v8.4s, v2.4s
	sm4e v8.4s, v3.4s
	sm4e v8.4s, v4.4s
	sm4e v8.4s, v5.4s
	sm4e v8.4s, v6.4s
	sm4e v8.4s, v7.4s
	rev64 v8.4s, v8.4s
	ext v8.16b, v8.16b, v8.16b, #8
	rev32 v8.16b, v8.16b
	eor	v18.16b, v18.16b, v8.16b

	rev32 v8.16b, v18.16b
	sm4e v8.4s, v0.4s
	sm4e v8.4s, v1.4s
	sm4e v8.4s, v2.4s
	sm4e v8.4s, v3.4s
	sm4e v8.4s, v4.4s
	sm4e v8.4s, v5.4s
	sm4e v8.4s, v6.4s
	sm4e v8.4s, v7.4s
	rev64 v8.4s, v8.4s
	ext v8.16b, v8.16b, v8.16b, #8
	rev32 v8.16b, v8.16b
	eor	v19.16b, v19.16b, v8.16b

	st1	{v16.4s-v19.4s}, [x1], #64
	mov	v8.16b, v19.16b

	cbz	w2, .end_cfb_enc
	b .loop_cfb_enc_4block

.loob_cfb_enc_1block:
	sub	w2, w2, #1

	ld1	{v16.4s}, [x0], #16

	rev32 v8.16b, v8.16b
	sm4e v8.4s, v0.4s
	sm4e v8.4s, v1.4s
	sm4e v8.4s, v2.4s
	sm4e v8.4s, v3.4s
	sm4e v8.4s, v4.4s
	sm4e v8.4s, v5.4s
	sm4e v8.4s, v6.4s
	sm4e v8.4s, v7.4s
	rev64 v8.4s, v8.4s
	ext v8.16b, v8.16b, v8.16b, #8
	rev32 v8.16b, v8.16b
	eor	v8.16b, v8.16b, v16.16b

	st1	{v8.4s}, [x1], #16

	cbnz w2, .loob_cfb_enc_1block

.end_cfb_enc:
	st1	{v8.4s}, [x4]

	ldp	d8,d9,[sp],#16
	ret
.size	sm4_v8_cfb_encrypt_blocks,.-sm4_v8_cfb_encrypt_blocks

.globl	sm4_v8_cfb_decrypt_blocks
.type	sm4_v8_cfb_decrypt_blocks,%function
.align	5
sm4_v8_cfb_decrypt_blocks:
	/* parameters:
	 *   x0: src
	 *   x1: dst
	 *   w2: nblocks
	 *   x3: key
	 *   x4: iv
	 */
	AARCH64_VALID_CALL_TARGET
	stp	d8,d9,[sp, #-16]!

	ld1	{v0.4s-v3.4s}, [x3], #64
	ld1	{v4.4s-v7.4s}, [x3]

	ld1	{v8.4s},[x4]

.loop_cfb_dec_8block:
	cmp	w2, #8
	blt	.cfb_dec_4block

	sub	w2, w2, #8

	ld1	{v12.4s-v15.4s}, [x0], #64
	ld1	{v16.4s-v19.4s}, [x0], #64

	rev32 v20.16b, v8.16b
	rev32 v21.16b, v12.16b
	rev32 v22.16b, v13.16b
	rev32 v23.16b, v14.16b
	rev32 v24.16b, v15.16b
	rev32 v25.16b, v16.16b
	rev32 v26.16b, v17.16b
	rev32 v27.16b, v18.16b
	sm4e v20.4s, v0.4s
	sm4e v21.4s, v0.4s
	sm4e v22.4s, v0.4s
	sm4e v23.4s, v0.4s
	sm4e v24.4s, v0.4s
	sm4e v25.4s, v0.4s
	sm4e v26.4s, v0.4s
	sm4e v27.4s, v0.4s
	sm4e v20.4s, v1.4s
	sm4e v21.4s, v1.4s
	sm4e v22.4s, v1.4s
	sm4e v23.4s, v1.4s
	sm4e v24.4s, v1.4s
	sm4e v25.4s, v1.4s
	sm4e v26.4s, v1.4s
	sm4e v27.4s, v1.4s
	sm4e v20.4s, v2.4s
	sm4e v21.4s, v2.4s
	sm4e v22.4s, v2.4s
	sm4e v23.4s, v2.4s
	sm4e v24.4s, v2.4s
	sm4e v25.4s, v2.4s
	sm4e v26.4s, v2.4s
	sm4e v27.4s, v2.4s
	sm4e v20.4s, v3.4s
	sm4e v21.4s, v3.4s
	sm4e v22.4s, v3.4s
	sm4e v23.4s, v3.4s
	sm4e v24.4s, v3.4s
	sm4e v25.4s, v3.4s
	sm4e v26.4s, v3.4s
	sm4e v27.4s, v3.4s
	sm4e v20.4s, v4.4s
	sm4e v21.4s, v4.4s
	sm4e v22.4s, v4.4s
	sm4e v23.4s, v4.4s
	sm4e v24.4s, v4.4s
	sm4e v25.4s, v4.4s
	sm4e v26.4s, v4.4s
	sm4e v27.4s, v4.4s
	sm4e v20.4s, v5.4s
	sm4e v21.4s, v5.4s
	sm4e v22.4s, v5.4s
	sm4e v23.4s, v5.4s
	sm4e v24.4s, v5.4s
	sm4e v25.4s, v5.4s
	sm4e v26.4s, v5.4s
	sm4e v27.4s, v5.4s
	sm4e v20.4s, v6.4s
	sm4e v21.4s, v6.4s
	sm4e v22.4s, v6.4s
	sm4e v23.4s, v6.4s
	sm4e v24.4s, v6.4s
	sm4e v25.4s, v6.4s
	sm4e v26.4s, v6.4s
	sm4e v27.4s, v6.4s
	sm4e v20.4s, v7.4s
	sm4e v21.4s, v7.4s
	sm4e v22.4s, v7.4s
	sm4e v23.4s, v7.4s
	sm4e v24.4s, v7.4s
	sm4e v25.4s, v7.4s
	sm4e v26.4s, v7.4s
	sm4e v27.4s, v7.4s
	rev64 v20.4s, v20.4s
	rev64 v21.4s, v21.4s
	rev64 v22.4s, v22.4s
	rev64 v23.4s, v23.4s
	rev64 v24.4s, v24.4s
	rev64 v25.4s, v25.4s
	rev64 v26.4s, v26.4s
	rev64 v27.4s, v27.4s
	ext v20.16b, v20.16b, v20.16b, #8
	ext v21.16b, v21.16b, v21.16b, #8
	ext v22.16b, v22.16b, v22.16b, #8
	ext v23.16b, v23.16b, v23.16b, #8
	ext v24.16b, v24.16b, v24.16b, #8
	ext v25.16b, v25.16b, v25.16b, #8
	ext v26.16b, v26.16b, v26.16b, #8
	ext v27.16b, v27.16b, v27.16b, #8
	rev32 v20.16b, v20.16b
	rev32 v21.16b, v21.16b
	rev32 v22.16b, v22.16b
	rev32 v23.16b, v23.16b
	rev32 v24.16b, v24.16b
	rev32 v25.16b, v25.16b
	rev32 v26.16b, v26.16b
	rev32 v27.16b, v27.16b

	mov	v8.16b, v19.16b		//Modify IV

	eor	v20.16b, v20.16b, v12.16b
	eor	v21.16b, v21.16b, v13.16b
	eor	v22.16b, v22.16b, v14.16b
	eor	v23.16b, v23.16b, v15.16b
	eor	v24.16b, v24.16b, v16.16b
	eor	v25.16b, v25.16b, v17.16b
	eor	v26.16b, v26.16b, v18.16b
	eor	v27.16b, v27.16b, v19.16b

	st1	{v20.4s-v23.4s}, [x1], #64
	st1	{v24.4s-v27.4s}, [x1], #64

	cbz	w2, .end_cfb_dec
	b .loop_cfb_dec_8block

.cfb_dec_4block:
	cmp	w2, #4
	blt	.loop_cfb_dec_1block

	sub	w2, w2, #4

	ld1	{v12.4s-v15.4s}, [x0], #64

	rev32 v20.16b, v8.16b
	rev32 v21.16b, v12.16b
	rev32 v22.16b, v13.16b
	rev32 v23.16b, v14.16b
	sm4e v20.4s, v0.4s
	sm4e v21.4s, v0.4s
	sm4e v22.4s, v0.4s
	sm4e v23.4s, v0.4s
	sm4e v20.4s, v1.4s
	sm4e v21.4s, v1.4s
	sm4e v22.4s, v1.4s
	sm4e v23.4s, v1.4s
	sm4e v20.4s, v2.4s
	sm4e v21.4s, v2.4s
	sm4e v22.4s, v2.4s
	sm4e v23.4s, v2.4s
	sm4e v20.4s, v3.4s
	sm4e v21.4s, v3.4s
	sm4e v22.4s, v3.4s
	sm4e v23.4s, v3.4s
	sm4e v20.4s, v4.4s
	sm4e v21.4s, v4.4s
	sm4e v22.4s, v4.4s
	sm4e v23.4s, v4.4s
	sm4e v20.4s, v5.4s
	sm4e v21.4s, v5.4s
	sm4e v22.4s, v5.4s
	sm4e v23.4s, v5.4s
	sm4e v20.4s, v6.4s
	sm4e v21.4s, v6.4s
	sm4e v22.4s, v6.4s
	sm4e v23.4s, v6.4s
	sm4e v20.4s, v7.4s
	sm4e v21.4s, v7.4s
	sm4e v22.4s, v7.4s
	sm4e v23.4s, v7.4s
	rev64 v20.4s, v20.4s
	rev64 v21.4s, v21.4s
	rev64 v22.4s, v22.4s
	rev64 v23.4s, v23.4s
	ext v20.16b, v20.16b, v20.16b, #8
	ext v21.16b, v21.16b, v21.16b, #8
	ext v22.16b, v22.16b, v22.16b, #8
	ext v23.16b, v23.16b, v23.16b, #8
	rev32 v20.16b, v20.16b
	rev32 v21.16b, v21.16b
	rev32 v22.16b, v22.16b
	rev32 v23.16b, v23.16b

	mov	v8.16b, v15.16b		//Modify IV

	eor	v20.16b, v20.16b, v12.16b
	eor	v21.16b, v21.16b, v13.16b
	eor	v22.16b, v22.16b, v14.16b
	eor	v23.16b, v23.16b, v15.16b

	st1	{v20.4s-v23.4s}, [x1], #64

	cbz	w2, .end_cfb_dec

.loop_cfb_dec_1block:
	sub	w2, w2, #1

	ld1	{v12.4s}, [x0], #16

	rev32 v20.16b, v8.16b
	sm4e v20.4s, v0.4s
	sm4e v20.4s, v1.4s
	sm4e v20.4s, v2.4s
	sm4e v20.4s, v3.4s
	sm4e v20.4s, v4.4s
	sm4e v20.4s, v5.4s
	sm4e v20.4s, v6.4s
	sm4e v20.4s, v7.4s
	rev64 v20.4s, v20.4s
	ext v20.16b, v20.16b, v20.16b, #8
	rev32 v20.16b, v20.16b

	eor	v20.16b, v20.16b, v12.16b
	st1	{v20.4s}, [x1], #16

	mov	v8.16b, v12.16b		//Modify IV

	cbnz w2, .loop_cfb_dec_1block

.end_cfb_dec:
	/* store new IV */
	st1	{v8.4s}, [x4]

	ldp	d8,d9,[sp],#16
	ret
.size	sm4_v8_cfb_decrypt_blocks,.-sm4_v8_cfb_decrypt_blocks

#define tweak_calc(out, in, MSK, TMP)			\
		sshr TMP.2d, in.2d, #63;				\
		and	 TMP.16b, TMP.16b, MSK.16b;			\
		add	 out.2d, in.2d, in.2d;				\
		ext	 TMP.16b, TMP.16b, TMP.16b, #8;		\
		eor	 out.16b, out.16b, TMP.16b;

.globl	sm4_v8_xts_encrypt
.type	sm4_v8_xts_encrypt,%function
.align	5
sm4_v8_xts_encrypt:
	/* parameters:
	 *   x0: src
	 *   x1: dst
	 *   w2: nbytes
	 *   x3: key
	 *   x4: tweak
	 *   x5: key array for tweak
	 */
	AARCH64_VALID_CALL_TARGET
	stp	d8,d9,[sp, #-16]!

	ld1	{v8.16b}, [x4]

	cbz	x5, .enc_xts_nokey2

	/* load round key array for tweak */
	ld1	{v0.16b-v3.16b}, [x5], #64
	ld1	{v4.16b-v7.16b}, [x5]

	/* first tweak */
	rev32 v8.16b, v8.16b
	sm4e v8.4s, v0.4s
	sm4e v8.4s, v1.4s
	sm4e v8.4s, v2.4s
	sm4e v8.4s, v3.4s
	sm4e v8.4s, v4.4s
	sm4e v8.4s, v5.4s
	sm4e v8.4s, v6.4s
	sm4e v8.4s, v7.4s
	rev64 v8.4s, v8.4s
	ext v8.16b, v8.16b, v8.16b, #8
	rev32 v8.16b, v8.16b

.enc_xts_nokey2:
	/* load key array */
	ld1	{v0.16b-v3.16b}, [x3], #64
	ld1	{v4.16b-v7.16b}, [x3]

	and w5, w2, #15
	lsr	w2, w2, #4
	cbz w5, .enc_xts_mask
	/* leave the last block for tail */
	sub	w2, w2, #1

.enc_xts_mask:
	/* init mask */
	movi v31.2s, #0x1
	movi v16.2s, #0x87
	uzp1 v31.4s, v31.4s, v16.4s

	cbz	w2, .enc_xts_tail

.enc_xts_8block:
	sub	w2, w2, #8
	tbnz w2, #31, .enc_xts_4block

	tweak_calc(v9, v8, v31, v16)
	tweak_calc(v10, v9, v31, v17)
	tweak_calc(v11, v10, v31, v18)
	tweak_calc(v12, v11, v31, v19)
	tweak_calc(v13, v12, v31, v16)
	tweak_calc(v14, v13, v31, v17)
	tweak_calc(v15, v14, v31, v18)

	ld1	{v20.16b-v23.16b}, [x0], #64
	ld1	{v24.16b-v27.16b}, [x0], #64
	eor	v20.16b, v20.16b,  v8.16b
	eor	v21.16b, v21.16b,  v9.16b
	eor	v22.16b, v22.16b, v10.16b
	eor	v23.16b, v23.16b, v11.16b
	eor	v24.16b, v24.16b, v12.16b
	eor	v25.16b, v25.16b, v13.16b
	eor	v26.16b, v26.16b, v14.16b
	eor	v27.16b, v27.16b, v15.16b

	rev32 v20.16b, v20.16b
	rev32 v21.16b, v21.16b
	rev32 v22.16b, v22.16b
	rev32 v23.16b, v23.16b
	rev32 v24.16b, v24.16b
	rev32 v25.16b, v25.16b
	rev32 v26.16b, v26.16b
	rev32 v27.16b, v27.16b
	sm4e v20.4s, v0.4s
	sm4e v21.4s, v0.4s
	sm4e v22.4s, v0.4s
	sm4e v23.4s, v0.4s
	sm4e v24.4s, v0.4s
	sm4e v25.4s, v0.4s
	sm4e v26.4s, v0.4s
	sm4e v27.4s, v0.4s
	sm4e v20.4s, v1.4s
	sm4e v21.4s, v1.4s
	sm4e v22.4s, v1.4s
	sm4e v23.4s, v1.4s
	sm4e v24.4s, v1.4s
	sm4e v25.4s, v1.4s
	sm4e v26.4s, v1.4s
	sm4e v27.4s, v1.4s
	sm4e v20.4s, v2.4s
	sm4e v21.4s, v2.4s
	sm4e v22.4s, v2.4s
	sm4e v23.4s, v2.4s
	sm4e v24.4s, v2.4s
	sm4e v25.4s, v2.4s
	sm4e v26.4s, v2.4s
	sm4e v27.4s, v2.4s
	sm4e v20.4s, v3.4s
	sm4e v21.4s, v3.4s
	sm4e v22.4s, v3.4s
	sm4e v23.4s, v3.4s
	sm4e v24.4s, v3.4s
	sm4e v25.4s, v3.4s
	sm4e v26.4s, v3.4s
	sm4e v27.4s, v3.4s
	sm4e v20.4s, v4.4s
	sm4e v21.4s, v4.4s
	sm4e v22.4s, v4.4s
	sm4e v23.4s, v4.4s
	sm4e v24.4s, v4.4s
	sm4e v25.4s, v4.4s
	sm4e v26.4s, v4.4s
	sm4e v27.4s, v4.4s
	sm4e v20.4s, v5.4s
	sm4e v21.4s, v5.4s
	sm4e v22.4s, v5.4s
	sm4e v23.4s, v5.4s
	sm4e v24.4s, v5.4s
	sm4e v25.4s, v5.4s
	sm4e v26.4s, v5.4s
	sm4e v27.4s, v5.4s
	sm4e v20.4s, v6.4s
	sm4e v21.4s, v6.4s
	sm4e v22.4s, v6.4s
	sm4e v23.4s, v6.4s
	sm4e v24.4s, v6.4s
	sm4e v25.4s, v6.4s
	sm4e v26.4s, v6.4s
	sm4e v27.4s, v6.4s
	sm4e v20.4s, v7.4s
	sm4e v21.4s, v7.4s
	sm4e v22.4s, v7.4s
	sm4e v23.4s, v7.4s
	sm4e v24.4s, v7.4s
	sm4e v25.4s, v7.4s
	sm4e v26.4s, v7.4s
	sm4e v27.4s, v7.4s
	rev64 v20.4s, v20.4s
	rev64 v21.4s, v21.4s
	rev64 v22.4s, v22.4s
	rev64 v23.4s, v23.4s
	rev64 v24.4s, v24.4s
	rev64 v25.4s, v25.4s
	rev64 v26.4s, v26.4s
	rev64 v27.4s, v27.4s
	ext v20.16b, v20.16b, v20.16b, #8
	ext v21.16b, v21.16b, v21.16b, #8
	ext v22.16b, v22.16b, v22.16b, #8
	ext v23.16b, v23.16b, v23.16b, #8
	ext v24.16b, v24.16b, v24.16b, #8
	ext v25.16b, v25.16b, v25.16b, #8
	ext v26.16b, v26.16b, v26.16b, #8
	ext v27.16b, v27.16b, v27.16b, #8
	rev32 v20.16b, v20.16b
	rev32 v21.16b, v21.16b
	rev32 v22.16b, v22.16b
	rev32 v23.16b, v23.16b
	rev32 v24.16b, v24.16b
	rev32 v25.16b, v25.16b
	rev32 v26.16b, v26.16b
	rev32 v27.16b, v27.16b

	eor	v20.16b, v20.16b,  v8.16b
	eor	v21.16b, v21.16b,  v9.16b
	eor	v22.16b, v22.16b, v10.16b
	eor	v23.16b, v23.16b, v11.16b
	eor	v24.16b, v24.16b, v12.16b
	eor	v25.16b, v25.16b, v13.16b
	eor	v26.16b, v26.16b, v14.16b
	eor	v27.16b, v27.16b, v15.16b
	st1	{v20.16b-v23.16b}, [x1], #64
	st1	{v24.16b-v27.16b}, [x1], #64

	tweak_calc(v8, v15, v31, v19)

	cbz	w2, .enc_xts_tail
	b .enc_xts_8block

.enc_xts_4block:
	add	w2, w2, #8
	cmp	w2, #4
	blt	.enc_xts_1block

	sub	w2, w2, #4

	tweak_calc(v9, v8, v31, v16)
	tweak_calc(v10, v9, v31, v17)
	tweak_calc(v11, v10, v31, v18)

	ld1	{v20.16b-v23.16b}, [x0], #64
	eor	v20.16b, v20.16b, v8.16b
	eor	v21.16b, v21.16b, v9.16b
	eor	v22.16b, v22.16b, v10.16b
	eor	v23.16b, v23.16b, v11.16b

	rev32 v20.16b, v20.16b
	rev32 v21.16b, v21.16b
	rev32 v22.16b, v22.16b
	rev32 v23.16b, v23.16b
	sm4e v20.4s, v0.4s
	sm4e v21.4s, v0.4s
	sm4e v22.4s, v0.4s
	sm4e v23.4s, v0.4s
	sm4e v20.4s, v1.4s
	sm4e v21.4s, v1.4s
	sm4e v22.4s, v1.4s
	sm4e v23.4s, v1.4s
	sm4e v20.4s, v2.4s
	sm4e v21.4s, v2.4s
	sm4e v22.4s, v2.4s
	sm4e v23.4s, v2.4s
	sm4e v20.4s, v3.4s
	sm4e v21.4s, v3.4s
	sm4e v22.4s, v3.4s
	sm4e v23.4s, v3.4s
	sm4e v20.4s, v4.4s
	sm4e v21.4s, v4.4s
	sm4e v22.4s, v4.4s
	sm4e v23.4s, v4.4s
	sm4e v20.4s, v5.4s
	sm4e v21.4s, v5.4s
	sm4e v22.4s, v5.4s
	sm4e v23.4s, v5.4s
	sm4e v20.4s, v6.4s
	sm4e v21.4s, v6.4s
	sm4e v22.4s, v6.4s
	sm4e v23.4s, v6.4s
	sm4e v20.4s, v7.4s
	sm4e v21.4s, v7.4s
	sm4e v22.4s, v7.4s
	sm4e v23.4s, v7.4s
	rev64 v20.4s, v20.4s
	rev64 v21.4s, v21.4s
	rev64 v22.4s, v22.4s
	rev64 v23.4s, v23.4s
	ext v20.16b, v20.16b, v20.16b, #8
	ext v21.16b, v21.16b, v21.16b, #8
	ext v22.16b, v22.16b, v22.16b, #8
	ext v23.16b, v23.16b, v23.16b, #8
	rev32 v20.16b, v20.16b
	rev32 v21.16b, v21.16b
	rev32 v22.16b, v22.16b
	rev32 v23.16b, v23.16b

	eor	v20.16b, v20.16b, v8.16b
	eor	v21.16b, v21.16b, v9.16b
	eor	v22.16b, v22.16b, v10.16b
	eor	v23.16b, v23.16b, v11.16b
	st1	{v20.16b-v23.16b}, [x1], #64

	tweak_calc(v8, v11, v31, v19)

	cbz	w2, .enc_xts_tail

.enc_xts_1block:
	sub	w2, w2, #1

	ld1	{v20.16b}, [x0], #16
	eor	v20.16b, v20.16b, v8.16b

	rev32 v20.16b, v20.16b
	sm4e v20.4s, v0.4s
	sm4e v20.4s, v1.4s
	sm4e v20.4s, v2.4s
	sm4e v20.4s, v3.4s
	sm4e v20.4s, v4.4s
	sm4e v20.4s, v5.4s
	sm4e v20.4s, v6.4s
	sm4e v20.4s, v7.4s
	rev64 v20.4s, v20.4s
	ext v20.16b, v20.16b, v20.16b, #8
	rev32 v20.16b, v20.16b

	eor	v20.16b, v20.16b, v8.16b
	st1	{v20.16b}, [x1], #16

	tweak_calc(v8, v8, v31, v16)

	cbnz w2, .enc_xts_1block

.enc_xts_tail:
	uxtw x5, w5
	cbz	x5, .enc_xts_end

	tweak_calc(v9, v8, v31, v16)
	ld1	{v20.16b}, [x0]
	eor	v20.16b, v20.16b, v8.16b
	rev32 v20.16b, v20.16b
	sm4e v20.4s, v0.4s
	sm4e v20.4s, v1.4s
	sm4e v20.4s, v2.4s
	sm4e v20.4s, v3.4s
	sm4e v20.4s, v4.4s
	sm4e v20.4s, v5.4s
	sm4e v20.4s, v6.4s
	sm4e v20.4s, v7.4s
	rev64 v20.4s, v20.4s
	ext v20.16b, v20.16b, v20.16b, #8
	rev32 v20.16b, v20.16b
	eor	v20.16b, v20.16b, v8.16b

	adr x6, .cts_permute_table
	add	x7, x6, #32
	add	x6, x6, x5
	sub	x7, x7, x5
	ld1	{v23.16b}, [x6]
	ld1	{v24.16b}, [x7]

	add	x0, x0, x5
	ld1	{v21.16b}, [x0]

	tbl	v22.16b, {v20.16b}, v23.16b
	tbx	v20.16b, {v21.16b}, v24.16b

	eor	v20.16b, v20.16b, v9.16b
	rev32 v20.16b, v20.16b
	sm4e v20.4s, v0.4s
	sm4e v20.4s, v1.4s
	sm4e v20.4s, v2.4s
	sm4e v20.4s, v3.4s
	sm4e v20.4s, v4.4s
	sm4e v20.4s, v5.4s
	sm4e v20.4s, v6.4s
	sm4e v20.4s, v7.4s
	rev64 v20.4s, v20.4s
	ext v20.16b, v20.16b, v20.16b, #8
	rev32 v20.16b, v20.16b
	eor	v20.16b, v20.16b, v9.16b

	add	x5, x1, x5
	st1	{v22.16b}, [x5]
	st1	{v20.16b}, [x1]

	b .enc_xts_ret

.enc_xts_end:
	/* new tweak */
	st1	{v8.16b}, [x4]

.enc_xts_ret:
	ldp	d8,d9,[sp],#16
	ret
.size	sm4_v8_xts_encrypt,.-sm4_v8_xts_encrypt

.globl	sm4_v8_xts_decrypt
.type	sm4_v8_xts_decrypt,%function
.align	5
sm4_v8_xts_decrypt:
	/* parameters:
	 *   x0: src
	 *   x1: dst
	 *   w2: nbytes
	 *   x3: key
	 *   x4: tweak
	 *   x5: key array for tweak
	 */
	AARCH64_VALID_CALL_TARGET
	stp	d8,d9,[sp, #-16]!

	ld1	{v8.16b}, [x4]

	cbz	x5, .dec_xts_nokey2

	/* load round key array for tweak */
	ld1	{v0.16b-v3.16b}, [x5], #64
	ld1	{v4.16b-v7.16b}, [x5]

	/* first tweak */
	rev32 v8.16b, v8.16b
	sm4e v8.4s, v0.4s
	sm4e v8.4s, v1.4s
	sm4e v8.4s, v2.4s
	sm4e v8.4s, v3.4s
	sm4e v8.4s, v4.4s
	sm4e v8.4s, v5.4s
	sm4e v8.4s, v6.4s
	sm4e v8.4s, v7.4s
	rev64 v8.4s, v8.4s
	ext v8.16b, v8.16b, v8.16b, #8
	rev32 v8.16b, v8.16b

.dec_xts_nokey2:
	ld1	{v0.16b-v3.16b}, [x3], #64
	ld1	{v4.16b-v7.16b}, [x3]

	and w5, w2, #15
	lsr	w2, w2, #4
	cbz w5, .dec_xts_mask
	/* leave the last block for tail */
	sub	w2, w2, #1

.dec_xts_mask:
	/* init mask */
	movi v31.2s, #0x1
	movi v16.2s, #0x87
	uzp1 v31.4s, v31.4s, v16.4s

	cbz	w2, .dec_xts_tail

.dec_xts_8block:
	sub	w2, w2, #8
	tbnz w2, #31, .dec_xts_4block

	tweak_calc(v9, v8, v31, v16)
	tweak_calc(v10, v9, v31, v17)
	tweak_calc(v11, v10, v31, v18)
	tweak_calc(v12, v11, v31, v19)
	tweak_calc(v13, v12, v31, v16)
	tweak_calc(v14, v13, v31, v17)
	tweak_calc(v15, v14, v31, v18)

	ld1	{v20.16b-v23.16b}, [x0], #64
	ld1	{v24.16b-v27.16b}, [x0], #64
	eor	v20.16b, v20.16b, v8.16b
	eor	v21.16b, v21.16b, v9.16b
	eor	v22.16b, v22.16b, v10.16b
	eor	v23.16b, v23.16b, v11.16b
	eor	v24.16b, v24.16b, v12.16b
	eor	v25.16b, v25.16b, v13.16b
	eor	v26.16b, v26.16b, v14.16b
	eor	v27.16b, v27.16b, v15.16b

	rev32 v20.16b, v20.16b
	rev32 v21.16b, v21.16b
	rev32 v22.16b, v22.16b
	rev32 v23.16b, v23.16b
	rev32 v24.16b, v24.16b
	rev32 v25.16b, v25.16b
	rev32 v26.16b, v26.16b
	rev32 v27.16b, v27.16b
	sm4e v20.4s, v0.4s
	sm4e v21.4s, v0.4s
	sm4e v22.4s, v0.4s
	sm4e v23.4s, v0.4s
	sm4e v24.4s, v0.4s
	sm4e v25.4s, v0.4s
	sm4e v26.4s, v0.4s
	sm4e v27.4s, v0.4s
	sm4e v20.4s, v1.4s
	sm4e v21.4s, v1.4s
	sm4e v22.4s, v1.4s
	sm4e v23.4s, v1.4s
	sm4e v24.4s, v1.4s
	sm4e v25.4s, v1.4s
	sm4e v26.4s, v1.4s
	sm4e v27.4s, v1.4s
	sm4e v20.4s, v2.4s
	sm4e v21.4s, v2.4s
	sm4e v22.4s, v2.4s
	sm4e v23.4s, v2.4s
	sm4e v24.4s, v2.4s
	sm4e v25.4s, v2.4s
	sm4e v26.4s, v2.4s
	sm4e v27.4s, v2.4s
	sm4e v20.4s, v3.4s
	sm4e v21.4s, v3.4s
	sm4e v22.4s, v3.4s
	sm4e v23.4s, v3.4s
	sm4e v24.4s, v3.4s
	sm4e v25.4s, v3.4s
	sm4e v26.4s, v3.4s
	sm4e v27.4s, v3.4s
	sm4e v20.4s, v4.4s
	sm4e v21.4s, v4.4s
	sm4e v22.4s, v4.4s
	sm4e v23.4s, v4.4s
	sm4e v24.4s, v4.4s
	sm4e v25.4s, v4.4s
	sm4e v26.4s, v4.4s
	sm4e v27.4s, v4.4s
	sm4e v20.4s, v5.4s
	sm4e v21.4s, v5.4s
	sm4e v22.4s, v5.4s
	sm4e v23.4s, v5.4s
	sm4e v24.4s, v5.4s
	sm4e v25.4s, v5.4s
	sm4e v26.4s, v5.4s
	sm4e v27.4s, v5.4s
	sm4e v20.4s, v6.4s
	sm4e v21.4s, v6.4s
	sm4e v22.4s, v6.4s
	sm4e v23.4s, v6.4s
	sm4e v24.4s, v6.4s
	sm4e v25.4s, v6.4s
	sm4e v26.4s, v6.4s
	sm4e v27.4s, v6.4s
	sm4e v20.4s, v7.4s
	sm4e v21.4s, v7.4s
	sm4e v22.4s, v7.4s
	sm4e v23.4s, v7.4s
	sm4e v24.4s, v7.4s
	sm4e v25.4s, v7.4s
	sm4e v26.4s, v7.4s
	sm4e v27.4s, v7.4s
	rev64 v20.4s, v20.4s
	rev64 v21.4s, v21.4s
	rev64 v22.4s, v22.4s
	rev64 v23.4s, v23.4s
	rev64 v24.4s, v24.4s
	rev64 v25.4s, v25.4s
	rev64 v26.4s, v26.4s
	rev64 v27.4s, v27.4s
	ext v20.16b, v20.16b, v20.16b, #8
	ext v21.16b, v21.16b, v21.16b, #8
	ext v22.16b, v22.16b, v22.16b, #8
	ext v23.16b, v23.16b, v23.16b, #8
	ext v24.16b, v24.16b, v24.16b, #8
	ext v25.16b, v25.16b, v25.16b, #8
	ext v26.16b, v26.16b, v26.16b, #8
	ext v27.16b, v27.16b, v27.16b, #8
	rev32 v20.16b, v20.16b
	rev32 v21.16b, v21.16b
	rev32 v22.16b, v22.16b
	rev32 v23.16b, v23.16b
	rev32 v24.16b, v24.16b
	rev32 v25.16b, v25.16b
	rev32 v26.16b, v26.16b
	rev32 v27.16b, v27.16b

	eor	v20.16b, v20.16b, v8.16b
	eor	v21.16b, v21.16b, v9.16b
	eor	v22.16b, v22.16b, v10.16b
	eor	v23.16b, v23.16b, v11.16b
	eor	v24.16b, v24.16b, v12.16b
	eor	v25.16b, v25.16b, v13.16b
	eor	v26.16b, v26.16b, v14.16b
	eor	v27.16b, v27.16b, v15.16b
	st1	{v20.16b-v23.16b}, [x1], #64
	st1	{v24.16b-v27.16b}, [x1], #64

	tweak_calc(v8, v15, v31, v19)

	cbz	w2, .dec_xts_tail
	b .dec_xts_8block

.dec_xts_4block:
	add	w2, w2, #8
	cmp	w2, #4
	blt	.dec_xts_1block

	sub	w2, w2, #4

	tweak_calc(v9, v8, v31, v16)
	tweak_calc(v10, v9, v31, v17)
	tweak_calc(v11, v10, v31, v18)

	ld1	{v20.16b-v23.16b}, [x0], #64
	eor	v20.16b, v20.16b, v8.16b
	eor	v21.16b, v21.16b, v9.16b
	eor	v22.16b, v22.16b, v10.16b
	eor	v23.16b, v23.16b, v11.16b

	rev32 v20.16b, v20.16b
	rev32 v21.16b, v21.16b
	rev32 v22.16b, v22.16b
	rev32 v23.16b, v23.16b
	sm4e v20.4s, v0.4s
	sm4e v21.4s, v0.4s
	sm4e v22.4s, v0.4s
	sm4e v23.4s, v0.4s
	sm4e v20.4s, v1.4s
	sm4e v21.4s, v1.4s
	sm4e v22.4s, v1.4s
	sm4e v23.4s, v1.4s
	sm4e v20.4s, v2.4s
	sm4e v21.4s, v2.4s
	sm4e v22.4s, v2.4s
	sm4e v23.4s, v2.4s
	sm4e v20.4s, v3.4s
	sm4e v21.4s, v3.4s
	sm4e v22.4s, v3.4s
	sm4e v23.4s, v3.4s
	sm4e v20.4s, v4.4s
	sm4e v21.4s, v4.4s
	sm4e v22.4s, v4.4s
	sm4e v23.4s, v4.4s
	sm4e v20.4s, v5.4s
	sm4e v21.4s, v5.4s
	sm4e v22.4s, v5.4s
	sm4e v23.4s, v5.4s
	sm4e v20.4s, v6.4s
	sm4e v21.4s, v6.4s
	sm4e v22.4s, v6.4s
	sm4e v23.4s, v6.4s
	sm4e v20.4s, v7.4s
	sm4e v21.4s, v7.4s
	sm4e v22.4s, v7.4s
	sm4e v23.4s, v7.4s
	rev64 v20.4s, v20.4s
	rev64 v21.4s, v21.4s
	rev64 v22.4s, v22.4s
	rev64 v23.4s, v23.4s
	ext v20.16b, v20.16b, v20.16b, #8
	ext v21.16b, v21.16b, v21.16b, #8
	ext v22.16b, v22.16b, v22.16b, #8
	ext v23.16b, v23.16b, v23.16b, #8
	rev32 v20.16b, v20.16b
	rev32 v21.16b, v21.16b
	rev32 v22.16b, v22.16b
	rev32 v23.16b, v23.16b

	eor	v20.16b, v20.16b, v8.16b
	eor	v21.16b, v21.16b, v9.16b
	eor	v22.16b, v22.16b, v10.16b
	eor	v23.16b, v23.16b, v11.16b
	st1	{v20.16b-v23.16b}, [x1], #64

	tweak_calc(v8, v11, v31, v19)

	cbz	w2, .dec_xts_tail

.dec_xts_1block:
	sub	w2, w2, #1

	ld1	{v20.16b}, [x0], #16
	eor	v20.16b, v20.16b, v8.16b

	rev32 v20.16b, v20.16b
	sm4e v20.4s, v0.4s
	sm4e v20.4s, v1.4s
	sm4e v20.4s, v2.4s
	sm4e v20.4s, v3.4s
	sm4e v20.4s, v4.4s
	sm4e v20.4s, v5.4s
	sm4e v20.4s, v6.4s
	sm4e v20.4s, v7.4s
	rev64 v20.4s, v20.4s
	ext v20.16b, v20.16b, v20.16b, #8
	rev32 v20.16b, v20.16b

	eor	v20.16b, v20.16b, v8.16b
	st1	{v20.16b}, [x1], #16

	tweak_calc(v8, v8, v31, v16)

	cbnz w2, .dec_xts_1block

.dec_xts_tail:
	uxtw x5, w5
	cbz	x5, .dec_xts_end

	tweak_calc(v9, v8, v31, v16)
	ld1	{v20.16b}, [x0]
	eor	v20.16b, v20.16b, v9.16b
	rev32 v20.16b, v20.16b
	sm4e v20.4s, v0.4s
	sm4e v20.4s, v1.4s
	sm4e v20.4s, v2.4s
	sm4e v20.4s, v3.4s
	sm4e v20.4s, v4.4s
	sm4e v20.4s, v5.4s
	sm4e v20.4s, v6.4s
	sm4e v20.4s, v7.4s
	rev64 v20.4s, v20.4s
	ext v20.16b, v20.16b, v20.16b, #8
	rev32 v20.16b, v20.16b
	eor	v20.16b, v20.16b, v9.16b

	adr x6, .cts_permute_table
	add	x7, x6, #32
	add	x6, x6, x5
	sub	x7, x7, x5
	ld1	{v23.16b}, [x6]
	ld1	{v24.16b}, [x7]

	add	x0, x0, x5
	ld1	{v21.16b}, [x0]

	tbl	v22.16b, {v20.16b}, v23.16b
	tbx	v20.16b, {v21.16b}, v24.16b

	eor	v20.16b, v20.16b, v8.16b
	rev32 v20.16b, v20.16b
	sm4e v20.4s, v0.4s
	sm4e v20.4s, v1.4s
	sm4e v20.4s, v2.4s
	sm4e v20.4s, v3.4s
	sm4e v20.4s, v4.4s
	sm4e v20.4s, v5.4s
	sm4e v20.4s, v6.4s
	sm4e v20.4s, v7.4s
	rev64 v20.4s, v20.4s
	ext v20.16b, v20.16b, v20.16b, #8
	rev32 v20.16b, v20.16b
	eor	v20.16b, v20.16b, v8.16b

	add	x5, x1, x5
	st1	{v22.16b}, [x5]
	st1	{v20.16b}, [x1]

	b .dec_xts_ret

.dec_xts_end:
	/* new tweak */
	st1	{v8.16b}, [x4]

.dec_xts_ret:
	ldp	d8,d9,[sp],#16
	ret
.size	sm4_v8_xts_decrypt,.-sm4_v8_xts_decrypt
