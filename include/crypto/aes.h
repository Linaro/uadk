/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2023 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_AES_H__
#define __WD_AES_H__

#include <linux/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UINT_B_CNT	8
#define AES_MAXNR	14

struct aes_key {
	unsigned int rd_key[4 * (AES_MAXNR + 1)];
	__u8 rounds;
};

union uni {
	unsigned char b[UINT_B_CNT];
	__u32 w[2];
	__u64 d;
};

void aes_encrypt(__u8 *key, __u32 key_len, __u8 *src, __u8 *dst);
#ifdef __cplusplus
}
#endif

#endif
