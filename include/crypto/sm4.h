/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_SM4_H__
#define __WD_SM4_H__

#include <linux/types.h>

#ifdef __cplusplus
extern "C" {
#endif

void sm4_encrypt(__u8 *key, __u32 key_len, __u8 *input, __u8 *output);
#ifdef __cplusplus
}
#endif

#endif
