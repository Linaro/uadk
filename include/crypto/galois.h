/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2023 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_GALOIS_H__
#define __WD_GALOIS_H__

#include <linux/types.h>

#ifdef __cplusplus
extern "C" {
#endif

void galois_compute(__u8 *S, __u8 *H, __u8 *g, __u32 len);

#ifdef __cplusplus
}
#endif

#endif
