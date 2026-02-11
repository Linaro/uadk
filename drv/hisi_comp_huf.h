/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __HISI_COMP_HUF_H
#define __HISI_COMP_HUF_H

#include <linux/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int check_bfinal_complete_block(void *addr, __u32 bit_len);

#ifdef __cplusplus
}
#endif

#endif /* __HISI_COMP_HUF_H */
