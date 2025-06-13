/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __HISI_ZIP_HUF_H
#define __HISI_ZIP_HUF_H

#include <asm/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int check_huffman_block_integrity(void *data, __u32 bit_len);

#ifdef __cplusplus
}
#endif

#endif /* __HISI_ZIP_HUF_H */
