// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#ifndef WD_ALG_COMMON_H
#define WD_ALG_COMMON_H

#include <pthread.h>
#include <stdbool.h>
#include "wd.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BYTE_BITS			8
#define BYTE_BITS_SHIFT			3
#define GET_NEGATIVE(val)		(0 - (val))

#define BITS_TO_BYTES(bits)	(((bits) + 7) >> 3)
#define BYTES_TO_BITS(bytes)	((bytes) << 3)

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))
#define MAX_STR_LEN		256
#define CTX_TYPE_INVALID	9999
#define POLL_TIME		1000

#ifdef __cplusplus
}
#endif

#endif
