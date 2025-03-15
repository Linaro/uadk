/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_DH_DRV_H
#define __WD_DH_DRV_H

#include <asm/types.h>

#include "../wd_dh.h"
#include "../wd_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* DH message format */
struct wd_dh_msg {
	struct wd_dh_req req;
	__u32 tag; /* User-defined request identifier */
	void *g;
	__u16 gbytes;
	__u16 key_bytes; /* Input key bytes */
	__u8 is_g2;
	__u8 result; /* Data format, denoted by WD error code */
};

#ifdef __cplusplus
}
#endif

#endif /* __WD_DH_DRV_H */
