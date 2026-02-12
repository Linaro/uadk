/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_UDMA_DRV_H
#define __WD_UDMA_DRV_H

#include <linux/types.h>

#include "../wd_udma.h"
#include "../wd_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* udma message format */
struct wd_udma_msg {
	struct wd_udma_req req;
	struct wd_data_addr *src;
	struct wd_data_addr *dst;
	int addr_num;
	int value;
	enum wd_udma_op_type op_type;
	__u32 tag; /* User-defined request identifier */
	__u8 result; /* alg op error code */
};

struct wd_udma_msg *wd_udma_get_msg(__u32 idx, __u32 tag);

#ifdef __cplusplus
}
#endif

#endif /* __WD_UDMA_DRV_H */
