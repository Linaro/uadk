/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */
#ifndef __WD_RSA_DRV_H
#define __WD_RSA_DRV_H

#include <linux/types.h>

#include "../wd_rsa.h"
#include "../wd_util.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wd_rsa_kg_in {
	__u8 *e;
	__u8 *p;
	__u8 *q;
	__u32 ebytes;
	__u32 pbytes;
	__u32 qbytes;
	__u32 key_size;
	void *data[];
};

struct wd_rsa_kg_out {
	__u8 *d;
	__u8 *n;
	__u8 *qinv;
	__u8 *dq;
	__u8 *dp;
	__u32 key_size;
	__u32 dbytes;
	__u32 nbytes;
	__u32 dpbytes;
	__u32 dqbytes;
	__u32 qinvbytes;
	__u32 size;
	void *data[];
};

/* RSA message format */
struct wd_rsa_msg {
	struct wd_rsa_req req;
	struct wd_mm_ops *mm_ops;
	enum wd_mem_type mm_type;
	__u32 tag; /* User-defined request identifier */
	__u16 key_bytes; /* Input key bytes */
	__u8 key_type; /* Denoted by enum wd_rsa_key_type */
	__u8 result; /* Data format, denoted by WD error code */
	__u8 *key; /* Input key VA pointer, should be DMA buffer */
	__u8 *rsv_out; /* reserved output data pointer */
};

struct wd_rsa_msg *wd_rsa_get_msg(__u32 idx, __u32 tag);

#ifdef __cplusplus
}
#endif

#endif /* __WD_RSA_DRV_H */
