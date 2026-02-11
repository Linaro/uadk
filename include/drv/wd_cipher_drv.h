/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_CIPHER_DRV_H
#define __WD_CIPHER_DRV_H

#include <linux/types.h>

#include "../wd_cipher.h"
#include "../wd_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* fixme wd_cipher_msg */
struct wd_cipher_msg {
	struct wd_cipher_req req;
	/* request identifier */
	__u32 tag;
	/* Denoted by enum wcrypto_type */
	__u8 alg_type;
	/* Denoted by enum wcrypto_cipher_type */
	__u8 alg;
	/* Denoted by enum wcrypto_cipher_op_type */
	__u8 op_type;
	/* Denoted by enum wcrypto_cipher_mode_type */
	__u8 mode;
	/* Data format, include pbuffer and sgl */
	__u8 data_fmt;
	/* Operation result, denoted by WD error code */
	__u8 result;

	/* Key bytes */
	__u16 key_bytes;
	/* iv bytes */
	__u16 iv_bytes;
	/* in bytes */
	__u32 in_bytes;
	/* out_bytes */
	__u32 out_bytes;

	/* input key pointer */
	__u8 *key;
	/* input iv pointer */
	__u8 *iv;
	/* input data pointer */
	__u8 *in;
	/* output data pointer */
	__u8 *out;
	struct wd_mm_ops *mm_ops;
	enum wd_mem_type mm_type;
};

struct wd_cipher_msg *wd_cipher_get_msg(__u32 idx, __u32 tag);

#ifdef __cplusplus
}
#endif

#endif /* __WD_CIPHER_DRV_H */
