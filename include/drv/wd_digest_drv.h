/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */
#ifndef __WD_DIGEST_DRV_H
#define __WD_DIGEST_DRV_H

#include "../wd_digest.h"
#include "../wd_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* fixme wd_digest_msg */
struct wd_digest_msg {
	struct wd_digest_req req;
	/* request identifier */
	__u32 tag;
	/* Denoted by enum wcrypto_type */
	__u8 alg_type;
	/* Denoted by enum wcrypto_digest_type */
	__u8 alg;
	/* is there next block data */
	__u8 has_next;
	/* Denoted by enum wcrypto_digest_mode_type */
	__u8 mode;
	/* Data format, include pbuffer and sgl */
	__u8 data_fmt;
	/* Operation result, denoted by WD error code */
	__u8 result;
	/* user identifier: struct wcrypto_cb_tag */
	__u64 usr_data;

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
	/* total of data for stream mode */
	__u64 long_data_len;
};

struct wd_digest_msg *wd_digest_get_msg(__u32 idx, __u32 tag);

#ifdef __cplusplus
}
#endif

#endif /* __WD_DIGEST_DRV_H */
