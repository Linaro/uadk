/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */
#ifndef __WD_DIGEST_DRV_H
#define __WD_DIGEST_DRV_H

#include "../wd_digest.h"
#include "../wd_util.h"

#ifdef __cplusplus
extern "C" {
#endif

enum hash_block_type {
	HASH_FIRST_BLOCK,
	HASH_MIDDLE_BLOCK,
	HASH_END_BLOCK,
	HASH_SINGLE_BLOCK,
};

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
	/* partial bytes for stream mode */
	__u32 partial_bytes;

	/* input key pointer */
	__u8 *key;
	/* input iv pointer */
	__u8 *iv;
	/* input data pointer */
	__u8 *in;
	/* output data pointer */
	__u8 *out;
	/* partial pointer for stream mode */
	__u8 *partial_block;
	/* total of data for stream mode */
	__u64 long_data_len;
};

static inline enum hash_block_type get_hash_block_type(struct wd_digest_msg *msg)
{
	/*
	 *     [has_next , iv_bytes]
	 *     [    1    ,     0   ]   =   long hash(first bd)
	 *     [    1    ,     1   ]   =   long hash(middle bd)
	 *     [    0    ,     1   ]   =   long hash(end bd)
	 *     [    0    ,     0   ]   =   block hash(single bd)
	 */
	if (msg->has_next && !msg->iv_bytes)
		return HASH_FIRST_BLOCK;
	else if (msg->has_next && msg->iv_bytes)
		return HASH_MIDDLE_BLOCK;
	else if (!msg->has_next && msg->iv_bytes)
		return HASH_END_BLOCK;
	else
		return HASH_SINGLE_BLOCK;
}

#ifdef __cplusplus
}
#endif

#endif /* __WD_DIGEST_DRV_H */
