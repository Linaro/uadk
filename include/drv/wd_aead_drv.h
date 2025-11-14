/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_AEAD_DRV_H
#define __WD_AEAD_DRV_H

#include "../wd_aead.h"
#include "../wd_util.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wd_aead_msg {
	struct wd_aead_req req;
	/* Request identifier */
	__u32 tag;
	/* Denoted by enum wcrypto_type */
	__u8 alg_type;
	/* Denoted by enum wcrypto_cipher_type */
	__u8 calg;
	/* Denoted by enum wcrypto_cipher_mode_type */
	__u8 cmode;
	/* Denoted by enum wcrypto_digest_type */
	__u8 dalg;
	/* Denoted by enum wcrypto_digest_mode_type */
	__u8 dmode;
	/* Denoted by enum wcrypto_aead_op_type */
	__u8 op_type;
	/* Data format, include pbuffer and sgl */
	__u8 data_fmt;
	/* Operation result, denoted by WD error code */
	__u8 result;

	/* in bytes */
	__u32 in_bytes;
	/* out_bytes */
	__u32 out_bytes;
	/* iv bytes */
	__u16 iv_bytes;
	/* cipher key bytes */
	__u16 ckey_bytes;
	/* authentication key bytes */
	__u16 akey_bytes;
	/* Input associated data bytes */
	__u16 assoc_bytes;
	/* Outpue authentication bytes */
	__u16 auth_bytes;

	/* input cipher key pointer */
	__u8 *ckey;
	/* input authentication key pointer */
	__u8 *akey;
	/* input iv pointer */
	__u8 *iv;
	/* input auth iv pointer */
	__u8 *aiv;
	/* input data pointer */
	__u8 *in;
	/* output data pointer */
	__u8 *out;
	/* mac */
	__u8 *mac;
	/* mac data pointer for decrypto as stream mode */
	__u8 *dec_mac;
	/* total of data for stream mode */
	__u64 long_data_len;
	enum wd_aead_msg_state msg_state;
	struct wd_mm_ops *mm_ops;
	enum wd_mem_type mm_type;
	void *drv_cfg; /* internal driver configuration */
};

struct wd_aead_aiv_addr {
	__u8 *aiv;
	__u8 *aiv_status;
	__u8 *aiv_nosva;
};

struct wd_aead_extend_ops {
	void *params;
	int (*eops_aiv_init)(struct wd_alg_driver *drv,
			     struct wd_mm_ops *mm_ops,
			     void **params);
	void (*eops_aiv_uninit)(struct wd_alg_driver *drv,
				struct wd_mm_ops *mm_ops,
				void *params);
};

struct wd_aead_msg *wd_aead_get_msg(__u32 idx, __u32 tag);

#ifdef __cplusplus
}
#endif

#endif /* __WD_AEAD_DRV_H */
