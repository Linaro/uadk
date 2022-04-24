/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_AEAD_DRV_H
#define __WD_AEAD_DRV_H

#include "../wd_common.h"
#include "../wd_alg_common.h"
#include "../wd_aead.h"

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
	__u8 aiv[MAX_IV_SIZE];
	/* input data pointer */
	__u8 *in;
	/* output data pointer */
	__u8 *out;
	/* mac */
	__u8 *mac;
};

struct wd_aead_driver {
	const char	*drv_name;
	const char	*alg_name;
	__u32	drv_ctx_size;
	int	(*init)(struct wd_ctx_config_internal *config, void *priv);
	void	(*exit)(void *priv);
	int	(*aead_send)(handle_t ctx, struct wd_aead_msg *msg);
	int	(*aead_recv)(handle_t ctx, struct wd_aead_msg *msg);
};

void wd_aead_set_driver(struct wd_aead_driver *drv);
struct wd_aead_driver *wd_aead_get_driver(void);

#ifdef WD_STATIC_DRV
#define WD_AEAD_SET_DRIVER(drv)					      \
struct wd_aead_driver *wd_aead_get_driver(void)			\
{									\
	return &drv;							\
}
#else
#define WD_AEAD_SET_DRIVER(drv)				              \
static void __attribute__((constructor)) set_aead_driver(void)		      \
{									      \
	wd_aead_set_driver(&(drv));					      \
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* __WD_AEAD_DRV_H */
