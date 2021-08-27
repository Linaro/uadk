/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_DIGEST_DRV_H
#define __WD_DIGEST_DRV_H

#include "include/wd_digest.h"
#include "include/wd_alg_common.h"

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
};

struct wd_digest_driver {
	const char	*drv_name;
	const char	*alg_name;
	__u32	drv_ctx_size;
	int	(*init)(struct wd_ctx_config_internal *config, void *priv);
	void	(*exit)(void *priv);
	int	(*digest_send)(handle_t ctx, struct wd_digest_msg *msg);
	int	(*digest_recv)(handle_t ctx, struct wd_digest_msg *msg);
};

void wd_digest_set_driver(struct wd_digest_driver *drv);

#ifdef WD_STATIC_DRV
#define WD_DIGEST_SET_DRIVER(drv)					      \
extern const struct wd_digest_driver wd_digest_##drv __attribute__((alias(#drv)));

#else
#define WD_DIGEST_SET_DRIVER(drv)					      \
static void __attribute__((constructor)) set_drivers(void)		      \
{									      \
	wd_digest_set_driver(&drv);					      \
}
#endif
#endif /* __WD_DIGEST_DRV_H */
