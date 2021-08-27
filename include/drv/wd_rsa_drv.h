/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_RSA_DRV_H
#define __WD_RSA_DRV_H

#include "../wd_rsa.h"

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
	__u64 tag; /* User-defined request identifier */
	__u16 key_bytes; /* Input key bytes */
	__u8 key_type; /* Denoted by enum wd_rsa_key_type */
	__u8 result; /* Data format, denoted by WD error code */
	__u8 *key; /* Input key VA pointer, should be DMA buffer */
};

struct wd_rsa_driver {
	const char *drv_name;
	const char *alg_name;
	__u32 drv_ctx_size;
	int (*init)(struct wd_ctx_config_internal *config, void *priv,
		    const char *alg_name);
	void (*exit)(void *priv);
	int (*send)(handle_t sess, struct wd_rsa_msg *msg);
	int (*recv)(handle_t sess, struct wd_rsa_msg *msg);
};

void wd_rsa_set_driver(struct wd_rsa_driver *drv);

#ifdef WD_STATIC_DRV
#define WD_RSA_SET_DRIVER(drv)						      \
extern const struct wd_rsa_driver wd_##drv __attribute__((alias(#drv)))
#else
#define WD_RSA_SET_DRIVER(drv)						      \
static void __attribute__((constructor)) set_driver_rsa(void)		      \
{									      \
	wd_rsa_set_driver(&drv);					      \
}
#endif

#endif /* __WD_RSA_DRV_H */
