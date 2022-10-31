/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved. */

#ifndef __WD_DH_DRV_H
#define __WD_DH_DRV_H

#include <asm/types.h>
#include "../wd_alg_common.h"
#include "../wd_dh.h"

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

struct wd_dh_driver {
	const char *drv_name;
	const char *alg_name;
	__u32 drv_ctx_size;
	int (*init)(struct wd_ctx_config_internal *config, void *priv,
		    const char *alg_name);
	void (*exit)(void *priv);
	int (*send)(handle_t sess, void *dh_msg);
	int (*recv)(handle_t sess, void *dh_msg);
};

void wd_dh_set_driver(struct wd_dh_driver *drv);
struct wd_dh_driver *wd_dh_get_driver(void);
struct wd_dh_msg *wd_dh_get_msg(__u32 idx, __u32 tag);

#ifdef WD_STATIC_DRV
#define WD_DH_SET_DRIVER(drv)						\
struct wd_dh_driver *wd_dh_get_driver(void)				\
{									\
	return &drv;							\
}
#else
#define WD_DH_SET_DRIVER(drv)						\
void __attribute__((constructor)) set_driver_dh(void)		\
{									\
	wd_dh_set_driver(&(drv));						\
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* __WD_DH_DRV_H */
