/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_DH_DRV_H
#define __WD_DH_DRV_H

#include "../wd_dh.h"

/* DH message format */
struct wd_dh_msg {
	struct wd_dh_req req;
	__u64 tag; /* User-defined request identifier */
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
	int (*init)(struct wd_ctx_config_internal *config, void *priv);
	void (*exit)(void *priv);
	int (*send)(handle_t sess, struct wd_dh_msg *msg);
	int (*recv)(handle_t sess, struct wd_dh_msg *msg);
};

void wd_dh_set_driver(struct wd_dh_driver *drv);

#define WD_DH_SET_DRIVER(drv)						      \
extern const struct wd_dh_driver wd_##drv __attribute__((alias(#drv)));\
static void __attribute__((constructor)) set_driver_dh(void)		      \
{}

#endif /* __WD_DH_DRV_H */
