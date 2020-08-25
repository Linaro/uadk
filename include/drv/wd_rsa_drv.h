/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_RSA_DRV_H
#define __WD_RSA_DRV_H

#include "../wd_rsa.h"

struct wd_rsa_msg;

struct wd_rsa_driver {
	const char *drv_name;
	const char *alg_name;
	__u32 drv_ctx_size;
	int (*init)(struct wd_ctx_config *config, void *priv);
	void (*exit)(void *priv);
	int (*send)(handle_t sess, struct wd_rsa_msg *msg);
	int (*recv)(handle_t sess, struct wd_rsa_msg *msg);
};

/*
* to do: put wd_comp_msg temporarily, should be move to a internal head file
*        together with wd_comp_driver definition.
*/
/* RSA message format of Warpdrive */
struct wd_rsa_msg {
	struct wd_rsa_req req;
	__u64 tag; /* User-defined request identifier */
	__u16 key_bytes; /* Input key bytes */
	__u8 key_type; /* Denoted by enum wd_rsa_key_type */
	__u8 result; /* Data format, denoted by WD error code */
	__u8 *key; /* Input key VA pointer, should be DMA buffer */
};

void wd_rsa_set_driver(struct wd_rsa_driver *drv);

#define WD_RSA_SET_DRIVER(drv)						      \
extern const struct wd_rsa_driver wd_rsa_##drv __attribute__((alias(#drv)));\
static void __attribute__((constructor)) set_driver(void)		      \
{									      \
	wd_rsa_set_driver(&drv);					      \
}

#endif /* __WD_RSA_DRV_H */
