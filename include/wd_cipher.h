/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_CIPHER_H
#define __WD_CIPHER_H

#include "config.h"
#include "wd.h"
#include "wd_alg_common.h"

/**
 * wd_cipher_op_type - Algorithm type of option
 */
enum wd_cipher_op_type {
	WD_CIPHER_ENCRYPTION,
	WD_CIPHER_DECRYPTION,
};
/**
 * wd_cipher_type - Algorithm type of cipher
 */
enum wd_cipher_alg {
	WD_CIPHER_SM4,
	WD_CIPHER_AES,
	WD_CIPHER_DES,
	WD_CIPHER_3DES,
};
/**
 * wd_cipher_mode - Algorithm mode of cipher
 */
enum wd_cipher_mode {
	WD_CIPHER_ECB,
	WD_CIPHER_CBC,
	WD_CIPHER_CTR,
	WD_CIPHER_XTS,
	WD_CIPHER_OFB,
	WD_CIPHER_CFB,
};

struct wd_cipher_sess_setup {
	enum wd_cipher_alg alg;
	enum wd_cipher_mode mode;
	enum wd_buff_type buff_type;
};

typedef void *wd_alg_cipher_cb_t(void *cb_param);

struct wd_cipher_sess {
	char			*alg_name;
	char			node_path[MAX_DEV_NAME_LEN + 1];
	wd_dev_mask_t		*dev_mask;
	struct wd_alg_cipher	*drv;
	__u32			mode;
	void			*priv;
};

struct wd_cipher_arg {
	void			*src;
	void			*dst;
	void			*iv;
	__u32			in_bytes;
	__u32			iv_bytes;
	__u32			out_bytes;
	wd_alg_cipher_cb_t	*cb;
	void			*cb_param;
};

extern handle_t wd_alg_cipher_alloc_sess(struct wd_cipher_sess_setup *setup,
					wd_dev_mask_t *dev_mask);
extern void wd_alg_cipher_free_sess(handle_t handle);
extern int wd_alg_do_cipher(handle_t handle, struct wd_cipher_arg *arg);
extern int wd_alg_encrypt(handle_t handle, struct wd_cipher_arg *arg);
extern int wd_alg_decrypt(handle_t handle, struct wd_cipher_arg *arg);
extern int wd_alg_set_key(handle_t handle, __u8 *key, __u32 key_len);

#endif /* __WD_CIPHER_H */
