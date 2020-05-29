/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_CIPHER_H
#define __WD_CIPHER_H

#include "config.h"
#include "wd.h"

typedef void *wd_alg_cipher_cb_t(void *cb_param);

struct wd_alg_cipher;

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
	__u32			cryptlen;
	wd_alg_cipher_cb_t	*cb;
	void			*cb_param;
};

struct wd_alg_cipher {
	char	*drv_name;
	char	*alg_name;
	int	(*init)(struct wd_cipher_sess *sess);
	void	(*exit)(struct wd_cipher_sess *sess);
	int	(*prep)(struct wd_cipher_sess *sess,
			struct wd_cipher_arg *arg);
	void	(*fini)(struct wd_cipher_sess *sess);
	int	(*set_key)(struct wd_cipher_sess *sess, const __u8 *key,
			   __u32 key_len);
	int	(*encrypt)(struct wd_cipher_sess *sess,
			   struct wd_cipher_arg *arg);
	int	(*decrypt)(struct wd_cipher_sess *sess,
			   struct wd_cipher_arg *arg);
	int	(*async_poll)(struct wd_cipher_sess *sess,
			      struct wd_cipher_arg *arg);
};

extern handle_t wd_alg_cipher_alloc_sess(char *alg_name, uint32_t mode,
					wd_dev_mask_t *dev_mask);
extern void wd_alg_cipher_free_sess(handle_t handle);
extern int wd_alg_encrypt(handle_t handle, struct wd_cipher_arg *arg);
extern int wd_alg_decrypt(handle_t handle, struct wd_cipher_arg *arg);
extern int wd_alg_set_key(handle_t handle, __u8 *key, __u32 key_len);

#endif /* __WD_CIPHER_H */
