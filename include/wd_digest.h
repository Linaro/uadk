/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_DIGEST_H
#define __WD_DIGEST_H

#include "config.h"
#include "wd.h"

typedef void *wd_alg_digest_cb_t(void *cb_param);

struct wd_alg_digest;

struct wd_digest_sess {
	char			*alg_name;
	char			node_path[MAX_DEV_NAME_LEN + 1];
	wd_dev_mask_t		*dev_mask;
	struct wd_alg_digest	*drv;
	__u32			mode;
	void			*priv;
};

/* fix me */
struct wd_digest_arg {
	void			*src;
	void			*dst;
	void			*iv;
	__u32			cryptlen;
	wd_alg_digest_cb_t	*cb;
	void			*cb_param;
};

/* fix me */
struct wd_alg_digest {
	char	*drv_name;
	char	*alg_name;
	int	(*init)(struct wd_digest_sess *sess);
	void	(*exit)(struct wd_digest_sess *sess);
	int	(*prep)(struct wd_digest_sess *sess,
			struct wd_digest_arg *arg);
	void	(*fini)(struct wd_digest_sess *sess);
	int	(*set_key)(struct wd_digest_sess *sess, const __u8 *key,
			   __u32 key_len);
	int	(*encrypt)(struct wd_digest_sess *sess,
			   struct wd_digest_arg *arg);
	int	(*decrypt)(struct wd_digest_sess *sess,
			   struct wd_digest_arg *arg);
	int	(*async_poll)(struct wd_digest_sess *sess,
			      struct wd_digest_arg *arg);
};

extern handle_t wd_alg_digest_alloc_sess(char *alg_name, uint32_t mode,
					 wd_dev_mask_t *dev_mask);
extern void wd_alg_digest_free_sess(handle_t handle);
extern int wd_alg_do_digest(handle_t handle, struct wd_digest_arg *arg);
extern int wd_alg_set_digest_key(handle_t handle, __u8 *key, __u32 key_len);

#endif /* __WD_DIGEST_H */
