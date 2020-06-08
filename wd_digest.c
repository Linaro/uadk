/* SPDX-License-Identifier: Apache-2.0 */
#include "hisi_sec.h"
#include "wd_digest.h"

struct wd_alg_digest {
	char	*drv_name;
	char	*alg_name;
	int	(*init)(struct wd_digest_sess *sess);
	void	(*exit)(struct wd_digest_sess *sess);
	int	(*prep)(struct wd_digest_sess *sess, struct wd_digest_arg *arg);
	void	(*fini)(struct wd_digest_sess *sess);
	int	(*set_key)(struct wd_digest_sess *sess, const __u8 *key, __u32 key_len);
	int	(*digest)(struct wd_digest_sess *sess, struct wd_digest_arg *arg);
	int	(*async_poll)(struct wd_digest_sess *sess, struct wd_digest_arg *arg);
} wd_alg_digest_list[] = {
	{
		.drv_name	= "hisi_sec",
		.alg_name	= "??", /* fix me */
		.init		= hisi_digest_init,
		.exit		= hisi_digest_exit,
		.prep		= hisi_digest_prep,
		.fini		= hisi_digest_fini,
		.set_key	= hisi_digest_set_key,
		.digest		= hisi_digest_digest,
		.async_poll	= hisi_digest_poll,
	},
};

handle_t wd_alg_digest_alloc_sess(struct wd_digest_sess_setup *setup,
				  wd_dev_mask_t *dev_mask)
{
	return 0;
}

void wd_alg_digest_free_sess(handle_t handle)
{
}

int wd_alg_do_digest(handle_t handle, struct wd_digest_arg *arg)
{
	return 0;
}

int wd_alg_set_digest_key(handle_t handle, __u8 *key, __u32 key_len)
{
	return 0;
}

int wd_alg_digest_poll(handle_t handle, __u32 count)
{
	return 0;
}
