/* SPDX-License-Identifier: Apache-2.0 */
#include "hisi_sec.h"
#include "wd_cipher.h"

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
} wd_alg_cipher_list[] = {
	{
		.drv_name	= "hisi_sec",
		.alg_name	= "cipher",
		.init		= hisi_cipher_init,
		.exit		= hisi_cipher_exit,
		.prep		= hisi_cipher_prep,
		.fini		= hisi_cipher_fini,
		.set_key	= hisi_cipher_set_key,
		.encrypt	= hisi_cipher_encrypt,
		.decrypt	= hisi_cipher_decrypt,
		.async_poll	= hisi_cipher_poll,
	},
};

handle_t wd_alg_cipher_alloc_sess(char *alg_name, uint32_t mode,
				  wd_dev_mask_t *dev_mask)
{
	return 0;
}

void wd_alg_cipher_free_sess(handle_t handle)
{
}

int wd_alg_encrypt(handle_t handle, struct wd_cipher_arg *arg)
{
	return 0;
}

int wd_alg_decrypt(handle_t handle, struct wd_cipher_arg *arg)
{
	return 0;
}

int wd_alg_set_key(handle_t handle, __u8 *key, __u32 key_len)
{
	return 0;
}
