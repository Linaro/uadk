/* SPDX-License-Identifier: Apache-2.0 */
#include "hisi_sec.h"
#include "wd_cipher.h"

#define XTS_MODE_KEY_DIVISOR 2
#define SM4_KEY_SIZE         16
#define DES_KEY_SIZE	     8
#define DES3_3KEY_SIZE	     (3 * DES_KEY_SIZE)
#define MAX_CIPHER_KEY_SIZE  64

struct wd_alg_cipher {
	char	*drv_name;
	char	*alg_name;
	int	(*init)(struct wd_ctx_config *config, void* priv);
	void	(*exit)(void* priv);
	int	(*poll)(handle_t ctx, __u32 num);
}

wd_alg_cipher_list[] = {
	{
		.drv_name	= "hisi_sec2",
		.alg_name	= "cipher",
		.init		= hisi_sec_init,
		.exit		= hisi_sec_exit,
		.poll	= hisi_sec_poll,
	},
};

handle_t wd_alg_cipher_alloc_sess(struct wd_cipher_sess_setup *setup)
{
	return 0;
}

void wd_alg_cipher_free_sess(handle_t handle)
{

}

int wd_alg_do_cipher(handle_t handle, struct wd_cipher_arg *arg)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)handle;

	return 0;
}

int wd_alg_encrypt(handle_t handle, struct wd_cipher_arg *arg)
{
	return 0;
}

int wd_alg_decrypt(handle_t handle, struct wd_cipher_arg *arg)
{
	return 0;
}

static int is_des_weak_key(const __u64 *key, __u16 keylen)
{
	return 0;
}

static int aes_key_len_check(__u16 length)
{
	switch (length) {
		case AES_KEYSIZE_128:
		case AES_KEYSIZE_192:
		case AES_KEYSIZE_256:
			return 0;
		default:
			return -EINVAL;
	}
}

static int cipher_key_len_check(enum wd_cipher_alg alg, __u16 length)
{
	int ret = 0;

	switch (alg) {
	case WD_CIPHER_SM4:
		if (length != SM4_KEY_SIZE)
			ret = -EINVAL;
		break;
	case WD_CIPHER_AES:
		ret = aes_key_len_check(length);
		break;
	case WD_CIPHER_DES:
		if (length != DES_KEY_SIZE)
			ret = -EINVAL;
		break;
	case WD_CIPHER_3DES:
		if (length != DES3_3KEY_SIZE)
			ret = -EINVAL;
		break;
	default:
		WD_ERR("%s: input alg err!\n", __func__);
		return -EINVAL;
	}

	return ret;
}

int wd_alg_set_key(handle_t handle, __u8 *key, __u32 key_len)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)handle;
	__u16 length = key_len;
	int ret;

	if (!key || !sess) {
		WD_ERR("%s inpupt param err!\n", __func__);
		return -EINVAL;
	}

	/* fix me: need check key_len */
	if (sess->mode == WD_CIPHER_XTS)
		length = key_len / XTS_MODE_KEY_DIVISOR;

	ret = cipher_key_len_check(sess->alg, length);
	if (ret) {
		WD_ERR("%s inpupt key length err!\n", __func__);
		return -EINVAL;
	}
	if (sess->mode == WD_CIPHER_DES && is_des_weak_key(key, length)) {
		WD_ERR("%s: input des key is weak key!\n", __func__);
		return -EINVAL;
	}

	return 0;
}

int wd_cipher_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	return 0;
}

void wd_cipher_uninit(void)
{

}

int wd_alg_cipher_poll(handle_t handle, __u32 count)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)handle;

	return 0;
}
