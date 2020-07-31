/* SPDX-License-Identifier: Apache-2.0 */
#include "hisi_sec.h"
#include "wd_cipher.h"

#define XTS_MODE_KEY_DIVISOR 2
#define SM4_KEY_SIZE         16
#define DES_KEY_SIZE	     8
#define DES3_3KEY_SIZE	     (3 * DES_KEY_SIZE)
#define MAX_CIPHER_KEY_SIZE  64

#define WD_POOL_MAX_ENTRIES  1024
#define DES_WEAK_KEY_NUM     4
static __u64 des_weak_key[DES_WEAK_KEY_NUM] = {0};

struct req_pool {
	struct wd_cipher_req *reqs[WD_POOL_MAX_ENTRIES];
	int head;
	int tail;
};

struct wd_async_req_pool {
	struct req_pool *pools;
	int pool_nums;
};

struct wd_cipher_setting {
	struct wd_ctx_config config;
	struct wd_sched      sched;
	void *sched_ctx;
	struct wd_cipher_driver *driver;
	void *priv;
	struct wd_async_req_pool pool;
};

struct wd_cipher_driver {
	char	*drv_name;
	char	*alg_name;
	int	(*init)(struct wd_ctx_config *config, void* priv);
	void	(*exit)(void* priv);
	int	(*cipher_send)(handle_t ctx, struct wd_cipher_msg *msg);
	int	(*cipher_recv)(handle_t ctx, struct wd_cipher_msg *msg);
	int	(*poll)(handle_t ctx, __u32 num);
};

static struct wd_cipher_driver wd_alg_cipher_list[] = {
	{
		.drv_name	= "hisi_sec2",
		.alg_name	= "cipher",
		.init		= hisi_sec_init,
		.exit		= hisi_sec_exit,
		.cipher_send	= hisi_sec_cipher_send,
		.cipher_recv	= hisi_sec_cipher_recv,
		.poll	= hisi_sec_poll,
	},
};

static struct wd_cipher_setting g_wd_cipher_setting;

handle_t wd_alg_cipher_alloc_sess(struct wd_cipher_sess_setup *setup)
{
	return 0;
}

void wd_alg_cipher_free_sess(handle_t handle)
{

}

int wd_do_cipher(handle_t handle, struct wd_cipher_req *req)
{
	//get ctx handle
	//build msg
	//call wd cipher setting

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
	int i;

	for (i = 0; i < DES_WEAK_KEY_NUM; i++) {
		if (*key == des_weak_key[i])
			return 1;
	}

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

static int copy_config_to_global_setting(struct wd_ctx_config *config)
{
	return 0;
}

static int copy_sched_to_global_setting(struct wd_sched *sched)
{
	return 0;
}

int wd_cipher_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	int ret;

	if (g_wd_cipher_setting.driver)
		return 0;

	if (!config || !sched)
		return -EINVAL;
	/* set config and sched */
	ret = copy_config_to_global_setting(config);
	if (ret < 0)
		return ret;

	ret = copy_sched_to_globak_setting(sched);
	if (ret < 0)
		return ret;

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
