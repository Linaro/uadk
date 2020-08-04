/* SPDX-License-Identifier: Apache-2.0 */
#include "hisi_sec.h"
#include "wd_cipher.h"

#define XTS_MODE_KEY_DIVISOR	2
#define SM4_KEY_SIZE		16
#define DES_KEY_SIZE		8
#define DES3_3KEY_SIZE		(3 * DES_KEY_SIZE)
#define MAX_CIPHER_KEY_SIZE	64

#define WD_POOL_MAX_ENTRIES	1024
#define DES_WEAK_KEY_NUM	4
#define MAX_RETRY_COUNTS	200000000
static __u64 des_weak_key[DES_WEAK_KEY_NUM] = {0};

struct msg_pool {
	struct wd_cipher_msg *msg[WD_POOL_MAX_ENTRIES];
	int head;
	int tail;
};

struct wd_async_msg_pool {
	struct msg_pool *pools;
	int pool_nums;
};

struct wd_cipher_setting {
	struct wd_ctx_config config;
	struct wd_sched      sched;
	void *sched_ctx;
	struct wd_cipher_driver *driver;
	void *priv;
	struct wd_async_msg_pool pool;
};

struct wd_cipher_driver {
	const char	*drv_name;
	const char	*alg_name;
	__u32	drv_ctx_size;
	int	(*init)(struct wd_ctx_config *config, void* priv);
	void	(*exit)(void* priv);
	int	(*cipher_send)(handle_t ctx, struct wd_cipher_msg *msg);
	int	(*cipher_recv)(handle_t ctx, struct wd_cipher_msg *msg);
	int	(*poll)(handle_t ctx, __u32 num);
};

static struct wd_cipher_driver wd_cipher_driver_list[] = {
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

int wd_alg_set_key(struct wd_cipher_req *req, __u8 *key, __u32 key_len)
{
	__u16 length = key_len;
	int ret;

	if (!key || !req) {
		WD_ERR("%s inpupt param err!\n", __func__);
		return -EINVAL;
	}

	/* fix me: need check key_len */
	if (req->mode == WD_CIPHER_XTS)
		length = key_len / XTS_MODE_KEY_DIVISOR;

	ret = cipher_key_len_check(req->alg, length);
	if (ret) {
		WD_ERR("%s inpupt key length err!\n", __func__);
		return -EINVAL;
	}
	if (req->alg == WD_CIPHER_DES && is_des_weak_key((__u64 *)key, length)) {
		WD_ERR("%s: input des key is weak key!\n", __func__);
		return -EINVAL;
	}

	req->key_bytes = key_len;
	memcpy(req->key, key, key_len);

	return 0;
}
/* support cipher only */
static struct wd_cipher_driver *find_cipher_driver(const char *driver)
{
	const char *drv_name;
	bool found = false;

	if (!driver)
		return NULL;

	drv_name = wd_cipher_driver_list[0].drv_name;
	if (!strncmp(driver, drv_name, strlen(driver))) {
		found = true;
	}

	if (!found)
		return NULL;

	return &wd_cipher_driver_list[0];
}

static int copy_config_to_global_setting(struct wd_ctx_config *cfg)
{
	struct wd_ctx *ctxs;
	int i;

	if (cfg->ctx_num == 0)
		return -EINVAL;
	/*use malloc maybe better */
	ctxs = malloc(sizeof(struct wd_ctx) * cfg->ctx_num);
	if (!ctxs)
		return -ENOMEM;

	memset(ctxs, 0, sizeof(struct wd_ctx) * cfg->ctx_num);

	/* check every context */
	for (i = 0; i < cfg->ctx_num; i++) {
		if (!cfg->ctxs[i].ctx)
			return -EINVAL;
	}

	/* get ctxs from user set */
	memcpy(ctxs, cfg->ctxs, sizeof(struct wd_ctx) * cfg->ctx_num);
	g_wd_cipher_setting.config.ctxs = ctxs;
	/* fix me */
	g_wd_cipher_setting.config.priv = cfg->priv;
	g_wd_cipher_setting.config.ctx_num = cfg->ctx_num;

	return 0;
}

static int copy_sched_to_global_setting(struct wd_sched *sched)
{
	if (!sched->name || sched->sched_ctx_size <= 0)
		return -EINVAL;

	g_wd_cipher_setting.sched.name = strdup(sched->name);
	g_wd_cipher_setting.sched.sched_ctx_size = sched->sched_ctx_size;
	g_wd_cipher_setting.sched.pick_next_ctx = sched->pick_next_ctx;
	g_wd_cipher_setting.sched.poll_policy = sched->poll_policy;

	return 0;
}

static void clear_config_in_global_setting(void)
{
	g_wd_cipher_setting.config.ctx_num = 0;
	g_wd_cipher_setting.config.priv = NULL;
	free(g_wd_cipher_setting.config.ctxs);
}

static void clear_sched_in_global_setting(void)
{
	char *name = (char *)g_wd_cipher_setting.sched.name;

	free(name);
	g_wd_cipher_setting.sched.poll_policy = NULL;
	g_wd_cipher_setting.sched.pick_next_ctx = NULL;
	g_wd_cipher_setting.sched.sched_ctx_size = 0;
}

int wd_cipher_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	struct wd_cipher_driver *driver;
	const char *driver_name;
	handle_t h_ctx;
	void *priv;
	int ret;

	if (g_wd_cipher_setting.driver)
		return 0;

	if (!config || !sched)
		return -EINVAL;
	/* set config and sched */
	ret = copy_config_to_global_setting(config);
	if (ret < 0) {
		WD_ERR("Fail to copy configuration to global setting!\n");
		return ret;
	}

	ret = copy_sched_to_global_setting(sched);
	if (ret < 0) {
		WD_ERR("Fail to copy schedule to global setting!\n");
		goto out;
	}

	/* find driver and set driver */
	h_ctx = config->ctxs[0].ctx; // like a q from wd v1
	driver_name = wd_get_driver_name(h_ctx);
	driver = find_cipher_driver(driver_name);
	g_wd_cipher_setting.driver = driver;

	/* alloc sched context memory */
	g_wd_cipher_setting.sched_ctx = calloc(1, sched->sched_ctx_size);
	if (!g_wd_cipher_setting.sched_ctx) {
		ret = -ENOMEM;
		goto out_sched;
	}
	/* init sysnc request pool */
	ret = wd_init_async_request_pool(&g_wd_cipher_setting.pool);
	if (ret)
		goto out_pool;
	/* init ctx related resources in specific driver */
	priv = calloc(1, g_wd_cipher_setting.driver->drv_ctx_size);
	if (!priv) {
		ret = -ENOMEM;
		goto out_priv;
	}
	g_wd_cipher_setting.priv = priv;
	/* sec init */
	ret = g_wd_cipher_setting.driver->init(&g_wd_cipher_setting.config, priv);
	if (ret < 0)
		goto out_init;

	return 0;
out_init:
	free(priv);
out_priv:
	wd_uninit_async_request_pool(&g_wd_cipher_setting.pool);
out_pool:
	free(g_wd_cipher_setting.sched_ctx);
out_sched:
	clear_sched_in_global_setting();
out:
	clear_config_in_global_setting();

	return ret;
}

void wd_cipher_uninit(void)
{
	clear_sched_in_global_setting();
	clear_config_in_global_setting();
}

int wd_alg_cipher_poll(handle_t handle, __u32 count)
{
	return 0;
}

static void fill_request_msg(struct wd_cipher_msg *msg, struct wd_cipher_req *req)
{
	msg->in = req->src;
	msg->in_bytes = req->in_bytes;
	msg->out = req->dst;
	msg->out_bytes = req->out_bytes;
	msg->key = req->key;
	msg->key_bytes = req->key_bytes;
	msg->op_type = req->op_type;
	msg->iv = req->iv;
	msg->iv_bytes = req->iv_bytes;
}

int wd_do_cipher(handle_t sess, struct wd_cipher_req *req)
{
	struct wd_ctx_config *config = &g_wd_cipher_setting.config;
	void *sched_ctx = g_wd_cipher_setting.sched_ctx;
	struct wd_cipher_msg msg, recv_msg;
	__u64 recv_cnt = 0;
	handle_t h_ctx;
	int ret;

	h_ctx = g_wd_cipher_setting.sched.pick_next_ctx(config, sched_ctx, req, 0);

	/* fill cipher requset msg */
	fill_request_msg(&msg, req);
	/* send bd */
	ret = g_wd_cipher_setting.driver->cipher_send(h_ctx, &msg);
	if (ret) {
		WD_ERR("wd send err!\n");
		return ret;
	}

	do {
		ret = g_wd_cipher_setting.driver->cipher_recv(h_ctx, &recv_msg);
		if (ret == -WD_HW_EACCESS) {
			WD_ERR("wd recv err!\n");
			goto recv_err;
		} else if ((ret == -WD_EBUSY) || (ret == -EAGAIN)) {
			if (++recv_cnt > MAX_RETRY_COUNTS) {
				WD_ERR("wd recv timeout fail!\n");
				ret = -ETIMEDOUT;
				goto recv_err;
			}
		}
	} while(ret < 0);

	/* get out */
	//req.dst = recv_msg.out;

	return 0;
recv_err:
	return ret;
}
