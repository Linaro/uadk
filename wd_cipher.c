/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include "include/drv/wd_cipher_drv.h"
#include "wd_cipher.h"

#define XTS_MODE_KEY_DIVISOR	2
#define SM4_KEY_SIZE		16
#define DES_KEY_SIZE		8
#define DES3_2KEY_SIZE		(2 * DES_KEY_SIZE)
#define DES3_3KEY_SIZE		(3 * DES_KEY_SIZE)
#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32

#define WD_POOL_MAX_ENTRIES	1024
#define DES_WEAK_KEY_NUM	16

static const unsigned char des_weak_keys[DES_WEAK_KEY_NUM][DES_KEY_SIZE] = {
	/* weak keys */
	{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
	{0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE},
	{0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E},
	{0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1},
	/* semi-weak keys */
	{0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE},
	{0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01},
	{0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1},
	{0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E},
	{0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1},
	{0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01},
	{0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE},
	{0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E},
	{0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E},
	{0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01},
	{0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE},
	{0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1}
};

static char *wd_cipher_alg_name[WD_CIPHER_ALG_TYPE_MAX][WD_CIPHER_MODE_TYPE_MAX] = {
	{"ecb(sm4)", "cbc(sm4)", "ctr(sm4)", "xts(sm4)", "ofb(sm4)",
	 "cfb(sm4)", "cbc-cs1(sm4)", "cbc-cs2(sm4)", "cbc-cs3(sm4)"},
	{"ecb(aes)", "cbc(aes)", "ctr(aes)", "xts(aes)", "ofb(aes)",
	 "cfb(aes)", "cbc-cs1(aes)", "cbc-cs2(aes)", "cbc-cs3(aes)"},
	{"cbc(des)", "ecb(des)",},
	{"cbc(des3_ede)", "ecb(des3_ede)",}
};

struct wd_cipher_setting {
	enum wd_status status;
	struct wd_ctx_config_internal config;
	struct wd_sched      sched;
	struct wd_async_msg_pool pool;
	struct wd_alg_driver *driver;
	void *priv;
	void *dlhandle;
	void *dlh_list;
} wd_cipher_setting;

struct wd_cipher_sess {
	char			*alg_name;
	enum wd_cipher_alg	alg;
	enum wd_cipher_mode	mode;
	wd_dev_mask_t		*dev_mask;
	struct wd_alg_cipher	*drv;
	void			*priv;
	unsigned char		key[MAX_CIPHER_KEY_SIZE];
	__u32			key_bytes;
	void			*sched_key;
};

struct wd_env_config wd_cipher_env_config;
static struct wd_init_attrs wd_cipher_init_attrs;

static void wd_cipher_close_driver(void)
{
	if (wd_cipher_setting.dlhandle) {
		wd_release_drv(wd_cipher_setting.driver);
		dlclose(wd_cipher_setting.dlhandle);
		wd_cipher_setting.dlhandle = NULL;
	}
}

static int wd_cipher_open_driver(void)
{
	struct wd_alg_driver *driver = NULL;
	const char *alg_name = "cbc(aes)";
	char lib_path[PATH_STR_SIZE];
	int ret;

	/*
	 * Compatible with the normal acquisition of device
	 * drivers in the init interface
	 */
	if (wd_cipher_setting.dlh_list)
		return 0;

	ret = wd_get_lib_file_path("libhisi_sec.so", lib_path, false);
	if (ret)
		return ret;

	wd_cipher_setting.dlhandle = dlopen(lib_path, RTLD_NOW);
	if (!wd_cipher_setting.dlhandle) {
		WD_ERR("failed to open libhisi_sec.so, %s\n", dlerror());
		return -WD_EINVAL;
	}

	driver = wd_request_drv(alg_name, false);
	if (!driver) {
		wd_cipher_close_driver();
		WD_ERR("failed to get %s driver support\n", alg_name);
		return -WD_EINVAL;
	}

	wd_cipher_setting.driver = driver;

	return 0;
}

static bool is_des_weak_key(const __u8 *key)
{
	int i;

	for (i = 0; i < DES_WEAK_KEY_NUM; i++) {
		if (memcmp(des_weak_keys[i], key, DES_KEY_SIZE) == 0)
			return true;
	}

	return false;
}

static int aes_key_len_check(__u32 length)
{
	switch (length) {
	case AES_KEYSIZE_128:
	case AES_KEYSIZE_192:
	case AES_KEYSIZE_256:
		return 0;
	default:
		return -WD_EINVAL;
	}
}

static int cipher_key_len_check(struct wd_cipher_sess *sess, __u32 length)
{
	int ret = 0;

	if (sess->mode == WD_CIPHER_XTS && length == AES_KEYSIZE_192) {
		WD_ERR("unsupported XTS key length, length = %u\n", length);
		return -WD_EINVAL;
	}

	switch (sess->alg) {
	case WD_CIPHER_SM4:
		if (length != SM4_KEY_SIZE)
			ret = -WD_EINVAL;
		break;
	case WD_CIPHER_AES:
		ret = aes_key_len_check(length);
		break;
	case WD_CIPHER_DES:
		if (length != DES_KEY_SIZE)
			ret = -WD_EINVAL;
		break;
	case WD_CIPHER_3DES:
		if (length != DES3_2KEY_SIZE && length != DES3_3KEY_SIZE)
			ret = -WD_EINVAL;
		break;
	default:
		WD_ERR("cipher input alg err, alg = %d\n", sess->alg);
		return -WD_EINVAL;
	}

	return ret;
}

int wd_cipher_set_key(handle_t h_sess, const __u8 *key, __u32 key_len)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)h_sess;
	__u32 length = key_len;
	int ret;

	if (!key || !sess) {
		WD_ERR("invalid: cipher set key input param err!\n");
		return -WD_EINVAL;
	}

	if (sess->mode == WD_CIPHER_XTS)
		length = key_len / XTS_MODE_KEY_DIVISOR;

	ret = cipher_key_len_check(sess, length);
	if (ret) {
		WD_ERR("cipher set key input key length err!\n");
		return -WD_EINVAL;
	}
	if (sess->alg == WD_CIPHER_DES && is_des_weak_key(key)) {
		WD_ERR("input des key is weak key!\n");
		return -WD_EINVAL;
	}

	sess->key_bytes = key_len;
	memcpy(sess->key, key, key_len);

	return 0;
}

handle_t wd_cipher_alloc_sess(struct wd_cipher_sess_setup *setup)
{
	struct wd_cipher_sess *sess = NULL;
	bool ret;

	if (unlikely(!setup)) {
		WD_ERR("invalid: cipher input setup is NULL!\n");
		return (handle_t)0;
	}

	sess = malloc(sizeof(struct wd_cipher_sess));
	if (!sess) {
		WD_ERR("failed to alloc session memory!\n");
		return (handle_t)0;
	}
	memset(sess, 0, sizeof(struct wd_cipher_sess));

	if (setup->alg >= WD_CIPHER_ALG_TYPE_MAX ||
	     setup->mode >= WD_CIPHER_MODE_TYPE_MAX) {
		WD_ERR("failed to check algorithm!\n");
		return (handle_t)0;
	}
	sess->alg_name = wd_cipher_alg_name[setup->alg][setup->mode];
	sess->alg = setup->alg;
	sess->mode = setup->mode;
	ret = wd_drv_alg_support(sess->alg_name, wd_cipher_setting.driver);
	if (!ret) {
		WD_ERR("failed to support this algorithm: %s!\n", sess->alg_name);
		goto err_sess;
	}

	/* Some simple scheduler don't need scheduling parameters */
	sess->sched_key = (void *)wd_cipher_setting.sched.sched_init(
		wd_cipher_setting.sched.h_sched_ctx, setup->sched_param);
	if (WD_IS_ERR(sess->sched_key)) {
		WD_ERR("failed to init session schedule key!\n");
		goto err_sess;
	}

	return (handle_t)sess;

err_sess:
	if (sess->sched_key)
		free(sess->sched_key);
	free(sess);
	return (handle_t)0;
}

void wd_cipher_free_sess(handle_t h_sess)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)h_sess;

	if (unlikely(!sess)) {
		WD_ERR("invalid: cipher input h_sess is NULL!\n");
		return;
	}

	wd_memset_zero(sess->key, MAX_CIPHER_KEY_SIZE);

	if (sess->sched_key)
		free(sess->sched_key);
	free(sess);
}

static void wd_cipher_clear_status(void)
{
	wd_alg_clear_init(&wd_cipher_setting.status);
}

static int wd_cipher_common_init(struct wd_ctx_config *config,
	struct wd_sched *sched)
{
	int ret;

	ret = wd_set_epoll_en("WD_CIPHER_EPOLL_EN",
			      &wd_cipher_setting.config.epoll_en);
	if (ret < 0)
		return ret;

	ret = wd_init_ctx_config(&wd_cipher_setting.config, config);
	if (ret < 0)
		return ret;

	ret = wd_init_sched(&wd_cipher_setting.sched, sched);
	if (ret < 0)
		goto out_clear_ctx_config;

	/* allocate async pool for every ctx */
	ret = wd_init_async_request_pool(&wd_cipher_setting.pool,
					 config->ctx_num, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_cipher_msg));
	if (ret < 0)
		goto out_clear_sched;

	ret = wd_alg_init_driver(&wd_cipher_setting.config,
					wd_cipher_setting.driver,
					&wd_cipher_setting.priv);
	if (ret)
		goto out_clear_pool;

	return 0;

out_clear_pool:
	wd_uninit_async_request_pool(&wd_cipher_setting.pool);
out_clear_sched:
	wd_clear_sched(&wd_cipher_setting.sched);
out_clear_ctx_config:
	wd_clear_ctx_config(&wd_cipher_setting.config);
	return ret;
}

static void wd_cipher_common_uninit(void)
{
	void *priv = wd_cipher_setting.priv;

	if (!priv)
		return;

	/* uninit async request pool */
	wd_uninit_async_request_pool(&wd_cipher_setting.pool);

	/* unset config, sched, driver */
	wd_clear_sched(&wd_cipher_setting.sched);

	wd_alg_uninit_driver(&wd_cipher_setting.config,
		 wd_cipher_setting.driver, &priv);
}

int wd_cipher_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	bool flag;
	int ret;

	pthread_atfork(NULL, NULL, wd_cipher_clear_status);

	flag = wd_alg_try_init(&wd_cipher_setting.status);
	if (!flag)
		return -WD_EEXIST;

	ret = wd_init_param_check(config, sched);
	if (ret)
		goto out_clear_init;

	ret = wd_cipher_open_driver();
	if (ret)
		goto out_clear_init;

	ret = wd_cipher_common_init(config, sched);
	if (ret)
		goto out_close_driver;

	wd_alg_set_init(&wd_cipher_setting.status);

	return 0;

out_close_driver:
	wd_cipher_close_driver();
out_clear_init:
	wd_alg_clear_init(&wd_cipher_setting.status);
	return ret;
}

void wd_cipher_uninit(void)
{
	wd_cipher_common_uninit();

	wd_cipher_close_driver();
	wd_alg_clear_init(&wd_cipher_setting.status);
}

int wd_cipher_init2_(char *alg, __u32 sched_type, int task_type, struct wd_ctx_params *ctx_params)
{
	struct wd_ctx_nums cipher_ctx_num[WD_CIPHER_DECRYPTION + 1] = {0};
	struct wd_ctx_params cipher_ctx_params = {0};
	int ret = 0;
	bool flag;

	pthread_atfork(NULL, NULL, wd_cipher_clear_status);

	flag = wd_alg_try_init(&wd_cipher_setting.status);
	if (!flag)
		return -WD_EEXIST;

	if (!alg || sched_type > SCHED_POLICY_BUTT ||
	     task_type < 0 || task_type > TASK_MAX_TYPE) {
		WD_ERR("invalid: input param is wrong!\n");
		ret = -WD_EINVAL;
		goto out_uninit;
	}

	/*
	 * Driver lib file path could set by env param.
	 * than open tham by wd_dlopen_drv()
	 * use NULL means dynamic query path
	 */
	wd_cipher_setting.dlh_list = wd_dlopen_drv(NULL);
	if (!wd_cipher_setting.dlh_list) {
		WD_ERR("fail to open driver lib files.\n");
		goto out_uninit;
	}

res_retry:
	memset(&wd_cipher_setting.config, 0, sizeof(struct wd_ctx_config_internal));

	/* Get alg driver and dev name */
	wd_cipher_setting.driver = wd_alg_drv_bind(task_type, alg);
	if (!wd_cipher_setting.driver) {
		WD_ERR("fail to bind a valid driver.\n");
		ret = -WD_EINVAL;
		goto out_dlopen;
	}

	cipher_ctx_params.ctx_set_num = cipher_ctx_num;
	ret = wd_ctx_param_init(&cipher_ctx_params, ctx_params,
				wd_cipher_setting.driver,
				WD_CIPHER_TYPE, WD_CIPHER_DECRYPTION + 1);
	if (ret) {
		if (ret == -WD_EAGAIN) {
			wd_disable_drv(wd_cipher_setting.driver);
			wd_alg_drv_unbind(wd_cipher_setting.driver);
			goto res_retry;
		}
		goto out_driver;
	}

	wd_cipher_init_attrs.alg = alg;
	wd_cipher_init_attrs.sched_type = sched_type;
	wd_cipher_init_attrs.driver = wd_cipher_setting.driver;
	wd_cipher_init_attrs.ctx_params = &cipher_ctx_params;
	wd_cipher_init_attrs.alg_init = wd_cipher_common_init;
	wd_cipher_init_attrs.alg_poll_ctx = wd_cipher_poll_ctx;
	ret = wd_alg_attrs_init(&wd_cipher_init_attrs);
	if (ret) {
		if (ret == -WD_ENODEV) {
			wd_disable_drv(wd_cipher_setting.driver);
			wd_alg_drv_unbind(wd_cipher_setting.driver);
			wd_ctx_param_uninit(&cipher_ctx_params);
			goto res_retry;
		}
		WD_ERR("fail to init alg attrs.\n");
		goto out_params_uninit;
	}

	wd_alg_set_init(&wd_cipher_setting.status);
	wd_ctx_param_uninit(&cipher_ctx_params);

	return 0;

out_params_uninit:
	wd_ctx_param_uninit(&cipher_ctx_params);
out_driver:
	wd_alg_drv_unbind(wd_cipher_setting.driver);
out_dlopen:
	wd_dlclose_drv(wd_cipher_setting.dlh_list);
out_uninit:
	wd_alg_clear_init(&wd_cipher_setting.status);
	return ret;
}

void wd_cipher_uninit2(void)
{
	wd_cipher_common_uninit();

	wd_alg_attrs_uninit(&wd_cipher_init_attrs);
	wd_alg_drv_unbind(wd_cipher_setting.driver);
	wd_dlclose_drv(wd_cipher_setting.dlh_list);
	wd_cipher_setting.dlh_list = NULL;
	wd_alg_clear_init(&wd_cipher_setting.status);
}

static void fill_request_msg(struct wd_cipher_msg *msg,
			     struct wd_cipher_req *req,
			     struct wd_cipher_sess *sess)
{
	memcpy(&msg->req, req, sizeof(struct wd_cipher_req));

	msg->alg_type = WD_CIPHER;
	msg->alg = sess->alg;
	msg->mode = sess->mode;
	msg->op_type = req->op_type;
	msg->in = req->src;
	msg->in_bytes = req->in_bytes;
	msg->out = req->dst;
	msg->out_bytes = req->out_bytes;
	msg->key = sess->key;
	msg->key_bytes = sess->key_bytes;
	msg->iv = req->iv;
	msg->iv_bytes = req->iv_bytes;
	msg->data_fmt = req->data_fmt;
}

static int cipher_iv_len_check(struct wd_cipher_req *req,
			       struct wd_cipher_sess *sess)
{
	int ret = 0;

	/* Only the ECB mode does not need iv. */
	if (sess->mode == WD_CIPHER_ECB)
		return 0;

	switch (sess->alg) {
	case WD_CIPHER_AES:
	case WD_CIPHER_SM4:
		if (req->iv_bytes != AES_BLOCK_SIZE) {
			WD_ERR("AES or SM4 input iv bytes is err, size = %u\n",
				req->iv_bytes);
			ret = -WD_EINVAL;
		}
		break;
	case WD_CIPHER_3DES:
	case WD_CIPHER_DES:
		if (req->iv_bytes != DES3_BLOCK_SIZE) {
			WD_ERR("3DES or DES input iv bytes is err, size = %u\n",
				req->iv_bytes);
			ret = -WD_EINVAL;
		}
		break;
	default:
		ret = -WD_EINVAL;
		break;
	}

	return ret;
}

static int wd_cipher_check_params(handle_t h_sess,
				struct wd_cipher_req *req, __u8 mode)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)h_sess;
	int ret;

	if (unlikely(!h_sess || !req)) {
		WD_ERR("invalid: cipher input sess or req is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(mode == CTX_MODE_ASYNC && !req->cb)) {
		WD_ERR("invalid: cipher req cb is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->out_buf_bytes < req->in_bytes)) {
		WD_ERR("cipher set out_buf_bytes is error, size = %u\n",
			req->out_buf_bytes);
		return -WD_EINVAL;
	}

	if (req->data_fmt == WD_SGL_BUF) {
		ret = wd_check_datalist(req->list_src, req->in_bytes);
		if (unlikely(ret)) {
			WD_ERR("failed to check the src datalist, len = %u\n",
				req->in_bytes);
			return -WD_EINVAL;
		}

		/* cipher dst len is equal to src len */
		ret = wd_check_datalist(req->list_dst, req->in_bytes);
		if (unlikely(ret)) {
			WD_ERR("failed to check the dst datalist, len = %u\n",
				req->in_bytes);
			return -WD_EINVAL;
		}
	}

	return cipher_iv_len_check(req, sess);
}

static int send_recv_sync(struct wd_ctx_internal *ctx,
			  struct wd_cipher_msg *msg)
{
	struct wd_msg_handle msg_handle;
	int ret;

	msg_handle.send = wd_cipher_setting.driver->send;
	msg_handle.recv = wd_cipher_setting.driver->recv;

	pthread_spin_lock(&ctx->lock);
	ret = wd_handle_msg_sync(&msg_handle, ctx->ctx, msg, NULL,
			  wd_cipher_setting.config.epoll_en);
	pthread_spin_unlock(&ctx->lock);
	return ret;
}

int wd_do_cipher_sync(handle_t h_sess, struct wd_cipher_req *req)
{
	struct wd_ctx_config_internal *config = &wd_cipher_setting.config;
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)h_sess;
	struct wd_ctx_internal *ctx;
	struct wd_cipher_msg msg;
	__u32 idx;
	int ret;

	ret = wd_cipher_check_params(h_sess, req, CTX_MODE_SYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check cipher params!\n");
		return ret;
	}

	memset(&msg, 0, sizeof(struct wd_cipher_msg));
	fill_request_msg(&msg, req, sess);
	req->state = 0;

	idx = wd_cipher_setting.sched.pick_next_ctx(
		     wd_cipher_setting.sched.h_sched_ctx,
		     sess->sched_key, CTX_MODE_SYNC);
	ret = wd_check_ctx(config, CTX_MODE_SYNC, idx);
	if (unlikely(ret))
		return ret;

	wd_dfx_msg_cnt(config->msg_cnt, WD_CTX_CNT_NUM, idx);
	ctx = config->ctxs + idx;

	ret = send_recv_sync(ctx, &msg);
	req->state = msg.result;

	return ret;
}

int wd_do_cipher_async(handle_t h_sess, struct wd_cipher_req *req)
{
	struct wd_ctx_config_internal *config = &wd_cipher_setting.config;
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)h_sess;
	struct wd_ctx_internal *ctx;
	struct wd_cipher_msg *msg;
	int msg_id, ret;
	__u32 idx;

	ret = wd_cipher_check_params(h_sess, req, CTX_MODE_ASYNC);
	if (unlikely(ret)) {
		WD_ERR("failed to check cipher params!\n");
		return ret;
	}

	idx = wd_cipher_setting.sched.pick_next_ctx(
		     wd_cipher_setting.sched.h_sched_ctx,
		     sess->sched_key, CTX_MODE_ASYNC);
	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;
	wd_dfx_msg_cnt(config->msg_cnt, WD_CTX_CNT_NUM, idx);

	msg_id = wd_get_msg_from_pool(&wd_cipher_setting.pool, idx,
				   (void **)&msg);
	if (unlikely(msg_id < 0)) {
		WD_ERR("busy, failed to get msg from pool!\n");
		return -WD_EBUSY;
	}

	fill_request_msg(msg, req, sess);
	msg->tag = msg_id;

	ret = wd_cipher_setting.driver->send(ctx->ctx, msg);
	if (unlikely(ret < 0)) {
		if (ret != -WD_EBUSY)
			WD_ERR("wd cipher async send err!\n");

		goto fail_with_msg;
	}

	ret = wd_add_task_to_async_queue(&wd_cipher_env_config, idx);
	if (ret)
		goto fail_with_msg;

	return 0;

fail_with_msg:
	wd_put_msg_to_pool(&wd_cipher_setting.pool, idx, msg->tag);
	return ret;
}

struct wd_cipher_msg *wd_cipher_get_msg(__u32 idx, __u32 tag)
{
	return wd_find_msg_in_pool(&wd_cipher_setting.pool, idx, tag);
}

int wd_cipher_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_cipher_setting.config;
	struct wd_ctx_internal *ctx;
	struct wd_cipher_msg resp_msg, *msg;
	struct wd_cipher_req *req;
	__u64 recv_count = 0;
	__u32 tmp = expt;
	int ret;

	if (unlikely(!count)) {
		WD_ERR("invalid: cipher poll ctx input param is NULL!\n");
		return -WD_EINVAL;
	}

	*count = 0;

	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	do {
		ret = wd_cipher_setting.driver->recv(ctx->ctx, &resp_msg);
		if (ret == -WD_EAGAIN)
			return ret;
		else if (ret < 0) {
			WD_ERR("wd cipher recv hw err!\n");
			return ret;
		}
		recv_count++;
		msg = wd_find_msg_in_pool(&wd_cipher_setting.pool, idx,
					  resp_msg.tag);
		if (!msg) {
			WD_ERR("failed to get msg from pool!\n");
			return -WD_EINVAL;
		}

		msg->tag = resp_msg.tag;
		msg->req.state = resp_msg.result;
		req = &msg->req;

		req->cb(req, req->cb_param);
		/* free msg cache to msg_pool */
		wd_put_msg_to_pool(&wd_cipher_setting.pool, idx,
				   resp_msg.tag);
		*count = recv_count;
	} while (--tmp);

	return ret;
}

int wd_cipher_poll(__u32 expt, __u32 *count)
{
	handle_t h_ctx = wd_cipher_setting.sched.h_sched_ctx;
	struct wd_sched *sched = &wd_cipher_setting.sched;

	if (unlikely(!count)) {
		WD_ERR("invalid: cipher poll input param is NULL!\n");
		return -WD_EINVAL;
	}

	return sched->poll_policy(h_ctx, expt, count);
}

static const struct wd_config_variable table[] = {
	{ .name = "WD_CIPHER_CTX_NUM",
	  .def_val = "sync:2@0,async:2@0",
	  .parse_fn = wd_parse_ctx_num
	},
	{ .name = "WD_CIPHER_ASYNC_POLL_EN",
	  .def_val = "0",
	  .parse_fn = wd_parse_async_poll_en
	}
};

static const struct wd_alg_ops wd_cipher_ops = {
	.alg_name = "cipher",
	.op_type_num = 1,
	.alg_init = wd_cipher_init,
	.alg_uninit = wd_cipher_uninit,
	.alg_poll_ctx = wd_cipher_poll_ctx
};

int wd_cipher_env_init(struct wd_sched *sched)
{
	wd_cipher_env_config.sched = sched;

	return wd_alg_env_init(&wd_cipher_env_config, table,
				&wd_cipher_ops, ARRAY_SIZE(table), NULL);
}

void wd_cipher_env_uninit(void)
{
	wd_alg_env_uninit(&wd_cipher_env_config, &wd_cipher_ops);
}

int wd_cipher_ctx_num_init(__u32 node, __u32 type, __u32 num, __u8 mode)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, num);
	if (ret)
		return ret;

	return wd_alg_env_init(&wd_cipher_env_config, table,
			      &wd_cipher_ops, ARRAY_SIZE(table), &ctx_attr);
}

void wd_cipher_ctx_num_uninit(void)
{
	wd_alg_env_uninit(&wd_cipher_env_config, &wd_cipher_ops);
}

int wd_cipher_get_env_param(__u32 node, __u32 type, __u32 mode,
			    __u32 *num, __u8 *is_enable)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, 0);
	if (ret)
		return ret;

	return wd_alg_get_env_param(&wd_cipher_env_config,
				    ctx_attr, num, is_enable);
}
