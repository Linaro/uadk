/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#include <stdlib.h>
#include <pthread.h>
#include "include/drv/wd_aead_drv.h"
#include "wd_aead.h"
#include "wd_util.h"

#define XTS_MODE_KEY_DIVISOR	2
#define SM4_KEY_SIZE		16
#define DES_KEY_SIZE		8
#define DES3_2KEY_SIZE		(2 * DES_KEY_SIZE)
#define DES3_3KEY_SIZE		(3 * DES_KEY_SIZE)
#define MAX_CIPHER_KEY_SIZE	64

#define WD_AEAD_CCM_GCM_MIN	4U
#define WD_AEAD_CCM_GCM_MAX	16
#define MAX_HMAC_KEY_SIZE	128U
#define WD_POOL_MAX_ENTRIES	1024
#define MAX_RETRY_COUNTS	200000000

#define POLL_SIZE		70000
#define POLL_TIME		1000

static int g_aead_mac_len[WD_DIGEST_TYPE_MAX] = {
	WD_DIGEST_SM3_LEN, WD_DIGEST_MD5_LEN, WD_DIGEST_SHA1_LEN,
	WD_DIGEST_SHA256_LEN, WD_DIGEST_SHA224_LEN,
	WD_DIGEST_SHA384_LEN, WD_DIGEST_SHA512_LEN,
	WD_DIGEST_SHA512_224_LEN, WD_DIGEST_SHA512_256_LEN
};

struct wd_aead_setting {
	struct wd_ctx_config_internal config;
	struct wd_sched sched;
	struct wd_aead_driver *driver;
	struct wd_async_msg_pool pool;
	void *sched_ctx;
	void *priv;
}wd_aead_setting;

struct wd_env_config wd_aead_env_config;

#ifdef WD_STATIC_DRV
extern struct wd_aead_driver wd_aead_hisi_aead_driver;
static void wd_aead_set_static_drv(void)
{
	wd_aead_setting.driver = &wd_aead_hisi_aead_driver;
}
#else
static void __attribute__((constructor)) wd_aead_open_driver(void)
{
	void *driver;

	driver = dlopen("libhisi_sec.so", RTLD_NOW);
	if (!driver)
		WD_ERR("failed to open libhisi_sec.so\n");
}
#endif

void wd_aead_set_driver(struct wd_aead_driver *drv)
{
	wd_aead_setting.driver = drv;
}

static int aes_key_len_check(__u16 length)
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

static int cipher_key_len_check(enum wd_cipher_alg alg, __u16 length)
{
	int ret = 0;

	switch (alg) {
	case WD_CIPHER_SM4:
		if (length != SM4_KEY_SIZE)
			ret = -WD_EINVAL;
		break;
	case WD_CIPHER_AES:
		ret = aes_key_len_check(length);
		break;
	default:
		WD_ERR("failed to check cipher key!\n");
		return -WD_EINVAL;
	}

	return ret;
}

static unsigned int get_iv_block_size(int mode)
{
	int ret;

	/* AEAD just used AES and SM4 algorithm */
	switch (mode) {
	case WD_CIPHER_CBC:
	case WD_CIPHER_CCM:
		ret = AES_BLOCK_SIZE;
		break;
	case WD_CIPHER_GCM:
		ret = GCM_BLOCK_SIZE;
		break;
	default:
		ret = AES_BLOCK_SIZE;
	}

	return ret;
}

int wd_aead_set_ckey(handle_t h_sess, const __u8 *key, __u16 key_len)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;
	int ret;

	if (!key || !sess || !sess->ckey) {
		WD_ERR("failed to check cipher key inpupt param!\n");
		return -WD_EINVAL;
	}

	ret = cipher_key_len_check(sess->calg, key_len);
	if (ret) {
		WD_ERR("failed to check cipher key length!\n");
		return -WD_EINVAL;
	}

	sess->ckey_bytes = key_len;
	memcpy(sess->ckey, key, key_len);

	return 0;
}

int wd_aead_set_akey(handle_t h_sess, const __u8 *key, __u16 key_len)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;

	if (!key || !sess || !sess->akey) {
		WD_ERR("failed to check authenticate key param!\n");
		return -WD_EINVAL;
	}

	if ((sess->dalg <= WD_DIGEST_SHA224 && key_len >
	    MAX_HMAC_KEY_SIZE >> 1) || key_len == 0 ||
	    key_len > MAX_HMAC_KEY_SIZE) {
		WD_ERR("failed to check authenticate key length!\n");
		return -WD_EINVAL;
	}

	sess->akey_bytes = key_len;
	memcpy(sess->akey, key, key_len);

	return 0;
}

int wd_aead_set_authsize(handle_t h_sess, __u16 authsize)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;

	if (!sess) {
		WD_ERR("failed to check session parameter!\n");
		return -WD_EINVAL;
	}

	if (sess->cmode == WD_CIPHER_CCM) {
		if (authsize < WD_AEAD_CCM_GCM_MIN ||
		    authsize > WD_AEAD_CCM_GCM_MAX ||
		    authsize % (WD_AEAD_CCM_GCM_MIN >> 1)) {
			WD_ERR("failed to check aead CCM authsize!\n");
			return -WD_EINVAL;
		}
	} else if (sess->cmode == WD_CIPHER_GCM) {
		if (authsize < WD_AEAD_CCM_GCM_MIN << 1 ||
		    authsize > WD_AEAD_CCM_GCM_MAX) {
			WD_ERR("failed to check aead GCM authsize!\n");
			return -WD_EINVAL;
		}
	} else {
		if (sess->dalg >= WD_DIGEST_TYPE_MAX ||
		    authsize & (WD_AEAD_CCM_GCM_MAX - 1) ||
		    authsize > g_aead_mac_len[sess->dalg]) {
			WD_ERR("failed to check aead mac authsize!\n");
			return -WD_EINVAL;
		}
	}

	sess->auth_bytes = authsize;

	return 0;
}

int wd_aead_get_authsize(handle_t h_sess)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;

	if (!sess) {
		WD_ERR("failed to check session parameter!\n");
		return -WD_EINVAL;
	}

	return sess->auth_bytes;
}

int wd_aead_get_maxauthsize(handle_t h_sess)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;

	if (!sess || sess->dalg >= WD_DIGEST_TYPE_MAX) {
		WD_ERR("failed to check session parameter!\n");
		return -WD_EINVAL;
	}

	if (sess->cmode == WD_CIPHER_CCM || sess->cmode == WD_CIPHER_GCM)
		return WD_AEAD_CCM_GCM_MAX;

	return g_aead_mac_len[sess->dalg];
}

handle_t wd_aead_alloc_sess(struct wd_aead_sess_setup *setup)
{
	struct wd_aead_sess *sess = NULL;

	if (!setup) {
		WD_ERR("failed to check session input parameter!\n");
		return (handle_t)0;
	}

	sess = malloc(sizeof(struct wd_aead_sess));
	if (!sess) {
		WD_ERR("failed to alloc session memory!\n");
		return (handle_t)0;
	}
	memset(sess, 0, sizeof(struct wd_aead_sess));

	sess->calg = setup->calg;
	sess->cmode = setup->cmode;
	sess->ckey = malloc(MAX_CIPHER_KEY_SIZE);
	if (!sess->ckey) {
		WD_ERR("failed to alloc cipher key memory!\n");
		free(sess);
		return (handle_t)0;
	}
	memset(sess->ckey, 0, MAX_CIPHER_KEY_SIZE);

	sess->dalg = setup->dalg;
	sess->dmode = setup->dmode;
	sess->akey = malloc(MAX_HMAC_KEY_SIZE);
	if (!sess->akey) {
		WD_ERR("failed to alloc digest key memory!\n");
		free(sess->ckey);
		free(sess);
		return (handle_t)0;
	}
	memset(sess->akey, 0, MAX_HMAC_KEY_SIZE);

	sess->numa = setup->numa;

	return (handle_t)sess;
}

void wd_aead_free_sess(handle_t h_sess)
{
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;

	if (!sess) {
		WD_ERR("failed to check session parameter!\n");
		return;
	}

	if (sess->ckey) {
		wd_memset_zero(sess->ckey, MAX_CIPHER_KEY_SIZE);
		free(sess->ckey);
	}

	if (sess->akey) {
		wd_memset_zero(sess->akey, MAX_HMAC_KEY_SIZE);
		free(sess->akey);
	}
	free(sess);
}

static int aead_param_check(struct wd_aead_sess *sess,
	struct wd_aead_req *req)
{
	__u32 len;
	int ret;

	if (unlikely(!sess || !req)) {
		WD_ERR("aead input sess or req is NULL.\n");
		return -WD_EINVAL;
	}

	if (unlikely(sess->cmode == WD_CIPHER_CBC &&
	   (req->in_bytes & (AES_BLOCK_SIZE - 1)))) {
		WD_ERR("failed to check input data length!\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->iv_bytes != get_iv_block_size(sess->cmode))) {
		WD_ERR("failed to check aead IV length!\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->out_buf_bytes < req->out_bytes)) {
		WD_ERR("failed to check aead out buffer length!\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->op_type == WD_CIPHER_ENCRYPTION_DIGEST &&
	    req->out_buf_bytes < (req->out_bytes + sess->auth_bytes))) {
		WD_ERR("failed to check aead type or mac length!\n");
		return -WD_EINVAL;
	}

	if (req->data_fmt == WD_SGL_BUF) {
		len = req->in_bytes + req->assoc_bytes;
		if (req->op_type == WD_CIPHER_DECRYPTION_DIGEST)
			len += sess->auth_bytes;

		ret = wd_check_datalist(req->list_src, len);
		if (unlikely(ret)) {
			WD_ERR("failed to check the src datalist!\n");
			return -WD_EINVAL;
		}

		ret = wd_check_datalist(req->list_dst, req->out_buf_bytes);
		if (unlikely(ret)) {
			WD_ERR("failed to check the dst datalist!\n");
			return -WD_EINVAL;
		}
	}

	return 0;
}

int wd_aead_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	void *priv;
	int ret;

	if (wd_aead_setting.config.ctx_num) {
		WD_ERR("aead have initialized.\n");
		return -WD_EEXIST;
	}

	if (!config || !sched) {
		WD_ERR("failed to check aead init input param!\n");
		return -WD_EINVAL;
	}

	if (!wd_is_sva(config->ctxs[0].ctx)) {
		WD_ERR("failed to system is SVA mode!\n");
		return -WD_EINVAL;
	}

	ret = wd_init_ctx_config(&wd_aead_setting.config, config);
	if (ret) {
		WD_ERR("failed to set config, ret = %d!\n", ret);
		return ret;
	}

	ret = wd_init_sched(&wd_aead_setting.sched, sched);
	if (ret < 0) {
		WD_ERR("failed to set sched, ret = %d!\n", ret);
		goto out;
	}

	/* set driver */
#ifdef WD_STATIC_DRV
	wd_aead_set_static_drv();
#endif

	/* init sync request pool */
	ret = wd_init_async_request_pool(&wd_aead_setting.pool,
				config->ctx_num, WD_POOL_MAX_ENTRIES,
				sizeof(struct wd_aead_msg));
	if (ret < 0) {
		WD_ERR("failed to init aead aysnc request pool.\n");
		goto out_sched;
	}

	/* init ctx related resources in specific driver */
	priv = malloc(wd_aead_setting.driver->drv_ctx_size);
	if (!priv) {
		ret = -WD_ENOMEM;
		goto out_priv;
	}
	memset(priv, 0, wd_aead_setting.driver->drv_ctx_size);
	wd_aead_setting.priv = priv;
	/* sec init */
	ret = wd_aead_setting.driver->init(&wd_aead_setting.config, priv);
	if (ret < 0) {
		WD_ERR("failed to init aead dirver!\n");
		goto out_init;
	}

	return 0;

out_init:
	free(priv);
out_priv:
	wd_uninit_async_request_pool(&wd_aead_setting.pool);
out_sched:
	wd_clear_sched(&wd_aead_setting.sched);
out:
	wd_clear_ctx_config(&wd_aead_setting.config);
	return ret;
}

void wd_aead_uninit(void)
{
	void *priv = wd_aead_setting.priv;

	if (!priv)
		return;

	wd_aead_setting.driver->exit(priv);
	wd_aead_setting.priv = NULL;
	free(priv);

	wd_uninit_async_request_pool(&wd_aead_setting.pool);
	wd_clear_sched(&wd_aead_setting.sched);
	wd_clear_ctx_config(&wd_aead_setting.config);
}

static void fill_request_msg(struct wd_aead_msg *msg, struct wd_aead_req *req,
			    struct wd_aead_sess *sess)
{
	memcpy(&msg->req, req, sizeof(struct wd_aead_req));

	msg->alg_type = WD_AEAD;
	msg->calg = sess->calg;
	msg->cmode = sess->cmode;
	msg->dalg = sess->dalg;
	msg->dmode = sess->dmode;
	msg->op_type = req->op_type;
	msg->in = req->src;
	msg->in_bytes = req->in_bytes;
	msg->out = req->dst;
	msg->out_bytes = req->out_bytes;
	msg->ckey = sess->ckey;
	msg->ckey_bytes = sess->ckey_bytes;
	msg->akey = sess->akey;
	msg->akey_bytes = sess->akey_bytes;
	msg->iv = req->iv;
	msg->iv_bytes = req->iv_bytes;
	msg->assoc_bytes = req->assoc_bytes;
	msg->auth_bytes = sess->auth_bytes;
	msg->data_fmt = req->data_fmt;
}

int wd_do_aead_sync(handle_t h_sess, struct wd_aead_req *req)
{
	struct wd_ctx_config_internal *config = &wd_aead_setting.config;
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;
	struct wd_ctx_internal *ctx;
	struct wd_aead_msg msg;
	struct sched_key key;
	__u64 recv_cnt = 0;
	__u32 idx;
	int ret;

	ret = aead_param_check(sess, req);
	if (unlikely(ret))
		return -WD_EINVAL;

	key.mode = CTX_MODE_SYNC;
	key.type = 0;
	key.numa_id = sess->numa;

	idx = wd_aead_setting.sched.pick_next_ctx(
		wd_aead_setting.sched.h_sched_ctx, req, &key);
	ret = wd_check_ctx(config, CTX_MODE_SYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;
	memset(&msg, 0, sizeof(struct wd_aead_msg));
	msg.aiv = malloc(req->iv_bytes);
	if (unlikely(!msg.aiv)) {
		WD_ERR("failed to alloc auth iv memory!\n");
		return -WD_EINVAL;
	}
	memset(msg.aiv, 0, req->iv_bytes);
	fill_request_msg(&msg, req, sess);
	req->state = 0;

	pthread_spin_lock(&ctx->lock);
	ret = wd_aead_setting.driver->aead_send(ctx->ctx, &msg);
	if (unlikely(ret < 0)) {
		WD_ERR("failed to send aead bd!\n");
		goto err_out;
	}

	do {
		if (req->in_bytes >= POLL_SIZE) {
			ret = wd_ctx_wait(ctx->ctx, POLL_TIME);
			if (unlikely(ret < 0))
				WD_ERR("wd ctx wait timeout(%d)!\n", ret);
		}
		ret = wd_aead_setting.driver->aead_recv(ctx->ctx, &msg);
		req->state = msg.result;
		if (ret == -WD_HW_EACCESS) {
			WD_ERR("failed to recv bd!\n");
			goto err_out;
		} else if (ret == -WD_EAGAIN) {
			if (++recv_cnt > MAX_RETRY_COUNTS) {
				WD_ERR("failed to recv bd and timeout!\n");
				ret = -WD_ETIMEDOUT;
				goto err_out;
			}
		}
	} while (ret < 0);
	pthread_spin_unlock(&ctx->lock);
	free(msg.aiv);

	return 0;

err_out:
	pthread_spin_unlock(&ctx->lock);
	free(msg.aiv);
	return ret;
}

int wd_do_aead_async(handle_t h_sess, struct wd_aead_req *req)
{
	struct wd_ctx_config_internal *config = &wd_aead_setting.config;
	struct wd_aead_sess *sess = (struct wd_aead_sess *)h_sess;
	struct wd_ctx_internal *ctx;
	struct wd_aead_msg *msg;
	struct sched_key key;
	int msg_id, ret;
	__u32 idx;

	ret = aead_param_check(sess, req);
	if (unlikely(ret))
		return -WD_EINVAL;

	if (unlikely(!req->cb)) {
		WD_ERR("aead input req cb is NULL.\n");
		return -WD_EINVAL;
	}

	key.mode = CTX_MODE_ASYNC;
	key.type = 0;
	key.numa_id = sess->numa;

	idx = wd_aead_setting.sched.pick_next_ctx(
		wd_aead_setting.sched.h_sched_ctx, req, &key);
	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	msg_id = wd_get_msg_from_pool(&wd_aead_setting.pool,
				     idx, (void **)&msg);
	if (unlikely(msg_id < 0)) {
		WD_ERR("failed to get msg from pool!\n");
		return -WD_EBUSY;
	}

	fill_request_msg(msg, req, sess);
	msg->aiv = malloc(req->iv_bytes);
	if (unlikely(!msg->aiv)) {
		WD_ERR("failed to alloc auth iv memory!\n");
		return -WD_EINVAL;
	}
	memset(msg->aiv, 0, req->iv_bytes);
	msg->tag = msg_id;

	ret = wd_aead_setting.driver->aead_send(ctx->ctx, msg);
	if (unlikely(ret < 0)) {
		if (ret != -WD_EBUSY)
			WD_ERR("failed to send BD, hw is err!\n");

		wd_put_msg_to_pool(&wd_aead_setting.pool, idx, msg->tag);
		free(msg->aiv);
	}

	wd_add_task_to_async_queue(&wd_aead_env_config, idx);

	return ret;
}

int wd_aead_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_aead_setting.config;
	struct wd_ctx_internal *ctx;
	struct wd_aead_msg resp_msg, *msg;
	struct wd_aead_req *req;
	__u64 recv_count = 0;
	int ret;

	if (!count) {
		WD_ERR("aead poll ctx input param is NULL!\n");
		return -WD_EINVAL;
	}

	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	do {
		ret = wd_aead_setting.driver->aead_recv(ctx->ctx, &resp_msg);
		if (ret == -WD_EAGAIN) {
			return ret;
		} else if (ret < 0) {
			WD_ERR("wd aead recv hw err!\n");
			return ret;
		}

		recv_count++;
		msg = wd_find_msg_in_pool(&wd_aead_setting.pool,
					    idx, resp_msg.tag);
		if (!msg) {
			WD_ERR("failed to get msg from pool!\n");
			return -WD_EINVAL;
		}

		msg->tag = resp_msg.tag;
		msg->req.state = resp_msg.result;
		req = &msg->req;
		req->cb(req, req->cb_param);
		wd_put_msg_to_pool(&wd_aead_setting.pool,
				     idx, resp_msg.tag);
		free(msg->aiv);
		*count = recv_count;
	} while (--expt);

	return ret;
}

int wd_aead_poll(__u32 expt, __u32 *count)
{
	handle_t h_ctx = wd_aead_setting.sched.h_sched_ctx;
	struct wd_sched *sched = &wd_aead_setting.sched;

	if (unlikely(!sched->poll_policy)) {
		WD_ERR("failed to check aead poll_policy!\n");
		return -WD_EINVAL;
	}

	return sched->poll_policy(h_ctx, expt, count);
}

static const struct wd_config_variable table[] = {
	{ .name = "WD_AEAD_CTX_NUM",
	  .def_val = "sync:2@0,async:2@0",
	  .parse_fn = wd_parse_ctx_num
	},
	{ .name = "WD_AEAD_ASYNC_POLL_EN",
	  .def_val = "0",
	  .parse_fn = wd_parse_async_poll_en
	}
};

static const struct wd_alg_ops wd_aead_ops = {
        .alg_name = "aead",
        .op_type_num = 1,
        .alg_init = wd_aead_init,
        .alg_uninit = wd_aead_uninit,
        .alg_poll_ctx = wd_aead_poll_ctx
};

int wd_aead_env_init(void)
{
	return wd_alg_env_init(&wd_aead_env_config, table,
			       &wd_aead_ops, ARRAY_SIZE(table), NULL);
}

void wd_aead_env_uninit(void)
{
	return wd_alg_env_uninit(&wd_aead_env_config);
}

int wd_aead_ctx_num_init(__u32 node, __u32 type, __u32 num, __u8 mode)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, num);
	if (ret)
		return ret;

	return wd_alg_env_init(&wd_aead_env_config, table,
			      &wd_aead_ops, ARRAY_SIZE(table), &ctx_attr);
}

void wd_aead_ctx_num_uninit(void)
{
	return wd_alg_env_uninit(&wd_aead_env_config);
}

int wd_aead_get_env_param(__u32 node, __u32 type, __u32 mode,
			  __u32 *num, __u8 *is_enable)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, 0);
	if (ret)
		return ret;

	return wd_alg_get_env_param(&wd_aead_env_config,
				    ctx_attr, num, is_enable);
}
