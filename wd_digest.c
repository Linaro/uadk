/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#include <stdlib.h>
#include <pthread.h>
#include "wd_util.h"
#include "include/drv/wd_digest_drv.h"
#include "wd_digest.h"

#define XTS_MODE_KEY_DIVISOR	2
#define SM4_KEY_SIZE		16
#define DES_KEY_SIZE		8
#define DES3_3KEY_SIZE		(3 * DES_KEY_SIZE)
#define GMAC_IV_LEN		16
#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32

#define WD_POOL_MAX_ENTRIES	1024
#define DES_WEAK_KEY_NUM	4

static int g_digest_mac_len[WD_DIGEST_TYPE_MAX] = {
	WD_DIGEST_SM3_LEN, WD_DIGEST_MD5_LEN, WD_DIGEST_SHA1_LEN,
	WD_DIGEST_SHA256_LEN, WD_DIGEST_SHA224_LEN,
	WD_DIGEST_SHA384_LEN, WD_DIGEST_SHA512_LEN,
	WD_DIGEST_SHA512_224_LEN, WD_DIGEST_SHA512_256_LEN,
	WD_DIGEST_AES_XCBC_MAC_96_LEN, WD_DIGEST_AES_XCBC_PRF_128_LEN,
	WD_DIGEST_AES_CMAC_LEN, WD_DIGEST_AES_GMAC_LEN
};

static int g_digest_mac_full_len[WD_DIGEST_TYPE_MAX] = {
	WD_DIGEST_SM3_FULL_LEN, WD_DIGEST_MD5_LEN, WD_DIGEST_SHA1_FULL_LEN,
	WD_DIGEST_SHA256_FULL_LEN, WD_DIGEST_SHA224_FULL_LEN,
	WD_DIGEST_SHA384_FULL_LEN, WD_DIGEST_SHA512_FULL_LEN,
	WD_DIGEST_SHA512_224_FULL_LEN, WD_DIGEST_SHA512_256_FULL_LEN
};

struct wd_digest_setting {
	enum wd_status status;
	struct wd_ctx_config_internal config;
	struct wd_sched	sched;
	struct wd_digest_driver	*driver;
	struct wd_async_msg_pool pool;
	void *sched_ctx;
	void *priv;
	void *dlhandle;
} wd_digest_setting;

struct wd_digest_sess {
	char			*alg_name;
	enum wd_digest_type	alg;
	enum wd_digest_mode	mode;
	void			*priv;
	unsigned char		key[MAX_HMAC_KEY_SIZE];
	__u32			key_bytes;
	void			*sched_key;
	/*
	 * Notify the BD state, zero is frist BD, non-zero
	 * is middle or final BD.
	 */
	int			bd_state;
	/* Total of data for stream mode */
	__u64			 long_data_len;
};

struct wd_env_config wd_digest_env_config;

#ifdef WD_STATIC_DRV
static void wd_digest_set_static_drv(void)
{
	wd_digest_setting.driver = wd_digest_get_driver();
	if (!wd_digest_setting.driver)
		WD_ERR("failed to get driver!\n");
}
#else
static void __attribute__((constructor)) wd_digest_open_driver(void)
{
	/* Fix me: vendor driver should be put in /usr/lib/wd/ */
	wd_digest_setting.dlhandle = dlopen("libhisi_sec.so", RTLD_NOW);
	if (!wd_digest_setting.dlhandle)
		WD_ERR("failed to open libhisi_sec.so!\n");
}

static void __attribute__((destructor)) wd_digest_close_driver(void)
{
	if (wd_digest_setting.dlhandle)
		dlclose(wd_digest_setting.dlhandle);
}
#endif

void wd_digest_set_driver(struct wd_digest_driver *drv)
{
	wd_digest_setting.driver = drv;
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

int wd_digest_set_key(handle_t h_sess, const __u8 *key, __u32 key_len)
{
	struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;
	int ret;

	if (!key || !sess) {
		WD_ERR("failed to check key param!\n");
		return -WD_EINVAL;
	}

	if ((sess->alg <= WD_DIGEST_SHA224 && key_len >
		MAX_HMAC_KEY_SIZE >> 1) || key_len == 0 ||
		key_len > MAX_HMAC_KEY_SIZE) {
		WD_ERR("failed to check digest key length, size = %u\n",
			key_len);
		return -WD_EINVAL;
	}

	if (sess->alg == WD_DIGEST_AES_GMAC) {
		ret = aes_key_len_check(key_len);
		if (ret) {
			WD_ERR("failed to check aes-gmac key length, size = %u\n",
				key_len);
			return ret;
		}
	}

	sess->key_bytes = key_len;
	memcpy(sess->key, key, key_len);

	return 0;
}

handle_t wd_digest_alloc_sess(struct wd_digest_sess_setup *setup)
{
	struct wd_digest_sess *sess = NULL;

	if (unlikely(!setup)) {
		WD_ERR("failed to check alloc sess param!\n");
		return (handle_t)0;
	}

	sess = malloc(sizeof(struct wd_digest_sess));
	if (!sess)
		return (handle_t)0;
	memset(sess, 0, sizeof(struct wd_digest_sess));

	sess->alg = setup->alg;
	sess->mode = setup->mode;
	/* Some simple scheduler don't need scheduling parameters */
	sess->sched_key = (void *)wd_digest_setting.sched.sched_init(
			wd_digest_setting.sched.h_sched_ctx, setup->sched_param);
	if (WD_IS_ERR(sess->sched_key)) {
		WD_ERR("failed to init session schedule key!\n");
		free(sess);
		return (handle_t)0;
	}

	return (handle_t)sess;
}

void wd_digest_free_sess(handle_t h_sess)
{
	struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;

	if (unlikely(!sess)) {
		WD_ERR("failed to check free sess param!\n");
		return;
	}

	wd_memset_zero(sess->key, MAX_HMAC_KEY_SIZE);
	if (sess->sched_key)
		free(sess->sched_key);
	free(sess);
}

int wd_digest_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	void *priv;
	bool flag;
	int ret;

	flag = wd_alg_try_init(&wd_digest_setting.status);
	if (!flag)
		return 0;

	ret = wd_init_param_check(config, sched);
	if (ret)
		goto out_clear_init;

	ret = wd_set_epoll_en("WD_DIGEST_EPOLL_EN",
			      &wd_digest_setting.config.epoll_en);
	if (ret < 0)
		goto out_clear_init;

	ret = wd_init_ctx_config(&wd_digest_setting.config, config);
	if (ret < 0)
		goto out_clear_init;

	ret = wd_init_sched(&wd_digest_setting.sched, sched);
	if (ret < 0)
		goto out_clear_ctx_config;

	/* set driver */
#ifdef WD_STATIC_DRV
	wd_digest_set_static_drv();
#endif

	/* allocate async pool for every ctx */
	ret = wd_init_async_request_pool(&wd_digest_setting.pool,
					 config->ctx_num, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_digest_msg));
	if (ret < 0)
		goto out_clear_sched;

	/* init ctx related resources in specific driver */
	priv = calloc(1, wd_digest_setting.driver->drv_ctx_size);
	if (!priv) {
		ret = -WD_ENOMEM;
		goto out_clear_pool;
	}
	wd_digest_setting.priv = priv;

	ret = wd_digest_setting.driver->init(&wd_digest_setting.config, priv);
	if (ret < 0) {
		WD_ERR("failed to init digest dirver!\n");
		goto out_free_priv;
	}

	wd_alg_set_init(&wd_digest_setting.status);

	return 0;

out_free_priv:
	free(priv);
	wd_digest_setting.priv = NULL;
out_clear_pool:
	wd_uninit_async_request_pool(&wd_digest_setting.pool);
out_clear_sched:
	wd_clear_sched(&wd_digest_setting.sched);
out_clear_ctx_config:
	wd_clear_ctx_config(&wd_digest_setting.config);
out_clear_init:
	wd_alg_clear_init(&wd_digest_setting.status);
	return ret;
}

void wd_digest_uninit(void)
{
	void *priv = wd_digest_setting.priv;

	if (!priv)
		return;

	wd_digest_setting.driver->exit(priv);
	wd_digest_setting.priv = NULL;
	free(priv);

	wd_uninit_async_request_pool(&wd_digest_setting.pool);

	wd_clear_sched(&wd_digest_setting.sched);
	wd_clear_ctx_config(&wd_digest_setting.config);
	wd_alg_clear_init(&wd_digest_setting.status);
}

static int wd_aes_hmac_length_check(struct wd_digest_sess *sess,
	struct wd_digest_req *req)
{
	switch (sess->alg) {
	case WD_DIGEST_AES_XCBC_MAC_96:
	case WD_DIGEST_AES_XCBC_PRF_128:
	case WD_DIGEST_AES_CMAC:
		if (!req->in_bytes) {
			WD_ERR("failed to check 0 packet length, alg = %d\n",
				sess->alg);
			return -WD_EINVAL;
		}
		break;
	default:
		break;
	}

	return 0;
}

static int wd_mac_length_check(struct wd_digest_sess *sess,
			       struct wd_digest_req *req)
{
	if (unlikely(req->out_bytes == 0)) {
		WD_ERR("invalid: digest alg:%d mac length is 0.\n", sess->alg);
		return -WD_EINVAL;
	}

	if (unlikely(!req->has_next &&
	    req->out_bytes > g_digest_mac_len[sess->alg])) {
		WD_ERR("invalid: digest mac length, alg = %d, out_bytes = %u\n",
			sess->alg, req->out_bytes);
		return -WD_EINVAL;
	}

	/* User need to input full mac buffer in first and middle hash */
	if (unlikely(req->has_next &&
	    req->out_bytes != g_digest_mac_full_len[sess->alg])) {
		WD_ERR("invalid: digest mac full length is error, alg = %d, out_bytes = %u\n",
			sess->alg, req->out_bytes);
		return -WD_EINVAL;
	}

	return 0;
}

static int wd_digest_param_check(struct wd_digest_sess *sess,
	struct wd_digest_req *req)
{
	int ret;

	if (unlikely(!sess || !req)) {
		WD_ERR("invalid: digest input sess or req is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->out_buf_bytes < req->out_bytes)) {
		WD_ERR("failed to check digest out buffer length, size = %u\n",
			req->out_buf_bytes);
		return -WD_EINVAL;
	}

	if (unlikely(sess->alg >= WD_DIGEST_TYPE_MAX)) {
		WD_ERR("invalid: check digest type, alg = %d\n", sess->alg);
		return -WD_EINVAL;
	}

	ret = wd_mac_length_check(sess, req);
	if (ret)
		return ret;

	if (unlikely(sess->alg == WD_DIGEST_AES_GMAC &&
	    req->iv_bytes != GMAC_IV_LEN)) {
		WD_ERR("failed to check digest aes_gmac iv length, iv_bytes = %u\n",
			req->iv_bytes);
		return -WD_EINVAL;
	}

	if (req->data_fmt == WD_SGL_BUF) {
		ret = wd_check_datalist(req->list_in, req->in_bytes);
		if (unlikely(ret)) {
			WD_ERR("failed to check the src datalist, size = %u\n",
				req->in_bytes);
			return -WD_EINVAL;
		}
	}

	return wd_aes_hmac_length_check(sess, req);
}

static void fill_request_msg(struct wd_digest_msg *msg,
			     struct wd_digest_req *req,
			     struct wd_digest_sess *sess)
{
	memcpy(&msg->req, req, sizeof(struct wd_digest_req));

	msg->alg_type = WD_DIGEST;
	msg->alg = sess->alg;
	msg->mode = sess->mode;
	msg->key = sess->key;
	msg->key_bytes = sess->key_bytes;
	msg->iv = req->iv;
	msg->in = req->in;
	msg->in_bytes = req->in_bytes;
	msg->out = req->out;
	msg->out_bytes = req->out_bytes;
	msg->data_fmt = req->data_fmt;
	msg->has_next = req->has_next;
	sess->long_data_len += req->in_bytes;
	msg->long_data_len = sess->long_data_len;

	/* To store the stream BD state, iv_bytes also means BD state */
	msg->iv_bytes = sess->bd_state;
	if (req->has_next == 0) {
		sess->long_data_len = 0;
		sess->bd_state = 0;
	}
}

static int send_recv_sync(struct wd_ctx_internal *ctx, struct wd_digest_sess *dsess,
			  struct wd_digest_msg *msg)
{
	struct wd_msg_handle msg_handle;
	int ret;

	msg_handle.send = wd_digest_setting.driver->digest_send;
	msg_handle.recv = wd_digest_setting.driver->digest_recv;

	pthread_spin_lock(&ctx->lock);
	ret = wd_handle_msg_sync(&msg_handle, ctx->ctx, msg,
				 NULL, wd_digest_setting.config.epoll_en);
	if (unlikely(ret))
		goto out;

	/*
	 * non-zero is final BD or middle BD as stream mode.
	 */
	dsess->bd_state = msg->has_next;

out:
	pthread_spin_unlock(&ctx->lock);
	return ret;
}

int wd_do_digest_sync(handle_t h_sess, struct wd_digest_req *req)
{
	struct wd_ctx_config_internal *config = &wd_digest_setting.config;
	struct wd_digest_sess *dsess = (struct wd_digest_sess *)h_sess;
	struct wd_ctx_internal *ctx;
	struct wd_digest_msg msg;
	__u32 idx;
	int ret;

	ret = wd_digest_param_check(dsess, req);
	if (unlikely(ret))
		return -WD_EINVAL;

	memset(&msg, 0, sizeof(struct wd_digest_msg));
	fill_request_msg(&msg, req, dsess);
	req->state = 0;

	idx = wd_digest_setting.sched.pick_next_ctx(
		wd_digest_setting.sched.h_sched_ctx,
		dsess->sched_key, CTX_MODE_SYNC);
	ret = wd_check_ctx(config, CTX_MODE_SYNC, idx);
	if (unlikely(ret))
		return ret;

	wd_dfx_msg_cnt(config->msg_cnt, WD_CTX_CNT_NUM, idx);
	ctx = config->ctxs + idx;
	ret = send_recv_sync(ctx, dsess, &msg);
	req->state = msg.result;

	return ret;
}

int wd_do_digest_async(handle_t h_sess, struct wd_digest_req *req)
{
	struct wd_ctx_config_internal *config = &wd_digest_setting.config;
	struct wd_digest_sess *dsess = (struct wd_digest_sess *)h_sess;
	struct wd_ctx_internal *ctx;
	struct wd_digest_msg *msg;
	int msg_id, ret;
	__u32 idx;

	ret = wd_digest_param_check(dsess, req);
	if (unlikely(ret))
		return -WD_EINVAL;

	if (unlikely(!req->cb)) {
		WD_ERR("invalid: digest input req cb is NULL!\n");
		return -WD_EINVAL;
	}

	idx = wd_digest_setting.sched.pick_next_ctx(
		wd_digest_setting.sched.h_sched_ctx,
		dsess->sched_key, CTX_MODE_ASYNC);
	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	wd_dfx_msg_cnt(config->msg_cnt, WD_CTX_CNT_NUM, idx);
	ctx = config->ctxs + idx;

	msg_id = wd_get_msg_from_pool(&wd_digest_setting.pool, idx,
				   (void **)&msg);
	if (unlikely(msg_id < 0)) {
		WD_ERR("busy, failed to get msg from pool!\n");
		return -WD_EBUSY;
	}

	fill_request_msg(msg, req, dsess);
	msg->tag = msg_id;

	ret = wd_digest_setting.driver->digest_send(ctx->ctx, msg);
	if (unlikely(ret < 0)) {
		if (ret != -WD_EBUSY)
			WD_ERR("failed to send BD, hw is err!\n");

		goto fail_with_msg;
	}

	ret = wd_add_task_to_async_queue(&wd_digest_env_config, idx);
	if (ret)
		goto fail_with_msg;

	return 0;

fail_with_msg:
	wd_put_msg_to_pool(&wd_digest_setting.pool, idx, msg->tag);
	return ret;
}

struct wd_digest_msg *wd_digest_get_msg(__u32 idx, __u32 tag)
{
	return wd_find_msg_in_pool(&wd_digest_setting.pool, idx, tag);
}

int wd_digest_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_digest_setting.config;
	struct wd_ctx_internal *ctx;
	struct wd_digest_msg recv_msg, *msg;
	struct wd_digest_req *req;
	__u32 recv_cnt = 0;
	__u32 tmp = expt;
	int ret;

	if (unlikely(!count)) {
		WD_ERR("invalid: digest poll ctx input param is NULL!\n");
		return -WD_EINVAL;
	}

	*count = 0;

	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	do {
		ret = wd_digest_setting.driver->digest_recv(ctx->ctx,
							    &recv_msg);
		if (ret == -WD_EAGAIN) {
			return ret;
		} else if (ret < 0) {
			WD_ERR("wd recv err!\n");
			return ret;
		}

		recv_cnt++;

		msg = wd_find_msg_in_pool(&wd_digest_setting.pool, idx,
					  recv_msg.tag);
		if (!msg) {
			WD_ERR("failed to get msg from pool!\n");
			return -WD_EINVAL;
		}

		msg->req.state = recv_msg.result;
		req = &msg->req;
		if (likely(req))
			req->cb(req);

		wd_put_msg_to_pool(&wd_digest_setting.pool, idx,
				   recv_msg.tag);
		*count = recv_cnt;
	} while (--tmp);

	return ret;
}

int wd_digest_poll(__u32 expt, __u32 *count)
{
	handle_t h_ctx = wd_digest_setting.sched.h_sched_ctx;
	struct wd_sched *sched = &wd_digest_setting.sched;

	if (unlikely(!count)) {
		WD_ERR("invalid: digest poll input param is NULL!\n");
		return -WD_EINVAL;
	}

	return sched->poll_policy(h_ctx, expt, count);
}

static const struct wd_config_variable table[] = {
	{ .name = "WD_DIGEST_CTX_NUM",
	  .def_val = "sync:2@0,async:2@0",
	  .parse_fn = wd_parse_ctx_num
	},
	{ .name = "WD_DIGEST_ASYNC_POLL_EN",
	  .def_val = "0",
	  .parse_fn = wd_parse_async_poll_en
	}
};

static const struct wd_alg_ops wd_digest_ops = {
	.alg_name = "digest",
	.op_type_num = 1,
	.alg_init = wd_digest_init,
	.alg_uninit = wd_digest_uninit,
	.alg_poll_ctx = wd_digest_poll_ctx
};

int wd_digest_env_init(struct wd_sched *sched)
{
	wd_digest_env_config.sched = sched;

	return wd_alg_env_init(&wd_digest_env_config, table,
			       &wd_digest_ops, ARRAY_SIZE(table), NULL);
}

void wd_digest_env_uninit(void)
{
	return wd_alg_env_uninit(&wd_digest_env_config, &wd_digest_ops);
}

int wd_digest_ctx_num_init(__u32 node, __u32 type, __u32 num, __u8 mode)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, num);
	if (ret)
		return ret;

	return wd_alg_env_init(&wd_digest_env_config, table,
			      &wd_digest_ops, ARRAY_SIZE(table), &ctx_attr);
}

void wd_digest_ctx_num_uninit(void)
{
	return wd_alg_env_uninit(&wd_digest_env_config, &wd_digest_ops);
}

int wd_digest_get_env_param(__u32 node, __u32 type, __u32 mode,
			    __u32 *num, __u8 *is_enable)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, 0);
	if (ret)
		return ret;

	return wd_alg_get_env_param(&wd_digest_env_config,
				    ctx_attr, num, is_enable);
}
