/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#include <stdlib.h>
#include <pthread.h>
#include "wd_digest.h"
#include "include/drv/wd_digest_drv.h"
#include "wd_util.h"

#define XTS_MODE_KEY_DIVISOR	2
#define SM4_KEY_SIZE		16
#define DES_KEY_SIZE		8
#define DES3_3KEY_SIZE		(3 * DES_KEY_SIZE)

#define WD_POOL_MAX_ENTRIES	1024
#define DES_WEAK_KEY_NUM	4
#define MAX_RETRY_COUNTS	200000000

#define POLL_SIZE		100000
#define POLL_TIME		1000

static int g_digest_mac_len[WD_DIGEST_TYPE_MAX] = {
	WD_DIGEST_SM3_LEN, WD_DIGEST_MD5_LEN, WD_DIGEST_SHA1_LEN,
	WD_DIGEST_SHA256_LEN, WD_DIGEST_SHA224_LEN,
	WD_DIGEST_SHA384_LEN, WD_DIGEST_SHA512_LEN,
	WD_DIGEST_SHA512_224_LEN, WD_DIGEST_SHA512_256_LEN
};
struct wd_digest_setting {
	struct wd_ctx_config_internal config;
	struct wd_sched	sched;
	struct wd_digest_driver	*driver;
	struct wd_async_msg_pool pool;
	void *sched_ctx;
	void *priv;
}wd_digest_setting;

struct wd_env_config wd_digest_env_config;

#ifdef WD_STATIC_DRV
extern struct wd_digest_driver wd_digest_hisi_digest_driver;
static void wd_digest_set_static_drv(void)
{
	/*
	 * Fix me: a parameter can be introduced to decide to choose
	 * specific driver. Same as dynamic case.
	 */
	wd_digest_setting.driver = &wd_digest_hisi_digest_driver;
}
#else
static void __attribute__((constructor)) wd_digest_open_driver(void)
{
	void *driver;

	/* Fix me: vendor driver should be put in /usr/lib/wd/ */
	driver = dlopen("libhisi_sec.so", RTLD_NOW);
	if (!driver)
		WD_ERR("fail to open libhisi_sec.so\n");
}
#endif

void wd_digest_set_driver(struct wd_digest_driver *drv)
{
	wd_digest_setting.driver = drv;
}

int wd_digest_set_key(handle_t h_sess, const __u8 *key, __u32 key_len)
{
	struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;

	if (!key || !sess || !sess->key) {
		WD_ERR("failed to check key param!\n");
		return -WD_EINVAL;
	}

	if ((sess->alg <= WD_DIGEST_SHA224 && key_len >
		MAX_HMAC_KEY_SIZE >> 1) || key_len == 0 ||
		key_len > MAX_HMAC_KEY_SIZE) {
		WD_ERR("failed to check digest key length!\n");
		return -WD_EINVAL;
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
	sess->numa = setup->numa;

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
	free(sess);
}

int wd_digest_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	void *priv;
	int ret;

	if (wd_digest_setting.config.ctx_num) {
		WD_ERR("digest have initialized.\n");
		return -WD_EEXIST;
	}

	if (!config || !sched) {
		WD_ERR("failed to check input param!\n");
		return -WD_EINVAL;
	}

	if (!wd_is_sva(config->ctxs[0].ctx)) {
		WD_ERR("err, non sva, please check system!\n");
		return -WD_EINVAL;
	}

	ret = wd_init_ctx_config(&wd_digest_setting.config, config);
	if (ret < 0) {
		WD_ERR("failed to set config, ret = %d!\n", ret);
		return ret;
	}

	ret = wd_init_sched(&wd_digest_setting.sched, sched);
	if (ret < 0) {
		WD_ERR("failed to set sched, ret = %d!\n", ret);
		goto out;
	}

	/* set driver */
#ifdef WD_STATIC_DRV
	wd_digest_set_static_drv();
#endif

	/* sadly find we allocate async pool for every ctx */
	ret = wd_init_async_request_pool(&wd_digest_setting.pool,
					 config->ctx_num, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_digest_msg));
	if (ret < 0) {
		WD_ERR("failed to init req pool, ret = %d!\n", ret);
		goto out_sched;
	}

	/* init ctx related resources in specific driver */
	priv = malloc(wd_digest_setting.driver->drv_ctx_size);
	if (!priv) {
		WD_ERR("failed to alloc digest driver ctx!\n");
		ret = -WD_ENOMEM;
		goto out_priv;
	}
	memset(priv, 0, wd_digest_setting.driver->drv_ctx_size);
	wd_digest_setting.priv = priv;
	/* sec init */
	ret = wd_digest_setting.driver->init(&wd_digest_setting.config, priv);
	if (ret < 0) {
		WD_ERR("failed to init digest dirver!\n");
		goto out_init;
	}

	return 0;

out_init:
	free(priv);
out_priv:
	wd_uninit_async_request_pool(&wd_digest_setting.pool);
out_sched:
	wd_clear_sched(&wd_digest_setting.sched);
out:
	wd_clear_ctx_config(&wd_digest_setting.config);
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
}

static int digest_param_check(struct wd_digest_sess *sess,
	struct wd_digest_req *req)
{
	int ret;

	if (unlikely(!sess || !req)) {
		WD_ERR("digest input sess or req is NULL.\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->out_buf_bytes < req->out_bytes)) {
		WD_ERR("failed to check digest out buffer length!\n");
		return -WD_EINVAL;
	}

	if (unlikely(sess->alg >= WD_DIGEST_TYPE_MAX || req->out_bytes == 0 ||
	    req->out_bytes > g_digest_mac_len[sess->alg])) {
		WD_ERR("failed to check digest type or mac length!\n");
		return -WD_EINVAL;
	}

	if (req->data_fmt == WD_SGL_BUF) {
		ret = wd_check_datalist(req->list_in, req->in_bytes);
		if (unlikely(ret)) {
			WD_ERR("failed to check the src datalist!\n");
			return -WD_EINVAL;
		}
	}

	return 0;
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
	msg->in = req->in;
	msg->in_bytes = req->in_bytes;
	msg->out = req->out;
	msg->out_bytes = req->out_bytes;
	msg->data_fmt = req->data_fmt;
	msg->has_next = req->has_next;
	sess->long_data_len += req->in_bytes;
	msg->long_data_len = sess->long_data_len;
	/* To store the stream bd state */
	msg->iv_bytes = sess->state;
}

int wd_do_digest_sync(handle_t h_sess, struct wd_digest_req *req)
{
	struct wd_ctx_config_internal *config = &wd_digest_setting.config;
	struct wd_digest_sess *dsess = (struct wd_digest_sess *)h_sess;
	struct wd_ctx_internal *ctx;
	struct wd_digest_msg msg;
	struct sched_key key;
	__u64 recv_cnt = 0;
	__u32 idx;
	int ret;

	ret = digest_param_check(dsess, req);
	if (unlikely(ret))
		return -WD_EINVAL;

	key.mode = CTX_MODE_SYNC;
	key.type = 0;
	key.numa_id = dsess->numa;

	idx = wd_digest_setting.sched.pick_next_ctx(
		wd_digest_setting.sched.h_sched_ctx, req, &key);
	ret = wd_check_ctx(config, CTX_MODE_SYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	memset(&msg, 0, sizeof(struct wd_digest_msg));
	fill_request_msg(&msg, req, dsess);
	req->state = 0;

	pthread_spin_lock(&ctx->lock);
	ret = wd_digest_setting.driver->digest_send(ctx->ctx, &msg);
	if (unlikely(ret < 0)) {
		WD_ERR("failed to send bd!\n");
		goto err_out;
	}

	do {
		if (req->in_bytes >= POLL_SIZE) {
			ret = wd_ctx_wait(ctx->ctx, POLL_TIME);
			if (unlikely(ret < 0))
				WD_ERR("wd ctx wait timeout(%d)!\n", ret);
		}
		ret = wd_digest_setting.driver->digest_recv(ctx->ctx, &msg);
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
		dsess->state = msg.out_bytes;
	} while (ret < 0);

	pthread_spin_unlock(&ctx->lock);

	return 0;

err_out:
	pthread_spin_unlock(&ctx->lock);
	return ret;
}

int wd_do_digest_async(handle_t h_sess, struct wd_digest_req *req)
{
	struct wd_ctx_config_internal *config = &wd_digest_setting.config;
	struct wd_digest_sess *dsess = (struct wd_digest_sess *)h_sess;
	struct wd_ctx_internal *ctx;
	struct wd_digest_msg *msg;
	struct sched_key key;
	int msg_id, ret;
	__u32 idx;

	ret = digest_param_check(dsess, req);
	if (unlikely(ret))
		return -WD_EINVAL;

	if (unlikely(!req->cb)) {
		WD_ERR("digest input req cb is NULL.\n");
		return -WD_EINVAL;
	}

	key.mode = CTX_MODE_ASYNC;
	key.type = 0;
	key.numa_id = dsess->numa;

	idx = wd_digest_setting.sched.pick_next_ctx(
		wd_digest_setting.sched.h_sched_ctx, req, &key);
	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

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

		wd_put_msg_to_pool(&wd_digest_setting.pool, idx, msg->tag);
		return ret;
	}

	wd_add_task_to_async_queue(&wd_digest_env_config, idx);

	return 0;
}

int wd_digest_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_digest_setting.config;
	struct wd_ctx_internal *ctx;
	struct wd_digest_msg recv_msg, *msg;
	struct wd_digest_req *req;
	__u32 recv_cnt = 0;
	int ret;

	if (unlikely(!count)) {
		WD_ERR("digest count is NULL.\n");
		return -WD_EINVAL;
	}

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
	} while (--expt);

	return ret;
}

int wd_digest_poll(__u32 expt, __u32 *count)
{
	handle_t h_ctx = wd_digest_setting.sched.h_sched_ctx;
	struct wd_sched *sched = &wd_digest_setting.sched;

	if (unlikely(!sched->poll_policy)) {
		WD_ERR("failed to check digest poll_policy!\n");
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

int wd_digest_env_init(void)
{
	return wd_alg_env_init(&wd_digest_env_config, table,
			       &wd_digest_ops, ARRAY_SIZE(table), NULL);
}

void wd_digest_env_uninit(void)
{
	return wd_alg_env_uninit(&wd_digest_env_config);
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
	return wd_alg_env_uninit(&wd_digest_env_config);
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
