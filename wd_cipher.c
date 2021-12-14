/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <numa.h>
#include "wd_cipher.h"
#include "wd_util.h"
#include "include/drv/wd_cipher_drv.h"

#define XTS_MODE_KEY_DIVISOR	2
#define SM4_KEY_SIZE		16
#define DES_KEY_SIZE		8
#define DES3_2KEY_SIZE		(2 * DES_KEY_SIZE)
#define DES3_3KEY_SIZE		(3 * DES_KEY_SIZE)

#define WD_POOL_MAX_ENTRIES	1024
#define DES_WEAK_KEY_NUM	4
#define MAX_RETRY_COUNTS	200000000

#define POLL_SIZE		100000
#define POLL_TIME		1000

static __u64 des_weak_key[DES_WEAK_KEY_NUM] = {
	0x0101010101010101, 0xFEFEFEFEFEFEFEFE,
	0xE0E0E0E0F1F1F1F1, 0x1F1F1F1F0E0E0E0E
};

struct wd_cipher_setting {
	struct wd_ctx_config_internal config;
	struct wd_sched      sched;
	void *sched_ctx;
	struct wd_cipher_driver *driver;
	void *priv;
	void *dlhandle;
	struct wd_async_msg_pool pool;
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

#ifdef WD_STATIC_DRV
static void wd_cipher_set_static_drv(void)
{
	wd_cipher_setting.driver = wd_cipher_get_driver();
	if (!wd_cipher_setting.driver)
		WD_ERR("fail to get driver\n");
}
#else
static void __attribute__((constructor)) wd_cipher_open_driver(void)
{
	wd_cipher_setting.dlhandle = dlopen("libhisi_sec.so", RTLD_NOW);
	if (!wd_cipher_setting.dlhandle)
		WD_ERR("fail to open libhisi_sec.so\n");
}

static void __attribute__((destructor)) wd_cipher_close_driver(void)
{
	if (wd_cipher_setting.dlhandle)
		dlclose(wd_cipher_setting.dlhandle);
}
#endif

void wd_cipher_set_driver(struct wd_cipher_driver *drv)
{
	wd_cipher_setting.driver = drv;
}

static bool is_des_weak_key(const __u64 *key)
{
	int i;

	for (i = 0; i < DES_WEAK_KEY_NUM; i++) {
		if (*key == des_weak_key[i])
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
		WD_ERR("unsupported XTS key length, length = %u.\n", length);
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
		WD_ERR("cipher input alg err, alg is %d.\n", sess->alg);
		return -WD_EINVAL;
	}

	return ret;
}

static int cipher_init_check(struct wd_ctx_config *config,
			     struct wd_sched *sched)
{
	if (!config || !sched) {
		WD_ERR("wd cipher config or sched is NULL!\n");
		return -WD_EINVAL;
	}

	if (!wd_is_sva(config->ctxs[0].ctx)) {
		WD_ERR("err, non sva, please check system!\n");
		return -WD_EINVAL;
	}

	return 0;
}

int wd_cipher_set_key(handle_t h_sess, const __u8 *key, __u32 key_len)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)h_sess;
	__u32 length = key_len;
	int ret;

	if (!key || !sess) {
		WD_ERR("cipher set key input param err!\n");
		return -WD_EINVAL;
	}

	if (sess->mode == WD_CIPHER_XTS)
		length = key_len / XTS_MODE_KEY_DIVISOR;

	ret = cipher_key_len_check(sess, length);
	if (ret) {
		WD_ERR("cipher set key input key length err!\n");
		return -WD_EINVAL;
	}
	if (sess->alg == WD_CIPHER_DES && is_des_weak_key((__u64 *)key)) {
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

	if (unlikely(!setup)) {
		WD_ERR("cipher input setup is NULL!\n");
		return (handle_t)0;
	}

	sess = malloc(sizeof(struct wd_cipher_sess));
	if (!sess) {
		WD_ERR("fail to alloc session memory!\n");
		return (handle_t)0;
	}
	memset(sess, 0, sizeof(struct wd_cipher_sess));

	sess->alg = setup->alg;
	sess->mode = setup->mode;
	/* Some simple scheduler don't need scheduling parameters */
	sess->sched_key = (void *)wd_cipher_setting.sched.sched_init(
		wd_cipher_setting.sched.h_sched_ctx, setup->sched_param);
	if (WD_IS_ERR(sess->sched_key)) {
		WD_ERR("failed to init session schedule key!\n");
		free(sess);
		return (handle_t)0;
	}

	return (handle_t)sess;
}

void wd_cipher_free_sess(handle_t h_sess)
{
	struct wd_cipher_sess *sess = (struct wd_cipher_sess *)h_sess;

	if (unlikely(!sess)) {
		WD_ERR("cipher input h_sess is NULL!\n");
		return;
	}

	wd_memset_zero(sess->key, MAX_CIPHER_KEY_SIZE);

	if (sess->sched_key)
		free(sess->sched_key);
	free(sess);
}

int wd_cipher_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	void *priv;
	int ret;

	ret = cipher_init_check(config, sched);
	if (ret)
		return ret;

	ret = wd_init_ctx_config(&wd_cipher_setting.config, config);
	if (ret < 0) {
		WD_ERR("failed to set config, ret = %d!\n", ret);
		return ret;
	}

	ret = wd_init_sched(&wd_cipher_setting.sched, sched);
	if (ret < 0) {
		WD_ERR("failed to set sched, ret = %d!\n", ret);
		goto out;
	}

#ifdef WD_STATIC_DRV
	/* set driver */
	wd_cipher_set_static_drv();
#endif

	/* allocate async pool for every ctx */
	ret = wd_init_async_request_pool(&wd_cipher_setting.pool,
					 config->ctx_num, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_cipher_msg));
	if (ret < 0) {
		WD_ERR("failed to init req pool, ret = %d!\n", ret);
		goto out_sched;
	}

	/* init ctx related resources in specific driver */
	priv = calloc(1, wd_cipher_setting.driver->drv_ctx_size);
	if (!priv) {
		ret = -WD_ENOMEM;
		goto out_priv;
	}
	wd_cipher_setting.priv = priv;

	ret = wd_cipher_setting.driver->init(&wd_cipher_setting.config, priv);
	if (ret < 0) {
		WD_ERR("hisi sec init failed.\n");
		goto out_init;
	}

	return 0;

out_init:
	free(priv);
out_priv:
	wd_uninit_async_request_pool(&wd_cipher_setting.pool);
out_sched:
	wd_clear_sched(&wd_cipher_setting.sched);
out:
	wd_clear_ctx_config(&wd_cipher_setting.config);
	return ret;
}

void wd_cipher_uninit(void)
{
	void *priv = wd_cipher_setting.priv;

	if (!priv)
		return;

	wd_cipher_setting.driver->exit(priv);
	wd_cipher_setting.priv = NULL;
	free(priv);

	wd_uninit_async_request_pool(&wd_cipher_setting.pool);
	wd_clear_sched(&wd_cipher_setting.sched);
	wd_clear_ctx_config(&wd_cipher_setting.config);
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
			WD_ERR("AES or SM4 input iv bytes is err!\n");
			ret = -WD_EINVAL;
		}
		break;
	case WD_CIPHER_3DES:
	case WD_CIPHER_DES:
		if (req->iv_bytes != DES3_BLOCK_SIZE) {
			WD_ERR("3DES or DES input iv bytes is err!\n");
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
	int ret = 0;

	if (unlikely(!h_sess || !req)) {
		WD_ERR("cipher input sess or req is NULL.\n");
		return -WD_EINVAL;
	}

	if (unlikely(mode == CTX_MODE_ASYNC && !req->cb)) {
		WD_ERR("cipher req cb is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->out_buf_bytes < req->in_bytes)) {
		WD_ERR("cipher set out_buf_bytes is error!\n");
		return -WD_EINVAL;
	}

	if (req->data_fmt == WD_SGL_BUF) {
		ret = wd_check_datalist(req->list_src, req->in_bytes);
		if (unlikely(ret)) {
			WD_ERR("failed to check the src datalist!\n");
			return -WD_EINVAL;
		}

		/* cipher dst len is equal to src len */
		ret = wd_check_datalist(req->list_dst, req->in_bytes);
		if (unlikely(ret)) {
			WD_ERR("failed to check the dst datalist!\n");
			return -WD_EINVAL;
		}
	}

	ret = cipher_iv_len_check(req, sess);
	if (unlikely(ret))
		return ret;

	return 0;
}

static int send_recv_sync(struct wd_ctx_internal *ctx,
			  struct wd_cipher_msg *msg)
{
	__u64 recv_cnt = 0;
	int ret;

	pthread_spin_lock(&ctx->lock);
	ret = wd_cipher_setting.driver->cipher_send(ctx->ctx, msg);
	if (unlikely(ret < 0)) {
		WD_ERR("wd cipher send err!\n");
		goto out;
	}

	do {
		if (msg->is_polled) {
			ret = wd_ctx_wait(ctx->ctx, POLL_TIME);
			if (unlikely(ret < 0))
				WD_ERR("wd cipher ctx wait timeout(%d)!\n", ret);
		}
		ret = wd_cipher_setting.driver->cipher_recv(ctx->ctx, msg);
		if (ret == -WD_HW_EACCESS) {
			WD_ERR("wd cipher recv err!\n");
			goto out;
		} else if (ret == -WD_EAGAIN) {
			if (++recv_cnt > MAX_RETRY_COUNTS) {
				WD_ERR("wd cipher recv timeout fail!\n");
				ret = -WD_ETIMEDOUT;
				goto out;
			}
		}
	} while (ret < 0);

out:
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
	msg.is_polled = (req->in_bytes >= POLL_SIZE);
	req->state = 0;

	idx = wd_cipher_setting.sched.pick_next_ctx(
		     wd_cipher_setting.sched.h_sched_ctx,
		     sess->sched_key, CTX_MODE_SYNC);
	ret = wd_check_ctx(config, CTX_MODE_SYNC, idx);
	if (unlikely(ret))
		return ret;

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

	msg_id = wd_get_msg_from_pool(&wd_cipher_setting.pool, idx,
				   (void **)&msg);
	if (unlikely(msg_id < 0)) {
		WD_ERR("busy, failed to get msg from pool!\n");
		return -WD_EBUSY;
	}

	fill_request_msg(msg, req, sess);
	msg->tag = msg_id;
	msg->is_polled = 0;

	ret = wd_cipher_setting.driver->cipher_send(ctx->ctx, msg);
	if (unlikely(ret < 0)) {
		if (ret != -WD_EBUSY)
			WD_ERR("wd cipher async send err!\n");

		wd_put_msg_to_pool(&wd_cipher_setting.pool, idx, msg->tag);
	}

	wd_add_task_to_async_queue(&wd_cipher_env_config, idx);

	return ret;
}

int wd_cipher_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_cipher_setting.config;
	struct wd_ctx_internal *ctx;
	struct wd_cipher_msg resp_msg, *msg;
	struct wd_cipher_req *req;
	__u64 recv_count = 0;
	int ret;

	if (unlikely(!count)) {
		WD_ERR("wd cipher poll ctx input param is NULL!\n");
		return -WD_EINVAL;
	}

	*count = 0;

	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	do {
		ret = wd_cipher_setting.driver->cipher_recv(ctx->ctx, &resp_msg);
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
	} while (--expt);

	return ret;
}

int wd_cipher_poll(__u32 expt, __u32 *count)
{
	handle_t h_ctx = wd_cipher_setting.sched.h_sched_ctx;
	struct wd_sched *sched = &wd_cipher_setting.sched;

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
	return wd_alg_env_uninit(&wd_cipher_env_config);
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
	return wd_alg_env_uninit(&wd_cipher_env_config);
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
