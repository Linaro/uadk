/* SPDX-License-Identifier: Apache-2.0 */
#include <stdlib.h>
#include <pthread.h>
#include "wd_digest.h"
#include "include/drv/wd_digest_drv.h"
#include "wd_util.h"

#define XTS_MODE_KEY_DIVISOR	2
#define SM4_KEY_SIZE		16
#define DES_KEY_SIZE		8
#define DES3_3KEY_SIZE		(3 * DES_KEY_SIZE)
#define MAX_CIPHER_KEY_SIZE	64

#define MAX_HMAC_KEY_SIZE	128
#define WD_POOL_MAX_ENTRIES	1024
#define DES_WEAK_KEY_NUM	4
#define MAX_RETRY_COUNTS	200000000

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

	if (!setup) {
		WD_ERR("failed to check alloc sess param!\n");
		return (handle_t)0;
	}

	sess = malloc(sizeof(struct wd_digest_sess));
	if (!sess)
		return (handle_t)0;
	memset(sess, 0, sizeof(struct wd_digest_sess));

	sess->alg = setup->alg;
	sess->mode = setup->mode;
	sess->key = malloc(MAX_HMAC_KEY_SIZE);
	if (!sess->key) {
		free(sess);
		WD_ERR("failed to alloc sess key!\n");
		return (handle_t)0;
	}
	memset(sess->key, 0, MAX_HMAC_KEY_SIZE);

	return (handle_t)sess;
}

void wd_digest_free_sess(handle_t h_sess)
{
	struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;

	if (!sess) {
		WD_ERR("failed to check free sess param!\n");
		return;
	}

	if (sess->key) {
		wd_memset_zero(sess->key, MAX_HMAC_KEY_SIZE);
		free(sess->key);
	}
	free(sess);
}

int wd_digest_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	void *priv;
	int ret;

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
	priv = malloc(sizeof(wd_digest_setting.driver->drv_ctx_size));
	if (!priv) {
		WD_ERR("failed to alloc digest driver ctx!\n");
		ret = -WD_ENOMEM;
		goto out_priv;
	}
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

	if (req->out_buf_bytes < req->out_bytes) {
		WD_ERR("failed to check digest out buffer length!\n");
		return -WD_EINVAL;
	}

	if (sess->alg >= WD_DIGEST_TYPE_MAX || req->out_bytes == 0 ||
	    req->out_bytes > g_digest_mac_len[sess->alg]) {
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
	msg->has_next = req->has_next;
	msg->data_fmt = req->data_fmt;
}

int wd_do_digest_sync(handle_t h_sess, struct wd_digest_req *req)
{
	struct wd_ctx_config_internal *config = &wd_digest_setting.config;
	struct wd_digest_sess *dsess = (struct wd_digest_sess *)h_sess;
	struct wd_ctx_internal *ctx;
	struct wd_digest_msg msg;
	__u64 recv_cnt = 0;
	int index, ret;

	ret = digest_param_check(dsess, req);
	if (ret)
		return -WD_EINVAL;

	/* fix me: maybe wrong */
	index = wd_digest_setting.sched.pick_next_ctx(0, req, NULL);
	if (unlikely(index >= config->ctx_num)) {
		WD_ERR("fail to pick next ctx!\n");
		return -WD_EINVAL;
	}
	ctx = config->ctxs + index;
	if (ctx->ctx_mode != CTX_MODE_SYNC) {
                WD_ERR("failed to check ctx mode!\n");
                return -WD_EINVAL;
        }

	memset(&msg, 0, sizeof(struct wd_digest_msg));
	fill_request_msg(&msg, req, dsess);
	req->state = 0;

	pthread_spin_lock(&ctx->lock);
	ret = wd_digest_setting.driver->digest_send(ctx->ctx, &msg);
	if (ret < 0) {
		pthread_spin_unlock(&ctx->lock);
		WD_ERR("failed to send bd!\n");
		return ret;
	}

	do {
		ret = wd_digest_setting.driver->digest_recv(ctx->ctx, &msg);
		req->state = msg.result;
		if (ret == -WD_HW_EACCESS) {
			WD_ERR("failed to recv bd!\n");
			goto recv_err;
		} else if (ret == -WD_EAGAIN) {
			if (++recv_cnt > MAX_RETRY_COUNTS) {
				WD_ERR("failed to recv bd and timeout!\n");
				ret = -WD_ETIMEDOUT;
				goto recv_err;
			}
		}
	} while (ret < 0);

	pthread_spin_unlock(&ctx->lock);

	return 0;

recv_err:
	pthread_spin_unlock(&ctx->lock);
	return ret;
}

int wd_do_digest_async(handle_t h_sess, struct wd_digest_req *req)
{
	struct wd_ctx_config_internal *config = &wd_digest_setting.config;
	struct wd_digest_sess *dsess = (struct wd_digest_sess *)h_sess;
	struct wd_ctx_internal *ctx;
	struct wd_digest_msg *msg;
	int index, idx, ret;

	ret = digest_param_check(dsess, req);
	if (ret)
		return -WD_EINVAL;

	if (unlikely(!req->cb)) {
		WD_ERR("digest input req cb is NULL.\n");
		return -WD_EINVAL;
	}

	index = wd_digest_setting.sched.pick_next_ctx(0, req, NULL);
	if (unlikely(index >= config->ctx_num)) {
		WD_ERR("fail to pick next ctx!\n");
		return -WD_EINVAL;
	}
	ctx = config->ctxs + index;
	if (ctx->ctx_mode != CTX_MODE_ASYNC) {
                WD_ERR("failed to check ctx mode!\n");
                return -WD_EINVAL;
        }

	idx = wd_get_msg_from_pool(&wd_digest_setting.pool, index,
				   (void **)&msg);
	if (idx < 0) {
		WD_ERR("busy, failed to get msg from pool!\n");
		return -WD_EBUSY;
	}

	fill_request_msg(msg, req, dsess);
	msg->tag = idx;

	ret = wd_digest_setting.driver->digest_send(ctx->ctx, msg);
	if (ret < 0) {
		WD_ERR("failed to send BD, hw is err!\n");
		wd_put_msg_to_pool(&wd_digest_setting.pool, index, msg->tag);
		return ret;
	}

	return 0;
}

int wd_digest_poll_ctx(__u32 index, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_digest_setting.config;
	struct wd_ctx_internal *ctx = config->ctxs + index;
	struct wd_digest_msg recv_msg, *msg;
	struct wd_digest_req *req;
	__u32 recv_cnt = 0;
	int ret;

	if (unlikely(index >= config->ctx_num || !count)) {
		WD_ERR("digest input poll ctx or count is NULL.\n");
		return -WD_EINVAL;
	}

	do {
		ret = wd_digest_setting.driver->digest_recv(ctx->ctx,
							    &recv_msg);
		if (ret == -WD_EAGAIN) {
			break;
		} else if (ret < 0) {
			WD_ERR("wd recv err!\n");
			break;
		}

		expt--;
		recv_cnt++;

		msg = wd_find_msg_in_pool(&wd_digest_setting.pool, index,
					  recv_msg.tag);
		if (!msg) {
			WD_ERR("failed to get msg from pool!\n");
			break;
		}

		msg->req.state = recv_msg.result;
		req = &msg->req;
		if (likely(req))
			req->cb(req);

		wd_put_msg_to_pool(&wd_digest_setting.pool, index,
				   recv_msg.tag);
	} while (expt > 0);
	*count = recv_cnt;

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
