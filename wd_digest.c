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

struct wd_digest_setting {
	struct wd_ctx_config_internal config;
	struct wd_sched	sched;
	struct wd_digest_driver	*driver;
	struct wd_async_msg_pool pool;
	void *sched_ctx;
	void *priv;
};

static struct wd_digest_setting g_wd_digest_setting;
extern struct wd_digest_driver wd_digest_hisi_digest_driver;

#ifdef WD_STATIC_DRV
static void wd_digest_set_static_drv(void)
{
	/*
	 * Fix me: a parameter can be introduced to decide to choose
	 * specific driver. Same as dynamic case.
	 */
	g_wd_digest_setting.driver = &wd_digest_hisi_digest_driver;
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
	g_wd_digest_setting.driver = drv;
}

int wd_digest_set_key(handle_t h_sess, const __u8 *key, __u32 key_len)
{
	struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;
	if (!key || !sess || !sess->key) {
		WD_ERR("fail to check key param!\n");
		return -EINVAL;
	}

	if (key_len > MAX_HMAC_KEY_SIZE) {
		WD_ERR("fail to check key length!\n");
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
		WD_ERR("fail to check alloc sess param!\n");
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
		WD_ERR("fail to alloc sess key!\n");
		return (handle_t)0;
	}
	memset(sess->key, 0, MAX_HMAC_KEY_SIZE);

	return (handle_t)sess;
}

void wd_digest_free_sess(handle_t h_sess)
{
	struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;

	if (!sess) {
		WD_ERR("fail to check free sess param!\n");
		return	;
	}

	if (sess->key)
		free(sess->key);
	free(sess);
}

int wd_digest_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	void *priv;
	int ret;

	if (g_wd_digest_setting.config.ctx_num) {
		WD_ERR("Digest driver is exists, name: %s\n",
		g_wd_digest_setting.driver->drv_name);
		return 0;
	}

	if (!config || !sched) {
		WD_ERR("fail to check input param\n");
		return -EINVAL;
	}

	if (!wd_is_sva(config->ctxs[0].ctx)) {
		WD_ERR("err, non sva, please check system!\n");
		return -EINVAL;
	}

	ret = wd_init_ctx_config(&g_wd_digest_setting.config, config);
	if (ret < 0) {
		WD_ERR("failed to set config, ret = %d!\n", ret);
		return ret;
	}

	ret = wd_init_sched(&g_wd_digest_setting.sched, sched);
	if (ret < 0) {
		WD_ERR("failed to set sched, ret = %d!\n", ret);
		goto out;
	}

	/* set driver */
#ifdef WD_STATIC_DRV
	wd_digest_set_static_drv();
#endif

	/* fix me: sadly find we allocate async pool for every ctx */
	ret = wd_init_async_request_pool(&g_wd_digest_setting.pool,
					 config->ctx_num, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_digest_msg));
	if (ret < 0) {
		WD_ERR("failed to init req pool, ret = %d!\n", ret);
		goto out_sched;
	}

	/* init ctx related resources in specific driver */
	priv = malloc(sizeof(g_wd_digest_setting.driver->drv_ctx_size));
	if (!priv) {
		WD_ERR("fail to alloc digest driver ctx!\n");
		ret = -ENOMEM;
		goto out_priv;
	}
	g_wd_digest_setting.priv = priv;
	/* sec init */
	ret = g_wd_digest_setting.driver->init(&g_wd_digest_setting.config, priv);
	if (ret < 0) {
		WD_ERR("fail to init digest dirver!\n");
		goto out_init;
	}

	return 0;

out_init:
	free(priv);
out_priv:
	wd_uninit_async_request_pool(&g_wd_digest_setting.pool);
out_sched:
	wd_clear_sched(&g_wd_digest_setting.sched);
out:
	wd_clear_ctx_config(&g_wd_digest_setting.config);
	return ret;
}

void wd_digest_uninit(void)
{
	void *priv = g_wd_digest_setting.priv;
	if (!priv)
		return;

	g_wd_digest_setting.driver->exit(priv);
	free(priv);
	g_wd_digest_setting.priv = NULL;
	
	wd_uninit_async_request_pool(&g_wd_digest_setting.pool);

	wd_clear_sched(&g_wd_digest_setting.sched);
	wd_clear_ctx_config(&g_wd_digest_setting.config);
}

static void fill_request_msg(struct wd_digest_msg *msg,
			     struct wd_digest_req *req,
			     struct wd_digest_sess *sess)
{
	memcpy(&msg->req, req, sizeof(struct wd_digest_req));

	msg->alg = sess->alg;
	msg->mode = sess->mode;
	msg->key = sess->key;
	msg->key_bytes = sess->key_bytes;
	msg->in = req->in;
	msg->in_bytes = req->in_bytes;
	msg->out = req->out;
	msg->out_bytes = req->out_bytes;
	msg->has_next = req->has_next;
}

int wd_do_digest_sync(handle_t h_sess, struct wd_digest_req *req)
{
	struct wd_ctx_config_internal *config = &g_wd_digest_setting.config;
	struct wd_digest_sess *dsess = (struct wd_digest_sess *)h_sess;
	struct wd_ctx_internal *ctx;
	struct wd_digest_msg msg;
	__u64 recv_cnt = 0;
	int index, ret;

	if (!dsess || !req) {
		WD_ERR("digest input sess or req is NULL!\n");
		return -EINVAL;
	}

	/* fix me: maybe wrong */
	index = g_wd_digest_setting.sched.pick_next_ctx(0, req, NULL);
	if (index >= config->ctx_num) {
		WD_ERR("fail to pick next ctx!\n");
		return -EINVAL;
	}
	ctx = config->ctxs + index;

	memset(&msg, 0, sizeof(struct wd_digest_msg));
	fill_request_msg(&msg, req, dsess);
	req->state = 0;

	pthread_mutex_lock(&ctx->lock);

	ret = g_wd_digest_setting.driver->digest_send(ctx->ctx, &msg);
	if (ret < 0) {
		pthread_mutex_unlock(&ctx->lock);
		WD_ERR("fail to send bd!\n");
		return ret;
	}

	do {
		ret = g_wd_digest_setting.driver->digest_recv(ctx->ctx, &msg);
		if (ret == -WD_HW_EACCESS) {
			WD_ERR("fail to recv bd!\n");
			goto recv_err;
		} else if (ret == -EAGAIN) {
			if (++recv_cnt > MAX_RETRY_COUNTS) {
				WD_ERR("fail to recv bd and timeout!\n");
				ret = -ETIMEDOUT;
				goto recv_err;
			}
		}
	} while (ret < 0);

	pthread_mutex_unlock(&ctx->lock);

	return 0;

recv_err:
	req->state = msg.result;
	pthread_mutex_unlock(&ctx->lock);
	return ret;
}

int wd_do_digest_async(handle_t h_sess, struct wd_digest_req *req)
{
	struct wd_ctx_config_internal *config = &g_wd_digest_setting.config;
	struct wd_digest_sess *dsess = (struct wd_digest_sess *)h_sess;
	struct wd_ctx_internal *ctx;
        struct wd_digest_msg *msg;
	int index, idx, ret;

        if (!dsess || !req) {
                WD_ERR("digest input sess or req is NULL!\n");
		return -EINVAL;
        }

	index = g_wd_digest_setting.sched.pick_next_ctx(0, req, NULL);
	if (unlikely(index >= config->ctx_num)) {
		WD_ERR("fail to pick next ctx!\n");
		return -EINVAL;
	}
	ctx = config->ctxs + index;

	idx = wd_get_msg_from_pool(&g_wd_digest_setting.pool, index,
				   (void **)&msg);
	if (idx < 0) {
		WD_ERR("busy, failed to get msg from pool!\n");
		return -EBUSY;
	}

	fill_request_msg(msg, req, dsess);
	msg->tag = idx;

	pthread_mutex_lock(&ctx->lock);

	ret = g_wd_digest_setting.driver->digest_send(ctx->ctx, msg);
	if (ret < 0) {
		WD_ERR("fail to  send BD, hw is err!\n");
		wd_put_msg_to_pool(&g_wd_digest_setting.pool, index, msg->tag);
		return ret;
	}

	pthread_mutex_unlock(&ctx->lock);

	return 0;
}

int wd_digest_poll_ctx(__u32 index, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &g_wd_digest_setting.config;
	struct wd_ctx_internal *ctx = config->ctxs + index;
	struct wd_digest_msg recv_msg, *msg;
	struct wd_digest_req *req;
	__u32 recv_cnt = 0;
	int ret;

	if (unlikely(index >= config->ctx_num || !count)) {
		WD_ERR("digest input poll ctx or count is NULL.\n");
		return -EINVAL;
	}

	do {
		pthread_mutex_lock(&ctx->lock);
		ret = g_wd_digest_setting.driver->digest_recv(ctx->ctx,
							      &recv_msg);
		pthread_mutex_unlock(&ctx->lock);
		if (ret == -EAGAIN) {
			break;
		} else if (ret < 0) {
			WD_ERR("wd recv err!\n");
			break;
		}

		expt--;
		recv_cnt++;

		msg = wd_find_msg_in_pool(&g_wd_digest_setting.pool, index,
					  recv_msg.tag);
		if (!msg) {
			WD_ERR("get msg from pool is NULL!\n");
			break;
		}

		req = &msg->req;
		if (likely(req))
			req->cb(req);

		wd_put_msg_to_pool(&g_wd_digest_setting.pool, index,
				   recv_msg.tag);
	} while (expt > 0);
	*count = recv_cnt;

	return ret;
}

int wd_digest_poll(__u32 expt, __u32 *count)
{
	return g_wd_digest_setting.sched.poll_policy(0, 0, expt, count);
}
