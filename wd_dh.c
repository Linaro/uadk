/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>

#include "config.h"
#include "include/drv/wd_dh_drv.h"
#include "wd_dh.h"
#include "wd_util.h"

#define WD_POOL_MAX_ENTRIES		1024
#define DH_BALANCE_THRHD		1280
#define DH_RESEND_CNT			8
#define DH_MAX_KEY_SIZE			512
#define DH_RECV_MAX_CNT			60000000 // 1 min
#define WD_DH_G2			2

static __thread int balance;

struct wd_dh_sess {
	__u32 alg_type;
	__u32 key_size;
	struct wd_dtb g;
	struct wd_dh_sess_setup setup;
	struct sched_key key;
};

static struct wd_dh_setting {
	struct wd_ctx_config_internal config;
	struct wd_sched sched;
	void *sched_ctx;
	const struct wd_dh_driver *driver;
	void *priv;
	struct wd_async_msg_pool pool;
} wd_dh_setting;

struct wd_env_config wd_dh_env_config;

#ifdef WD_STATIC_DRV
extern const struct wd_dh_driver wd_dh_hisi_hpre;
static void wd_dh_set_static_drv(void)
{
	wd_dh_setting.driver = &wd_dh_hisi_hpre;
}
#else
static void __attribute__((constructor)) wd_dh_open_driver(void)
{
	void *driver;

	driver = dlopen("libhisi_hpre.so", RTLD_NOW);
	if (!driver)
		WD_ERR("Fail to open libhisi_hpre.so\n");
}
#endif

void wd_dh_set_driver(struct wd_dh_driver *drv)
{
	if (!drv) {
		WD_ERR("drv NULL\n");
		return;
	}

	wd_dh_setting.driver = drv;
}

static int param_check(struct wd_ctx_config *config, struct wd_sched *sched)
{
	if (!config || !config->ctxs[0].ctx || !sched) {
		WD_ERR("config or sched NULL\n");
		return -WD_EINVAL;
	}

	if (!wd_is_sva(config->ctxs[0].ctx)) {
		WD_ERR("no sva, do not dh init\n");
		return -WD_EINVAL;
	}

	return 0;
}

int wd_dh_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	void *priv;
	int ret;

	if (param_check(config, sched))
		return -WD_EINVAL;

	ret = wd_init_ctx_config(&wd_dh_setting.config, config);
	if (ret) {
		WD_ERR("failed to wd initialize ctx config, ret = %d\n", ret);
		return ret;
	}

	ret = wd_init_sched(&wd_dh_setting.sched, sched);
	if (ret) {
		WD_ERR("failed to wd initialize sched, ret = %d\n", ret);
		goto out;
	}

#ifdef WD_STATIC_DRV
	wd_dh_set_static_drv();
#endif

	/* initialize async request pool */
	ret = wd_init_async_request_pool(&wd_dh_setting.pool,
					 config->ctx_num, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_dh_msg));
	if (ret) {
		WD_ERR("failed to initialize async req pool, ret = %d!\n", ret);
		goto out_sched;
	}

	/* initialize ctx related resources in specific driver */
	priv = malloc(wd_dh_setting.driver->drv_ctx_size);
	if (!priv) {
		WD_ERR("failed to calloc drv ctx\n");
		ret = -WD_ENOMEM;
		goto out_priv;
	}

	memset(priv, 0, wd_dh_setting.driver->drv_ctx_size);
	wd_dh_setting.priv = priv;
	ret = wd_dh_setting.driver->init(&wd_dh_setting.config, priv,
					 wd_dh_setting.driver->alg_name);
	if (ret < 0) {
		WD_ERR("failed to drv init, ret= %d\n", ret);
		goto out_init;
	}

	return 0;

out_init:
	free(priv);
out_priv:
	wd_uninit_async_request_pool(&wd_dh_setting.pool);
out_sched:
	wd_clear_sched(&wd_dh_setting.sched);
out:
	wd_clear_ctx_config(&wd_dh_setting.config);

	return ret;
}

void wd_dh_uninit(void)
{
	if (!wd_dh_setting.priv) {
		WD_ERR("repeat uninit dh\n");
		return;
	}

	/* driver uninit */
	wd_dh_setting.driver->exit(wd_dh_setting.priv);
	free(wd_dh_setting.priv);
	wd_dh_setting.priv = NULL;

	/* uninit async request pool */
	wd_uninit_async_request_pool(&wd_dh_setting.pool);

	/* unset config, sched, driver */
	wd_clear_sched(&wd_dh_setting.sched);
	wd_clear_ctx_config(&wd_dh_setting.config);
}

static int fill_dh_msg(struct wd_dh_msg *msg, struct wd_dh_req *req,
			struct wd_dh_sess *sess)
{
	memcpy(&msg->req, req, sizeof(*req));
	msg->result = WD_EINVAL;
	msg->key_bytes = sess->key_size;

	if (unlikely(req->pri_bytes < sess->key_size)) {
		WD_ERR("req pri bytes = %hu error!\n", req->pri_bytes);
		return -WD_EINVAL;
	}

	if (req->op_type == WD_DH_PHASE1) {
		msg->g = (__u8 *)sess->g.data;
		msg->gbytes = sess->g.dsize;
	} else if (req->op_type == WD_DH_PHASE2) {
		msg->g = (__u8 *)req->pv;
		msg->gbytes = req->pvbytes;
	} else {
		WD_ERR("op_type = %hhu error!\n", req->op_type);
		return -WD_EINVAL;
	}

	if (!msg->g) {
		WD_ERR("request dh g is NULL!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int dh_send(handle_t ctx, struct wd_dh_msg *msg)
{
	__u32 tx_cnt = 0;
	int ret;

	do {
		ret = wd_dh_setting.driver->send(ctx, msg);
		if (ret == -WD_EBUSY) {
			if (tx_cnt++ >= DH_RESEND_CNT) {
				WD_ERR("failed to send: retry exit!\n");
				break;
			}
			usleep(1);
		} else if (ret < 0) {
			WD_ERR("failed to send: send error = %d!\n", ret);
			break;
		}
	} while (ret);

	return ret;
}

static int dh_recv_sync(handle_t ctx, struct wd_dh_msg *msg)
{
	struct wd_dh_req *req = &msg->req;
	__u32 rx_cnt = 0;
	int ret;

	do {
		ret = wd_dh_setting.driver->recv(ctx, msg);
		if (ret == -WD_EAGAIN) {
			if (rx_cnt++ >= DH_RECV_MAX_CNT) {
				WD_ERR("failed to recv: timeout!\n");
				return -WD_ETIMEDOUT;
			}

			if (balance > DH_BALANCE_THRHD)
				usleep(1);
		} else if (ret < 0) {
			WD_ERR("failed to recv: error = %d!\n", ret);
			return ret;
		}
	} while (ret < 0);

	balance = rx_cnt;
	req->status = msg->result;

	return GET_NEGATIVE(req->status);
}

int wd_do_dh_sync(handle_t sess, struct wd_dh_req *req)
{
	struct wd_ctx_config_internal *config = &wd_dh_setting.config;
	handle_t h_sched_ctx = wd_dh_setting.sched.h_sched_ctx;
	struct wd_dh_sess *sess_t = (struct wd_dh_sess *)sess;
	struct wd_ctx_internal *ctx;
	struct wd_dh_msg msg;
	__u32 idx;
	int ret;

	if (unlikely(!sess || !req)) {
		WD_ERR("input param NULL!\n");
		return -WD_EINVAL;
	}

	sess_t->key.mode = CTX_MODE_SYNC;
	idx = wd_dh_setting.sched.pick_next_ctx(h_sched_ctx, req, &sess_t->key);
	ret = wd_check_ctx(config, CTX_MODE_SYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	memset(&msg, 0, sizeof(struct wd_dh_msg));
	ret = fill_dh_msg(&msg, req, sess_t);
	if (unlikely(ret))
		return ret;

	pthread_spin_lock(&ctx->lock);
	ret = dh_send(ctx->ctx, &msg);
	if (unlikely(ret))
		goto fail;

	ret = dh_recv_sync(ctx->ctx, &msg);
	req->pri_bytes = msg.req.pri_bytes;
fail:
	pthread_spin_unlock(&ctx->lock);

	return ret;
}

int wd_do_dh_async(handle_t sess, struct wd_dh_req *req)
{
	struct wd_ctx_config_internal *config = &wd_dh_setting.config;
	handle_t h_sched_ctx = wd_dh_setting.sched.h_sched_ctx;
	struct wd_dh_sess *sess_t = (struct wd_dh_sess *)sess;
	struct wd_dh_msg *msg = NULL;
	struct wd_ctx_internal *ctx;
	int ret, mid;
	__u32 idx;

	if (unlikely(!req || !sess || !req->cb)) {
		WD_ERR("input param NULL!\n");
		return -WD_EINVAL;
	}

	sess_t->key.mode = CTX_MODE_ASYNC;
	idx = wd_dh_setting.sched.pick_next_ctx(h_sched_ctx, req,
						  &sess_t->key);
	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	mid = wd_get_msg_from_pool(&wd_dh_setting.pool, idx, (void **)&msg);
	if (mid < 0)
		return -WD_EBUSY;

	ret = fill_dh_msg(msg, req, (struct wd_dh_sess *)sess);
	if (ret)
		goto fail_with_msg;
	msg->tag = mid;

	pthread_spin_lock(&ctx->lock);
	ret = dh_send(ctx->ctx, msg);
	if (ret) {
		pthread_spin_unlock(&ctx->lock);
		goto fail_with_msg;
	}
	pthread_spin_unlock(&ctx->lock);

	wd_add_task_to_async_queue(&wd_dh_env_config, idx);

	return ret;

fail_with_msg:
	wd_put_msg_to_pool(&wd_dh_setting.pool, idx, mid);

	return ret;
}

int wd_dh_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_dh_setting.config;
	struct wd_ctx_internal *ctx;
	struct wd_dh_msg rcv_msg;
	struct wd_dh_req *req;
	struct wd_dh_msg *msg;
	__u32 rcv_cnt = 0;
	int ret;

	if (unlikely(!count)) {
		WD_ERR("count is NULL!\n");
		return -WD_EINVAL;
	}

	*count = 0;

	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	do {
		ret = wd_dh_setting.driver->recv(ctx->ctx, &rcv_msg);
		if (ret == -WD_EAGAIN) {
			return ret;
		} else if (unlikely(ret)) {
			WD_ERR("failed to async recv, ret = %d!\n", ret);
			*count = rcv_cnt;
			wd_put_msg_to_pool(&wd_dh_setting.pool, idx,
					   rcv_msg.tag);
			return ret;
		}
		rcv_cnt++;
		msg = wd_find_msg_in_pool(&wd_dh_setting.pool,
			idx, rcv_msg.tag);
		if (!msg) {
			WD_ERR("failed to find msg!\n");
			return -WD_EINVAL;
		}

		msg->req.pri_bytes = rcv_msg.req.pri_bytes;
		msg->req.status = rcv_msg.result;
		req = &msg->req;
		req->cb(req);
		wd_put_msg_to_pool(&wd_dh_setting.pool, idx, rcv_msg.tag);
		*count = rcv_cnt;
	} while (--expt);

	return ret;
}

int wd_dh_poll(__u32 expt, __u32 *count)
{
	handle_t h_sched_ctx = wd_dh_setting.sched.h_sched_ctx;

	return wd_dh_setting.sched.poll_policy(h_sched_ctx, expt, count);
}

int wd_dh_get_mode(handle_t sess, __u8 *alg_mode)
{
	if (!sess || !alg_mode) {
		WD_ERR("dh get mode: param NULL!\n");
		return -WD_EINVAL;
	}

	*alg_mode = ((struct wd_dh_sess *)sess)->setup.is_g2;

	return 0;
}

__u32 wd_dh_key_bits(handle_t sess)
{
	if (!sess) {
		WD_ERR("get dh key bits, sess NULL!\n");
		return 0;
	}

	return ((struct wd_dh_sess *)sess)->setup.key_bits;
}

int wd_dh_set_g(handle_t sess, struct wd_dtb *g)
{
	struct wd_dh_sess *sess_t = (struct wd_dh_sess *)sess;

	if (!sess_t || !g) {
		WD_ERR("param NULL!\n");
		return -WD_EINVAL;
	}

	if (g->dsize &&
		g->bsize <= sess_t->g.bsize &&
		g->dsize <= sess_t->g.bsize) {
		memset(sess_t->g.data, 0, g->bsize);
		memcpy(sess_t->g.data, g->data, g->dsize);
		sess_t->g.dsize = g->dsize;
		if (*g->data != WD_DH_G2 && sess_t->setup.is_g2)
			return -WD_EINVAL;
		return WD_SUCCESS;
	}

	return -WD_EINVAL;
}

void wd_dh_get_g(handle_t sess, struct wd_dtb **g)
{
	if (!sess || !g) {
		WD_ERR("param NULL!\n");
		return;
	}

	*g = &((struct wd_dh_sess *)sess)->g;
}

handle_t wd_dh_alloc_sess(struct wd_dh_sess_setup *setup)
{
	struct wd_dh_sess *sess;

	if (!setup) {
		WD_ERR("alloc dh sess setup NULL!\n");
		return (handle_t)0;
	}

	/* key width check */
	if (setup->key_bits != 768 &&
		setup->key_bits != 1024 &&
		setup->key_bits != 1536 &&
		setup->key_bits != 2048 &&
		setup->key_bits != 3072 &&
		setup->key_bits != 4096) {
		WD_ERR("alloc dh sess key_bit %u err!\n", setup->key_bits);
		return (handle_t)0;
	}

	sess = malloc(sizeof(struct wd_dh_sess));
	if (!sess)
		return (handle_t)0;

	memset(sess, 0, sizeof(struct wd_dh_sess));
	memcpy(&sess->setup, setup, sizeof(*setup));
	sess->key_size = setup->key_bits >> BYTE_BITS_SHIFT;

	sess->g.data = malloc(sess->key_size);
	if (!sess->g.data) {
		free(sess);
		return (handle_t)0;
	}
	sess->g.bsize = sess->key_size;

	sess->key.numa_id = setup->numa;

	return (handle_t)sess;
}

void wd_dh_free_sess(handle_t sess)
{
	struct wd_dh_sess *sess_t = (struct wd_dh_sess *)sess;

	if (!sess_t) {
		WD_ERR("free rsa sess param NULL!\n");
		return;
	}

	if (sess_t->g.data)
		free(sess_t->g.data);

	free(sess_t);
}

static const struct wd_config_variable table[] = {
	{ .name = "WD_DH_CTX_NUM",
	  .def_val = "sync:2@0,async:2@0",
	  .parse_fn = wd_parse_ctx_num
	},
	{ .name = "WD_DH_ASYNC_POLL_EN",
	  .def_val = "0",
	  .parse_fn = wd_parse_async_poll_en
	}
};

static const struct wd_alg_ops wd_dh_ops = {
	.alg_name = "dh",
	.op_type_num = 1,
	.alg_init = wd_dh_init,
	.alg_uninit = wd_dh_uninit,
	.alg_poll_ctx = wd_dh_poll_ctx
};

int wd_dh_env_init(void)
{
	return wd_alg_env_init(&wd_dh_env_config, table,
			       &wd_dh_ops, ARRAY_SIZE(table), NULL);
}

void wd_dh_env_uninit(void)
{
	return wd_alg_env_uninit(&wd_dh_env_config);
}

int wd_dh_ctx_num_init(__u32 node, __u32 type, __u32 num, __u8 mode)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, num);
	if (ret)
		return ret;

	return wd_alg_env_init(&wd_dh_env_config, table,
			      &wd_dh_ops, ARRAY_SIZE(table), &ctx_attr);
}

void wd_dh_ctx_num_uninit(void)
{
	return wd_alg_env_uninit(&wd_dh_env_config);
}

int wd_dh_get_env_param(__u32 node, __u32 type, __u32 mode,
			__u32 *num, __u8 *is_enable)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, 0);
	if (ret)
		return ret;

	return wd_alg_get_env_param(&wd_dh_env_config,
				    ctx_attr, num, is_enable);
}
