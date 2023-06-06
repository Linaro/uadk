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

#include "include/drv/wd_dh_drv.h"
#include "wd_util.h"

#define WD_POOL_MAX_ENTRIES		1024
#define DH_MAX_KEY_SIZE			512
#define WD_DH_G2			2

static __thread __u64 balance;

struct wd_dh_sess {
	__u32 alg_type;
	__u32 key_size;
	struct wd_dtb g;
	struct wd_dh_sess_setup setup;
	void  *sched_key;
};

static struct wd_dh_setting {
	enum wd_status status;
	struct wd_ctx_config_internal config;
	struct wd_sched sched;
	struct wd_async_msg_pool pool;
	struct wd_alg_driver *driver;
	void *priv;
	void *dlhandle;
	void *dlh_list;
} wd_dh_setting;

struct wd_env_config wd_dh_env_config;
static struct wd_init_attrs wd_dh_init_attrs;

static void wd_dh_close_driver(void)
{
	if (!wd_dh_setting.dlhandle)
		return;

	wd_release_drv(wd_dh_setting.driver);
	dlclose(wd_dh_setting.dlhandle);
	wd_dh_setting.dlhandle = NULL;
}

static int wd_dh_open_driver(void)
{
	struct wd_alg_driver *driver = NULL;
	char lib_path[PATH_MAX];
	const char *alg_name = "dh";
	int ret;

	ret = wd_get_lib_file_path("libhisi_hpre.so", lib_path, false);
	if (ret)
		return ret;

	wd_dh_setting.dlhandle = dlopen(lib_path, RTLD_NOW);
	if (!wd_dh_setting.dlhandle) {
		WD_ERR("failed to open libhisi_hpre.so, %s!\n", dlerror());
		return -WD_EINVAL;
	}

	driver = wd_request_drv(alg_name, false);
	if (!driver) {
		wd_dh_close_driver();
		WD_ERR("failed to get %s driver support\n", alg_name);
		return -WD_EINVAL;
	}

	wd_dh_setting.driver = driver;

	return 0;
}

static void wd_dh_clear_status(void)
{
	wd_alg_clear_init(&wd_dh_setting.status);
}

static int wd_dh_common_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	int ret;

	ret = wd_set_epoll_en("WD_DH_EPOLL_EN",
			      &wd_dh_setting.config.epoll_en);
	if (ret < 0)
		return ret;

	ret = wd_init_ctx_config(&wd_dh_setting.config, config);
	if (ret)
		return ret;

	ret = wd_init_sched(&wd_dh_setting.sched, sched);
	if (ret)
		goto out_clear_ctx_config;

	/* initialize async request pool */
	ret = wd_init_async_request_pool(&wd_dh_setting.pool,
					 config->ctx_num, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_dh_msg));
	if (ret)
		goto out_clear_sched;

	ret = wd_alg_init_driver(&wd_dh_setting.config,
				 wd_dh_setting.driver,
				 &wd_dh_setting.priv);
	if (ret)
		goto out_clear_pool;

	return 0;

out_clear_pool:
	wd_uninit_async_request_pool(&wd_dh_setting.pool);
out_clear_sched:
	wd_clear_sched(&wd_dh_setting.sched);
out_clear_ctx_config:
	wd_clear_ctx_config(&wd_dh_setting.config);
	return ret;
}

static int wd_dh_common_uninit(void)
{
	if (!wd_dh_setting.priv) {
		WD_ERR("invalid: repeat uninit dh!\n");
		return -WD_EINVAL;
	}

	/* uninit async request pool */
	wd_uninit_async_request_pool(&wd_dh_setting.pool);

	/* unset config, sched, driver */
	wd_clear_sched(&wd_dh_setting.sched);
	wd_alg_uninit_driver(&wd_dh_setting.config,
			     wd_dh_setting.driver,
			     &wd_dh_setting.priv);

	return 0;
}

int wd_dh_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	bool flag;
	int ret;

	pthread_atfork(NULL, NULL, wd_dh_clear_status);

	flag = wd_alg_try_init(&wd_dh_setting.status);
	if (!flag)
		return -WD_EEXIST;

	ret = wd_init_param_check(config, sched);
	if (ret)
		goto out_clear_init;

	ret = wd_dh_open_driver();
	if (ret)
		goto out_clear_init;

	ret = wd_dh_common_init(config, sched);
	if (ret)
		goto out_close_driver;

	wd_alg_set_init(&wd_dh_setting.status);

	return 0;

out_close_driver:
	wd_dh_close_driver();
out_clear_init:
	wd_alg_clear_init(&wd_dh_setting.status);
	return ret;
}

void wd_dh_uninit(void)
{
	int ret;

	ret = wd_dh_common_uninit();
	if (ret)
		return;

	wd_dh_close_driver();
	wd_alg_clear_init(&wd_dh_setting.status);
}

int wd_dh_init2_(char *alg, __u32 sched_type, int task_type, struct wd_ctx_params *ctx_params)
{
	struct wd_ctx_nums dh_ctx_num[WD_DH_PHASE2] = {0};
	struct wd_ctx_params dh_ctx_params = {0};
	int ret = -WD_EINVAL;
	bool flag;

	pthread_atfork(NULL, NULL, wd_dh_clear_status);

	flag = wd_alg_try_init(&wd_dh_setting.status);
	if (!flag)
		return -WD_EEXIST;

	if (!alg || sched_type >= SCHED_POLICY_BUTT ||
	    task_type < 0 || task_type >= TASK_MAX_TYPE) {
		WD_ERR("invalid: input param is wrong!\n");
		goto out_clear_init;
	}

	if (strcmp(alg, "dh")) {
		WD_ERR("invalid: the alg %s not support!\n", alg);
		goto out_clear_init;
	}

	/*
	 * Driver lib file path could set by env param.
	 * than open tham by wd_dlopen_drv()
	 * default dir in the /root/lib/xxx.so and then dlopen
	 */
	wd_dh_setting.dlh_list = wd_dlopen_drv(NULL);
	if (!wd_dh_setting.dlh_list) {
		WD_ERR("failed to open driver lib files!\n");
		goto out_clear_init;
	}

	while (ret) {
		memset(&wd_dh_setting.config, 0, sizeof(struct wd_ctx_config_internal));

		/* Get alg driver and dev name */
		wd_dh_setting.driver = wd_alg_drv_bind(task_type, alg);
		if (!wd_dh_setting.driver) {
			WD_ERR("fail to bind a valid driver.\n");
			ret = -WD_EINVAL;
			goto out_dlopen;
		}

		dh_ctx_params.ctx_set_num = dh_ctx_num;
		ret = wd_ctx_param_init(&dh_ctx_params, ctx_params,
					wd_dh_setting.driver, WD_DH_TYPE, WD_DH_PHASE2);
		if (ret) {
			if (ret == -WD_EAGAIN) {
				wd_disable_drv(wd_dh_setting.driver);
				wd_alg_drv_unbind(wd_dh_setting.driver);
				continue;
			}
			goto out_driver;
		}

		wd_dh_init_attrs.alg = alg;
		wd_dh_init_attrs.sched_type = sched_type;
		wd_dh_init_attrs.driver = wd_dh_setting.driver;
		wd_dh_init_attrs.ctx_params = &dh_ctx_params;
		wd_dh_init_attrs.alg_init = wd_dh_common_init;
		wd_dh_init_attrs.alg_poll_ctx = wd_dh_poll_ctx;
		ret = wd_alg_attrs_init(&wd_dh_init_attrs);
		if (ret) {
			if (ret == -WD_ENODEV) {
				wd_disable_drv(wd_dh_setting.driver);
				wd_alg_drv_unbind(wd_dh_setting.driver);
				wd_ctx_param_uninit(&dh_ctx_params);
				continue;
			}
			WD_ERR("failed to init alg attrs!\n");
			goto out_params_uninit;
		}
	}

	wd_alg_set_init(&wd_dh_setting.status);
	wd_ctx_param_uninit(&dh_ctx_params);

	return 0;

out_params_uninit:
	wd_ctx_param_uninit(&dh_ctx_params);
out_driver:
	wd_alg_drv_unbind(wd_dh_setting.driver);
out_dlopen:
	wd_dlclose_drv(wd_dh_setting.dlh_list);
out_clear_init:
	wd_alg_clear_init(&wd_dh_setting.status);
	return ret;
}

void wd_dh_uninit2(void)
{
	int ret;

	ret = wd_dh_common_uninit();
	if (ret)
		return;

	wd_alg_attrs_uninit(&wd_dh_init_attrs);
	wd_alg_drv_unbind(wd_dh_setting.driver);
	wd_dlclose_drv(wd_dh_setting.dlh_list);
	wd_dh_setting.dlh_list = NULL;
	wd_alg_clear_init(&wd_dh_setting.status);
}

static int fill_dh_msg(struct wd_dh_msg *msg, struct wd_dh_req *req,
			struct wd_dh_sess *sess)
{
	memcpy(&msg->req, req, sizeof(*req));
	msg->result = WD_EINVAL;
	msg->key_bytes = sess->key_size;

	if (unlikely(req->pri_bytes < sess->key_size)) {
		WD_ERR("invalid: req pri bytes %hu is error!\n", req->pri_bytes);
		return -WD_EINVAL;
	}

	if (req->op_type == WD_DH_PHASE1) {
		msg->g = (__u8 *)sess->g.data;
		msg->gbytes = sess->g.dsize;
	} else if (req->op_type == WD_DH_PHASE2) {
		msg->g = (__u8 *)req->pv;
		msg->gbytes = req->pvbytes;
	} else {
		WD_ERR("invalid: op_type %hhu is error!\n", req->op_type);
		return -WD_EINVAL;
	}

	if (!msg->g) {
		WD_ERR("invalid: request dh g is NULL!\n");
		return -WD_EINVAL;
	}

	return 0;
}

int wd_do_dh_sync(handle_t sess, struct wd_dh_req *req)
{
	struct wd_ctx_config_internal *config = &wd_dh_setting.config;
	handle_t h_sched_ctx = wd_dh_setting.sched.h_sched_ctx;
	struct wd_dh_sess *sess_t = (struct wd_dh_sess *)sess;
	struct wd_msg_handle msg_handle;
	struct wd_ctx_internal *ctx;
	struct wd_dh_msg msg;
	__u32 idx;
	int ret;

	if (unlikely(!sess || !req)) {
		WD_ERR("invalid: input param NULL!\n");
		return -WD_EINVAL;
	}

	idx = wd_dh_setting.sched.pick_next_ctx(h_sched_ctx,
							   sess_t->sched_key,
							   CTX_MODE_SYNC);
	ret = wd_check_ctx(config, CTX_MODE_SYNC, idx);
	if (ret)
		return ret;

	wd_dfx_msg_cnt(config, WD_CTX_CNT_NUM, idx);
	ctx = config->ctxs + idx;

	memset(&msg, 0, sizeof(struct wd_dh_msg));
	ret = fill_dh_msg(&msg, req, sess_t);
	if (unlikely(ret))
		return ret;

	msg_handle.send = wd_dh_setting.driver->send;
	msg_handle.recv = wd_dh_setting.driver->recv;

	pthread_spin_lock(&ctx->lock);
	ret = wd_handle_msg_sync(&msg_handle, ctx->ctx, &msg, &balance,
				 wd_dh_setting.config.epoll_en);
	pthread_spin_unlock(&ctx->lock);
	if (unlikely(ret))
		return ret;

	req->pri_bytes = msg.req.pri_bytes;
	req->status = msg.result;

	return GET_NEGATIVE(msg.result);
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
		WD_ERR("invalid: input param NULL!\n");
		return -WD_EINVAL;
	}

	idx = wd_dh_setting.sched.pick_next_ctx(h_sched_ctx,
							   sess_t->sched_key,
							   CTX_MODE_ASYNC);
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

	ret = wd_dh_setting.driver->send(ctx->ctx, msg);
	if (unlikely(ret)) {
		if (ret != -WD_EBUSY)
			WD_ERR("failed to send dh BD, hw is err!\n");

		goto fail_with_msg;
	}

	wd_dfx_msg_cnt(config, WD_CTX_CNT_NUM, idx);
	ret = wd_add_task_to_async_queue(&wd_dh_env_config, idx);
	if (ret)
		goto fail_with_msg;

	return 0;

fail_with_msg:
	wd_put_msg_to_pool(&wd_dh_setting.pool, idx, mid);

	return ret;
}

struct wd_dh_msg *wd_dh_get_msg(__u32 idx, __u32 tag)
{
	return wd_find_msg_in_pool(&wd_dh_setting.pool, idx, tag);
}

int wd_dh_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_dh_setting.config;
	struct wd_ctx_internal *ctx;
	struct wd_dh_msg rcv_msg;
	struct wd_dh_req *req;
	struct wd_dh_msg *msg;
	__u32 rcv_cnt = 0;
	__u32 tmp = expt;
	int ret;

	if (unlikely(!count)) {
		WD_ERR("invalid: count is NULL!\n");
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
	} while (--tmp);

	return ret;
}

int wd_dh_poll(__u32 expt, __u32 *count)
{
	handle_t h_sched_ctx = wd_dh_setting.sched.h_sched_ctx;

	if (unlikely(!count)) {
		WD_ERR("invalid: dh poll count is NULL!\n");
		return -WD_EINVAL;
	}

	return wd_dh_setting.sched.poll_policy(h_sched_ctx, expt, count);
}

int wd_dh_get_mode(handle_t sess, __u8 *alg_mode)
{
	if (!sess || !alg_mode) {
		WD_ERR("invalid: dh get mode, param NULL!\n");
		return -WD_EINVAL;
	}

	*alg_mode = ((struct wd_dh_sess *)sess)->setup.is_g2;

	return 0;
}

__u32 wd_dh_key_bits(handle_t sess)
{
	if (!sess) {
		WD_ERR("invalid: get dh key bits, sess NULL!\n");
		return 0;
	}

	return ((struct wd_dh_sess *)sess)->setup.key_bits;
}

int wd_dh_set_g(handle_t sess, struct wd_dtb *g)
{
	struct wd_dh_sess *sess_t = (struct wd_dh_sess *)sess;

	if (!sess_t || !g) {
		WD_ERR("invalid: dh set g, param NULL!\n");
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
		WD_ERR("invalid: dh get g, param NULL!\n");
		return;
	}

	*g = &((struct wd_dh_sess *)sess)->g;
}

handle_t wd_dh_alloc_sess(struct wd_dh_sess_setup *setup)
{
	struct wd_dh_sess *sess;

	if (!setup) {
		WD_ERR("invalid: alloc dh sess setup NULL!\n");
		return (handle_t)0;
	}

	/* key width check */
	if (setup->key_bits != 768 &&
		setup->key_bits != 1024 &&
		setup->key_bits != 1536 &&
		setup->key_bits != 2048 &&
		setup->key_bits != 3072 &&
		setup->key_bits != 4096) {
		WD_ERR("invalid: alloc dh sess key_bit %u is err!\n", setup->key_bits);
		return (handle_t)0;
	}

	sess = malloc(sizeof(struct wd_dh_sess));
	if (!sess)
		return (handle_t)0;

	memset(sess, 0, sizeof(struct wd_dh_sess));
	memcpy(&sess->setup, setup, sizeof(*setup));
	sess->key_size = setup->key_bits >> BYTE_BITS_SHIFT;

	sess->g.data = malloc(sess->key_size);
	if (!sess->g.data)
		goto sess_err;

	sess->g.bsize = sess->key_size;
	/* Some simple scheduler don't need scheduling parameters */
	sess->sched_key = (void *)wd_dh_setting.sched.sched_init(
		     wd_dh_setting.sched.h_sched_ctx, setup->sched_param);
	if (WD_IS_ERR(sess->sched_key)) {
		WD_ERR("failed to init session schedule key!\n");
		goto sched_err;
	}

	return (handle_t)sess;

sched_err:
	free(sess->g.data);
sess_err:
	free(sess);
	return (handle_t)0;
}

void wd_dh_free_sess(handle_t sess)
{
	struct wd_dh_sess *sess_t = (struct wd_dh_sess *)sess;

	if (!sess_t) {
		WD_ERR("invalid: free dh sess param NULL!\n");
		return;
	}

	if (sess_t->g.data)
		free(sess_t->g.data);

	if (sess_t->sched_key)
		free(sess_t->sched_key);
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

int wd_dh_env_init(struct wd_sched *sched)
{
	wd_dh_env_config.sched = sched;

	return wd_alg_env_init(&wd_dh_env_config, table,
			       &wd_dh_ops, ARRAY_SIZE(table), NULL);
}

void wd_dh_env_uninit(void)
{
	wd_alg_env_uninit(&wd_dh_env_config, &wd_dh_ops);
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
	wd_alg_env_uninit(&wd_dh_env_config, &wd_dh_ops);
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
