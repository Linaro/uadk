// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include <stdlib.h>
#include <pthread.h>
#include <limits.h>
#include "include/drv/wd_udma_drv.h"
#include "wd_udma.h"

struct wd_udma_sess {
	const char *alg_name;
	wd_dev_mask_t *dev_mask;
	void *priv;
	void *sched_key;
};

static struct wd_udma_setting {
	enum wd_status status;
	struct wd_ctx_config_internal config;
	struct wd_sched sched;
	struct wd_async_msg_pool pool;
	struct wd_alg_driver *driver;
	void *dlhandle;
	void *dlh_list;
} wd_udma_setting;

static struct wd_init_attrs wd_udma_init_attrs;

static void wd_udma_close_driver(void)
{
#ifndef WD_STATIC_DRV
	wd_dlclose_drv(wd_udma_setting.dlh_list);
	wd_udma_setting.dlh_list = NULL;
#else
	wd_release_drv(wd_udma_setting.driver);
	hisi_udma_remove();
#endif
}

static int wd_udma_open_driver(void)
{
#ifndef WD_STATIC_DRV
	/*
	 * Driver lib file path could set by env param.
	 * then open tham by wd_dlopen_drv()
	 * use NULL means dynamic query path
	 */
	wd_udma_setting.dlh_list = wd_dlopen_drv(NULL);
	if (!wd_udma_setting.dlh_list) {
		WD_ERR("fail to open driver lib files.\n");
		return -WD_EINVAL;
	}
#else
	hisi_udma_probe();
#endif
	return WD_SUCCESS;
}

void wd_udma_free_sess(handle_t sess)
{
	struct wd_udma_sess *sess_t = (struct wd_udma_sess *)sess;

	if (!sess_t) {
		WD_ERR("invalid: free udma sess param NULL!\n");
		return;
	}

	if (sess_t->sched_key)
		free(sess_t->sched_key);
	free(sess_t);
}

handle_t wd_udma_alloc_sess(struct wd_udma_sess_setup *setup)
{
	struct wd_udma_sess *sess;

	if (!setup) {
		WD_ERR("invalid: alloc udma sess setup NULL!\n");
		return (handle_t)0;
	}

	sess = calloc(1, sizeof(struct wd_udma_sess));
	if (!sess)
		return (handle_t)0;

	sess->alg_name = "udma";
	/* Some simple scheduler don't need scheduling parameters */
	sess->sched_key = (void *)wd_udma_setting.sched.sched_init(
		     wd_udma_setting.sched.h_sched_ctx, setup->sched_param);
	if (WD_IS_ERR(sess->sched_key)) {
		WD_ERR("failed to init session schedule key!\n");
		goto free_sess;
	}

	return (handle_t)sess;

free_sess:
	free(sess);
	return (handle_t)0;
}

static int wd_udma_addr_check(struct wd_data_addr *data_addr)
{
	if (unlikely(!data_addr->addr)) {
		WD_ERR("invalid: udma addr is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(!data_addr->data_size ||
		      data_addr->data_size > data_addr->addr_size)) {
		WD_ERR("invalid: udma size is error, data_size %lu, addr_size is %lu!\n",
		       data_addr->data_size, data_addr->addr_size);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int wd_udma_param_check(struct wd_udma_sess *sess,
			       struct wd_udma_req *req)
{
	struct wd_data_addr *src, *dst;
	int i, ret;

	if (unlikely(!sess || !req)) {
		WD_ERR("invalid: input param NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->addr_num <= 0)) {
		WD_ERR("invalid: addr num is error %d!\n", req->addr_num);
		return -WD_EINVAL;
	}

	src = req->src;
	dst = req->dst;
	if (unlikely(req->op_type >= WD_UDMA_OP_MAX)) {
		WD_ERR("invalid: op_type is error %u!\n", req->op_type);
		return -WD_EINVAL;
	} else if (unlikely(req->op_type == WD_UDMA_MEMCPY && (!src || !dst))) {
		WD_ERR("invalid: memcpy src or dst is NULL!\n");
		return -WD_EINVAL;
	} else if (unlikely(req->op_type == WD_UDMA_MEMSET &&
			   ((!src && !dst) || (src && dst)))) {
		WD_ERR("invalid: memset src and dst is error!\n");
		return -WD_EINVAL;
	}

	if (req->op_type == WD_UDMA_MEMSET)
		dst = !req->src ? req->dst : req->src;

	for (i = 0; i < req->addr_num; i++) {
		if (req->op_type == WD_UDMA_MEMCPY) {
			ret = wd_udma_addr_check(&src[i]);
			if (unlikely(ret)) {
				WD_ERR("invalid: udma memcpy src addr is error!\n");
				return -WD_EINVAL;
			}

			ret = wd_udma_addr_check(&dst[i]);
			if (unlikely(ret)) {
				WD_ERR("invalid: udma memcpy dst addr is error!\n");
				return -WD_EINVAL;
			}

			if (unlikely(dst[i].data_size != src[i].data_size)) {
				WD_ERR("invalid: udma memcpy data_size is error!\n"
				       "src %lu, dst %lu!\n",
					dst[i].data_size, src[i].data_size);
				return -WD_EINVAL;
			}
		} else {
			ret = wd_udma_addr_check(&dst[i]);
			if (unlikely(ret)) {
				WD_ERR("invalid: udma memset addr is error!\n");
				return -WD_EINVAL;
			}
		}
	}

	return WD_SUCCESS;
}

static void fill_udma_msg(struct wd_udma_msg *msg, struct wd_udma_req *req)
{
	msg->result = WD_EINVAL;

	memcpy(&msg->req, req, sizeof(*req));
	msg->op_type = req->op_type;
	msg->addr_num = req->addr_num;
	msg->value = req->value;
	if (req->op_type == WD_UDMA_MEMSET) {
		msg->dst = !req->src ? req->dst : req->src;
	} else {
		msg->src = req->src;
		msg->dst = req->dst;
	}
}

int wd_do_udma_sync(handle_t h_sess, struct wd_udma_req *req)
{
	struct wd_ctx_config_internal *config = &wd_udma_setting.config;
	handle_t h_sched_ctx = wd_udma_setting.sched.h_sched_ctx;
	struct wd_udma_sess *sess_t = (struct wd_udma_sess *)h_sess;
	struct wd_msg_handle msg_handle;
	struct wd_ctx_internal *ctx;
	struct wd_udma_msg msg = {0};
	__u32 idx;
	int ret;

	ret = wd_udma_param_check(sess_t, req);
	if (unlikely(ret))
		return ret;

	idx = wd_udma_setting.sched.pick_next_ctx(h_sched_ctx,
						  sess_t->sched_key,
						  CTX_MODE_SYNC);
	ret = wd_check_ctx(config, CTX_MODE_SYNC, idx);
	if (unlikely(ret))
		return ret;

	wd_dfx_msg_cnt(config, WD_CTX_CNT_NUM, idx);
	ctx = config->ctxs + idx;

	fill_udma_msg(&msg, req);

	msg_handle.send = wd_udma_setting.driver->send;
	msg_handle.recv = wd_udma_setting.driver->recv;
	pthread_spin_lock(&ctx->lock);
	ret = wd_handle_msg_sync(wd_udma_setting.driver, &msg_handle, ctx->ctx,
				 &msg, NULL, wd_udma_setting.config.epoll_en);
	pthread_spin_unlock(&ctx->lock);
	if (unlikely(ret))
		return ret;

	req->status = msg.result;

	return GET_NEGATIVE(msg.result);
}

int wd_do_udma_async(handle_t sess, struct wd_udma_req *req)
{
	struct wd_ctx_config_internal *config = &wd_udma_setting.config;
	handle_t h_sched_ctx = wd_udma_setting.sched.h_sched_ctx;
	struct wd_udma_sess *sess_t = (struct wd_udma_sess *)sess;
	struct wd_udma_msg *msg = NULL;
	struct wd_ctx_internal *ctx;
	int ret, mid;
	__u32 idx;

	ret = wd_udma_param_check(sess_t, req);
	if (unlikely(ret))
		return ret;

	if (unlikely(!req->cb)) {
		WD_ERR("invalid: udma input req cb is NULL!\n");
		return -WD_EINVAL;
	}

	idx = wd_udma_setting.sched.pick_next_ctx(h_sched_ctx,
						  sess_t->sched_key,
						  CTX_MODE_ASYNC);
	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (unlikely(ret))
		return ret;
	ctx = config->ctxs + idx;

	mid = wd_get_msg_from_pool(&wd_udma_setting.pool, idx, (void **)&msg);
	if (unlikely(mid < 0)) {
		WD_ERR("failed to get msg from pool!\n");
		return mid;
	}

	fill_udma_msg(msg, req);
	msg->tag = mid;

	ret = wd_alg_driver_send(wd_udma_setting.driver, ctx->ctx, msg);
	if (unlikely(ret)) {
		if (ret != -WD_EBUSY)
			WD_ERR("failed to send udma BD, hw is err!\n");

		goto fail_with_msg;
	}

	wd_dfx_msg_cnt(config, WD_CTX_CNT_NUM, idx);

	return WD_SUCCESS;

fail_with_msg:
	wd_put_msg_to_pool(&wd_udma_setting.pool, idx, mid);

	return ret;
}

static int wd_udma_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_udma_setting.config;
	struct wd_udma_msg rcv_msg = {0};
	struct wd_ctx_internal *ctx;
	struct wd_udma_req *req;
	struct wd_udma_msg *msg;
	__u32 rcv_cnt = 0;
	__u32 tmp = expt;
	int ret;

	*count = 0;

	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	do {
		ret = wd_alg_driver_recv(wd_udma_setting.driver, ctx->ctx, &rcv_msg);
		if (ret == -WD_EAGAIN) {
			return ret;
		} else if (unlikely(ret)) {
			WD_ERR("failed to async recv, ret = %d!\n", ret);
			*count = rcv_cnt;
			wd_put_msg_to_pool(&wd_udma_setting.pool, idx,
					   rcv_msg.tag);
			return ret;
		}
		rcv_cnt++;
		msg = wd_find_msg_in_pool(&wd_udma_setting.pool, idx, rcv_msg.tag);
		if (!msg) {
			WD_ERR("failed to find udma msg!\n");
			return -WD_EINVAL;
		}

		msg->req.status = rcv_msg.result;
		req = &msg->req;
		req->cb(req);
		wd_put_msg_to_pool(&wd_udma_setting.pool, idx, rcv_msg.tag);
		*count = rcv_cnt;
	} while (--tmp);

	return ret;
}

int wd_udma_poll(__u32 expt, __u32 *count)
{
	handle_t h_sched_ctx = wd_udma_setting.sched.h_sched_ctx;

	if (unlikely(!count || !expt)) {
		WD_ERR("invalid: udma poll count is NULL or expt is 0!\n");
		return -WD_EINVAL;
	}

	return wd_udma_setting.sched.poll_policy(h_sched_ctx, expt, count);
}

static void wd_udma_clear_status(void)
{
	wd_alg_clear_init(&wd_udma_setting.status);
}

static void wd_udma_alg_uninit(void)
{
	/* Uninit async request pool */
	wd_uninit_async_request_pool(&wd_udma_setting.pool);
	/* Unset config, sched, driver */
	wd_clear_sched(&wd_udma_setting.sched);
	wd_alg_uninit_driver(&wd_udma_setting.config, wd_udma_setting.driver);
}

void wd_udma_uninit(void)
{
	enum wd_status status;

	wd_alg_get_init(&wd_udma_setting.status, &status);
	if (status == WD_UNINIT)
		return;

	wd_udma_alg_uninit();
	wd_alg_attrs_uninit(&wd_udma_init_attrs);
	wd_alg_drv_unbind(wd_udma_setting.driver);
	wd_udma_close_driver();
	wd_alg_clear_init(&wd_udma_setting.status);
}

static int wd_udma_alg_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	int ret;

	ret = wd_set_epoll_en("WD_UDMA_EPOLL_EN", &wd_udma_setting.config.epoll_en);
	if (ret < 0)
		return ret;

	ret = wd_init_ctx_config(&wd_udma_setting.config, config);
	if (ret < 0)
		return ret;

	ret = wd_init_sched(&wd_udma_setting.sched, sched);
	if (ret < 0)
		goto out_clear_ctx_config;

	/* Allocate async pool for every ctx */
	ret = wd_init_async_request_pool(&wd_udma_setting.pool, config, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_udma_msg));
	if (ret < 0)
		goto out_clear_sched;

	ret = wd_alg_init_driver(&wd_udma_setting.config, wd_udma_setting.driver);
	if (ret)
		goto out_clear_pool;

	return WD_SUCCESS;

out_clear_pool:
	wd_uninit_async_request_pool(&wd_udma_setting.pool);
out_clear_sched:
	wd_clear_sched(&wd_udma_setting.sched);
out_clear_ctx_config:
	wd_clear_ctx_config(&wd_udma_setting.config);
	return ret;
}

int wd_udma_init(const char *alg, __u32 sched_type, int task_type,
		 struct wd_ctx_params *ctx_params)
{
	struct wd_ctx_nums udma_ctx_num[WD_UDMA_OP_MAX] = {0};
	struct wd_ctx_params udma_ctx_params = {0};
	int state, ret = -WD_EINVAL;

	pthread_atfork(NULL, NULL, wd_udma_clear_status);

	state = wd_alg_try_init(&wd_udma_setting.status);
	if (state)
		return state;

	if (!alg || sched_type >= SCHED_POLICY_BUTT ||
	    task_type < 0 || task_type >= TASK_MAX_TYPE) {
		WD_ERR("invalid: input param is wrong!\n");
		goto out_clear_init;
	}

	if (strcmp(alg, "udma")) {
		WD_ERR("invalid: the alg %s not support!\n", alg);
		goto out_clear_init;
	}

	state = wd_udma_open_driver();
	if (state)
		goto out_clear_init;

	while (ret) {
		memset(&wd_udma_setting.config, 0, sizeof(struct wd_ctx_config_internal));

		/* Get alg driver and dev name */
		wd_udma_setting.driver = wd_alg_drv_bind(task_type, alg);
		if (!wd_udma_setting.driver) {
			WD_ERR("fail to bind a valid driver.\n");
			ret = -WD_EINVAL;
			goto out_dlopen;
		}

		udma_ctx_params.ctx_set_num = udma_ctx_num;
		ret = wd_ctx_param_init(&udma_ctx_params, ctx_params,
					wd_udma_setting.driver, WD_UDMA_TYPE, WD_UDMA_OP_MAX);
		if (ret) {
			if (ret == -WD_EAGAIN) {
				wd_disable_drv(wd_udma_setting.driver);
				wd_alg_drv_unbind(wd_udma_setting.driver);
				continue;
			}
			goto out_driver;
		}

		(void)strcpy(wd_udma_init_attrs.alg, alg);
		wd_udma_init_attrs.sched_type = sched_type;
		wd_udma_init_attrs.driver = wd_udma_setting.driver;
		wd_udma_init_attrs.ctx_params = &udma_ctx_params;
		wd_udma_init_attrs.alg_init = wd_udma_alg_init;
		wd_udma_init_attrs.alg_poll_ctx = wd_udma_poll_ctx;
		ret = wd_alg_attrs_init(&wd_udma_init_attrs);
		if (ret) {
			if (ret == -WD_ENODEV) {
				wd_disable_drv(wd_udma_setting.driver);
				wd_alg_drv_unbind(wd_udma_setting.driver);
				wd_ctx_param_uninit(&udma_ctx_params);
				continue;
			}
			WD_ERR("failed to init alg attrs!\n");
			goto out_params_uninit;
		}
	}

	wd_alg_set_init(&wd_udma_setting.status);
	wd_ctx_param_uninit(&udma_ctx_params);

	return WD_SUCCESS;

out_params_uninit:
	wd_ctx_param_uninit(&udma_ctx_params);
out_driver:
	wd_alg_drv_unbind(wd_udma_setting.driver);
out_dlopen:
	wd_udma_close_driver();
out_clear_init:
	wd_alg_clear_init(&wd_udma_setting.status);
	return ret;
}

struct wd_udma_msg *wd_udma_get_msg(__u32 idx, __u32 tag)
{
	return wd_find_msg_in_pool(&wd_udma_setting.pool, idx, tag);
}
