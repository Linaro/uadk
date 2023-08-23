/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2023-2024 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2023-2024 Linaro ltd.
 */

#include "adapter_private.h"

struct rr_adapter_ctx {
	uint32_t send_idx;
	uint32_t recv_idx;
};

static int uadk_adapter_rr_init(struct wd_alg_driver *adapter)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	struct rr_adapter_ctx *priv = (struct rr_adapter_ctx *)ctx->priv;

	if (!priv) {
		priv = calloc(1, sizeof(*priv));
		if (!priv)
			return -ENOMEM;

		ctx->priv = priv;
	}

	return 0;
}

static void uadk_adapter_rr_exit(struct wd_alg_driver *adapter)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;

	if (ctx->priv) {
		free(ctx->priv);
		ctx->priv = NULL;
	}
}

/* fixme, how to ensure send and recv are matched in async mode */
static int uadk_adapter_rr_send(struct wd_alg_driver *adapter, handle_t handle, void *msg)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	struct rr_adapter_ctx *priv = (struct rr_adapter_ctx *)ctx->priv;
	struct uadk_adapter_worker *worker = &ctx->workers[priv->send_idx];
	int ret;

	ret = worker->driver->send(worker->driver, handle, msg);
	if (ret)
		return ret;

	worker->inflight_pkts++;
	priv->send_idx++;
	priv->send_idx %= ctx->workers_nb;

	return 0;
}

static int uadk_adapter_rr_recv(struct wd_alg_driver *adapter, handle_t handle, void *msg)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	struct rr_adapter_ctx *priv = (struct rr_adapter_ctx *)ctx->priv;
	struct uadk_adapter_worker *worker = &ctx->workers[priv->recv_idx];
	uint32_t recv_idx = priv->recv_idx;
	int ret;

	if (unlikely(worker->inflight_pkts == 0)) {
		do {
			recv_idx++;
			recv_idx %= ctx->workers_nb;
			if (recv_idx == priv->recv_idx)
				return 0;
			worker = &ctx->workers[recv_idx];
		} while (worker->inflight_pkts == 0);
	}
	ret = worker->driver->recv(worker->driver, handle, msg);
	if (ret)
		return ret;

	recv_idx++;
	recv_idx %= ctx->workers_nb;
	priv->recv_idx = recv_idx;
	worker->inflight_pkts--;

	return 0;
}

static struct uadk_adapter_ops adapter_rr_ops = {
	uadk_adapter_rr_init,
	uadk_adapter_rr_exit,
	uadk_adapter_rr_send,
	uadk_adapter_rr_recv,
};

static struct uadk_user_adapter rr_adapter = {
	.name = "roundrobin-adapter",
	.description = "adapter which will round robin across workers",
	.mode = UADK_ADAPT_MODE_ROUNDROBIN,
	.ops = &adapter_rr_ops
};

struct uadk_user_adapter *uadk_user_adapter_roundrobin = &rr_adapter;
