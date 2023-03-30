/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2023-2024 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2023-2024 Linaro ltd.
 */

#include <stdlib.h>
#include "adapter_private.h"

struct rr_adapter_ctx {
	unsigned int send_idx;
	unsigned int recv_idx;
};

static int uadk_adapter_rr_init(struct wd_alg_driver *adapter)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	struct rr_adapter_ctx *priv;

	/* init may reenter, free and re-allocate */
	if (ctx->priv)
		free(ctx->priv);

	priv = malloc(sizeof(*priv));
	if (!priv)
		return -ENOMEM;

	memset(priv, 0, sizeof(*priv));
	ctx->priv = priv;

	return 0;
}

static void uadk_adapter_rr_exit(struct wd_alg_driver *adapter)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;

	free(ctx->priv);
}

/* fixme, how to ensure send and recv are matched in async mode */
static int uadk_adapter_rr_send(struct wd_alg_driver *adapter, handle_t handle, void *drv_msg)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	struct rr_adapter_ctx *priv = (struct rr_adapter_ctx *)ctx->priv;
	struct uadk_adapter_worker *worker = &ctx->workers[priv->send_idx];
	int ret;

	ret = worker->driver->send(worker->driver, handle, drv_msg);
	if (ret)
		return ret;

	priv->send_idx++;
	priv->send_idx %= ctx->workers_nb;

	return 0;
}

static int uadk_adapter_rr_recv(struct wd_alg_driver *adapter, handle_t handle, void *drv_msg)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	struct rr_adapter_ctx *priv = (struct rr_adapter_ctx *)ctx->priv;
	struct uadk_adapter_worker *worker = &ctx->workers[priv->recv_idx];
	int ret;

	ret = worker->driver->recv(worker->driver, handle, drv_msg);
	if (ret)
		return ret;

	priv->recv_idx++;
	priv->recv_idx %= ctx->workers_nb;

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
