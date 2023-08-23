/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2023-2024 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2023-2024 Linaro ltd.
 */

#include "adapter_private.h"

#define THRESHOLD_MAX_WORKER_NB 2
#define THRESHOLD_DEF_PKT_SIZE 8192

struct threshold_adapter_ctx {
	uint32_t threshold;
	struct uadk_adapter_worker *primary_worker;
	struct uadk_adapter_worker *secondary_worker;
};

static int uadk_adapter_threshold_init(struct wd_alg_driver *adapter)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	struct threshold_adapter_ctx *priv = (struct threshold_adapter_ctx *)ctx->priv;
	int i;

	/* init may reenter */
	if (!priv) {
		priv = calloc(1, sizeof(*priv));
		if (!priv)
			return -ENOMEM;

		priv->threshold = THRESHOLD_DEF_PKT_SIZE;
		ctx->priv = priv;
	}

	for (i = 0; i < ctx->workers_nb; i++) {
		if (!priv->primary_worker) {
			priv->primary_worker = &ctx->workers[i];
		} else if (!priv->secondary_worker) {
			if (priv->primary_worker->driver->priority <
			    ctx->workers[i].driver->priority) {
				priv->secondary_worker = priv->primary_worker;
				priv->primary_worker = &ctx->workers[i];
			}

		}
		/* only consider two workers */
		if (i == THRESHOLD_MAX_WORKER_NB)
			break;
	}

	return 0;
}

static void uadk_adapter_threshold_exit(struct wd_alg_driver *adapter)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;

	if (ctx->priv) {
		free(ctx->priv);
		ctx->priv = NULL;
	}
}

static int uadk_adapter_threshold_send(struct wd_alg_driver *adapter, handle_t handle, void *msg)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	struct threshold_adapter_ctx *priv = (struct threshold_adapter_ctx *)ctx->priv;
	struct uadk_adapter_worker *worker;
	uint32_t pkt_size;
	int ret;

	/* hack, get the first uint32 as size */
	pkt_size = *(uint32_t *)(msg);

	if (pkt_size >= priv->threshold)
		worker = priv->primary_worker;
	else
		worker = priv->secondary_worker;

	ret = worker->driver->send(worker->driver, handle, msg);
	if (ret)
		return ret;

	worker->inflight_pkts++;

	return 0;
}

static int uadk_adapter_threshold_recv(struct wd_alg_driver *adapter, handle_t handle, void *msg)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	struct threshold_adapter_ctx *priv = (struct threshold_adapter_ctx *)ctx->priv;
	struct uadk_adapter_worker *worker;
	int ret;

	if (priv->primary_worker->inflight_pkts)
		worker = priv->primary_worker;
	else if (priv->secondary_worker->inflight_pkts)
		worker = priv->secondary_worker;
	else
		return 0;

	ret = worker->driver->recv(worker->driver, handle, msg);
	if (ret)
		return ret;

	worker->inflight_pkts--;

	return 0;
}

static int uadk_adapter_threshold_cfg(struct wd_alg_driver *adapter,
				      enum uadk_adapter_mode mode, void *cfg)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	struct threshold_adapter_ctx *priv = (struct threshold_adapter_ctx *)ctx->priv;
	struct uadk_adapter_threshold_cfg *threshold_cfg =
					(struct uadk_adapter_threshold_cfg *)cfg;

	if (mode != UADK_ADAPT_MODE_THRESHOLD) {
		fprintf(stderr, "cfg mode not supported\n");
		return -EINVAL;
	}

	if (threshold_cfg)
		priv->threshold = threshold_cfg->threshold;

	return 0;
}

static struct uadk_adapter_ops adapter_threshold_ops = {
	uadk_adapter_threshold_init,
	uadk_adapter_threshold_exit,
	uadk_adapter_threshold_send,
	uadk_adapter_threshold_recv,
	uadk_adapter_threshold_cfg,
};

static struct uadk_user_adapter threshold_adapter = {
	.name = "threshold-adapter",
	.description = "adapter choose worker according to threshold",
	.mode = UADK_ADAPT_MODE_THRESHOLD,
	.ops = &adapter_threshold_ops
};

struct uadk_user_adapter *uadk_user_adapter_threshold = &threshold_adapter;
