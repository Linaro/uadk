/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2023-2024 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2023-2024 Linaro ltd.
 */

#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

#include "adapter_private.h"
#include "wd.h"

int uadk_adapter_attach_worker(struct wd_alg_driver *adapter,
			       struct wd_alg_driver *drv, void *dlhandle)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	struct uadk_adapter_worker *worker;
	int idx = ctx->workers_nb;

	if (idx >= UADK_MAX_NB_WORKERS) {
		fprintf(stderr, "%s too many workers\n", __func__);
		return -EINVAL;
	}

	worker = &ctx->workers[idx];
	worker->driver = drv;
	worker->dlhandle = dlhandle;
	ctx->workers_nb++;

	return 0;
}

/* todo */
int uadk_adapter_parse(struct wd_alg_driver *adapter, char *lib_path,
		       char *drv_name, char *alg_name)
{
	struct wd_alg_driver *drv;
	void *dlhandle = NULL;
	int ret;

	if (lib_path) {
		dlhandle = dlopen(lib_path, RTLD_NOW);
		if (!dlhandle) {
			fprintf(stderr, "%s failed to dlopen %s\n", __func__, dlerror());
			return -EINVAL;
		}
	}

	drv = wd_find_drv(drv_name, alg_name);
	if (!drv) {
		fprintf(stderr, "%s failed to find driver\n", __func__);
		ret = -EINVAL;
		goto fail;
	}

	ret = uadk_adapter_attach_worker(adapter, drv, dlhandle);
	if (ret)
		goto fail;

	// parse cmdline and return

	// parse config

	// parse env

	// attach workers

	return 0;
fail:
	if (dlhandle)
		dlclose(dlhandle);
	return ret;
}

static int uadk_adapter_load_user_adapter(struct wd_alg_driver *adapter,
					  struct uadk_user_adapter *user_adapter)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	int ret;

	/* load scheduler instance operations functions */
	ctx->ops.init = user_adapter->ops->init;
	ctx->ops.exit = user_adapter->ops->exit;
	ctx->ops.send = user_adapter->ops->send;
	ctx->ops.recv = user_adapter->ops->recv;

	if (ctx->priv) {
		free(ctx->priv);
		ctx->priv = NULL;
	}

	if (ctx->ops.init) {
		ret = ctx->ops.init(adapter);
		if (ret)
			return ret;
	}

	ctx->mode = user_adapter->mode;

	return 0;
}

int uadk_adapter_set_mode(struct wd_alg_driver *adapter, enum uadk_adapter_mode mode)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	int ret;

	if (mode == ctx->mode)
		return 0;

	switch (mode) {
	case UADK_ADAPT_MODE_ROUNDROBIN:
		ret = uadk_adapter_load_user_adapter(adapter, uadk_user_adapter_roundrobin);
		if (ret)
			return ret;

		break;

	default:
		fprintf(stderr, "Not yet supported");
		return -ENOTSUP;
	}

	return 0;
}

static int uadk_adapter_init(struct wd_alg_driver *adapter, void *conf)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	int ret, i;

	for (i = 0; i < ctx->workers_nb; i++) {
		struct uadk_adapter_worker *worker = &ctx->workers[i];

		if (worker->inited)
			continue;

		ret = wd_alg_driver_init(worker->driver, conf);
		if (ret)
			continue;
		worker->inited = true;
	}

	return 0;
}

static void uadk_adapter_exit(struct wd_alg_driver *adapter)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;
	int i;

	for (i = 0; i < ctx->workers_nb; i++) {
		struct uadk_adapter_worker *worker = &ctx->workers[i];

		if (!worker->inited)
			continue;

		wd_alg_driver_exit(worker->driver);
		worker->inited = false;

		if (worker->dlhandle) {
			dlclose(worker->dlhandle);
			worker->dlhandle = NULL;
		}
	}

	if (ctx->ops.exit)
		ctx->ops.exit(adapter);
}

static int uadk_adapter_send(struct wd_alg_driver *adapter, handle_t handle, void *msg)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;

	if (unlikely(ctx->workers_nb == 0)) {
		fprintf(stderr, "%s failed since no worker\n", __func__);
		return -EINVAL;
	}

	/* Just forward if only one worker */
	if (ctx->workers_nb == 1)
		return wd_alg_driver_send(ctx->workers[0].driver, handle, msg);

	/* dispatch according to policy */
	if (ctx->ops.send)
		return ctx->ops.send(adapter, handle, msg);

	return -EINVAL;
}

static int uadk_adapter_recv(struct wd_alg_driver *adapter, handle_t handle, void *msg)
{
	struct uadk_adapter_ctx *ctx = (struct uadk_adapter_ctx *)adapter->priv;

	if (unlikely(ctx->workers_nb == 0)) {
		fprintf(stderr, "%s failed since no worker\n", __func__);
		return -EINVAL;
	}

	/* Just forward if only one worker */
	if (ctx->workers_nb == 1)
		return wd_alg_driver_recv(ctx->workers[0].driver, handle, msg);

	/* dispatch according to policy */
	if (ctx->ops.recv)
		return ctx->ops.recv(adapter, handle, msg);

	return -EINVAL;
}

struct wd_alg_driver *uadk_adapter_alloc(void)
{
	struct wd_alg_driver *adapter = malloc(sizeof(*adapter));

	if (adapter == NULL)
		return NULL;

	adapter->priv = malloc(sizeof(struct uadk_adapter_ctx));
	if (adapter->priv == NULL) {
		free(adapter);
		return NULL;
	}
	memset(adapter->priv, 0, sizeof(struct uadk_adapter_ctx));

	adapter->init = uadk_adapter_init;
	adapter->exit = uadk_adapter_exit;
	adapter->send = uadk_adapter_send;
	adapter->recv = uadk_adapter_recv;

	// parse env
	// uadk_adapter_set_mode(adapter, mode);

	return adapter;
}

void uadk_adapter_free(struct wd_alg_driver *adapter)
{
	if (adapter)
		free(adapter->priv);

	free(adapter);
}


