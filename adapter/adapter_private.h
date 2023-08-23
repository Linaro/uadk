/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2023-2024 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2023-2024 Linaro ltd.
 */

#include <stdio.h>
#include <stdlib.h>
#include "adapter.h"
#include "wd.h"

/* Maximum number of bonded drv per adapter */
#ifndef UADK_MAX_NB_WORKERS
#define UADK_MAX_NB_WORKERS  (8)
#endif

struct uadk_adapter_ops {
	int (*init)(struct wd_alg_driver *drv);
	void (*exit)(struct wd_alg_driver *drv);
	int (*send)(struct wd_alg_driver *drv, handle_t handle, void *msg);
	int (*recv)(struct wd_alg_driver *drv, handle_t handle, void *msg);
	int (*cfg)(struct wd_alg_driver *adapter, enum uadk_adapter_mode mode, void *cfg);
};

struct uadk_user_adapter {
	const char *name;                       /* adapter name */
	const char *description;                /* adapter description */
	enum uadk_adapter_mode mode;            /* adapter mode */
	struct uadk_adapter_ops *ops;           /* adapter operation */
};

struct uadk_adapter_worker {
	struct wd_alg_driver *driver;
	/* handle of shared library */
	void *dlhandle;
	bool inited;
	uint32_t inflight_pkts;
};

struct uadk_adapter_ctx {
	/* priviate ctx */
	void *priv;
	/* worker number */
	unsigned int workers_nb;
	enum uadk_adapter_mode mode;
	/* workers attached to the adapter */
	struct uadk_adapter_worker workers[UADK_MAX_NB_WORKERS];
	struct uadk_adapter_ops ops;
};

extern struct uadk_user_adapter *uadk_user_adapter_roundrobin;
extern struct uadk_user_adapter *uadk_user_adapter_threshold;
