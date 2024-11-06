/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2024-2025 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2024-2025 Linaro ltd.
 */

#ifndef __ADAPTER_H
#define __ADAPTER_H

#include "wd_alg.h"
#include "wd_util.h"

#define UADK_MAX_NB_WORKERS  (2)
#define UADK_WORKER_LIFETIME (10)

enum uadk_adapter_mode {
	UADK_ADAPT_MODE_PRIMARY,
	UADK_ADAPT_MODE_ROUNDROBIN,
};

struct uadk_adapter_worker {
	struct wd_alg_driver *driver;
	struct wd_ctx_config *ctx_config;
	struct wd_sched *sched;
	struct wd_ctx_config_internal config;
	struct wd_async_msg_pool pool;
	bool valid;
	int idx;
};

struct uadk_adapter {
	unsigned int workers_nb;
	enum uadk_adapter_mode mode;
	struct uadk_adapter_worker workers[UADK_MAX_NB_WORKERS];
};

int uadk_adapter_add_workers(struct uadk_adapter *adapter, char *alg);

struct uadk_adapter_worker *uadk_adapter_choose_worker(
	struct uadk_adapter *adapter,
	enum alg_task_type type
);

struct uadk_adapter_worker *uadk_adapter_switch_worker(
	struct uadk_adapter *adapter,
	struct uadk_adapter_worker *worker,
	int para
);
#endif
