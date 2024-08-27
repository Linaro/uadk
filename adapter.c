
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2024-2025 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2024-2025 Linaro ltd.
 */

#include "adapter.h"

int uadk_adapter_add_workers(struct uadk_adapter *adapter, char *alg)
{
	struct uadk_adapter_worker *worker;
	struct wd_alg_driver *drv;
	int idx = 0;
	
	do {
		drv = wd_find_drv(NULL, alg, idx);
		if (!drv)
			break;

		worker = &adapter->workers[idx];
		worker->driver = drv;
		worker->lifetime = 0;
		worker->idx = idx;
		adapter->workers_nb++;
		
		if (++idx >= UADK_MAX_NB_WORKERS)
			break;
	} while (drv);

	return (adapter->workers_nb == 0);
}

struct uadk_adapter_worker *uadk_adapter_choose_worker(
	struct uadk_adapter *adapter,
	enum alg_task_type type)
{
	struct uadk_adapter_worker *worker;

	/* use worker[0] for simplicity now */
	worker = &adapter->workers[0];
	worker->valid = true;
	worker->lifetime = 0;

	return worker;
}

struct uadk_adapter_worker *uadk_adapter_switch_worker(
	struct uadk_adapter *adapter,
	struct uadk_adapter_worker *worker,
	int para)
{
	struct uadk_adapter_worker *new_worker;
	int idx = worker->idx;

	if (adapter->workers_nb == 1)
		return worker;

	if (para) {
		idx += 1;
	} else {
		if (idx == 0)
			idx = adapter->workers_nb - 1;
		else
			idx -= 1;
	}

	new_worker = &adapter->workers[idx];
	new_worker->valid = true;
	new_worker->lifetime = 0;

	return new_worker;
}
