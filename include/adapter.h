/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2023-2024 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2023-2024 Linaro ltd.
 */

#ifndef __ADAPTER_H
#define __ADAPTER_H

#include "wd_alg.h"

enum uadk_adapter_mode {
	UADK_ADAPT_MODE_NONE,			// no mode
	UADK_ADAPT_MODE_ROUNDROBIN,		// roundrobin
	UADK_ADAPT_MODE_THRESHOLD,		// > threshold, accelerator,
						// < threshold, cpu
	UADK_ADAPT_MODE_FAILOVER,		// fail to enqueue (full or fail), switch to backup
};

struct wd_alg_driver *uadk_adapter_alloc(void);
void uadk_adapter_free(struct wd_alg_driver *adapter);
int uadk_adapter_set_mode(struct wd_alg_driver *adapter, enum uadk_adapter_mode mode);
int uadk_adapter_attach_worker(struct wd_alg_driver *adapter,
			       struct wd_alg_driver *drv, void *dlhandle);
int uadk_adapter_parse(struct wd_alg_driver *adapter, char *lib_path,
		       char *drv_name, char *alg_name);
#endif
