// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#ifndef __WD_COMMON_H
#define __WD_COMMON_H

#include "uacce.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DEV_NAME_LEN		256

struct wd_ctx_h {
	int fd;
	char dev_path[MAX_DEV_NAME_LEN];
	char *dev_name;
	char *drv_name;
	unsigned long qfrs_offs[UACCE_QFRT_MAX];
	void *qfrs_base[UACCE_QFRT_MAX];
	struct uacce_dev *dev;
	void *priv;
};

#ifdef __cplusplus
}
#endif

#endif /* __WD_COMMON_H */
