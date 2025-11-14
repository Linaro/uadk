/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#ifndef WD_INTERNAL_H
#define WD_INTERNAL_H

#include <pthread.h>
#include <stdbool.h>
#include "wd.h"

#ifdef __cplusplus
extern "C" {
#endif
#define NOSVA_DEVICE_MAX		16
#define DECIMAL_NUMBER		10
#define MAX_FD_NUM	65535

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

struct wd_soft_ctx {
	int fd;
	void *priv;
};

struct wd_ce_ctx {
	int fd;
	char *drv_name;
	void *priv;
};

struct wd_ctx_internal {
	handle_t ctx;
	__u8 op_type;
	__u8 ctx_mode;
	__u16 sqn;
	pthread_spinlock_t lock;
};

struct wd_ctx_config_internal {
	__u32 ctx_num;
	int shmid;
	struct wd_ctx_internal *ctxs;
	void *priv;
	bool epoll_en;
	unsigned long *msg_cnt;
	char *alg_name;
};

struct wd_datalist {
	void *data;
	__u32 len;
	struct wd_datalist *next;
};

#ifdef __cplusplus
}
#endif

#endif
