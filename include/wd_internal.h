/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#ifndef WD_INTERNAL_H
#define WD_INTERNAL_H

#include <pthread.h>
#include <stdbool.h>
#include "wd.h"
#include "wd_alg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEVICE_REGION_MAX		16
#define DECIMAL_NUMBER		10
#define MAX_FD_NUM	65535

struct wd_ctx_h {
	__u8 ctx_type;
	int fd;
	char dev_path[MAX_DEV_NAME_LEN];
	char *dev_name;
	char *drv_name;
	unsigned long qfrs_offs[UACCE_QFRT_MAX];
	void *qfrs_base[UACCE_QFRT_MAX];
	struct uacce_dev *dev;
	void *priv;
};

struct wd_ctx_internal {
	__u8 op_type;
	__u8 ctx_mode;
	__u8 ctx_type;
	handle_t ctx;
	__u16 sqn;
	pthread_spinlock_t lock;
	struct wd_alg_driver *drv;
	__u32 hw_load;
};

struct wd_ctx_config_internal {
	__u32 ctx_num;
	int shmid;
	struct wd_ctx_internal *ctxs;
	void *priv;
	bool epoll_en;
	unsigned long *msg_cnt;
	const char *alg_name;

	struct wd_alg_driver **drv_array;
	__u32 drv_count;
};

struct wd_datalist {
	void *data;
	__u32 len;
	struct wd_datalist *next;
};

struct wd_sched_params {
	__u32 pkt_size;
	/* block mode or stream mode */
	__u16 data_mode;
	__u16 prio_mode;

	/* Compat filtering parameters for session-ctx matching */
	const char *alg_name;
	struct wd_ctx_internal *ctxs;
};

int memcmp_consttime(const void *s1, const void *s2, size_t n);

#ifdef __cplusplus
}
#endif

#endif
