/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#ifndef _UAPIUUACCE_H
#define _UAPIUUACCE_H

#include <linux/types.h>
#include <linux/ioctl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UACCE_CMD_START         _IO('W', 0)
#define UACCE_CMD_PUT_Q         _IO('W', 1)
#define UACCE_CMD_GET_SS_DMA    _IOR('W', 100, unsigned long)

/**
 * UACCE Device flags:
 *
 * SVA: Shared Virtual Addresses
 *      Support PASID
 *      Support device page faults (PCI PRI or SMMU Stall)
 */

enum {
        UACCE_DEV_SVA = 0x1,
};

#define UACCE_API_VER_NOIOMMU_SUBFIX	"_noiommu"

enum uacce_qfrt {
	UACCE_QFRT_MMIO = 0,	/* device mmio region */
	UACCE_QFRT_DUS = 1,	/* device user share */
	UACCE_QFRT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif
