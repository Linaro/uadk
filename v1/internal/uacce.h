/*
 * Copyright 2019 Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _UAPI_WD_UACCE_H
#define _UAPI_WD_UACCE_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define WD_UACCE_CLASS_NAME	"uacce"

/**
 * WD_UACCE Device Attributes:
 *
 * NOIOMMU: the device has no IOMMU support
 *	can do ssva, but no map to the dev
 * PASID: the device has IOMMU which support PASID setting
 *	can do ssva, mapped to dev per process
 * FAULT_FROM_DEV: the device has IOMMU which can do page fault request
 *	no need for ssva, should be used with PASID
 * KMAP_DUS: map the Device user-shared space to kernel
 * DRVMAP_DUS: Driver self-maintain its DUS
 * SVA: full function device
 * SHARE_DOMAIN: no PASID, can do ssva only for one process and the kernel
 */
#define WD_UACCE_DEV_SVA		(1<<0)
#define WD_UACCE_DEV_NOIOMMU		(1<<1)
#define WD_UACCE_DEV_PASID		(1<<2)

/* uacce mode of the driver */
#define WD_UACCE_MODE_NOWD_UACCE	0 /* don't use uacce */
#define WD_UACCE_MODE_NOIOMMU		2 /* use uacce noiommu mode */

#define WD_UACCE_API_VER_NOIOMMU_SUBFIX	"_noiommu"
#define WD_UACCE_QFR_NA ((unsigned long)-1)

/**
 * enum uacce_qfrt: queue file region type
 * @WD_UACCE_QFRT_MMIO: device mmio region
 * @WD_UACCE_QFRT_DUS: device user share region
 * @WD_UACCE_QFRT_SS: static share memory(no-sva)
 */
enum uacce_qfrt {
	WD_UACCE_QFRT_MMIO = 0,		/* device mmio region */
	WD_UACCE_QFRT_DUS,		/* device user share */
	WD_UACCE_QFRT_SS,		/* static share memory */
	WD_UACCE_QFRT_MAX,
};

#define WD_UACCE_QFRT_INVALID WD_UACCE_QFRT_MAX

/* Pass DMA SS region slice size by granularity 64KB */
#define WD_UACCE_GRAN_SIZE		0x10000ull
#define WD_UACCE_GRAN_SHIFT		16
#define WD_UACCE_GRAN_NUM_MASK		0xfffull

/*
 * WD_UACCE_CMD_START_Q: Start queue
 */
#define WD_UACCE_CMD_START_Q	_IO('W', 0)

/*
 * WD_UACCE_CMD_PUT_Q:
 * User actively stop queue and free queue resource immediately
 * Optimization method since close fd may delay
 */
#define WD_UACCE_CMD_PUT_Q		_IO('W', 1)
#define WD_UACCE_CMD_SHARE_SVAS		_IO('W', 2)
#define WD_UACCE_CMD_GET_SS_DMA		_IOR('W', 3, unsigned long)

#endif
