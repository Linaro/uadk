/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _UAPIUUACCE_H
#define _UAPIUUACCE_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define UACCE_CMD_START         _IO('W', 0)
#define UACCE_CMD_PUT_Q         _IO('W', 1)
#define UACCE_CMD_GET_SS_DMA    _IOR('W', 100, unsigned long)
#define UACCE_CMD_SHARE_SVAS    _IO('W', 101)

/**
 * UACCE Device flags:
 *
 * SVA: Shared Virtual Addresses
 *      Support PASID
 *      Support device page faults (PCI PRI or SMMU Stall)
 */

enum {
        UACCE_DEV_SVA = 0x1,
        UACCE_DEV_NOIOMMU = 0x100,
};

#define UACCE_API_VER_NOIOMMU_SUBFIX	"_noiommu"

enum uacce_qfrt {
	UACCE_QFRT_MMIO = 0,	/* device mmio region */
	UACCE_QFRT_DUS = 1,	/* device user share */
	UACCE_QFRT_DKO,         /* device kernel-only */
	UACCE_QFRT_SS,          /* static share memory */
};
#endif
