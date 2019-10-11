/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _UAPIUUACCE_H
#define _UAPIUUACCE_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define UACCE_CMD_SHARE_SVAS    _IO('W', 0)
#define UACCE_CMD_START         _IO('W', 1)
#define UACCE_CMD_PUT_Q         _IO('W', 2)
#define UACCE_CMD_GET_SS_DMA    _IOR('W', 100, unsigned long)

/**
 * UACCE Device flags:
 *
 * SHARE_DOMAIN: no PASID, can share sva only for one process and the kernel
 * SVA: Shared Virtual Addresses
 *      Support PASID
 *      Support device page fault (pcie device) or smmu stall (platform device)
 */

enum {
        UACCE_DEV_SHARE_DOMAIN = 0x0,
        UACCE_DEV_SVA = 0x1,
        UACCE_DEV_NOIOMMU = 0x100,
};

#define UACCE_API_VER_NOIOMMU_SUBFIX	"_noiommu"

#define UACCE_QFR_NA ((unsigned long)-1)
enum uacce_qfrt {
	UACCE_QFRT_MMIO = 0,	/* device mmio region */
	UACCE_QFRT_DKO,		/* device kernel-only */
	UACCE_QFRT_DUS,		/* device user share */
	UACCE_QFRT_SS,		/* static share memory */
	UACCE_QFRT_MAX = 16,
};
#define UACCE_QFRT_INVALID UACCE_QFRT_MAX
#endif
