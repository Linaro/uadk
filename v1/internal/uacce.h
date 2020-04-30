/* SPDX-License-Identifier: GPL-2.0-or-later WITH Linux-syscall-note */
/* Copyright (c) 2018-2019 HiSilicon Limited. */
#ifndef _UAPIUUACCE_H
#define _UAPIUUACCE_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define UACCE_CLASS_NAME	"uacce"
#define UACCE_DEV_ATTRS		"attrs"
/*
 * UACCE_CMD_START_Q: Start queue
 */
#define UACCE_CMD_START_Q		_IO('W', 0)

/*
 * UACCE_CMD_PUT_Q:
 * User actively stop queue and free queue resource immediately
 * Optimization method since close fd may delay
 */
#define UACCE_CMD_PUT_Q		_IO('W', 1)

#define UACCE_CMD_SHARE_SVAS	_IO('W', 2)

#define UACCE_CMD_GET_SS_DMA	_IOR('W', 3, unsigned long)


/**
 * UACCE Device Attributes:
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
#define UACCE_DEV_SVA			(1<<0)
#define UACCE_DEV_NOIOMMU		(1<<1)
#define UACCE_DEV_PASID			(1<<2)

/* uacce mode of the driver */
#define UACCE_MODE_NOUACCE	0 /* don't use uacce */
#define UACCE_MODE_NOIOMMU	2 /* use uacce noiommu mode */

#define UACCE_API_VER_NOIOMMU_SUBFIX	"_noiommu"

#define UACCE_QFR_NA ((unsigned long)-1)

/**
 * enum uacce_qfrt: queue file region type
 * @UACCE_QFRT_MMIO: device mmio region
 * @UACCE_QFRT_DUS: device user share region
 * @UACCE_QFRT_SS: static share memory(no-sva)
 */
enum uacce_qfrt {
	UACCE_QFRT_MMIO = 0,	/* device mmio region */
	UACCE_QFRT_DUS,		/* device user share */
	UACCE_QFRT_SS,		/* static share memory */
	UACCE_QFRT_MAX,
};
#define UACCE_QFRT_INVALID UACCE_QFRT_MAX

/* Pass DMA SS region slice size by granularity 64KB */
#define UACCE_GRAN_SIZE			0x10000ull
#define UACCE_GRAN_SHIFT		16
#define UACCE_GRAN_NUM_MASK		0xfffull
#endif
