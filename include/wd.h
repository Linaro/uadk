// SPDX-License-Identifier: Apache-2.0
#ifndef __WD_H
#define __WD_H
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "uacce.h"

#define PATH_STR_SIZE			256
#define MAX_ATTR_STR_SIZE		256
#define WD_NAME_SIZE			64
#define MAX_DEV_NAME_LEN		256

typedef void (*wd_log)(const char *format, ...);

#ifndef WD_ERR
#ifndef WITH_LOG_FILE
extern wd_log log_out;

#define __WD_FILENAME__ (strrchr(__FILE__, '/') ?	\
		((char *)((uintptr_t)strrchr(__FILE__, '/') + 1)) : __FILE__)

#define WD_ERR(format, args...)	\
	(log_out ? log_out("[%s, %d, %s]:"format,	\
	__WD_FILENAME__, __LINE__, __func__, ##args) : 	\
	fprintf(stderr, format, ##args))
#else
extern FILE *flog_fd;
#define WD_ERR(format, args...)				\
	if (!flog_fd)					\
		flog_fd = fopen(WITH_LOG_FILE, "a+");	\
	if (flog_fd)					\
		fprintf(flog_fd, format, ##args);	\
	else						\
		fprintf(stderr, "log %s not exists!",	\
			WITH_LOG_FILE);
#endif
#endif

#ifdef DEBUG_LOG
#define dbg(msg, ...) fprintf(stderr, msg, ##__VA_ARGS__)
#else
#define dbg(msg, ...)
#endif

/* WD error code */
#define	WD_SUCCESS			0
#define	WD_STREAM_END			1
#define	WD_STREAM_START			2
#define	WD_EIO				EIO
#define	WD_EAGAIN			EAGAIN
#define	WD_ENOMEM			ENOMEM
#define	WD_EACCESS			EACCESS
#define	WD_EBUSY			EBUSY
#define	WD_ENODEV			ENODEV
#define	WD_EINVAL			EINVAL
#define	WD_ETIMEDOUT			ETIMEDOUT
#define	WD_ADDR_ERR			61
#define	WD_HW_EACCESS			62
#define	WD_SGL_ERR			63
#define	WD_VERIFY_ERR			64
#define	WD_OUT_EPARA			66
#define	WD_IN_EPARA			67
#define	WD_ENOPROC			68

enum wcrypto_type {
	WD_CIPHER,
	WD_DIGEST,
	WD_AEAD,
};

struct wd_dtb {
	char *data;	/* data/buffer start address */
	__u32 dsize;	/* data size */
	__u32 bsize;	/* buffer size */
};

struct uacce_dev {
	/* sysfs node content */
	int flags;				/* flag: SVA */
	char api[WD_NAME_SIZE];			/* HW context type */
	char algs[MAX_ATTR_STR_SIZE];		/* dev supported algorithms */
	unsigned long qfrs_offs[UACCE_QFRT_MAX];
	char dev_root[PATH_STR_SIZE];		/* sysfs path with dev name */

	char char_dev_path[MAX_DEV_NAME_LEN];	/* dev path in devfs */

	int numa_id;
};

struct uacce_dev_list {
	struct uacce_dev *dev;
	struct uacce_dev_list *next;
};

struct wd_dev_mask {
	unsigned char *mask;

	int len;
	unsigned int magic;
};

typedef unsigned long long int handle_t;
typedef struct wd_dev_mask wd_dev_mask_t;

static inline uint32_t wd_ioread32(void *addr)
{
	uint32_t ret;

	ret = *((volatile uint32_t *)addr);
	__sync_synchronize();
	return ret;
}

static inline uint64_t wd_ioread64(void *addr)
{
	uint64_t ret;

	ret = *((volatile uint64_t *)addr);
	__sync_synchronize();
	return ret;
}

static inline void wd_iowrite32(void *addr, uint32_t value)
{
	__sync_synchronize();
	*((volatile uint32_t *)addr) = value;
}

static inline void wd_iowrite64(void *addr, uint64_t value)
{
	__sync_synchronize();
	*((volatile uint64_t *)addr) = value;
}

/**
 * wd_request_ctx() - Request a communication context from a device.
 * @dev: Indicate one device.
 *
 * Return the handle of related context or NULL otherwise.
 *
 * The context is communication context between user and hardware. One context
 * must be got before doing any task. This function can be used among multiple
 * threads. dev should be got from wd_get_accel_list() firstly.
 */
extern handle_t wd_request_ctx(struct uacce_dev *dev);

/**
 * wd_release_ctx() - Release a context.
 * @h_ctx: The handle of context which will be released.
 *
 * The function is the wrapper of close fd. So the release of context maybe
 * delay.
 */
extern void wd_release_ctx(handle_t h_ctx);

/**
 * wd_ctx_start() - Start a context.
 * @h_ctx: The handle of context which will be started.
 *
 * Return 0 if successful or less than 0 otherwise.
 *
 * Context will be started after calling this function. If necessary resource
 * (e.g. MMIO and DUS) already got, tasks can be received by context.
 */
extern int wd_ctx_start(handle_t h_ctx);

/**
 * wd_release_ctx_force() - Release a context forcely.
 * @h_ctx: The handle of context which will be released.
 *
 * Return 0 if successful or less than 0 otherwise.
 *
 * Context will be stopped and related hardware will be released, which avoids
 * release delay in wd_release_ctx(). After calling this function, context
 * related hardware resource will be released, however, fd is still there.
 * wd_release_ctx mush be used to release context finally, other APIs about
 * context can not work with this context after calling wd_release_ctx_force.
 */
extern int wd_release_ctx_force(handle_t h_ctx);

/**
 * wd_ctx_set_priv() - Store some information in context.
 * @h_ctx: The handle of context.
 * @priv: The pointer of memory which stores above information.
 *
 * Return 0 if successful or less than 0 otherwise.
 */
extern int wd_ctx_set_priv(handle_t h_ctx, void *priv);

/**
 * wd_ctx_get_priv() - Get stored information in context.
 * @h_ctx: The handle of context.
 *
 * Return pointer of memory of stored information if successful or NULL
 * otherwise.
 */
extern void *wd_ctx_get_priv(handle_t h_ctx);

/**
 * wd_ctx_get_api() - Get api string of context.
 * @h_ctx: The handle of context.
 *
 * Return api string or NULL otherwise.
 *
 * This function is a wrapper of reading /sys/class/uacce/<dev>/api, which is
 * used to define api version between user space and kernel driver.
 */
extern char *wd_ctx_get_api(handle_t h_ctx);

/**
 * wd_drv_mmap_qfr() - Map and get the base address of one context region.
 * @h_ctx: The handle of context.
 * @qfrt: Name of context region, which could be got in kernel head file
 *        include/uapi/misc/uacce/uacce.h
 *
 * Return pointer of context region if successful or NULL otherwise.
 *
 * Normally, UACCE_QFRT_MMIO is for MMIO registers of one context,
 * UACCE_QFRT_DUS is for task communication memory of one context.
 */
extern void *wd_drv_mmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt);

/**
 * wd_drv_unmap_qfr() - Unmap one context region.
 * @h_ctx: The handle of context.
 * @qfrt: Name of context region, which could be got in kernel head file
 *        include/uapi/misc/uacce/uacce.h.
 */
extern void wd_drv_unmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt);

/**
 * wd_ctx_wait() - Wait task in context finished.
 * @h_ctx: The handle of context.
 * @ms: Timeout parameter.
 *
 * Return more than 0 if successful, 0 for timeout, less than 0 otherwise.
 *
 * This function is a wrapper of Linux poll interface.
 */
extern int wd_ctx_wait(handle_t h_ctx, __u16 ms);

/**
 * wd_is_sva() - Check if the system supports SVA.
 * @h_ctx: The handle of context.
 *
 * Return 1 if SVA, 0 for no SVA, less than 0 otherwise.
 */
extern int wd_is_sva(handle_t h_ctx);

/**
 * wd_get_accel_name() - Get device name or driver name.
 * @dev_path: The path of device. e.g. /dev/hisi_zip-0.
 * @no_apdx: Flag to indicate getting device name(0) or driver name(1).
 *
 * Return device name, e.g. hisi_zip-0; driver name, e.g. hisi_zip.
 */
extern char *wd_get_accel_name(char *dev_path, int no_apdx);

/**
 * wd_get_numa_id() - Get the NUMA id of one context.
 * @h_ctx: The handle of context.
 *
 * Return NUMA id of related context.
 */
extern int wd_get_numa_id(handle_t h_ctx);

/**
 * wd_get_avail_ctx() - Get available context in one device.
 * @dev: The uacce_dev for one device.
 *
 * Return number of available context in dev or less than 0 otherwise.
 */
extern int wd_get_avail_ctx(struct uacce_dev *dev);

/**
 * wd_get_accel_list() - Get device list for one algorithm.
 * @alg_name: Algorithm name, which could be got from
 *            /sys/class/uacce/<device>/algorithm.
 *
 * Return device list in which devices support given algorithm or NULL
 * otherwise.
 */
extern struct uacce_dev_list *wd_get_accel_list(char *alg_name);

/**
 * wd_free_list_accels() - Free device list.
 * @list: Device list which will be free.
 */
extern void wd_free_list_accels(struct uacce_dev_list *list);

/**
 * wd_ctx_set_io_cmd() - Send ioctl command to context.
 * @h_ctx: The handle of context.
 * @cmd: ioctl command which could be found in Linux kernel head file,
 *       include/uapi/misc/uacce/uacce.h, hisi_qm.h...
 * @arg: Command output buffer if some information will be got from kernel or
 *       NULL otherwise.
 *
 * This function is a wrapper of ioctl.
 */
extern int wd_ctx_set_io_cmd(handle_t h_ctx, unsigned long cmd, void *arg);

/**
 * wd_ctx_get_region_size() - Get region offset size
 * @h_ctx: The handle of context.
 * @qfrt: Name of context region, which could be got in kernel head file
 *        include/uapi/misc/uacce/uacce.h
 * Return device region size.
 */
extern unsigned long wd_ctx_get_region_size(handle_t h_ctx, enum uacce_qfrt qfrt);

#endif
