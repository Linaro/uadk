// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#ifndef __WD_H
#define __WD_H
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <asm/types.h>
#include "uacce.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PATH_STR_SIZE			256
#define MAX_ATTR_STR_SIZE		384
#define WD_NAME_SIZE			64
#define MAX_DEV_NAME_LEN		256
#define LINUX_CRTDIR_SIZE		1
#define LINUX_PRTDIR_SIZE		2
#define WD_CTX_CNT_NUM			1024
#define WD_IPC_KEY			0x500011

typedef void (*wd_log)(const char *format, ...);

#ifndef WD_NO_LOG
#define WD_DEBUG(fmt, args...)  \
	do {\
		openlog("uadk-debug", LOG_CONS | LOG_PID, LOG_LOCAL5);\
		syslog(LOG_DEBUG, fmt, ##args);\
	} while (0)

#define WD_INFO(fmt, args...)  \
	do {\
		openlog("uadk-info", LOG_CONS | LOG_PID, LOG_LOCAL5);\
		syslog(LOG_INFO, fmt, ##args);\
	} while (0)

#define WD_ERR(fmt, args...)  \
	do {\
		openlog("uadk-err", LOG_CONS | LOG_PID, LOG_LOCAL5);\
		syslog(LOG_ERR, fmt, ##args);\
	} while (0)
#else
#define OPEN_LOG(s)
#define WD_DEBUG(fmt, args...)   fprintf(stderr, fmt, ##args)
#define WD_INFO(fmt, args...)    fprintf(stderr, fmt, ##args)
#define WD_ERR(fmt, args...)     fprintf(stderr, fmt, ##args)
#endif

/* @h_ctx: The handle of context. */
#define WD_DEV_ERR(h_ctx, format, args...)\
	do {							\
		char *dev_name = wd_ctx_get_dev_name(h_ctx);	\
		WD_ERR("%s: "format"\n", dev_name, ##args);	\
	} while (0)

#define WD_CONSOLE printf

/* WD error code */
#define	WD_SUCCESS			0
#define	WD_STREAM_END			1
#define	WD_STREAM_START			2
#define	WD_EIO				EIO
#define	WD_EAGAIN			EAGAIN
#define	WD_ENOMEM			ENOMEM
#define	WD_EACCESS			EACCESS
#define	WD_EBUSY			EBUSY
#define	WD_EEXIST			EEXIST
#define	WD_ENODEV			ENODEV
#define	WD_EINVAL			EINVAL
#define	WD_ETIMEDOUT			ETIMEDOUT
#define	WD_ADDR_ERR			61 /* address error */
#define	WD_HW_EACCESS			62 /* hardware access denied, such as resetting */
#define	WD_SGL_ERR			63 /* sgl input parameter error */
#define	WD_VERIFY_ERR			64 /* verified error */
#define	WD_OUT_EPARA			66 /* output parameter error */
#define	WD_IN_EPARA			67 /* input parameter error */
#define	WD_ENOPROC			68 /* no processed */

#define WD_HANDLE_ERR(h)		((long long)(h))
#define WD_IS_ERR(h)			((uintptr_t)(h) > \
					(uintptr_t)(-1000))

enum wcrypto_type {
	WD_CIPHER,
	WD_DIGEST,
	WD_AEAD,
};

struct wd_dtb {
	/* data/buffer start address */
	char *data;
	/* data size */
	__u32 dsize;
	/* buffer size */
	__u32 bsize;
};

struct uacce_dev {
	/* sysfs node content */
	/* flag: SVA */
	int flags;
	/* HW context type */
	char api[WD_NAME_SIZE];
	/* dev supported algorithms */
	char algs[MAX_ATTR_STR_SIZE];
	unsigned long qfrs_offs[UACCE_QFRT_MAX];
	/* sysfs path with dev name */
	char dev_root[PATH_STR_SIZE];

	/* dev path in devfs */
	char char_dev_path[MAX_DEV_NAME_LEN];

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

#define handle_t uintptr_t
typedef struct wd_dev_mask wd_dev_mask_t;

#if defined(__AARCH64_CMODEL_SMALL__) && __AARCH64_CMODEL_SMALL__
#define dsb(opt)        { asm volatile("dsb " #opt : : : "memory"); }
#define rmb() dsb(ld) /* read fence */
#define wmb() dsb(st) /* write fence */
#define mb() dsb(sy) /* rw fence */
#else
#define rmb() __sync_synchronize() /* read fence */
#define wmb() __sync_synchronize() /* write fence */
#define mb() __sync_synchronize() /* rw fence */
#endif

static inline uint32_t wd_ioread32(void *addr)
{
	uint32_t ret;

	ret = *((volatile uint32_t *)addr);
	rmb();
	return ret;
}

static inline uint64_t wd_ioread64(void *addr)
{
	uint64_t ret;

	ret = *((volatile uint64_t *)addr);
	rmb();
	return ret;
}

static inline void wd_iowrite32(void *addr, uint32_t value)
{
	wmb();
	*((volatile uint32_t *)addr) = value;
}

static inline void wd_iowrite64(void *addr, uint64_t value)
{
	wmb();
	*((volatile uint64_t *)addr) = value;
}

static inline void *WD_ERR_PTR(uintptr_t error)
{
	return (void *)error;
}

static inline long WD_PTR_ERR(const void *ptr)
{
	return (long)ptr;
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
handle_t wd_request_ctx(struct uacce_dev *dev);

/**
 * wd_release_ctx() - Release a context.
 * @h_ctx: The handle of context which will be released.
 *
 * The function is the wrapper of close fd. So the release of context maybe
 * delay.
 */
void wd_release_ctx(handle_t h_ctx);

/**
 * wd_ctx_start() - Start a context.
 * @h_ctx: The handle of context which will be started.
 *
 * Return 0 if successful or less than 0 otherwise.
 *
 * Context will be started after calling this function. If necessary resource
 * (e.g. MMIO and DUS) already got, tasks can be received by context.
 */
int wd_ctx_start(handle_t h_ctx);

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
int wd_release_ctx_force(handle_t h_ctx);

/**
 * wd_ctx_set_priv() - Store some information in context.
 * @h_ctx: The handle of context.
 * @priv: The pointer of memory which stores above information.
 *
 * Return 0 if successful or less than 0 otherwise.
 */
int wd_ctx_set_priv(handle_t h_ctx, void *priv);

/**
 * wd_ctx_get_priv() - Get stored information in context.
 * @h_ctx: The handle of context.
 *
 * Return pointer of memory of stored information if successful or NULL
 * otherwise.
 */
void *wd_ctx_get_priv(handle_t h_ctx);

/**
 * wd_ctx_get_api() - Get api string of context.
 * @h_ctx: The handle of context.
 *
 * Return api string or NULL otherwise.
 *
 * This function is a wrapper of reading /sys/class/uacce/<dev>/api, which is
 * used to define api version between user space and kernel driver.
 */
char *wd_ctx_get_api(handle_t h_ctx);

/**
 * wd_ctx_mmap_qfr() - Map and get the base address of one context region.
 * @h_ctx: The handle of context.
 * @qfrt: Name of context region, which could be got in kernel head file
 *        include/uapi/misc/uacce/uacce.h
 *
 * Return pointer of context region if successful or NULL otherwise.
 *
 * Normally, UACCE_QFRT_MMIO is for MMIO registers of one context,
 * UACCE_QFRT_DUS is for task communication memory of one context.
 */
void *wd_ctx_mmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt);

/**
 * wd_ctx_unmap_qfr() - Unmap one context region.
 * @h_ctx: The handle of context.
 * @qfrt: Name of context region, which could be got in kernel head file
 *        include/uapi/misc/uacce/uacce.h.
 */
void wd_ctx_unmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt);

/**
 * wd_ctx_wait() - Wait task in context finished.
 * @h_ctx: The handle of context.
 * @ms: Timeout parameter.
 *
 * Return more than 0 if successful, 0 for timeout, less than 0 otherwise.
 *
 * This function is a wrapper of Linux poll interface.
 */
int wd_ctx_wait(handle_t h_ctx, __u16 ms);

/**
 * wd_is_sva() - Check if the system supports SVA.
 * @h_ctx: The handle of context.
 *
 * Return 1 if SVA, 0 for no SVA, less than 0 otherwise.
 */
int wd_is_sva(handle_t h_ctx);

/**
 * wd_is_isolate() - Check if the device has been isolated.
 * @dev: Indicate one device.
 *
 * Return 1 if isolated, 0 for not isolated, less than 0 otherwise.
 */
int wd_is_isolate(struct uacce_dev *dev);

/**
 * wd_get_accel_name() - Get device name or driver name.
 * @dev_path: The path of device. e.g. /dev/hisi_zip-0.
 * @no_apdx: Flag to indicate getting device name(0) or driver name(1).
 *
 * Return device name, e.g. hisi_zip-0; driver name, e.g. hisi_zip.
 */
char *wd_get_accel_name(char *dev_path, int no_apdx);

/**
 * wd_get_numa_id() - Get the NUMA id of one context.
 * @h_ctx: The handle of context.
 *
 * Return NUMA id of related context.
 */
int wd_get_numa_id(handle_t h_ctx);

/**
 * wd_get_avail_ctx() - Get available context in one device.
 * @dev: The uacce_dev for one device.
 *
 * Return number of available context in dev or less than 0 otherwise.
 */
int wd_get_avail_ctx(struct uacce_dev *dev);

/**
 * wd_get_accel_list() - Get device list for one algorithm.
 * @alg_name: Algorithm name, which could be got from
 *            /sys/class/uacce/<device>/algorithm.
 *
 * Return device list in which devices support given algorithm or NULL
 * otherwise.
 */
struct uacce_dev_list *wd_get_accel_list(const char *alg_name);

/**
 * wd_find_dev_by_numa() - get device with max available ctx number from an
 *			   device list according to numa id.
 * @list: The device list.
 * @numa_id: The numa_id.
 *
 * Return device if succeed and other error number if fail.
 */
struct uacce_dev *wd_find_dev_by_numa(struct uacce_dev_list *list, int numa_id);

/**
 * wd_get_accel_dev() - Get device supporting the algorithm with
			smallest numa distance to current numa node.
 * @alg_name: Algorithm name, which could be got from
 *            /sys/class/uacce/<device>/algorithm.
 *
 * Return a device closest to current numa node supporting given algorithm
 * and the device need to be freed after usage.
 * Otherwise return NULL.
 */
struct uacce_dev *wd_get_accel_dev(const char *alg_name);

/**
 * wd_free_list_accels() - Free device list.
 * @list: Device list which will be free.
 */
void wd_free_list_accels(struct uacce_dev_list *list);

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
int wd_ctx_set_io_cmd(handle_t h_ctx, unsigned long cmd, void *arg);

/**
 * wd_ctx_get_region_size() - Get region offset size
 * @h_ctx: The handle of context.
 * @qfrt: Name of context region, which could be got in kernel head file
 *        include/uapi/misc/uacce/uacce.h
 * Return device region size.
 */
unsigned long wd_ctx_get_region_size(handle_t h_ctx, enum uacce_qfrt qfrt);

enum wd_page_type {
	WD_HUGE_PAGE = 0,
	WD_NORMAL_PAGE,
};

/*
 * struct wd_mempool_stats - Use to dump statistics info about mempool
 * @page_type: 0 huge page, 1 mmap + pin.
 * @page_size: Page size.
 * @pape_num: Page numbers in mempool.
 * @blk_size: Memory in mempool will be divied into blocks with same size,
 *	      this is size of each block. Currently it is 4KB fixed.
 * @blk_num: Number of blocks in mempool.
 * @free_blk_num: Number of free blocks in mempool.
 * @blk_usage_rate: In wd_blockpool_create function, it gets memory from
 *		    mempool by mempool blocks. As continuous blocks in mempool
 *		    may be needed, wd_blockpool_create may fail. blk_usage_rate
 * 		    helps to show the usage rate of mempool. It will be helpful
 *		    to show the state of memory fragmentation. e.g. 30 is 30%.
 */
struct wd_mempool_stats {
	enum wd_page_type page_type;
	unsigned long page_size;
	unsigned long page_num;
	unsigned long blk_size;
	unsigned long blk_num;
	unsigned long free_blk_num;
	unsigned long blk_usage_rate;
};

/*
 * struct wd_blockpool_stats - Use to dump statistics info about blkpool
 * @block_size: Block size.
 * @block_num: Number of blocks.
 * @free_block_num: Number of free blocks.
 * @block_usage_rate: Block usage rate, e.g. 30 is 30%
 * @mem_waste_rate: When blkpool allocate memory from mempool, it may waste
 *		    some memory as below figure. This is the waste rate,
 *		    e.g. 30 is 30%.
 *    +--+--+--+--+                    +-------------------+
 *    |  |  |  |  |    waste memory    |                   |    waste memory
 *    +--+--+--+--+  /                 +-------------------+  /
 *                  /                                        /
 *    +-------------+                  +-----+-----+-----+-----+
 *    |             |                  |     |     |     |     |
 *    +-------------+                  +-----+-----+-----+-----+
 */
struct wd_blockpool_stats {
	unsigned long block_size;
	unsigned long block_num;
	unsigned long free_block_num;
	unsigned long block_usage_rate;
	unsigned long mem_waste_rate;
};

/**
 * wd_block_alloc() - Allocate block memory from blkpool.
 * @blkpool: The handle of blkpool.
 *
 * Return addr of block memory.
 */
void *wd_block_alloc(handle_t blkpool);

/**
 * wd_block_free() - Free block memory.
 * @blkpool: The handle of blkpool.
 * @addr: The addr of block memory.
 */
void wd_block_free(handle_t blkpool, void *addr);

/**
 * wd_blockpool_create() - Blkpool allocate memory from mempool.
 * @mempool: The handle of mempool.
 * @block_size: Size of every block in blkpool.
 * @block_num: Number of blocks in blkpool.
 *
 * Return handle of blkpool if suceessful; On error, errno is set to indicate
 * the error. WD_EINVAL: An invalid value was specified for mempool、block_size
 * or block_num. WD_ENOMEM: Insufficient kernel memory was available.
 */
handle_t wd_blockpool_create(handle_t mempool, size_t block_size,
				  size_t block_num);

/**
 * wd_blockpool_destroy() - Destory blkpool and release memory to the mempool.
 * @blkpool: The handle of blkpool.
 */
void wd_blockpool_destroy(handle_t blkpool);

/**
 * wd_mempool_create() - Creat mempool.
 * @size: Size of mempool.
 * @node: Node of numa, the memory policy defines from which node memory is
 *	  allocated. If system does't support numa, node will be -1.
 *
 * Return handle of mempool if suceessful; On error,  errno is set to indicate
 * the error. WD_EINVAL: An invalid value was specified for size or node.
 * WD_ENOMEM: Insufficient kernel memory was available.
 */
handle_t wd_mempool_create(size_t size, int node);

/**
 * wd_mempool_destroy() - Destory mempool.
 * @mempool: The handle of mempool.
 */
void wd_mempool_destroy(handle_t mempool);

/**
 * wd_mempool_stats() - Dump statistics information about mempool.
 * @mempool: The handle of mempool.
 * @stats: Pointer of struct wd_mempool_stats.
 */
void wd_mempool_stats(handle_t mempool, struct wd_mempool_stats *stats);

/**
 * wd_blockpool_stats() - Dump statistics information about blkpool.
 * @blkpool: The handle of blkpool.
 * @stats: Pointer of struct wd_blockpool_stats.
 */
void wd_blockpool_stats(handle_t blkpool, struct wd_blockpool_stats *stats);

/**
 * wd_clone_dev() - clone a new uacce device.
 * @dev: The source device.
 *
 * Return a pointer value if succeed, and NULL if fail.
 */
struct uacce_dev *wd_clone_dev(struct uacce_dev *dev);

/**
 * wd_add_dev_to_list() - add a node to end of list.
 * @head: The list head.
 * @node: The node need to be add.
 */
void wd_add_dev_to_list(struct uacce_dev_list *head, struct uacce_dev_list *node);

/**
 * wd_create_device_nodemask() - create a numa node mask of device list.
 * @list: The devices list.
 *
 * Return a pointer value if succeed, and error number if fail.
 */
struct bitmask *wd_create_device_nodemask(struct uacce_dev_list *list);

/**
 * wd_free_device_nodemask() - free a numa node mask.
 * @bmp: A numa node mask.
 */
void wd_free_device_nodemask(struct bitmask *bmp);

/**
 * wd_ctx_get_dev_name() - Get the device name about task.
 * @h_ctx: The handle of context.
 * Return device name.
 */
char *wd_ctx_get_dev_name(handle_t h_ctx);

/**
 * wd_get_version() - Get the libwd version number and released time.
 */
void wd_get_version(void);

/**
 * wd_need_debug() - Get the debug flag from rsyslog.cnf
 */
bool wd_need_debug(void);

/**
 * wd_need_info() - Get the info flag from rsyslog.cnf
 */
bool wd_need_info(void);

#ifdef __cplusplus
}
#endif

#endif
