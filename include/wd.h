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
#define MAX_ATTR_STR_SIZE		384
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
#define WD_ERR(format, args...)	do {			\
	if (!flog_fd)					\
		flog_fd = fopen(WITH_LOG_FILE, "a+");	\
	if (flog_fd)					\
		fprintf(flog_fd, format, ##args);	\
	else						\
		fprintf(stderr, "log %s not exists!",	\
			WITH_LOG_FILE);			\
} while (0)
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
#define	WD_ADDR_ERR			61 /* address error */
#define	WD_HW_EACCESS			62 /* hardware access denied, such as resetting */
#define	WD_SGL_ERR			63 /* sgl input parameter error */
#define	WD_VERIFY_ERR			64 /* verified error */
#define	WD_OUT_EPARA			66 /* output parameter error */
#define	WD_IN_EPARA			67 /* input parameter error */
#define	WD_ENOPROC			68 /* no processed */

#define WD_HANDLE_ERR(h)		((long long)(h))
#define WD_IS_ERR(h)			((unsigned long long)(h) > \
					(unsigned long long)(-1000))

static inline void *WD_ERR_PTR(long error)
{
	return (void *)error;
}

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
struct uacce_dev_list *wd_get_accel_list(char *alg_name);

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
struct uacce_dev *wd_get_accel_dev(char *alg_name);

/**
 * wd_get_accel_api() - Get device supporting the chip version
 * @alg_name: Algorithm name, which could be got from
 *            /sys/class/uacce/<device>/algorithm.
 *
 * Return a chip number e.g. 920 or 930.
 * Otherwise return -EINVAL.
 */
int wd_get_accel_api(char *alg_name);

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

#endif
