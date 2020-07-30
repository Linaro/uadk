// SPDX-License-Identifier: GPL-2.0
#ifndef __WD_H
#define __WD_H
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>
#include "include/uacce.h"
#include "config.h"

#define SYS_VAL_SIZE		16
#define PATH_STR_SIZE		256
#define MAX_ATTR_STR_SIZE	256
#define WD_NAME_SIZE		64

#define UACCE_QFRT_MAX		4
#define UACCE_QFR_NA ((unsigned long)-1)

#define WD_CAPA_PRIV_DATA_SIZE	64

#define MAX_DEV_NAME_LEN		256
#define ARRAY_SIZE(x)			(sizeof(x) / sizeof((x)[0]))
#define MAX_ACCELS			16
#define MAX_BYTES_FOR_ACCELS		(MAX_ACCELS >> 3)
#define WD_DEV_MASK_MAGIC		0xa395deaf

#ifndef WD_ERR
#ifndef WITH_LOG_FILE
#define WD_ERR(format, args...) fprintf(stderr, format, ##args)
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

struct uacce_dev_info {
	/* sysfs node content */
	int		flags;
	int		avail_instn;
	char		api[WD_NAME_SIZE];
	char		algs[MAX_ATTR_STR_SIZE];
	unsigned long	qfrs_offs[UACCE_QFRT_MAX];

	char		name[WD_NAME_SIZE];
	char		alg_path[PATH_STR_SIZE];
	char		dev_root[PATH_STR_SIZE];

	int		node_id;
};

struct uacce_dev_list {
	struct uacce_dev_info	*info;
	struct uacce_dev_list	*next;
};

struct wd_dev_mask {
	unsigned char	*mask;
	int		len;
	unsigned int	magic;
};

typedef unsigned long long int	handle_t;
typedef struct wd_dev_mask	wd_dev_mask_t;


static inline uint32_t wd_ioread32(void *addr)
{
	uint32_t ret;

	ret = *((volatile uint32_t *)addr);
	__sync_synchronize();
	return ret;
}

static inline uint64_t wd_ioread64(void *addr)
{
	uint64_t	ret;

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

extern handle_t wd_request_ctx(char *node_path);
extern void wd_release_ctx(handle_t h_ctx);
extern int wd_ctx_start(handle_t h_ctx);
extern int wd_ctx_stop(handle_t h_ctx);
extern void *wd_ctx_get_priv(handle_t h_ctx);
extern int wd_ctx_set_priv(handle_t h_ctx, void *priv);
extern void wd_ctx_init_qfrs_offs(handle_t h_ctx);
extern char *wd_ctx_get_api(handle_t h_ctx);
extern void *wd_ctx_get_shared_va(handle_t h_ctx);
extern int wd_ctx_set_shared_va(handle_t h_ctx, void *shared_va);
extern int wd_ctx_get_fd(handle_t h_ctx);

extern void *wd_drv_mmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt,
			     size_t size);
extern void wd_drv_unmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt,
			     void *addr);
extern int wd_wait(handle_t h_ctx, __u16 ms);
extern int wd_is_nosva(handle_t h_ctx);
extern void *wd_reserve_mem(handle_t h_ctx, size_t size);
extern void *wd_get_dma_from_va(handle_t h_ctx, void *va);

extern int wd_get_accel_mask(char *alg_name, wd_dev_mask_t *dev_mask);

extern struct uacce_dev_list *wd_list_accels(wd_dev_mask_t *dev_mask);
extern char *wd_get_accel_name(char *node_path, int no_apdx);
extern int wd_clear_mask(wd_dev_mask_t *dev_mask, int idx);

/* new code */
/**
 * struct wd_ctx - Define one ctx and related type.
 * @ctx:	The ctx itself.
 * @op_type:	Define the operation type of this specific ctx.
 *		e.g. 0: compression; 1: decompression.
 * @ctx_mode:   Define this ctx is used for synchronization of asynchronization
 *		1: synchronization; 0: asynchronization;
 * @fd:		The open file descriptor of context.
 * @drv_name:	The driver name.
 * @dev_info:	Sysfs node content in UACCE framework.
 * @ss_va:	Shared virtual address.
 * @ss_pa:	Shared physical address.
 * @priv:	Define the pointer for vendor specific structure.
 */
struct wd_ctx {
	handle_t ctx;
	__u8 op_type;
	__u8 ctx_mode;
	int fd;
	char *drv_name;
	struct uacce_dev_info *dev_info;
	void *ss_va;
	void *ss_pa;
	void *priv;
};

/**
 * struct wd_ctx_config - Define a ctx set and its related attributes, which
 *			  will be used in the scope of current process.
 * @ctx_num:	The ctx number in below ctx array.
 * @ctxs:	Point to a ctx array, length is above ctx_num.
 * @priv:	The attributes of ctx defined by user, which is used by user
 *		defined scheduler.
 */
struct wd_ctx_config {
	int ctx_num;
	struct wd_ctx *ctxs;
	void *priv;
};

extern const char *wd_get_driver_name(handle_t h_ctx);
extern int wd_get_numa_id(handle_t h_ctx);

#endif
