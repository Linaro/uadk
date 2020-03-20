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
	int		iommu_type;
};

struct uacce_dev_list {
	struct uacce_dev_info	*info;
	struct uacce_dev_list	*next;
};

struct wd_ctx {
	int		fd;
	char		node_path[MAX_DEV_NAME_LEN];
	char		*dev_name;
	char		*drv_name;
	unsigned long	qfrs_offs[UACCE_QFRT_MAX];

	void		*ss_va;
	void		*ss_pa;

	struct uacce_dev_info	*dev_info;

	void		*priv;
};

struct wd_dev_mask {
	unsigned char	*mask;
	int		len;
	unsigned int	magic;
};

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

extern int wd_request_ctx(struct wd_ctx *ctx, char *node_path);
extern void wd_release_ctx(struct wd_ctx *ctx);
extern int wd_start_ctx(struct wd_ctx *ctx);
extern int wd_stop_ctx(struct wd_ctx *ctx);
extern void *wd_drv_mmap_qfr(struct wd_ctx *ctx, enum uacce_qfrt qfrt,
			     size_t size);
extern void wd_drv_unmap_qfr(struct wd_ctx *ctx, enum uacce_qfrt qfrt,
			     void *addr);
extern int wd_is_nosva(struct wd_ctx *ctx);
extern void *wd_reserve_mem(struct wd_ctx *ctx, size_t size);
extern void *wd_get_dma_from_va(struct wd_ctx *ctx, void *va);

extern int wd_get_accel_mask(char *alg_name, wd_dev_mask_t *dev_mask);

extern struct uacce_dev_list *wd_list_accels(wd_dev_mask_t *dev_mask);
extern char *wd_get_accel_name(char *node_path, int no_apdx);
extern int wd_clear_mask(wd_dev_mask_t *dev_mask, int idx);

#endif
