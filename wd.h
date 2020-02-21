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

#ifndef WD_CONTEXT
#define WD_CONTEXT
#endif	/* WD_CONTEXT */

#define SYS_VAL_SIZE		16
#define PATH_STR_SIZE		256
#define MAX_ATTR_STR_SIZE	256
#define WD_NAME_SIZE		64

#define UACCE_QFRT_MAX		4
#define UACCE_QFR_NA ((unsigned long)-1)

#define WD_CAPA_PRIV_DATA_SIZE	64

#define MAX_DEV_NAME_LEN		256
#define ARRAY_SIZE(x)			(sizeof(x) / sizeof((x)[0]))

typedef int bool;

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

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

struct wd_ctx {
	int		fd;
	char		node_path[MAX_DEV_NAME_LEN];
	char		*dev_name;
	char		*drv_name;
	unsigned long	qfrs_offs[UACCE_QFRT_MAX];

	void		*ss_va;
	void		*ss_pa;

	void		*priv;
};

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
extern void *wd_drv_mmap_qfr(struct wd_ctx *ctx, enum uacce_qfrt qfrt,
			     size_t size);
extern void wd_drv_unmap_qfr(struct wd_ctx *ctx, enum uacce_qfrt qfrt,
			     void *addr);
extern void *wd_reserve_mem(struct wd_ctx *ctx, size_t size);
extern void *wd_get_dma_from_va(struct wd_ctx *ctx, void *va);
#endif
