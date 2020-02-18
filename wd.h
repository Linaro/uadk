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

#if defined(__AARCH64_CMODEL_SMALL__) && __AARCH64_CMODEL_SMALL__

#define dsb(opt)	asm volatile("dsb " #opt : : : "memory")
#define rmb()		dsb(ld)
#define wmb()		dsb(st)
#define mb()		dsb(sy)

#else

#define rmb()
#define wmb()
#define mb()
#ifndef __UT__
#error "no platform mb, define one before compiling"
#endif

#endif

/* Capabilities */
struct wd_capa {
	char *alg;
	int throughput;
	int latency;
	__u32 flags;
	__u8 priv[WD_CAPA_PRIV_DATA_SIZE];/* For algorithm parameters */
};

struct wd_ctx {
	int		fd;
	char		node_path[MAX_DEV_NAME_LEN];
	char		*dev_name;
	char		*drv_name;
	unsigned long	qfrs_offs[UACCE_QFRT_MAX];
	struct wd_drv	*drv;

	void		*ss_va;
	void		*ss_pa;

	struct wd_capa	capa;

	void		*priv;
};

static inline void wd_reg_write(void *reg_addr, uint32_t value)
{
	*((volatile uint32_t *)reg_addr) = value;
	wmb();
}

static inline uint32_t wd_reg_read(void *reg_addr)
{
	uint32_t temp;

	temp = *((volatile uint32_t *)reg_addr);
	rmb();

	return temp;
}

extern int wd_request_ctx(struct wd_ctx *ctx, char *node_path);
extern void wd_release_ctx(struct wd_ctx *ctx);
extern void *wd_drv_mmap_qfr(struct wd_ctx *ctx, enum uacce_qfrt qfrt,
			     size_t size);
extern void wd_drv_unmap_qfr(struct wd_ctx *ctx, enum uacce_qfrt qfrt,
			     void *addr);
extern void *wd_reserve_mem(struct wd_ctx *ctx, size_t size);
extern void *wd_get_dma_from_va(struct wd_ctx *ctx, void *va);
#endif
