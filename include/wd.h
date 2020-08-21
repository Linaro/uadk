// SPDX-License-Identifier: Apache-2.0
#ifndef __WD_H
#define __WD_H
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "include/uacce.h"
#include "config.h"

#define PATH_STR_SIZE			256
#define MAX_ATTR_STR_SIZE		256
#define WD_NAME_SIZE			64

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

struct uacce_dev_info {
	/* sysfs node content */
	int flags;
	/* to do: should be removed as it is dynamic, should use api to get its value */
	int avail_instn;
	char api[WD_NAME_SIZE];
	char algs[MAX_ATTR_STR_SIZE];
	unsigned long qfrs_offs[UACCE_QFRT_MAX];

	char name[WD_NAME_SIZE];
	char alg_path[PATH_STR_SIZE];
	char dev_root[PATH_STR_SIZE];

	int node_id;
};

struct uacce_dev_list {
	struct uacce_dev_info *info;
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

extern handle_t wd_request_ctx(char *dev_path);
extern void wd_release_ctx(handle_t h_ctx);
extern int wd_ctx_start(handle_t h_ctx);
extern int wd_ctx_stop(handle_t h_ctx);
extern void *wd_ctx_get_priv(handle_t h_ctx);
extern int wd_ctx_set_priv(handle_t h_ctx, void *priv);
extern char *wd_ctx_get_api(handle_t h_ctx);
extern int wd_ctx_get_fd(handle_t h_ctx);
extern void *wd_drv_mmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt);
extern void wd_drv_unmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt);
extern int wd_wait(handle_t h_ctx, __u16 ms);
extern int wd_is_nosva(handle_t h_ctx);
extern struct uacce_dev_list *wd_list_accels(wd_dev_mask_t *dev_mask);
extern char *wd_get_accel_name(char *dev_path, int no_apdx);
extern const char *wd_get_driver_name(handle_t h_ctx);
extern int wd_get_numa_id(handle_t h_ctx);
extern int wd_ctx_get_avail_ctx(char *dev_path);
extern struct uacce_dev_list *wd_get_accel_list(char *alg_name);
extern void wd_free_list_accels(struct uacce_dev_list *list);
extern int wd_ctx_set_io_cmd(handle_t h_ctx, int cmd, void *arg);

#endif
