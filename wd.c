/* SPDX-License-Identifier: Apache-2.0 */
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <sys/poll.h>
#include <ctype.h>

#include "wd_internal.h"


#define SYS_CLASS_DIR	"/sys/class/uacce"

static struct wd_drv wd_drv_list[] = {
	{
		.drv_name	= "hisi_zip",
		.alloc_ctx	= hisi_qm_alloc_ctx,
		.free_ctx	= hisi_qm_free_ctx,
		.send		= hisi_qm_send,
		.recv		= hisi_qm_recv,
	},
};

/* pick the name of accelerator */
static char *get_accel_name(char *node_path, int no_apdx)
{
	char	*name, *dash;
	int	i, appendix, len;

	/* find '/' index in the string and keep the last level */
	name = rindex(node_path, '/');
	if (name) {
		/* absolute path */
		if (strlen(name) == 1)
			return NULL;
		name++;
	} else {
		/* relative path */
		name = node_path;
	}
	if (strlen(name) == 0)
		return NULL;

	if (no_apdx) {
		/* find '-' index in the name string */
		appendix = 1;
		dash = rindex(name, '-');
		if (dash) {
			for (i = 1; i < strlen(dash); i++) {
				if (!isdigit(dash[i])) {
					appendix = 0;
					break;
				}
			}
			/* treat dash as a part of name if there's no digit */
			if (i == 1)
				appendix = 0;
		}
	} else
		appendix = 0;

	/* remove '-' and digits */
	len = appendix ? strlen(name) - strlen(dash) : strlen(name);
	return strndup(name, len);
}

int wd_request_ctx(struct wd_ctx *ctx, char *node_path)
{
	int	i, ret = -EINVAL;

	if (!node_path || !ctx || (strlen(node_path) + 1 >= MAX_DEV_NAME_LEN))
		return ret;

	ctx->dev_name = get_accel_name(node_path, 0);
	if (!ctx->dev_name)
		return ret;
	ctx->drv_name = get_accel_name(node_path, 1);
	if (!ctx->drv_name)
		goto out;

	strncpy(ctx->node_path, node_path, MAX_DEV_NAME_LEN - 1);
	ctx->fd = open(node_path, O_RDWR | O_CLOEXEC);
	if (ctx->fd < 0) {
		WD_ERR("Failed to open %s (%d).\n", node_path, errno);
		goto out_fd;
	}
	/* make process receiving async signal from kernel */
	fcntl(ctx->fd, F_SETOWN, getpid());
	ret = fcntl(ctx->fd, F_GETFL);
	if (ret < 0)
		goto out_ctl;
	fcntl(ctx->fd, F_SETFL, ret | FASYNC);

	/* match driver with accel name */
	for (i = 0; i < ARRAY_SIZE(wd_drv_list); i++) {
		if (!strncmp(wd_drv_list[i].drv_name, ctx->drv_name,
			     strlen(ctx->drv_name))) {
			ctx->drv = &wd_drv_list[i];
			ret = ctx->drv->alloc_ctx(ctx);
			if (ret < 0) {
				WD_ERR("Failed to allocate hw (%d).\n", ret);
				goto out_ctl;
			}
		}
	}
	ret = ioctl(ctx->fd, UACCE_CMD_START);
	if (ret)
		WD_ERR("fail to start on %s\n", node_path);
	return ret;

out_ctl:
	close(ctx->fd);
out_fd:
	free(ctx->drv_name);
out:
	free(ctx->dev_name);
	return ret;
}

void wd_release_ctx(struct wd_ctx *ctx)
{

	ctx->drv->free_ctx(ctx);
	close(ctx->fd);
	free(ctx->drv_name);
	free(ctx->dev_name);
}

void *wd_drv_mmap_qfr(struct wd_ctx *ctx, enum uacce_qfrt qfrt, size_t size)
{
	off_t	off = qfrt * getpagesize();

	if (ctx->qfrs_offs[qfrt] != 0)
		size = ctx->qfrs_offs[qfrt];

	return mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, ctx->fd, off);
}

void wd_drv_unmap_qfr(struct wd_ctx *ctx, enum uacce_qfrt qfrt, void *addr)
{
	size_t	size;

	if (ctx->qfrs_offs[qfrt] != 0) {
		size = ctx->qfrs_offs[qfrt];
		munmap(addr, size);
	}
}

void *wd_reserve_mem(struct wd_ctx *ctx, size_t size)
{
	int ret;

	ctx->ss_va = wd_drv_mmap_qfr(ctx, UACCE_QFRT_SS, size);

	if (ctx->ss_va == MAP_FAILED) {
		WD_ERR("wd drv mmap fail!\n");
		return NULL;
	}

	ret = (long)ioctl(ctx->fd, UACCE_CMD_GET_SS_DMA, &ctx->ss_pa);
	if (ret) {
		WD_ERR("fail to get PA!\n");
		return NULL;
	}

	return ctx->ss_va;
}

void *wd_get_dma_from_va(struct wd_ctx *ctx, void *va)
{
	return va - ctx->ss_va + ctx->ss_pa;
}
