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
#include <ctype.h>
#include <dirent.h>

#include "wd.h"


#define SYS_CLASS_DIR	"/sys/class/uacce"

static int get_raw_attr(char *dev_root, char *attr, char *buf, size_t sz)
{
	char attr_file[PATH_STR_SIZE];
	int fd;
	ssize_t size;

	if (!dev_root || !attr || !buf || (sz == 0))
		return -EINVAL;

	size = snprintf(attr_file, PATH_STR_SIZE, "%s/%s", dev_root, attr);
	if (size < 0)
		return -EINVAL;

	fd = open(attr_file, O_RDONLY, 0);
	if (fd < 0) {
		WD_ERR("open %s fail (%d)!\n", attr_file, errno);
		return -ENODEV;
	}
	size = read(fd, buf, sz);
	if (size <= 0) {
		WD_ERR("read nothing at %s!\n", attr_file);
		size = -EIO;
	}

	close(fd);
	return (int)size;
}

static int get_int_attr(struct uacce_dev_info *info, char *attr, int *val)
{
	int ret;
	char buf[MAX_ATTR_STR_SIZE];

	if (!info || !attr || !val)
		return -EINVAL;

	ret = get_raw_attr(info->dev_root, attr, buf, MAX_ATTR_STR_SIZE);
	if (ret < 0)
		return ret;

	*val = strtol(buf, NULL, 10);
	return 0;
}

static int get_str_attr(struct uacce_dev_info *info, char *attr, char *buf,
			size_t buf_sz)
{
	int ret;

	if (!info || !attr || !buf || (buf_sz == 0))
		return -EINVAL;

	ret = get_raw_attr(info->dev_root, attr, buf, buf_sz);
	if (ret < 0) {
		buf[0] = '\0';
		return ret;
	}

	if ((size_t)ret == buf_sz)
		ret--;

	buf[ret] = '\0';
	while ((ret > 1) && (buf[ret - 1] == '\n')) {
		buf[ret-- - 1] = '\0';
	}
	return ret;
}

static int get_dev_info(struct uacce_dev_info *info)
{
	int	value;

	get_int_attr(info, "available_instances", &info->avail_instn);
	get_int_attr(info, "flags", &info->flags);
	get_str_attr(info, "api", info->api, WD_NAME_SIZE);
	get_str_attr(info, "algorithms", info->algs, MAX_ATTR_STR_SIZE);
	get_int_attr(info, "region_mmio_size", &value);
	info->qfrs_offs[UACCE_QFRT_MMIO] = value;
	get_int_attr(info, "region_dus_size", &value);
	info->qfrs_offs[UACCE_QFRT_DUS] = value;
	info->qfrs_offs[UACCE_QFRT_SS] = 0;

	return 0;
}

static struct uacce_dev_info *read_uacce_sysfs(char *dev_name)
{
	struct uacce_dev_info	*info = NULL;
	DIR			*class = NULL;
	struct dirent		*dev = NULL;
	char			*name = NULL;
	int			len;

	if (!dev_name)
		return NULL;

	info = calloc(1, sizeof(struct uacce_dev_info));
	if (info == NULL)
		return NULL;

	class = opendir(SYS_CLASS_DIR);
	if (!class) {
		WD_ERR("WD framework is not enabled on the system!\n");
		goto out;
	}

	while ((dev = readdir(class)) != NULL) {
		name = dev->d_name;
		if (!strncmp(dev_name, name, strlen(dev_name))) {
			snprintf(info->dev_root, MAX_DEV_NAME_LEN - 1, "%s/%s",
				 SYS_CLASS_DIR, dev_name);
			len = WD_NAME_SIZE - 1;
			if (len > strlen(name) + 1)
				len = strlen(name) + 1;
			strncpy(info->name, name, len);
			get_dev_info(info);
			break;
		}
	}
	if (dev == NULL)
		goto out_dir;

	closedir(class);

	return info;
out_dir:
	closedir(class);
out:
	free(info);
	return NULL;
}

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
	int	ret = -EINVAL;

	if (!node_path || !ctx || (strlen(node_path) + 1 >= MAX_DEV_NAME_LEN))
		return ret;

	ctx->dev_name = get_accel_name(node_path, 0);
	if (!ctx->dev_name)
		return ret;
	ctx->drv_name = get_accel_name(node_path, 1);
	if (!ctx->drv_name)
		goto out;

	ctx->dev_info = read_uacce_sysfs(ctx->dev_name);
	if (!ctx->dev_info)
		goto out_info;

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
	ret = fcntl(ctx->fd, F_SETFL, ret | FASYNC);
	if (ret < 0)
		goto out_ctl;

	return ret;

out_ctl:
	close(ctx->fd);
out_fd:
	free(ctx->dev_info);
out_info:
	free(ctx->drv_name);
out:
	free(ctx->dev_name);
	return ret;
}

void wd_release_ctx(struct wd_ctx *ctx)
{

	close(ctx->fd);
	free(ctx->dev_info);
	free(ctx->drv_name);
	free(ctx->dev_name);
}

int wd_start_ctx(struct wd_ctx *ctx)
{
	int	ret;

	ret = ioctl(ctx->fd, UACCE_CMD_START);
	if (ret)
		WD_ERR("fail to start on %s\n", ctx->node_path);
	return ret;
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

int wd_is_nosva(struct wd_ctx *ctx)
{
	if (ctx->dev_info->flags & UACCE_DEV_SVA)
		return 0;
	return 1;
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
