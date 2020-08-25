/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "wd.h"
#include "wd_alg_common.h"

#define SYS_CLASS_DIR			"/sys/class/uacce"
#define MAX_DEV_NAME_LEN		256

wd_log log_out = NULL;

struct wd_ctx_h {
	int fd;
	char dev_path[MAX_DEV_NAME_LEN];
	char *dev_name;
	char *drv_name;
	unsigned long qfrs_offs[UACCE_QFRT_MAX];
	void *qfrs_base[UACCE_QFRT_MAX];
	void *ss_va;
	void *ss_pa;
	struct uacce_dev_info *dev_info;
	void *priv;
};

static int get_raw_attr(char *dev_root, char *attr, char *buf, size_t sz)
{
	char attr_file[PATH_STR_SIZE];
	ssize_t size;
	int fd;

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

	return size;
}

static int get_int_attr(struct uacce_dev_info *info, char *attr, int *val)
{
	char buf[MAX_ATTR_STR_SIZE];
	int ret;

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

static void get_dev_info(struct uacce_dev_info *info)
{
	int value;

	get_int_attr(info, "flags", &info->flags);
	get_str_attr(info, "api", info->api, WD_NAME_SIZE);
	get_str_attr(info, "algorithms", info->algs, MAX_ATTR_STR_SIZE);
	get_int_attr(info, "region_mmio_size", &value);
	info->qfrs_offs[UACCE_QFRT_MMIO] = value;
	get_int_attr(info, "region_dus_size", &value);
	info->qfrs_offs[UACCE_QFRT_DUS] = value;
	info->qfrs_offs[UACCE_QFRT_SS] = 0;
	get_int_attr(info, "device/numa_node", &info->numa_id);
}

static struct uacce_dev_info *read_uacce_sysfs(char *dev_name)
{
	struct uacce_dev_info *info = NULL;
	struct dirent *dev = NULL;
	DIR *class = NULL;
	char *name = NULL;
	int len;

	if (!dev_name)
		return NULL;

	info = calloc(1, sizeof(struct uacce_dev_info));
	if (!info)
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
	if (!dev)
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
char *wd_get_accel_name(char *dev_path, int no_apdx)
{
	int i, appendix, len;
	char *name, *dash;

	/* find '/' index in the string and keep the last level */
	name = rindex(dev_path, '/');
	if (name) {
		/* absolute path */
		if (strlen(name) == 1)
			return NULL;
		name++;
	} else {
		/* relative path */
		name = dev_path;
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
	} else {
		appendix = 0;
	}

	/* remove '-' and digits */
	len = appendix ? strlen(name) - strlen(dash) : strlen(name);

	return strndup(name, len);
}

static void wd_ctx_init_qfrs_offs(struct wd_ctx_h *ctx)
{
	memcpy(&ctx->qfrs_offs, &ctx->dev_info->qfrs_offs,
	       sizeof(ctx->qfrs_offs));
}

handle_t wd_request_ctx(char *dev_path)
{
	struct wd_ctx_h	*ctx;
	int ret = -EINVAL;

	if (!dev_path || (strlen(dev_path) + 1 >= MAX_DEV_NAME_LEN))
		return (handle_t)NULL;

	ctx = calloc(1, sizeof(struct wd_ctx_h));
	if (!ctx)
		return (handle_t)NULL;

	ctx->dev_name = wd_get_accel_name(dev_path, 0);
	if (!ctx->dev_name)
		return ret;

	ctx->drv_name = wd_get_accel_name(dev_path, 1);
	if (!ctx->drv_name)
		goto out;

	ctx->dev_info = read_uacce_sysfs(ctx->dev_name);
	if (!ctx->dev_info)
		goto out_info;

	wd_ctx_init_qfrs_offs(ctx);

	strncpy(ctx->dev_path, dev_path, MAX_DEV_NAME_LEN - 1);
	ctx->fd = open(dev_path, O_RDWR | O_CLOEXEC);
	if (ctx->fd < 0) {
		WD_ERR("Failed to open %s (%d).\n", dev_path, errno);
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

	return (handle_t)ctx;

out_ctl:
	close(ctx->fd);
out_fd:
	free(ctx->dev_info);
out_info:
	free(ctx->drv_name);
out:
	free(ctx->dev_name);
	return (handle_t)NULL;
}

void wd_release_ctx(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx)
		return;

	close(ctx->fd);
	free(ctx->dev_info);
	free(ctx->drv_name);
	free(ctx->dev_name);
	free(ctx);
}

int wd_ctx_start(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;
	int ret;

	if (!ctx)
		return -EINVAL;

	ret = wd_ctx_set_io_cmd(h_ctx, UACCE_CMD_START, NULL);
	if (ret)
		WD_ERR("fail to start on %s\n", ctx->dev_path);

	return ret;
}

int wd_ctx_stop(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx)
		return -EINVAL;

	return wd_ctx_set_io_cmd(h_ctx, UACCE_CMD_PUT_Q, NULL);
}

void *wd_drv_mmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;
	off_t off = qfrt * getpagesize();
	size_t size;
	void *addr;

	if (!ctx || !ctx->qfrs_offs[qfrt])
		return NULL;

	size = ctx->qfrs_offs[qfrt];

	addr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, ctx->fd, off);
	if (!addr)
		return NULL;

	ctx->qfrs_base[qfrt] = addr;

	return addr;
}

void wd_drv_unmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx)
		return;

	if (ctx->qfrs_offs[qfrt] != 0)
		munmap(ctx->qfrs_base[qfrt], ctx->qfrs_offs[qfrt]);
}

void *wd_ctx_get_priv(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx)
		return NULL;

	return ctx->priv;
}

int wd_ctx_set_priv(handle_t h_ctx, void *priv)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx)
		return -EINVAL;

	ctx->priv = priv;

	return 0;
}

char *wd_ctx_get_api(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx)
		return NULL;

	return ctx->dev_info->api;
}

int wd_ctx_wait(handle_t h_ctx, __u16 ms)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;
	struct pollfd fds[1];
	int ret;

	if (!ctx)
		return -EINVAL;

	fds[0].fd = ctx->fd;
	fds[0].events = POLLIN;
	ret = poll(fds, 1, ms);
	if (ret == -1)
		return -errno;

	return 0;
}

int wd_is_nosva(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx)
		return 0;

	if (ctx->dev_info->flags & UACCE_DEV_SVA)
		return 0;

	return 1;
}

int wd_get_numa_id(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	return ctx->dev_info->numa_id;
}

/* to do: update interface doc */
int wd_get_avail_ctx(struct uacce_dev_info *dev)
{
	int avail_ctx;

	get_int_attr(dev, "available_instances", &avail_ctx);

	return avail_ctx;
}

static int get_dev_alg_name(char *dev_path, char *buf, size_t sz)
{
	int ret;

	ret = get_raw_attr(dev_path, "algorithms", buf, sz);
	if (ret < 0) {
		buf[0] = '\0';
		return ret;
	}

	if ((size_t)ret == sz)
		buf[sz - 1] = '\0';

	return 0;
}

static bool dev_has_alg(const char *dev_alg_name, const char *alg_name)
{
	char *pos;

	pos = strstr(dev_alg_name, alg_name);
	if (!pos)
		return false;
	else
		return true;
}

static void add_uacce_dev_to_list(struct uacce_dev_list *head,
				  struct uacce_dev_list *node)
{
	struct uacce_dev_list *tmp = head;

	while (tmp->next)
		tmp = tmp->next;

	tmp->next = node;
}

struct uacce_dev_list *wd_get_accel_list(char *alg_name)
{
	struct uacce_dev_list *node = NULL, *head = NULL;
	char dev_alg_name[MAX_ATTR_STR_SIZE];
	char dev_path[MAX_DEV_NAME_LEN];
	struct dirent *dev = NULL;
	DIR *wd_class = NULL;
	int ret;

	wd_class = opendir(SYS_CLASS_DIR);
	if (!wd_class) {
		WD_ERR("WarpDrive framework isn't enabled in system!\n");
		return NULL;
	}

	while ((dev = readdir(wd_class)) != NULL) {
		if (!strncmp(dev->d_name, ".", 1) ||
		    !strncmp(dev->d_name, "..", 2))
			continue;

		ret = snprintf(dev_path, MAX_DEV_NAME_LEN, "%s/%s",
			       SYS_CLASS_DIR, dev->d_name);
		if (ret > MAX_DEV_NAME_LEN || ret < 0)
			goto free_list;

		ret = get_dev_alg_name(dev_path, dev_alg_name,
				       sizeof(dev_alg_name));
		if (ret < 0) {
			WD_ERR("Failed to get alg for %s, ret = %d\n",
			       dev_path, ret);
			return NULL;
		}

		if (dev_has_alg(dev_alg_name, alg_name)) {
			node = calloc(1, sizeof(*node));
			if (!node)
				goto free_list;

			node->info = read_uacce_sysfs(dev->d_name);
			if (!node->info)
				goto free_list;

			if (!head)
				head = node;
			else
				add_uacce_dev_to_list(head, node);
		} else {
			continue;
		}

	}

	closedir(wd_class);

	return head;

free_list:
	wd_free_list_accels(head);
	return NULL;
}

void wd_free_list_accels(struct uacce_dev_list *list)
{
	struct uacce_dev_list *curr, *next;

	if (!list)
		return;

	curr = list;
	while (curr) {
		next = curr->next;
		if (curr->info)
			free(curr->info);
		free(curr);
		curr = next;
	}
}

int wd_ctx_set_io_cmd(handle_t h_ctx, unsigned long cmd, void *arg)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx)
		return -EINVAL;

	if (!arg)
		return ioctl(ctx->fd, cmd);
	else
		return ioctl(ctx->fd, cmd, arg);
}

int wd_register_log(wd_log log)
{
	if (!log) {
		WD_ERR("param null!\n");
		return -WD_EINVAL;
	}

	if (log_out) {
		WD_ERR("can not duplicate register!\n");
		return -WD_EINVAL;
	}

	log_out = log;
	dbg("log register\n");

	return WD_SUCCESS;
}
