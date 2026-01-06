/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <numa.h>
#include <sched.h>

#include "wd.h"
#include "wd_alg.h"
#include "wd_internal.h"
#define SYS_CLASS_DIR			"/sys/class/uacce"
#define FILE_MAX_SIZE			(8 << 20)
#define WD_DEV_USAGE_SIZE		256

enum UADK_LOG_LEVEL {
	WD_LOG_NONE = 0,
	WD_LOG_ERROR,
	WD_LOG_INFO,
	WD_LOG_DEBUG,
	WD_LOG_INVALID,
};

static int uadk_log_level = WD_LOG_INVALID;

struct dev_usage_info {
	const char *dev_name;
	__u8 alg_op_type;
	int (*usage_parse_fn)(char *buf, const char *alg_name, __u8 alg_op_type);
};

static const char * const hpre_ecc_algs[] = {
	"sm2",
	"ecdh",
	"x448",
	"x25519",
	"ecdsa"
};

static const char * const zip_dae_algs[] = {
	"udma",
	"hashagg",
	"hashjoin",
	"gather",
};

static int wd_check_ctx_type(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	/* A simple and efficient method to check the queue type */
	if (ctx->fd < 0 || ctx->fd > MAX_FD_NUM) {
		WD_INFO("Invalid: this ctx not HW ctx.\n");
		return -WD_HW_EACCESS;
	}

	return 0;
}

static void wd_parse_log_level(void)
{
	const char *syslog_file = "/etc/rsyslog.conf";
	const char *log_dir = "/var/log/uadk.log";
	bool log_debug = false;
	bool log_info = false;
	struct stat file_info;
	char *file_contents;
	FILE *in_file;

	if (uadk_log_level == WD_LOG_INVALID)
		uadk_log_level = WD_LOG_NONE;

	in_file = fopen(syslog_file, "r");
	if (!in_file) {
		WD_ERR("failed to open the rsyslog.conf file.\n");
		return;
	}

	if (stat(syslog_file, &file_info) == -1) {
		WD_ERR("failed to get file information.\n");
		goto close_file;
	}

	if (file_info.st_size <= 0 || file_info.st_size > FILE_MAX_SIZE) {
		WD_ERR("failed to check rsyslog.conf size.\n");
		goto close_file;
	}

	file_contents = malloc(file_info.st_size);
	if (!file_contents) {
		WD_ERR("failed to get file contents memory.\n");
		goto close_file;
	}

	while (fscanf(in_file, " %[^\n ] ", file_contents) != EOF) {
		if (!strcmp("local5.debug", file_contents))
			log_debug = true;
		else if (!strcmp("local5.info", file_contents))
			log_info = true;

		if (log_debug && !strcmp(log_dir, file_contents)) {
			uadk_log_level = WD_LOG_DEBUG;
			break;
		} else if (log_info && !strcmp(log_dir, file_contents)) {
			uadk_log_level = WD_LOG_INFO;
			break;
		}
	}

	free(file_contents);

close_file:
	fclose(in_file);
}

static int get_raw_attr(const char *dev_root, const char *attr, char *buf,
			size_t sz)
{
	char attr_file[PATH_STR_SIZE];
	char attr_path[PATH_MAX];
	char *ptrRet = NULL;
	ssize_t size;
	int fd;

	size = snprintf(attr_file, PATH_STR_SIZE, "%s/%s", dev_root, attr);
	if (size < 0) {
		WD_ERR("failed to snprintf, dev_root: %s, attr: %s!\n",
		       dev_root, attr);
		return -WD_EINVAL;
	}

	ptrRet = realpath(attr_file, attr_path);
	if (ptrRet == NULL) {
		WD_ERR("failed to resolve path, attr_file: %s!\n", attr_file);
		return -WD_ENODEV;
	}

	fd = open(attr_path, O_RDONLY, 0);
	if (fd < 0) {
		WD_ERR("failed to open %s(%d)!\n", attr_path, -errno);
		return -WD_ENODEV;
	}

	memset(buf, 0, sz);
	size = read(fd, buf, sz);
	if (size <= 0) {
		WD_ERR("failed to read anything at %s!\n", attr_path);
		size = -WD_EIO;
	}

	close(fd);

	return size;
}

static int get_int_attr(struct uacce_dev *dev, const char *attr, int *val)
{
	char buf[MAX_ATTR_STR_SIZE] = {'\0'};
	int ret;

	ret = get_raw_attr(dev->dev_root, attr, buf, MAX_ATTR_STR_SIZE - 1);
	if (ret < 0)
		return ret;

	*val = strtol(buf, NULL, 10);
	if (errno == ERANGE) {
		WD_ERR("failed to strtol %s, out of range!\n", buf);
		return -errno;
	}

	return 0;
}

static int get_str_attr(struct uacce_dev *dev, const char *attr, char *buf,
			size_t buf_sz)
{
	__u32 ret;
	int size;

	size = get_raw_attr(dev->dev_root, attr, buf, buf_sz);
	if (size < 0) {
		buf[0] = '\0';
		return size;
	}

	ret = size;
	if (ret == buf_sz)
		ret--;

	buf[ret] = '\0';
	while ((ret > 1) && (buf[ret - 1] == '\n')) {
		buf[ret-- - 1] = '\0';
	}

	return ret;
}

static int access_attr(const char *dev_root, const char *attr, int mode)
{
	char attr_file[PATH_STR_SIZE];
	ssize_t size;

	if (!dev_root || !attr)
		return -WD_EINVAL;

	size = snprintf(attr_file, PATH_STR_SIZE, "%s/%s", dev_root, attr);
	if (size < 0)
		return -WD_EINVAL;

	return access(attr_file, mode);
}

int wd_is_isolate(struct uacce_dev *dev)
{
	int value = 0;
	int ret;

	if (!dev || !strlen(dev->dev_root))
		return -WD_EINVAL;

	ret = access_attr(dev->dev_root, "isolate", F_OK);
	if (!ret) {
		ret = get_int_attr(dev, "isolate", &value);
		if (ret < 0)
			return ret;
	}

	return value == 1 ? 1 : 0;
}

static int get_dev_info(struct uacce_dev *dev)
{
	int value = 0;
	int ret;

	/* hardware err isolate flag */
	ret = access_attr(dev->dev_root, "isolate", F_OK);
	if (!ret) {
		ret = get_int_attr(dev, "isolate", &value);
		if (ret < 0)
			return ret;
		else if (value == 1) {
			WD_ERR("skip isolated uacce device!\n");
			return -WD_ENODEV;
		}
	}

	ret = get_int_attr(dev, "flags", &dev->flags);
	if (ret < 0)
		return ret;

	ret = get_int_attr(dev, "region_mmio_size", &value);
	if (ret < 0)
		return ret;

	dev->qfrs_offs[UACCE_QFRT_MMIO] = value;

	ret = get_int_attr(dev, "region_dus_size", &value);
	if (ret < 0)
		return ret;

	dev->qfrs_offs[UACCE_QFRT_DUS] = value;

	ret = get_int_attr(dev, "device/numa_node", &dev->numa_id);
	if (ret < 0)
		return ret;

	/* Special processing is performed when NUMA is not configured */
	if (dev->numa_id < 0) {
		WD_INFO("numa node of the device is not configured, set it to 0!\n");
		dev->numa_id = 0;
	}

	ret = get_str_attr(dev, "api", dev->api, WD_NAME_SIZE);
	if (ret < 0)
		return ret;

	return get_str_attr(dev, "algorithms", dev->algs, MAX_ATTR_STR_SIZE);
}

static struct uacce_dev *read_uacce_sysfs(const char *dev_name)
{
	struct uacce_dev *dev = NULL;
	int ret;

	if (!dev_name)
		return NULL;

	dev = calloc(1, sizeof(struct uacce_dev));
	if (!dev)
		return NULL;

	ret = snprintf(dev->dev_root, MAX_DEV_NAME_LEN, "%s/%s",
			   SYS_CLASS_DIR, dev_name);
	if (ret < 0)
		goto out;

	ret = snprintf(dev->char_dev_path, MAX_DEV_NAME_LEN,
			   "/dev/%s", dev_name);
	if (ret < 0)
		goto out;

	ret = get_dev_info(dev);
	if (ret < 0)
		goto out;

	return dev;

out:
	free(dev);
	return NULL;
}

char *wd_get_accel_name(char *dev_path, int no_apdx)
{
	int i, appendix, dash_len, len;
	char *dash = NULL;
	char *name;

	if (!dev_path || (no_apdx != 0 && no_apdx != 1))
		return NULL;

	if (!index(dev_path, '-'))
		return NULL;

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

	if (!strlen(name))
		return NULL;

	if (no_apdx) {
		/* find '-' index in the name string */
		appendix = 1;
		dash = rindex(name, '-');
		if (!dash)
			goto out;

		dash_len = strlen(dash);
		for (i = 1; i < dash_len; i++) {
			if (!isdigit(dash[i])) {
				appendix = 0;
				break;
			}
		}
		/* treat dash as a part of name if there's no digit */
		if (i == 1)
			appendix = 0;
	} else {
		appendix = 0;
	}

out:
	/* remove '-' and digits */
	len = (dash && appendix) ? strlen(name) - strlen(dash) : strlen(name);

	return strndup(name, len);
}

static void wd_ctx_init_qfrs_offs(struct wd_ctx_h *ctx)
{
	memcpy(ctx->qfrs_offs, ctx->dev->qfrs_offs,
	       sizeof(ctx->qfrs_offs));
}

struct uacce_dev *wd_clone_dev(struct uacce_dev *dev)
{
	struct uacce_dev *new;

	new = calloc(1, sizeof(*dev));
	if (!new)
		return NULL;

	memcpy(new, dev, sizeof(*dev));

	return new;
}

void wd_add_dev_to_list(struct uacce_dev_list *head, struct uacce_dev_list *node)
{
	struct uacce_dev_list *tmp = head;

	while (tmp->next)
		tmp = tmp->next;

	tmp->next = node;
}

handle_t wd_request_ctx(struct uacce_dev *dev)
{
	struct wd_ctx_h	*ctx;
	char char_dev_path[PATH_MAX];
	char *ptrRet = NULL;
	int fd;

	if (!dev || !strlen(dev->dev_root))
		return 0;

	ptrRet = realpath(dev->char_dev_path, char_dev_path);
	if (ptrRet == NULL)
		return 0;

	fd = open(char_dev_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		WD_ERR("failed to open %s!(err = %d)\n", char_dev_path, -errno);
		return 0;
	}

	ctx = calloc(1, sizeof(struct wd_ctx_h));
	if (!ctx)
		goto close_fd;

	ctx->dev_name = wd_get_accel_name(dev->char_dev_path, 0);
	if (!ctx->dev_name)
		goto free_ctx;

	ctx->drv_name = wd_get_accel_name(dev->char_dev_path, 1);
	if (!ctx->drv_name)
		goto free_dev_name;

	ctx->dev = wd_clone_dev(dev);
	if (!ctx->dev)
		goto free_drv_name;

	ctx->fd = fd;

	wd_ctx_init_qfrs_offs(ctx);

	memcpy(ctx->dev_path, dev->char_dev_path, MAX_DEV_NAME_LEN);
	ctx->dev_path[MAX_DEV_NAME_LEN - 1] = '\0';

	return (handle_t)ctx;

free_drv_name:
	free(ctx->drv_name);
free_dev_name:
	free(ctx->dev_name);
free_ctx:
	free(ctx);
close_fd:
	close(fd);
	return 0;
}

void wd_release_ctx(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx || wd_check_ctx_type(h_ctx))
		return;

	close(ctx->fd);
	free(ctx->dev);
	free(ctx->drv_name);
	free(ctx->dev_name);
	free(ctx);
}

int wd_ctx_start(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;
	int ret;

	if (!ctx || wd_check_ctx_type(h_ctx))
		return -WD_EINVAL;

	ret = wd_ctx_set_io_cmd(h_ctx, UACCE_CMD_START, NULL);
	if (ret)
		WD_ERR("failed to start on %s (%d), ret = %d!\n",
		       ctx->dev_path, -errno, ret);

	return ret;
}

int wd_release_ctx_force(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;
	int ret;

	if (!ctx)
		return -WD_EINVAL;

	ret = wd_ctx_set_io_cmd(h_ctx, UACCE_CMD_PUT_Q, NULL);
	if (ret)
		WD_ERR("failed to stop on %s (%d), ret = %d!\n",
		       ctx->dev_path, -errno, ret);

	return ret;
}

void *wd_ctx_mmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;
	off_t off = qfrt * getpagesize();
	size_t size;
	void *addr;

	if (!ctx || qfrt >= UACCE_QFRT_MAX || !ctx->qfrs_offs[qfrt]) {
		WD_ERR("failed to check input ctx or qfrt!\n");
		return NULL;
	}

	size = ctx->qfrs_offs[qfrt];

	addr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, ctx->fd, off);
	if (addr == MAP_FAILED) {
		WD_ERR("failed to mmap, qfrt = %u, err = %d!\n", qfrt, -errno);
		return NULL;
	}

	ctx->qfrs_base[qfrt] = addr;

	return addr;
}

void wd_ctx_unmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx || qfrt >= UACCE_QFRT_MAX)
		return;

	if (ctx->qfrs_offs[qfrt] != 0)
		munmap(ctx->qfrs_base[qfrt], ctx->qfrs_offs[qfrt]);
}

unsigned long wd_ctx_get_region_size(handle_t h_ctx, enum uacce_qfrt qfrt)
{
	struct wd_ctx_h *ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx || qfrt >= UACCE_QFRT_MAX)
			return 0;
	return ctx->qfrs_offs[qfrt];
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
		return -WD_EINVAL;

	ctx->priv = priv;

	return 0;
}

char *wd_ctx_get_api(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx || !ctx->dev)
		return NULL;

	return ctx->dev->api;
}

int wd_ctx_wait(handle_t h_ctx, __u16 ms)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;
	struct pollfd fds[1];
	int ret;

	if (!ctx)
		return -WD_EINVAL;

	fds[0].fd = ctx->fd;
	fds[0].events = POLLIN;
	ret = poll(fds, 1, ms);
	if (ret == -1)
		return -errno;

	return ret;
}

int wd_is_sva(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;
	int ret;

	if (!ctx)
		return -WD_EINVAL;

	ret = wd_check_ctx_type(h_ctx);
	if (ret)
		return ret;

	if (!ctx->dev)
		return -WD_EINVAL;

	if ((unsigned int)ctx->dev->flags & UACCE_DEV_SVA)
		return 1;

	return 0;
}

int wd_get_numa_id(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx || !ctx->dev)
		return -WD_EINVAL;

	return ctx->dev->numa_id;
}

int wd_get_avail_ctx(struct uacce_dev *dev)
{
	int avail_ctx, ret;

	if (!dev)
		return -WD_EINVAL;

	ret = get_int_attr(dev, "available_instances", &avail_ctx);
	if (ret < 0)
		return ret;

	return avail_ctx;
}

static int get_dev_alg_name(const char *d_name, char *dev_alg_name, size_t sz)
{
	char dev_path[MAX_DEV_NAME_LEN] = {0};
	__u32 size;
	int ret;

	ret = snprintf(dev_path, MAX_DEV_NAME_LEN, "%s/%s",
		       SYS_CLASS_DIR, d_name);
	if (ret < 0)
		return ret;
	else if (ret > MAX_DEV_NAME_LEN)
		return -WD_EINVAL;

	ret = get_raw_attr(dev_path, "algorithms", dev_alg_name, sz);
	if (ret < 0) {
		dev_alg_name[0] = '\0';
		return ret;
	}

	size = ret;
	if (size == sz)
		dev_alg_name[sz - 1] = '\0';

	return 0;
}

static bool dev_has_alg(const char *dev_alg_name, const char *alg_name)
{
	char *str_end;
	char *str;

	str = strstr(dev_alg_name, alg_name);
	if (!str)
		return false;
	str_end = str + strlen(alg_name);
	if ((*str_end == '\n' || *str_end == '\0') &&
	    ((str > dev_alg_name && *(str - 1) == '\n') || str == dev_alg_name))
		return true;

	return false;
}

static int check_alg_name(const char *alg_name)
{
	int i = 0;

	if (!alg_name)
		return -WD_EINVAL;

	while (alg_name[i] != '\0') {
		i++;
		if (i >= MAX_ATTR_STR_SIZE) {
			WD_ERR("failed to get list, alg name is too long!\n");
			return -WD_EINVAL;
		}
	}

	return 0;
}

struct uacce_dev_list *wd_get_accel_list(const char *alg_name)
{
	struct uacce_dev_list *node, *head = NULL;
	char dev_alg_name[MAX_ATTR_STR_SIZE];
	struct dirent *dev_dir;
	DIR *wd_class;
	int ret;

	if (check_alg_name(alg_name))
		return NULL;

	wd_class = opendir(SYS_CLASS_DIR);
	if (!wd_class) {
		WD_ERR("UADK framework isn't enabled in system!\n");
		return NULL;
	}

	while ((dev_dir = readdir(wd_class)) != NULL) {
		if (!strncmp(dev_dir->d_name, ".", LINUX_CRTDIR_SIZE) ||
		    !strncmp(dev_dir->d_name, "..", LINUX_PRTDIR_SIZE))
			continue;

		ret = access_attr(SYS_CLASS_DIR, dev_dir->d_name, F_OK);
		if (ret < 0) {
			WD_ERR("failed to access dev: %s, ret: %d\n",
				    dev_dir->d_name, ret);
			continue;
		}

		ret = get_dev_alg_name(dev_dir->d_name, dev_alg_name,
				       sizeof(dev_alg_name));
		if (ret < 0) {
			WD_ERR("failed to get dev: %s alg name!\n", dev_dir->d_name);
			continue;
		}

		if (!dev_has_alg(dev_alg_name, alg_name))
			continue;

		node = calloc(1, sizeof(*node));
		if (!node)
			goto free_list;

		node->dev = read_uacce_sysfs(dev_dir->d_name);
		if (!node->dev) {
			free(node);
			node = NULL;
			continue;
		}

		if (!head)
			head = node;
		else
			wd_add_dev_to_list(head, node);
	}

	closedir(wd_class);

	return head;

free_list:
	closedir(wd_class);
	wd_free_list_accels(head);
	return NULL;
}

struct uacce_dev *wd_find_dev_by_numa(struct uacce_dev_list *list, int numa_id)
{
	struct uacce_dev *dev = WD_ERR_PTR(-WD_ENODEV);
	struct uacce_dev_list *p = list;
	int ctx_num, ctx_max = 0;

	if (!list) {
		WD_ERR("invalid: list is NULL!\n");
		return WD_ERR_PTR(-WD_EINVAL);
	}

	while (p) {
		if (p->dev && numa_id != p->dev->numa_id) {
			p = p->next;
			continue;
		}

		ctx_num = wd_get_avail_ctx(p->dev);
		if (ctx_num > ctx_max) {
			dev = p->dev;
			ctx_max = ctx_num;
		}

		p = p->next;
	}

	if (dev == WD_ERR_PTR(-WD_ENODEV))
		WD_ERR("no available device was found in numa %d!\n", numa_id);

	return dev;
}

void wd_free_list_accels(struct uacce_dev_list *list)
{
	struct uacce_dev_list *curr, *next;

	if (!list)
		return;

	curr = list;
	while (curr) {
		next = curr->next;
		if (curr->dev)
			free(curr->dev);
		free(curr);
		curr = next;
	}
}

struct uacce_dev *wd_get_accel_dev(const char *alg_name)
{
	struct uacce_dev_list *list, *head;
	struct uacce_dev *dev = NULL, *target = NULL;
	int cpu = sched_getcpu();
	int node = numa_node_of_cpu(cpu);
	int ctx_num, tmp;
	int dis = 1024;
	int max = 0;

	head = wd_get_accel_list(alg_name);
	if (!head)
		return NULL;

	list = head;
	while (list) {
		tmp = numa_distance(node, list->dev->numa_id);
		ctx_num = wd_get_avail_ctx(list->dev);
		if ((dis > tmp && ctx_num > 0) ||
		    (dis == tmp && ctx_num > max)) {
			dev = list->dev;
			dis = tmp;
			max = ctx_num;
		}

		list = list->next;
	}

	if (dev)
		target = wd_clone_dev(dev);

	wd_free_list_accels(head);

	return target;
}

int wd_ctx_set_io_cmd(handle_t h_ctx, unsigned long cmd, void *arg)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx)
		return -WD_EINVAL;

	if (!arg)
		return ioctl(ctx->fd, cmd);

	return ioctl(ctx->fd, cmd, arg);
}

struct bitmask *wd_create_device_nodemask(struct uacce_dev_list *list)
{
	struct uacce_dev_list *p;
	struct bitmask *bmp;

	if (!list) {
		WD_ERR("invalid: list is NULL!\n");
		return WD_ERR_PTR(-WD_EINVAL);
	}

	bmp = numa_allocate_nodemask();
	if (!bmp) {
		WD_ERR("failed to alloc bitmask(%d)!\n", errno);
		return WD_ERR_PTR(-WD_ENOMEM);
	}

	p = list;
	while (p) {
		numa_bitmask_setbit(bmp, p->dev->numa_id);
		p = p->next;
	}

	return bmp;
}

void wd_free_device_nodemask(struct bitmask *bmp)
{
	if (!bmp)
		return;

	numa_free_nodemask(bmp);
}

void wd_get_version(void)
{
	const char *wd_released_time = UADK_RELEASED_TIME;
	const char *wd_version = UADK_VERSION_NUMBER;

	WD_CONSOLE("%s\n", wd_version);
	WD_CONSOLE("%s\n", wd_released_time);
}

bool wd_need_debug(void)
{
	switch (uadk_log_level) {
	case WD_LOG_NONE:
	case WD_LOG_ERROR:
	case WD_LOG_INFO:
		return false;
	case WD_LOG_DEBUG:
		return true;
	case WD_LOG_INVALID:
		wd_parse_log_level();
		return uadk_log_level >= WD_LOG_DEBUG;
	default:
		return false;
	}
}

bool wd_need_info(void)
{
	switch (uadk_log_level) {
	case WD_LOG_NONE:
	case WD_LOG_ERROR:
		return false;
	case WD_LOG_INFO:
	case WD_LOG_DEBUG:
		return true;
	case WD_LOG_INVALID:
		wd_parse_log_level();
		return uadk_log_level >= WD_LOG_INFO;
	default:
		return false;
	}
}

char *wd_ctx_get_dev_name(handle_t h_ctx)
{
	struct wd_ctx_h	*ctx = (struct wd_ctx_h *)h_ctx;

	if (!ctx)
		return NULL;

	return ctx->dev_name;
}

void wd_release_alg_cap(struct wd_capability *head)
{
	struct wd_capability *cap_pnext = head;
	struct wd_capability *cap_node;

	while (cap_pnext) {
		cap_node = cap_pnext;
		cap_pnext = cap_pnext->next;
		free(cap_node);
	}
}

struct wd_capability *wd_get_alg_cap(void)
{
	struct wd_alg_list *head = wd_get_alg_head();
	struct wd_alg_list *pnext = head->next;
	struct wd_capability *cap_head = NULL;
	struct wd_capability *cap_pnext = NULL;
	struct wd_capability *cap_node;

	while (pnext) {
		cap_node = calloc(1, sizeof(struct wd_capability));
		if (!cap_node) {
			WD_ERR("fail to alloc wd capability head\n");
			goto alloc_err;
		}

		(void)strcpy(cap_node->alg_name, pnext->alg_name);
		(void)strcpy(cap_node->drv_name, pnext->drv_name);
		cap_node->available = pnext->available;
		cap_node->priority = pnext->priority;
		cap_node->calc_type = pnext->calc_type;
		cap_node->next = NULL;

		pnext = pnext->next;
		if (!cap_pnext) {
			cap_head = cap_node;
			cap_pnext = cap_node;
		}
		cap_pnext->next = cap_node;
		cap_pnext = cap_node;
	}

	return cap_head;

alloc_err:
	wd_release_alg_cap(cap_head);
	return NULL;
}

static int wd_parse_usage_value(char *buf, const char *type_name)
{
	char *str;
	int ret;

	str = strstr(buf, type_name);
	if (!str)
		return -WD_EINVAL;

	str += strlen(type_name);
	ret = strtol(str, NULL, 10);
	if (ret < 0)
		WD_ERR("fail to get device usage value, ret %d!\n", ret);

	return ret;
}

/*
 * The format of the string obtained from sysfs is fixed
 * and does not need to consider other scenarios.
 */
static int wd_zip_usage_parse_fn(char *buf, const char *alg_name, __u8 alg_op_type)
{
	size_t size = ARRAY_SIZE(zip_dae_algs);
	size_t i;

	for (i = 0; i < size; i++) {
		if (!strcmp(alg_name, zip_dae_algs[i])) {
			if (alg_op_type != 0) {
				WD_ERR("invalid: alg_name %s alg_op_type error!\n", alg_name);
				return -WD_EINVAL;
			}
			return wd_parse_usage_value(buf, "DAE: ");
		}
	}

	if (alg_op_type == 0)
		return wd_parse_usage_value(buf, "COMPRESS: ");

	return wd_parse_usage_value(buf, "DECOMPRESS: ");
}

static int wd_sec_usage_parse_fn(char *buf, const char *alg_name, __u8 alg_op_type)
{
	return wd_parse_usage_value(buf, "SEC: ");
}

static int wd_hpre_usage_parse_fn(char *buf, const char *alg_name, __u8 alg_op_type)
{
	size_t size = ARRAY_SIZE(hpre_ecc_algs);
	size_t i;

	for (i = 0; i < size; i++) {
		if (!strcmp(alg_name, hpre_ecc_algs[i]))
			return wd_parse_usage_value(buf, "ECC: ");
	}

	return wd_parse_usage_value(buf, "RSA: ");
}

static const struct dev_usage_info dev_usage_parse[] = {
	{
		.dev_name = "hisi_zip",
		.alg_op_type = 2,
		.usage_parse_fn = wd_zip_usage_parse_fn
	 }, {
		.dev_name = "hisi_sec",
		.alg_op_type = 1,
		.usage_parse_fn = wd_sec_usage_parse_fn
	 }, {
		.dev_name = "hisi_hpre",
		.alg_op_type = 1,
		.usage_parse_fn = wd_hpre_usage_parse_fn
	 },
};

static int wd_parse_dev_usage(struct uacce_dev *dev, char *buf,
			      const char *alg_name, __u8 alg_op_type)
{
	size_t size = ARRAY_SIZE(dev_usage_parse);
	size_t i;

	for (i = 0; i < size; i++) {
		if (strstr(dev->dev_root, dev_usage_parse[i].dev_name))
			break;
	}

	if (i == size) {
		WD_ERR("failed to find parse function!\n");
		return -WD_EINVAL;
	}

	if (alg_op_type >= dev_usage_parse[i].alg_op_type) {
		WD_ERR("invalid: alg_op_type %u is error!\n", alg_op_type);
		return -WD_EINVAL;
	}

	return dev_usage_parse[i].usage_parse_fn(buf, alg_name, alg_op_type);
}

static int wd_read_dev_usage(struct uacce_dev *dev, const char *alg_name, __u8 alg_op_type)
{
	char buf[WD_DEV_USAGE_SIZE];
	int ret;

	ret = access_attr(dev->dev_root, "dev_usage", F_OK);
	if (ret) {
		WD_ERR("failed to access dev_usage!\n");
		return ret;
	}

	ret = get_str_attr(dev, "dev_usage", buf, WD_DEV_USAGE_SIZE);
	if (ret < 0)
		return ret;

	return wd_parse_dev_usage(dev, buf, alg_name, alg_op_type);
}

int wd_get_dev_usage(struct uacce_dev *dev, const char *alg_name, __u8 alg_op_type)
{
	if (!dev || !alg_name) {
		WD_ERR("invalid: dev or alg name is NULL!\n");
		return -WD_EINVAL;
	}

	if (!dev_has_alg(dev->algs, alg_name)) {
		WD_ERR("invalid: dev does not support alg %s!\n", alg_name);
		return -WD_EINVAL;
	}

	return wd_read_dev_usage(dev, alg_name, alg_op_type);
}
