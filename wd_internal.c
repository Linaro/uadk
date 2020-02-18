/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <dirent.h>

#include "wd_internal.h"

#define SYS_CLASS_DIR		"/sys/class/uacce"

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

struct uacce_dev_info *read_uacce_sysfs(char *dev_name)
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
