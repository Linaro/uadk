/* SPDX-License-Identifier: Apache-2.0 */
//#include "config.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <sys/poll.h>

#include "wd.h"
#include "wd_adapter.h"

#define SYS_CLASS_DIR	"/sys/class"

unsigned int page_size = 0;
unsigned int page_shift = 0;

struct _dev_info {
	int node_id;
	int numa_dis;
	int iommu_type;
	int flags;
	int ref;
	int is_load;
	int available_instances;
	int weight;
	char alg_path[PATH_STR_SIZE];
	char dev_root[PATH_STR_SIZE];
	char name[WD_NAME_SIZE];
	char api[WD_NAME_SIZE];
	char algs[MAX_ATTR_STR_SIZE];
	unsigned long qfrs_pg_start[UACCE_QFRT_MAX];
};

static size_t _get_raw_attr(char *dev_root, char *attr, char *buf, size_t sz)
{
	char attr_file[PATH_STR_SIZE];
	int fd;
	size_t size;

	size = snprintf(attr_file, PATH_STR_SIZE, "%s/"UACCE_DEV_ATTRS"/%s",
			dev_root, attr);
	if (size < 0)
		return -EINVAL;

	fd = open(attr_file, O_RDONLY, 0);
	if (fd < 0) {
		WD_ERR("open %s fail!\n", attr_file);
		return fd;
	}
	size = read(fd, buf, sz);
	if (size <= 0) {
		WD_ERR("read nothing at %s!\n", attr_file);
		size = -ENODEV;
	}

	close(fd);
	return size;
}

static int _get_int_attr(struct _dev_info *dinfo, char *attr)
{
	size_t size;
	char buf[MAX_ATTR_STR_SIZE];

	size = _get_raw_attr(dinfo->dev_root, attr, buf, MAX_ATTR_STR_SIZE);
	if (size < 0)
		return size;

	return atoi((char *)&buf);
}

/*
 * Get string from an attr of sysfs. '\n' is used as a token of substring.
 * So '\n' could be in the middle of the string or at the last of the string.
 * Now remove the token '\n' at the end of the string to avoid confusion.
 */
static size_t _get_str_attr(struct _dev_info *dinfo, char *attr, char *buf,
			 size_t buf_sz)
{
	size_t size;

	size = _get_raw_attr(dinfo->dev_root, attr, buf, buf_sz);
	if (size < 0) {
		buf[0] = '\0';
		return size;
	}

	if (size == buf_sz)
		size = size - 1;

	buf[size] = '\0';
	while ((size > 1) && (buf[size - 1] == '\n')) {
		buf[size - 1] = '\0';
		size = size - 1;
	}
	return size;
}

static void _get_ul_vec_attr(struct _dev_info *dinfo, char *attr,
			       unsigned long *vec, int vec_sz)
{
	char buf[MAX_ATTR_STR_SIZE];
	int size, i, j;
	char *begin, *end;

	size = _get_raw_attr(dinfo->dev_root, attr, buf, MAX_ATTR_STR_SIZE);
	if (size < 0) {
		for (i = 0; i < vec_sz; i++)
			vec[i] = 0;
		return;
	}

	begin = buf;
	for (i = 0; i < vec_sz; i++) {
		vec[i] = strtoul(begin, &end, 0);
		if (!end)
			break;
		begin = end;
	}

	for (j = i; j < vec_sz; j++)
		vec[j] = 0;
}

static int _get_dev_info(struct _dev_info *dinfo)
{
	dinfo->numa_dis = _get_int_attr(dinfo, "numa_distance");
	dinfo->available_instances = _get_int_attr(dinfo,
						   "available_instances");
	dinfo->node_id = _get_int_attr(dinfo, "node_id");
	dinfo->flags = _get_int_attr(dinfo, "flags");
	_get_str_attr(dinfo, "api", dinfo->api, WD_NAME_SIZE);
	_get_str_attr(dinfo, "algorithms", dinfo->algs, MAX_ATTR_STR_SIZE);
	_get_ul_vec_attr(dinfo, "qfrs_pg_start", dinfo->qfrs_pg_start,
			   UACCE_QFRT_MAX);
	/*
	 * Use available_instances as the base of weight.
	 * Remote NUMA node cuts the weight.
	 */
	if (dinfo->available_instances > 0)
		dinfo->weight = dinfo->available_instances;
	else
		dinfo->weight = 0;
	/* Check whether it's the remote distance. */
	if (dinfo->numa_dis)
		dinfo->weight = dinfo->weight >> 2;

	return 0;
}

static bool _is_matched_alg(char *algs, char *alg)
{
	char *s;

	while ((s = strsep(&algs, "\n"))) {
		if (!strncmp(s, alg, strlen(s)))
			return 1;
	}
	return 0;
}

static void _copy_if_better(struct _dev_info *old, struct _dev_info *new,
			    struct wd_capa *capa)
{
	dbg("try accelerator %s (inst_num=%d)...", new->name,
	    new->available_instances);

	/* Does the new dev match the need? */
	if (new->available_instances <=0 ||
	    !_is_matched_alg(new->algs, capa->alg))
		goto out;

	/* todo: priority, latency, throughput and etc. check */

	/* Is the new dev better? */
	if (!old->name[0] || (new->weight > old->weight)) {
		memcpy(old, new, sizeof(*old));
		dbg("adopted\n");
		return;
	}

out:
	dbg("ignored\n");
}

static struct _dev_info *_find_available_res(struct wd_capa *capa, char *path)
{
	struct dirent *device;
	struct _dev_info dinfo, *dinfop = NULL;
	DIR *wd_class = NULL;
	const char *name;

	dinfop = calloc(1, sizeof(*dinfop));
	if (!dinfop) {
		WD_ERR("nomemory!\n");
		errno = -ENOMEM;
		goto err;
	}

	wd_class = opendir(SYS_CLASS_DIR"/"UACCE_CLASS_NAME);
	if (!wd_class) {
		WD_ERR("WD framework is not enabled on the system!\n");
		errno = -ENODEV;
		goto err_with_dinfop;
	}

	while ((device = readdir(wd_class)) != NULL) {
		name = device->d_name;
		if (!strncmp(name, ".", 1) || !strncmp(name, "..", 2))
			continue;

		(void)strncpy(dinfo.dev_root,
			      SYS_CLASS_DIR "/" UACCE_CLASS_NAME "/",
			      PATH_STR_SIZE - 1);
		(void)strncat(dinfo.dev_root, device->d_name, PATH_STR_SIZE - 1);
		(void)strncpy(dinfo.name, name, WD_NAME_SIZE - 1);
		if (!_get_dev_info(&dinfo)) {
			if (path && !strncmp(path, name, PATH_STR_SIZE)) {
				memcpy(dinfop, &dinfo, sizeof(dinfo));
				break;
			} else
				_copy_if_better(dinfop, &dinfo, capa);
		}
	}

	if (!dinfop->name[0]) {
		WD_ERR("Get no matching device!\n");
		errno = -ENODEV;
		goto err_with_dinfop;
	}

	closedir(wd_class);
	return dinfop;

err_with_dinfop:
	free(dinfop);
err:
	if (wd_class)
		closedir(wd_class);
	return NULL;
}

int wd_request_queue(struct wd_queue *q)
{
	int ret;
	struct _dev_info *dev;

	if(!page_size) {
		ret = get_page_size();
		if (ret)
			return ret;
	}

	dev = _find_available_res(&q->capa, q->dev_path);
	if (!dev) {
		dbg("cannot find available dev\n");
		return -ENODEV;
	}

	snprintf(q->dev_path, PATH_STR_SIZE, "%s/%s", "/dev", dev->name);
	q->fd = open(q->dev_path, O_RDWR | O_CLOEXEC);
	if (q->fd == -1) {
		dbg("fail to open %s\n", q->dev_path);
		ret = -ENODEV;
		goto err_with_dev;
	}
	q->hw_type = dev->api;
	q->dev_flags = dev->flags;
	q->dev_info = dev;
	memcpy(q->qfrs_pg_start, dev->qfrs_pg_start, sizeof(q->qfrs_pg_start));
	ret = drv_open(q);
	if (ret) {
		dbg("fail to init the queue by driver!\n");
		goto err_with_fd;
	}

	ret = ioctl(q->fd, UACCE_CMD_START);
	if (ret) {
		dbg("fail to start %s\n", q->dev_path);
		goto err_with_drv_openned;
	}

	return 0;

err_with_drv_openned:
	drv_close(q);
err_with_fd:
	close(q->fd);
err_with_dev:
	free(dev);
	return ret;
}

void wd_release_queue(struct wd_queue *q)
{
	drv_close(q);
	close(q->fd);
	free(q->dev_info);
}

int wd_send(struct wd_queue *q, void *req)
{
	return drv_send(q, req);
}

int wd_recv(struct wd_queue *q, void **resp)
{
	return drv_recv(q, resp);
}

static int wd_wait(struct wd_queue *q, __u16 ms)
{
	struct pollfd fds[1];
	int ret;

	fds[0].fd = q->fd;
	fds[0].events = POLLIN;
	ret = poll(fds, 1, ms);
	if (ret == -1)
		return -errno;

	return 0;
}

int wd_recv_sync(struct wd_queue *q, void **resp, __u16 ms)
{
	int ret;

	while (1) {
		ret = wd_recv(q, resp);
		if (ret == -EBUSY) {
			ret = wd_wait(q, ms);
			if (ret)
				return ret;
		} else
			return ret;
	}
}

void wd_flush(struct wd_queue *q)
{
	drv_flush(q);
}

void *wd_reserve_memory(struct wd_queue *q, size_t size)
{
	return drv_reserve_mem(q, size);
}

int wd_share_reserved_memory(struct wd_queue *q, struct wd_queue *target_q)
{
	return ioctl(q->fd, UACCE_CMD_SHARE_SVAS, target_q->fd);
}

