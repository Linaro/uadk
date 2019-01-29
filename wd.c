/* SPDX-License-Identifier: Apache-2.0 */
//#include "config.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
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
#define MAX_MATCH_DEV	4
#define ALG_STR_SIZE	32

struct _alg_info;

struct _dev_info {
	int node_id;
	int numa_dis;
	int iommu_type;
	int flags;
	int ref;
	int is_load;
	int available_instances;
	char alg_path[PATH_STR_SIZE];
	char dev_root[PATH_STR_SIZE];
	char name[WD_NAME_SIZE];
	char api[WD_NAME_SIZE];
	DIR *class;
	struct _alg_info *alg_list;
	unsigned long qfrs_pg_start[UACCE_QFRT_MAX];
	TAILQ_ENTRY(_dev_info) next;
};

struct _alg_info {
	int type;
	struct wd_capa capa;
	char alg_root[PATH_STR_SIZE];
	char name[WD_NAME_SIZE];
	struct _dev_info *dinfo;
	struct _alg_info *next;
};

TAILQ_HEAD(wd_dev_list, _dev_info);
static struct wd_dev_list wd_dev_cache_list =
	TAILQ_HEAD_INITIALIZER(wd_dev_cache_list);

static DIR *_get_wd_class(void)
{
	struct _dev_info *dinfo;

	dinfo = TAILQ_FIRST(&wd_dev_cache_list);
	if (dinfo)
		return dinfo->class;

	return  opendir(SYS_CLASS_DIR"/"UACCE_CLASS_NAME);
}

static void _put_wd_class(DIR * class)
{
	seekdir(class, 0);
	if (TAILQ_EMPTY(&wd_dev_cache_list) && class)
		closedir(class);
}

static int _alg_param_check(struct _alg_info *ainfo, struct wd_capa *capa)
{
	return 0;/* to be fixed */
}

static int _capa_check(struct _alg_info *ainfo, struct wd_capa *capa)
{
	struct wd_capa *alg_capa = &ainfo->capa;

	if (strncmp(ainfo->name, capa->alg, strlen(capa->alg)))
		return -ENODEV;
	if (capa->latency > 0) {
		if (alg_capa->latency <= 0 ||
		    alg_capa->latency > capa->latency)
			return -ENODEV;
	}
	if (capa->throughput > 0) {
		if (alg_capa->throughput <= 0 ||
		    alg_capa->throughput < capa->throughput)
			return -ENODEV;
	}
	return _alg_param_check(ainfo, capa);
}

static void _add_alg(struct _alg_info *ainfo, struct _dev_info *dinfo)
{
	struct _alg_info *alg_list = dinfo->alg_list;

	dinfo->alg_list = ainfo;
	ainfo->next = alg_list;
}

static struct _dev_info *_get_cache_dev(const char *dev_name)
{
	struct _dev_info *dinfo;

	TAILQ_FOREACH(dinfo, &wd_dev_cache_list, next) {
		if (strncmp(dinfo->name, dev_name, strlen(dev_name)))
			continue;
		return dinfo;
	}
	return NULL;
}

/*
 * Query devices that match the algorithm. All matched devices are stored in
 * adev[].
 */
static int _get_alg_cache_dev(struct wd_capa *capa, struct _dev_info **adev)
{
	struct _dev_info *dinfo;
	struct _alg_info *alg;
	int cnt = 0;

	TAILQ_FOREACH(dinfo, &wd_dev_cache_list, next) {
		alg = dinfo->alg_list;
		for (; (cnt < MAX_MATCH_DEV) && alg && capa; alg = alg->next) {
			if (_capa_check(alg, capa) < 0) {
				continue;
			}
			adev[cnt++] = dinfo;
		}
	}
	return cnt;
}

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

static size_t _get_str_attr(struct _dev_info *dinfo, char *attr, char *buf,
			 size_t buf_sz)
{
	size_t size;

	size = _get_raw_attr(dinfo->dev_root, attr, buf, buf_sz);
	if (size < 0) {
		buf[0] = '\0';
		return size;
	}
	buf[size - 1] = '\0'; /* remove the last "\n" */
	if (size > 1 && buf[size-2]=='\n')
		buf[size - 2] = '\0';
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
	_get_ul_vec_attr(dinfo, "qfrs_pg_start", dinfo->qfrs_pg_start,
			   UACCE_QFRT_MAX);

	return 0;
}

static int _get_alg_info(struct _dev_info *dinfo, struct wd_capa *capa)
{
	char *alg_file = dinfo->alg_path;
	char alg_info[PATH_STR_SIZE];
	char alg[ALG_STR_SIZE];
	int alg_fd;
	size_t info_size;
	struct _alg_info *ainfo = NULL;
	char *sect, *d_alg;

	if (!strstr(alg_file, UACCE_CLASS_NAME)) {
		strncpy(alg_file, dinfo->dev_root, PATH_STR_SIZE);
		strcat(alg_file, "/attrs/algorithms");
	}
	alg_fd = open(alg_file, O_RDONLY, 0);
	if (alg_fd < 0) {
		WD_ERR("open %s fail!\n", alg_file);
		return alg_fd;
	}
	info_size = read(alg_fd, alg_info, PATH_STR_SIZE);
	if (info_size <= 0) {
		WD_ERR("read nothing at %s!\n", alg_file);
		return -ENODEV;
	}
	d_alg = strstr(alg_info, capa->alg);
	if (!d_alg)
		return -ENODEV;
	memcpy(alg, d_alg, ALG_STR_SIZE);
	sect = strstr(alg, "\n");
	if (!sect) {
		WD_ERR("ALG %s description is too long!\n", capa->alg);
		return -ENODEV;
	}
	sect = '\0';
	ainfo = malloc(sizeof(*ainfo));
	memset((void *)ainfo, 0, sizeof(*ainfo));
	strcpy(ainfo->name, alg);
	ainfo->dinfo = dinfo;
	if (_capa_check(ainfo, capa)) {
		close(alg_fd);
		free(ainfo);
		return -ENODEV;
	}
	_add_alg(ainfo, dinfo);
	close(alg_fd);

	return 0;
}

static int _filter_out_match_ones(const char *name, struct _dev_info **adev)
{
	int i;

	for (i = 0; adev[i] && i < MAX_MATCH_DEV; i++) {
		if (!strncmp(name, adev[i]->name, strlen(name)))
			return 0;
	}

	return -ENODEV;
}

static int _find_available_res(struct wd_capa *capa, struct _dev_info **adev)
{
	struct dirent *device;
	struct _dev_info *dinfo = NULL, *dev;
	DIR *wd_class;
	int dev_cnt = 0;
	const char *name;

	dev_cnt = _get_alg_cache_dev(capa, adev);
	if (dev_cnt == MAX_MATCH_DEV)
		return dev_cnt;
	wd_class = _get_wd_class();
	if (!wd_class) {
		WD_ERR("WD framework is not enabled on the system!\n");
		return -ENODEV;
	}

	while ((device = readdir(wd_class)) != NULL) {
		name = device->d_name;
		if (!strncmp(name, ".", 1) || !strncmp(name, "..", 2))
			continue;
		if (!_filter_out_match_ones(name, adev))
			continue;
		dinfo = _get_cache_dev(name);
		if (dinfo) {
			if (_get_alg_info(dinfo, capa) < 0)
				continue;
			adev[dev_cnt] = dinfo;
			dev_cnt++;
			if (dev_cnt == MAX_MATCH_DEV)
				break;
		}
		if (!dinfo) {
			dinfo = malloc(sizeof(*dinfo));
			if (!dinfo) {
				_put_wd_class(wd_class);
				return dev_cnt;
			}
		}
		memset((void *)dinfo, 0, sizeof(*dinfo));
		(void)strncpy(dinfo->dev_root,
		SYS_CLASS_DIR"/"UACCE_CLASS_NAME"/", PATH_STR_SIZE);
		(void)strcat(dinfo->dev_root, device->d_name);
		if (_get_dev_info(dinfo) < 0)
			continue;
		if (dinfo->available_instances <=0)
			continue;
		strncpy(dinfo->name, device->d_name, WD_NAME_SIZE);
		if (_get_alg_info(dinfo, capa) < 0)
			continue;
		dinfo->class = wd_class;
		adev[dev_cnt] = dinfo;
		if (TAILQ_EMPTY(&wd_dev_cache_list)) {
			TAILQ_INSERT_TAIL(&wd_dev_cache_list, dinfo, next);
			dinfo = NULL;
		} else {
			TAILQ_FOREACH(dev, &wd_dev_cache_list, next) {
				if (dinfo->numa_dis > dev->numa_dis &&
				     TAILQ_NEXT(dev, next)) {
					continue;
				} else if (dinfo->numa_dis <= dev->numa_dis) {
					TAILQ_INSERT_BEFORE(dev, dinfo, next);
					dinfo = NULL;
					break;
				}
				TAILQ_INSERT_AFTER(&wd_dev_cache_list,
						      dev, dinfo, next);
				dinfo = NULL;
				break;
			}
		}
		dev_cnt++;
		if (dev_cnt == MAX_MATCH_DEV)
			break;
	}
	if (dinfo)
		free(dinfo);
	_put_wd_class(wd_class);
	return dev_cnt;
}

int wd_request_queue(struct wd_queue *q)
{
	int ret, dev_cnt, i = 0;
	struct _dev_info *dev_list[MAX_MATCH_DEV];

	memset(dev_list, 0, sizeof(dev_list));
	dev_cnt = _find_available_res(&q->capa, dev_list);
	if (dev_cnt <= 0 || dev_cnt > MAX_MATCH_DEV)
		return -ENODEV;
retry_next_dev:
	snprintf(q->dev_path, PATH_STR_SIZE, "%s/%s",
		"/dev", dev_list[i]->name);
	q->fd = open(q->dev_path, O_RDWR | O_CLOEXEC);
	if (q->fd == -1)
		return -ENODEV;
	q->hw_type = dev_list[i]->api;
	q->dev_flags = dev_list[i]->flags;
	ret = drv_open(q);
	if (ret) {
		i++;
		if (i < dev_cnt)
			goto retry_next_dev;
		goto err_with_fd;
	}

	ret = ioctl(q->fd, UACCE_CMD_START);
	if (ret)
		goto err_with_drv_openned;

	return 0;

err_with_drv_openned:
	drv_close(q);
err_with_fd:
	close(q->fd);
	return ret;
}

void wd_release_queue(struct wd_queue *q)
{
	drv_close(q);
	close(q->fd);
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

