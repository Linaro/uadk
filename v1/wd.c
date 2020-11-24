// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
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
#include "wd_util.h"
#include "wd_adapter.h"

#define SYS_CLASS_DIR	"/sys/class"
#define LINUX_DEV_DIR	"/dev"
#define UACCE_CLASS_DIR SYS_CLASS_DIR"/"UACCE_CLASS_NAME
#define _TRY_REQUEST_TIMES		64
#define INT_MAX_SIZE			10
#define LINUX_CRTDIR_SIZE		1
#define LINUX_PRTDIR_SIZE		2

#ifdef WITH_LOG_FILE
FILE *flog_fd = NULL;
#endif

#define offsetof(t, m) ((size_t) &((t *)0)->m)
#define container_of(ptr, type, member) ({ \
		typeof(((type *)0)->member)(*__mptr) = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); })

struct dev_info {
	int node_id;
	int numa_dis;
	int flags;
	int ref;
	int available_instances;
	unsigned int weight;
	char dev_root[PATH_STR_SIZE];
	char name[WD_NAME_SIZE];
	char api[WD_NAME_SIZE];
	char algs[MAX_ATTR_STR_SIZE];
	unsigned long qfrs_offset[UACCE_QFRT_MAX];
};

static int get_raw_attr(const char *dev_root, const char *attr,
							char *buf, size_t sz)
{
	char attr_file[PATH_STR_SIZE];
	int fd;
	int size;

	size = snprintf(attr_file, PATH_STR_SIZE, "%s/"UACCE_DEV_ATTRS"/%s",
			dev_root, attr);
	if (size <= 0) {
		WD_ERR("get %s/%s path fail!\n", dev_root, attr);
		return size;
	}

	/* The attr_file = "/sys/class/uacce/attrs/xxx"
	 * It's the Internal Definition File Node
	 */
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

static int get_int_attr(struct dev_info *dinfo, const char *attr)
{
	int size;
	char buf[MAX_ATTR_STR_SIZE];

	/*
	 * The signed int max number is INT_MAX 10bit char "4294967295"
	 * When the value is begger than INT_MAX, it returns INT_MAX
	 */
	size = get_raw_attr(dinfo->dev_root, attr, buf, MAX_ATTR_STR_SIZE);
	if (size < 0 || size >= INT_MAX_SIZE)
		return size;
	/* Handing the read string's end tails '\n' to '\0' */
	buf[size] = '\0';
	return atoi((char *)buf);
}

/*
 * Get string from an attr of sysfs. '\n' is used as a token of substring.
 * So '\n' could be in the middle of the string or at the last of the string.
 * Now remove the token '\n' at the end of the string to avoid confusion.
 */
static int get_str_attr(struct dev_info *dinfo, const char *attr, char *buf,
			size_t buf_sz)
{
	int size;

	size = get_raw_attr(dinfo->dev_root, attr, buf, buf_sz);
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

static int get_ul_vec_attr(struct dev_info *dinfo, const char *attr,
			   unsigned long *vec, int vec_sz)
{
	char buf[MAX_ATTR_STR_SIZE];
	int size, i, j;
	char *begin, *end;

	size = get_raw_attr(dinfo->dev_root, attr, buf, MAX_ATTR_STR_SIZE);
	if (size < 0 || size >= MAX_ATTR_STR_SIZE) {
		for (i = 0; i < vec_sz; i++)
			vec[i] = 0;
		return size;
	}

	/*
	 * The unsigned long int max number is ULLONG_MAX 20bit
	 * char "18446744073709551615" When the value is
	 * bigger than ULLONG_MAX, It returns ULLONG_MAX
	 */
	buf[size] = '\0';
	begin = buf;
	for (i = 0; i < vec_sz; i++) {
		vec[i] = strtoul(begin, &end, 10);
		if (!end)
			break;
		begin = end;
	}

	for (j = i; j < vec_sz; j++)
		vec[j] = 0;

	return 0;
}

static int is_alg_support(struct dev_info *dinfo, const char *alg)
{
	int alg_support_flag = 0;
	char *alg_save = NULL;
	char *alg_tmp;

	alg_tmp = strtok_r(dinfo->algs, "\n", &alg_save);
	while (alg_tmp != NULL) {
		if (alg && !strcmp(alg_tmp, alg))
			alg_support_flag++;
		alg_tmp = strtok_r(NULL, "\n", &alg_save);
	}
	return  alg_support_flag;
}

static int get_dev_info(struct dev_info *dinfo, const char *alg)
{
	int ret;

	ret = get_int_attr(dinfo, "isolate");
	if (ret < 0 || ret == 1)
		return -ENODEV;

	ret = get_int_attr(dinfo, "dev_state");
	if (ret < 0)
		return ret;

	ret = get_str_attr(dinfo, "algorithms",
			    dinfo->algs, MAX_ATTR_STR_SIZE);
	if (ret < 0)
		return ret;

	/* Add ALG check to cut later pointless logic */
	ret = is_alg_support(dinfo, alg);
	if (ret == 0)
		return -ENODEV;
	ret = get_int_attr(dinfo, "available_instances");
	if (ret <= 0)
		return -ENODEV;
	dinfo->available_instances = ret;

	ret = get_int_attr(dinfo, "numa_distance");
	if (ret < 0)
		return ret;
	dinfo->numa_dis = ret;

	dinfo->node_id = get_int_attr(dinfo, "node_id");

	ret = get_int_attr(dinfo, "flags");
	if (ret < 0)
		return ret;
	dinfo->flags = ret;

	ret = get_str_attr(dinfo, "api", dinfo->api, WD_NAME_SIZE);
	if (ret < 0)
		return ret;

	ret = get_ul_vec_attr(dinfo, "qfrs_offset", dinfo->qfrs_offset,
			      UACCE_QFRT_MAX);
	if (ret < 0)
		return ret;

	/*
	 * Use available_instances as the base of weight.
	 * Remote NUMA node cuts the weight.
	 */
	dinfo->weight = dinfo->available_instances;

	/* Check whether it's the remote distance. */
	if (dinfo->numa_dis)
		dinfo->weight = dinfo->weight >> 2;

	return 0;
}

static void copy_if_better(struct dev_info *old, struct dev_info *new,
			    struct wd_capa *capa)
{
	dbg("try accelerator %s (inst_num=%d)...", new->name,
	    new->available_instances);

	/* Is the new dev better? */
	if (old && (!old->name[0] || (new->weight > old->weight))) {
		memcpy(old, new, sizeof(*old));
		dbg("adopted\n");
		return;
	}
}

static void pre_init_dev(struct dev_info *dinfo, const char *name)
{
	int ret;

	ret = snprintf(dinfo->name, WD_NAME_SIZE, "%s", name);
	if (ret < 0) {
		WD_ERR("get file name fail!\n");
		return;
	}

	ret = snprintf(dinfo->dev_root, PATH_STR_SIZE,
		       "%s/%s", UACCE_CLASS_DIR, name);
	if (ret < 0) {
		WD_ERR("get uacce file path fail!\n");
		return;
	}
}

static int get_denoted_dev(struct wd_capa *capa, const char *dev,
				struct dev_info *dinfop)
{
	pre_init_dev(dinfop, dev);
	if (!get_dev_info(dinfop, capa->alg))
		return 0;
	WD_ERR("fail to get dev %s!\n", dev);
	return -ENODEV;
}

static int find_available_dev(struct dev_info *dinfop, struct wd_capa *capa)
{
	struct dirent *device;
	DIR *wd_class = NULL;
	struct dev_info dinfo;
	char *name;
	int cnt = 0;

	wd_class = opendir(UACCE_CLASS_DIR);
	if (!wd_class) {
		WD_ERR("WD framework is not enabled on the system!\n");
		return -ENODEV;
	}

	while (true) {
		device = readdir(wd_class);
		if (!device)
			break;
		name = device->d_name;
		if (!strncmp(name, ".", LINUX_CRTDIR_SIZE) ||
			!strncmp(name, "..", LINUX_PRTDIR_SIZE))
			continue;
		pre_init_dev(&dinfo, name);
		if (!get_dev_info(&dinfo, capa->alg)) {
			copy_if_better(dinfop, &dinfo, capa);
			cnt++;
		}
	}
	closedir(wd_class);
	return cnt;
}

static int find_available_res(struct wd_queue *q, struct dev_info *dinfop,
						int *num)
{
	struct wd_capa *capa = &q->capa;
	const char *dev = q->dev_path;
	int ret;

	/* As user denotes a device */
	if (dev && dev[0] && dev[0] != '/' && !strstr(dev, "../")) {
		if (!dinfop) {
			WD_ERR("dinfop NULL!\n");
			return -EINVAL;
		}
		if (!get_denoted_dev(capa, dev, dinfop))
			goto dev_path;
	}

	ret = find_available_dev(dinfop, capa);
	if (ret <= 0 && dinfop) {
		WD_ERR("get /%s path fail!\n", dinfop->name);
		return -ENODEV;
	}

	if (num) {
		*num = ret;
		return 0;
	}

dev_path:
	if (!dinfop) {
		WD_ERR("dinfop NULL!\n");
		return -EINVAL;
	}

	ret = snprintf(q->dev_path, PATH_STR_SIZE, "%s/%s",
						LINUX_DEV_DIR, dinfop->name);
	if (ret <= 0) {
		WD_ERR("snprintf err, ret %d!\n", ret);
		return -EINVAL;
	}
	return 0;
}

static int get_queue_from_dev(struct wd_queue *q, const struct dev_info *dev)
{
	struct q_info *qinfo;

	qinfo = q->info;
	qinfo->fd = open(q->dev_path, O_RDWR | O_CLOEXEC);
	if (qinfo->fd == -1) {
		qinfo->fd = 0;
		return -ENODEV;
	}

	qinfo->hw_type = dev->api;
	qinfo->dev_flags = dev->flags;
	qinfo->dev_info = dev;
	qinfo->head = &qinfo->ss_list;
	__atomic_clear(&qinfo->ref, __ATOMIC_RELEASE);
	TAILQ_INIT(&qinfo->ss_list);
	memcpy(qinfo->qfrs_offset, dev->qfrs_offset,
				sizeof(qinfo->qfrs_offset));

	return 0;
}
static int wd_start_queue(struct wd_queue *q)
{
	int ret;
	struct q_info *qinfo = q->info;

	ret = ioctl(qinfo->fd, UACCE_CMD_START);
	if (ret)
		WD_ERR("fail to start queue of %s\n", q->dev_path);
	return ret;
}
static void wd_close_queue(struct wd_queue *q)
{
	struct q_info *qinfo = q->info;

	close(qinfo->fd);
}

int wd_request_queue(struct wd_queue *q)
{
	struct dev_info *dinfop;
	int ret, try_cnt = 0;

	if (!q) {
		WD_ERR("input param q is NULL!\n");
		return -EINVAL;
	}
	dinfop = calloc(1, sizeof(struct q_info) + sizeof(*dinfop));
	if (!dinfop) {
		WD_ERR("calloc for queue info fail!\n");
		return -ENOMEM;
	};
	q->info = dinfop + 1;
try_again:
	ret = find_available_res(q, dinfop, NULL);
	if (ret) {
		WD_ERR("cannot find available dev\n");
		goto err_with_dev;
	}
	ret = get_queue_from_dev(q, (const struct dev_info *)dinfop);
	if (ret == -ENODEV) {
		try_cnt++;
		if (try_cnt < _TRY_REQUEST_TIMES) {
			memset(dinfop, 0, sizeof(*dinfop));
			goto try_again;
		}
		WD_ERR("fail to get queue!\n");
		goto err_with_fd;
	}
	ret = drv_open(q);
	if (ret) {
		WD_ERR("fail to init the queue by driver!\n");
		goto err_with_fd;
	}
	ret = wd_start_queue(q);
	if (ret)
		goto err_with_drv_openned;
	return ret;
err_with_drv_openned:
	drv_close(q);
err_with_fd:
	wd_close_queue(q);
err_with_dev:
	free(dinfop);
	return ret;
}

void wd_release_queue(struct wd_queue *q)
{
	struct wd_ss_region *rg;
	struct wd_ss_region_list *head;
	struct q_info *qinfo, *sqinfo;

	if (!q || !q->info) {
		WD_ERR("release queue param error!\n");
		return;
	}
	qinfo = q->info;
	if (__atomic_load_n(&qinfo->ref, __ATOMIC_RELAXED)) {
		WD_ERR("q(%s) is busy, release fail!\n", q->capa.alg);
		return;
	}
	head = qinfo->head;
	sqinfo = container_of(head, struct q_info, ss_list);
	if (sqinfo != qinfo) /* q_share */
		__atomic_sub_fetch(&sqinfo->ref, 1, __ATOMIC_RELAXED);

	/* q_reserve */
	if (qinfo->ss_size)
		drv_unmap_reserve_mem(q, qinfo->ss_va, qinfo->ss_size);

	while (true) {
		rg = TAILQ_FIRST(&qinfo->ss_list);
		if (!rg)
			break;
		TAILQ_REMOVE(&qinfo->ss_list, rg, next);
		free(rg);
	}

	drv_close(q);
	if (ioctl(qinfo->fd, UACCE_CMD_PUT_Q)) {
		WD_ERR("fail to put queue!\n");
		return;
	}
	wd_close_queue(q);
	free((void *)qinfo->dev_info);
	qinfo->dev_info = NULL;
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
	struct q_info *qinfo = q->info;
	struct pollfd fds[1];
	int ret;

	fds[0].fd = qinfo->fd;
	fds[0].events = POLLIN;
	ret = poll(fds, 1, ms);
	if (ret == -1)
		return -ENODEV;

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

void *wd_reserve_memory(struct wd_queue *q, size_t size)
{
	return drv_reserve_mem(q, size);
}

int wd_share_reserved_memory(struct wd_queue *q,
			struct wd_queue *target_q)
{
	int ret;
	struct q_info *qinfo = q->info, *tqinfo = target_q->info;
	const struct dev_info *info = qinfo->dev_info;
	const struct dev_info *tgt_info = tqinfo->dev_info;

	if (((qinfo->dev_flags & UACCE_DEV_NOIOMMU) &&
		!(tqinfo->dev_flags & UACCE_DEV_NOIOMMU)) ||
		(!(qinfo->dev_flags & UACCE_DEV_NOIOMMU) &&
		(tqinfo->dev_flags & UACCE_DEV_NOIOMMU))) {
		WD_ERR("IOMMU type mismatching as share mem!\n");
		return -EINVAL;
	}
	if (info->node_id != tgt_info->node_id)
		WD_ERR("Warn: the 2 queues is not at the same node!\n");

	ret = ioctl(qinfo->fd, UACCE_CMD_SHARE_SVAS, tqinfo->fd);
	if (ret) {
		WD_ERR("ioctl share dma memory fail!\n");
		return ret;
	}

	/* Just share DMA mem from 'q' in NO-IOMMU mode */
	if (qinfo->dev_flags & UACCE_DEV_NOIOMMU)
		tqinfo->head = qinfo->head;

	__atomic_add_fetch(&qinfo->ref, 1, __ATOMIC_RELAXED);

	return 0;
}

int wd_get_available_dev_num(const char *algorithm)
{
	struct wd_queue q;
	int num = 0, ret;

	memset(&q, 0, sizeof(q));
	q.capa.alg = algorithm;
	q.dev_path[0] = 0;
	ret = find_available_res(&q, NULL, &num);
	if (ret < 0)
		WD_ERR("find_available_res err, ret %d!\n", ret);
	return num;
}

int wd_get_node_id(struct wd_queue *q)
{
	struct q_info *qinfo = q->info;
	const struct dev_info *dev = qinfo->dev_info;

	return dev->node_id;
}

void *wd_dma_map(struct wd_queue *q, void *va, size_t sz)
{
	struct q_info *qinfo = q->info;
	struct wd_ss_region *rgn;

	TAILQ_FOREACH(rgn, qinfo->head, next) {
		if (rgn->va <= va && va < rgn->va + rgn->size)
			return (void *)(uintptr_t)(rgn->pa +
				((uintptr_t)va - (uintptr_t)rgn->va));
	}

	return NULL;
}

void wd_dma_unmap(struct wd_queue *q, void *va, void *dma, size_t sz)
{
	/* For no-iommu, dma-unmap doing nothing */
}

void *wd_dma_to_va(struct wd_queue *q, void *dma)
{
	struct wd_ss_region *rgn;
	struct q_info *qinfo = q->info;
	uintptr_t va;

	TAILQ_FOREACH(rgn, qinfo->head, next) {
		if (rgn->pa <= (uintptr_t)dma &&
			(uintptr_t)dma < rgn->pa + rgn->size) {
			va = (uintptr_t)dma - rgn->pa + (uintptr_t)rgn->va;
			return (void *)va;
		}
	}

	return NULL;
}

void *wd_drv_mmap_qfr(struct wd_queue *q, enum uacce_qfrt qfrt,
				    enum uacce_qfrt qfrt_next, size_t size)
{
	struct q_info *qinfo = q->info;
	off_t off;
	void *ptr;

	off = qinfo->qfrs_offset[qfrt];

	if (qfrt_next != UACCE_QFRT_INVALID)
		size = qinfo->qfrs_offset[qfrt_next] - qinfo->qfrs_offset[qfrt];

	ptr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, qinfo->fd, off);
	return ptr;
}

void wd_drv_unmmap_qfr(struct wd_queue *q, void *addr,
				     enum uacce_qfrt qfrt,
				     enum uacce_qfrt qfrt_next, size_t size)
{
	struct q_info *qinfo = q->info;

	if (!addr)
		return;
	if (qfrt_next != UACCE_QFRT_INVALID)
		size = qinfo->qfrs_offset[qfrt_next] - qinfo->qfrs_offset[qfrt];
	munmap(addr, size);
}
