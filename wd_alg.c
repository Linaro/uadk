/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/auxv.h>

#include "wd.h"
#include "wd_alg.h"

#define SYS_CLASS_DIR			"/sys/class/uacce"
#define SVA_FILE_NAME			"flags"
#define DEV_SVA_SIZE		32
#define STR_DECIMAL		0xA

static struct wd_alg_list alg_list_head;
static struct wd_alg_list *alg_list_tail = &alg_list_head;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static bool wd_check_dev_sva(const char *dev_name)
{
	char dev_path[PATH_MAX] = {'\0'};
	char buf[DEV_SVA_SIZE] = {'\0'};
	unsigned int val;
	ssize_t ret;
	int fd;

	ret = snprintf(dev_path, PATH_STR_SIZE, "%s/%s/%s", SYS_CLASS_DIR,
			  dev_name, SVA_FILE_NAME);
	if (ret < 0) {
		WD_ERR("failed to snprintf, device name: %s!\n", dev_name);
		return false;
	}

	/**
	 * The opened file is the specified device driver file.
	 * no need for realpath processing.
	 */
	fd = open(dev_path, O_RDONLY, 0);
	if (fd < 0) {
		WD_ERR("failed to open %s(%d)!\n", dev_path, -errno);
		return false;
	}

	ret = read(fd, buf, DEV_SVA_SIZE - 1);
	if (ret <= 0) {
		WD_ERR("failed to read anything at %s!\n", dev_path);
		close(fd);
		return false;
	}
	close(fd);

	val = strtol(buf, NULL, STR_DECIMAL);
	if (val & UACCE_DEV_SVA)
		return true;

	return false;
}

static bool wd_check_accel_dev(const char *dev_name)
{
	struct dirent *dev_dir;
	DIR *wd_class;

	wd_class = opendir(SYS_CLASS_DIR);
	if (!wd_class) {
		WD_ERR("UADK framework isn't enabled in system!\n");
		return false;
	}

	while ((dev_dir = readdir(wd_class)) != NULL) {
		if (!strncmp(dev_dir->d_name, ".", LINUX_CRTDIR_SIZE) ||
		     !strncmp(dev_dir->d_name, "..", LINUX_PRTDIR_SIZE))
			continue;

		if (!strncmp(dev_dir->d_name, dev_name, strlen(dev_name)) &&
		     wd_check_dev_sva(dev_dir->d_name)) {
			closedir(wd_class);
			return true;
		}
	}
	closedir(wd_class);

	return false;
}

static bool wd_check_ce_support(const char *dev_name)
{
	unsigned long hwcaps = 0;

	#if defined(__arm__) || defined(__arm)
		hwcaps = getauxval(AT_HWCAP2);
	#elif defined(__aarch64__)
		hwcaps = getauxval(AT_HWCAP);
	#endif
	if (!strcmp("isa_ce_sm3", dev_name) && (hwcaps & HWCAP_CE_SM3))
		return true;

	if (!strcmp("isa_ce_sm4", dev_name) && (hwcaps & HWCAP_CE_SM4))
		return true;

	return false;
}

static bool wd_check_sve_support(void)
{
	unsigned long hwcaps = 0;

	#if defined(__aarch64__)
		hwcaps = getauxval(AT_HWCAP);
	#endif
	if (hwcaps & HWCAP_SVE)
		return true;

	return false;
}

static bool wd_alg_check_available(int calc_type, const char *dev_name)
{
	bool ret = false;

	switch (calc_type) {
	case UADK_ALG_SOFT:
		break;
	/* Should find the CPU if not support CE */
	case UADK_ALG_CE_INSTR:
		ret = wd_check_ce_support(dev_name);
		break;
	/* Should find the CPU if not support SVE */
	case UADK_ALG_SVE_INSTR:
		ret = wd_check_sve_support();
		break;
	/* Check if the current driver has device support */
	case UADK_ALG_HW:
		ret = wd_check_accel_dev(dev_name);
		break;
	}

	return ret;
}

static bool wd_alg_driver_match(struct wd_alg_driver *drv,
	struct wd_alg_list *node)
{
	if (strcmp(drv->alg_name, node->alg_name))
		return false;

	if (strcmp(drv->drv_name, node->drv_name))
		return false;

	if (drv->priority != node->priority)
		return false;

	if (drv->calc_type != node->calc_type)
		return false;

	return true;
}

static bool wd_alg_repeat_check(struct wd_alg_driver *drv)
{
	struct wd_alg_list *npre = &alg_list_head;
	struct wd_alg_list *pnext = NULL;

	pthread_mutex_lock(&mutex);
	pnext = npre->next;
	while (pnext) {
		if (wd_alg_driver_match(drv, pnext)) {
			pthread_mutex_unlock(&mutex);
			return true;
		}
		npre = pnext;
		pnext = pnext->next;
	}
	pthread_mutex_unlock(&mutex);

	return false;
}

int wd_alg_driver_register(struct wd_alg_driver *drv)
{
	struct wd_alg_list *new_alg;

	if (!drv) {
		WD_ERR("invalid: register drv is NULL!\n");
		return -WD_EINVAL;
	}

	if (!drv->init || !drv->exit || !drv->send || !drv->recv) {
		WD_ERR("invalid: driver's parameter is NULL!\n");
		return -WD_EINVAL;
	}

	if (wd_alg_repeat_check(drv))
		return 0;

	new_alg = calloc(1, sizeof(struct wd_alg_list));
	if (!new_alg) {
		WD_ERR("failed to alloc alg driver memory!\n");
		return -WD_ENOMEM;
	}

	strncpy(new_alg->alg_name, drv->alg_name, ALG_NAME_SIZE - 1);
	strncpy(new_alg->drv_name, drv->drv_name, DEV_NAME_LEN - 1);
	new_alg->priority = drv->priority;
	new_alg->calc_type = drv->calc_type;
	new_alg->drv = drv;
	new_alg->refcnt = 0;
	new_alg->next = NULL;

	new_alg->available = wd_alg_check_available(drv->calc_type, drv->drv_name);
	if (!new_alg->available) {
		free(new_alg);
		return -WD_ENODEV;
	}

	pthread_mutex_lock(&mutex);
	alg_list_tail->next = new_alg;
	alg_list_tail = new_alg;
	pthread_mutex_unlock(&mutex);

	return 0;
}

void wd_alg_driver_unregister(struct wd_alg_driver *drv)
{
	struct wd_alg_list *npre = &alg_list_head;
	struct wd_alg_list *pnext = npre->next;

	/* Alg driver list has no drivers */
	if (!pnext || !drv)
		return;

	pthread_mutex_lock(&mutex);
	while (pnext) {
		if (wd_alg_driver_match(drv, pnext))
			break;
		npre = pnext;
		pnext = pnext->next;
	}

	/* The current algorithm is not registered */
	if (!pnext) {
		pthread_mutex_unlock(&mutex);
		return;
	}

	/* Used to locate the problem and ensure symmetrical use driver */
	if (pnext->refcnt > 0)
		WD_ERR("driver<%s> still in used: %d\n", pnext->drv_name, pnext->refcnt);

	if (pnext == alg_list_tail)
		alg_list_tail = npre;

	npre->next = pnext->next;
	free(pnext);
	pthread_mutex_unlock(&mutex);
}

struct wd_alg_list *wd_get_alg_head(void)
{
	return &alg_list_head;
}

bool wd_drv_alg_support(const char *alg_name,
			struct wd_alg_driver *drv)
{
	struct wd_alg_list *head = &alg_list_head;
	struct wd_alg_list *pnext = head->next;

	if (!alg_name || !drv)
		return false;

	while (pnext) {
		if (!strcmp(alg_name, pnext->alg_name) &&
		     !strcmp(drv->drv_name, pnext->drv_name)) {
			return true;
		}
		pnext = pnext->next;
	}

	return false;
}

void wd_enable_drv(struct wd_alg_driver *drv)
{
	struct wd_alg_list *head = &alg_list_head;
	struct wd_alg_list *pnext = head->next;

	if (!pnext || !drv)
		return;

	pthread_mutex_lock(&mutex);
	while (pnext) {
		if (wd_alg_driver_match(drv, pnext))
			break;
		pnext = pnext->next;
	}

	if (pnext)
		pnext->available = wd_alg_check_available(drv->calc_type, drv->drv_name);
	pthread_mutex_unlock(&mutex);
}

void wd_disable_drv(struct wd_alg_driver *drv)
{
	struct wd_alg_list *head = &alg_list_head;
	struct wd_alg_list *pnext = head->next;

	if (!pnext || !drv)
		return;

	pthread_mutex_lock(&mutex);
	while (pnext) {
		if (wd_alg_driver_match(drv, pnext) && pnext->available)
			break;
		pnext = pnext->next;
	}

	if (pnext)
		pnext->available = false;
	pthread_mutex_unlock(&mutex);
}

struct wd_alg_driver *wd_request_drv(const char *alg_name, bool hw_mask)
{
	struct wd_alg_list *head = &alg_list_head;
	struct wd_alg_list *pnext = head->next;
	struct wd_alg_list *select_node = NULL;
	struct wd_alg_driver *drv = NULL;
	int tmp_priority = -1;

	if (!pnext) {
		WD_ERR("invalid: requset drv pnext is NULL!\n");
		return NULL;
	}

	if (!alg_name) {
		WD_ERR("invalid: alg_name is NULL!\n");
		return NULL;
	}

	/* Check the list to get an best driver */
	pthread_mutex_lock(&mutex);
	while (pnext) {
		/* hw_mask true mean not to used hardware dev */
		if ((hw_mask && pnext->drv->calc_type == UADK_ALG_HW) ||
		    (!hw_mask && pnext->drv->calc_type != UADK_ALG_HW)) {
			pnext = pnext->next;
			continue;
		}

		if (!strcmp(alg_name, pnext->alg_name) && pnext->available &&
		    pnext->drv->priority > tmp_priority) {
			tmp_priority = pnext->drv->priority;
			select_node = pnext;
			drv = pnext->drv;
		}
		pnext = pnext->next;
	}

	if (select_node)
		select_node->refcnt++;
	pthread_mutex_unlock(&mutex);

	return drv;
}

void wd_release_drv(struct wd_alg_driver *drv)
{
	struct wd_alg_list *head = &alg_list_head;
	struct wd_alg_list *pnext = head->next;
	struct wd_alg_list *select_node = NULL;

	if (!pnext || !drv)
		return;

	pthread_mutex_lock(&mutex);
	while (pnext) {
		if (wd_alg_driver_match(drv, pnext) && pnext->refcnt > 0) {
			select_node = pnext;
			break;
		}
		pnext = pnext->next;
	}

	if (select_node)
		select_node->refcnt--;
	pthread_mutex_unlock(&mutex);
}

struct wd_alg_driver *wd_find_drv(char *drv_name, char *alg_name, int idx)
{
	struct wd_alg_list *head = &alg_list_head;
	struct wd_alg_list *pnext = head->next;
	struct wd_alg_driver *drv = NULL;

	if (!pnext || !alg_name) {
		WD_ERR("invalid: request alg param is error!\n");
		return NULL;
	}

	pthread_mutex_lock(&mutex);

	if (drv_name) {
		while (pnext) {
			if (!strcmp(alg_name, pnext->alg_name) &&
			    !strcmp(drv_name, pnext->drv_name)) {
				drv = pnext->drv;
				break;
			}
			pnext = pnext->next;
		}
	} else {
		int i = 0;

		while (pnext) {
			if (!strcmp(alg_name, pnext->alg_name)) {
				if (i++ == idx) {
					drv = pnext->drv;
					break;
				}
			}
			pnext = pnext->next;
		}
	}

	pthread_mutex_unlock(&mutex);

	return drv;
}
