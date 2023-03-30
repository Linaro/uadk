/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "wd.h"
#include "wd_alg.h"

#define SYS_CLASS_DIR			"/sys/class/uacce"
static struct wd_alg_list alg_list_head;
static struct wd_alg_list *alg_list_tail = &alg_list_head;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

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

		if (!strncmp(dev_dir->d_name, dev_name, strlen(dev_name))) {
			closedir(wd_class);
			return true;
		}
	}
	closedir(wd_class);

	return false;
}

int wd_alg_driver_register(struct wd_alg_driver *drv)
{
	struct wd_alg_list *new_alg;

	if (!drv) {
		WD_ERR("invalid: register drv is NULL!\n");
		return -WD_EINVAL;
	}

	new_alg = calloc(1, sizeof(struct wd_alg_list));
	if (!new_alg) {
		WD_ERR("failed to alloc alg driver memory!\n");
		return -WD_ENOMEM;
	}

	new_alg->alg_name = drv->alg_name;
	new_alg->drv_name = drv->drv_name;
	new_alg->priority = drv->priority;
	new_alg->drv = drv;
	new_alg->refcnt = 0;
	new_alg->next = NULL;

	if (drv->priority == UADK_ALG_HW) {
		/* If not find dev, remove this driver node */
		new_alg->available = wd_check_accel_dev(drv->drv_name);
		if (!new_alg->available) {
			free(new_alg);
			WD_ERR("failed to find alg driver's device!\n");
			return -WD_ENODEV;
		}
	} else {
		/* Should find the CPU if not support SVE or CE */
		new_alg->available = true;
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
		if (!strcmp(drv->alg_name, pnext->alg_name) &&
		     !strcmp(drv->drv_name, pnext->drv_name) &&
		     drv->priority == pnext->priority) {
			break;
		}
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
		if (!strcmp(drv->alg_name, pnext->alg_name) &&
		     !strcmp(drv->drv_name, pnext->drv_name) &&
		     drv->priority == pnext->priority) {
			break;
		}
		pnext = pnext->next;
	}

	if (drv->priority == UADK_ALG_HW) {
		/* If not find dev, remove this driver node */
		pnext->available = wd_check_accel_dev(drv->drv_name);
	} else {
		/* Should find the CPU if not support SVE or CE */
		pnext->available = true;
	}
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
		if (!strcmp(drv->alg_name, pnext->alg_name) &&
		     !strcmp(drv->drv_name, pnext->drv_name) &&
		     drv->priority == pnext->priority) {
			break;
		}
		pnext = pnext->next;
	}

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

	if (!pnext || !alg_name) {
		WD_ERR("invalid: request alg param is error!\n");
		return NULL;
	}

	/* Check the list to get an best driver */
	pthread_mutex_lock(&mutex);
	while (pnext) {
		/* hw_mask true mean not to used hardware dev */
		if (hw_mask && pnext->drv->priority == UADK_ALG_HW) {
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
		if (!strcmp(drv->alg_name, pnext->alg_name) &&
			!strcmp(drv->drv_name, pnext->drv_name) &&
			drv->priority == pnext->priority) {
			select_node = pnext;
			break;
		}
		pnext = pnext->next;
	}

	if (select_node && select_node->refcnt > 0)
		select_node->refcnt--;
	pthread_mutex_unlock(&mutex);
}

struct wd_alg_driver *wd_find_drv(char *drv_name, char *alg_name)
{
	struct wd_alg_list *head = &alg_list_head;
	struct wd_alg_list *pnext = head->next;
	struct wd_alg_driver *drv = NULL;

	if (!pnext || !alg_name) {
		WD_ERR("invalid: request alg param is error!\n");
		return NULL;
	}

	pthread_mutex_lock(&mutex);
	while (pnext) {
		if (!strcmp(alg_name, pnext->alg_name) &&
		    !strcmp(drv_name, pnext->drv_name)) {
			drv = pnext->drv;
			break;
		}
		pnext = pnext->next;
	}

	pthread_mutex_unlock(&mutex);

	return drv;
}

