
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2024-2025 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2024-2025 Linaro ltd.
 */

#include "adapter.h"

#define CONFIG_FILE_ENV "UADK_CONF"
#define DRIVER_NAME_KEY "driver_name"
#define MODE_KEY "mode"
#define LOOP_KEY "looptime"
#define WORKERS_NB 8

static int read_value_int(char *conf, const char *key)
{
	FILE *fp = fopen(conf, "r");
	char line[1024];
	int ret = 0;

	if (fp == NULL)
		return 0;

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *key_value = strtok(line, "=");
			if (key_value && strcmp(key_value, key) == 0) {
				char *value = strtok(NULL, "\n");

				if (value) {
					ret = atoi(value);
					goto exit;
				}
			}
	}
exit:
	fclose(fp);
	return ret;
}

static void read_config_entries(char *conf, struct uadk_adapter *adapter, char *alg_name)
{
	struct uadk_adapter_worker *worker;
	FILE *fp = fopen(conf, "r");
	struct wd_alg_driver *drv;
	char *drv_name = NULL;
	char line[1024];
	int i = 0;

	if (fp == NULL)
		return;

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *key_value = strtok(line, "=");

		if (key_value && strcmp(key_value, DRIVER_NAME_KEY) == 0)
			drv_name = strdup(strtok(NULL, "\n"));

		if ((drv_name != NULL) && (alg_name != NULL)) {
			drv = wd_find_drv(drv_name, alg_name, 0);
			if (!drv)
				continue;

			worker = &adapter->workers[i];
			worker->driver = drv;
			worker->idx = i;
			pthread_mutex_init(&worker->mutex, NULL);
			adapter->workers_nb++;
			if (drv_name) {
				free(drv_name);
				drv_name = NULL;
			}

			if (++i >= UADK_MAX_NB_WORKERS)
				break;
		}
	}

	if (drv_name)
		free(drv_name);

	fclose(fp);
}

int uadk_adapter_add_workers(struct uadk_adapter *adapter, char *alg)
{
	char *conf = getenv(CONFIG_FILE_ENV);
	struct uadk_adapter_worker workers[WORKERS_NB];
	struct uadk_adapter_worker worker;
	struct wd_alg_driver *drv;
	int idx = 0, i, j;

	adapter->looptime = UADK_WORKER_LOOPTIME;

	if (conf != NULL) {
		int looptime = 0;

		/* if env UADK_CONF exist, parse config first */
		adapter->mode = read_value_int(conf, MODE_KEY);
		looptime = read_value_int(conf, LOOP_KEY);
		if (looptime != 0)
			adapter->looptime = looptime;

		read_config_entries(conf, adapter, alg);
		if (adapter->workers_nb != 0)
			return 0;
	}

	/* Then parse all system drivers to workers */
	do {
		drv = wd_find_drv(NULL, alg, idx);
		if (!drv)
			break;

		workers[idx++].driver = drv;

		if (idx >= WORKERS_NB)
			break;
	} while (drv);

	/* Sorted as priority */
	for (i = 0; i < idx; i++) {
		for (j = i; j < idx; j++) {
			if (workers[i].driver->priority <
			    workers[j].driver->priority) {
				worker.driver = workers[i].driver;
				workers[i].driver = workers[j].driver;
				workers[j].driver = worker.driver;
			}
		}
	}

	for (i = 0; i < idx; i++) {
		adapter->workers[i].driver = workers[i].driver;
		adapter->workers[i].idx = i;
		adapter->workers_nb++;
		pthread_mutex_init(&adapter->workers[i].mutex, NULL);

		if (adapter->workers_nb >= UADK_MAX_NB_WORKERS)
			break;
	}

	return (adapter->workers_nb == 0);
}

struct uadk_adapter_worker *uadk_adapter_choose_worker(
	struct uadk_adapter *adapter,
	enum alg_task_type type)
{
	struct uadk_adapter_worker *worker;

	/* use worker[0] for simplicity now */
	worker = &adapter->workers[0];
	worker->valid = true;

	return worker;
}

struct uadk_adapter_worker *uadk_adapter_switch_worker(
	struct uadk_adapter *adapter,
	struct uadk_adapter_worker *worker,
	int para)
{
	struct uadk_adapter_worker *new_worker;
	int idx = worker->idx;

	if (adapter->workers_nb == 1)
		return worker;

	if (para) {
		idx += 1;
	} else {
		if (idx == 0)
			idx = adapter->workers_nb - 1;
		else
			idx -= 1;
	}

	new_worker = &adapter->workers[idx];
	new_worker->valid = true;

	return new_worker;
}

void uadk_adapter_free(struct uadk_adapter *adapter)
{
	for (int i = 0; i < adapter->workers_nb; i++)
		pthread_mutex_destroy(&adapter->workers[i].mutex);
	free(adapter);
}
