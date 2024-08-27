
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2024-2025 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2024-2025 Linaro ltd.
 */

#include "adapter.h"

#define CONFIG_FILE_ENV "UADK_CONF"
#define DRIVER_NAME_KEY "driver_name"
#define MODE_KEY "mode"

static int read_value_int(FILE *fp, const char *key)
{
	char line[1024];

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *key_value = strtok(line, "=");
			if (key_value && strcmp(key_value, key) == 0) {
				char *value = strtok(NULL, "\n");

				if (value) {
					int mode = atoi(value);
					return mode;
				}
			}
	}
	return 0;
}

static void read_config_entries(FILE *fp, struct uadk_adapter *adapter, char *alg_name)
{
	struct uadk_adapter_worker *worker;
	struct wd_alg_driver *drv;
	char *drv_name = NULL;
	char line[1024];
	int i = 0;

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
			worker->lifetime = 0;
			worker->idx = i;
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
}

int uadk_adapter_add_workers(struct uadk_adapter *adapter, char *alg)
{
	char *uadk_conf = getenv(CONFIG_FILE_ENV);
	struct uadk_adapter_worker *worker;
	struct wd_alg_driver *drv;
	FILE *fp = NULL;
	int idx = 0;

	if (uadk_conf != NULL)
		fp = fopen(uadk_conf, "r");

	if (fp) {
		/* if env UADK_CONF exist, only parse config */
		adapter->mode = read_value_int(fp, MODE_KEY);
		read_config_entries(fp, adapter, alg);
		fclose(fp);
	} else {
		/* if no UADK_CONF, parse all drv to the workers*/
		do {
			drv = wd_find_drv(NULL, alg, idx);
			if (!drv)
				break;

			worker = &adapter->workers[idx];
			worker->driver = drv;
			worker->lifetime = 0;
			worker->idx = idx;
			adapter->workers_nb++;

			if (++idx >= UADK_MAX_NB_WORKERS)
				break;
		} while (drv);
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
	worker->lifetime = 0;

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
	new_worker->lifetime = 0;

	return new_worker;
}
