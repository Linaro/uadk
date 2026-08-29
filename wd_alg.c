/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/auxv.h>

#include "wd.h"
#include "wd_alg_common.h"

#define SYS_CLASS_DIR			"/sys/class/uacce"

/* Registry structure (List manager) */
struct wd_alg_registry {
	struct wd_drv_node *head;
	struct wd_drv_node *tail;
	pthread_mutex_t mutex;
	int drv_type_num;             /* Number of unique driver nodes in the list */
};

static struct wd_drv_node drv_list_head;
static struct wd_alg_registry alg_registry = {
	.head = &drv_list_head,
	.tail = &drv_list_head,
	.mutex = PTHREAD_MUTEX_INITIALIZER,
	.drv_type_num = 0,
};

struct acc_alg_item {
	const char *name;
	const char *algtype;
};

static struct acc_alg_item alg_options[] = {
	{"zlib", "comp"},
	{"gzip", "comp"},
	{"deflate", "comp"},
	{"lz77_zstd", "comp"},
	{"lz4", "comp"},
	{"lz77_only", "comp"},
	{"hashagg", "hashagg"},
	{"udma", "udma"},
	{"hashjoin", "hashjoin"},
	{"gather", "hashjoin"},
	{"join-gather", "hashjoin"},

	{"rsa", "rsa"},
	{"dh", "dh"},
	{"ecdh", "ecc"},
	{"x25519", "ecc"},
	{"x448", "ecc"},
	{"ecdsa", "ecc"},
	{"sm2", "ecc"},

	{"ecb(aes)", "cipher"},
	{"cbc(aes)", "cipher"},
	{"xts(aes)", "cipher"},
	{"ofb(aes)", "cipher"},
	{"cfb(aes)", "cipher"},
	{"ctr(aes)", "cipher"},
	{"cbc-cs1(aes)", "cipher"},
	{"cbc-cs2(aes)", "cipher"},
	{"cbc-cs3(aes)", "cipher"},
	{"ecb(sm4)", "cipher"},
	{"xts(sm4)", "cipher"},
	{"cbc(sm4)", "cipher"},
	{"ofb(sm4)", "cipher"},
	{"cfb(sm4)", "cipher"},
	{"ctr(sm4)", "cipher"},
	{"cbc-cs1(sm4)", "cipher"},
	{"cbc-cs2(sm4)", "cipher"},
	{"cbc-cs3(sm4)", "cipher"},
	{"ecb(des)", "cipher"},
	{"cbc(des)", "cipher"},
	{"ecb(des3_ede)", "cipher"},
	{"cbc(des3_ede)", "cipher"},
	{"xts-gb(sm4)", "cipher"},

	{"ccm(aes)", "aead"},
	{"gcm(aes)", "aead"},
	{"ccm(sm4)", "aead"},
	{"gcm(sm4)", "aead"},
	{"authenc(generic,cbc(aes))", "aead"},
	{"authenc(generic,cbc(sm4))", "aead"},

	{"sm3", "digest"},
	{"md5", "digest"},
	{"sha1", "digest"},
	{"sha256", "digest"},
	{"sha224", "digest"},
	{"sha384", "digest"},
	{"sha512", "digest"},
	{"sha512-224", "digest"},
	{"sha512-256", "digest"},
	{"cmac(aes)", "digest"},
	{"gmac(aes)", "digest"},
	{"xcbc-mac-96(aes)", "digest"},
	{"xcbc-prf-128(aes)", "digest"},
	{"", ""}
};

int wd_get_alg_type(const char *alg_name, char *alg_type)
{
	__u64 i;

	if (!alg_name || !alg_type) {
		WD_ERR("invalid: alg_name or alg_type is NULL!\n");
		return -WD_EINVAL;
	}

	for (i = 0; i < ARRAY_SIZE(alg_options); i++) {
		if (strcmp(alg_name, alg_options[i].name) == 0) {
			(void)strcpy(alg_type, alg_options[i].algtype);
			return WD_SUCCESS;
		}
	}

	return -WD_EINVAL;
}

static bool wd_check_accel_dev(const char *dev_name)
{
	struct dirent *dev_dir;
	DIR *wd_class;

	wd_class = opendir(SYS_CLASS_DIR);
	if (!wd_class) {
		WD_ERR("invalid: UADK framework isn't enabled in system!\n");
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

static bool wd_check_ce_support(const char *alg_name)
{
	unsigned long hwcaps = 0;
	const char *alg_tail;
	size_t tail_len;
	size_t alg_len;

	#if defined(__arm__) || defined(__arm)
		hwcaps = getauxval(AT_HWCAP2);
	#elif defined(__aarch64__)
		hwcaps = getauxval(AT_HWCAP);
	#endif
	if (!strcmp("sm3", alg_name) && (hwcaps & HWCAP_CE_SM3))
		return true;

	alg_len = strlen(alg_name);
	tail_len = strlen("(sm4)");
	if (alg_len <= tail_len)
		return false;

	alg_tail = alg_name + (alg_len - tail_len);
	if (!strcmp("(sm4)", alg_tail) && (hwcaps & HWCAP_CE_SM4))
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

static bool wd_alg_check_available(int calc_type,
	const char *alg_name, const char *dev_name)
{
	bool ret = false;

	switch (calc_type) {
	case UADK_ALG_SOFT:
		break;
	/* Should find the CPU if not support CE */
	case UADK_ALG_CE_INSTR:
		ret = wd_check_ce_support(alg_name);
		break;
	/* Should find the CPU if not support SVE */
	case UADK_ALG_SVE_INSTR:
		ret = wd_check_sve_support();
		break;
	/* Check if the current driver has device support */
	case UADK_ALG_HW:
		ret = wd_check_accel_dev(dev_name);
		break;
	default:
		break;
	}

	return ret;
}

/**
 * Mapping from task_type to calc_type filter:
 *
 *   TASK_HW    →  calc_type == UADK_ALG_HW
 *   TASK_INSTR →  calc_type != UADK_ALG_HW  (CE_INSTR | SVE_INSTR | SOFT)
 *   TASK_MIX   →  all calc_type values
 */
static inline bool wd_alg_drv_type_match(int task_type, int drv_calc_type)
{
	switch (task_type) {
	case TASK_HW:
		return drv_calc_type == UADK_ALG_HW ||
			 drv_calc_type == UADK_ALG_NPU ||
			 drv_calc_type == UADK_ALG_GPU;
	case TASK_INSTR:
		return drv_calc_type == UADK_ALG_CE_INSTR ||
			 drv_calc_type == UADK_ALG_SVE_INSTR;
	case TASK_MIX:
		return true;
	default:
		return false;
	}
}

int wd_alg_driver_register(struct wd_alg_driver *drv)
{
	struct wd_drv_node *node;
	struct wd_drv_node *target_node = NULL;
	char alg_type[ALG_NAME_SIZE];
	int i, ret;

	if (!drv) {
		WD_ERR("invalid: register drv is NULL!\n");
		return -WD_EINVAL;
	}

	if (!drv->init || !drv->exit || !drv->send || !drv->recv) {
		WD_ERR("invalid: driver's parameter is NULL!\n");
		return -WD_EINVAL;
	}

	ret = wd_get_alg_type(drv->alg_name, alg_type);
	if (ret) {
		WD_ERR("failed to get alg_type for %s!\n", drv->alg_name);
		return -WD_EINVAL;
	}

	pthread_mutex_lock(&alg_registry.mutex);
	node = alg_registry.head->next;
	/* Search for an existing node with the same drv_name */
	while (node) {
		if (strcmp(node->drv_name, drv->drv_name) == 0 &&
		     strcmp(node->alg_type, alg_type) == 0) {
			target_node = node;
			break;
		}
		node = node->next;
	}

	if (target_node) {
		/* Consistency check: a driver must strictly have uniform properties */
		if (target_node->priority != drv->priority ||
		    target_node->calc_type != drv->calc_type) {
			WD_ERR("invalid: driver %s attributes mismatch on re-register!\n",
			       drv->drv_name);
			pthread_mutex_unlock(&alg_registry.mutex);
			return -WD_EINVAL;
		}

		/* Check if alg_name already exists in this driver's array */
		for (i = 0; i < target_node->alg_count; i++) {
			if (strcmp(target_node->algs[i].alg_name, drv->alg_name) == 0) {
				/* Algorithm already registered, skip duplicate */
				pthread_mutex_unlock(&alg_registry.mutex);
				return WD_SUCCESS;
			}
		}

		/* Check array capacity */
		if (target_node->alg_count >= MAX_DRV_ALG_NUM) {
			WD_ERR("invalid: driver %s alg array overflow (max %d)!\n",
			       drv->drv_name, MAX_DRV_ALG_NUM);
			pthread_mutex_unlock(&alg_registry.mutex);
			return -WD_ENOMEM;
		}

		/* Add new algorithm to existing driver node */
		strncpy(target_node->algs[target_node->alg_count].alg_name,
			drv->alg_name, ALG_NAME_SIZE - 1);
		target_node->algs[target_node->alg_count].alg_name[ALG_NAME_SIZE - 1] = '\0';
		target_node->algs[target_node->alg_count].available =
			wd_alg_check_available(drv->calc_type, drv->alg_name, drv->drv_name);
		if (!target_node->algs[target_node->alg_count].available) {
			WD_ERR("invalid: driver %s alg %s not available on current system!\n",
				 drv->drv_name, drv->alg_name);
			pthread_mutex_unlock(&alg_registry.mutex);
			return -WD_ENODEV;
		}
		target_node->alg_count++;
	} else {
		/* Create a new driver node */
		target_node = calloc(1, sizeof(struct wd_drv_node));
		if (!target_node) {
			WD_ERR("failed to alloc drv node memory!\n");
			pthread_mutex_unlock(&alg_registry.mutex);
			return -WD_ENOMEM;
		}

		strncpy(target_node->drv_name, drv->drv_name, DEV_NAME_LEN - 1);
		target_node->drv_name[DEV_NAME_LEN - 1] = '\0';
		snprintf(target_node->alg_type, ALG_NAME_SIZE, "%s", alg_type);
		target_node->priority = drv->priority;
		target_node->calc_type = drv->calc_type;
		target_node->drv = drv;
		target_node->refcnt = 0;
		target_node->alg_count = 0;

		/* Add the first algorithm to the new node's array */
		strncpy(target_node->algs[0].alg_name, drv->alg_name, ALG_NAME_SIZE - 1);
		target_node->algs[0].alg_name[ALG_NAME_SIZE - 1] = '\0';
		target_node->algs[0].available =
			wd_alg_check_available(drv->calc_type, drv->alg_name, drv->drv_name);
		if (!target_node->algs[0].available) {
			free(target_node);
			WD_INFO("info: driver %s alg %s has no device register!\n",
				  drv->drv_name, drv->alg_name);
			pthread_mutex_unlock(&alg_registry.mutex);
			return -WD_ENODEV;
		}
		target_node->alg_count = 1;
		target_node->next = NULL;

		/* Append to list tail */
		alg_registry.tail->next = target_node;
		alg_registry.tail = target_node;
		__atomic_fetch_add(&alg_registry.drv_type_num, 1, __ATOMIC_RELAXED);
	}

	pthread_mutex_unlock(&alg_registry.mutex);
	return WD_SUCCESS;
}

void wd_alg_driver_unregister(struct wd_alg_driver *drv)
{
	struct wd_drv_node *npre = alg_registry.head;
	struct wd_drv_node *pnext;
	char alg_type[ALG_NAME_SIZE];
	int i, ret;

	if (!npre || !drv)
		return;

	ret = wd_get_alg_type(drv->alg_name, alg_type);
	if (ret) {
		WD_ERR("failed to get alg_type for %s!\n", drv->alg_name);
		return;
	}

	pthread_mutex_lock(&alg_registry.mutex);
	/* Find the driver node matching drv_name */
	pnext = npre->next;
	while (pnext) {
		if (strcmp(drv->drv_name, pnext->drv_name) == 0 &&
		     strcmp(pnext->alg_type, alg_type) == 0)
			break;
		npre = pnext;
		pnext = pnext->next;
	}

	if (!pnext) {
		pthread_mutex_unlock(&alg_registry.mutex);
		return;
	}

	/* Find and remove the specific alg_name from the node's array */
	for (i = 0; i < pnext->alg_count; i++) {
		if (strcmp(pnext->algs[i].alg_name, drv->alg_name) == 0) {
			/* Compact the array: move the last element to the removed slot */
			if (i != pnext->alg_count - 1)
				pnext->algs[i] = pnext->algs[pnext->alg_count - 1];
			pnext->alg_count--;
			break;
		}
	}

	/* If the driver no longer supports any algorithms, remove the entire node */
	if (!pnext->alg_count) {
		if (pnext->refcnt > 0)
			WD_INFO("info: release driver <%s> as it is still in use: %d!\n",
				pnext->drv_name, pnext->refcnt);

		if (pnext == alg_registry.tail)
			alg_registry.tail = npre;

		npre->next = pnext->next;
		free(pnext);
		if (alg_registry.drv_type_num > 0)
			__atomic_fetch_sub(&alg_registry.drv_type_num, 1, __ATOMIC_RELAXED);
	}

	pthread_mutex_unlock(&alg_registry.mutex);
}

struct wd_drv_node *wd_get_alg_head(void)
{
	return alg_registry.head;
}

/**
 * wd_alg_match_drv() - Check if a given algorithm match a specific driver.
 * @drv: Pointer to the driver instance
 * @alg_name: Specific algorithm name to check (e.g., "cbc(aes)")
 *
 * Uses the new hierarchical structure: finds the driver node, then searches
 * its internal static algorithm array.
 *
 * Return: true if supported and available, false otherwise.
 */
bool wd_alg_match_drv(struct wd_alg_driver *drv, const char *alg_name)
{
	struct wd_drv_node *node;
	int i;

	if (!drv || !alg_name)
		return false;

	pthread_mutex_lock(&alg_registry.mutex);
	node = alg_registry.head->next;
	while (node) {
		if (node->drv == drv) {
			/* Found the driver node, now search its algs array */
			for (i = 0; i < node->alg_count; i++) {
				if (!strcmp(node->algs[i].alg_name, alg_name) &&
				    node->algs[i].available) {
					pthread_mutex_unlock(&alg_registry.mutex);
					return true;
				}
			}
			/* Driver found, but algorithm not in its array or not available */
			pthread_mutex_unlock(&alg_registry.mutex);
			return false;
		}
		node = node->next;
	}
	pthread_mutex_unlock(&alg_registry.mutex);

	return false;
}

bool wd_drv_alg_support(const char *alg_name, void *param)
{
	struct wd_ctx_config_internal *config = param;
	struct wd_drv_node *head = alg_registry.head;
	struct wd_drv_node *node;
	__u32 i;
	int j;

	if (!alg_name || !config || !config->ctxs)
		return false;

	pthread_mutex_lock(&alg_registry.mutex);
	/* Check whether the currently allocated ctxs supports the specified algorithm. */
	for (i = 0; i < config->ctx_num; i++) {
		if (!config->ctxs[i].drv)
			continue;
		node = head->next;
		while (node) {
			/* Query the position of the driver matching the context in the list. */
			if (!strcmp(config->ctxs[i].drv->drv_name, node->drv_name)) {
				for (j = 0; j < node->alg_count; j++) {
					if (!strcmp(alg_name, node->algs[j].alg_name) &&
					    node->algs[j].available) {
						pthread_mutex_unlock(&alg_registry.mutex);
						return true;
					}
				}
			}
			node = node->next;
		}
	}
	pthread_mutex_unlock(&alg_registry.mutex);

	return false;
}

struct wd_alg_driver *wd_request_drv(const char *alg_name, int drv_type)
{
	struct wd_drv_node *node = alg_registry.head->next;
	struct wd_drv_node *drv_node = NULL;
	struct wd_alg_driver *drv = NULL;
	bool type_match = false;
	int tmp_priority = -1;
	int i;

	if (!node) {
		WD_ERR("invalid: request drv node is NULL!\n");
		return NULL;
	}

	if (!alg_name) {
		WD_ERR("invalid: alg_name is NULL!\n");
		return NULL;
	}

	pthread_mutex_lock(&alg_registry.mutex);
	while (node) {
		type_match = false;
		/* Check calc_type against requested drv_type */
		if (drv_type == ALG_DRV_FB && (node->calc_type == UADK_ALG_SOFT ||
		    node->calc_type == UADK_ALG_CE_INSTR ||
		    node->calc_type == UADK_ALG_SVE_INSTR))
			type_match = true;

		if (type_match && node->drv->priority > tmp_priority) {
			/* Check if this driver supports the requested alg_name */
			for (i = 0; i < node->alg_count; i++) {
				if (!strcmp(alg_name, node->algs[i].alg_name) &&
				    node->algs[i].available) {
					drv_node = node;
					drv = node->drv;
					tmp_priority = node->drv->priority;
					break;
				}
			}
		}
		node = node->next;
	}

	/* Increment refcnt on the selected driver node */
	if (drv)
		drv_node->refcnt++;
	pthread_mutex_unlock(&alg_registry.mutex);

	return drv;
}

int wd_alg_get_dev_usage(const char *dev_name, const char *alg_type, __u8 alg_op_type)
{
	struct wd_drv_node *node = alg_registry.head->next;
	struct hisi_dev_usage dev_usage;
	struct wd_alg_driver *drv;

	if (!dev_name || !alg_type) {
		WD_ERR("invalid: dev_name or alg_type is NULL!\n");
		return -WD_EINVAL;
	}

	while (node) {
		/* Match dev_name and alg_type at the driver node level */
		if (strstr(dev_name, node->drv_name) &&
		    !strcmp(alg_type, node->alg_type))
			break;

		node = node->next;
	}

	if (!node)
		return -WD_EACCES;

	drv = node->drv;
	if (!drv->get_usage)
		return -WD_EINVAL;

	dev_usage.drv = drv;
	dev_usage.alg_op_type = alg_op_type;
	dev_usage.dev_name = dev_name;

	return drv->get_usage(&dev_usage);
}

/**
 * wd_put_drv_array() - Release driver array allocated by wd_get_drv_array().
 *
 * Frees the driver pointer array. Does NOT touch the drivers themselves
 * (refcount managed separately by wd_alg_drv_ref_inc/dec).
 *
 * @drv_array: Driver array from wd_get_drv_array()
 * @drv_count: Number of entries (unused, for API symmetry)
 */
void wd_put_drv_array(struct wd_alg_driver **drv_array, const __u32 drv_count)
{
	if (drv_array)
		free(drv_array);
}

static int wd_compare_drv_priority(const void *a, const void *b)
{
	struct wd_alg_driver *driver_a = *(struct wd_alg_driver **)a;
	struct wd_alg_driver *driver_b = *(struct wd_alg_driver **)b;

	/* Higher priority value should come first */
	if (driver_a->priority > driver_b->priority)
		return -1;
	/* a has lower priority, should come after b */
	else if (driver_a->priority < driver_b->priority)
		return 1;
	/* equal priority */
	return 0;
}

/**
 * wd_get_drv_array() - Discover all unique drivers matching alg_type and task_type.
 *
 * @alg_type:  Algorithm class string ("cipher", "digest", "aead", "comp", etc.)
 * @task_type: TASK_HW (hardware only), TASK_INSTR (instruction only), TASK_MIX (all)
 * @drv_array: Output - newly allocated array of unique wd_alg_driver* pointers,
 *             caller must free with plain free()
 * @drv_count: Output - number of unique drivers found
 *
 * Traverses wd_drv_node list once:
 *   1. Matches by alg_type at node level (no need to traverse algs array for this).
 *   2. Filters by task_type using wd_alg_drv_type_match().
 *   3. Deduplicates is inherently solved (each node is a unique driver).
 *
 * This is a PURE QUERY — no reference counting or resource allocation side effects.
 * Reference counting is done separately by wd_alg_drv_ref_inc/dec().
 *
 * Return: 0 on success, negative on failure.
 */
int wd_get_drv_array(const char *alg_type, int task_type, const char *drv_name,
		     struct wd_alg_driver ***drv_array, __u32 *drv_count)
{
	struct wd_drv_node *head, *node;
	struct wd_alg_driver **drivers;
	__u32 max_driver_count;
	__u32 current_count = 0;
	bool has_available_alg;
	int i;

	if (!alg_type || !drv_array || !drv_count) {
		WD_ERR("invalid: NULL parameter!\n");
		return -WD_EINVAL;
	}

	*drv_array = NULL;
	*drv_count = 0;
	head = wd_get_alg_head();
	if (!head) {
		WD_ERR("failed to get alg list head!\n");
		return -WD_EINVAL;
	}

	max_driver_count = __atomic_load_n(&alg_registry.drv_type_num, __ATOMIC_RELAXED);
	if (!max_driver_count) {
		WD_ERR("invalid: no drivers registered for alg_type: %s\n", alg_type);
		return -WD_EINVAL;
	}

	drivers = calloc(max_driver_count, sizeof(struct wd_alg_driver *));
	if (!drivers) {
		WD_ERR("failed to allocate drivers array!\n");
		return -WD_ENOMEM;
	}

	/*
	 * Single traversal of wd_drv_node list:
	 * - Match by alg_type at node level
	 * - Filter by task_type
	 * - Deduplication inherently solved
	 */
	node = head->next;
	while (node) {
		if (strcmp(node->alg_type, alg_type) == 0 &&
		    wd_alg_drv_type_match(task_type, node->calc_type)) {

			if (drv_name && strcmp(node->drv_name, drv_name) != 0) {
				node = node->next;
				continue;
			}

			/* Check if at least one algorithm in this driver is available */
			has_available_alg = false;
			for (i = 0; i < node->alg_count; i++) {
				if (node->algs[i].available) {
					has_available_alg = true;
					break;
				}
			}

			if (!has_available_alg) {
				node = node->next;
				continue;
			}

			if (current_count >= max_driver_count) {
				WD_ERR("failed to check driver array overflow!\n");
				goto query_failed;
			}
			drivers[current_count] = node->drv;
			current_count++;
		}
		node = node->next;
	}

	if (!current_count) {
		WD_ERR("invalid: no available drivers for alg_type: %s, task_type: %d\n",
		       alg_type, task_type);
		goto query_failed;
	}

	/* Sort drivers by priority (higher priority first) */
	if (current_count > 1)
		qsort(drivers, current_count, sizeof(struct wd_alg_driver *),
		      wd_compare_drv_priority);

	WD_DEBUG("Driver discovery: %u unique drivers for alg_type=%s\n",
		current_count, alg_type);
	*drv_array = drivers;
	*drv_count = current_count;

	return WD_SUCCESS;

query_failed:
	free(drivers);
	return -WD_EINVAL;
}

/**
 * wd_alg_drv_ref_inc() - Increment reference count for each unique driver.
 *
 * @drv_array: Array of unique driver pointers
 * @drv_count: Number of drivers in the array
 *
 * For each unique driver, finds its node in wd_drv_node list and
 * increments refcnt by exactly 1. This ensures refcnt reflects the
 * number of configs using the driver, not the number of ctxs.
 *
 * Must be called after wd_get_drv_array() and after ctx binding.
 */
void wd_alg_drv_ref_inc(struct wd_alg_driver **drv_array, __u32 drv_count)
{
	struct wd_drv_node *node;
	__u32 i;

	if (!drv_array || !drv_count)
		return;

	pthread_mutex_lock(&alg_registry.mutex);
	for (i = 0; i < drv_count; i++) {
		if (!drv_array[i])
			continue;
		/* Directly find the unique driver node and increment refcnt */
		node = alg_registry.head->next;
		while (node) {
			if (node->drv == drv_array[i]) {
				node->refcnt++;
				break;
			}
			node = node->next;
		}
	}
	pthread_mutex_unlock(&alg_registry.mutex);
}

/**
 * wd_alg_drv_ref_dec() - Decrement reference count for each unique driver.
 *
 * @drv_array: Array of unique driver pointers
 * @drv_count: Number of drivers in the array
 *
 * Inverse of wd_alg_drv_ref_inc(). Decrements refcnt by 1 for each
 * unique driver. Must be called during cleanup.
 */
void wd_alg_drv_ref_dec(struct wd_alg_driver **drv_array, __u32 drv_count)
{
	struct wd_drv_node *node;
	__u32 i;

	if (!drv_array || !drv_count)
		return;

	pthread_mutex_lock(&alg_registry.mutex);
	for (i = 0; i < drv_count; i++) {
		if (!drv_array[i])
			continue;
		/* Directly find the unique driver node and decrement refcnt */
		node = alg_registry.head->next;
		while (node) {
			if (node->drv == drv_array[i] && node->refcnt > 0) {
				node->refcnt--;
				break;
			}
			node = node->next;
		}
	}
	pthread_mutex_unlock(&alg_registry.mutex);
}
