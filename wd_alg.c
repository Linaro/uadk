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

struct acc_alg_item {
	const char *name;
	const char *algtype;
};

static struct acc_alg_item alg_options[] = {
	{"zlib", "zlib"},
	{"gzip", "gzip"},
	{"deflate", "deflate"},
	{"lz77_zstd", "lz77_zstd"},
	{"lz4", "lz4"},
	{"lz77_only", "lz77_only"},
	{"hashagg", "hashagg"},
	{"udma", "udma"},
	{"hashjoin", "hashjoin"},
	{"gather", "gather"},
	{"join-gather", "hashjoin"},

	{"rsa", "rsa"},
	{"dh", "dh"},
	{"ecdh", "ecdh"},
	{"x25519", "x25519"},
	{"x448", "x448"},
	{"ecdsa", "ecdsa"},
	{"sm2", "sm2"},

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
			return 0;
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

static bool wd_check_ce_support(const char *alg_name)
{
	unsigned long support_sm3 = 0;
	unsigned long support_sm4 = 0;
	const char *alg_tail;
	size_t tail_len;
	size_t alg_len;

	#if defined(__aarch64__)
		unsigned long hwcaps = 0;

		hwcaps = getauxval(AT_HWCAP);
		support_sm3 = hwcaps & HWCAP_CE_SM3;
		support_sm4 = hwcaps & HWCAP_CE_SM4;
	#endif
	if (!strcmp("sm3", alg_name) && support_sm3)
		return true;

	alg_len = strlen(alg_name);
	tail_len = strlen("(sm4)");
	if (alg_len <= tail_len)
		return false;

	alg_tail = alg_name + (alg_len - tail_len);
	if (!strcmp("(sm4)", alg_tail) && support_sm4)
		return true;

	return false;
}

static bool wd_check_sve_support(void)
{
	unsigned long hwcaps = 0;

	#if defined(__aarch64__)
		hwcaps = getauxval(AT_HWCAP);
		hwcaps &= HWCAP_SVE;
	#endif
	if (hwcaps)
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

	(void)wd_get_alg_type(drv->alg_name, new_alg->alg_type);
	strncpy(new_alg->alg_name, drv->alg_name, ALG_NAME_SIZE - 1);
	strncpy(new_alg->drv_name, drv->drv_name, DEV_NAME_LEN - 1);
	new_alg->priority = drv->priority;
	new_alg->calc_type = drv->calc_type;
	new_alg->drv = drv;
	new_alg->refcnt = 0;
	new_alg->next = NULL;

	new_alg->available = wd_alg_check_available(drv->calc_type,
			     drv->alg_name, drv->drv_name);
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
		pnext->available = wd_alg_check_available(drv->calc_type,
				   drv->alg_name, drv->drv_name);
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

int wd_alg_driver_init(struct wd_alg_driver *drv, void *conf)
{
	return drv->init(drv, conf);
}

void wd_alg_driver_exit(struct wd_alg_driver *drv)
{
	drv->exit(drv);
}

int wd_alg_driver_send(struct wd_alg_driver *drv, handle_t ctx, void *msg)
{
	return drv->send(drv, ctx, msg);
}

int wd_alg_driver_recv(struct wd_alg_driver *drv, handle_t ctx, void *msg)
{
	return drv->recv(drv, ctx, msg);
}

int wd_alg_get_dev_usage(const char *dev_name, const char *alg_type, __u8 alg_op_type)
{
	struct wd_alg_list *pnext = alg_list_head.next;
	struct hisi_dev_usage dev_usage;
	struct wd_alg_driver *drv;
	size_t len;

	if (!dev_name || !alg_type) {
		WD_ERR("dev_name or alg_type is NULL!\n");
		return -WD_EINVAL;
	}

	while (pnext) {
		len = strlen(pnext->drv_name);
		if (!strncmp(dev_name, pnext->drv_name, len) && *(dev_name + len) == '-' &&
		    !strcmp(alg_type, pnext->alg_type) && pnext->drv->priv)
			break;

		pnext = pnext->next;
	}

	if (!pnext)
		return -WD_EACCES;

	drv = pnext->drv;
	if (!drv->get_usage)
		return -WD_EINVAL;

	dev_usage.drv = drv;
	dev_usage.alg_op_type = alg_op_type;
	dev_usage.dev_name = dev_name;

	return drv->get_usage(&dev_usage);
}
