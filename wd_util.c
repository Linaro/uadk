// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "wd_sched.h"
#include "wd_util.h"
#include "wd_alg.h"
#include "wd_bmm.h"
#include "wd_internal.h"

#define WD_BALANCE_THRHD		1280
#define WD_RECV_MAX_CNT_SLEEP		60000000
#define WD_RECV_MAX_CNT_NOSLEEP		200000000
#define PRIVILEGE_FLAG			0600
#define MIN(a, b)			((a) > (b) ? (b) : (a))
#define MAX(a, b)			((a) > (b) ? (a) : (b))

#define WD_INIT_SLEEP_UTIME		1000
#define US2S(us)			((us) >> 20)
#define WD_INIT_RETRY_TIMEOUT		3

#define WD_DRV_LIB_DIR			"uadk"
#define WD_DRV_CONF_FILE		"uadk.cnf"

#define WD_PATH_DIR_NUM			2
#define UADK_MAX_NUMA_NODES		64

struct msg_pool {
	/* message array allocated dynamically */
	void *msgs;
	int *used;
	__u32 msg_num;
	__u32 msg_size;
	int tail;
};

/* parse wd env begin */

/* define comp's combination of two operation type and two mode here */
static const char *comp_ctx_type[2][2] = {
	{"sync-comp:", "sync-decomp:"},
	{"async-comp:", "async-decomp:"}
};

/* define two ctx mode here for cipher and other alg */
static const char *ctx_mode_type[2][1] = { {"sync:"}, {"async:"} };

static const char *wd_env_name[WD_TYPE_MAX] = {
	"WD_COMP_CTX_NUM",
	"WD_CIPHER_CTX_NUM",
	"WD_DIGEST_CTX_NUM",
	"WD_AEAD_CTX_NUM",
	"WD_RSA_CTX_NUM",
	"WD_DH_CTX_NUM",
	"WD_ECC_CTX_NUM",
	"WD_AGG_CTX_NUM",
	"WD_UDMA_CTX_NUM",
	"WD_JOIN_GATHER_CTX_NUM",
};

struct drv_lib_list {
	void *dlhandle;
	struct drv_lib_list *next;
};

static void *wd_internal_alloc(void *usr, size_t size)
{
	if (size)
		return malloc(size);
	else
		return NULL;
}

static void wd_internal_free(void *usr, void *va)
{
	if (va)
		free(va);
}

static __u32 wd_mem_bufsize(void *usr)
{
	/* Malloc memory min size is 1 Byte */
	return 1;
}

int wd_mem_ops_init(handle_t h_ctx, struct wd_mm_ops *mm_ops, int mem_type)
{
	int ret;

	ret = wd_is_sva(h_ctx);
	if (ret == UACCE_DEV_SVA || ret == -WD_HW_EACCESS) {
		/*
		 * In software queue scenario, all memory is handled as virtual memory
		 * and processed in the same way as SVA mode
		 */
		mm_ops->sva_mode = true;
	} else if (!ret) {
		mm_ops->sva_mode = false;
	} else {
		WD_ERR("failed to check ctx!\n");
		return ret;
	}

	/*
	 * Under SVA mode, there is no need to consider the memory type;
	 * directly proceed with virtual memory handling
	 */
	if (mm_ops->sva_mode) {
		mm_ops->alloc = (void *)wd_internal_alloc;
		mm_ops->free = (void *)wd_internal_free;
		mm_ops->iova_map = NULL;
		mm_ops->iova_unmap = NULL;
		mm_ops->get_bufsize = (void *)wd_mem_bufsize;
		mm_ops->usr = NULL;
		return 0;
	}

	switch (mem_type) {
	case UADK_MEM_AUTO:
		/*
		 * The memory pool needs to be allocated according to
		 * the block size when it is first executed in the UADK
		 */
		mm_ops->usr = NULL;
		WD_ERR("automatic under No-SVA mode is not supported!\n");
		return -WD_EINVAL;
	case UADK_MEM_USER:
		if (!mm_ops->alloc || !mm_ops->free || !mm_ops->iova_map ||
		    !mm_ops->iova_unmap || !mm_ops->usr) { // The user create a memory pool
			WD_ERR("failed to check memory ops, some ops function is NULL!\n");
			return -WD_EINVAL;
		}
		break;
	case UADK_MEM_PROXY:
		if (!mm_ops->usr) {
			WD_ERR("failed to check memory pool!\n");
			return -WD_EINVAL;
		}
		mm_ops->alloc = (void *)wd_mem_alloc;
		mm_ops->free = (void *)wd_mem_free;
		mm_ops->iova_map = (void *)wd_mem_map;
		mm_ops->iova_unmap = (void *)wd_mem_unmap;
		mm_ops->get_bufsize = (void *)wd_get_bufsize;
		break;
	default:
		WD_ERR("failed to check memory type!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static void clone_ctx_to_internal(struct wd_ctx *ctx,
					  struct wd_ctx_internal *ctx_in)
{
	ctx_in->ctx = ctx->ctx;
	ctx_in->op_type = ctx->op_type;
	ctx_in->ctx_mode = ctx->ctx_mode;
}

static int wd_shm_create(struct wd_ctx_config_internal *in)
{
	int shm_size = sizeof(unsigned long) * WD_CTX_CNT_NUM;
	void *ptr;
	int shmid;

	if (!wd_need_info())
		return 0;

	shmid = shmget(WD_IPC_KEY, shm_size, IPC_CREAT | PRIVILEGE_FLAG);
	if (shmid < 0) {
		WD_ERR("failed to get shared memory id(%d).\n", errno);
		return -WD_EINVAL;
	}

	ptr = shmat(shmid, NULL, 0);
	if (ptr == (void *)-1) {
		WD_ERR("failed to get shared memory addr(%d).\n", errno);
		return -WD_EINVAL;
	}

	memset(ptr, 0, shm_size);

	in->shmid = shmid;
	in->msg_cnt = ptr;

	return 0;
}

static void wd_shm_delete(struct wd_ctx_config_internal *in)
{
	if (!wd_need_info())
		return;

	/* deleted shared memory */
	shmdt(in->msg_cnt);
	shmctl(in->shmid, IPC_RMID, NULL);

	in->shmid = 0;
	in->msg_cnt = NULL;
}

int wd_init_ctx_config(struct wd_ctx_config_internal *in,
		       struct wd_ctx_config *cfg)
{
	struct wd_ctx_internal *ctxs;
	const char *alg_name;
	__u32 i, j;
	int ret;

	if (!cfg->ctx_num) {
		WD_ERR("invalid: ctx_num is 0!\n");
		return -WD_EINVAL;
	}

	ret = wd_shm_create(in);
	if (ret)
		return ret;

	ctxs = calloc(1, cfg->ctx_num * sizeof(struct wd_ctx_internal));
	if (!ctxs) {
		WD_ERR("failed to alloc memory for internal ctxs!\n");
		ret = -WD_ENOMEM;
		goto err_shm_del;
	}

	for (i = 0; i < cfg->ctx_num; i++) {
		if (!cfg->ctxs[i].ctx) {
			WD_ERR("invalid: ctx<%u> is NULL!\n", i);
			break;
		}
		clone_ctx_to_internal(cfg->ctxs + i, ctxs + i);
		ret = pthread_spin_init(&ctxs[i].lock, PTHREAD_PROCESS_SHARED);
		if (ret) {
			WD_ERR("failed to init ctxs lock!\n");
			goto err_out;
		}

		alg_name = in->alg_name;
		if (strcmp(in->alg_name, COMP_ALG) == 0) {
			if (cfg->ctxs[i].op_type == 0)
				alg_name = CTX_COMP_ALG;
			else
				alg_name = CTX_DECOMP_ALG;
		}

		ret = wd_insert_ctx_list(cfg->ctxs[i].ctx, alg_name);
		if (ret) {
			WD_ERR("failed to add ctx to mem list!\n");
			goto err_out;
		}
	}

	in->ctxs = ctxs;
	in->priv = cfg->priv;
	in->ctx_num = cfg->ctx_num;

	return 0;

err_out:
	for (j = 0; j < i; j++)
		pthread_spin_destroy(&ctxs[j].lock);
	free(ctxs);
err_shm_del:
	wd_shm_delete(in);
	return ret;
}

static void wd_sched_set_param_default(handle_t h_sched_ctx,
				       void *sched_key, void *sched_param)
{

}

int wd_init_sched(struct wd_sched *in, struct wd_sched *from)
{
	if (!from->name || !from->sched_init ||
	    !from->pick_next_ctx || !from->poll_policy) {
		WD_ERR("invalid: member of wd_sched is NULL!\n");
		return -WD_EINVAL;
	}

	in->h_sched_ctx = from->h_sched_ctx;
	in->name = strdup(from->name);
	if (!in->name)
		return -WD_ENOMEM;

	in->sched_init = from->sched_init;
	in->sched_uninit = from->sched_uninit;
	in->pick_next_ctx = from->pick_next_ctx;
	in->poll_policy = from->poll_policy;
	in->set_param = from->set_param;

	if (!from->set_param) {
		WD_ERR("set param is NULL, use default!\n");
		in->set_param = wd_sched_set_param_default;
	}

	return 0;
}

void wd_clear_sched(struct wd_sched *in)
{
	char *name = (char *)in->name;

	if (name)
		free(name);
	in->h_sched_ctx = 0;
	in->name = NULL;
	in->sched_init = NULL;
	in->sched_uninit = NULL;
	in->pick_next_ctx = NULL;
	in->poll_policy = NULL;
	in->set_param = NULL;
}

void wd_clear_ctx_config(struct wd_ctx_config_internal *in)
{
	__u32 i;

	for (i = 0; in->ctxs && i < in->ctx_num; i++)
		pthread_spin_destroy(&in->ctxs[i].lock);

	in->priv = NULL;
	in->ctx_num = 0;
	if (in->ctxs) {
		free(in->ctxs);
		in->ctxs = NULL;
	}

	wd_shm_delete(in);
}

void wd_memset_zero(void *data, __u32 size)
{
	__u32 tmp = size;
	char *s = data;

	if (!s)
		return;

	while (tmp--)
		*s++ = 0;
}

static void get_ctx_msg_num(struct wd_cap_config *cap, __u32 *msg_num)
{
	if (!cap || !cap->ctx_msg_num)
		return;

	if (cap->ctx_msg_num > WD_POOL_MAX_ENTRIES) {
		WD_INFO("ctx_msg_num %u is invalid, use default value: %u!\n",
			cap->ctx_msg_num, *msg_num);
		return;
	}

	*msg_num = cap->ctx_msg_num;
}

static int init_msg_pool(struct msg_pool *pool, __u32 msg_num, __u32 msg_size)
{
	pool->msgs = calloc(1, msg_num * msg_size);
	if (!pool->msgs) {
		WD_ERR("failed to alloc memory for msgs arrary of msg pool!\n");
		return -WD_ENOMEM;
	}

	pool->used = calloc(1, msg_num * sizeof(int));
	if (!pool->used) {
		free(pool->msgs);
		pool->msgs = NULL;
		WD_ERR("failed to alloc memory for used arrary of msg pool!\n");
		return -WD_ENOMEM;
	}

	pool->msg_size = msg_size;
	pool->msg_num = msg_num;
	pool->tail = 0;

	return 0;
}

static void uninit_msg_pool(struct msg_pool *pool)
{
	if (!pool->msg_num)
		return;

	free(pool->msgs);
	free(pool->used);
	pool->msgs = NULL;
	pool->used = NULL;
	memset(pool, 0, sizeof(*pool));
}

int wd_init_async_request_pool(struct wd_async_msg_pool *pool, struct wd_ctx_config *config,
			       __u32 msg_num, __u32 msg_size)
{
	__u32 pool_num = config->ctx_num;
	__u32 i, j;
	int ret;

	pool->pool_num = pool_num;

	pool->pools = calloc(1, pool_num * sizeof(struct msg_pool));
	if (!pool->pools) {
		WD_ERR("failed to alloc memory for async msg pools!\n");
		return -WD_ENOMEM;
	}

	/* If user set valid msg num, use user's. */
	get_ctx_msg_num(config->cap, &msg_num);
	for (i = 0; i < pool_num; i++) {
		if (config->ctxs[i].ctx_mode == CTX_MODE_SYNC)
			continue;

		ret = init_msg_pool(&pool->pools[i], msg_num, msg_size);
		if (ret < 0)
			goto err;
	}

	return 0;
err:
	for (j = 0; j < i; j++)
		uninit_msg_pool(&pool->pools[j]);
	free(pool->pools);
	pool->pools = NULL;
	return ret;
}

void wd_uninit_async_request_pool(struct wd_async_msg_pool *pool)
{
	__u32 i;

	for (i = 0; i < pool->pool_num; i++)
		uninit_msg_pool(&pool->pools[i]);

	free(pool->pools);
	pool->pools = NULL;
	pool->pool_num = 0;
}

void *wd_find_msg_in_pool(struct wd_async_msg_pool *pool,
			  int ctx_idx, __u32 tag)
{
	struct msg_pool *p;
	__u32 msg_num;

	if ((__u32)ctx_idx >= pool->pool_num) {
		WD_ERR("invalid: message ctx id index is %d!\n", ctx_idx);
		return NULL;
	}
	p = &pool->pools[ctx_idx];
	msg_num = p->msg_num;

	/* tag value start from 1 */
	if (!tag || tag > msg_num) {
		WD_ERR("invalid: message cache tag is %u!\n", tag);
		return NULL;
	}

	return (void *)((uintptr_t)p->msgs + p->msg_size * (tag - 1));
}

int wd_get_msg_from_pool(struct wd_async_msg_pool *pool,
			 int ctx_idx, void **msg)
{
	struct msg_pool *p = &pool->pools[ctx_idx];
	__u32 msg_num = p->msg_num;
	__u32 msg_size = p->msg_size;
	__u32 cnt = 0;
	__u32 idx = p->tail;

	/* Scheduler set a sync ctx */
	if (!msg_num)
		return -WD_EINVAL;

	while (__atomic_test_and_set(&p->used[idx], __ATOMIC_ACQUIRE)) {
		idx = (idx + 1) % msg_num;
		cnt++;
		if (cnt == msg_num)
			return -WD_EBUSY;
	}

	p->tail = (idx + 1) % msg_num;
	*msg = (void *)((uintptr_t)p->msgs + msg_size * idx);

	return idx + 1;
}

void wd_put_msg_to_pool(struct wd_async_msg_pool *pool, int ctx_idx, __u32 tag)
{
	struct msg_pool *p = &pool->pools[ctx_idx];
	__u32 msg_num = p->msg_num;

	/* tag value start from 1 */
	if (!tag || tag > msg_num) {
		WD_ERR("invalid: message cache idx is %u!\n", tag);
		return;
	}

	__atomic_clear(&p->used[tag - 1], __ATOMIC_RELEASE);
}

int wd_check_src_dst(void *src, __u32 in_bytes, void *dst, __u32 out_bytes)
{
	if ((in_bytes && !src) || (out_bytes && !dst))
		return -WD_EINVAL;

	return 0;
}

int wd_check_datalist(struct wd_datalist *head, __u64 size)
{
	struct wd_datalist *tmp = head;
	__u64 list_size = 0;

	while (tmp) {
		if (tmp->data)
			list_size += tmp->len;

		tmp = tmp->next;
	}

	return list_size >= size ? 0 : -WD_EINVAL;
}

void dump_env_info(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa;
	struct wd_ctx_range **ctx_table;
	int i, j, k;

	FOREACH_NUMA(i, config, config_numa) {
		if (!config_numa->ctx_table)
			continue;

		ctx_table = config_numa->ctx_table;
		WD_ERR("-> %s: %d: sync num: %u\n", __func__, i,
		       config_numa->sync_ctx_num);
		WD_ERR("-> %s: %d: async num: %u\n", __func__, i,
		       config_numa->async_ctx_num);
		for (j = 0; j < CTX_MODE_MAX; j++)
			for (k = 0; k < config_numa->op_type_num; k++) {
				WD_ERR("-> %d: [%d][%d].begin: %u\n",
				       i, j, k, ctx_table[j][k].begin);
				WD_ERR("-> %d: [%d][%d].end: %u\n",
				       i, j, k, ctx_table[j][k].end);
				WD_ERR("-> %d: [%d][%d].size: %u\n",
				       i, j, k, ctx_table[j][k].size);
			}
	}
}

static void *wd_get_config_numa(struct wd_env_config *config, int node)
{
	struct wd_env_config_per_numa *config_numa;
	int i;

	FOREACH_NUMA(i, config, config_numa)
		if (config_numa->node == node)
			break;

	if (i == config->numa_num) {
		WD_ERR("invalid: missing numa node is %d!\n", node);
		return NULL;
	}

	return config_numa;
}

static void wd_free_numa(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa;
	int i;

	FOREACH_NUMA(i, config, config_numa)
		free(config_numa->dev);

	free(config->config_per_numa);
	config->config_per_numa = NULL;
	config->numa_num = 0;
}

/**
 * @numa_dev_num: number of devices of the same type (like sec2) on each numa.
 * @numa_num: number of numa node that has this type of device.
 */
static __u16 wd_get_dev_numa(struct uacce_dev_list *head,
			     int *numa_dev_num, __u16 size)
{
	struct uacce_dev_list *list = head;
	__u16 numa_num = 0;

	while (list) {
		if (list->dev->numa_id >= size) {
			WD_ERR("invalid: numa id is %d!\n", list->dev->numa_id);
			return 0;
		}

		if (!numa_dev_num[list->dev->numa_id])
			numa_num++;

		numa_dev_num[list->dev->numa_id]++;
		list = list->next;
	}

	return numa_num;
}

static void wd_set_numa_dev(struct uacce_dev_list *head,
			    struct wd_env_config *config)
{
	struct uacce_dev_list *list = head;
	struct wd_env_config_per_numa *config_numa;
	struct uacce_dev *dev;

	while (list) {
		config_numa = wd_get_config_numa(config, list->dev->numa_id);
		if (!config_numa)
			break;

		dev = config_numa->dev + config_numa->dev_num;
		memcpy(dev, list->dev, sizeof(*list->dev));
		config_numa->dev_num++;
		list = list->next;
	}
}

static int wd_set_config_numa(struct wd_env_config *config,
			      const int *numa_dev_num, int max_node)
{
	struct wd_env_config_per_numa *config_numa;
	int i;

	config->config_per_numa = calloc(config->numa_num, sizeof(*config_numa));
	if (!config->config_per_numa)
		return -WD_ENOMEM;

	config_numa = config->config_per_numa;
	for (i = 0; i < max_node; i++) {
		if (!numa_dev_num[i])
			continue;

		config_numa->node = i;
		config_numa->dev = calloc(numa_dev_num[i],
					  sizeof(struct uacce_dev));
		if (!config_numa->dev) {
			/* free config_per_numa and all uacce dev */
			wd_free_numa(config);
			return -WD_ENOMEM;
		}

		config_numa->dev_num = 0;
		config_numa++;
	}

	return 0;
}

static int wd_alloc_numa(struct wd_env_config *config,
			 const struct wd_alg_ops *ops)
{
	struct uacce_dev_list *head;
	int *numa_dev_num;
	int ret, max_node;

	max_node = numa_max_node() + 1;
	if (max_node <= 0)
		return -WD_EINVAL;

	numa_dev_num = calloc(max_node, sizeof(int));
	if (!numa_dev_num)
		return -WD_ENOMEM;

	/* get uacce_dev */
	head = wd_get_accel_list(ops->alg_name);
	if (!head) {
		WD_ERR("invalid: no device to support %s\n", ops->alg_name);
		ret = -WD_ENODEV;
		goto free_numa_dev_num;
	}

	/* get numa num and device num of each numa from uacce_dev list */
	config->numa_num = wd_get_dev_numa(head, numa_dev_num, max_node);
	if (!config->numa_num || config->numa_num > max_node) {
		WD_ERR("invalid: numa number is %u!\n", config->numa_num);
		ret = -WD_ENODEV;
		goto free_list;
	}

	/* alloc and init config_per_numa and all uacce dev */
	ret = wd_set_config_numa(config, numa_dev_num, max_node);
	if (ret) {
		WD_ERR("failed to set numa config, ret = %d!\n", ret);
		goto free_list;
	}

	/* set device and device num for config numa from uacce_dev list */
	wd_set_numa_dev(head, config);
	wd_free_list_accels(head);
	free(numa_dev_num);

	return 0;

free_list:
	config->numa_num = 0;
	wd_free_list_accels(head);
free_numa_dev_num:
	free(numa_dev_num);
	return ret;
}

static int is_number(const char *str)
{
	size_t i, len;

	if (!str)
		return 0;

	len = strlen(str);
	if (!len)
		return 0;

	if (len != 1 && str[0] == '0')
		return 0;

	for (i = 0; i < len; i++)
		if (!(isdigit(str[i])))
			return 0;

	return 1;
}

static int str_to_bool(const char *s, bool *target)
{
	int tmp;

	if (!is_number(s))
		return -WD_EINVAL;

	tmp = strtol(s, NULL, 10);
	if (tmp != 0 && tmp != 1)
		return -WD_EINVAL;

	*target = tmp;

	return 0;
}

static int parse_num_on_numa(const char *s, int *num, int *node)
{
	char *sep, *start, *left;

	if (!strlen(s)) {
		WD_ERR("invalid: input string length is zero!\n");
		return -WD_EINVAL;
	}

	start = strdup(s);
	if (!start)
		return -WD_ENOMEM;

	left = start;
	sep = strsep(&left, "@");
	if (!sep)
		goto out;

	if (is_number(sep) && is_number(left)) {
		*num = strtol(sep, NULL, 10);
		*node = strtol(left, NULL, 10);
		free(start);
		return 0;
	}

out:
	WD_ERR("invalid: input env format is %s!\n", s);
	free(start);
	return -WD_EINVAL;
}

static int wd_alloc_ctx_table_per_numa(struct wd_env_config_per_numa *config)
{
	struct wd_ctx_range **ctx_table;
	int i, j, ret;

	if (config->ctx_table)
		return 0;

	ctx_table = calloc(1, sizeof(struct wd_ctx_range *) * CTX_MODE_MAX);
	if (!ctx_table)
		return -WD_ENOMEM;

	for (i = 0; i < CTX_MODE_MAX; i++) {
		ctx_table[i] = calloc(1,
				sizeof(struct wd_ctx_range) *
				config->op_type_num);
		if (!ctx_table[i]) {
			ret = -WD_ENOMEM;
			goto free_mem;
		}
	}

	config->ctx_table = ctx_table;

	return 0;

free_mem:
	for (j = 0; j < i; j++)
		free(ctx_table[j]);

	free(ctx_table);
	return ret;
}

static void wd_free_ctx_table_per_numa(struct wd_env_config_per_numa *config)
{
	int i;

	if (!config->ctx_table)
		return;

	for (i = 0; i < CTX_MODE_MAX; i++)
		free(config->ctx_table[i]);

	free(config->ctx_table);
	config->ctx_table = NULL;
}

static void wd_free_ctx_table(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa;
	int i;

	FOREACH_NUMA(i, config, config_numa)
		wd_free_ctx_table_per_numa(config_numa);
}

static int get_and_fill_ctx_num(struct wd_env_config_per_numa *config_numa,
				const char *p, int ctx_num)
{
	struct wd_ctx_range **ctx_table = config_numa->ctx_table;
	const char *type;
	int i, j;

	/**
	 * There're two types of environment variables, mode:num@node and
	 * mode-type:num@node, parse ctx num with comp_ctx_type and ctx_type.
	 */

	for (i = 0; i < CTX_MODE_MAX; i++)
		for (j = 0; j < config_numa->op_type_num; j++) {
			if (config_numa->op_type_num == 1)
				type = ctx_mode_type[i][j];
			else
				type = comp_ctx_type[i][j];

			if (!strncmp(p, type, strlen(type))) {
				ctx_table[i][j].size = ctx_num;
				return 0;
			}
		}

	return -WD_EINVAL;
}

static int wd_parse_section(struct wd_env_config *config, char *section)
{
	struct wd_env_config_per_numa *config_numa;
	int ctx_num, node, ret;
	char *ctx_section;

	ctx_section = index(section, ':');
	if (!ctx_section) {
		WD_ERR("invalid: ctx section got wrong format: %s!\n", section);
		return -WD_EINVAL;
	}

	ctx_section++;

	ret = parse_num_on_numa(ctx_section, &ctx_num, &node);
	if (ret)
		return ret;

	config_numa = wd_get_config_numa(config, node);
	if (!config_numa)
		return -WD_EINVAL;

	config_numa->op_type_num = config->op_type_num;
	ret = wd_alloc_ctx_table_per_numa(config_numa);
	if (ret)
		return ret;

	ret = get_and_fill_ctx_num(config_numa, section, ctx_num);
	if (ret) {
		WD_ERR("invalid: ctx section got wrong ctx type: %s!\n",
		       section);
		wd_free_ctx_table_per_numa(config_numa);
		return ret;
	}

	return 0;
}

static int get_start_ctx_index(struct wd_env_config *config,
			       struct wd_env_config_per_numa *config_numa)
{
	struct wd_env_config_per_numa *config_cur = config->config_per_numa;
	int start = 0;

	for (; config_cur < config_numa; config_cur++)
		start += config_cur->sync_ctx_num + config_cur->async_ctx_num;

	return start;
}

static void set_ctx_index(struct wd_env_config_per_numa *config_numa,
			  __u8 mode, int *start)
{
	struct wd_ctx_range **ctx_table = config_numa->ctx_table;
	int size, i, sum = 0;

	for (i = 0; i < config_numa->op_type_num; i++)
		sum += ctx_table[mode][i].size;

	if (mode)
		config_numa->async_ctx_num = sum;
	else
		config_numa->sync_ctx_num = sum;

	if (!sum)
		return;

	for (i = 0; i < config_numa->op_type_num; i++) {
		size = ctx_table[mode][i].size;
		if (!size)
			continue;
		ctx_table[mode][i].begin = *start;
		ctx_table[mode][i].end = *start + size - 1;
		*start += size;
	}
}

static void wd_fill_ctx_table(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa;
	int start, i, j;

	FOREACH_NUMA(i, config, config_numa) {
		if (!config_numa->ctx_table)
			continue;

		start = get_start_ctx_index(config, config_numa);
		for (j = 0; j < CTX_MODE_MAX; j++)
			set_ctx_index(config_numa, j, &start);
	}
}

static int parse_ctx_num(struct wd_env_config *config, const char *s)
{
	char *left, *section, *start;
	int ret;

	start = strdup(s);
	if (!start)
		return -WD_ENOMEM;

	left = start;

	while ((section = strsep(&left, ","))) {
		ret = wd_parse_section(config, section);
		if (ret)
			goto err_free_ctx_table;
	}

	wd_fill_ctx_table(config);
	free(start);

	return 0;

err_free_ctx_table:
	wd_free_ctx_table(config);
	free(start);
	return ret;
}

int wd_parse_ctx_num(struct wd_env_config *config, const char *s)
{
	return parse_ctx_num(config, s);
}

static int wd_parse_env(struct wd_env_config *config)
{
	const struct wd_config_variable *var;
	const char *var_s;
	int ret;
	__u32 i;

	for (i = 0; i < config->table_size; i++) {
		var = config->table + i;

		var_s = secure_getenv(var->name);
		if (!var_s || !strlen(var_s)) {
			var_s = var->def_val;
			WD_INFO("no %s environment variable! Use default: %s\n",
				var->name, var->def_val);
		}

		ret = var->parse_fn(config, var_s);
		if (ret) {
			WD_ERR("failed to parse %s environment variable!\n",
			       var->name);
			return -WD_EINVAL;
		}
	}

	return 0;
}

static int wd_parse_ctx_attr(struct wd_env_config *env_config,
			     struct wd_ctx_attr *attr)
{
	struct wd_env_config_per_numa *config_numa;
	int ret;

	config_numa = wd_get_config_numa(env_config, attr->node);
	if (!config_numa)
		return -WD_EINVAL;

	config_numa->op_type_num = env_config->op_type_num;
	ret = wd_alloc_ctx_table_per_numa(config_numa);
	if (ret)
		return ret;

	config_numa->ctx_table[attr->mode][attr->type].size = attr->num;
	wd_fill_ctx_table(env_config);

	/* Use default sched and disable internal poll */
	env_config->sched = NULL;

	return 0;
}

static int wd_init_env_config(struct wd_env_config *config,
			      struct wd_ctx_attr *attr,
			      const struct wd_alg_ops *ops,
			      const struct wd_config_variable *table,
			      __u32 table_size)
{
	config->op_type_num = ops->op_type_num;
	config->table_size = table_size;
	config->table = table;

	return attr ? wd_parse_ctx_attr(config, attr) : wd_parse_env(config);
}

static void wd_uninit_env_config(struct wd_env_config *config)
{
	wd_free_ctx_table(config);

	config->op_type_num = 0;
	config->table_size = 0;
	config->table = NULL;
}

static __u8 get_ctx_mode(struct wd_env_config_per_numa *config, __u32 idx)
{
	struct wd_ctx_range **ctx_table = config->ctx_table;
	__u32 i;

	for (i = 0; i < config->op_type_num; i++) {
		if ((idx >= ctx_table[CTX_MODE_SYNC][i].begin) &&
		    (idx <= ctx_table[CTX_MODE_SYNC][i].end) &&
		    ctx_table[CTX_MODE_SYNC][i].size)
			return CTX_MODE_SYNC;
	}
	return CTX_MODE_ASYNC;
}

static int get_op_type(struct wd_env_config_per_numa *config,
		       __u32 idx, __u8 ctx_mode)
{
	struct wd_ctx_range **ctx_table = config->ctx_table;
	__u32 i;

	if (config->op_type_num == 1)
		return 0;

	for (i = 0; i < config->op_type_num; i++) {
		if ((idx >= ctx_table[ctx_mode][i].begin) &&
		    (idx <= ctx_table[ctx_mode][i].end) &&
		    ctx_table[ctx_mode][i].size)
			return i;
	}

	WD_ERR("failed to get op type!\n");
	return -WD_EINVAL;
}

static handle_t request_ctx_on_numa(struct wd_env_config_per_numa *config)
{
	struct uacce_dev *dev;
	handle_t h_ctx;
	int i, ctx_num;

	for (i = 0; i < config->dev_num; i++) {
		dev = config->dev + i;
		ctx_num = wd_get_avail_ctx(dev);
		if (ctx_num <= 0)
			continue;

		h_ctx = wd_request_ctx(dev);
		if (h_ctx)
			return h_ctx;
	}

	return 0;
}

static int wd_get_wd_ctx(struct wd_env_config_per_numa *config,
			 struct wd_ctx_config *ctx_config, __u32 start)
{
	int ctx_num = config->sync_ctx_num + config->async_ctx_num;
	handle_t h_ctx;
	__u32 i, j;
	int ret;

	if (!ctx_num)
		return 0;

	for (i = start; i < start + ctx_num; i++) {
		h_ctx = request_ctx_on_numa(config);
		if (!h_ctx) {
			ret = -WD_EBUSY;
			WD_ERR("failed to request more ctxs!\n");
			goto free_ctx;
		}

		ctx_config->ctxs[i].ctx = h_ctx;
		ctx_config->ctxs[i].ctx_mode = get_ctx_mode(config, i);
		ret = get_op_type(config, i, ctx_config->ctxs[i].ctx_mode);
		if (ret < 0) {
			wd_release_ctx(ctx_config->ctxs[i].ctx);
			goto free_ctx;
		}

		ctx_config->ctxs[i].op_type = ret;
	}

	return 0;

free_ctx:
	for (j = start; j < i; j++)
		wd_release_ctx(ctx_config->ctxs[j].ctx);
	return ret;
}

static void wd_put_wd_ctx(struct wd_ctx_config *ctx_config, __u32 ctx_num)
{
	__u32 i;

	for (i = 0; i < ctx_num; i++)
		wd_release_ctx(ctx_config->ctxs[i].ctx);
}

static int wd_alloc_ctx(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa;
	struct wd_ctx_config *ctx_config;
	__u32 i, ctx_num = 0, start = 0;
	int ret;

	config->ctx_config = calloc(1, sizeof(*ctx_config));
	if (!config->ctx_config)
		return -WD_ENOMEM;

	ctx_config = config->ctx_config;

	FOREACH_NUMA(i, config, config_numa)
		ctx_num += config_numa->sync_ctx_num + config_numa->async_ctx_num;

	ctx_config->ctxs = calloc(ctx_num, sizeof(struct wd_ctx));
	if (!ctx_config->ctxs) {
		ret = -WD_ENOMEM;
		goto err_free_ctx_config;
	}
	ctx_config->ctx_num = ctx_num;

	FOREACH_NUMA(i, config, config_numa) {
		ret = wd_get_wd_ctx(config_numa, ctx_config, start);
		if (ret)
			goto err_free_ctxs;

		start += config_numa->sync_ctx_num + config_numa->async_ctx_num;
	}

	return 0;

err_free_ctxs:
	wd_put_wd_ctx(ctx_config, start);
	free(ctx_config->ctxs);
err_free_ctx_config:
	free(ctx_config);
	config->ctx_config = NULL;
	return ret;
}

static void wd_free_ctx(struct wd_env_config *config)
{
	struct wd_ctx_config *ctx_config;

	if (!config->ctx_config)
		return;

	ctx_config = config->ctx_config;
	wd_put_wd_ctx(ctx_config, ctx_config->ctx_num);
	free(ctx_config->ctxs);
	free(ctx_config);
	config->ctx_config = NULL;
}

static int wd_sched_fill_table(struct wd_env_config_per_numa *config_numa,
			       struct wd_sched *sched, __u8 mode, int type_num)
{
	struct wd_ctx_range **ctx_table;
	struct sched_params param;
	int i, ret, ctx_num;

	if (mode)
		ctx_num = config_numa->async_ctx_num;
	else
		ctx_num = config_numa->sync_ctx_num;

	ctx_table = config_numa->ctx_table;
	param.numa_id = config_numa->node;
	param.mode = mode;
	for (i = 0; i < type_num && ctx_num; i++) {
		if (!ctx_table[mode][i].size)
			continue;

		param.type = i;
		param.begin = ctx_table[mode][i].begin;
		param.end = ctx_table[mode][i].end;
		param.ctx_prop = UADK_ALG_HW;
		ret = wd_sched_rr_instance(sched, &param);
		if (ret)
			return ret;
	}

	return 0;
}

static void wd_uninit_sched_config(struct wd_env_config *config)
{
	if (!config->sched || !config->internal_sched)
		return;

	wd_sched_rr_release(config->sched);
	config->sched = NULL;
}

static int wd_init_sched_config(struct wd_env_config *config,
				void *alg_poll_ctx)
{
	struct wd_env_config_per_numa *config_numa;
	int i, j, ret, max_node, type_num;

	type_num = config->op_type_num;
	max_node = numa_max_node() + 1;
	if (max_node <= 0)
		return -WD_EINVAL;

	config->internal_sched = false;
	if (!config->sched) {
		WD_ERR("no sched is specified, alloc a default sched!\n");
		config->sched = wd_sched_rr_alloc(SCHED_POLICY_RR, type_num,
						  max_node, alg_poll_ctx);
		if (!config->sched)
			return -WD_ENOMEM;

		config->internal_sched = true;
	}

	config->sched->name = "SCHED_RR";

	FOREACH_NUMA(i, config, config_numa) {
		for (j = 0; j < CTX_MODE_MAX; j++) {
			ret = wd_sched_fill_table(config_numa,
						  config->sched, j,
						  type_num);
			if (ret)
				goto err_release_sched;
		}
	}

	return 0;

err_release_sched:
	wd_uninit_sched_config(config);

	return ret;
}

static int wd_init_resource(struct wd_env_config *config,
			    const struct wd_alg_ops *ops)
{
	int ret;

	ret = wd_alloc_ctx(config);
	if (ret)
		return ret;

	ret = wd_init_sched_config(config, ops->alg_poll_ctx);
	if (ret)
		goto err_uninit_ctx;

	ret = ops->alg_init(config->ctx_config, config->sched);
	if (ret)
		goto err_uninit_sched;

	return 0;

err_uninit_sched:
	wd_uninit_sched_config(config);
err_uninit_ctx:
	wd_free_ctx(config);
	return ret;
}

static void wd_uninit_resource(struct wd_env_config *config,
			       const struct wd_alg_ops *ops)
{
	ops->alg_uninit();
	wd_uninit_sched_config(config);
	wd_free_ctx(config);
}

int wd_alg_env_init(struct wd_env_config *env_config,
		    const struct wd_config_variable *table,
		    const struct wd_alg_ops *ops,
		    __u32 table_size,
		    struct wd_ctx_attr *ctx_attr)
{
	int ret;

	ret = wd_alloc_numa(env_config, ops);
	if (ret)
		return ret;

	ret = wd_init_env_config(env_config, ctx_attr, ops, table, table_size);
	if (ret)
		goto free_numa;

	ret = wd_init_resource(env_config, ops);
	if (ret)
		goto uninit_env_config;

	return 0;

uninit_env_config:
	wd_uninit_env_config(env_config);
free_numa:
	wd_free_numa(env_config);
	return ret;
}

void wd_alg_env_uninit(struct wd_env_config *env_config,
		       const struct wd_alg_ops *ops)
{
	wd_uninit_resource(env_config, ops);
	wd_uninit_env_config(env_config);
	wd_free_numa(env_config);
}

int wd_alg_get_env_param(struct wd_env_config *env_config,
			 struct wd_ctx_attr attr,
			 __u32 *num, __u8 *is_enable)
{
	struct wd_env_config_per_numa *config_numa;

	if (!num || !is_enable) {
		WD_ERR("invalid: input pointer num or is_enable is NULL!\n");
		return -WD_EINVAL;
	}

	*is_enable = 0;

	config_numa = wd_get_config_numa(env_config, attr.node);
	if (!config_numa)
		return -WD_EINVAL;

	*num = (config_numa->ctx_table) ?
	       config_numa->ctx_table[attr.mode][attr.type].size : 0;

	return 0;
}

int wd_set_ctx_attr(struct wd_ctx_attr *ctx_attr,
		     __u32 node, __u32 type, __u8 mode, __u32 num)
{
	if (mode >= CTX_MODE_MAX) {
		WD_ERR("invalid: ctx mode is %u!\n", mode);
		return -WD_EINVAL;
	}

	ctx_attr->node = node;
	ctx_attr->mode = mode;
	ctx_attr->num = num;
	/* If type is CTX_TYPE_INVALID, we need update it to 0. */
	ctx_attr->type = (type == CTX_TYPE_INVALID) ? 0 : type;

	return 0;
}

int wd_check_ctx(struct wd_ctx_config_internal *config, __u8 mode, __u32 idx)
{
	struct wd_ctx_internal *ctx;

	if (unlikely(idx == QUEUE_FULL_POS))
		return -WD_EBUSY;

	if (unlikely(idx >= config->ctx_num)) {
		WD_ERR("failed to pick a proper ctx: idx %u!\n", idx);
		return -WD_EINVAL;
	}

	ctx = config->ctxs + idx;
	if (ctx->ctx_mode != mode) {
		WD_ERR("invalid: ctx(%u) mode is %hhu!\n", idx, ctx->ctx_mode);
		return -WD_EINVAL;
	}

	return 0;
}

int wd_set_epoll_en(const char *var_name, bool *epoll_en)
{
	const char *s;
	int ret;

	s = secure_getenv(var_name);
	if (!s || !strlen(s)) {
		*epoll_en = 0;
		return 0;
	}

	ret = str_to_bool(s, epoll_en);
	if (ret) {
		WD_ERR("failed to parse %s!\n", var_name);
		return ret;
	}

	if (*epoll_en)
		WD_ERR("epoll wait is enabled!\n");

	return 0;
}

int wd_handle_msg_sync(struct wd_msg_handle *msg_handle, handle_t ctx,
		       void *msg, __u64 *balance, bool epoll_en)
{
	__u64 timeout = WD_RECV_MAX_CNT_NOSLEEP;
	__u64 rx_cnt = 0;
	int ret;

	if (balance)
		timeout = WD_RECV_MAX_CNT_SLEEP;

	ret = msg_handle->send(ctx, msg);
	if (unlikely(ret < 0)) {
		WD_ERR("failed to send msg to hw, ret = %d!\n", ret);
		return ret;
	}

	do {
		if (epoll_en) {
			ret = wd_ctx_wait(ctx, POLL_TIME);
			if (unlikely(ret < 0))
				WD_ERR("wd ctx wait timeout(%d)!\n", ret);
		}

		ret = msg_handle->recv(ctx, msg);
		if (ret != -WD_EAGAIN) {
			if (unlikely(ret < 0)) {
				WD_ERR("failed to recv msg: error = %d!\n", ret);
				return ret;
			}
			break;
		}

		rx_cnt++;
		if (unlikely(rx_cnt >= timeout)) {
			WD_ERR("failed to recv msg: timeout!\n");
			return -WD_ETIMEDOUT;
		}

		if (balance && *balance > WD_BALANCE_THRHD)
			usleep(1);
	} while (1);

	if (balance)
		*balance = rx_cnt;

	return ret;
}

int wd_init_param_check(struct wd_ctx_config *config, struct wd_sched *sched)
{
	if (!config || !config->ctxs || !config->ctxs[0].ctx) {
		WD_ERR("invalid: wd_ctx_config is NULL!\n");
		return -WD_EINVAL;
	}

	if (!sched) {
		WD_ERR("invalid: wd_sched is NULL!\n");
		return -WD_EINVAL;
	}

	return 0;
}

int wd_alg_try_init(enum wd_status *status)
{
	enum wd_status expected;
	__u32 count = 0;
	bool ret;

	/*
	 * Here is aimed to protect the security of the initialization interface
	 * in the multi-thread scenario. Only one thread can get the WD_INITING
	 * status to initialize algorithm. Other thread will wait for the result.
	 * And the algorithm initialization interfaces is a liner process.
	 * So the initing thread will return a result to notify other thread go on.
	 */
	do {
		expected = WD_UNINIT;
		ret = __atomic_compare_exchange_n(status, &expected, WD_INITING, true,
						  __ATOMIC_RELAXED, __ATOMIC_RELAXED);
		if (expected == WD_INIT) {
			WD_ERR("The algorithm has been initialized!\n");
			return -WD_EEXIST;
		}
		usleep(WD_INIT_SLEEP_UTIME);

		if (US2S(WD_INIT_SLEEP_UTIME * ++count) >= WD_INIT_RETRY_TIMEOUT) {
			WD_ERR("The algorithm initialize wait timeout!\n");
			return -WD_ETIMEDOUT;
		}
	} while (!ret);

	return 0;
}

static int wd_alg_init_fallback(struct wd_alg_driver *fb_driver)
{
	if (!fb_driver->init) {
		WD_ERR("soft acc driver have no init interface.\n");
		return -WD_EINVAL;
	}

	fb_driver->init(NULL, NULL);

	return 0;
}

static void wd_alg_uninit_fallback(struct wd_alg_driver *fb_driver)
{
	if (!fb_driver->exit) {
		WD_ERR("soft acc driver have no exit interface.\n");
		return;
	}

	fb_driver->exit(NULL);
}

static int wd_ctx_init_driver(struct wd_ctx_config_internal *config,
					struct wd_alg_driver *driver)
{
	void *priv;
	int ret;

	if (!driver || !driver->priv_size)
		return -WD_EINVAL;

	if (driver->ops_size) {
		driver->extend_ops = calloc(1, driver->ops_size);
		if (!driver->extend_ops)
			return -WD_ENOMEM;
	} else {
		driver->extend_ops = NULL;
	}

	priv = calloc(1, driver->priv_size);
	if (!priv) {
		if (driver->extend_ops)
			free(driver->extend_ops);

		return -WD_ENOMEM;
	}

	ret = driver->init(config, priv);
	if (ret < 0) {
		if (driver->extend_ops)
			free(driver->extend_ops);

		free(priv);
		return ret;
	}
	driver->drv_data = priv;

	if (driver->fallback) {
		ret = wd_alg_init_fallback((struct wd_alg_driver *)driver->fallback);
		if (ret)
			driver->fallback = 0;
	}

	return 0;
}

static void wd_ctx_uninit_driver(struct wd_alg_driver *driver)
{
	void *priv;

	if (!driver)
		return;
	priv = driver->drv_data;
	if (!priv)
		return;
	driver->exit(priv);
	free(priv);
	driver->drv_data = NULL;
	if (driver->extend_ops) {
		free(driver->extend_ops);
		driver->extend_ops = NULL;
	}

	if (driver->fallback)
		wd_alg_uninit_fallback((struct wd_alg_driver *)driver->fallback);
}

int wd_alg_init_driver(struct wd_ctx_config_internal *config)
{
	__u32 i, j;
	int ret;

	/* Only initialize the drivers that have been filtered and selected for use. */
	for (i = 0; i < config->drv_count; i++) {
		ret = wd_ctx_init_driver(config, config->drv_array[i]);
		if (ret)
			goto init_err;
	}

	return 0;

init_err:
	for (j = 0; j < i; j++)
		wd_ctx_uninit_driver(config->drv_array[j]);
	/* Ctx config just need clear once */
	wd_clear_ctx_config(config);

	return ret;
}

void wd_alg_uninit_driver(struct wd_ctx_config_internal *config)
{
	__u32 i;

	for (i = 0; i < config->drv_count; i++)
		wd_ctx_uninit_driver(config->drv_array[i]);

	/* Ctx config just need clear once */
	wd_clear_ctx_config(config);
}

void wd_dlclose_drv(void *dlh_list)
{
	struct drv_lib_list *dlhead = (struct drv_lib_list *)dlh_list;
	struct drv_lib_list *dlnode;

	if (!dlhead) {
		WD_INFO("driver so file list is empty.\n");
		return;
	}

	while (dlhead) {
		dlnode = dlhead;
		dlhead = dlhead->next;
		dlclose(dlnode->dlhandle);
		free(dlnode);
	}
}

static void add_lib_to_list(struct drv_lib_list *head,
			    struct drv_lib_list *node)
{
	struct drv_lib_list *tmp = head;

	while (tmp->next)
		tmp = tmp->next;

	tmp->next = node;
}

static int wd_set_ctx_nums(struct wd_ctx_params *ctx_params,
			   const char *section, __u32 op_type_num, int is_comp)
{
	struct wd_ctx_nums *ctxs = ctx_params->ctx_set_num;
	int ret, ctx_num, node;
	char *ctx_section;
	const char *type;
	__u32 i, j;

	ctx_section = index(section, ':');
	if (!ctx_section) {
		WD_ERR("invalid: ctx section got wrong format: %s!\n", section);
		return -WD_EINVAL;
	}
	ctx_section++;
	ret = parse_num_on_numa(ctx_section, &ctx_num, &node);
	if (ret)
		return ret;

	/* If the number of ctxs is set to 0, skip the configuration */
	if (!ctx_num)
		return 0;

	/* Validate node is within the system's NUMA node range */
	if (node < 0 || node > numa_max_node()) {
		WD_ERR("invalid: numa node %d exceeds system max node %d!\n",
		       node, numa_max_node());
		return -WD_EINVAL;
	}

	for (i = 0; i < CTX_MODE_MAX; i++) {
		for (j = 0; j < op_type_num; j++) {
			type = is_comp ? comp_ctx_type[i][j] : ctx_mode_type[i][0];
			if (strncmp(section, type, strlen(type)))
				continue;

			/* If there're multiple configurations, use the maximum ctx number */
			if (!i)
				ctxs[j].sync_ctx_num = MAX(ctxs[j].sync_ctx_num, (__u32)ctx_num);
			else
				ctxs[j].async_ctx_num = MAX(ctxs[j].async_ctx_num, (__u32)ctx_num);

			/* enable a node here, all enabled nodes share the same configuration */
			numa_bitmask_setbit(ctx_params->bmp, node);
			return 0;
		}
	}

	return -WD_EINVAL;
}

static int wd_env_set_ctx_nums(const char *alg_name, const char *name, const char *var_s,
			       struct wd_ctx_params *ctx_params, __u32 op_type_num)
{
	char *left, *section, *start;
	int is_comp;
	int ret;

	/* COMP environment variable's format is different, mark it */
	is_comp = strncmp(name, "WD_COMP_CTX_NUM", sizeof("WD_COMP_CTX_NUM") - 1) ? 0 : 1;
	if (is_comp && op_type_num > ARRAY_SIZE(comp_ctx_type))
		return -WD_EINVAL;

	start = strdup(var_s);
	if (!start)
		return -WD_ENOMEM;

	left = start;
	while ((section = strsep(&left, ","))) {
		ret = wd_set_ctx_nums(ctx_params, section, op_type_num, is_comp);
		if (ret < 0)
			break;
	}

	free(start);
	return ret;
}

void wd_ctx_param_uninit(struct wd_ctx_params *ctx_params)
{
	numa_free_nodemask(ctx_params->bmp);
}

int wd_ctx_param_init(struct wd_ctx_params *ctx_params,
		      struct wd_ctx_params *user_ctx_params,
		      char *alg, enum wd_type type,
		      int max_op_type)
{
	const char *env_name = wd_env_name[type];
	const char *var_s;
	int i, ret;

	ctx_params->bmp = numa_allocate_nodemask();
	if (!ctx_params->bmp) {
		WD_ERR("fail to allocate nodemask.\n");
		return -WD_ENOMEM;
	}

	/* Only hw driver support environment variable */
	var_s = secure_getenv(env_name);
	if (var_s && strlen(var_s)) {
		/* environment variable has the highest priority */
		ret = wd_env_set_ctx_nums(alg, env_name, var_s,
					  ctx_params, max_op_type);
		if (ret) {
			WD_ERR("fail to init ctx nums from %s!\n", env_name);
			numa_free_nodemask(ctx_params->bmp);
			return ret;
		}
	} else {
		/* environment variable is not set, try to use user_ctx_params first */
		if (user_ctx_params) {
			copy_bitmask_to_bitmask(user_ctx_params->bmp, ctx_params->bmp);
			if (user_ctx_params->op_type_num > (__u32)max_op_type) {
				WD_ERR("fail to check user op type numbers.\n");
				numa_free_nodemask(ctx_params->bmp);
				return -WD_EINVAL;
			}
			ctx_params->cap = user_ctx_params->cap;
			ctx_params->ctx_set_num = user_ctx_params->ctx_set_num;
			ctx_params->op_type_num = user_ctx_params->op_type_num;

			return 0;
		}
		/* user_ctx_params is also not set, use driver's defalut queue_num */
		numa_bitmask_setall(ctx_params->bmp);
		for (i = 0; i < max_op_type; i++) {
			ctx_params->ctx_set_num[i].sync_ctx_num = 1;
			ctx_params->ctx_set_num[i].async_ctx_num = 1;
		}
	}
	ctx_params->op_type_num = max_op_type;

	return 0;
}

static void dladdr_empty(void)
{
}

static int line_check_valid(char *line)
{
	line[strcspn(line, "\n")] = 0;
	if (line[0] == '\0' || line[0] == '#')
		return 0;

	if (!strstr(line, ".so"))
		return 0;

	return 1;
}

static int check_uadk_config_file(const char *wd_dir, const char *lib_file)
{
	char *path_buf, *uadk_cnf_path, *line;
	int ret = -WD_EINVAL;
	FILE *fp;

	path_buf = calloc(WD_PATH_DIR_NUM, PATH_MAX);
	if (!path_buf) {
		WD_ERR("fail to alloc memery for path_buf.\n");
		return -WD_ENOMEM;
	}

	uadk_cnf_path = path_buf;
	line = path_buf + PATH_MAX;

	snprintf(uadk_cnf_path, PATH_MAX, "%s/%s/%s", wd_dir, WD_DRV_LIB_DIR,
		 WD_DRV_CONF_FILE);
	fp = fopen(uadk_cnf_path, "r");
	if (!fp) {
		ret = 0;
		goto free_buf;
	}

	while (fgets(line, PATH_MAX, fp)) {
		if (!line_check_valid(line))
			continue;

		if (strstr(line, lib_file)) {
			ret = 0;
			goto close_fp;
		}
	}

close_fp:
	fclose(fp);
free_buf:
	free(path_buf);
	return ret;
}

int wd_get_lib_file_path(const char *lib_file, char *lib_path, bool is_dir)
{
	char *path_buf, *path, *file_path;
	Dl_info file_info;
	int len, rc, i;
	int ret = 0;

	/* Get libwd.so file's system path */
	rc = dladdr(dladdr_empty, &file_info);
	if (!rc) {
		WD_ERR("fail to get lib file path.\n");
		return -WD_EINVAL;
	}

	path_buf = calloc(WD_PATH_DIR_NUM, PATH_MAX);
	if (!path_buf) {
		WD_ERR("fail to calloc path_buf.\n");
		return -WD_ENOMEM;
	}
	file_path = path_buf;
	path = path_buf + PATH_MAX;
	strncpy(file_path, file_info.dli_fname, PATH_MAX - 1);

	/* Clear the file path's tail file name */
	len = strlen(file_path) - 1;
	for (i = len; i >= 0; i--) {
		if (file_path[i] == '/') {
			memset(&file_path[i], 0, PATH_MAX - i);
			break;
		}
	}

	if (is_dir) {
		len = snprintf(lib_path, PATH_MAX, "%s/%s", file_path, WD_DRV_LIB_DIR);
	} else {
		/* Confirm whether the corresponding file exists in uadk.cnf */
		ret = check_uadk_config_file(file_path, lib_file);
		if (ret)
			goto free_path;

		len = snprintf(lib_path, PATH_MAX, "%s/%s/%s",
			       file_path, WD_DRV_LIB_DIR, lib_file);
	}

	if (len >= PATH_MAX) {
		ret = -WD_EINVAL;
		goto free_path;
	}

	if (!realpath(lib_path, path)) {
		WD_ERR("invalid: %s: no such file or directory!\n", path);
		ret = -WD_EINVAL;
	}

free_path:
	free(path_buf);
	return ret;
}

/*
 * There are many other .so files in this file directory (/root/lib/),
 * and it is necessary to screen out valid uadk driver files
 * through this function.
 */
static int file_check_valid(const char *lib_file)
{
#define MIN_FILE_LEN 6
#define FILE_TAIL_LEN 3
	const char *dot = strrchr(lib_file, '.');
	size_t len;

	/* Check if the filename length is sufficient. */
	len = strlen(lib_file);
	if (len < MIN_FILE_LEN)
		return -EINVAL;

	/* Check if it starts with "lib". */
	if (strncmp(lib_file, "lib", FILE_TAIL_LEN) != 0)
		return -EINVAL;

	/* Check if it ends with ".so". */
	if (!dot || strcmp(dot, ".so") != 0)
		return -EINVAL;

	return 0;
}

static void create_lib_to_list(const char *lib_path, struct drv_lib_list **head)
{
	typedef int (*alg_ops)(struct wd_alg_driver *drv);
	struct drv_lib_list *node;
	alg_ops dl_func;

	node = calloc(1, sizeof(*node));
	if (!node)
		return;

	node->dlhandle = dlopen(lib_path, RTLD_NODELETE | RTLD_NOW);
	if (!node->dlhandle) {
		WD_ERR("failed to open lib file: %s, err: %s\n", lib_path, dlerror());
		free(node);
		return;
	}

	dl_func = dlsym(node->dlhandle, "wd_alg_driver_register");
	if (!dl_func) {
		WD_ERR("dlsym failed for %s: %s\n", lib_path, dlerror());
		dlclose(node->dlhandle);
		free(node);
		return;
	}

	if (!*head) {
		*head = node;
		return;
	}
	add_lib_to_list(*head, node);
}

static struct drv_lib_list *load_libraries_from_config(const char *config_path,
						       const char *lib_dir_path)
{
	char *lib_path, *line;
	struct drv_lib_list *head = NULL;
	FILE *config_file;
	int ret;

	lib_path = calloc(1, PATH_MAX);
	if (!lib_path) {
		WD_ERR("Failed to alloc memery for lib_path.\n");
		return head;
	}

	line = calloc(1, PATH_MAX);
	if (!line) {
		WD_ERR("Failed to alloc memery for lib_line.\n");
		goto free_path;
	}

	config_file = fopen(config_path, "r");
	if (!config_file) {
		WD_ERR("Failed to open config file: %s\n", config_path);
		goto free_line;
	}

	/* Read config file line by line */
	while (fgets(line, PATH_MAX, config_file)) {
		if (!line_check_valid(line))
			continue;

		ret = snprintf(lib_path, PATH_MAX, "%s/%s", lib_dir_path, line);
		if (ret < 0)
			break;

		create_lib_to_list(lib_path, &head);
	}

	fclose(config_file);

free_line:
	free(line);
free_path:
	free(lib_path);
	return head;
}

static struct drv_lib_list *load_all_libraries(DIR *wd_dir, const char *lib_dir_path)
{
	struct drv_lib_list *head = NULL;
	struct dirent *lib_dir;
	char *lib_path;
	int ret;

	lib_path = calloc(1, PATH_MAX);
	if (!lib_path) {
		WD_ERR("fail to alloc memery for lib_path.\n");
		return NULL;
	}

	rewinddir(wd_dir); /* Ensure we're at the start of the directory */

	while ((lib_dir = readdir(wd_dir)) != NULL) {
		if (!strncmp(lib_dir->d_name, ".", LINUX_CRTDIR_SIZE) ||
		    !strncmp(lib_dir->d_name, "..", LINUX_PRTDIR_SIZE))
			continue;

		ret = file_check_valid(lib_dir->d_name);
		if (ret)
			continue;

		ret = snprintf(lib_path, PATH_MAX, "%s/%s", lib_dir_path, lib_dir->d_name);
		if (ret < 0)
			break;

		create_lib_to_list(lib_path, &head);
	}

	free(lib_path);
	return head;
}

void *wd_dlopen_drv(const char *cust_lib_dir)
{
	char *path_buf, *lib_dir_path, *config_path, *lib_path;
	struct drv_lib_list *head = NULL;
	int ret, len;
	DIR *wd_dir;

	path_buf = calloc(WD_PATH_DIR_NUM, PATH_MAX);
	if (!path_buf) {
		WD_ERR("Failed to alloc memory for path_buf buffers.\n");
		return head;
	}

	config_path = calloc(1, PATH_MAX);
	if (!config_path) {
		WD_ERR("Failed to alloc memory for config_path buffers.\n");
		free(path_buf);
		return head;
	}

	lib_dir_path = path_buf;
	lib_path = path_buf + PATH_MAX;

	if (!cust_lib_dir) {
		ret = wd_get_lib_file_path(NULL, lib_dir_path, true);
		if (ret)
			goto free_path;
	} else {
		if (!realpath(cust_lib_dir, lib_path)) {
			WD_ERR("invalid: %s: no such file or directory!\n", lib_path);
			goto free_path;
		}

		len = snprintf(lib_dir_path, PATH_MAX, "%s", cust_lib_dir);
		if (len < 0 || len >= PATH_MAX)
			goto free_path;

		lib_dir_path[PATH_MAX - 1] = '\0';
	}

	wd_dir = opendir(lib_dir_path);
	if (!wd_dir) {
		WD_ERR("UADK driver lib dir: %s not exist!\n", lib_dir_path);
		goto free_path;
	}

	len = snprintf(config_path, PATH_MAX, "%s/%s", lib_dir_path, WD_DRV_CONF_FILE);
	if (len < 0 || len >= PATH_MAX)
		goto close_dir;

	ret = access(config_path, F_OK);
	if (!ret)
		/* Load specified libraries from config file */
		head = load_libraries_from_config(config_path, lib_dir_path);
	else
		/* Load all valid .so files */
		head = load_all_libraries(wd_dir, lib_dir_path);

close_dir:
	closedir(wd_dir);
free_path:
	free(path_buf);
	free(config_path);
	return (void *)head;
}

/**
 * wd_ctx_unbind_drivers() - Unbind drivers from internal contexts.
 *
 * Decrements driver refcounts and clears all drv pointers.
 *
 * @config: Internal ctx config
 */
void wd_ctx_unbind_drivers(struct wd_ctx_config_internal *config)
{
	__u32 i;

	if (!config || !config->drv_array)
		return;

	wd_alg_drv_ref_dec(config->drv_array, config->drv_count);

	for (i = 0; i < config->ctx_num; i++)
		config->ctxs[i].drv = NULL;
}

/**
 * wd_ctx_bind_drivers() - Bind drivers to internal contexts via round-robin.
 *
 * This is the single write point for ctxs[i].drv in the entire lifecycle.
 * Uses RR rule: ctxs[i].drv = drv_array[i % drv_count]
 *
 * Also:
 * - Sets up soft fallback for HW drivers (once per unique HW driver)
 * - Caches drv_array in config for session queries
 * - Increments driver refcounts (deduplicated: each unique driver +1)
 *
 * @config:    Internal ctx config (ctxs[] already copied by wd_init_ctx_config)
 * @drv_array: Discovered unique drivers
 * @drv_count: Number of unique drivers
 * Return: 0 on success, negative on failure
 */
int wd_ctx_bind_drivers(struct wd_ctx_config_internal *config_api,
			struct wd_ctx_config_internal *config_in, int init_type)
{
	struct wd_alg_driver *drv;
	__u32 i;

	if (!config_api || init_type > WD_TYPE_V2) {
		WD_ERR("invalid: parameters are NULL!\n");
		return -WD_EINVAL;
	}

	if (init_type == WD_TYPE_V1) {
		if (!config_api->drv_array || config_api->drv_count != 1) {
			WD_ERR("invalid: config driver number is error!\n");
			return -WD_EINVAL;
		}
		for (i = 0; i < config_api->ctx_num; i++) {
			config_api->ctxs[i].drv = config_api->drv_array[0];
			config_api->ctxs[i].ctx_type = config_api->drv_array[0]->calc_type;
		}

		drv = config_api->drv_array[0];
		if (!drv->fallback) {
			drv->fallback = (handle_t)wd_request_drv(
				config_api->alg_name, ALG_DRV_FB);
		}
		return WD_SUCCESS;
	}

	if (!config_in || !config_in->drv_array || !config_in->drv_count) {
		WD_ERR("invalid: V2 parameters, config_in=%p, drv_array=%p, ctx_num=%u!\n",
		       config_in, config_in ? config_in->drv_array : NULL,
		       config_in ? config_in->ctx_num : 0);
		return -WD_EINVAL;
	}

	WD_DEBUG("discovered %u drivers for ctx binding\n", config_in->drv_count);
	for (i = 0; i < config_in->ctx_num; i++) {
		if (!config_in->ctxs[i].drv) {
			WD_ERR("failed to check ctx<%u> driver bound in internal config!\n", i);
			continue;
		}
		/*
		 * The internally allocated queues have already been bound to the drivers,
		 * so only direct assignment processing is required here.
		 */
		config_api->ctxs[i].drv = config_in->ctxs[i].drv;
		config_api->ctxs[i].ctx_type = config_in->ctxs[i].ctx_type;
	}

	/* HW driver needs soft fallback — set once per unique driver */
	for (i = 0; i < config_in->drv_count; i++) {
		drv = config_in->drv_array[i];
		if (!drv)
			continue;

		if (drv->calc_type == UADK_ALG_HW && !drv->fallback) {
			drv->fallback = (handle_t)wd_request_drv(
				config_api->alg_name, ALG_DRV_FB);
			WD_DEBUG("Set fallback for HW driver %s\n", drv->drv_name);
		}
	}

	/* Cache driver array for session queries */
	config_api->drv_array = config_in->drv_array;
	config_api->drv_count = config_in->drv_count;

	/* Deduplicated refcount increment */
	wd_alg_drv_ref_inc(config_in->drv_array, config_in->drv_count);

	return WD_SUCCESS;
}

/**
 * wd_alg_config_uninit() - Free driver discovery result.
 *
 * Releases the drv_array allocated by wd_alg_drv_discover().
 * Does NOT touch the drivers themselves (refcount managed separately).
 *
 * @attrs: Initialization attributes
 */
void wd_alg_config_uninit(struct wd_init_attrs *attrs)
{
	struct wd_ctx_config_internal *internal_config = attrs->ctx_config_internal;

	if (!internal_config || !internal_config->drv_array)
		return;

	/* Release wd_get_drv_array alloc memory */
	wd_put_drv_array(internal_config->drv_array, internal_config->drv_count);
	internal_config->drv_array = NULL;
	internal_config->drv_count = 0;

	/* Release ctx_config_internal */
	if (internal_config->ctxs)
		free(internal_config->ctxs);
	free(internal_config);
	attrs->ctx_config_internal = NULL;
}

static __u32 wd_ctx_num_sum(struct wd_ctx_params *ctx_params,
			    struct wd_alg_driver **drv_array,
			    __u32 drv_count)
{
	__u32 total_ctx_num = 0;
	__u32 async_num = 0;
	__u32 sync_num = 0;
	__u32 numa_count = 0;
	__u32 per_driver_ctx;
	int max_node, n;
	__u32 i;

	for (i = 0; i < ctx_params->op_type_num; i++) {
		sync_num += ctx_params->ctx_set_num[i].sync_ctx_num;
		async_num += ctx_params->ctx_set_num[i].async_ctx_num;
	}
	per_driver_ctx = sync_num + async_num;

	max_node = numa_max_node() + 1;
	if (max_node <= 0 || max_node > NUMA_NUM_NODES)
		max_node = NUMA_NUM_NODES;

	for (n = 0; n < max_node; n++) {
		if (numa_bitmask_isbitset(ctx_params->bmp, n))
			numa_count++;
	}
	if (!numa_count)
		numa_count = 1;

	for (i = 0; i < drv_count; i++) {
		if (drv_array[i]->calc_type == UADK_ALG_HW)
			total_ctx_num += per_driver_ctx * numa_count;
		else
			total_ctx_num += per_driver_ctx;
	}

	WD_DEBUG("total ctxs: %u (per_driver=%u, hw_numa=%u, drv_count=%u)\n",
		 total_ctx_num, per_driver_ctx, numa_count, drv_count);

	return total_ctx_num;
}

/**
 * wd_alg_config_init() - Discover matching drivers.
 *
 * Normalizes attrs->alg to alg_type ("cipher", "digest", etc.),
 * then calls wd_get_drv_array() to find all unique drivers.
 * Results stored in attrs->drv_array and attrs->drv_count.
 * Filter drivers by sched_policy: NONE→CE, SINGLE→SVE.
 * In-place removes non-matching entries, keeps at most 1 (highest priority).
 * Returns filtered count via drv_count, or negative on no match.
 *
 * Pure query — no resource allocation, no refcount changes.
 *
 * @attrs: Initialization attributes (input: alg, task_type; output: drv_array, drv_count)
 * Return: 0 on success, negative on failure
 */
static int wd_filter_drv_by_sched(__u32 sched_type,
				  struct wd_alg_driver **drv_array,
				  __u32 *drv_count)
{
	int primary_type, fallback_type = -1;
	__u32 drv_array_cnt = *drv_count;
	__u32 i, kept = 0;

	if (sched_type == SCHED_POLICY_NONE) {
		primary_type = UADK_ALG_CE_INSTR;
	} else if (sched_type == SCHED_POLICY_SINGLE) {
		/* SINGLE: prefer SVE, fall back to CE when SVE unavailable */
		primary_type = UADK_ALG_SVE_INSTR;
		fallback_type = UADK_ALG_CE_INSTR;
	} else {
		return 0;
	}

	for (i = 0; i < drv_array_cnt; i++) {
		if (drv_array[i]->calc_type == primary_type) {
			if (kept != i)
				drv_array[kept] = drv_array[i];
			kept++;
		}
	}

	/* Fallback to secondary type only if primary yielded nothing */
	if (!kept && fallback_type >= 0) {
		for (i = 0; i < drv_array_cnt; i++) {
			if (drv_array[i]->calc_type == fallback_type) {
				if (kept != i)
					drv_array[kept] = drv_array[i];
				kept++;
			}
		}
	}

	*drv_count = kept;

	if (!kept) {
		WD_ERR("invalid: no %s driver found for %s scheduler\n",
		       sched_type == SCHED_POLICY_NONE ? "CE" : "SVE/CE",
		       sched_type == SCHED_POLICY_NONE ? "NONE" : "SINGLE");
		return -WD_EINVAL;
	}
	/* Keep only the first (highest priority) */
	if (kept > 1)
		*drv_count = 1;

	return 0;
}

int wd_alg_config_init(struct wd_init_attrs *attrs)
{
	struct wd_ctx_config_internal *internal_config = NULL;
	struct wd_alg_driver **temp_drv_array = NULL;
	char alg_type[CRYPTO_MAX_ALG_NAME] = {0};
	__u32 tmp_drv_count;
	__u32 tmp_ctx_num;
	int ret;

	if (!attrs || !attrs->alg[0] || !attrs->ctx_params)
		return -WD_EINVAL;

	/* Normalize alg to alg_type (e.g. "cipher", "digest") */
	ret = wd_get_alg_type(attrs->alg, alg_type);
	if (ret || !alg_type[0]) {
		WD_ERR("failed to get alg type for %s!\n", attrs->alg);
		return -WD_EINVAL;
	}

	/* Driver discovery */
	ret = wd_get_drv_array(alg_type, attrs->task_type, NULL,
				&temp_drv_array, &tmp_drv_count);
	if (ret || !tmp_drv_count) {
		WD_ERR("failed to get %s's driver array!\n", attrs->alg);
		goto driver_error;
	}

	/* Filter drivers by sched_policy semantic constraints */
	ret = wd_filter_drv_by_sched(attrs->sched_type, temp_drv_array, &tmp_drv_count);
	if (ret)
		goto driver_error;

	/* Calculate total sync/async context counts */
	tmp_ctx_num = wd_ctx_num_sum(attrs->ctx_params, temp_drv_array, tmp_drv_count);
	if (!tmp_ctx_num) {
		WD_ERR("invalid: total_ctx_num is zero!\n");
		ret = -WD_EINVAL;
		goto driver_error;
	}

	/* Allocate internal ctx_config structure */
	internal_config = calloc(1, sizeof(*internal_config));
	if (!internal_config) {
		ret = -WD_ENOMEM;
		WD_ERR("failed to allocate ctx_config_internal!\n");
		goto driver_error;
	}

	/* Allocate internal ctx array */
	internal_config->ctxs = calloc(tmp_ctx_num, sizeof(struct wd_ctx_internal));
	if (!internal_config->ctxs) {
		WD_ERR("failed to allocate internal ctxs array!\n");
		ret = -WD_ENOMEM;
		goto clean_config;
	}

	/* Initialize configuration */
	internal_config->ctx_num = tmp_ctx_num;
	internal_config->drv_array = temp_drv_array;
	internal_config->drv_count = tmp_drv_count;
	attrs->ctx_config_internal = internal_config;

	WD_DEBUG("Algorithm initialization started: alg=%s, task_type=%u\n",
		attrs->alg, attrs->task_type);

	return WD_SUCCESS;

clean_config:
	free(internal_config);
driver_error:
	wd_put_drv_array(temp_drv_array, tmp_drv_count);
	attrs->ctx_config_internal = NULL;
	return ret;
}

static int wd_parse_dev_id(handle_t h_ctx)
{
	struct wd_ctx_h *ctx = (struct wd_ctx_h *)h_ctx;
	char *dev_path = ctx->dev_path;
	char *last_str = NULL;
	char *endptr;
	int dev_id;

	if (!dev_path)
		return -WD_EINVAL;

	last_str = strrchr(dev_path, '-');
	if (!last_str || *(last_str + 1) == '\0')
		return -WD_EINVAL;

	dev_id = strtol(last_str + 1, &endptr, DECIMAL_NUMBER);
	if (*endptr != '\0' || dev_id < 0)
		return -WD_EINVAL;

	return dev_id;
}

static int wd_sched_ctx_region_key(handle_t ctx, __u8 ctx_type,
				   bool is_dev_policy, int *numa_id)
{
	struct wd_ctx_h *hctx;
	int dev_id;

	if (is_dev_policy) {
		dev_id = wd_parse_dev_id(ctx);
		if (dev_id < 0)
			return dev_id;

		*numa_id = dev_id;
		return dev_id;
	}

	*numa_id = 0;
	if (ctx_type != UADK_ALG_HW)
		return 0;

	hctx = (struct wd_ctx_h *)ctx;
	if (hctx->dev)
		*numa_id = hctx->dev->numa_id;

	return 0;
}

static int wd_alg_sched_instance(struct wd_sched *sched,
				 struct wd_ctx_config_internal *internal_config)
{
	struct wd_ctx_internal *cur, *nxt = NULL;
	struct sched_params sparams;
	int cur_rgn_key, cur_numa_id;
	int nxt_rgn_key, nxt_numa_id;
	__u32 seg_begin, seg_end;
	__u8 mode, inctx_type;
	__u32 op_type, i = 0;
	bool is_dev;
	int ret;

	if (!sched || !internal_config) {
		WD_ERR("invalid: sched, ctx_config, or ctx_params is NULL!\n");
		return -WD_EINVAL;
	}

	if (!sched || !internal_config || !internal_config->ctxs) {
		WD_ERR("invalid: internal_config->ctxs is NULL!\n");
		return -WD_EINVAL;
	}

	is_dev = (sched->sched_policy == SCHED_POLICY_DEV);
	for (i = 0; i < internal_config->ctx_num;) {
		cur = &internal_config->ctxs[i];
		mode = internal_config->ctxs[i].ctx_mode;
		op_type = internal_config->ctxs[i].op_type;
		inctx_type = internal_config->ctxs[i].ctx_type;

		cur_rgn_key = wd_sched_ctx_region_key(cur->ctx, inctx_type, is_dev, &cur_numa_id);
		if (cur_rgn_key < 0) {
			WD_ERR("failed to parse region key for ctx %u!\n", i);
			return -WD_EINVAL;
		}

		/* Scan forward for contiguous ctxs with identical segment key */
		seg_begin = i;
		for (seg_end = seg_begin; seg_end + 1 < internal_config->ctx_num; seg_end++) {
			nxt = &internal_config->ctxs[seg_end + 1];
			if (nxt->ctx_mode != mode || nxt->op_type != op_type ||
			    nxt->ctx_type != inctx_type)
				break;

			nxt_rgn_key = wd_sched_ctx_region_key(nxt->ctx, nxt->ctx_type,
					 is_dev, &nxt_numa_id);
			if (nxt_rgn_key < 0) {
				WD_ERR("failed to parse region key for ctx %u!\n", seg_end + 1);
				return -WD_EINVAL;
			}
			if (nxt_rgn_key != cur_rgn_key || nxt_numa_id != cur_numa_id)
				break;
		}

		/* Register segment to scheduler */
		memset(&sparams, 0, sizeof(sparams));
		sparams.numa_id = cur_numa_id;
		sparams.dev_id = cur_rgn_key;
		sparams.type = op_type;
		sparams.mode = mode;
		sparams.begin = seg_begin;
		sparams.end = seg_end;
		sparams.ctx_prop = inctx_type;

		ret = wd_sched_rr_instance(sched, &sparams);
		if (ret) {
			WD_ERR("failed to register ctx[%u, %u] (op_type=%u, mode=%u, prop=%d)!\n",
			       seg_begin, seg_end, op_type, mode, inctx_type);
			return ret;
		}

		i = seg_end + 1;
	}

	return WD_SUCCESS;
}

static void wd_free_ctxs_batch(struct wd_init_attrs *attrs,
			       __u32 allocated_count)
{
	struct wd_ctx_config_internal *internal_config = attrs->ctx_config_internal;
	struct wd_alg_driver *drv;
	__u32 i;

	if (!internal_config || !internal_config->ctxs || !allocated_count)
		return;

	for (i = 0; i < allocated_count; i++) {
		if (!internal_config->ctxs[i].ctx)
			continue;

		drv = internal_config->ctxs[i].drv;
		if (drv && drv->free_ctx)
			drv->free_ctx(internal_config->ctxs[i].ctx);

		internal_config->ctxs[i].ctx = 0;
	}
}

static int wd_alloc_single_drv_ctxs(struct wd_init_attrs *attrs,
				     struct wd_alg_driver *drv,
				     __u8 ctx_mode, __u8 op_type,
				     __u32 *ctx_idx)
{
	struct wd_ctx_config_internal *internal_config = attrs->ctx_config_internal;
	struct wd_ctx_params *ctx_params = attrs->ctx_params;
	struct wd_drv_ctx_params dparams;
	int numa_nodes[UADK_MAX_NUMA_NODES];
	__u32 mode_ctx_num, numa_count = 0;
	__u32 numa_idx, j;
	int max_node, n;
	handle_t ctx;
	int ret;

	if (ctx_mode == CTX_MODE_SYNC)
		mode_ctx_num = ctx_params->ctx_set_num[op_type].sync_ctx_num;
	else
		mode_ctx_num = ctx_params->ctx_set_num[op_type].async_ctx_num;
	if (!mode_ctx_num)
		return WD_SUCCESS;

	if ((attrs->sched_type == SCHED_POLICY_NONE ||
	     attrs->sched_type == SCHED_POLICY_SINGLE) && mode_ctx_num > 1)
		mode_ctx_num = 1;

	if (drv->calc_type == UADK_ALG_HW) {
		max_node = numa_max_node() + 1;
		if (max_node <= 0 || max_node > UADK_MAX_NUMA_NODES)
			max_node = UADK_MAX_NUMA_NODES;
		for (n = 0; n < max_node; n++) {
			if (numa_bitmask_isbitset(ctx_params->bmp, n))
				numa_nodes[numa_count++] = n;
		}
	} else {
		numa_nodes[0] = 0;
		numa_count = 1;
	}
	if (!numa_count) {
		numa_nodes[0] = 0;
		numa_count = 1;
	}

	for (numa_idx = 0; numa_idx < numa_count; numa_idx++) {
		for (j = 0; j < mode_ctx_num; j++) {
			memset(&dparams, 0, sizeof(dparams));
			dparams.ctx_mode = ctx_mode;
			dparams.op_type = op_type;
			dparams.numa_id = numa_nodes[numa_idx];
			dparams.bmp = ctx_params->bmp;
			dparams.epoll_en = false;
			ret = drv->alloc_ctx(attrs->alg, &dparams, &ctx);
			if (!ctx || ret < 0) {
				if (ret == -WD_ENODEV)
					break;
				WD_ERR("failed to alloc ctx %u from driver %s on numa %d!\n",
				       *ctx_idx, drv->drv_name, numa_nodes[numa_idx]);
				return ret;
			}

			internal_config->ctxs[*ctx_idx].ctx = ctx;
			internal_config->ctxs[*ctx_idx].op_type = dparams.op_type;
			internal_config->ctxs[*ctx_idx].ctx_mode = dparams.ctx_mode;
			internal_config->ctxs[*ctx_idx].ctx_type = drv->calc_type;
			internal_config->ctxs[*ctx_idx].drv = drv;
			(*ctx_idx)++;
		}
	}

	return WD_SUCCESS;
}

static int wd_alloc_ctxs_batch(struct wd_init_attrs *attrs,
				__u8 ctx_mode, __u32 *start_idx)
{
	struct wd_ctx_config_internal *internal_config = attrs->ctx_config_internal;
	struct wd_ctx_params *ctx_params = attrs->ctx_params;
	struct wd_alg_driver *drv;
	__u8 op_type, op_type_num;
	__u32 ctx_idx, drv_idx;
	int ret;

	op_type_num = ctx_params->op_type_num;
	if (attrs->sched_type == SCHED_POLICY_NONE ||
	    attrs->sched_type == SCHED_POLICY_SINGLE)
		op_type_num = 1;

	ctx_idx = *start_idx;
	for (drv_idx = 0; drv_idx < internal_config->drv_count; drv_idx++) {
		drv = internal_config->drv_array[drv_idx];
		if (!drv || !drv->alloc_ctx) {
			WD_ERR("failed to check driver %s alloc_ctx!\n",
			       drv ? drv->drv_name : "unknown");
			ret = -WD_EINVAL;
			goto err_ctxs;
		}

		for (op_type = 0; op_type < op_type_num; op_type++) {
			ret = wd_alloc_single_drv_ctxs(attrs, drv,
						       ctx_mode, op_type,
						       &ctx_idx);
			if (ret)
				goto err_ctxs;
		}
	}
	*start_idx = ctx_idx;

	return WD_SUCCESS;

err_ctxs:
	wd_free_ctxs_batch(attrs, ctx_idx);
	return ret;
}

/**
 * wd_alg_ctx_uninit() - Release ctxs, scheduler, ctx_config.
 *
 * Releases resources in reverse allocation order:
 * 1. Release scheduler
 * 2. Release ctxs via RR rule (drv->free_ctx)
 * 3. Free ctx_config and ctxs array
 *
 * @attrs: Initialization attributes
 */
void wd_alg_ctx_uninit(struct wd_init_attrs *attrs)
{
	struct wd_ctx_config_internal *internal_config;

	if (!attrs)
		return;

	internal_config = attrs->ctx_config_internal;

	WD_DEBUG("releasing ctxs, scheduler, and ctx_config\n");
	/* Release scheduler */
	if (attrs->sched) {
		wd_sched_rr_release(attrs->sched);
		attrs->sched = NULL;
	}

	/* Release ctxs via RR rule */
	if (internal_config)
		wd_free_ctxs_batch(attrs, internal_config->ctx_num);

	/* Release user-visible ctx_config */
	if (attrs->ctx_config) {
		if (attrs->ctx_config->ctxs) {
			free(attrs->ctx_config->ctxs);
			attrs->ctx_config->ctxs = NULL;
		}
		free(attrs->ctx_config);
		attrs->ctx_config = NULL;
	}

	WD_DEBUG("ctx uninit complete\n");
}

static int wd_init_ctx_config_sched(struct wd_init_attrs *attrs)
{
	struct wd_ctx_config_internal *internal_config = attrs->ctx_config_internal;
	struct wd_ctx_params *ctx_params = attrs->ctx_params;
	__u32 total_ctx_num = internal_config->ctx_num;
	__u32 i;
	int ret;

	/* Allocate user-visible wd_ctx_config structure */
	attrs->ctx_config = calloc(1, sizeof(struct wd_ctx_config));
	if (!attrs->ctx_config) {
		WD_ERR("failed to allocate ctx_config!\n");
		return -WD_ENOMEM;
	}

	/* Allocate user-visible wd_ctx array */
	attrs->ctx_config->ctxs = calloc(total_ctx_num, sizeof(struct wd_ctx));
	if (!attrs->ctx_config->ctxs) {
		WD_ERR("failed to allocate ctxs array!\n");
		ret = -WD_ENOMEM;
		goto cleanup_config;
	}

	attrs->ctx_config->ctx_num = total_ctx_num;
	/* Copy queue information from internal to user-visible config */
	for (i = 0; i < total_ctx_num; i++) {
		attrs->ctx_config->ctxs[i].ctx = internal_config->ctxs[i].ctx;
		attrs->ctx_config->ctxs[i].op_type = internal_config->ctxs[i].op_type;
		attrs->ctx_config->ctxs[i].ctx_mode = internal_config->ctxs[i].ctx_mode;
	}

	/* ── Call algorithm-specific init ── */
	attrs->ctx_config->cap = ctx_params->cap;
	ret = attrs->alg_init(attrs->ctx_config, attrs->sched);
	if (ret) {
		WD_ERR("failed to initialize algorithm!\n");
		goto cleanup_ctxs;
	}

	return WD_SUCCESS;

cleanup_ctxs:
	free(attrs->ctx_config->ctxs);
	attrs->ctx_config->ctxs = NULL;
cleanup_config:
	free(attrs->ctx_config);
	attrs->ctx_config = NULL;
	return ret;
}

/**
 * wd_alg_ctx_init() - Allocate contexts, scheduler, and initialize algorithm.
 *
 * Uses drivers discovered by wd_alg_config_init().
 * Allocates contexts via RR: ctx[i] -> drv_array[i % drv_count]->alloc_ctx()
 * Then allocates scheduler, registers context ranges, and calls alg_init
 * which performs wd_init_ctx_config() (wd_ctx[] -> wd_ctx_internal[] copy).
 *
 * On return:
 *   - attrs->ctx_config: user-visible context array (populated)
 *   - attrs->sched: scheduler (allocated and populated)
 *   - attrs->ctx_config_internal: MUST be set by alg_init callback
 *
 * NOTE: ctxs[i].drv is still NULL after this function — set later by
 * wd_ctx_bind_drivers().
 *
 * @attrs: Initialization attributes (input: drv_array, ctx_params, alg_init, etc.)
 * Return: 0 on success, negative on failure
 */
int wd_alg_ctx_init(struct wd_init_attrs *attrs)
{
	struct wd_ctx_config_internal *internal_config;
	int numa_num_int = numa_max_node();
	__u16 region_num, numa_num;
	__u32 ctx_idx = 0;
	int ret;

	if (numa_num_int < 0)
		numa_num = 0;
	else
		numa_num = (__u16)numa_num_int;

	if (!attrs || !attrs->ctx_params || !attrs->ctx_config_internal ||
	     !attrs->ctx_config_internal->drv_array) {
		WD_ERR("invalid: attrs, ctx_params, or drv_array is NULL/empty!\n");
		return -WD_EINVAL;
	}

	/*
	 * Ensure that contexts (ctx) with the same attributes are allocated first,
	 * thereby maintaining queue continuity within the contexts.
	 */
	ret = wd_alloc_ctxs_batch(attrs, CTX_MODE_SYNC, &ctx_idx);
	if (ret)
		return -WD_EINVAL;

	/* wd_alloc_ctxs_batch already cleaned up via its internal err_ctxs. */
	ret = wd_alloc_ctxs_batch(attrs, CTX_MODE_ASYNC, &ctx_idx);
	if (ret)
		return -WD_EINVAL;

	/* Backfill actual allocated count */
	internal_config = attrs->ctx_config_internal;
	internal_config->ctx_num = ctx_idx;
	if (!ctx_idx) {
		WD_ERR("no contexts allocated on any NUMA node!\n");
		ret = -WD_EINVAL;
		goto cleanup_ctxs;
	}

	/* ── Allocate scheduler ── */
	if (attrs->sched_type == SCHED_POLICY_DEV)
		region_num = DEVICE_REGION_MAX;
	else if (numa_num == 0)
		region_num = 1;
	else
		region_num = numa_num + 1;

	attrs->sched = wd_sched_rr_alloc(attrs->sched_type,
					  attrs->ctx_params->op_type_num,
					  region_num,
					  attrs->alg_poll_ctx);
	if (!attrs->sched) {
		WD_ERR("failed to allocate scheduler!\n");
		ret = -WD_ENOMEM;
		goto cleanup_ctxs;
	}

	/* ── Register contexts to scheduler ── */
	internal_config = attrs->ctx_config_internal;
	ret = wd_alg_sched_instance(attrs->sched, internal_config);
	if (ret) {
		WD_ERR("failed to register contexts to scheduler!\n");
		goto cleanup_sched;
	}

	/* ── Allocate user ctx_config and initialize algorithm ── */
	ret = wd_init_ctx_config_sched(attrs);
	if (ret) {
		WD_ERR("failed to allocate user ctx_config and initialize algorithm!\n");
		goto cleanup_user_config;
	}

	WD_DEBUG("ctx init complete: %u ctxs from %u drivers\n",
		internal_config->ctx_num, internal_config->drv_count);

	return WD_SUCCESS;

	/* ── Error cleanup (LIFO) ── */
cleanup_user_config:
	if (attrs->ctx_config) {
		if (attrs->ctx_config->ctxs)
			free(attrs->ctx_config->ctxs);
		free(attrs->ctx_config);
		attrs->ctx_config = NULL;
	}
cleanup_sched:
	wd_sched_rr_release(attrs->sched);
	attrs->sched = NULL;
cleanup_ctxs:
	/* Free ctxs allocated so far using RR rule */
	wd_free_ctxs_batch(attrs, ctx_idx);
	return ret;
}

/**
 * wd_alg_attrs_uninit() - Release all algorithm resources.
 *
 * Releases resources in reverse order of allocation:
 *   1. wd_alg_ctx_uninit()    — free contexts, scheduler, ctx_config
 *   2. wd_alg_config_uninit() — free driver array and internal config
 *
 * @attrs: Initialization attributes
 */
void wd_alg_attrs_uninit(struct wd_init_attrs *attrs)
{
	if (!attrs)
		return;

	WD_DEBUG("Algorithm cleanup started: alg=%s\n", attrs->alg);

	/* Release ctxs, scheduler, ctx_config */
	wd_alg_ctx_uninit(attrs);

	/* Free driver array and internal config */
	wd_alg_config_uninit(attrs);

	WD_DEBUG("Algorithm cleanup complete\n");
}

static bool wd_check_sva_mode(const char *alg_type)
{
	struct uacce_dev_list *dev_list;
	bool is_sva = true;

	dev_list = wd_get_accel_list(alg_type);
	if (!dev_list || !dev_list->dev)
		return true;

	if (!(dev_list->dev->flags & UACCE_DEV_SVA))
		is_sva = false;

	wd_free_list_accels(dev_list);
	return is_sva;
}

static int wd_check_nosva_type(struct wd_init_attrs *attrs)
{
	char alg_type_buf[CRYPTO_MAX_ALG_NAME] = {0};
	bool is_sva;
	int ret;

	ret = wd_get_alg_type(attrs->alg, alg_type_buf);
	if (ret) {
		WD_ERR("failed to get alg type for No-SVA check!\n");
		return -WD_EINVAL;
	}

	/* These two special types require the use of the original algorithm names. */
	if (strcmp(alg_type_buf, "comp") == 0 ||
	     strcmp(alg_type_buf, "ecc") == 0)
		(void)strcpy(alg_type_buf, attrs->alg);

	is_sva = wd_check_sva_mode(alg_type_buf);
	if (is_sva) {
		if (attrs->sched_type == SCHED_POLICY_DEV) {
			WD_ERR("invalid: SVA mode does not support SCHED_POLICY_DEV!\n");
			return -WD_EINVAL;
		}
		return WD_SUCCESS;
	}

	/*
	 * No-SVA with TASK_INSTR: CE/SVE drivers execute on CPU and
	 * do not perform DMA, no dependency on hardware SVA mode.
	 */
	if (attrs->task_type == TASK_INSTR)
		return WD_SUCCESS;

	/* No-SVA only allows TASK_HW */
	if (attrs->task_type != TASK_HW) {
		WD_ERR("invalid: No-SVA mode only supports TASK_HW, got %u!\n",
		       attrs->task_type);
		return -WD_EINVAL;
	}

	/* TASK_HW + DEV: correct combination */
	if (attrs->sched_type == SCHED_POLICY_DEV)
		return WD_SUCCESS;

	/* TASK_HW + RR/LOOP/HUNGRY: auto-switch to DEV */
	if (attrs->sched_type == SCHED_POLICY_RR ||
	    attrs->sched_type == SCHED_POLICY_LOOP ||
	    attrs->sched_type == SCHED_POLICY_HUNGRY) {
		WD_INFO("info: No-SVA mode auto-switching sched %u to SCHED_POLICY_DEV!\n",
			attrs->sched_type);
		attrs->sched_type = SCHED_POLICY_DEV;
		return WD_SUCCESS;
	}

	/* TASK_HW + NONE/SINGLE/INSTR: reject */
	WD_ERR("invalid: No-SVA mode requires SCHED_POLICY_DEV, got %u!\n",
	       attrs->sched_type);
	return -WD_EINVAL;
}

/**
 * wd_task_sched_check() - Validate task_type + sched_type combination.
 *
 * After driver discovery, check that the requested scheduling
 * policy is compatible with the discovered drivers and task type.
 *
 * Invalid combinations:
 *   TASK_HW + SCHED_POLICY_INSTR   - instr poll only polls ctx[0],
 *                                     losing HW async completions.
 *   TASK_INSTR + SCHED_POLICY_DEV  - CE/SVE/SOFT drivers have no
 *                                     dev_id for device-level domains.
 *   SCHED_POLICY_NONE + >1 driver  - NONE always picks ctx[0];
 *                                     different sessions may route to
 *                                     a driver that doesn\'t support
 *                                     their algorithm.
 *
 * @attrs: Initialization attributes (drv_count must be populated)
 * Return: 0 on success, -WD_EINVAL on invalid combination
 */
static int wd_task_sched_check(struct wd_init_attrs *attrs)
{
	struct wd_alg_driver **drv_arr;

	if (attrs->task_type == TASK_HW &&
	     attrs->sched_type == SCHED_POLICY_INSTR) {
		WD_ERR("invalid: HW tasks must not use INSTR scheduler\n");
		return -WD_EINVAL;
	}

	if (attrs->task_type == TASK_MIX &&
	     attrs->sched_type == SCHED_POLICY_INSTR) {
		WD_ERR("invalid: MIX tasks must not use INSTR scheduler\n");
		return -WD_EINVAL;
	}

	if (attrs->sched_type == SCHED_POLICY_NONE &&
	     attrs->ctx_config_internal->drv_count > 1) {
		WD_ERR("invalid: NONE scheduler requires single driver\n");
		return -WD_EINVAL;
	}

	/* NONE scheduler: only TASK_INSTR (CE driver) is valid */
	if (attrs->sched_type == SCHED_POLICY_NONE &&
	    (attrs->task_type == TASK_HW || attrs->task_type == TASK_MIX)) {
		WD_ERR("invalid: NONE scheduler only supports TASK_INSTR!\n");
		return -WD_EINVAL;
	}

	/* SINGLE scheduler: only TASK_INSTR (SVE driver) is valid */
	if (attrs->sched_type == SCHED_POLICY_SINGLE &&
	    (attrs->task_type == TASK_HW || attrs->task_type == TASK_MIX)) {
		WD_ERR("invalid: SINGLE scheduler only supports TASK_INSTR!\n");
		return -WD_EINVAL;
	}

	/* NONE with TASK_INSTR: must be CE driver */
	if (attrs->sched_type == SCHED_POLICY_NONE &&
	    attrs->task_type == TASK_INSTR) {
		drv_arr = attrs->ctx_config_internal->drv_array;
		if (drv_arr && drv_arr[0] &&
		    drv_arr[0]->calc_type != UADK_ALG_CE_INSTR) {
			WD_ERR("invalid: NONE scheduler requires CE driver, got type %d!\n",
			       drv_arr[0]->calc_type);
			return -WD_EINVAL;
		}
	}

	/* SINGLE with TASK_INSTR: must be SVE driver */
	if (attrs->sched_type == SCHED_POLICY_SINGLE &&
	    attrs->task_type == TASK_INSTR) {
		drv_arr = attrs->ctx_config_internal->drv_array;
		if (drv_arr && drv_arr[0] &&
		    (drv_arr[0]->calc_type != UADK_ALG_SVE_INSTR &&
		     drv_arr[0]->calc_type != UADK_ALG_CE_INSTR)) {
			WD_ERR("invalid: SINGLE scheduler requires CE/SVE driver, got type %d!\n",
			       drv_arr[0]->calc_type);
			return -WD_EINVAL;
		}
	}

	/* No-SVA mode: only TASK_HW + SCHED_POLICY_DEV is allowed */
	return wd_check_nosva_type(attrs);
}

/**
 * wd_alg_attrs_init() - Initialize algorithm with auto-discovered drivers.
 *
 * Initialization sequence:
 *   1. wd_alg_config_init()    — discover matching drivers, allocate internal config
 *   2. wd_task_sched_check()   — validate task_type + sched_type compatibility
 *   3. wd_alg_ctx_init()       — allocate contexts, scheduler, and initialize algorithm
 *
 * After this, driver init is done by the caller via wd_alg_init_driver().
 *
 * @attrs: Initialization attributes (input/output)
 * Return: 0 on success, negative on failure
 */
int wd_alg_attrs_init(struct wd_init_attrs *attrs)
{
	int ret;

	if (!attrs) {
		WD_ERR("invalid: attrs is NULL!\n");
		return -WD_EINVAL;
	}

	/* Driver discovery and configuration setup */
	ret = wd_alg_config_init(attrs);
	if (ret) {
		WD_ERR("failed to discover drivers!\n");
		goto out_undiscover;
	}
	WD_DEBUG("discovered %u unique drivers\n", attrs->ctx_config_internal->drv_count);

	/* Scheduler compatibility check */
	ret = wd_task_sched_check(attrs);
	if (ret) {
		WD_ERR("failed to match task type with sched type!\n");
		goto out_undiscover;
	}

	/* Allocate ctxs, init scheduler and algorithm */
	ret = wd_alg_ctx_init(attrs);
	if (ret) {
		WD_ERR("failed to init ctx!\n");
		goto out_undiscover;
	}

	WD_DEBUG("Algorithm initialization complete: %u contexts from %u drivers\n",
		attrs->ctx_config_internal->ctx_num, attrs->ctx_config_internal->drv_count);

	return WD_SUCCESS;

out_undiscover:
	wd_alg_config_uninit(attrs);
	return ret;
}
