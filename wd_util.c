// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include <ctype.h>
#include "wd_sched.h"
#include "wd_util.h"

#define WD_ASYNC_DEF_POLL_NUM		1
#define WD_ASYNC_DEF_QUEUE_DEPTH	1024
#define WD_BALANCE_THRHD		1280
#define WD_RECV_MAX_CNT_SLEEP		60000000
#define WD_RECV_MAX_CNT_NOSLEEP		200000000
#define PRIVILEGE_FLAG			0600
#define MIN(a, b)			((a) > (b) ? (b) : (a))
#define MAX(a, b)			((a) > (b) ? (a) : (b))

#define WD_INIT_SLEEP_UTIME		1000
#define WD_INIT_RETRY_TIMES		10000
#define US2S(us)			((us) >> 20)
#define WD_INIT_RETRY_TIMEOUT		3

#define WD_SOFT_CTX_NUM		2
#define WD_SOFT_SYNC_CTX		0
#define WD_SOFT_ASYNC_CTX		1

#define WD_DRV_LIB_DIR			"uadk"

#define WD_PATH_DIR_NUM			2

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
static const char *ctx_type[2][1] = { {"sync:"}, {"async:"} };

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
};

struct async_task {
	__u32 idx;
};

struct async_task_queue {
	struct async_task *head;
	int depth;
	/* the producer offset of task queue */
	int prod;
	/* the consumer offset of task queue */
	int cons;
	int cur_task;
	int left_task;
	int end;
	sem_t empty_sem;
	sem_t full_sem;
	pthread_mutex_t lock;
	pthread_t tid;
	int (*alg_poll_ctx)(__u32, __u32, __u32 *);
};

struct drv_lib_list {
	void *dlhandle;
	struct drv_lib_list *next;
};

struct acc_alg_item {
	const char *name;
	const char *algtype;
};

struct wd_ce_ctx {
	char *drv_name;
	void *priv;
};

static struct acc_alg_item alg_options[] = {
	{"zlib", "zlib"},
	{"gzip", "gzip"},
	{"deflate", "deflate"},
	{"lz77_zstd", "lz77_zstd"},
	{"hashagg", "hashagg"},
	{"udma", "udma"},

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
			WD_ERR("invalid: ctx is NULL!\n");
			ret = -WD_EINVAL;
			goto err_out;
		}
		clone_ctx_to_internal(cfg->ctxs + i, ctxs + i);
		ret = pthread_spin_init(&ctxs[i].lock, PTHREAD_PROCESS_SHARED);
		if (ret) {
			WD_ERR("failed to init ctxs lock!\n");
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

int wd_init_sched(struct wd_sched *in, struct wd_sched *from)
{
	if (!from->name || !from->sched_init ||
	    !from->pick_next_ctx || !from->poll_policy) {
		WD_ERR("invalid: member of wd_sched is NULL!\n");
		return -WD_EINVAL;
	}

	in->h_sched_ctx = from->h_sched_ctx;
	in->name = strdup(from->name);
	in->sched_init = from->sched_init;
	in->pick_next_ctx = from->pick_next_ctx;
	in->poll_policy = from->poll_policy;

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
	in->pick_next_ctx = NULL;
	in->poll_policy = NULL;
}

void wd_clear_ctx_config(struct wd_ctx_config_internal *in)
{
	__u32 i;

	for (i = 0; i < in->ctx_num; i++)
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

	if ((__u32)ctx_idx > pool->pool_num) {
		WD_ERR("invalid: message ctx id index is %d!\n", ctx_idx);
		return NULL;
	}
	p = &pool->pools[ctx_idx];
	msg_num = p->msg_num;

	/* tag value start from 1 */
	if (tag == 0 || tag > msg_num) {
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
	if (config->numa_num == 0 || config->numa_num > max_node) {
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
	if (len == 0)
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

int wd_parse_async_poll_en(struct wd_env_config *config, const char *s)
{
	int ret;

	ret = str_to_bool(s, &config->enable_internal_poll);
	if (ret)
		WD_ERR("failed to parse async poll enable flag(%s)!\n", s);

	return ret;
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
				type = ctx_type[i][j];
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

int wd_parse_async_poll_num(struct wd_env_config *config, const char *s)
{
	struct wd_env_config_per_numa *config_numa;
	char *left, *section, *start;
	int node, poll_num, ret;

	if (!config->enable_internal_poll) {
		WD_ERR("internal poll not enabled, skip parse poll number!\n");
		return 0;
	}

	start = strdup(s);
	if (!start)
		return -ENOMEM;

	left = start;
	while ((section = strsep(&left, ","))) {
		ret = parse_num_on_numa(section, &poll_num, &node);
		if (ret)
			goto out;
		config_numa = wd_get_config_numa(config, node);
		if (!config_numa) {
			ret = -WD_EINVAL;
			goto out;
		}
		config_numa->async_poll_num = poll_num;
	}

	free(start);
	return 0;
out:
	free(start);
	return ret;
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
	env_config->enable_internal_poll = 0;
	config_numa->async_poll_num = 0;

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
	void *func = NULL;

	type_num = config->op_type_num;
	max_node = numa_max_node() + 1;
	if (max_node <= 0)
		return -WD_EINVAL;

	if (!config->enable_internal_poll)
		func = alg_poll_ctx;

	config->internal_sched = false;
	if (!config->sched) {
		WD_ERR("no sched is specified, alloc a default sched!\n");
		config->sched = wd_sched_rr_alloc(SCHED_POLICY_RR, type_num,
						  max_node, func);
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

static struct async_task_queue *find_async_queue(struct wd_env_config *config,
						 __u32 idx)
{
	struct wd_env_config_per_numa *config_numa;
	struct wd_ctx_range **ctx_table;
	struct async_task_queue *head;
	unsigned long offset = 0;
	__u32 i, num = 0;

	FOREACH_NUMA(i, config, config_numa) {
		num += config_numa->sync_ctx_num + config_numa->async_ctx_num;
		if (idx < num)
			break;
	}

	if (i == config->numa_num) {
		WD_ERR("failed to find a proper numa node!\n");
		return NULL;
	}

	if (!config_numa->async_poll_num) {
		WD_ERR("invalid: async_poll_num of numa is zero!\n");
		return NULL;
	}

	ctx_table = config_numa->ctx_table;
	for (i = 0; i < config_numa->op_type_num; i++) {
		if (idx <= ctx_table[CTX_MODE_ASYNC][i].end &&
		    idx >= ctx_table[CTX_MODE_ASYNC][i].begin) {
			offset = (idx - ctx_table[CTX_MODE_ASYNC][i].begin) %
				 config_numa->async_poll_num;
			break;
		}
	}

	if (i == config_numa->op_type_num) {
		WD_ERR("failed to find async queue for ctx: idx %u!\n", idx);
		return NULL;
	}

	head = (struct async_task_queue *)config_numa->async_task_queue_array;

	return head + offset;
}

int wd_add_task_to_async_queue(struct wd_env_config *config, __u32 idx)
{
	struct async_task_queue *task_queue;
	struct async_task *task;
	int curr_prod, ret;

	if (!config->enable_internal_poll)
		return 0;

	task_queue = find_async_queue(config, idx);
	if (!task_queue)
		return -WD_EINVAL;

	ret = sem_wait(&task_queue->empty_sem);
	if (ret) {
		WD_ERR("failed to wait empty_sem!\n");
		return ret;
	}

	pthread_mutex_lock(&task_queue->lock);

	/* get an available async task and fill ctx idx */
	curr_prod = task_queue->prod;
	task = task_queue->head + curr_prod;
	task->idx = idx;

	/* update global information of task queue */
	task_queue->prod = (curr_prod + 1) % task_queue->depth;
	task_queue->cur_task++;
	task_queue->left_task--;

	pthread_mutex_unlock(&task_queue->lock);

	ret = sem_post(&task_queue->full_sem);
	if (ret) {
		WD_ERR("failed to post full_sem!\n");
		goto err_out;
	}

	return 0;

err_out:
	pthread_mutex_lock(&task_queue->lock);
	task_queue->left_task++;
	task_queue->cur_task--;
	task_queue->prod = curr_prod;
	pthread_mutex_unlock(&task_queue->lock);
	sem_post(&task_queue->empty_sem);

	return ret;
}

static void *async_poll_process_func(void *args)
{
	struct async_task_queue *task_queue = args;
	struct async_task *head, *task;
	__u32 count;
	int cons, ret;

	while (1) {
		if (sem_wait(&task_queue->full_sem)) {
			if (errno == EINTR) {
				continue;
			}
		}
		if (__atomic_load_n(&task_queue->end, __ATOMIC_ACQUIRE)) {
			__atomic_store_n(&task_queue->end, 0, __ATOMIC_RELEASE);
			goto out;
		}

		pthread_mutex_lock(&task_queue->lock);

		/* async sending message isn't submitted yet */
		if (task_queue->cons == task_queue->prod) {
			pthread_mutex_unlock(&task_queue->lock);
			sem_post(&task_queue->full_sem);
			continue;
		}

		cons = task_queue->cons;
		head = task_queue->head;
		task = head + cons;

		task_queue->cons = (cons + 1) % task_queue->depth;
		task_queue->cur_task--;
		task_queue->left_task++;

		pthread_mutex_unlock(&task_queue->lock);

		ret = task_queue->alg_poll_ctx(task->idx, 1, &count);
		if (ret < 0) {
			pthread_mutex_lock(&task_queue->lock);
			task_queue->cons = cons;
			task_queue->cur_task++;
			task_queue->left_task--;
			pthread_mutex_unlock(&task_queue->lock);
			if (ret == -WD_EAGAIN) {
				sem_post(&task_queue->full_sem);
				continue;
			} else
				goto out;
		}

		if (sem_post(&task_queue->empty_sem))
			goto out;
	}
out:
	return NULL;
}

static int wd_init_one_task_queue(struct async_task_queue *task_queue,
				  void *alg_poll_ctx)

{
	struct async_task *head;
	pthread_t thread_id;
	pthread_attr_t attr;
	int depth, ret;

	task_queue->depth = depth = WD_ASYNC_DEF_QUEUE_DEPTH;

	head = calloc(task_queue->depth, sizeof(*head));
	if (!head)
		return -WD_ENOMEM;

	task_queue->head = head;
	task_queue->left_task = depth;
	task_queue->alg_poll_ctx = alg_poll_ctx;

	if (sem_init(&task_queue->empty_sem, 0, depth)) {
		WD_ERR("failed to init empty_sem!\n");
		goto err_free_head;
	}

	if (sem_init(&task_queue->full_sem, 0, 0)) {
		WD_ERR("failed to init full_sem!\n");
		goto err_uninit_empty_sem;
	}

	if (pthread_mutex_init(&task_queue->lock, NULL)) {
		WD_ERR("failed to init task queue's mutex lock!\n");
		goto err_uninit_full_sem;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	task_queue->tid = 0;
	if (pthread_create(&thread_id, &attr, async_poll_process_func,
			   task_queue)) {
		WD_ERR("failed to create poll thread!\n");
		goto err_destory_mutex;
	}

	task_queue->tid = thread_id;
	pthread_attr_destroy(&attr);

	return 0;

err_destory_mutex:
	pthread_attr_destroy(&attr);
	pthread_mutex_destroy(&task_queue->lock);
err_uninit_full_sem:
	sem_destroy(&task_queue->full_sem);
err_uninit_empty_sem:
	sem_destroy(&task_queue->empty_sem);
err_free_head:
	free(head);
	ret = -errno;
	return ret;
}

static void wd_uninit_one_task_queue(struct async_task_queue *task_queue)
{
	/*
	 * If there's no async task, async_poll_process_func() is sleeping
	 * on task_queue->full_sem. It'll cause that threads could not
	 * be end and memory leak.
	 */
	sem_post(&task_queue->full_sem);
	__atomic_store_n(&task_queue->end, 1, __ATOMIC_RELEASE);
	while (__atomic_load_n(&task_queue->end, __ATOMIC_ACQUIRE))
		sched_yield();

	pthread_mutex_destroy(&task_queue->lock);
	sem_destroy(&task_queue->full_sem);
	sem_destroy(&task_queue->empty_sem);
	free(task_queue->head);
	task_queue->head = NULL;
}

static int wd_init_async_polling_thread_per_numa(struct wd_env_config *config,
						 struct wd_env_config_per_numa *config_numa,
						 void *alg_poll_ctx)
{
	struct async_task_queue *task_queue, *queue_head;
	int i, j, ret;
	double num;

	if (!config_numa->async_ctx_num)
		return 0;

	if (!config_numa->async_poll_num) {
		WD_ERR("invalid async poll num (%lu) is set.\n",
		       config_numa->async_poll_num);
		WD_ERR("change to default value: %d\n", WD_ASYNC_DEF_POLL_NUM);
		config_numa->async_poll_num = WD_ASYNC_DEF_POLL_NUM;
	}

	num = MIN(config_numa->async_poll_num, config_numa->async_ctx_num);

	/* make max task queues as the number of async ctxs */
	queue_head = calloc(config_numa->async_ctx_num, sizeof(*queue_head));
	if (!queue_head)
		return -WD_ENOMEM;

	task_queue = queue_head;
	for (i = 0; i < num; task_queue++, i++) {
		ret = wd_init_one_task_queue(task_queue, alg_poll_ctx);
		if (ret) {
			for (j = 0; j < i; task_queue++, j++)
				wd_uninit_one_task_queue(task_queue);
			free(queue_head);
			return ret;
		}
	}

	config_numa->async_task_queue_array = (void *)queue_head;

	return 0;
}

static void wd_uninit_async_polling_thread_per_numa(struct wd_env_config *cfg,
						    struct wd_env_config_per_numa *config_numa)
{
	struct async_task_queue *task_queue, *head;
	double num;
	int i;

	if (!config_numa || !config_numa->async_task_queue_array)
		return;

	head = config_numa->async_task_queue_array;
	task_queue = head;
	num = MIN(config_numa->async_poll_num, config_numa->async_ctx_num);

	for (i = 0; i < num; task_queue++, i++)
		wd_uninit_one_task_queue(task_queue);
	free(head);
	config_numa->async_task_queue_array = NULL;
}

static int wd_init_async_polling_thread(struct wd_env_config *config,
					void *alg_poll_ctx)
{
	struct wd_env_config_per_numa *config_numa;
	int i, ret;

	if (!config->enable_internal_poll)
		return 0;

	FOREACH_NUMA(i, config, config_numa) {
		ret = wd_init_async_polling_thread_per_numa(config, config_numa,
							    alg_poll_ctx);
		if (ret)
			goto out;
	}

	return 0;

out:
	FOREACH_NUMA(i, config, config_numa)
		wd_uninit_async_polling_thread_per_numa(config, config_numa);

	return ret;
}

static void wd_uninit_async_polling_thread(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa;
	int i;

	if (!config->enable_internal_poll)
		return;

	FOREACH_NUMA(i, config, config_numa)
		wd_uninit_async_polling_thread_per_numa(config, config_numa);
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

	ret = wd_init_async_polling_thread(config, ops->alg_poll_ctx);
	if (ret)
		goto err_uninit_alg;

	return 0;

err_uninit_alg:
	ops->alg_uninit();
err_uninit_sched:
	wd_uninit_sched_config(config);
err_uninit_ctx:
	wd_free_ctx(config);
	return ret;
}

static void wd_uninit_resource(struct wd_env_config *config,
			       const struct wd_alg_ops *ops)
{
	wd_uninit_async_polling_thread(config);
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

	*is_enable = env_config->enable_internal_poll;

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

int wd_handle_msg_sync(struct wd_alg_driver *drv, struct wd_msg_handle *msg_handle,
		       handle_t ctx, void *msg, __u64 *balance, bool epoll_en)
{
	__u64 timeout = WD_RECV_MAX_CNT_NOSLEEP;
	__u64 rx_cnt = 0;
	int ret;

	if (balance)
		timeout = WD_RECV_MAX_CNT_SLEEP;

	ret = msg_handle->send(drv, ctx, msg);
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

		ret = msg_handle->recv(drv, ctx, msg);
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
		WD_ERR("invalid: config or config->ctxs is NULL!\n");
		return -WD_EINVAL;
	}

	if (!sched) {
		WD_ERR("invalid: sched is NULL!\n");
		return -WD_EINVAL;
	}

	if (!wd_is_sva(config->ctxs[0].ctx)) {
		WD_ERR("invalid: the mode is non sva, please check system!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static void wd_get_alg_type(const char *alg_name, char *alg_type)
{
	__u64 i;

	for (i = 0; i < ARRAY_SIZE(alg_options); i++) {
		if (strcmp(alg_name, alg_options[i].name) == 0) {
			(void)strcpy(alg_type, alg_options[i].algtype);
			break;
		}
	}
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

int wd_alg_init_driver(struct wd_ctx_config_internal *config,
		       struct wd_alg_driver *driver)
{
	int ret;

	if (!driver->init) {
		driver->fallback = 0;
		WD_ERR("driver have no init interface.\n");
		ret = -WD_EINVAL;
		goto err_alloc;
	}

	ret = driver->init(driver, config);
	if (ret < 0) {
		WD_ERR("driver init failed.\n");
		goto err_alloc;
	}

	if (driver->fallback) {
		ret = wd_alg_init_fallback((struct wd_alg_driver *)driver->fallback);
		if (ret) {
			driver->fallback = 0;
			WD_ERR("soft alg driver init failed.\n");
		}
	}

	return 0;

err_alloc:
	return ret;
}

void wd_alg_uninit_driver(struct wd_ctx_config_internal *config,
			  struct wd_alg_driver *driver)
{
	driver->exit(driver);
	/* Ctx config just need clear once */
	wd_clear_ctx_config(config);

	if (driver->fallback)
		wd_alg_uninit_fallback((struct wd_alg_driver *)driver->fallback);
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

static int wd_set_ctx_nums(struct wd_ctx_params *ctx_params, struct uacce_dev_list *list,
			   const char *section, __u32 op_type_num, int is_comp)
{
	struct wd_ctx_nums *ctxs = ctx_params->ctx_set_num;
	int ret, ctx_num, node;
	struct uacce_dev *dev;
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

	dev = wd_find_dev_by_numa(list, node);
	if (WD_IS_ERR(dev))
		return -WD_ENODEV;

	for (i = 0; i < CTX_MODE_MAX; i++) {
		for (j = 0; j < op_type_num; j++) {
			type = is_comp ? comp_ctx_type[i][j] : ctx_type[i][0];
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
	char alg_type[CRYPTO_MAX_ALG_NAME];
	char *left, *section, *start;
	struct uacce_dev_list *list;
	int is_comp;
	int ret = 0;

	/* COMP environment variable's format is different, mark it */
	is_comp = strncmp(name, "WD_COMP_CTX_NUM", strlen(name)) ? 0 : 1;
	if (is_comp && op_type_num > ARRAY_SIZE(comp_ctx_type))
		return -WD_EINVAL;

	start = strdup(var_s);
	if (!start)
		return -WD_ENOMEM;

	wd_get_alg_type(alg_name, alg_type);
	list = wd_get_accel_list(alg_type);
	if (!list) {
		WD_ERR("failed to get devices!\n");
		free(start);
		return -WD_ENODEV;
	}

	left = start;
	while ((section = strsep(&left, ","))) {
		ret = wd_set_ctx_nums(ctx_params, list, section, op_type_num, is_comp);
		if (ret < 0)
			break;
	}

	wd_free_list_accels(list);
	free(start);
	return ret;
}

void wd_ctx_param_uninit(struct wd_ctx_params *ctx_params)
{
	numa_free_nodemask(ctx_params->bmp);
}

int wd_ctx_param_init(struct wd_ctx_params *ctx_params,
		      struct wd_ctx_params *user_ctx_params,
		      struct wd_alg_driver *driver,
		      enum wd_type type, int max_op_type)
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
	if (var_s && strlen(var_s) && driver->calc_type == UADK_ALG_HW) {
		/* environment variable has the highest priority */
		ret = wd_env_set_ctx_nums(driver->alg_name, env_name, var_s,
					  ctx_params, max_op_type);
		if (ret) {
			WD_ERR("fail to init ctx nums from %s!\n", env_name);
			numa_free_nodemask(ctx_params->bmp);
			return ret;
		}
	} else {
		/* environment variable is not set, try to use user_ctx_params first */
		if (user_ctx_params) {
			if (user_ctx_params->bmp) {
				copy_bitmask_to_bitmask(user_ctx_params->bmp, ctx_params->bmp);
			} else {
				/* default value */
				numa_bitmask_setall(ctx_params->bmp);
			}
			ctx_params->cap = user_ctx_params->cap;
			ctx_params->ctx_set_num = user_ctx_params->ctx_set_num;
			ctx_params->op_type_num = user_ctx_params->op_type_num;
			if (ctx_params->op_type_num > (__u32)max_op_type) {
				WD_ERR("fail to check user op type numbers.\n");
				numa_free_nodemask(ctx_params->bmp);
				return -WD_EINVAL;
			}

			return 0;
		}

		/* user_ctx_params is also not set, use driver's defalut queue_num */
		numa_bitmask_setall(ctx_params->bmp);
		for (i = 0; i < driver->op_type_num; i++) {
			ctx_params->ctx_set_num[i].sync_ctx_num = driver->queue_num;
			ctx_params->ctx_set_num[i].async_ctx_num = driver->queue_num;
		}
	}

	ctx_params->op_type_num = driver->op_type_num;
	if (ctx_params->op_type_num > (__u32)max_op_type) {
		WD_ERR("fail to check driver op type numbers.\n");
		numa_free_nodemask(ctx_params->bmp);
		return -WD_EAGAIN;
	}

	return 0;
}

static void dladdr_empty(void)
{
}

int wd_get_lib_file_path(const char *lib_file, char *lib_path, bool is_dir)
{
	char *path_buf, *path, *file_path;
	Dl_info file_info;
	int len, rc, i;

	/* Get libwd.so file's system path */
	rc = dladdr(dladdr_empty, &file_info);
	if (!rc) {
		WD_ERR("fail to get lib file path.\n");
		return -WD_EINVAL;
	}

	path_buf = calloc(WD_PATH_DIR_NUM, sizeof(char) * PATH_MAX);
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
		if (len >= PATH_MAX)
			goto free_path;
	} else {
		len = snprintf(lib_path, PATH_MAX, "%s/%s/%s", file_path, WD_DRV_LIB_DIR, lib_file);
		if (len >= PATH_MAX)
			goto free_path;
	}

	if (realpath(lib_path, path) == NULL) {
		WD_ERR("invalid: %s: no such file or directory!\n", path);
		goto free_path;
	}
	free(path_buf);

	return 0;

free_path:
	free(path_buf);
	return -WD_EINVAL;
}

/**
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

void *wd_dlopen_drv(const char *cust_lib_dir)
{
	typedef int (*alg_ops)(struct wd_alg_driver *drv);
	struct drv_lib_list *node, *head = NULL;
	char lib_dir_path[PATH_MAX] = {0};
	char lib_path[PATH_MAX] = {0};
	struct dirent *lib_dir;
	alg_ops dl_func = NULL;
	DIR *wd_dir;
	int ret;

	if (!cust_lib_dir) {
		ret = wd_get_lib_file_path(NULL, lib_dir_path, true);
		if (ret)
			return NULL;
	} else {
		if (realpath(cust_lib_dir, lib_path) == NULL) {
			WD_ERR("invalid: %s: no such file or directory!\n", lib_path);
			return NULL;
		}
		strncpy(lib_dir_path, cust_lib_dir, PATH_MAX - 1);
		lib_dir_path[PATH_MAX - 1] = '\0';
	}

	wd_dir = opendir(lib_dir_path);
	if (!wd_dir) {
		WD_ERR("UADK driver lib dir: %s not exist!\n", lib_dir_path);
		return NULL;
	}

	while ((lib_dir = readdir(wd_dir)) != NULL) {
		if (!strncmp(lib_dir->d_name, ".", LINUX_CRTDIR_SIZE) ||
		    !strncmp(lib_dir->d_name, "..", LINUX_PRTDIR_SIZE))
			continue;

		ret = file_check_valid(lib_dir->d_name);
		if (ret)
			continue;

		node = calloc(1, sizeof(*node));
		if (!node)
			goto free_list;

		ret = snprintf(lib_path, PATH_MAX, "%s/%s", lib_dir_path, lib_dir->d_name);
		if (ret < 0)
			goto free_node;

		node->dlhandle = dlopen(lib_path, RTLD_NODELETE | RTLD_NOW);
		if (!node->dlhandle) {
			free(node);
			/* there are many other files need to skip */
			continue;
		}

		dl_func = dlsym(node->dlhandle, "wd_alg_driver_register");
		if (dl_func == NULL) {
			dlclose(node->dlhandle);
			free(node);
			continue;
		}

		if (!head)
			head = node;
		else
			add_lib_to_list(head, node);
	}
	closedir(wd_dir);

	return (void *)head;

free_node:
	free(node);
free_list:
	closedir(wd_dir);
	wd_dlclose_drv(head);
	return NULL;
}

struct wd_alg_driver *wd_alg_drv_bind(int task_type, const char *alg_name)
{
	struct wd_alg_driver *set_driver = NULL;
	struct wd_alg_driver *drv;

	/* Get alg driver and dev name */
	switch (task_type) {
	case TASK_INSTR:
		drv = wd_request_drv(alg_name, true);
		if (!drv) {
			WD_ERR("no soft %s driver support\n", alg_name);
			return NULL;
		}
		set_driver = drv;
		set_driver->fallback = 0;
		break;
	case TASK_HW:
	case TASK_MIX:
		drv = wd_request_drv(alg_name, false);
		if (!drv) {
			WD_ERR("no HW %s driver support\n", alg_name);
			return NULL;
		}
		set_driver = drv;
		set_driver->fallback = 0;
		if (task_type == TASK_MIX) {
			drv = wd_request_drv(alg_name, true);
			if (!drv) {
				set_driver->fallback = 0;
				WD_ERR("no soft %s driver support\n", alg_name);
			} else {
				set_driver->fallback = (handle_t)drv;
				WD_ERR("successful to get soft driver\n");
			}
		}
		break;
	default:
		WD_ERR("task type error.\n");
		return NULL;
	}

	return set_driver;
}

void wd_alg_drv_unbind(struct wd_alg_driver *drv)
{
	struct wd_alg_driver *fb_drv = NULL;

	if (!drv)
		return;

	fb_drv = (struct wd_alg_driver *)drv->fallback;
	if (fb_drv)
		wd_release_drv(fb_drv);
	wd_release_drv(drv);
}

int wd_alg_try_init(enum wd_status *status)
{
	enum wd_status expected;
	__u32 count = 0;
	bool ret;

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

static __u32 wd_get_ctx_numbers(struct wd_ctx_params ctx_params, int end)
{
	__u32 count = 0;
	int i;

	for (i = 0; i < end; i++) {
		count += ctx_params.ctx_set_num[i].sync_ctx_num;
		count += ctx_params.ctx_set_num[i].async_ctx_num;
	}

	return count;
}

static struct uacce_dev_list *wd_get_usable_list(struct uacce_dev_list *list, struct bitmask *bmp)
{
	struct uacce_dev_list *p, *node, *result = NULL;
	struct uacce_dev *dev;
	int numa_id, ret;

	if (!bmp) {
		WD_ERR("invalid: bmp is NULL!\n");
		return WD_ERR_PTR(-WD_EINVAL);
	}

	p = list;
	while (p) {
		dev = p->dev;
		numa_id = dev->numa_id;
		ret = numa_bitmask_isbitset(bmp, numa_id);
		if (!ret) {
			p = p->next;
			continue;
		}

		node = calloc(1, sizeof(*node));
		if (!node) {
			result = WD_ERR_PTR(-WD_ENOMEM);
			goto out_free_list;
		}

		node->dev = wd_clone_dev(dev);
		if (!node->dev) {
			result = WD_ERR_PTR(-WD_ENOMEM);
			goto out_free_node;
		}

		if (!result)
			result = node;
		else
			wd_add_dev_to_list(result, node);

		p = p->next;
	}

	return result ? result : WD_ERR_PTR(-WD_ENODEV);

out_free_node:
	free(node);
out_free_list:
	wd_free_list_accels(result);
	return result;
}

static int wd_init_ctx_set(struct wd_init_attrs *attrs, struct uacce_dev_list *list,
			   __u32 idx, int numa_id, __u32 op_type)
{
	struct wd_ctx_nums ctx_nums = attrs->ctx_params->ctx_set_num[op_type];
	__u32 ctx_set_num = ctx_nums.sync_ctx_num + ctx_nums.async_ctx_num;
	struct wd_ctx_config *ctx_config = attrs->ctx_config;
	__u32 count = idx + ctx_set_num;
	struct uacce_dev *dev;
	__u32 i, cnt = 0;

	/* If the ctx set number is 0, the initialization is skipped. */
	if (!ctx_set_num)
		return 0;

	dev = wd_find_dev_by_numa(list, numa_id);
	if (WD_IS_ERR(dev))
		return WD_PTR_ERR(dev);

	for (i = idx; i < count; i++) {
		ctx_config->ctxs[i].ctx = wd_request_ctx(dev);
		if (errno == WD_EBUSY) {
			dev = wd_find_dev_by_numa(list, numa_id);
			if (WD_IS_ERR(dev))
				return WD_PTR_ERR(dev);

			if (cnt++ > WD_INIT_RETRY_TIMES) {
				WD_ERR("failed to request enough ctx due to timeout!\n");
				return -WD_ETIMEDOUT;
			}

			/* self-decrease i to eliminate self-increase on next loop */
			i--;
			continue;
		} else if (!ctx_config->ctxs[i].ctx) {
			/*
			 * wd_release_ctx_set will release ctx in
			 * caller wd_init_ctx_and_sched.
			 */
			return -WD_ENOMEM;
		}
		ctx_config->ctxs[i].op_type = op_type;
		ctx_config->ctxs[i].ctx_mode =
			((i - idx) < ctx_nums.sync_ctx_num) ?
			CTX_MODE_SYNC : CTX_MODE_ASYNC;
	}

	return 0;
}

static void wd_release_ctx_set(struct wd_ctx_config *ctx_config)
{
	__u32 i;

	for (i = 0; i < ctx_config->ctx_num; i++)
		if (ctx_config->ctxs[i].ctx) {
			wd_release_ctx(ctx_config->ctxs[i].ctx);
			ctx_config->ctxs[i].ctx = 0;
		}
}

static int wd_instance_sched_set(struct wd_sched *sched, struct wd_ctx_nums ctx_nums,
				 int idx, int numa_id, int op_type)
{
	struct sched_params sparams;
	int i, end, ret = 0;

	for (i = 0; i < CTX_MODE_MAX; i++) {
		sparams.numa_id = numa_id;
		sparams.type = op_type;
		sparams.mode = i;
		sparams.begin = idx + ctx_nums.sync_ctx_num * i;
		end = idx - 1 + ctx_nums.sync_ctx_num + ctx_nums.async_ctx_num * i;
		if (end < 0 || sparams.begin > (__u32)end)
			continue;

		sparams.end = end;
		ret = wd_sched_rr_instance(sched, &sparams);
		if (ret)
			goto out;
	}

out:
	return ret;
}

static int wd_init_ctx_and_sched(struct wd_init_attrs *attrs, struct bitmask *bmp,
				 struct uacce_dev_list *list)
{
	struct wd_ctx_params *ctx_params = attrs->ctx_params;
	__u32 op_type_num = ctx_params->op_type_num;
	int i, ret, max_node = numa_max_node() + 1;
	struct wd_ctx_nums ctx_nums;
	__u32 j, idx = 0;

	for (i = 0; i < max_node; i++) {
		if (!numa_bitmask_isbitset(bmp, i))
			continue;
		for (j = 0; j < op_type_num; j++) {
			ctx_nums = ctx_params->ctx_set_num[j];
			ret = wd_init_ctx_set(attrs, list, idx, i, j);
			if (ret)
				goto free_ctxs;
			ret = wd_instance_sched_set(attrs->sched, ctx_nums, idx, i, j);
			if (ret)
				goto free_ctxs;
			idx += (ctx_nums.sync_ctx_num + ctx_nums.async_ctx_num);
		}
	}

	return 0;

free_ctxs:
	wd_release_ctx_set(attrs->ctx_config);

	return ret;
}

static void wd_init_device_nodemask(struct uacce_dev_list *list, struct bitmask *bmp)
{
	struct uacce_dev_list *p = list;

	numa_bitmask_clearall(bmp);
	while (p) {
		numa_bitmask_setbit(bmp, p->dev->numa_id);
		p = p->next;
	}
}

static int wd_alg_ctx_init(struct wd_init_attrs *attrs)
{
	struct wd_ctx_config *ctx_config = attrs->ctx_config;
	struct wd_ctx_params *ctx_params = attrs->ctx_params;
	struct bitmask *used_bmp = ctx_params->bmp;
	struct uacce_dev_list *list, *used_list = NULL;
	__u32 ctx_set_num, op_type_num;
	int numa_cnt, ret;

	list = wd_get_accel_list(attrs->alg);
	if (!list) {
		WD_ERR("failed to get devices!\n");
		return -WD_ENODEV;
	}

	op_type_num = ctx_params->op_type_num;
	ctx_set_num = wd_get_ctx_numbers(*ctx_params, op_type_num);
	if (!ctx_set_num || !op_type_num) {
		WD_ERR("invalid: ctx_set_num is %u, op_type_num is %u!\n",
		       ctx_set_num, op_type_num);
		ret = -WD_EINVAL;
		goto out_freelist;
	}

	/*
	 * Not every numa has a device. Therefore, the first thing is to
	 * filter the devices in the selected numa node, and the second
	 * thing is to obtain the distribution of devices.
	 */
	used_list = wd_get_usable_list(list, used_bmp);
	if (WD_IS_ERR(used_list)) {
		ret = WD_PTR_ERR(used_list);
		WD_ERR("failed to get usable devices(%d)!\n", ret);
		goto out_freelist;
	}

	wd_init_device_nodemask(used_list, used_bmp);

	numa_cnt = numa_bitmask_weight(used_bmp);
	if (!numa_cnt) {
		ret = numa_cnt;
		WD_ERR("invalid: bmp is clear!\n");
		goto out_freeusedlist;
	}

	ctx_config->ctx_num = ctx_set_num * numa_cnt;
	ctx_config->ctxs = calloc(ctx_config->ctx_num, sizeof(struct wd_ctx));
	if (!ctx_config->ctxs) {
		ret = -WD_ENOMEM;
		WD_ERR("failed to alloc ctxs!\n");
		goto out_freeusedlist;
	}

	ret = wd_init_ctx_and_sched(attrs, used_bmp, used_list);
	if (ret)
		free(ctx_config->ctxs);

out_freeusedlist:
	wd_free_list_accels(used_list);
out_freelist:
	wd_free_list_accels(list);

	return ret;
}

static int wd_alg_ce_ctx_init(struct wd_init_attrs *attrs)
{
	struct wd_ctx_config *ctx_config = attrs->ctx_config;

	ctx_config->ctx_num = 1;
	ctx_config->ctxs = calloc(ctx_config->ctx_num, sizeof(struct wd_ctx));
	if (!ctx_config->ctxs) {
		WD_ERR("failed to alloc ctxs!\n");
		return -WD_ENOMEM;
	}

	ctx_config->ctxs[0].ctx = (handle_t)calloc(1, sizeof(struct wd_ce_ctx));
	if (!ctx_config->ctxs[0].ctx) {
		free(ctx_config->ctxs);
		return -WD_ENOMEM;
	}

	return WD_SUCCESS;
}

static void wd_alg_ce_ctx_uninit(struct wd_ctx_config *ctx_config)
{
	__u32 i;

	for (i = 0; i < ctx_config->ctx_num; i++) {
		if (ctx_config->ctxs[i].ctx) {
			free((struct wd_ce_ctx *)ctx_config->ctxs[i].ctx);
			ctx_config->ctxs[i].ctx = 0;
		}
	}

	free(ctx_config->ctxs);
}

static void wd_alg_ctx_uninit(struct wd_ctx_config *ctx_config)
{
	__u32 i;

	for (i = 0; i < ctx_config->ctx_num; i++) {
		if (ctx_config->ctxs[i].ctx) {
			wd_release_ctx(ctx_config->ctxs[i].ctx);
			ctx_config->ctxs[i].ctx = 0;
		}
	}

	free(ctx_config->ctxs);
}

static int wd_alg_init_sve_ctx(struct wd_ctx_config *ctx_config)
{
	struct wd_soft_ctx *ctx_sync, *ctx_async;

	ctx_config->ctx_num = WD_SOFT_CTX_NUM;
	ctx_config->ctxs = calloc(ctx_config->ctx_num, sizeof(struct wd_ctx));
	if (!ctx_config->ctxs)
		return -WD_ENOMEM;

	ctx_sync = calloc(1, sizeof(struct wd_soft_ctx));
	if (!ctx_sync)
		goto free_ctxs;

	ctx_config->ctxs[WD_SOFT_SYNC_CTX].op_type = 0;
	ctx_config->ctxs[WD_SOFT_SYNC_CTX].ctx_mode = CTX_MODE_SYNC;
	ctx_config->ctxs[WD_SOFT_SYNC_CTX].ctx = (handle_t)ctx_sync;

	ctx_async = calloc(1, sizeof(struct wd_soft_ctx));
	if (!ctx_async)
		goto free_ctx_sync;

	ctx_config->ctxs[WD_SOFT_ASYNC_CTX].op_type = 0;
	ctx_config->ctxs[WD_SOFT_ASYNC_CTX].ctx_mode = CTX_MODE_ASYNC;
	ctx_config->ctxs[WD_SOFT_ASYNC_CTX].ctx = (handle_t)ctx_async;

	return 0;

free_ctx_sync:
	free(ctx_sync);
free_ctxs:
	free(ctx_config->ctxs);
	return -WD_ENOMEM;
}

static void wd_alg_uninit_sve_ctx(struct wd_ctx_config *ctx_config)
{
	free((struct wd_soft_ctx *)ctx_config->ctxs[WD_SOFT_ASYNC_CTX].ctx);
	free((struct wd_soft_ctx *)ctx_config->ctxs[WD_SOFT_SYNC_CTX].ctx);
	free(ctx_config->ctxs);
}

int wd_alg_attrs_init(struct wd_init_attrs *attrs)
{
	wd_alg_poll_ctx alg_poll_func = attrs->alg_poll_ctx;
	wd_alg_init alg_init_func = attrs->alg_init;
	__u32 sched_type = attrs->sched_type;
	struct wd_ctx_config *ctx_config = NULL;
	struct wd_sched *alg_sched = NULL;
	char alg_type[CRYPTO_MAX_ALG_NAME];
	int driver_type = UADK_ALG_HW;
	const char *alg = attrs->alg;
	int ret = -WD_EINVAL;

	if (!attrs->ctx_params)
		return -WD_EINVAL;

	if (attrs->driver)
		driver_type = attrs->driver->calc_type;

	switch (driver_type) {
	case UADK_ALG_SOFT:
	case UADK_ALG_CE_INSTR:
		ctx_config = calloc(1, sizeof(*ctx_config));
		if (!ctx_config) {
			WD_ERR("fail to alloc ctx config\n");
			return -WD_ENOMEM;
		}
		attrs->ctx_config = ctx_config;

		/* Use default sched_type to alloc scheduler */
		alg_sched = wd_sched_rr_alloc(SCHED_POLICY_NONE, 1, 1, alg_poll_func);
		if (!alg_sched) {
			WD_ERR("fail to alloc scheduler\n");
			goto out_ctx_config;
		}

		attrs->sched = alg_sched;

		ret = wd_alg_ce_ctx_init(attrs);
		if (ret) {
			WD_ERR("fail to init ce ctx\n");
			goto out_freesched;
		}

		ret = alg_init_func(ctx_config, alg_sched);
		if (ret)
			goto out_pre_init;

		break;
	case UADK_ALG_SVE_INSTR:
		/* Use default sched_type to alloc scheduler */
		alg_sched = wd_sched_rr_alloc(SCHED_POLICY_SINGLE, 1, 1, alg_poll_func);
		if (!alg_sched) {
			WD_ERR("fail to alloc scheduler\n");
			return -WD_EINVAL;
		}
		attrs->sched = alg_sched;

		ctx_config = calloc(1, sizeof(*ctx_config));
		if (!ctx_config) {
			WD_ERR("fail to alloc ctx config\n");
			goto out_freesched;
		}
		attrs->ctx_config = ctx_config;

		ret = wd_alg_init_sve_ctx(ctx_config);
		if (ret) {
			WD_ERR("fail to init sve ctx!\n");
			goto out_freesched;
		}

		ctx_config->cap = attrs->ctx_params->cap;
		ret = alg_init_func(ctx_config, alg_sched);
		if (ret) {
			wd_alg_uninit_sve_ctx(ctx_config);
			goto out_freesched;
		}
		break;
	case UADK_ALG_HW:
		wd_get_alg_type(alg, alg_type);
		(void)strcpy(attrs->alg, alg_type);

		ctx_config = calloc(1, sizeof(*ctx_config));
		if (!ctx_config) {
			WD_ERR("fail to alloc ctx config\n");
			return -WD_ENOMEM;
		}
		attrs->ctx_config = ctx_config;

		alg_sched = wd_sched_rr_alloc(sched_type, attrs->ctx_params->op_type_num,
						  numa_max_node() + 1, alg_poll_func);
		if (!alg_sched) {
			WD_ERR("fail to instance scheduler\n");
			goto out_ctx_config;
		}
		attrs->sched = alg_sched;

		ret = wd_alg_ctx_init(attrs);
		if (ret) {
			WD_ERR("fail to init ctx\n");
			goto out_freesched;
		}

		ctx_config->cap = attrs->ctx_params->cap;
		ret = alg_init_func(ctx_config, alg_sched);
		if (ret)
			goto out_pre_init;
		break;
	default:
		WD_ERR("driver type error: %d\n", driver_type);
		return -WD_EINVAL;
	}

	return 0;

out_pre_init:
	if (driver_type == UADK_ALG_CE_INSTR || driver_type == UADK_ALG_SOFT)
		wd_alg_ce_ctx_uninit(ctx_config);
	else
		wd_alg_ctx_uninit(ctx_config);
out_freesched:
	wd_sched_rr_release(alg_sched);
out_ctx_config:
	if (ctx_config)
		free(ctx_config);
	return ret;
}

void wd_alg_attrs_uninit(struct wd_init_attrs *attrs)
{
	struct wd_ctx_config *ctx_config = attrs->ctx_config;
	struct wd_sched *alg_sched = attrs->sched;
	int driver_type = attrs->driver->calc_type;

	if (!ctx_config) {
		wd_sched_rr_release(alg_sched);
		return;
	}

	switch (driver_type) {
	case UADK_ALG_SOFT:
	case UADK_ALG_CE_INSTR:
		wd_alg_ce_ctx_uninit(ctx_config);
		break;
	case UADK_ALG_SVE_INSTR:
		wd_alg_uninit_sve_ctx(ctx_config);
		break;
	case UADK_ALG_HW:
		wd_alg_ctx_uninit(ctx_config);
		break;
	default:
		break;
	}

	free(ctx_config);
	wd_sched_rr_release(alg_sched);
}
