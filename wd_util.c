// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#define _GNU_SOURCE
#include <numa.h>
#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include "wd_alg_common.h"
#include "wd_util.h"
#include "wd_sched.h"

#define WD_ASYNC_DEF_POLL_NUM		1
#define WD_ASYNC_DEF_QUEUE_DEPTH	1024

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

static void clone_ctx_to_internal(struct wd_ctx *ctx,
				  struct wd_ctx_internal *ctx_in)
{
	ctx_in->ctx = ctx->ctx;
	ctx_in->op_type = ctx->op_type;
	ctx_in->ctx_mode = ctx->ctx_mode;
}

int wd_init_ctx_config(struct wd_ctx_config_internal *in,
		       struct wd_ctx_config *cfg)
{
	struct wd_ctx_internal *ctxs;
	int i, ret;

	if (!cfg->ctx_num) {
		WD_ERR("invalid parameters, ctx_num is 0!\n");
		return -WD_EINVAL;
	}

	/* ctx could only be invoked once for one process. */
	if (in->ctx_num && in->pid == getpid()) {
		WD_ERR("ctx have initialized.\n");
		return -WD_EEXIST;
	}

	ctxs = calloc(1, cfg->ctx_num * sizeof(struct wd_ctx_internal));
	if (!ctxs)
		return -WD_ENOMEM;

	for (i = 0; i < cfg->ctx_num; i++) {
		if (!cfg->ctxs[i].ctx) {
			WD_ERR("invalid parameters, ctx is NULL!\n");
			free(ctxs);
			return -WD_EINVAL;
		}

		clone_ctx_to_internal(cfg->ctxs + i, ctxs + i);
		ret = pthread_spin_init(&ctxs[i].lock, PTHREAD_PROCESS_SHARED);
		if (ret) {
			WD_ERR("init ctxs lock failed!\n");
			free(ctxs);
			return ret;
		}
	}

	in->ctxs = ctxs;
	in->pid = getpid();
	in->priv = cfg->priv;
	in->ctx_num = cfg->ctx_num;

	return 0;
}

int wd_init_sched(struct wd_sched *in, struct wd_sched *from)
{
	if (!from->name || !from->sched_init ||
	    !from->pick_next_ctx || !from->poll_policy)
		return -WD_EINVAL;

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
	int i;

	for (i = 0; i < in->ctx_num; i++)
		pthread_spin_destroy(&in->ctxs[i].lock);

	in->priv = NULL;
	in->ctx_num = 0;
	in->pid = 0;
	if (in->ctxs) {
		free(in->ctxs);
		in->ctxs = NULL;
	}
}

void wd_memset_zero(void *data, __u32 size)
{
	char *s = data;

	if (!s)
		return;

	while (size--)
		*s++ = 0;
}

static int init_msg_pool(struct msg_pool *pool, __u32 msg_num, __u32 msg_size)
{
	pool->msgs = calloc(1, msg_num * msg_size);
	if (!pool->msgs)
		return -WD_ENOMEM;

	pool->used = calloc(1, msg_num * sizeof(int));
	if (!pool->used) {
		free(pool->msgs);
		pool->msgs = NULL;
		return -WD_ENOMEM;
	}

	pool->msg_size = msg_size;
	pool->msg_num = msg_num;
	pool->tail = 0;

	return 0;
}

static void uninit_msg_pool(struct msg_pool *pool)
{
	free(pool->msgs);
	free(pool->used);
	pool->msgs = NULL;
	pool->used = NULL;
	memset(pool, 0, sizeof(*pool));
}

int wd_init_async_request_pool(struct wd_async_msg_pool *pool, __u32 pool_num,
			       __u32 msg_num, __u32 msg_size)
{
	int i, j, ret;

	pool->pool_num = pool_num;

	pool->pools = calloc(1, pool->pool_num * sizeof(struct msg_pool));
	if (!pool->pools)
		return -WD_ENOMEM;

	for (i = 0; i < pool->pool_num; i++) {
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
	int i;

	for (i = 0; i < pool->pool_num; i++)
		uninit_msg_pool(&pool->pools[i]);

	free(pool->pools);
	pool->pools = NULL;
	pool->pool_num = 0;
}

/* fix me: this is old wd_get_req_from_pool */
void *wd_find_msg_in_pool(struct wd_async_msg_pool *pool,
			  int ctx_idx, __u32 tag)
{
	struct msg_pool *p = &pool->pools[ctx_idx];
	__u32 msg_num = p->msg_num;

	/* tag value start from 1 */
	if (tag == 0 || tag > msg_num) {
		WD_ERR("invalid message cache tag(%u)\n", tag);
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
	int cnt = 0;
	__u32 idx = p->tail;

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
		WD_ERR("invalid message cache idx(%u)\n", tag);
		return;
	}

	__atomic_clear(&p->used[tag - 1], __ATOMIC_RELEASE);
}

int wd_check_datalist(struct wd_datalist *head, __u32 size)
{
	struct wd_datalist *tmp = head;
	__u32 list_size = 0;

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
		WD_ERR("-> %s: %d: sync num: %lu\n", __func__, i,
		       config_numa->sync_ctx_num);
		WD_ERR("-> %s: %d: async num: %lu\n", __func__, i,
		       config_numa->async_ctx_num);
		for (j = 0; j < CTX_MODE_MAX; j++)
			for (k = 0; k < config_numa->op_type_num; k++) {
				WD_ERR("-> %s: %d: [%d][%d].begin: %u\n",
				       __func__,
				       i, j, k, ctx_table[j][k].begin);
				WD_ERR("-> %s: %d: [%d][%d].end: %u\n",
				       __func__,
				       i, j, k, ctx_table[j][k].end);
				WD_ERR("-> %s: %d: [%d][%d].size: %u\n",
				       __func__,
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

	if (i == config->numa_num)
		return NULL;

	return config_numa;
}

static void wd_free_numa(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa;
	int i;

	if (!config->config_per_numa)
		return;

	FOREACH_NUMA(i, config, config_numa)
		free(config_numa->dev);

	free(config->config_per_numa);
	config->config_per_numa = NULL;
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
		if (list->dev->numa_id < 0) {
			list->dev->numa_id = 0;
		} else if (list->dev->numa_id >= size) {
			WD_ERR("numa id is wrong(%d)\n", list->dev->numa_id);
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
		if (!config_numa) {
			WD_ERR("%s got wrong numa node!\n", __func__);
			break;
		}

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
		WD_ERR("no device to support %s\n", ops->alg_name);
		ret = -WD_ENODEV;
		goto free_numa_dev_num;
	}

	/* get numa num and device num of each numa from uacce_dev list */
	config->numa_num = wd_get_dev_numa(head, numa_dev_num, max_node);
	if (config->numa_num == 0 || config->numa_num > max_node) {
		WD_ERR("numa num err(%u)!\n", config->numa_num);
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
	wd_free_list_accels(head);
free_numa_dev_num:
	free(numa_dev_num);
	return ret;
}

static int is_number(const char *str)
{
	int len, i;

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

/* 1 enable, 0 disable, others error */
int wd_parse_async_poll_en(struct wd_env_config *config, const char *s)
{
	int tmp;

	if (!is_number(s)) {
		WD_ERR("invalid async poll en flag: %s!\n", s);
		return -WD_EINVAL;
	}

	tmp = strtol(s, NULL, 10);
	if (tmp != 0 && tmp != 1) {
		WD_ERR("async poll en flag is not 0 or 1!\n");
		return -WD_EINVAL;
	}

	config->enable_internal_poll = tmp;

	return 0;
}

static int parse_num_on_numa(const char *s, int *num, int *node)
{
	char *sep, *start, *left;

	if (!strlen(s)) {
		WD_ERR("input string length is zero!\n");
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
	WD_ERR("input env format is invalid:%s\n", s);
	free(start);
	return -WD_EINVAL;
}

static int wd_alloc_ctx_table(struct wd_env_config_per_numa *config_numa)
{
	struct wd_ctx_range **ctx_table;
	int i, j, ret;

	if (config_numa->ctx_table)
		return 0;

	ctx_table = calloc(1, sizeof(struct wd_ctx_range *) * CTX_MODE_MAX);
	if (!ctx_table)
		return -WD_ENOMEM;

	for (i = 0; i < CTX_MODE_MAX; i++) {
		ctx_table[i] = calloc(1,
				sizeof(struct wd_ctx_range) *
				config_numa->op_type_num);
		if (!ctx_table[i]) {
			ret = -WD_ENOMEM;
			goto free_mem;
		}
	}

	config_numa->ctx_table = ctx_table;

	return 0;

free_mem:
	for (j = 0; j < i; j++) {
		free(ctx_table[j]);
		ctx_table[j] = NULL;
	}

	free(ctx_table);
	return ret;
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
		WD_ERR("%s got wrong format: %s!\n", __func__, section);
		return -WD_EINVAL;
	}

	ctx_section++;

	ret = parse_num_on_numa(ctx_section, &ctx_num, &node);
	if (ret)
		return ret;

	config_numa = wd_get_config_numa(config, node);
	if (!config_numa) {
		WD_ERR("%s got wrong numa node: %s!\n", __func__, section);
		return -WD_EINVAL;
	}

	config_numa->op_type_num = config->op_type_num;
	ret = wd_alloc_ctx_table(config_numa);
	if (ret)
		return ret;

	ret = get_and_fill_ctx_num(config_numa, section, ctx_num);
	if (ret)
		WD_ERR("%s got wrong ctx type: %s!\n", __func__, section);

	return ret;
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
	struct wd_env_config_per_numa *config_numa;
	char *left, *section, *start;
	int i, ret;

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
	FOREACH_NUMA(i, config, config_numa)
		free(config_numa->ctx_table);

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
			WD_ERR("%s got wrong numa node: %s!\n",
				__func__, section);
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
	int ret, i;

	for (i = 0; i < config->table_size; i++) {
		var = config->table + i;

		var_s = secure_getenv(var->name);
		if (!var_s || !strlen(var_s)) {
			var_s = var->def_val;
			WD_ERR("no %s environment variable! Use default: %s\n",
			       var->name, var->def_val);
		}

		ret = var->parse_fn(config, var_s);
		if (ret) {
			WD_ERR("fail to parse %s environment variable!\n",
			       var->name);
			return -WD_EINVAL;
		}
	}

	return 0;
}

static void wd_free_env(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa;
	int i, j;

	if (!config->config_per_numa)
		return;

	FOREACH_NUMA(i, config, config_numa) {
		if (!config_numa->ctx_table)
			continue;

		for (j = 0; j < CTX_MODE_MAX; j++)
			free(config_numa->ctx_table[j]);

		free(config_numa->ctx_table);
	}
}

static int wd_parse_ctx_attr(struct wd_env_config *env_config,
			     struct wd_ctx_attr *attr)
{
	struct wd_env_config_per_numa *config_numa;
	int ret;

	config_numa = wd_get_config_numa(env_config, attr->node);
	if (!config_numa) {
		WD_ERR("%s got wrong numa node!\n", __func__);
		return -WD_EINVAL;
	}

	config_numa->op_type_num = env_config->op_type_num;
	ret = wd_alloc_ctx_table(config_numa);
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
	config->op_type_num = 0;
	config->table_size = 0;
	config->table = NULL;

	wd_free_env(config);
}

static __u8 get_ctx_mode(struct wd_env_config_per_numa *config, int idx)
{
	struct wd_ctx_range **ctx_table = config->ctx_table;
	int i;

	for (i = 0; i < config->op_type_num; i++) {
		if ((idx >= ctx_table[CTX_MODE_SYNC][i].begin) &&
		    (idx <= ctx_table[CTX_MODE_SYNC][i].end) &&
		    ctx_table[CTX_MODE_SYNC][i].size)
			return CTX_MODE_SYNC;
	}
	return CTX_MODE_ASYNC;
}

static int get_op_type(struct wd_env_config_per_numa *config,
		       int idx, __u8 ctx_mode)
{
	struct wd_ctx_range **ctx_table = config->ctx_table;
	int i;

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
			 struct wd_ctx_config *ctx_config, int start)
{
	int ctx_num = config->sync_ctx_num + config->async_ctx_num;
	handle_t h_ctx;
	int i, j, ret;

	if (!ctx_num)
		return 0;

	for (i = start; i < start + ctx_num; i++) {
		h_ctx = request_ctx_on_numa(config);
		if (!h_ctx) {
			ret = -WD_EBUSY;
			WD_ERR("err: request too many ctxs\n");
			goto free_ctx;
		}

		ctx_config->ctxs[i].ctx = h_ctx;
		ctx_config->ctxs[i].ctx_mode = get_ctx_mode(config, i);
		ret = get_op_type(config, i, ctx_config->ctxs[i].ctx_mode);
		if (ret < 0)
			goto free_ctx;

		ctx_config->ctxs[i].op_type = ret;
	}

	return 0;

free_ctx:
	for (j = start; j < i; j++)
		wd_release_ctx(ctx_config->ctxs[j].ctx);
	return ret;
}

static void wd_put_wd_ctx(struct wd_ctx_config *ctx_config, int ctx_num)
{
	__u32 i;

	for (i = 0; i < ctx_num; i++)
		wd_release_ctx(ctx_config->ctxs[i].ctx);
}

static int wd_alloc_ctx(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa;
	struct wd_ctx_config *ctx_config;
	int ctx_num = 0, start = 0, ret = 0;
	int i;

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
	int num = 0;
	int i;

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
		WD_ERR("invalid parameter, async_poll_num of numa is zero!\n");
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

/* fix me: all return value here, and no config input */
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
	pthread_exit(NULL);
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
		WD_ERR("empty_sem init failed.\n");
		goto err_free_head;
	}

	if (sem_init(&task_queue->full_sem, 0, 0)) {
		WD_ERR("full_sem init failed.\n");
		goto err_uninit_empty_sem;
	}

	if (pthread_mutex_init(&task_queue->lock, NULL)) {
		WD_ERR("mutex init failed.\n");
		goto err_uninit_full_sem;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	task_queue->tid = 0;
	if (pthread_create(&thread_id, &attr, async_poll_process_func,
			   task_queue)) {
		WD_ERR("create poll thread failed.\n");
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

	num = fmin(config_numa->async_poll_num, config_numa->async_ctx_num);

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
	num = fmin(config_numa->async_poll_num, config_numa->async_ctx_num);

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
		WD_ERR("input parameter num or is_enable is NULL!\n");
		return -WD_EINVAL;
	}

	*is_enable = env_config->enable_internal_poll;

	config_numa = wd_get_config_numa(env_config, attr.node);
	if (!config_numa) {
		WD_ERR("%s got wrong numa node: %u!\n",
				__func__, attr.node);
		return -WD_EINVAL;
	}

	*num = (config_numa->ctx_table) ?
	       config_numa->ctx_table[attr.mode][attr.type].size : 0;

	return 0;
}

int wd_set_ctx_attr(struct wd_ctx_attr *ctx_attr,
		     __u32 node, __u32 type, __u8 mode, __u32 num)
{
	if (mode >= CTX_MODE_MAX) {
		WD_ERR("wrong ctx mode(%u))!\n", mode);
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
		WD_ERR("ctx %u mode = %hhu error!\n", idx, ctx->ctx_mode);
		return -WD_EINVAL;
	}

	return 0;
}
