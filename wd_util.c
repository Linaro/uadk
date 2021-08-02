// SPDX-License-Identifier: Apache-2.0
#include <numa.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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
	int head;
	int tail;
};

/* parse wd env begin */

/* define comp's combination of two operation type and two mode here */
static const char *comp_ctx_type[2][2] = {
	{"sync-comp:", "sync-decomp:"},
	{"async-comp:", "async-decomp:"}
};

/* define two ctx mode here for cipher and other alg*/
static const char *ctx_type[2][1] = { {"sync:"}, {"async:"} };

struct async_task {
	__u32 index;
};

struct async_task_queue {
	struct async_task *head;
	int depth;
	int prod;
	int cons;
	int cur_task;
	int left_task;
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
	int i;

	if (!cfg->ctx_num) {
		WD_ERR("invalid parameters, ctx_num is 0!\n");
		return -WD_EINVAL;
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
		pthread_spin_init(&ctxs[i].lock, PTHREAD_PROCESS_SHARED);
	}

	in->ctxs = ctxs;
	in->priv = cfg->priv;
	in->ctx_num = cfg->ctx_num;

	return 0;
}

int wd_init_sched(struct wd_sched *in, struct wd_sched *from)
{
	if (!from->name)
		return -WD_EINVAL;

	in->h_sched_ctx = from->h_sched_ctx;
	in->name = strdup(from->name);
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
	if (in->ctxs)
		free(in->ctxs);
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
		return -WD_ENOMEM;
	}

	pool->msg_size = msg_size;
	pool->msg_num = msg_num;
	pool->head = 0;
	pool->tail = 0;

	return 0;
}

static void uninit_msg_pool(struct msg_pool *pool)
{
	free(pool->msgs);
	free(pool->used);
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
void *wd_find_msg_in_pool(struct wd_async_msg_pool *pool, int index, __u32 tag)
{
	struct msg_pool *p;
	__u32 msg_num = pool->pools[index].msg_num;

	/* tag value start from 1 */
	if (tag == 0 || tag > msg_num) {
		WD_ERR("invalid message cache tag(%u)\n", tag);
		return NULL;
	}

	p = &pool->pools[index];

	return p->msgs + p->msg_size * (tag - 1);
}

int wd_get_msg_from_pool(struct wd_async_msg_pool *pool, int index, void **msg)
{
	struct msg_pool *p;
	__u32 msg_num = pool->pools[index].msg_num;
	__u32 msg_size;
	int cnt = 0;
	int idx = 0;

	p = &pool->pools[index];
	msg_size = p->msg_size;

	while (__atomic_test_and_set(&p->used[idx], __ATOMIC_ACQUIRE)) {
		idx = (idx + 1) % msg_num;
		cnt++;
		if (cnt == msg_num)
			return -WD_EBUSY;
	}

	*msg = p->msgs + msg_size * idx;

	return idx + 1;
}

void wd_put_msg_to_pool(struct wd_async_msg_pool *pool, int index, __u32 tag)
{
	struct msg_pool *p;
	__u32 msg_num = pool->pools[index].msg_num;

	/* tag value start from 1 */
	if (!tag || tag > msg_num) {
		WD_ERR("invalid message cache idx(%u)\n", tag);
		return;
	}

	p = &pool->pools[index];

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

static int wd_alloc_numa(struct wd_env_config *config,
			 const struct wd_alg_ops *ops)
{
	struct wd_env_config_per_numa *config_numa;
	struct uacce_dev_list *list, *head;
	int numa_id[MAX_NUMA_NUM] = {0};
	int i, numa_num = 0;

	/* get uacce_dev */
	head = wd_get_accel_list(ops->alg_name);
	if (!head) {
		WD_ERR("no device to support %s\n", ops->alg_name);
		return 0;
	}

	list = head;
	while (list) {
		if (list->dev->numa_id < 0) {
			numa_id[numa_num++] = 0;
			break;
		}

		numa_id[numa_num++] = list->dev->numa_id;
		list = list->next;
	}

	config->numa_num = numa_num;
	config->config_per_numa = calloc(numa_num, sizeof(*config_numa));
	if (!config->config_per_numa) {
		wd_free_list_accels(head);
		return -ENOMEM;
	}

	list = head;
	FOREACH_NUMA(i, config, config_numa) {
		config_numa->node = numa_id[i];
		memcpy(&config_numa->dev, list->dev, sizeof(*list->dev));
		list = list->next;
	}

	wd_free_list_accels(head);

	return 0;
}

static void wd_free_numa(struct wd_env_config *config)
{
	free(config->config_per_numa);
}

static int is_number(const char *str)
{
	int len = strlen(str);
	int i;

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

static int parse_ctx_num_on_numa(const char *s, int *ctx_num, int *node)
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
	if (is_number(sep) && is_number(left)) {
		*ctx_num = strtol(sep, NULL, 10);
		*node = strtol(left, NULL, 10);
		free(start);
		return 0;
	}

	WD_ERR("input env format is invaild:%s\n", s);
	free(start);
	return -WD_EINVAL;
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

static int wd_alloc_ctx_table(struct wd_env_config_per_numa *config_numa)
{
	struct wd_ctx_range **ctx_table;
	int i;

	if (config_numa->ctx_table)
		return 0;

	ctx_table = calloc(1, sizeof(struct wd_ctx_range *) * CTX_MODE_MAX);
	if (!ctx_table)
		return -ENOMEM;

	for (i = 0; i < CTX_MODE_MAX; i++)
		ctx_table[i] = calloc(1,
				sizeof(struct wd_ctx_range) *
				config_numa->op_type_num);

	config_numa->ctx_table = ctx_table;

	return 0;
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
	if (!ctx_section)
		return -WD_EINVAL;

	ctx_section++;

	ret = parse_ctx_num_on_numa(ctx_section, &ctx_num, &node);
	if (ret)
		return ret;

	config_numa = wd_get_config_numa(config, node);
	if (!config_numa) {
		WD_ERR("%s got wrong numa node: %s!\n", __func__, section);
		ret = -WD_EINVAL;
		return ret;
	}

	config_numa->op_type_num = config->op_type_num;
	ret = wd_alloc_ctx_table(config_numa);
	if (ret)
		return ret;

	ret = get_and_fill_ctx_num(config_numa, section, ctx_num);
	if (ret)
		WD_ERR("wrong comp ctx type: %s!\n", section);

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

static int set_ctx_index(struct wd_env_config_per_numa *config_numa,
			      __u8 mode, int *start)
{
	struct wd_ctx_range **ctx_table = config_numa->ctx_table;
	int size, j, k, sum = 0;

	for (j = 0; j < config_numa->op_type_num; j++)
		sum += ctx_table[mode][j].size;

	if (mode)
		config_numa->async_ctx_num = sum;
	else
		config_numa->sync_ctx_num = sum;

	if (sum) {
		for (k = 0; k < config_numa->op_type_num; k++) {
			size = ctx_table[mode][k].size;
			if (!size)
				continue;
			ctx_table[mode][k].begin = *start;
			ctx_table[mode][k].end = *start + size - 1;
			*start += size;
		}
	}

	return 0;
}

static int wd_fill_ctx_table(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa;
	int start, i, ret;

	FOREACH_NUMA(i, config, config_numa) {
		if (!config_numa->ctx_table)
			continue;

		start = get_start_ctx_index(config, config_numa);

		ret = set_ctx_index(config_numa, CTX_MODE_SYNC, &start);
		if (ret)
			return ret;

		ret = set_ctx_index(config_numa, CTX_MODE_ASYNC, &start);
		if (ret)
			return ret;
	}

	return 0;
}

static int parse_ctx_num(struct wd_env_config *config, const char *s)
{
	struct wd_env_config_per_numa *config_numa;
	char *left, *section, *start;
	int i, ret;

	start = strdup(s);
	if (!start)
		return -ENOMEM;

	left = start;

	while ((section = strsep(&left, ","))) {
		ret = wd_parse_section(config, section);
		if (ret)
			goto err_free_ctx_table;
	}

	ret = wd_fill_ctx_table(config);
	if (ret) {
		WD_ERR("check uadk comp ctx failed!\n");
		goto err_free_ctx_table;
	}

	free(start);

	return 0;

err_free_ctx_table:
	FOREACH_NUMA(i, config, config_numa)
		if (config_numa->ctx_table)
			free(config_numa->ctx_table);
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
	int ret, i;

	for (i = 0; i < config->table_size; i++) {
		var = config->table + i;
		if (config->disable_env)
			var_s = var->def_val;
		else
			var_s = getenv(var->name);

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

	FOREACH_NUMA(i, config, config_numa) {
		if (!config_numa->ctx_table)
			continue;

		for (j = 0; j < CTX_MODE_MAX; j++)
			free(config_numa->ctx_table[j]);
		free(config_numa->ctx_table);
		free(config_numa->async_task_queue_array);
	}
}

static __u8 get_ctx_mode(struct wd_env_config_per_numa *config, int index)
{
	struct wd_ctx_range **ctx_table = config->ctx_table;
	int i;

	for (i = 0; i < config->op_type_num; i++) {
		if ((index >= ctx_table[CTX_MODE_SYNC][i].begin) &&
		    (index <= ctx_table[CTX_MODE_SYNC][i].end) &&
		    ctx_table[CTX_MODE_SYNC][i].size)
			return CTX_MODE_SYNC;
	}
	return CTX_MODE_ASYNC;
}

static int get_op_type(struct wd_env_config_per_numa *config,
		       int index, __u8 ctx_mode)
{
	struct wd_ctx_range **ctx_table = config->ctx_table;
	int i;

	if (config->op_type_num == 1)
		return 0;

	for (i = 0; i < config->op_type_num; i++) {
		if ((index >= ctx_table[ctx_mode][i].begin) &&
		    (index <= ctx_table[ctx_mode][i].end) &&
		    ctx_table[ctx_mode][i].size)
			return i;
	}

	return -WD_EINVAL;
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
		h_ctx = wd_request_ctx(&config->dev);
		if (!h_ctx) {
			ret = -WD_EBUSY;
			goto free_ctx;
		}

		ctx_config->ctxs[i].ctx = h_ctx;
		/* put sync ctx in front of async ctx */
		ctx_config->ctxs[i].ctx_mode = get_ctx_mode(config, i);
		ret = get_op_type(config, i, ctx_config->ctxs[i].ctx_mode);
		if (ret < 0)
			goto free_ctx;

		ctx_config->ctxs[i].op_type = ret;
	}

	return 0;

free_ctx:
	for (j = 0; j < i; j++)
		wd_release_ctx(ctx_config->ctxs[j].ctx);
	return ret;
}

static void wd_put_wd_ctx(struct wd_ctx_config *ctx_config, int ctx_num)
{
	__u32 i;

	for (i = 0; i < ctx_num; i++)
		wd_release_ctx(ctx_config->ctxs[i].ctx);

	free(ctx_config->ctxs);
}

static struct wd_ctx_config *wd_alloc_ctx(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa;
	struct wd_ctx_config *ctx_config;
	int i, ctx_num = 0, start = 0, ret = 0;

	ctx_config = calloc(1, sizeof(*ctx_config));
	if (!ctx_config)
		return WD_ERR_PTR(-ENOMEM);

	FOREACH_NUMA(i, config, config_numa)
		ctx_num += config_numa->sync_ctx_num + config_numa->async_ctx_num;

	ctx_config->ctxs = calloc(ctx_num, sizeof(struct wd_ctx));
	if (!ctx_config->ctxs) {
		ret = -ENOMEM;
		goto err_free_ctx_config;
	}
	ctx_config->ctx_num = ctx_num;

	FOREACH_NUMA(i, config, config_numa) {
		ret = wd_get_wd_ctx(config_numa, ctx_config, start);
		if (ret) {
			ret = -WD_EBUSY;
			goto err_free_ctxs;
		}
		start += config_numa->sync_ctx_num + config_numa->async_ctx_num;
	}

	return ctx_config;

err_free_ctxs:
	wd_put_wd_ctx(ctx_config, start);
	free(ctx_config->ctxs);
err_free_ctx_config:
	free(ctx_config);
	return WD_ERR_PTR(ret);
}

static void wd_free_ctx(struct wd_ctx_config *ctx_config)
{

	 wd_put_wd_ctx(ctx_config, ctx_config->ctx_num);
	 free(ctx_config);
}

static int wd_sched_fill_table(struct wd_env_config_per_numa *config_numa,
			       struct wd_sched *sched, __u8 mode, int type_num)
{
	struct wd_ctx_range **ctx_table;
	int i, ret, ctx_num;

	if (mode)
		ctx_num = config_numa->async_ctx_num;
	else
		ctx_num = config_numa->sync_ctx_num;

	ctx_table = config_numa->ctx_table;
	for (i = 0; i < type_num && ctx_num; i++) {
		if (!ctx_table[mode][i].size)
			continue;

		ret = sample_sched_fill_data(
				sched, config_numa->node,
				mode, i,
				ctx_table[mode][i].begin,
				ctx_table[mode][i].end);
		if (ret)
			return ret;
	}

	return 0;
}

static struct wd_sched *wd_init_sched_config(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa;
	struct wd_sched *sched;
	int i, j, ret, type_num = config->op_type_num;
	void *func = NULL;

	if (!config->enable_internal_poll)
		func = config->alg_poll_ctx;

	sched = sample_sched_alloc(SCHED_POLICY_RR, type_num,
				   MAX_NUMA_NUM, func);
	if (!sched)
		return NULL;

	sched->name = "SCHED_RR";

	FOREACH_NUMA(i, config, config_numa) {
		for (j = 0; j < CTX_MODE_MAX; j++) {
			ret = wd_sched_fill_table(config_numa,
						  sched, j,
						  type_num);
			if (ret)
				goto err_release_sched;
		}
	}

	return sched;

err_release_sched:
	sample_sched_release(sched);
	return WD_ERR_PTR(ret);
}

static void wd_uninit_sched_config(struct wd_sched *sched_config)
{
	return sample_sched_release(sched_config);
}

static struct async_task_queue *find_async_queue(struct wd_env_config *config,
						 __u32 index)
{
	struct wd_env_config_per_numa *config_numa;
	int i, num = 0;

	FOREACH_NUMA(i, config, config_numa) {
		num += config_numa->sync_ctx_num + config_numa->async_ctx_num;
		if (index < num)
			break;
	}

	return config_numa->async_task_queue_array;
}

/* fix me: all return value here, and no config input */
int wd_add_task_to_async_queue(struct wd_env_config *config, __u32 index)
{
	struct async_task_queue *task_queue;
	struct async_task *head, *task;
	int prod;

	if (!config->enable_internal_poll)
		return 0;

	task_queue = find_async_queue(config, index);
	if (sem_wait(&task_queue->empty_sem))
		return 0;

	if (pthread_mutex_lock(&task_queue->lock))
		return 0;

	prod = task_queue->prod;
	head = task_queue->head;
	task = head + prod;
	/* fix me */
	task->index = index;

	prod = (prod + 1) % task_queue->depth;
	task_queue->prod = prod;
	task_queue->cur_task++;
	task_queue->left_task--;

	if (pthread_mutex_unlock(&task_queue->lock))
		return 0;

	if (sem_post(&task_queue->full_sem))
		return 0;

	return 1;
}

/* fix me: return value */
static void *async_poll_process_func(void *args)
{
	struct async_task_queue *task_queue = args;
	struct async_task *head, *task;
	__u32 count;
	int cons;

	while (1) {
		if (sem_wait(&task_queue->full_sem)) {
			if (errno == EINTR) {
				continue;
			}
		}

		if (pthread_mutex_lock(&task_queue->lock))
			return NULL;

		cons = task_queue->cons;
		head = task_queue->head;
		task = head + cons;

		task_queue->cons = (cons + 1) % task_queue->depth;
		task_queue->cur_task--;
		task_queue->left_task++;

		if (pthread_mutex_unlock(&task_queue->lock))
			return NULL;

		/* fix me: poll a group of ctxs */
		task_queue->alg_poll_ctx(task->index, 1, &count);

		if (sem_post(&task_queue->empty_sem))
			return NULL;
	}
}

static int wd_init_one_task_queue(struct async_task_queue *task_queue,
				  int (*alg_poll_ctx)(__u32, __u32, __u32 *))

{
	struct async_task *head;
	pthread_t thread_id;
	int depth, ret;

	task_queue->depth = depth = WD_ASYNC_DEF_QUEUE_DEPTH;

	head = calloc(task_queue->depth, sizeof(*head));
	if (!head)
		return -ENOMEM;

	task_queue->head = head;
	task_queue->left_task = depth;
	task_queue->alg_poll_ctx = alg_poll_ctx;

	if (sem_init(&task_queue->empty_sem, 0, depth)) {
		ret = -1;
		goto err_free_head;
	}

	if (sem_init(&task_queue->full_sem, 0, 0)) {
		ret = -2;
		goto err_uninit_empty_sem;
	}

	if (pthread_mutex_init(&task_queue->lock, NULL)) {
		ret = -3;
		goto err_uninit_full_sem;
	}

	/* fix me: make pthread joined? */
	if (pthread_create(&thread_id, NULL, async_poll_process_func,
			   task_queue)) {
		ret = -4;
		goto err_destory_mutex;
	}
	task_queue->tid = thread_id;

	return 0;

err_destory_mutex:
	pthread_mutex_destroy(&task_queue->lock);
err_uninit_full_sem:
	sem_destroy(&task_queue->full_sem);
err_uninit_empty_sem:
	sem_destroy(&task_queue->empty_sem);
err_free_head:
	free(head);
	return ret;
}

static void wd_uninit_one_task_queue(struct async_task_queue *task_queue)
{
	pthread_cancel(task_queue->tid);
	pthread_mutex_destroy(&task_queue->lock);
	sem_destroy(&task_queue->full_sem);
	sem_destroy(&task_queue->empty_sem);
	free(task_queue->head);
}

static int wd_init_async_polling_thread_per_numa(struct wd_env_config *config,
				struct wd_env_config_per_numa *config_numa)
{
	struct async_task_queue *task_queue, *head;
	int i, j, ret;

	if (!config_numa->async_ctx_num)
		return 0;

	config_numa->async_poll_num = WD_ASYNC_DEF_POLL_NUM;

	/* make max task queues as the number of async ctxs */
	task_queue = calloc(config_numa->async_ctx_num, sizeof(*head));
	if (!task_queue)
		return -ENOMEM;
	config_numa->async_task_queue_array = head = task_queue;

	for (i = 0; i < config_numa->async_poll_num; task_queue++, i++) {
		ret = wd_init_one_task_queue(task_queue, config->alg_poll_ctx);
		if (ret) {
			task_queue = head;
			for (j = 0; j < i; task_queue++, j++)
				wd_uninit_one_task_queue(task_queue);
			free(head);
			return ret;
		}
	}

	return 0;
}

static int wd_init_async_polling_thread(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa;
	int i;

	if (!config->enable_internal_poll)
		return 0;

	FOREACH_NUMA(i, config, config_numa)
		wd_init_async_polling_thread_per_numa(config, config_numa);

	return 0;
}

static void wd_uninit_async_polling_thread(struct wd_env_config *config)
{
}

static int wd_init_resource(struct wd_env_config *config,
			    const struct wd_alg_ops *ops)
{
	struct wd_ctx_config *ctx_config;
	struct wd_sched *sched_config;
	int ret = 0;

	ctx_config = wd_alloc_ctx(config);
	if (WD_IS_ERR(ctx_config))
		return -WD_EBUSY;
	config->ctx_config = ctx_config;

	config->alg_poll_ctx = ops->alg_poll_ctx;
	sched_config = wd_init_sched_config(config);
	if (WD_IS_ERR(sched_config))
		goto err_uninit_ctx;
	config->sched = sched_config;

	ret = ops->alg_init(ctx_config, sched_config);
	if (ret)
		goto err_uninit_sched;

	ret = wd_init_async_polling_thread(config);
	if (ret)
		goto err_uninit_alg;

	return 0;

err_uninit_alg:
	ops->alg_uninit();
err_uninit_sched:
	wd_uninit_sched_config(sched_config);
err_uninit_ctx:
	wd_free_ctx(ctx_config);
	return ret;
}

static void wd_uninit_resource(struct wd_env_config *config)
{
	wd_uninit_async_polling_thread(config);
	config->alg_uninit();
	wd_uninit_sched_config(config->sched);
	wd_free_ctx(config->ctx_config);
}

static void *wd_alloc_table(const struct wd_config_variable *table,
				 __u32 table_size)
{
	struct wd_config_variable *alg_table;
	int i;

	alg_table = malloc(table_size * sizeof(struct wd_config_variable));
	if (!alg_table)
		return NULL;

	memcpy(alg_table, table,
			table_size * sizeof(struct wd_config_variable));
	for (i = 0; i < table_size - 1; i++) {
		alg_table[i].def_val = malloc(MAX_STR_LEN);
		if (!alg_table[i].def_val) {
			WD_ERR("%s malloc fail\n", __func__);
			goto free_mem;
		}
	}

	return alg_table;

free_mem:
	for (i = i - 1; i >= 0; i--)
		free(alg_table[i].def_val);

	free(alg_table);
	return NULL;
}

static int wd_alg_table_init(const struct wd_config_variable *table,
			     __u32 table_size,
			     struct wd_ctx_attr *attr,
			     struct wd_env_config *env_config)
{
	struct wd_config_variable *var_tbl;
	const char *type_tbl;

	if (!attr) {
		env_config->disable_env = 0;
		env_config->table = table;
		return 0;
	}

	env_config->disable_env = 1;

	var_tbl = wd_alloc_table(table, table_size);
	if (!var_tbl)
		return -WD_ENOMEM;

	env_config->table = var_tbl;

	/**
	 * Below def_val's memory is allocated from wd_alloc_table,
	 * the length of memory allocated to def_val is MAX_STR_LEN.
	 *
	 * We use mode and type as index of a string two-dimensional
	 * array to init def_val.
	 */
	if (env_config->op_type_num == 1)
		type_tbl = ctx_type[attr->mode][attr->type];
	else
		type_tbl = comp_ctx_type[attr->mode][attr->type];

	snprintf(var_tbl[0].def_val, MAX_STR_LEN, "%s%u%c%u",
		 type_tbl, attr->num, '@', attr->node);

	return 0;
}

static void wd_alg_table_uninit(struct wd_env_config *config)
{
	int i;

	if (!config->disable_env)
		return;

	for (i = 0; i < config->table_size - 1; i++)
		free(config->table[i].def_val);

	free((struct wd_config_variable *)config->table);
}

int wd_alg_env_init(struct wd_env_config *env_config,
		    const struct wd_config_variable *table,
		    const struct wd_alg_ops *ops,
		    __u32 table_size,
		    struct wd_ctx_attr *ctx_attr)
{
	int ret;

	env_config->op_type_num = ops->op_type_num;
	env_config->table_size = table_size;

	ret = wd_alg_table_init(table, table_size,
				ctx_attr, env_config);
	if (ret)
		return ret;

	ret = wd_alloc_numa(env_config, ops);
	if (ret)
		goto table_uninit;

	ret = wd_parse_env(env_config);
	if (ret)
		goto free_numa;

	ret = wd_init_resource(env_config, ops);
	if (ret)
		goto free_env;

	/* Use alg_uninit as a sign of initialization complete */
	env_config->alg_uninit = ops->alg_uninit;

	return 0;

free_env:
	wd_free_env(env_config);
free_numa:
	wd_free_numa(env_config);
table_uninit:
	wd_alg_table_uninit(env_config);
	return ret;
}

void wd_alg_env_uninit(struct wd_env_config *env_config)
{
	/* Check whether the initialization is complete */
	if (!env_config->alg_uninit)
		return;

	wd_uninit_resource(env_config);
	wd_free_env(env_config);
	wd_free_numa(env_config);
	wd_alg_table_uninit(env_config);
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

	*num = config_numa->ctx_table[attr.mode][attr.type].size;

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
