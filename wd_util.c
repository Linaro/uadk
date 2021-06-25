// SPDX-License-Identifier: Apache-2.0
#include <numa.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include "wd_alg_common.h"
#include "wd_util.h"
#include "sched_sample.h"

#define WD_ASYNC_DEF_POLL_NUM		1
#define WD_ASYNC_DEF_QUEUE_DEPTH	1024
#define MAX_NUMA_NUM			4

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

	pool->pools = calloc(1, pool_num * sizeof(struct msg_pool));
	if (!pool->pools)
		return -WD_ENOMEM;

	pool->pool_num = pool_num;
	for (i = 0; i < pool_num; i++) {
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
	__u32 msg_num = pool->pools[index].msg_num;
	struct msg_pool *p;

	/* tag value start from 1 */
	if (tag == 0 || tag > msg_num) {
		WD_ERR("invalid message cache tag(%d)\n", tag);
		return NULL;
	}

	p = &pool->pools[index];

	return p->msgs + p->msg_size * (tag - 1);
}

int wd_get_msg_from_pool(struct wd_async_msg_pool *pool, int index, void **msg)
{
	__u32 msg_num = pool->pools[index].msg_num;
	struct msg_pool *p;
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
	__u32 msg_num = pool->pools[index].msg_num;
	struct msg_pool *p;

	/* tag value start from 1 */
	if (!tag || tag > msg_num) {
		WD_ERR("invalid message cache idx(%d)\n", tag);
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
	struct wd_env_config_per_numa *config_numa = config->config_per_numa;
	struct wd_ctx_range **ctx_table;
	int i, j, k;

	for (i = 0; i < config->numa_num; config_numa++, i++) {
		if (!config_numa->ctx_table)
			continue;

		ctx_table = config_numa->ctx_table;
		printf("-> dump_env_info: %d: sync num: %lu\n", i,
		       config_numa->sync_ctx_num);
		printf("-> dump_env_info: %d: async num: %lu\n", i,
		       config_numa->async_ctx_num);
		if (ctx_table) {
			for (j = 0; j < CTX_MODE_MAX; j++)
				for (k = 0; k < config_numa->op_type_num; k++) {
			printf("-> dump_env_info: %d: [%d][%d].begin: %u\n", i,
			       j, k, ctx_table[j][k].begin);
			printf("-> dump_env_info: %d: [%d][%d].end: %u\n", i,
			       j, k, ctx_table[j][k].end);
			printf("-> dump_env_info: %d: [%d][%d].size: %u\n", i,
			       j, k, ctx_table[j][k].size);
			}
		}
	}
}

int wd_parse_numa(struct wd_env_config *config, const char *s)
{
	struct wd_env_config_per_numa *config_numa;
	int max = numa_max_node();
	int nodes[max + 1], num = 0, tmp, i;
	char *n, *p;

	n = strdup(s);
	if (!n)
		return -ENOMEM;

	while ((p = strsep(&n, ","))) {
		/* todo: check all digits here */
		tmp = strtol(p, NULL, 10);
		if (tmp < 0 || tmp > max) {
			free(n);
			return -EINVAL;
		}
		/* fix me: ... */
		nodes[num++] = tmp;
	}

	config_numa = calloc(num, sizeof(*config_numa));
	if (!config_numa) {
		free(n);
		return -ENOMEM;
	}

	config->config_per_numa = config_numa;
	config->numa_num = num;
	for (i = 0; i < num; config_numa++, i++)
		config_numa->node = nodes[i];

	free(n);

	return 0;
}

static void __attribute__((unused))
wd_free_parse_numa(struct wd_env_config *config)
{
	free(config->config_per_numa);
}

/* 1 enable, 0 disable, others error */
int wd_parse_async_poll_en(struct wd_env_config *config, const char *s)
{
	int tmp;

	tmp = strtol(s, NULL, 10);
	if (tmp != 0 && tmp != 1)
		return -EINVAL;

	config->enable_internal_poll = tmp;

	return 0;
}

/* fix me */
static int parse_ctx_num_on_numa(const char *s, int *ctx_num, int *node)
{
	char *n;

	*ctx_num = strtol(s, NULL, 10);
	n = index(s, '@');
	n++;
	*node = strtol(n, NULL, 10);

	return 0;
}

static int wd_parse_ctx_num(struct wd_env_config *config, const char *s,
			    bool is_sync)
{
	struct wd_env_config_per_numa *config_numa = config->config_per_numa;
	int ctx_num, node, i, ret;
	char *n, *p;

	n = strdup(s);
	if (!n)
		return -ENOMEM;

	while ((p = strsep(&n, ","))) {
		ret = parse_ctx_num_on_numa(p, &ctx_num, &node);
		if (ret) {
			free(n);
			return -EINVAL;
		}

		for (i = 0; i < config->numa_num; config_numa++, i++)
			if (config_numa->node == node)
				break;
		if (i == config->numa_num) {
			WD_ERR("wrong numa node value: %s!\n", p);
			free(n);
			return -EINVAL;
		}

		if (is_sync)
			config_numa->sync_ctx_num = ctx_num;
		else
			config_numa->async_ctx_num = ctx_num;
	}

	free(n);

	return 0;
}

int wd_parse_sync_ctx_num(struct wd_env_config *config, const char *s)
{
	return wd_parse_ctx_num(config, s, 1);
}

int wd_parse_async_ctx_num(struct wd_env_config *config, const char *s)
{
	return wd_parse_ctx_num(config, s, 0);
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

static int comp_fill_ctx_table(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa = config->config_per_numa;
	struct wd_ctx_range **ctx_table;
	int start, size, i, j, k, sum;

	for (i = 0; i < config->numa_num; config_numa++, i++) {
		if (!config_numa->ctx_table)
			continue;

		start = get_start_ctx_index(config, config_numa);
		ctx_table = config_numa->ctx_table;

		for (sum = 0, j = 0; j < config_numa->op_type_num; j++)
			sum += ctx_table[CTX_MODE_SYNC][j].size;
		if (sum != config_numa->sync_ctx_num)
			return -EINVAL;
		if (config_numa->sync_ctx_num) {
			for (k = 0; k < config_numa->op_type_num; k++) {
				size = ctx_table[CTX_MODE_SYNC][k].size;
				ctx_table[CTX_MODE_SYNC][k].begin = start;
				ctx_table[CTX_MODE_SYNC][k].end = start +
								  size - 1;
				start += size;
			}
		}

		for (sum = 0, j = 0; j < config_numa->op_type_num; j++)
			sum += ctx_table[CTX_MODE_ASYNC][j].size;
		if (sum != config_numa->async_ctx_num)
			return -EINVAL;
		if (config_numa->async_ctx_num) {
			for (k = 0; k < config_numa->op_type_num; k++) {
				size = ctx_table[CTX_MODE_ASYNC][k].size;
				ctx_table[CTX_MODE_ASYNC][k].begin = start;
				ctx_table[CTX_MODE_ASYNC][k].end = start +
								   size - 1;
				start += size;
			}
		}
	}

	return 0;
}

static int comp_get_and_fill_ctx_num(struct wd_env_config_per_numa *config_numa,
				     const char *p, int ctx_num)
{
	struct wd_ctx_range **ctx_table = config_numa->ctx_table;

	if (!strncmp(p, "sync-comp", 9))
		ctx_table[0][0].size = ctx_num;
	else if (!strncmp(p, "sync-decomp", 11))
		ctx_table[0][1].size = ctx_num;
	else if (!strncmp(p, "async-comp", 10))
		ctx_table[1][0].size = ctx_num;
	else if (!strncmp(p, "async-decomp", 12))
		ctx_table[1][1].size = ctx_num;
	else
		return -EINVAL;

	return 0;
}

/* just pust this function in wd_util.c to avoid export more functions */
int wd_parse_comp_ctx_type(struct wd_env_config *config, const char *s)
{
	struct wd_env_config_per_numa *config_numa = config->config_per_numa;
	struct wd_ctx_range **ctx_table;
	int ctx_num, node, i, ret;
	char *n, *p, *c;

	n = strdup(s);
	if (!n)
		return -ENOMEM;

	while ((p = strsep(&n, ","))) {
		c = index(p, ':');
		c++;
		ret = parse_ctx_num_on_numa(c, &ctx_num, &node);
		if (ret)
			goto err_free_ctx_table;

		for (i = 0; i < config->numa_num; config_numa++, i++)
			if (config_numa->node == node)
				break;
		if (i == config->numa_num) {
			WD_ERR("wrong numa node value in ctx type: %s!\n", p);
			ret = -EINVAL;
			goto err_free_ctx_table;
		}

		if (!config_numa->ctx_table) {
			ctx_table = calloc(1, sizeof(struct wd_ctx_range *) *
					   CTX_MODE_MAX);
			if (!ctx_table) {
				ret = -ENOMEM;
				goto err_free_ctx_table;
			}
			config_numa->op_type_num = config->op_type_num;
			for (i = 0; i < config_numa->op_type_num; i++) {
				ctx_table[i] = calloc(1,
						sizeof(struct wd_ctx_range) *
						config_numa->op_type_num);
			}
			config_numa->ctx_table = ctx_table;
		}

		ret = comp_get_and_fill_ctx_num(config_numa, p, ctx_num);
		if (ret) {
			WD_ERR("wrong comp ctx type: %s!\n", p);
			goto err_free_ctx_table;
		}
	}

	ret = comp_fill_ctx_table(config);
	if (ret) {
		WD_ERR("check uadk comp ctx failed!\n");
		goto err_free_ctx_table;
	}

	free(n);

	return 0;

err_free_ctx_table:
	for (i = 0; i < config->numa_num; config_numa++, i++)
		if (config_numa->ctx_table)
			free(config_numa->ctx_table);
	free(n);
	return ret;
}

static int wd_parse_env(struct wd_env_config *config,
			const struct wd_config_variable *table,
			__u32 table_size)
{
	const struct wd_config_variable *var;
	const char *var_s;
	int ret, i;

	for (i = 0; i < table_size; i++) {
		var = table + i;
		var_s = getenv(var->name);
		if (!var_s) {
			var_s = var->def_val;
			WD_ERR("No %s environment variable! Use default: %s\n",
			       var->name, var->def_val);
		}

		ret = var->parse_fn(config, var_s);
		if (ret) {
			WD_ERR("fail to parse %s environment variable!\n",
			       var->name);
			return -EINVAL;
		}
	}

	return 0;
}

static void wd_free_env(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa = config->config_per_numa;
	int i, j;

	for (i = 0; i < config->numa_num; config_numa++, i++) {
		if (!config_numa->ctx_table)
			continue;

		for (j = 0; j < CTX_MODE_MAX; j++)
			free(config_numa->ctx_table[j]);
		free(config_numa->ctx_table);
		free(config_numa->async_task_queue_array);
	}
	free(config->config_per_numa);
}

static __u8 get_ctx_mode(struct wd_env_config_per_numa *config, int index)
{
	struct wd_ctx_range **ctx_table = config->ctx_table;
	int i;

	for (i = 0; i < config->op_type_num; i++) {
		if ((index >= ctx_table[CTX_MODE_SYNC][i].begin) &&
		    (index <= ctx_table[CTX_MODE_SYNC][i].end))
			return CTX_MODE_SYNC;
	}
	return CTX_MODE_ASYNC;
}

static int get_op_type(struct wd_env_config_per_numa *config, int index,
		       __u8 ctx_mode)
{
	struct wd_ctx_range **ctx_table = config->ctx_table;
	int i;

	for (i = 0; i < config->op_type_num; i++) {
		if ((index >= ctx_table[ctx_mode][i].begin) &&
		    (index <= ctx_table[ctx_mode][i].end))
			return i;
	}
	return -EINVAL;
}

static int wd_get_wd_ctx(struct wd_env_config_per_numa *config,
			 struct wd_ctx_config *ctx_config, int start)
{
	int ctx_num = config->sync_ctx_num + config->async_ctx_num;
	handle_t h_ctx;
	int i, j;

	for (i = start; i < start + ctx_num; i++) {
		h_ctx = wd_request_ctx(&config->dev);
		if (!h_ctx) {
			for (j = 0; j < i; j++)
				wd_release_ctx(ctx_config->ctxs[j].ctx);
			return -EBUSY;
		}

		ctx_config->ctxs[i].ctx = h_ctx;
		/* put sync ctx in front of async ctx */
		if (config->ctx_table) {
			ctx_config->ctxs[i].ctx_mode = get_ctx_mode(config, i);
			ctx_config->ctxs[i].op_type = get_op_type(
					config, i,
					ctx_config->ctxs[i].ctx_mode);
		}

		/* fix me: currently does not fill op_type */
	}

	return 0;
}

static void wd_put_wd_ctx(struct wd_ctx_config *ctx_config)
{
	__u32 i;

	for (i = 0; i < ctx_config->ctx_num; i++)
		wd_release_ctx(ctx_config->ctxs[i].ctx);

	free(ctx_config->ctxs);
}

static int wd_get_total_ctx_num(struct wd_env_config *config)
{
	struct wd_env_config_per_numa *config_numa = config->config_per_numa;
	int i, num = 0;

	for (i = 0; i < config->numa_num; config_numa++, i++)
		num += config_numa->sync_ctx_num + config_numa->async_ctx_num;

	return num;
}

static struct wd_ctx_config *wd_alloc_ctx(struct wd_env_config *config,
					  const struct wd_alg_ops *ops)
{
	struct wd_env_config_per_numa *config_numa = config->config_per_numa;
	struct uacce_dev_list *list, *head;
	struct wd_ctx_config *ctx_config;
	int i, ctx_num, start = 0, ret = 0;

	ctx_config = calloc(1, sizeof(*ctx_config));
	if (!ctx_config)
		return WD_ERR_PTR(-ENOMEM);

	ctx_num = wd_get_total_ctx_num(config);
	ctx_config->ctxs = calloc(ctx_num, sizeof(struct wd_ctx));
	if (!ctx_config->ctxs) {
		ret = -ENOMEM;
		goto err_free_ctx_config;
	}
	ctx_config->ctx_num = ctx_num;

	/* get uacce_dev */
	head = wd_get_accel_list(ops->alg_name);
	if (!head) {
		ret = -EINVAL;
		WD_ERR("no device to support %s\n", ops->alg_name);
		goto err_free_ctxs;
	}

	for (i = 0; i < config->numa_num; config_numa++, i++) {
		list = head;
		while (list) {
			if (config_numa->node == list->dev->numa_id)
				break;
			list = list->next;
		}
		if (!list) {
			WD_ERR("no match device in node %lu\n",
			       config_numa->node);
			continue;
		}

		memcpy(&config_numa->dev, list->dev, sizeof(*list->dev));

		/* already sort numa node from small to big in wd_parse_numa */
		ret = wd_get_wd_ctx(config_numa, ctx_config, start);
		if (ret) {
			ret = -EBUSY;
			goto err_free_list;
		}
		start += config_numa->sync_ctx_num + config_numa->async_ctx_num;
	}

	return ctx_config;

err_free_list:
	wd_free_list_accels(head);
err_free_ctxs:
	free(ctx_config->ctxs);
err_free_ctx_config:
	free(ctx_config);
	return WD_ERR_PTR(ret);
}

static void wd_free_ctx(struct wd_ctx_config *ctx_config)
{

	 wd_put_wd_ctx(ctx_config);
	 free(ctx_config);
}

static struct wd_sched *wd_init_sched_config(struct wd_env_config *config,
					     const struct wd_alg_ops *ops)
{
	struct wd_env_config_per_numa *config_numa = config->config_per_numa;
	struct wd_ctx_range **ctx_table;
	struct wd_sched *sched;
	int i, j, ret, type_num = ops->op_type_num;

	sched = sample_sched_alloc(SCHED_POLICY_RR, type_num,
				   MAX_NUMA_NUM, NULL);
	if (!sched)
		return NULL;

	sched->name = "SCHED_RR";

	ctx_table = config_numa->ctx_table;
	for (i = 0; i < config->numa_num; config_numa++, i++) {
		for (j = 0; j < type_num && config_numa->sync_ctx_num; j++) {
			ret = sample_sched_fill_data(
					sched, config_numa->node,
					CTX_MODE_SYNC, j,
					ctx_table[CTX_MODE_SYNC][j].begin,
					ctx_table[CTX_MODE_SYNC][j].end);
			if (ret)
				goto err_release_sched;
		}

		for (j = 0; j < type_num && config_numa->async_ctx_num; j++) {
			ret = sample_sched_fill_data(sched, config_numa->node,
					CTX_MODE_ASYNC, j,
					ctx_table[CTX_MODE_ASYNC][j].begin,
					ctx_table[CTX_MODE_ASYNC][j].end);
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
	struct wd_env_config_per_numa *config_numa = config->config_per_numa;
	int i, num = 0;

	for (i = 0; i < config->numa_num; config_numa++, i++) {
		num += config_numa->sync_ctx_num + config_numa->async_ctx_num;
		if (index < num)
			break;
	}

	return config_numa->async_task_queue_array;
}

/* fix me: all return value here, and no config input */
int wd_add_task_to_async_queue(struct wd_env_config *config, __u32 index)
{
	struct async_task_queue *task_queue = find_async_queue(config, index);
	struct async_task *head, *task;
	int prod;

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

static int wd_init_async_polling_thread(struct wd_env_config *config,
					struct wd_ctx_config *ctx_config)
{
	struct wd_env_config_per_numa *config_numa = config->config_per_numa;
	int i;

	if (!config->enable_internal_poll)
		return 0;

	for (i = 0; i < config->numa_num; config_numa++, i++)
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
	int ret;

	if (!ops->alg_init || !ops->alg_uninit || !ops->alg_poll_ctx) {
		WD_ERR("Missing alg_init or alg_uninit!\n");
		return -EINVAL;
	}
	ctx_config = wd_alloc_ctx(config, ops);
	if (WD_IS_ERR(ctx_config))
		return -EBUSY;
	config->ctx_config = ctx_config;

	sched_config = wd_init_sched_config(config, ops);
	if (WD_IS_ERR(sched_config))
		goto err_uninit_ctx;
	config->sched = sched_config;

	ret = ops->alg_init(ctx_config, sched_config);
	if (ret)
		goto err_uninit_sched;

	config->alg_uninit = ops->alg_uninit;
	config->alg_poll_ctx = ops->alg_poll_ctx;
	ret = wd_init_async_polling_thread(config, ctx_config);
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

int wd_alg_env_init(struct wd_env_config *env_config,
		    const struct wd_config_variable *table, __u32 table_size,
		    const struct wd_alg_ops *ops)
{
	int ret;

	if (!env_config || !table || !table_size || !ops)
		return -EINVAL;

	env_config->op_type_num = ops->op_type_num;
	ret = wd_parse_env(env_config, table, table_size);
	if (ret)
		return ret;

	ret = wd_init_resource(env_config, ops);
	if (ret) {
		wd_free_env(env_config);
		return ret;
	}

	return 0;
}

void wd_alg_env_uninit(struct wd_env_config *env_config)
{
	wd_uninit_resource(env_config);
	wd_free_env(env_config);
}
