// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>
#include <pthread.h>
#include "wd_alg_common.h"
#include "wd_util.h"

struct msg_pool {
	/* message array allocated dynamically */
	void *msgs;
	int *used;
	__u32 msg_num;
	__u32 msg_size;
	int head;
	int tail;
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
		WD_ERR("invalid params, ctx_num is 0!\n");
		return -EINVAL;
	}

	ctxs = calloc(1, cfg->ctx_num * sizeof(struct wd_ctx_internal));
	if (!ctxs)
		return -ENOMEM;

	for (i = 0; i < cfg->ctx_num; i++) {
		if (!cfg->ctxs[i].ctx) {
			WD_ERR("invalid params, ctx is NULL!\n");
			free(ctxs);
			return -EINVAL;
		}

		clone_ctx_to_internal(cfg->ctxs + i, ctxs + i);
		pthread_mutex_init(&ctxs[i].lock, NULL);
	}

	in->ctxs = ctxs;
	in->priv = cfg->priv;
	in->ctx_num = cfg->ctx_num;

	return 0;
}

int wd_init_sched(struct wd_sched *in, struct wd_sched *from)
{
	if (!from->name)
		return -EINVAL;

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
		pthread_mutex_destroy(&in->ctxs[i].lock);

	in->priv = NULL;
	in->ctx_num = 0;
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
		return -ENOMEM;

	pool->used = calloc(1, msg_num * sizeof(int));
	if (!pool->used) {
		free(pool->msgs);
		return -ENOMEM;
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
		return -ENOMEM;

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
		WD_ERR("invalid msg cache tag(%d)\n", tag);
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
			return -EBUSY;
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
		WD_ERR("invalid msg cache idx(%d)\n", tag);
		return;
	}

	p = &pool->pools[index];

	__atomic_clear(&p->used[tag - 1], __ATOMIC_RELEASE);
}
