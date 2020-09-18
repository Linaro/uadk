/* SPDX-License-Identifier: Apache-2.0 */
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>

#include "config.h"
#include "include/drv/wd_dh_drv.h"
#include "wd_dh.h"

#define WD_POOL_MAX_ENTRIES		1024
#define DH_BALANCE_THRHD		1280
#define DH_RESEND_CNT			8
#define DH_MAX_KEY_SIZE			512
#define DH_RECV_MAX_CNT			60000000 // 1 min
#define WD_DH_G2			2

static __thread int balance;

struct wd_dh_sess {
	__u32 alg_type;
	__u32 key_size;
	struct wd_dtb g;
	struct wd_dh_sess_setup setup;	
	struct sched_key key;
};

struct msg_pool {
	struct wd_dh_msg msg[WD_POOL_MAX_ENTRIES];
	int used[WD_POOL_MAX_ENTRIES];
	int head;
	int tail;
};

struct wd_async_msg_pool {
	struct msg_pool *pools;
	__u32 pool_nums;
};

static struct wd_dh_setting {
	struct wd_ctx_config_internal config;
	struct wd_sched sched;
	void *sched_ctx;
	const struct wd_dh_driver *driver;
	void *priv;
	struct wd_async_msg_pool pool;
} wd_dh_setting;

#ifdef WD_STATIC_DRV
extern struct wd_dh_driver wd_dh_hisi_hpre;
static void wd_dh_set_static_drv(void)
{
	wd_dh_setting.driver = &wd_dh_hisi_hpre;
}
#else
static void __attribute__((constructor)) wd_dh_open_driver(void)
{
	void *driver;

	driver = dlopen("libhisi_hpre.so", RTLD_NOW);
	if (!driver)
		WD_ERR("Fail to open libhisi_hpre.so\n");
}
#endif

void wd_dh_set_driver(struct wd_dh_driver *drv)
{
	if (!drv) {
		WD_ERR("drv NULL\n");
		return;
	}

	wd_dh_setting.driver = drv;
}

static void clone_ctx_to_internal(struct wd_ctx *ctx,
				  struct wd_ctx_internal *ctx_in)
{
	ctx_in->ctx = ctx->ctx;
	ctx_in->op_type = ctx->op_type;
	ctx_in->ctx_mode = ctx->ctx_mode;
}

static int init_global_ctx_setting(struct wd_ctx_config *cfg)
{
	struct wd_ctx_internal *ctxs;
	int i;

	if (!cfg->ctx_num) {
		WD_ERR("ctx_num error\n");
		return -EINVAL;
	}

	ctxs = malloc(cfg->ctx_num * sizeof(struct wd_ctx_internal));
	if (!ctxs)
		return -ENOMEM;

	for (i = 0; i < cfg->ctx_num; i++) {
		if (!cfg->ctxs[i].ctx) {
			WD_ERR("config ctx[%d] NULL\n", i);
			free(ctxs);
			return -EINVAL;
		}

		clone_ctx_to_internal(cfg->ctxs + i, ctxs + i);
		pthread_mutex_init(&ctxs[i].lock, NULL);
	}

	memcpy(ctxs, cfg->ctxs, cfg->ctx_num * sizeof(struct wd_ctx));
	wd_dh_setting.config.ctxs = ctxs;

	/* Can't copy with the size of priv structure. */
	wd_dh_setting.config.priv = cfg->priv;
	wd_dh_setting.config.ctx_num = cfg->ctx_num;

	return 0;
}

static int copy_sched_to_global_setting(struct wd_sched *sched)
{
	if (!sched->name) {
		WD_ERR("sched name NULL\n");
		return -EINVAL;
	}

	wd_dh_setting.sched.name = strdup(sched->name);
	wd_dh_setting.sched.pick_next_ctx = sched->pick_next_ctx;
	wd_dh_setting.sched.poll_policy = sched->poll_policy;

	return 0;
}

static void clear_sched_in_global_setting(void)
{
	free((void *)wd_dh_setting.sched.name);
	wd_dh_setting.sched.name = NULL;
	wd_dh_setting.sched.pick_next_ctx = NULL;
	wd_dh_setting.sched.poll_policy = NULL;
	wd_dh_setting.sched.name = NULL;
}

static void clear_config_in_global_setting(void)
{
	wd_dh_setting.config.priv = NULL;
	wd_dh_setting.config.ctx_num = 0;
	free(wd_dh_setting.config.ctxs);
	wd_dh_setting.config.ctxs = NULL;
}

static int wd_init_async_request_pool(struct wd_async_msg_pool *pool)
{
	int num = wd_dh_setting.config.ctx_num;

	pool->pools = malloc(num * sizeof(struct msg_pool));
	if (!pool->pools)
		return -ENOMEM;

	memset(pool->pools, 0, num * sizeof(struct msg_pool));
	pool->pool_nums = num;

	return 0;
}

static void wd_uninit_async_request_pool(struct wd_async_msg_pool *pool)
{
	struct msg_pool *p;
	int i, j;

	for (i = 0; i < pool->pool_nums; i++) {
		p = &pool->pools[i];
		for (j = 0; j < WD_POOL_MAX_ENTRIES; j++) {
			if (p->used[j])
				WD_ERR("pool %d isn't released from reqs pool.\n",
						j);
		}
	}

	free(pool->pools);
	pool->pools = NULL;
	pool->pool_nums = 0;
}

static struct wd_dh_req *wd_get_req_from_pool(struct wd_async_msg_pool *pool,
				handle_t h_ctx,
				struct wd_dh_msg *msg)
{
	struct wd_dh_msg *c_msg;
	struct msg_pool *p;
	int found = 0;
	int i;

	if (!msg->tag || msg->tag > WD_POOL_MAX_ENTRIES) {
		WD_ERR("invalid msg cache tag(%llu)\n", msg->tag);
		return NULL;
	}

	for (i = 0; i < wd_dh_setting.config.ctx_num; i++) {
		if (h_ctx == wd_dh_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found) {
		WD_ERR("failed to find ctx\n");
		return NULL;
	}

	p = &pool->pools[i];
	c_msg = &p->msg[msg->tag - 1];
	c_msg->req.pri_bytes = msg->req.pri_bytes;
	c_msg->req.status = msg->result;

	return &c_msg->req;
}

static struct wd_dh_msg *wd_get_msg_from_pool(struct wd_async_msg_pool *pool,
						handle_t h_ctx,
						struct wd_dh_req *req)
{
	struct wd_dh_msg *msg;
	struct msg_pool *p;
	int found = 0;
	__u32 idx = 0;
	int cnt = 0;
	int i;

	for (i = 0; i < wd_dh_setting.config.ctx_num; i++) {
		if (h_ctx == wd_dh_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found) {
		WD_ERR("failed to find ctx\n");
		return NULL;
	}

	p = &pool->pools[i];
	while (__atomic_test_and_set(&p->used[idx], __ATOMIC_ACQUIRE)) {
		idx = (idx + 1) % (WD_POOL_MAX_ENTRIES - 1);
		if (++cnt == WD_POOL_MAX_ENTRIES)
			return NULL;
	}

	/* get msg from msg_pool[] */
	msg = &p->msg[idx];
	memcpy(&msg->req, req, sizeof(*req));
	msg->tag = idx + 1;

	return msg;
}

static void wd_put_msg_to_pool(struct wd_async_msg_pool *pool,
			       handle_t h_ctx,
			       struct wd_dh_msg *msg)
{
	struct msg_pool *p;
	int found = 0;
	int i;

	if (!msg->tag || msg->tag > WD_POOL_MAX_ENTRIES) {
		WD_ERR("invalid msg cache idx(%llu)\n", msg->tag);
		return;
	}
	for (i = 0; i < wd_dh_setting.config.ctx_num; i++) {
		if (h_ctx == wd_dh_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found) {
		WD_ERR("ctx handle not fonud!\n");
		return;
	}

	p = &pool->pools[i];

	__atomic_clear(&p->used[msg->tag - 1], __ATOMIC_RELEASE);
}

int wd_dh_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	void *priv;
	int ret;

	/* wd_dh_init() could only be invoked once for one process. */
	if (wd_dh_setting.config.ctx_num) {
		WD_ERR("init dh error: repeat init dh\n");
		return 0;
	}

	if (!config || !config->ctxs[0].ctx || !sched) {
		WD_ERR("config or sched NULL\n");
		return -WD_EINVAL;
	}

	if (!wd_is_sva(config->ctxs[0].ctx)) {
		WD_ERR("no sva, do not dh init\n");
		return -WD_EINVAL;
	}

	ret = init_global_ctx_setting(config);
	if (ret) {
		WD_ERR("failed to init global ctx setting\n");
		return ret;
	}

	ret = copy_sched_to_global_setting(sched);
	if (ret) {
		WD_ERR("failed to copy sched to global setting\n");
		goto out;
	}

#ifdef WD_STATIC_DRV
	wd_dh_set_static_drv();
#endif

	/* init async request pool */
	ret = wd_init_async_request_pool(&wd_dh_setting.pool);
	if (ret) {
		WD_ERR("failed to init async req pool!\n");
		goto out_sched;
	}

	/* init ctx related resources in specific driver */
	priv = malloc(wd_dh_setting.driver->drv_ctx_size);
	if (!priv) {
		WD_ERR("failed to calloc drv ctx\n");
		ret = -ENOMEM;
		goto out_priv;
	}

	memset(priv, 0, wd_dh_setting.driver->drv_ctx_size);
	wd_dh_setting.priv = priv;
	ret = wd_dh_setting.driver->init(&wd_dh_setting.config, priv);
	if (ret < 0) {
		WD_ERR("failed to drv init, ret=%d\n", ret);
		goto out_init;
	}

	return 0;

out_init:
	free(priv);
out_priv:
	wd_uninit_async_request_pool(&wd_dh_setting.pool);
out_sched:
	clear_sched_in_global_setting();
out:
	clear_config_in_global_setting();

	return ret;
}

void wd_dh_uninit(void)
{
	if (!wd_dh_setting.pool.pool_nums) {
		WD_ERR("uninit dh error: repeat uninit dh\n");
		return;
	}

	/* driver uninit */
	wd_dh_setting.driver->exit(wd_dh_setting.priv);
	free(wd_dh_setting.priv);
	wd_dh_setting.priv = NULL;

	/* uninit async request pool */
	wd_uninit_async_request_pool(&wd_dh_setting.pool);

	/* unset config, sched, driver */
	clear_sched_in_global_setting();
	clear_config_in_global_setting();
}

static int fill_dh_msg(struct wd_dh_msg *msg, struct wd_dh_req *req,
			struct wd_dh_sess *sess)
{
	memcpy(&msg->req, req, sizeof(*req));
	msg->result = WD_EINVAL;

	if (req->op_type == WD_DH_PHASE1) {
		msg->g = (__u8 *)sess->g.data;
		msg->gbytes = sess->g.dsize;
	} else if (req->op_type == WD_DH_PHASE2) {
		msg->g = (__u8 *)req->pv;
		msg->gbytes = req->pvbytes;
	} else {
		WD_ERR("op_type=%d error!\n", req->op_type);
		return -EINVAL;
	}

	if (!msg->g) {
		WD_ERR("request dh g is NULL!\n");
		return -EINVAL;
	}

	return 0;
}

static int dh_send(handle_t ctx, struct wd_dh_msg *msg)
{
	__u32 tx_cnt = 0;
	int ret;

	do {
		ret = wd_dh_setting.driver->send(ctx, msg);
		if (ret == -EBUSY) {
			if (tx_cnt++ >= DH_RESEND_CNT) {
				WD_ERR("failed to send: retry exit!\n");
				break;
			}
			usleep(1);
		} else if (ret < 0) {
			WD_ERR("failed to send: send error = %d!\n", ret);
			break;
		}
	} while (ret);

	return ret;
}

static int dh_recv_sync(handle_t ctx, struct wd_dh_msg *msg)
{
	struct wd_dh_req *req = &msg->req;
	__u32 rx_cnt = 0;
	int ret;

	do {
		ret = wd_dh_setting.driver->recv(ctx, msg);
		if (ret == -EAGAIN) {
			if (rx_cnt++ >= DH_RECV_MAX_CNT) {
				WD_ERR("failed to recv: timeout!\n");
				return -ETIMEDOUT;
			}

			if (balance > DH_BALANCE_THRHD)
				usleep(1);
		} else if (ret < 0) {
			WD_ERR("failed to recv: error = %d!\n", ret);
			return ret;
		}
	} while (ret < 0);

	balance = rx_cnt;
	req->status = msg->result;

	return GET_NEGATIVE(req->status);
}

int wd_do_dh_sync(handle_t sess, struct wd_dh_req *req)
{
	struct wd_ctx_config_internal *config = &wd_dh_setting.config;
	handle_t h_sched_ctx = wd_dh_setting.sched.h_sched_ctx;
	struct wd_dh_sess *sess_t = (struct wd_dh_sess *)sess;
	struct wd_ctx_internal *ctx;
	struct wd_dh_msg msg;
	__u32 idx;
	int ret;

	if (unlikely(!sess || !req)) {
		WD_ERR("input param NULL!\n");
		return -WD_EINVAL;
	}

	idx = wd_dh_setting.sched.pick_next_ctx(h_sched_ctx, req, &sess_t->key);
	if (unlikely(idx >= config->ctx_num)) {
		WD_ERR("failed to pick ctx, idx=%u!\n", idx);
		return -EINVAL;
	}
	ctx = config->ctxs + idx;
	if (ctx->ctx_mode != CTX_MODE_SYNC) {
		WD_ERR("ctx %u mode=%hhu error!\n", idx, ctx->ctx_mode);
		return -EINVAL;
	}

	memset(&msg, 0, sizeof(struct wd_dh_msg));
	ret = fill_dh_msg(&msg, req, sess_t);
	if (unlikely(ret))
		return ret;

	pthread_mutex_lock(&ctx->lock);
	ret = dh_send(ctx->ctx, &msg);
	if (unlikely(ret))
		goto fail;

	ret = dh_recv_sync(ctx->ctx, &msg);
fail:
	pthread_mutex_unlock(&ctx->lock);

	return ret;
}

int wd_do_dh_async(handle_t sess, struct wd_dh_req *req)
{
	struct wd_ctx_config_internal *config = &wd_dh_setting.config;
	handle_t h_sched_ctx = wd_dh_setting.sched.h_sched_ctx;
	struct wd_dh_sess *sess_t = (struct wd_dh_sess *)sess;
	struct wd_ctx_internal *ctx;
	struct wd_dh_msg *msg;
	__u32 idx;
	int ret;

	if (unlikely(!req || !sess)) {
		WD_ERR("input param NULL!\n");
		return -WD_EINVAL;
	}

	idx = wd_dh_setting.sched.pick_next_ctx(h_sched_ctx, req, &sess_t->key);
	if (unlikely(idx >= config->ctx_num)) {
		WD_ERR("failed to pick ctx, idx=%u!\n", idx);
		return -EINVAL;
	}
	ctx = config->ctxs + idx;
	if (ctx->ctx_mode != CTX_MODE_ASYNC) {
		WD_ERR("ctx %u mode=%hhu error!\n", idx, ctx->ctx_mode);
		return -EINVAL;
	}

	msg = wd_get_msg_from_pool(&wd_dh_setting.pool, ctx->ctx, req);
	if (!msg)
		return -WD_EBUSY;

	ret = fill_dh_msg(msg, req, (struct wd_dh_sess *)sess);
	if (ret)
		goto fail_with_msg;

	pthread_mutex_lock(&ctx->lock);
	ret = dh_send(ctx->ctx, msg);
	if (ret) {
		pthread_mutex_unlock(&ctx->lock);
		goto fail_with_msg;
	}
	pthread_mutex_unlock(&ctx->lock);

	return ret;

fail_with_msg:
	wd_put_msg_to_pool(&wd_dh_setting.pool, ctx->ctx, msg);

	return ret;
}

int wd_dh_poll_ctx(__u32 pos, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_dh_setting.config;
	struct wd_ctx_internal *ctx;
	struct wd_dh_req *req;
	struct wd_dh_msg msg;
	__u32 rcv_cnt = 0;
	int ret;

	if (unlikely(!count || pos >= config->ctx_num)) {
		WD_ERR("param error, pos=%u, ctx_num=%u!\n",
			pos, config->ctx_num);
		return -EINVAL;
	}

	ctx = config->ctxs + pos;
	if (ctx->ctx_mode != CTX_MODE_ASYNC) {
		WD_ERR("ctx %u mode=%hhu error!\n", pos, ctx->ctx_mode);
		return -EINVAL;
	}

	pthread_mutex_unlock(&ctx->lock);
	do {
		ret = wd_dh_setting.driver->recv(ctx->ctx, &msg);
		if (ret == -EAGAIN) {
			break;
		} else if (ret < 0) {
			WD_ERR("failed to async recv, ret = %d!\n", ret);
			*count = rcv_cnt;
			wd_put_msg_to_pool(&wd_dh_setting.pool, ctx->ctx, &msg);
			return ret;
		}
		rcv_cnt++;
		req = wd_get_req_from_pool(&wd_dh_setting.pool, ctx->ctx, &msg);
		if (likely(req && req->cb))
			req->cb(req);
		wd_put_msg_to_pool(&wd_dh_setting.pool, ctx->ctx, &msg);
	} while (--expt);

	*count = rcv_cnt;

	return ret;
}

int wd_dh_poll(__u32 expt, __u32 *count)
{
	return wd_dh_setting.sched.poll_policy(0, 0, expt, count);
}

bool wd_dh_is_g2(handle_t sess)
{
	if (!sess) {
		WD_ERR("dh is g2 judge, sess NULL, return false!\n");
		return false;
	}

	return ((struct wd_dh_sess *)sess)->setup.is_g2;
}

int wd_dh_key_bits(handle_t sess)
{
	if (!sess) {
		WD_ERR("get dh key bits, sess NULL!\n");
		return 0;
	}

	return ((struct wd_dh_sess *)sess)->setup.key_bits;
}

int wd_dh_set_g(handle_t sess, struct wd_dtb *g)
{
	struct wd_dh_sess *sess_t = (struct wd_dh_sess *)sess;

	if (!sess_t || !g) {
		WD_ERR("param NULL!\n");
		return -WD_EINVAL;
	}

	if (g->dsize
		&& g->bsize <= sess_t->g.bsize
		&& g->dsize <= sess_t->g.bsize) {
		memset(sess_t->g.data, 0, g->bsize);
		memcpy(sess_t->g.data, g->data, g->dsize);
		sess_t->g.dsize = g->dsize;
		if (*g->data != WD_DH_G2 && sess_t->setup.is_g2)
			return -WD_EINVAL;
		return WD_SUCCESS;
	}

	return -WD_EINVAL;
}

void wd_dh_get_g(handle_t sess, struct wd_dtb **g)
{
	if (!sess || !g) {
		WD_ERR("param NULL!\n");
		return;
	}

	*g = &((struct wd_dh_sess *)sess)->g;
}

handle_t wd_dh_alloc_sess(struct wd_dh_sess_setup *setup)
{
	struct wd_dh_sess *sess;

	if (!setup) {
		WD_ERR("alloc dh sess setup NULL!\n");
		return (handle_t)0;
	}

	if (setup->key_bits != 768 &&
		setup->key_bits != 1024 &&
		setup->key_bits != 1536 &&
		setup->key_bits != 2048 &&
		setup->key_bits != 3072 &&
		setup->key_bits != 4096) {
		WD_ERR("alloc dh sess key_bit %u err!\n", setup->key_bits);
		return (handle_t)0;
	}

	sess = malloc(sizeof(struct wd_dh_sess));
	if (!sess)
		return (handle_t)0;

	memset(sess, 0, sizeof(struct wd_dh_sess));
	memcpy(&sess->setup, setup, sizeof(*setup));
	sess->key_size = setup->key_bits >> BYTE_BITS_SHIFT;

	sess->g.data = malloc(sess->key_size);
	if (!sess->g.data) {
		free(sess);
		return (handle_t)0;		
	}
	sess->g.bsize = sess->key_size;

	sess->key.mode = setup->mode;
	sess->key.numa_id = setup->numa_id;

	return (handle_t)sess;
}

void wd_dh_free_sess(handle_t sess)
{
	struct wd_dh_sess *sess_t = (struct wd_dh_sess *)sess;

	if (!sess_t) {
		WD_ERR("free rsa sess param NULL!\n");
		return;
	}

	if (sess_t->g.data)
		free(sess_t->g.data);

	free(sess_t);
}
