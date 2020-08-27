/* SPDX-License-Identifier: Apache-2.0 */
#include <stdlib.h>
#include "wd_digest.h"
#include "include/drv/wd_digest_drv.h"

#define XTS_MODE_KEY_DIVISOR	2
#define SM4_KEY_SIZE		16
#define DES_KEY_SIZE		8
#define DES3_3KEY_SIZE		(3 * DES_KEY_SIZE)
#define MAX_CIPHER_KEY_SIZE	64

#define MAX_HMAC_KEY_SIZE		128
#define WD_POOL_MAX_ENTRIES	1024
#define DES_WEAK_KEY_NUM	4
#define MAX_RETRY_COUNTS	200000000

struct msg_pool {
	struct wd_digest_msg msg[WD_POOL_MAX_ENTRIES];
	int used[WD_POOL_MAX_ENTRIES];
	int head;
	int tail;
};

struct wd_async_msg_pool {
	struct msg_pool *pools;
	int pool_nums;
};

struct wd_digest_setting {
	struct wd_ctx_config	config;
	struct wd_digest_sched	sched;
	struct wd_digest_driver	*driver;
	struct wd_async_msg_pool pool;
	void *sched_ctx;
	void *priv;
};

static struct wd_digest_setting g_wd_digest_setting;
extern struct wd_digest_driver wd_digest_hisi_digest_driver;

#ifdef WD_STATIC_DRV
static void wd_digest_set_static_drv(void)
{
	/*
	 * Fix me: a parameter can be introduced to decide to choose
	 * specific driver. Same as dynamic case.
	 */
	g_wd_digest_setting.driver = &wd_digest_hisi_digest_driver;
}
#else
static void __attribute__((constructor)) wd_digest_open_driver(void)
{
	void *driver;

	/* Fix me: vendor driver should be put in /usr/lib/wd/ */
	driver = dlopen("/usr/lib/wd/libhisi_sec.so", RTLD_NOW);
	if (!driver)
		WD_ERR("Fail to open libhisi_sec.so\n");
}
#endif

void wd_digest_set_driver(struct wd_digest_driver *drv)
{
	g_wd_digest_setting.driver = drv;
}

int wd_digest_set_key(struct wd_digest_req *req, const __u8 *key, __u32 key_len)
{
	if (!key || !req || !req->key) {
		WD_ERR("wd digest inpupt param err!\n");
		return -EINVAL;
	}

	if (key_len > MAX_HMAC_KEY_SIZE) {
		WD_ERR("wd digest input key length err!\n");
		return -WD_EINVAL;
	}

	req->key_bytes = key_len;
	memcpy(req->key, key, key_len);

	return 0;
}

handle_t wd_digest_alloc_sess(struct wd_digest_sess_setup *setup)
{
	struct wd_digest_sess *sess;

	if (!setup) {
		WD_ERR("wd digest input setup is NULL!\n");
		return (handle_t)0;
	}
	sess = calloc(1, sizeof(struct wd_digest_sess));
	return (handle_t)sess;
}

void wd_digest_free_sess(handle_t h_sess)
{
	struct wd_digest_sess *sess = (struct wd_digest_sess *)h_sess;

	free(sess);
}

static int copy_config_to_global_setting(struct wd_ctx_config *cfg)
{
	struct wd_ctx *ctxs;
	int i;

	if (cfg->ctx_num == 0)
		return -EINVAL;

	ctxs = malloc(sizeof(struct wd_ctx) * cfg->ctx_num);
	if (!ctxs)
		return -ENOMEM;

	memset(ctxs, 0, sizeof(struct wd_ctx) * cfg->ctx_num);

	/* check every context */
	for (i = 0; i < cfg->ctx_num; i++) {
		if (!cfg->ctxs[i].ctx)
			return -EINVAL;
	}

	/* get ctxs from user set */
	memcpy(ctxs, cfg->ctxs, sizeof(struct wd_ctx) * cfg->ctx_num);
	g_wd_digest_setting.config.ctxs = ctxs;

	/* fix me */
	g_wd_digest_setting.config.priv = cfg->priv;
	g_wd_digest_setting.config.ctx_num = cfg->ctx_num;

	return 0;
}

static int copy_sched_to_global_setting(struct wd_digest_sched *sched)
{
	if (!sched->name || sched->sched_ctx_size <= 0)
		return -EINVAL;

	g_wd_digest_setting.sched.name = strdup(sched->name);
	g_wd_digest_setting.sched.sched_ctx_size = sched->sched_ctx_size;
	g_wd_digest_setting.sched.pick_next_ctx = sched->pick_next_ctx;
	g_wd_digest_setting.sched.poll_policy = sched->poll_policy;

	return 0;
}

static void clear_config_in_global_setting(void)
{
	g_wd_digest_setting.config.ctx_num = 0;
	g_wd_digest_setting.config.priv = NULL;
	free(g_wd_digest_setting.config.ctxs);
}

static void clear_sched_in_global_setting(void)
{
	char *name = (char *)g_wd_digest_setting.sched.name;

	free(name);
	g_wd_digest_setting.sched.name = NULL;
	g_wd_digest_setting.sched.poll_policy = NULL;
	g_wd_digest_setting.sched.pick_next_ctx = NULL;
	g_wd_digest_setting.sched.sched_ctx_size = 0;
}

/* Each context has a reqs pool */
static int init_async_request_pool(struct wd_async_msg_pool *pool)
{
	int ctx_num;

	ctx_num = g_wd_digest_setting.config.ctx_num;
	pool->pools = calloc(1, ctx_num * sizeof(struct msg_pool));
	if (!pool->pools)
		return -ENOMEM;
	pool->pool_nums = ctx_num;

	return 0;
}

/* free every reqs pool */
static void uninit_async_request_pool(struct wd_async_msg_pool *pool)
{
	struct msg_pool *p;
	int i, j, num;

	num = pool->pool_nums;
	for (i = 0; i < num; i++) {
		p = &pool->pools[i];
		for (j = 0; j < WD_POOL_MAX_ENTRIES; j++) {
			if (p->used[j])
				WD_ERR("Entry #%d isn't released from reqs pool.\n", j);
				memset(&p->msg[j], 0, sizeof(struct wd_digest_msg));
		}
	}

	free(pool->pools);
}

static struct wd_digest_msg *get_msg_from_pool(struct wd_async_msg_pool *pool,
	handle_t h_ctx, struct wd_digest_req *req)
{
	struct wd_digest_msg *msg;
	struct msg_pool *p;
	int found = 0;
	int cnt = 0;
	int i;

	for (i = 0; i < g_wd_digest_setting.config.ctx_num; i++) {
		if (h_ctx == g_wd_digest_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found) {
		WD_ERR("ctx handler not fonud!\n");
		return NULL;
	}
	p = &pool->pools[i];

	while (__atomic_test_and_set(&p->used[p->tail], __ATOMIC_ACQUIRE)){
		p->tail = (p->tail + 1) % WD_POOL_MAX_ENTRIES;
		cnt++;
		/* full */
		if (cnt == WD_POOL_MAX_ENTRIES)
			return NULL;
	}
	/* get msg from msg_pool[] */
	msg = &p->msg[p->tail];
	memcpy(&msg->req, req, sizeof(struct wd_digest_req));
	msg->tag = p->tail;

	return msg;
}

static void put_msg_to_pool(struct wd_async_msg_pool *pool,
			       handle_t h_ctx,
			       struct wd_digest_msg *msg)
{
	struct msg_pool *p;
	int found = 0;
	int i;

	if (msg->tag < 0 || msg->tag >= WD_POOL_MAX_ENTRIES) {
		WD_ERR("invalid msg cache idx(%d)\n", msg->tag);
		return;
	}
	for (i = 0; i < g_wd_digest_setting.config.ctx_num; i++) {
		if (h_ctx == g_wd_digest_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found) {
		WD_ERR("ctx handler not fonud!\n");
		return;
	}

	p = &pool->pools[i];

	__atomic_clear(&p->used[msg->tag], __ATOMIC_RELEASE);
}

static struct wd_digest_req *get_req_from_pool(struct wd_async_msg_pool *pool,
	handle_t h_ctx, struct wd_digest_msg *msg)
{
	struct msg_pool *p;
	struct wd_digest_msg *c_msg;
	int found = 0;
	int i, idx;

	for (i = 0; i < g_wd_digest_setting.config.ctx_num; i++) {
		if (h_ctx == g_wd_digest_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found)
		return NULL;

	p = &pool->pools[i];
	/* empty */
	if (p->head == p->tail)
		return NULL;
	idx = msg->tag;
	c_msg = &p->msg[idx];

	/* what this is?? */
	msg->req.in = c_msg->req.in;
	msg->req.out = c_msg->req.out;
	msg->req.cb = c_msg->req.cb;
	msg->req.cb_param = c_msg->req.cb_param;

	return &msg->req;
}

int wd_digest_init(struct wd_ctx_config *config, struct wd_digest_sched *sched)
{
	void *priv;
	int ret;

	if (g_wd_digest_setting.driver) {
		WD_ERR("digest driver is exists, name: %s\n",
		g_wd_digest_setting.driver->drv_name);
		return 0;
	}

	if (!config || !sched)
		return -EINVAL;

	/* set config and sched */
	ret = copy_config_to_global_setting(config);
	if (ret < 0) {
		WD_ERR("Fail to copy configuration to global setting!\n");
		return ret;
	}

	ret = copy_sched_to_global_setting(sched);
	if (ret < 0) {
		WD_ERR("Fail to copy schedule to global setting!\n");
		goto out;
	}

	/* set driver */
#ifdef WD_STATIC_DRV
	wd_digest_set_static_drv();
#endif

	/* alloc sched context memory */
	g_wd_digest_setting.sched_ctx = calloc(1, sched->sched_ctx_size);
	if (!g_wd_digest_setting.sched_ctx) {
		ret = -ENOMEM;
		goto out_sched;
	}
	/* init sysnc request pool */
	ret = init_async_request_pool(&g_wd_digest_setting.pool);
	if (ret)
		goto out_pool;

	/* init ctx related resources in specific driver */
	priv = calloc(1, g_wd_digest_setting.driver->drv_ctx_size);
	if (!priv) {
		ret = -ENOMEM;
		goto out_priv;
	}
	g_wd_digest_setting.priv = priv;
	/* sec init */
	ret = g_wd_digest_setting.driver->init(&g_wd_digest_setting.config, priv);
	if (ret < 0) {
		WD_ERR("Fail to init digest dirver!\n");
		goto out_init;
	}

	return 0;
out_init:
	free(priv);
out_priv:
	uninit_async_request_pool(&g_wd_digest_setting.pool);
out_pool:
	free(g_wd_digest_setting.sched_ctx);
out_sched:
	clear_sched_in_global_setting();
out:
	clear_config_in_global_setting();

	return ret;
}

void wd_digest_uninit(void)
{
	clear_sched_in_global_setting();
	clear_config_in_global_setting();
	void *priv = g_wd_digest_setting.priv;
	if (!priv)
		return;

	g_wd_digest_setting.driver->exit(priv);
	free(priv);
	priv = NULL;
}

static void fill_request_msg(struct wd_digest_msg *msg, struct wd_digest_req *req)
{
	msg->alg = req->alg;
	msg->mode = req->mode;
	msg->in = req->in;
	msg->in_bytes = req->in_bytes;
	msg->out = req->out;
	msg->out_bytes = req->out_bytes;
	msg->key = req->key;
	msg->key_bytes = req->key_bytes;
	msg->has_next = req->has_next;
}

int wd_do_digest_sync(handle_t sess, struct wd_digest_req *req)
{
	struct wd_ctx_config *config = &g_wd_digest_setting.config;
	void *sched_ctx = g_wd_digest_setting.sched_ctx;
	struct wd_digest_msg msg, recv_msg;
	__u64 recv_cnt = 0;
	handle_t h_ctx;
	int ret;

	h_ctx = g_wd_digest_setting.sched.pick_next_ctx(config, sched_ctx, req, 0);
	if (!h_ctx) {
		WD_ERR("wd digest pick next ctx is NULL!\n");
		return -EINVAL;
	}

	fill_request_msg(&msg, req);
	req->state = 0;
	ret = g_wd_digest_setting.driver->digest_send(h_ctx, &msg);
	if (ret < 0) {
		WD_ERR("wd send err!\n");
		return ret;
	}

	do {
		ret = g_wd_digest_setting.driver->digest_recv(h_ctx, &recv_msg);
		if (ret == -WD_HW_EACCESS) {
			WD_ERR("Fail to recv bd!\n");
			goto recv_err;
		} else if (ret == -EAGAIN) {
			if (++recv_cnt > MAX_RETRY_COUNTS) {
				WD_ERR("Fail to recv bd and timeout!\n");
				ret = -ETIMEDOUT;
				goto recv_err;
			}
		}
	} while (ret < 0);

	return 0;
recv_err:
	req->state = msg.result;
	return ret;
}

int wd_do_digest_async(handle_t sess, struct wd_digest_req *req)
{
	struct wd_ctx_config *config = &g_wd_digest_setting.config;
	void *sched_ctx = g_wd_digest_setting.sched_ctx;
	struct wd_digest_msg *msg;
	handle_t h_ctx;
	int ret;

	h_ctx = g_wd_digest_setting.sched.pick_next_ctx(config, sched_ctx, req, 0);
	if (!h_ctx) {
		WD_ERR("pick next ctx is NULL!\n");
		return -EINVAL;
	}

	msg = get_msg_from_pool(&g_wd_digest_setting.pool, h_ctx, req);
	if (!msg) {
		WD_ERR("Fail to get pool msg!\n");
		return -EBUSY;
	}

	fill_request_msg(msg, req);

	ret = g_wd_digest_setting.driver->digest_send(h_ctx, msg);
	if (ret < 0) {
		WD_ERR("Fail to  send BD, hw is err!\n");
		put_msg_to_pool(&g_wd_digest_setting.pool, h_ctx, msg);
		return ret;
	}

	return 0;
}

int wd_digest_poll_ctx(handle_t h_ctx, __u32 expt, __u32 *count)
{
	struct wd_digest_msg recv_msg;
	struct wd_digest_req *req;
	__u64 try_cnt = 0;
	__u32 recv_cnt = 0;
	int ret;

	do {
		ret = g_wd_digest_setting.driver->digest_recv(h_ctx, &recv_msg);
		if (ret == -WD_HW_EACCESS) {
			WD_ERR("wd recv err!\n");
			goto recv_err;
		} else if ((ret == -WD_EBUSY) || (ret == -EAGAIN)) {
			if (++try_cnt > MAX_RETRY_COUNTS) {
				WD_ERR("wd recv timeout fail!\n");
				ret = -ETIMEDOUT;
				goto recv_err;
			}
			continue;
		}

		expt--;
		recv_cnt++;
		req = get_req_from_pool(&g_wd_digest_setting.pool, h_ctx, &recv_msg);
		req->cb(req);
	} while (expt > 0);

recv_err:
	*count = recv_cnt;
	return ret;
}

int wd_digest_poll(__u32 expt, __u32 *count)
{
	struct wd_ctx_config *config = &g_wd_digest_setting.config;
	int ret;

	ret = g_wd_digest_setting.sched.poll_policy(config);
	if (ret < 0)
		return ret;
	*count = ret;

	return 0;
}
