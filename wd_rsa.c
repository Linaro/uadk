/* SPDX-License-Identifier: Apache-2.0 */
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>

#include "config.h"
#include "hisi_hpre.h"
#include "wd_rsa.h"
#include "include/drv/wd_rsa_drv.h"

#define WD_POOL_MAX_ENTRIES		1024
#define WD_RSA_MAX_CTX_NUM		1024
#define WD_HW_EACCESS 			62

#define RSA_BALANCE_THRHD		1280
#define RSA_RESEND_CNT	8
#define RSA_MAX_KEY_SIZE		512
#define RSA_RECV_MAX_CNT		60000000 // 1 min

static __thread int balance;

struct wd_rsa_kg_in {
	__u8 *e;
	__u8 *p;
	__u8 *q;
	__u32 ebytes;
	__u32 pbytes;
	__u32 qbytes;
	__u32 key_size;
	void *data[];
};

struct wd_rsa_kg_out {
	__u8 *d;
	__u8 *n;
	__u8 *qinv;
	__u8 *dq;
	__u8 *dp;
	__u32 key_size;
	__u32 dbytes;
	__u32 nbytes;
	__u32 dpbytes;
	__u32 dqbytes;
	__u32 qinvbytes;
	void *data[];
};

struct wd_rsa_pubkey {
	struct wd_dtb n;
	struct wd_dtb e;
	__u32 key_size;
	void *data[];
};

struct wd_rsa_prikey1 {
	struct wd_dtb n;
	struct wd_dtb d;
	__u32 key_size;
	void *data[];
};

/* RSA crt private key */
struct wd_rsa_prikey2 {
	struct wd_dtb p;
	struct wd_dtb q;
	struct wd_dtb dp;
	struct wd_dtb dq;
	struct wd_dtb qinv;
	__u32 key_size;
	void *data[];
};

struct wd_rsa_prikey {
	struct wd_rsa_prikey1 pkey1;
	struct wd_rsa_prikey2 pkey2;
};

/* RSA CRT prikey param types */
enum wd_rsa_crt_prikey_para {
	WD_CRT_PRIKEY_DQ,
	WD_CRT_PRIKEY_DP,
	WD_CRT_PRIKEY_QINV,
	WD_CRT_PRIKEY_Q,
	WD_CRT_PRIKEY_P
};

struct wd_rsa_sess {
	__u32 alg_type;
	__u32 key_size;
	struct wd_rsa_pubkey *pubkey;
	struct wd_rsa_prikey *prikey;
	struct wd_rsa_sess_setup setup;
};

struct msg_pool {
	struct wd_rsa_msg msg[WD_POOL_MAX_ENTRIES];
	int used[WD_POOL_MAX_ENTRIES];
	int head;
	int tail;
};

struct wd_async_msg_pool {
	struct msg_pool *pools;
	int pool_nums;
};

struct wd_rsa_setting {
	struct wd_ctx_config config;
	struct wd_sched sched;
	void *sched_ctx;
	const struct wd_rsa_driver *driver;
	void *priv;
	struct wd_async_msg_pool pool;
} wd_rsa_setting;

#ifdef WD_STATIC_DRV
extern struct wd_rsa_driver wd_rsa_hisi_hpre;
static void wd_rsa_set_static_drv(void)
{
	/*
	 * Fix me: a parameter can be introduced to decide to choose
	 * specific driver. Same as dynamic case.
	 */
	wd_rsa_setting.driver = &wd_rsa_hisi_hpre;
}
#else
static void __attribute__((constructor)) wd_rsa_open_driver(void)
{
	void *driver;

	/* Fix me: vendor driver should be put in /usr/lib/wd/ */
	driver = dlopen("/usr/lib/wd/libhisi_hpre.so", RTLD_NOW);
	if (!driver)
		WD_ERR("Fail to open libhisi_hpre.so\n");
}
#endif

void wd_rsa_set_driver(struct wd_rsa_driver *drv)
{
	wd_rsa_setting.driver = drv;
}

static int copy_config_to_global_setting(struct wd_ctx_config *cfg)
{
	struct wd_ctx *ctxs;
	int i;

	if (cfg->ctx_num <= 0 || cfg->ctx_num > WD_RSA_MAX_CTX_NUM) {
		WD_ERR("ctx_num = %d error\n", cfg->ctx_num);
		return -EINVAL;
	}

	ctxs = calloc(1, cfg->ctx_num * sizeof(struct wd_ctx));
	if (!ctxs) {
		WD_ERR("failed to calloc\n");
		return -ENOMEM;
	}

	for (i = 0; i < cfg->ctx_num; i++) {
		if (!cfg->ctxs[i].ctx) {
			WD_ERR("config ctx NULL\n");
			return -EINVAL;
		}
	}

	memcpy(ctxs, cfg->ctxs, cfg->ctx_num * sizeof(struct wd_ctx));
	wd_rsa_setting.config.ctxs = ctxs;
	/* Can't copy with the size of priv structure. */
	wd_rsa_setting.config.priv = cfg->priv;
	wd_rsa_setting.config.ctx_num = cfg->ctx_num;

	return 0;
}

static int copy_sched_to_global_setting(struct wd_sched *sched)
{
	if (!sched->name) {
		WD_ERR("sched param error\n");
		return -EINVAL;
	}

	wd_rsa_setting.sched.name = strdup(sched->name);
	wd_rsa_setting.sched.pick_next_ctx = sched->pick_next_ctx;
	wd_rsa_setting.sched.poll_policy = sched->poll_policy;

	return 0;
}

static void clear_sched_in_global_setting(void)
{
	char *name = (char *)wd_rsa_setting.sched.name;

	free(name);
	wd_rsa_setting.sched.pick_next_ctx = NULL;
	wd_rsa_setting.sched.poll_policy = NULL;
	wd_rsa_setting.sched.name = NULL;
}

static void clear_config_in_global_setting(void)
{
	wd_rsa_setting.config.priv = NULL;
	wd_rsa_setting.config.ctx_num = 0;
	free(wd_rsa_setting.config.ctxs);
	wd_rsa_setting.config.ctxs = NULL;
}

/* Each ctx has a reqs pool. */
static int wd_init_async_request_pool(struct wd_async_msg_pool *pool)
{
	int num = wd_rsa_setting.config.ctx_num;
	struct msg_pool *p;
	int i;

	pool->pools = calloc(1, num * sizeof(struct msg_pool));
	if (!pool->pools) {
		WD_ERR("failed to calloc\n");
		return -ENOMEM;
	}

	pool->pool_nums = num;
	for (i = 0; i < num; i++) {
		p = &pool->pools[i];
		p->head = 0;
		p->tail = 0;
	}

	return 0;
}

static void wd_uninit_async_request_pool(struct wd_async_msg_pool *pool)
{
	struct msg_pool *p;
	int i, j, num;

	num = pool->pool_nums;
	for (i = 0; i < num; i++) {
		p = &pool->pools[i];
		for (j = 0; j < WD_POOL_MAX_ENTRIES; j++) {
			if (p->used[j]) //todo
				WD_ERR("Entry #%d isn't released from reqs "
					"pool.\n", j);
			memset(&p->msg[j], 0, sizeof(struct wd_rsa_msg));
		}
		p->head = 0;
		p->tail = 0;
	}

	free(pool->pools);
}

static struct wd_rsa_req *wd_get_req_from_pool(struct wd_async_msg_pool *pool,
				handle_t h_ctx,
				struct wd_rsa_msg *msg)
{
	struct msg_pool *p;
	struct wd_rsa_msg *c_msg;
	int i, found = 0;
	int idx;

	for (i = 0; i < wd_rsa_setting.config.ctx_num; i++) {
		if (h_ctx == wd_rsa_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found) {
		WD_ERR("failed to find ctx\n");
		return NULL;
	}

	p = &pool->pools[i];
	/* empty */
	if (p->head == p->tail) {
		WD_ERR("pool %d NULL\n", i);
		return NULL;
	}

	idx = msg->tag;
	c_msg = &p->msg[idx];
	c_msg->req.status = msg->result;

	return &c_msg->req;
}

static struct wd_rsa_msg *wd_get_msg_from_pool(struct wd_async_msg_pool *pool,
						handle_t h_ctx,
						struct wd_rsa_req *req)
{
	struct wd_rsa_msg *msg;
	struct msg_pool *p;
	int found = 0;
	int i, t;

	for (i = 0; i < wd_rsa_setting.config.ctx_num; i++) {
		if (h_ctx == wd_rsa_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found) {
		WD_ERR("failed to find ctx\n");
		return NULL;
	}

	p = &pool->pools[i];

	t = (p->tail + 1) % WD_POOL_MAX_ENTRIES;
	/* full */
	if (p->head == t) {
		WD_ERR("pool %d full\n", i);
		return NULL;
	}

	/* get msg from msg_pool[] */
	msg = &p->msg[p->tail];
	memcpy(&msg->req, req, sizeof(*req));
	msg->tag = p->tail;
	p->tail = t;

	return msg;
}

int wd_rsa_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	void *priv;
	int ret;

	/* wd_rsa_init() could only be invoked once for one process. */
	if (wd_rsa_setting.config.ctx_num) {
		WD_ERR("have initialized\n");
		return 0;
	}

	if (!config || !sched) {
		WD_ERR("config or sched NULL\n");
		return -WD_EINVAL;
	}

	/* set config and sched */
	ret = copy_config_to_global_setting(config);
	if (ret < 0)
		return ret;

	ret = copy_sched_to_global_setting(sched);
	if (ret < 0)
		goto out;

	/*
	 * Fix me: ctx could be passed into wd_rsa_set_static_drv to help to
	 * choose static rsailed vendor driver. For dynamic vendor driver,
	 * wd_rsa_open_driver will be called in the process of opening
	 * libwd_rsa.so to load related driver dynamic library. Vendor driver
	 * pointer will be passed to wd_rsa_setting.driver in the process of
	 * opening of vendor driver dynamic library. A configure file could be
	 * introduced to help to define which vendor driver lib should be
	 * loaded.
	 */
#ifdef WD_STATIC_DRV
	wd_rsa_set_static_drv();
#endif

	/* init async request pool */
	ret = wd_init_async_request_pool(&wd_rsa_setting.pool);
	if (ret < 0)
		goto out_sched;

	/* init ctx related resources in specific driver */
	priv = calloc(1, wd_rsa_setting.driver->drv_ctx_size);
	if (!priv) {
		WD_ERR("failed to calloc drv ctx\n");
		ret = -ENOMEM;
		goto out_priv;
	}
	wd_rsa_setting.priv = priv;
	ret = wd_rsa_setting.driver->init(&wd_rsa_setting.config, priv);
	if (ret < 0)
		goto out_init;

	return 0;

out_init:
	free(priv);
out_priv:
	wd_uninit_async_request_pool(&wd_rsa_setting.pool);
out_sched:
	clear_sched_in_global_setting();
out:
	clear_config_in_global_setting();

	return ret;
}

void wd_rsa_uninit(void)
{
	void *priv;

	/* driver uninit */
	priv = wd_rsa_setting.priv;
	wd_rsa_setting.driver->exit(priv);
	free(priv);
	wd_rsa_setting.priv = NULL;

	/* uninit async request pool */
	wd_uninit_async_request_pool(&wd_rsa_setting.pool);

	/* unset config, sched, driver */
	clear_sched_in_global_setting();
	clear_config_in_global_setting();
}

static int fill_rsa_msg(struct wd_rsa_msg *msg, struct wd_rsa_req *req,
			struct wd_rsa_sess *sess)
{
	__u8 *key = NULL;

	if (sess->setup.is_crt)
		msg->key_type = WD_RSA_PRIKEY2;
	else
		msg->key_type = WD_RSA_PRIKEY1;

	memcpy(&msg->req, req, sizeof(*req));
	msg->key_bytes = sess->key_size;
	msg->result = WD_EINVAL;

	switch (msg->req.op_type) {
	case WD_RSA_SIGN:
		key = (__u8 *)sess->prikey;
		break;
	case WD_RSA_VERIFY:
		key = (__u8 *)sess->pubkey;
		break;
	case WD_RSA_GENKEY:
		key = (__u8 *)req->src;
		break;
	default:
		WD_ERR("rsa msguest op type err!\n");
		return -WD_EINVAL;
	}

	if (!key) {
		WD_ERR("rsa msguest key null!\n");
		return -WD_EINVAL;
	}

	msg->key = key;

	return 0;
}

int wd_do_rsa_sync(handle_t h_sess, struct wd_rsa_req *req)
{
	struct wd_rsa_sess *sess = (struct wd_rsa_sess *)(uintptr_t)h_sess;
	struct wd_ctx_config *config = &wd_rsa_setting.config;
	struct wd_rsa_msg msg;
	__u64 rx_cnt = 0;
	handle_t h_ctx;
	int ret;

	if (unlikely(!h_sess || !req)) {
		WD_ERR("input param NULL!\n");
		return -WD_EINVAL;
	}

	h_ctx = wd_rsa_setting.sched.pick_next_ctx(config, req, 0);
	if (unlikely(!h_ctx)) {
		WD_ERR("failed to pick ctx!\n");
		return -WD_EINVAL;
	}

	memset(&msg, 0, sizeof(struct wd_rsa_msg));
	ret = fill_rsa_msg(&msg, req, sess);
	if (unlikely(ret))
		return ret;

	ret = wd_rsa_setting.driver->send(h_ctx, &msg);
	if (unlikely(ret < 0)) {
		WD_ERR("send err!\n");
		return ret;
	}

	do {
		ret = wd_rsa_setting.driver->recv(h_ctx, &msg);
		if (unlikely(ret == -WD_HW_EACCESS)) {
			WD_ERR("wd_recv hw err!\n");
			return ret;
		} else if (ret == -EAGAIN) {
			if (++rx_cnt > RSA_RECV_MAX_CNT) {
				WD_ERR("recv timeout fail!\n");
				return -ETIMEDOUT;
			} else if (balance > RSA_BALANCE_THRHD) {
				usleep(1);
			}
		}
	} while (ret < 0);

	balance = rx_cnt;
	req->status = msg.result;
	ret = GET_NEGATIVE(req->status);

	return ret;
}

int wd_do_rsa_async(handle_t sess, struct wd_rsa_req *req)
{
	struct wd_ctx_config *config = &wd_rsa_setting.config;
	struct wd_rsa_msg *msg;
	handle_t h_ctx;
	int ret;

	if (unlikely(!req || !sess)) {
		WD_ERR("input param NULL!\n");
		return -WD_EINVAL;
	}

	h_ctx = wd_rsa_setting.sched.pick_next_ctx(config, req, 0);
	if (unlikely(!h_ctx)) {
		WD_ERR("failed to pick ctx!\n");
		return -ENOMEM;
	}

	msg = wd_get_msg_from_pool(&wd_rsa_setting.pool, h_ctx, req);
	if (!msg)
		return -WD_EBUSY;

	ret = fill_rsa_msg(msg, req, (struct wd_rsa_sess *)(uintptr_t)sess);
	if (ret < 0)
		return ret;

	return wd_rsa_setting.driver->send(h_ctx, msg);
}

__u32 wd_rsa_poll_ctx(handle_t ctx, __u32 num)
{
	struct wd_rsa_req *req;
	struct wd_rsa_msg msg;
	int count = 0;
	int ret;

	do {
		ret = wd_rsa_setting.driver->recv(ctx, &msg);
		if (ret == -EAGAIN) {
			break;
		} else if (ret < 0) {
			WD_ERR("recv err at rsa poll!\n");
		}
		count++;
		req = wd_get_req_from_pool(&wd_rsa_setting.pool, ctx, &msg);
		req->cb(req->cb_param);
	} while (--num);

	/*TODO free idx of msg_pool */ //todo

	return count;
}

int wd_rsa_poll(__u32 *count)
{
	struct wd_ctx_config *config = &wd_rsa_setting.config;
	int ret;

	ret = wd_rsa_setting.sched.poll_policy(config);
	if (ret < 0)
		return ret;
	*count = ret;

	return 0;
}

int wd_rsa_kg_in_data(struct wd_rsa_kg_in *ki, char **data)
{
	if (!ki || !data) {
		WD_ERR("param is NULL!\n");
		return -WD_EINVAL;
	}

	*data = (char *)ki->data;
	return (int)GEN_PARAMS_SZ(ki->key_size);
}

int wd_rsa_kg_out_data(struct wd_rsa_kg_out *ko, char **data)
{
	if (!ko || !data) {
		WD_ERR("param is NULL!\n");
		return -WD_EINVAL;
	}

	*data = (char *)ko->data;

	/* CRT need this size, but no CRT size is smaller */
	return (int)CRT_GEN_PARAMS_SZ(ko->key_size);
}

/* Create a RSA key generate operation input with parameter e, p and q */
struct wd_rsa_kg_in *wd_rsa_new_kg_in(handle_t sess, struct wd_dtb *e,
				struct wd_dtb *p, struct wd_dtb *q)
{
	struct wd_rsa_kg_in *kg_in;
	struct wd_rsa_sess *c = (struct wd_rsa_sess *)(uintptr_t)sess;
	int kg_in_size;

	if (!sess || !c || !e || !p || !q) {
		WD_ERR("sess malloc kg_in memory fail!\n");
		return NULL;
	}

	if (!c->key_size || c->key_size > RSA_MAX_KEY_SIZE) {
		WD_ERR("key size err at create kg in!\n");
		return NULL;
	}

	if (e->dsize > c->key_size) {
		WD_ERR("e para err at create kg in!\n");
		return NULL;
	}
	if (p->dsize > CRT_PARAM_SZ(c->key_size)) {
		WD_ERR("p para err at create kg in!\n");
		return NULL;
	}
	if (q->dsize > CRT_PARAM_SZ(c->key_size)) {
		WD_ERR("q para err at create kg in!\n");
		return NULL;
	}

	kg_in_size = GEN_PARAMS_SZ(c->key_size);
	kg_in = malloc(kg_in_size + sizeof(*kg_in));
	if (!kg_in) {
		WD_ERR("sess malloc kg_in memory fail!\n");
		return NULL;
	}
	memset(kg_in, 0, kg_in_size + sizeof(*kg_in));
	kg_in->key_size = c->key_size;
	kg_in->ebytes = e->dsize;
	kg_in->pbytes = p->dsize;
	kg_in->qbytes = q->dsize;
	kg_in->e = (void *)kg_in->data;
	kg_in->p = (void *)kg_in->e + c->key_size;
	kg_in->q = (void *)kg_in->p + CRT_PARAM_SZ(c->key_size);

	memcpy(kg_in->e, e->data, e->dsize);
	memcpy(kg_in->p, p->data, p->dsize);
	memcpy(kg_in->q, q->data, q->dsize);

	return kg_in;
}

void wd_rsa_get_kg_in_params(struct wd_rsa_kg_in *kin, struct wd_dtb *e,
				      struct wd_dtb *q, struct wd_dtb *p)
{
	if (!kin || !e || !q || !p) {
		WD_ERR("para err at get input parameters key generate !\n");
		return;
	}

	e->bsize = kin->key_size;
	e->dsize = kin->ebytes;
	e->data = (void *)kin->e;
	q->bsize = CRT_PARAM_SZ(kin->key_size);
	q->dsize = kin->qbytes;
	q->data = (void *)kin->q;
	p->bsize = CRT_PARAM_SZ(kin->key_size);
	p->dsize = kin->pbytes;
	p->data = (void *)kin->p;
}

static void del_kg(void *sess, void *k)
{
	struct wd_rsa_sess *c = sess;

	if (!c || !k) {
		WD_ERR("del key generate params err!\n");
		return;
	}

	free(k);
}

void wd_rsa_del_kg_in(handle_t sess, struct wd_rsa_kg_in *ki)
{
	del_kg((void *)(uintptr_t)sess, ki);
}

struct wd_rsa_kg_out *wd_rsa_new_kg_out(handle_t sess)
{
	struct wd_rsa_sess *c = (struct wd_rsa_sess *)(uintptr_t)sess;
	struct wd_rsa_kg_out *kg_out;
	int kg_out_size;
	int kz;

	if (!c) {
		WD_ERR("sess null at new rsa key gen out!\n");
		return NULL;
	}

	kz = c->key_size;
	if (!kz || kz > RSA_MAX_KEY_SIZE) {
		WD_ERR("new kg out key size error!\n");
		return NULL;
	}

	if (c->setup.is_crt)
		kg_out_size = CRT_GEN_PARAMS_SZ(c->key_size);
	else
		kg_out_size = GEN_PARAMS_SZ(c->key_size);


	kg_out = malloc(kg_out_size + sizeof(*kg_out));
	if (!kg_out) {
		WD_ERR("sess malloc kg_in memory fail!\n");
		return NULL;
	}

	memset(kg_out, 0, kg_out_size + sizeof(*kg_out));
	kg_out->key_size = kz;
	kg_out->d = (void *)kg_out->data;
	kg_out->n = kg_out->d + kz;
	if (c->setup.is_crt) {
		kg_out->qinv = (void *)kg_out->n + kz;
		kg_out->dq = kg_out->qinv + CRT_PARAM_SZ(kz);
		kg_out->dp = kg_out->dq + CRT_PARAM_SZ(kz);
	}

	return kg_out;
}

void wd_rsa_del_kg_out(handle_t sess,  struct wd_rsa_kg_out *kout)
{
	del_kg((void *)(uintptr_t)sess, kout);
}

void wd_rsa_get_kg_out_params(struct wd_rsa_kg_out *kout, struct wd_dtb *d,
					struct wd_dtb *n)
{
	if (!kout) {
		WD_ERR("input null at get key gen params!\n");
		return;
	}

	if (d && kout->d) {
		d->bsize = kout->key_size;
		d->dsize = kout->dbytes;
		d->data = (void *)kout->d;
	}

	if (n && kout->n) {
		n->bsize = kout->key_size;
		n->dsize = kout->nbytes;
		n->data = (void *)kout->n;
	}
}

void wd_rsa_get_kg_out_crt_params(struct wd_rsa_kg_out *kout,
					struct wd_dtb *qinv,
					struct wd_dtb *dq, struct wd_dtb *dp)
{
	if (!kout || !qinv || !dq || !dp) {
		WD_ERR("input null at get key gen crt para!\n");
		return;
	}

	if (qinv && kout->qinv) {
		qinv->bsize = CRT_PARAM_SZ(kout->key_size);
		qinv->dsize = kout->qinvbytes;
		qinv->data = (void *)kout->qinv;
	}

	if (dq && kout->dq) {
		dq->bsize = CRT_PARAM_SZ(kout->key_size);
		dq->dsize = kout->dqbytes;
		dq->data = (void *)kout->dq;
	}

	if (dp && kout->dp) {
		dp->bsize = CRT_PARAM_SZ(kout->key_size);
		dp->dsize = kout->dpbytes;
		dp->data = (void *)kout->dp;
	}
}

void wd_rsa_set_kg_out_crt_psz(struct wd_rsa_kg_out *kout,
				    size_t qinv_sz,
				    size_t dq_sz,
				    size_t dp_sz)
{
	kout->qinvbytes = qinv_sz;
	kout->dqbytes = dq_sz;
	kout->dpbytes = dp_sz;
}

void wd_rsa_set_kg_out_psz(struct wd_rsa_kg_out *kout,
				size_t d_sz,
				size_t n_sz)
{
	kout->dbytes = d_sz;
	kout->nbytes = n_sz;
}

static void init_pkey2(struct wd_rsa_prikey2 *pkey2, int ksz)
{
	int hlf_ksz = CRT_PARAM_SZ(ksz);

	pkey2->dq.data = (char *)pkey2->data;
	pkey2->dp.data = pkey2->dq.data + hlf_ksz;
	pkey2->q.data = pkey2->dp.data + hlf_ksz;
	pkey2->p.data = pkey2->q.data + hlf_ksz;
	pkey2->qinv.data = pkey2->p.data + hlf_ksz;
	pkey2->dq.bsize = hlf_ksz;
	pkey2->dp.bsize = hlf_ksz;
	pkey2->q.bsize = hlf_ksz;
	pkey2->p.bsize = hlf_ksz;
	pkey2->qinv.bsize = hlf_ksz;
	pkey2->key_size = ksz;
}

static void init_pkey1(struct wd_rsa_prikey1 *pkey1, int ksz)
{
	pkey1->d.data = (char *)pkey1->data;
	pkey1->n.data = pkey1->d.data + ksz;
	pkey1->d.bsize = ksz;
	pkey1->n.bsize = ksz;
	pkey1->key_size = ksz;
}

static void init_pubkey(struct wd_rsa_pubkey *pubkey, int ksz)
{
	pubkey->e.data = (char *)pubkey->data;
	pubkey->n.data = pubkey->e.data + ksz;
	pubkey->e.bsize = ksz;
	pubkey->n.bsize = ksz;
	pubkey->key_size = ksz;
}

static int create_sess_key(struct wd_rsa_sess_setup *setup,
			struct wd_rsa_sess *sess)
{
	struct wd_rsa_prikey2 *pkey2;
	struct wd_rsa_prikey1 *pkey1;
	int len;

	if (setup->is_crt) {
		len = sizeof(struct wd_rsa_prikey) +
			CRT_PARAMS_SZ(sess->key_size);
		sess->prikey = malloc(len);
		if (!sess->prikey) {
			WD_ERR("alloc prikey2 fail!\n");
			return -WD_ENOMEM;
		}
		pkey2 = &sess->prikey->pkey2;
		memset(sess->prikey, 0, len);
		init_pkey2(pkey2, sess->key_size);
	} else {
		len = sizeof(struct wd_rsa_prikey) +
			GEN_PARAMS_SZ(sess->key_size);
		sess->prikey = malloc(len);
		if (!sess->prikey) {
			WD_ERR("alloc prikey1 fail!\n");
			return -WD_ENOMEM;
		}
		pkey1 = &sess->prikey->pkey1;
		memset(sess->prikey, 0, len);
		init_pkey1(pkey1, sess->key_size);
	}

	len = sizeof(struct wd_rsa_pubkey) +
		GEN_PARAMS_SZ(sess->key_size);
	sess->pubkey = malloc(len);
	if (!sess->pubkey) {
		free(sess->prikey);
		WD_ERR("alloc pubkey fail!\n");
		return -WD_ENOMEM;
	}

	memset(sess->pubkey, 0, len);
	init_pubkey(sess->pubkey, sess->key_size);

	return WD_SUCCESS;
}

static void del_sess_key(struct wd_rsa_sess *sess)
{
	// todo
	if (sess->prikey)
		free(sess->prikey);
	if (sess->pubkey)
		free(sess->pubkey);

}

static void del_sess(struct wd_rsa_sess *c)
{
	if (c)
		free(c);
}

/* Before initiate this context, we should get a queue from WD */
handle_t wd_rsa_alloc_sess(struct wd_rsa_sess_setup *setup)
{
	struct wd_rsa_sess *sess;
	int ret;

	if (!setup) {
		WD_ERR("alloc rsa sess setup NULL!\n");
		return 0;
	}

	if (setup->key_bits != 1024 &&
		setup->key_bits != 2048 &&
		setup->key_bits != 3072 &&
		setup->key_bits != 4096) {
		WD_ERR("alloc rsa sess key_bit %u err!\n", setup->key_bits);
		return 0;
	}

	sess = calloc(1, sizeof(struct wd_rsa_sess));
	if (!sess)
		return (handle_t)(uintptr_t)sess;

	memcpy(&sess->setup, setup, sizeof(*setup));
	sess->key_size = setup->key_bits >> BYTE_BITS_SHIFT;

	ret = create_sess_key(setup, sess);
	if (ret) {
		WD_ERR("fail creating rsa sess keys!\n");
		del_sess(sess);
		return 0;
	}

	return (handle_t)(uintptr_t)sess;
}

void wd_rsa_free_sess(handle_t sess)
{
	struct wd_rsa_sess *sess_t = (struct wd_rsa_sess *)(uintptr_t)sess;

	if (!sess_t) {
		WD_ERR("free rsa sess param err!\n");
		return;
	}

	del_sess_key(sess_t);
	del_sess(sess_t);
}


bool wd_rsa_is_crt(handle_t sess)
{
	if (!sess) {
		WD_ERR("rsa is crt judge, sess NULL, return false!\n");
		return false;
	}

	return ((struct wd_rsa_sess *)sess)->setup.is_crt;
}

int wd_rsa_key_bits(handle_t sess)
{
	if (!sess) {
		WD_ERR("get rsa key bits, sess NULL!\n");
		return 0;
	}

	return ((struct wd_rsa_sess *)sess)->setup.key_bits;
}

int wd_rsa_set_pubkey_params(handle_t sess, struct wd_dtb *e, struct wd_dtb *n)
{
	struct wd_rsa_sess *c = (struct wd_rsa_sess *)(uintptr_t)sess;

	if (!sess) {
		WD_ERR("sess NULL in set rsa public key!\n");
		return -WD_EINVAL;
	}

	if (e) {
		if (e->dsize > c->pubkey->key_size || !e->data) {
			WD_ERR("e err in set rsa public key!\n");
			return -WD_EINVAL;
		}

		c->pubkey->e.dsize = e->dsize;
		memset(c->pubkey->e.data, 0, c->pubkey->e.bsize);
		memcpy(c->pubkey->e.data, e->data, e->dsize);
	}

	if (n) {
		if (n->dsize > c->pubkey->key_size || !n->data) {
			WD_ERR("n err in set rsa public key!\n");
			return -WD_EINVAL;
		}

		c->pubkey->n.dsize = n->dsize;
		memset(c->pubkey->n.data, 0, c->pubkey->n.bsize);
		memcpy(c->pubkey->n.data, n->data, n->dsize);
	}
	return WD_SUCCESS;
}

void wd_rsa_get_pubkey_params(struct wd_rsa_pubkey *pbk, struct wd_dtb **e,
					struct wd_dtb **n)
{
	if (!pbk) {
		WD_ERR("input NULL in get rsa public key!\n");
		return;
	}
	if (e)
		*e = &pbk->e;

	if (n)
		*n = &pbk->n;
}

int wd_rsa_set_prikey_params(handle_t sess, struct wd_dtb *d, struct wd_dtb *n)
{
	struct wd_rsa_prikey1 *pkey1;
	struct wd_rsa_sess *c = (struct wd_rsa_sess *)(uintptr_t)sess;

	if (!sess || wd_rsa_is_crt(sess)) {
		WD_ERR("sess err in set rsa private key1!\n");
		return -WD_EINVAL;
	}
	pkey1 = &c->prikey->pkey1;
	if (d) {
		if (d->dsize > pkey1->key_size || !d->data) {
			WD_ERR("d err in set rsa private key1!\n");
			return -WD_EINVAL;
		}

		pkey1->d.dsize = d->dsize;
		memset(pkey1->d.data, 0, pkey1->d.bsize);
		memcpy(pkey1->d.data, d->data, d->dsize);
	}
	if (n) {
		if (n->dsize > pkey1->key_size || !n->data) {
			WD_ERR("en err in set rsa private key1!\n");
			return -WD_EINVAL;
		}

		pkey1->n.dsize = n->dsize;
		memset(pkey1->n.data, 0, pkey1->n.bsize);
		memcpy(pkey1->n.data, n->data, n->dsize);
	}
	return WD_SUCCESS;
}

void wd_rsa_get_prikey_params(struct wd_rsa_prikey *pvk, struct wd_dtb **d,
					struct wd_dtb **n)
{
	struct wd_rsa_prikey1 *pkey1;

	if (!pvk) {
		WD_ERR("pvk is NULL!\n");
		return;
	}

	pkey1 = &pvk->pkey1;

	if (d)
		*d = &pkey1->d;
	if (n)
		*n = &pkey1->n;
}

static int rsa_set_param(struct wd_dtb *src, struct wd_dtb *dst)
{
	if (!src || !dst || dst->dsize > src->bsize)
		return -WD_EINVAL;

	src->dsize = dst->dsize;
	memset(src->data, 0, src->bsize);
	memcpy(src->data, dst->data, dst->dsize);

	return WD_SUCCESS;
}

static int rsa_prikey2_param_set(struct wd_rsa_prikey2 *pkey2,
				 struct wd_dtb *param,
				 enum wd_rsa_crt_prikey_para type)
{
	int ret;

	if (param->dsize > pkey2->key_size || !param->data)
		return -WD_EINVAL;

	switch (type) {
	case WD_CRT_PRIKEY_DQ:
		ret = rsa_set_param(&pkey2->dq, param);
		break;

	case WD_CRT_PRIKEY_DP:
		ret = rsa_set_param(&pkey2->dp, param);
		break;

	case WD_CRT_PRIKEY_QINV:
		ret = rsa_set_param(&pkey2->qinv, param);
		break;

	case WD_CRT_PRIKEY_P:
		ret = rsa_set_param(&pkey2->p, param);
		break;

	case WD_CRT_PRIKEY_Q:
		ret = rsa_set_param(&pkey2->q, param);
		break;

	default:
		WD_ERR("%s: err type %d!\n", __func__, type);
		ret = -WD_EINVAL;
		break;
	}

	return ret;
}

int wd_rsa_set_crt_prikey_params(handle_t sess, struct wd_dtb *dq,
			struct wd_dtb *dp, struct wd_dtb *qinv,
			struct wd_dtb *q, struct wd_dtb *p)
{
	struct wd_rsa_sess *c = (struct wd_rsa_sess *)(uintptr_t)sess;
	struct wd_rsa_prikey2 *pkey2;
	int ret = -WD_EINVAL;

	if (!sess || !wd_rsa_is_crt(sess)) {
		WD_ERR("sess err in set rsa crt private key2!\n");
		return ret;
	}

	if (!dq || !dp || !qinv || !q || !p) {
		WD_ERR("para err in set rsa crt private key2!\n");
		return ret;
	}

	pkey2 = &c->prikey->pkey2;
	ret = rsa_prikey2_param_set(pkey2, dq, WD_CRT_PRIKEY_DQ);
	if (ret) {
		WD_ERR("dq err in set rsa private key2!\n");
		return ret;
	}

	ret = rsa_prikey2_param_set(pkey2, dp, WD_CRT_PRIKEY_DP);
	if (ret) {
		WD_ERR("dp err in set rsa private key2!\n");
		return ret;
	}

	ret = rsa_prikey2_param_set(pkey2, qinv, WD_CRT_PRIKEY_QINV);
	if (ret) {
		WD_ERR("qinv err in set rsa private key2!\n");
		return ret;
	}

	ret = rsa_prikey2_param_set(pkey2, q, WD_CRT_PRIKEY_Q);
	if (ret) {
		WD_ERR("q err in set rsa private key2!\n");
		return ret;
	}

	ret = rsa_prikey2_param_set(pkey2, p, WD_CRT_PRIKEY_P);
	if (ret) {
		WD_ERR("p err in set rsa private key2!\n");
		return ret;
	}

	return WD_SUCCESS;
}

void wd_rsa_get_crt_prikey_params(struct wd_rsa_prikey *pvk,
		struct wd_dtb **dq,
		struct wd_dtb **dp, struct wd_dtb **qinv,
		struct wd_dtb **q, struct wd_dtb **p)
{
	struct wd_rsa_prikey2 *pkey2;

	if (!pvk) {
		WD_ERR("pvk is NULL!\n");
		return;
	}

	pkey2 = &pvk->pkey2;

	if (dq)
		*dq = &pkey2->dq;
	if (dp)
		*dp = &pkey2->dp;
	if (qinv)
		*qinv = &pkey2->qinv;
	if (q)
		*q = &pkey2->q;
	if (p)
		*p = &pkey2->p;
}

void wd_rsa_get_pubkey(handle_t sess, struct wd_rsa_pubkey **pubkey)
{
	if (!sess || !pubkey) {
		WD_ERR("param is NULL!\n");
		return;
	}

	*pubkey = ((struct wd_rsa_sess *)sess)->pubkey;
}

void wd_rsa_get_prikey(handle_t sess, struct wd_rsa_prikey **prikey)
{
	if (!sess || !prikey) {
		WD_ERR("param is NULL!\n");
		return;
	}

	*prikey = ((struct wd_rsa_sess *)sess)->prikey;
}
