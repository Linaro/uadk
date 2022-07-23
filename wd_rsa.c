/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>

#include "config.h"
#include "include/drv/wd_rsa_drv.h"
#include "wd_util.h"

#define WD_POOL_MAX_ENTRIES		1024
#define WD_HW_EACCESS			62

#define RSA_MAX_KEY_SIZE		512

static __thread __u64 balance;

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

/* RSA CRT mode private key */
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

/* RSA private key parameter types */
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
	void *sched_key;
};

static struct wd_rsa_setting {
	struct wd_ctx_config_internal config;
	struct wd_sched sched;
	void *sched_ctx;
	const struct wd_rsa_driver *driver;
	void *priv;
	void *dlhandle;
	struct wd_async_msg_pool pool;
} wd_rsa_setting;

struct wd_env_config wd_rsa_env_config;

#ifdef WD_STATIC_DRV
static void wd_rsa_set_static_drv(void)
{
	wd_rsa_setting.driver = wd_rsa_get_driver();
	if (!wd_rsa_setting.driver)
		WD_ERR("failed to get rsa driver!\n");
}
#else
static void __attribute__((constructor)) wd_rsa_open_driver(void)
{
	wd_rsa_setting.dlhandle = dlopen("libhisi_hpre.so", RTLD_NOW);
	if (!wd_rsa_setting.dlhandle)
		WD_ERR("failed to open libhisi_hpre.so!\n");
}

static void __attribute__((destructor)) wd_rsa_close_driver(void)
{
	if (wd_rsa_setting.dlhandle)
		dlclose(wd_rsa_setting.dlhandle);
}
#endif

void wd_rsa_set_driver(struct wd_rsa_driver *drv)
{
	if (!drv) {
		WD_ERR("invalid: rsa drv is NULL!\n");
		return;
	}

	wd_rsa_setting.driver = drv;
}

int wd_rsa_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	void *priv;
	int ret;

	ret = wd_init_param_check(config, sched);
	if (ret)
		return ret;

	ret = wd_set_epoll_en("WD_RSA_EPOLL_EN",
			      &wd_rsa_setting.config.epoll_en);
	if (ret < 0)
		return ret;

	ret = wd_init_ctx_config(&wd_rsa_setting.config, config);
	if (ret < 0)
		return ret;

	ret = wd_init_sched(&wd_rsa_setting.sched, sched);
	if (ret < 0)
		goto out;

#ifdef WD_STATIC_DRV
	wd_rsa_set_static_drv();
#endif

	/* fix me: sadly find we allocate async pool for every ctx */
	ret = wd_init_async_request_pool(&wd_rsa_setting.pool,
					 config->ctx_num, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_rsa_msg));
	if (ret < 0)
		goto out_sched;

	/* initialize ctx related resources in specific driver */
	priv = calloc(1, wd_rsa_setting.driver->drv_ctx_size);
	if (!priv) {
		ret = -WD_ENOMEM;
		goto out_priv;
	}

	wd_rsa_setting.priv = priv;
	ret = wd_rsa_setting.driver->init(&wd_rsa_setting.config, priv,
					  wd_rsa_setting.driver->alg_name);
	if (ret < 0) {
		WD_ERR("failed to init rsa driver, ret = %d!\n", ret);
		goto out_init;
	}

	return 0;

out_init:
	free(priv);
	wd_rsa_setting.priv = NULL;
out_priv:
	wd_uninit_async_request_pool(&wd_rsa_setting.pool);
out_sched:
	wd_clear_sched(&wd_rsa_setting.sched);
out:
	wd_clear_ctx_config(&wd_rsa_setting.config);
	return ret;
}

void wd_rsa_uninit(void)
{
	if (!wd_rsa_setting.priv) {
		WD_ERR("invalid: repeat uninit rsa!\n");
		return;
	}

	/* driver uninit */
	wd_rsa_setting.driver->exit(wd_rsa_setting.priv);
	free(wd_rsa_setting.priv);
	wd_rsa_setting.priv = NULL;

	/* uninit async request pool */
	wd_uninit_async_request_pool(&wd_rsa_setting.pool);

	/* unset config, sched, driver */
	wd_clear_sched(&wd_rsa_setting.sched);
	wd_clear_ctx_config(&wd_rsa_setting.config);
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
		WD_ERR("invalid: rsa msg req op type %u is err!\n", msg->req.op_type);
		return -WD_EINVAL;
	}

	if (unlikely(!key)) {
		WD_ERR("invalid: rsa msg key null!\n");
		return -WD_EINVAL;
	}

	if (msg->req.op_type == WD_RSA_SIGN ||
		msg->req.op_type == WD_RSA_VERIFY) {
		if (unlikely(msg->req.src_bytes != sess->key_size)) {
			WD_ERR("invalid: sign or verf src_bytes != key_size!\n");
			return -WD_EINVAL;
		}

		if (unlikely(req->dst_bytes != sess->key_size)) {
			WD_ERR("invalid: req dst bytes %hu is error!\n", req->dst_bytes);
			return -WD_EINVAL;
		}
	}

	msg->key = key;

	return 0;
}

int wd_do_rsa_sync(handle_t h_sess, struct wd_rsa_req *req)
{
	struct wd_ctx_config_internal *config = &wd_rsa_setting.config;
	handle_t h_sched_ctx = wd_rsa_setting.sched.h_sched_ctx;
	struct wd_rsa_sess *sess = (struct wd_rsa_sess *)h_sess;
	struct wd_msg_handle msg_handle;
	struct wd_ctx_internal *ctx;
	struct wd_rsa_msg msg;
	__u32 idx;
	int ret;

	if (unlikely(!h_sess || !req)) {
		WD_ERR("invalid: input param NULL!\n");
		return -WD_EINVAL;
	}

	idx = wd_rsa_setting.sched.pick_next_ctx(h_sched_ctx,
							    sess->sched_key,
							    CTX_MODE_SYNC);
	ret = wd_check_ctx(config, CTX_MODE_SYNC, idx);
	if (ret)
		return ret;

	wd_dfx_msg_cnt(config->msg_cnt, WD_CTX_CNT_NUM, idx);
	ctx = config->ctxs + idx;

	memset(&msg, 0, sizeof(struct wd_rsa_msg));
	ret = fill_rsa_msg(&msg, req, sess);
	if (unlikely(ret))
		return ret;

	msg_handle.send = wd_rsa_setting.driver->send;
	msg_handle.recv = wd_rsa_setting.driver->recv;

	pthread_spin_lock(&ctx->lock);
	ret = wd_handle_msg_sync(&msg_handle, ctx->ctx, &msg, &balance,
				 wd_rsa_setting.config.epoll_en);
	pthread_spin_unlock(&ctx->lock);
	if (unlikely(ret))
		return ret;

	req->dst_bytes = msg.req.dst_bytes;
	req->status = msg.result;

	return GET_NEGATIVE(msg.result);
}

int wd_do_rsa_async(handle_t sess, struct wd_rsa_req *req)
{
	struct wd_ctx_config_internal *config = &wd_rsa_setting.config;
	handle_t h_sched_ctx = wd_rsa_setting.sched.h_sched_ctx;
	struct wd_rsa_sess *sess_t = (struct wd_rsa_sess *)sess;
	struct wd_rsa_msg *msg = NULL;
	struct wd_ctx_internal *ctx;
	int ret, mid;
	__u32 idx;

	if (unlikely(!req || !sess || !req->cb)) {
		WD_ERR("invalid: input param NULL!\n");
		return -WD_EINVAL;
	}

	idx = wd_rsa_setting.sched.pick_next_ctx(h_sched_ctx,
							    sess_t->sched_key,
							    CTX_MODE_ASYNC);
	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	wd_dfx_msg_cnt(config->msg_cnt, WD_CTX_CNT_NUM, idx);
	ctx = config->ctxs + idx;

	mid = wd_get_msg_from_pool(&wd_rsa_setting.pool, idx, (void **)&msg);
	if (mid < 0)
		return -WD_EBUSY;

	ret = fill_rsa_msg(msg, req, (struct wd_rsa_sess *)sess);
	if (ret)
		goto fail_with_msg;
	msg->tag = mid;

	ret = wd_rsa_setting.driver->send(ctx->ctx, msg);
	if (unlikely(ret)) {
		if (ret != -WD_EBUSY)
			WD_ERR("failed to send rsa BD, hw is err!\n");

		goto fail_with_msg;
	}

	ret = wd_add_task_to_async_queue(&wd_rsa_env_config, idx);
	if (ret)
		goto fail_with_msg;

	return 0;

fail_with_msg:
	wd_put_msg_to_pool(&wd_rsa_setting.pool, idx, mid);
	return ret;
}

struct wd_rsa_msg *wd_rsa_get_msg(__u32 idx, __u32 tag)
{
	return wd_find_msg_in_pool(&wd_rsa_setting.pool, idx, tag);
}

int wd_rsa_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_rsa_setting.config;
	struct wd_ctx_internal *ctx;
	struct wd_rsa_req *req;
	struct wd_rsa_msg recv_msg, *msg;
	__u32 rcv_cnt = 0;
	__u32 tmp = expt;
	int ret;

	if (unlikely(!count)) {
		WD_ERR("invalid: param count is NULL!\n");
		return -WD_EINVAL;
	}

	*count = 0;

	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	do {
		ret = wd_rsa_setting.driver->recv(ctx->ctx, &recv_msg);
		if (ret == -WD_EAGAIN) {
			return ret;
		} else if (ret < 0) {
			WD_ERR("failed to async recv, ret = %d!\n", ret);
			wd_put_msg_to_pool(&wd_rsa_setting.pool, idx,
					   recv_msg.tag);
			return ret;
		}
		rcv_cnt++;
		msg = wd_find_msg_in_pool(&wd_rsa_setting.pool, idx,
					  recv_msg.tag);
		if (!msg) {
			WD_ERR("failed to get msg from pool!\n");
			return -WD_EINVAL;
		}

		msg->req.dst_bytes = recv_msg.req.dst_bytes;
		msg->req.status = recv_msg.result;
		req = &msg->req;
		req->cb(req);
		wd_put_msg_to_pool(&wd_rsa_setting.pool, idx, recv_msg.tag);
		*count = rcv_cnt;
	} while (--tmp);

	return ret;
}

int wd_rsa_poll(__u32 expt, __u32 *count)
{
	handle_t h_sched_ctx = wd_rsa_setting.sched.h_sched_ctx;

	if (unlikely(!count)) {
		WD_ERR("invalid: rsa poll count is NULL!\n");
		return -WD_EINVAL;
	}

	return wd_rsa_setting.sched.poll_policy(h_sched_ctx, expt, count);
}

int wd_rsa_kg_in_data(struct wd_rsa_kg_in *ki, char **data)
{
	if (!ki || !data) {
		WD_ERR("invalid: param is NULL!\n");
		return -WD_EINVAL;
	}

	*data = (char *)ki->data;
	return (int)GEN_PARAMS_SZ(ki->key_size);
}

int wd_rsa_kg_out_data(struct wd_rsa_kg_out *ko, char **data)
{
	if (!ko || !data) {
		WD_ERR("invalid: param is NULL!\n");
		return -WD_EINVAL;
	}

	*data = (char *)ko->data;

	return ko->size;
}

/* Create a RSA key generate operation input with parameter e, p and q */
struct wd_rsa_kg_in *wd_rsa_new_kg_in(handle_t sess, struct wd_dtb *e,
				struct wd_dtb *p, struct wd_dtb *q)
{
	struct wd_rsa_kg_in *kg_in;
	struct wd_rsa_sess *c = (struct wd_rsa_sess *)sess;
	int kg_in_size;

	if (!c || !e || !p || !q) {
		WD_ERR("invalid: sess malloc kg_in memory params err!\n");
		return NULL;
	}

	if (!c->key_size || c->key_size > RSA_MAX_KEY_SIZE) {
		WD_ERR("invalid: key size err at create kg in!\n");
		return NULL;
	}

	if (!e->dsize || e->dsize > c->key_size) {
		WD_ERR("invalid: e para err at create kg in!\n");
		return NULL;
	}
	if (!p->dsize || p->dsize > CRT_PARAM_SZ(c->key_size)) {
		WD_ERR("invalid: p para err at create kg in!\n");
		return NULL;
	}
	if (!q->dsize || q->dsize > CRT_PARAM_SZ(c->key_size)) {
		WD_ERR("invalid: q para err at create kg in!\n");
		return NULL;
	}

	kg_in_size = GEN_PARAMS_SZ(c->key_size);
	kg_in = malloc(kg_in_size + sizeof(*kg_in));
	if (!kg_in) {
		WD_ERR("failed to malloc kg_in memory!\n");
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
		WD_ERR("invalid: para err at get input parameters key generate!\n");
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

static void del_kg(void *k)
{
	if (!k) {
		WD_ERR("invalid: del key generate params err!\n");
		return;
	}

	free(k);
}

void wd_rsa_del_kg_in(handle_t sess, struct wd_rsa_kg_in *ki)
{
	del_kg(ki);
}

struct wd_rsa_kg_out *wd_rsa_new_kg_out(handle_t sess)
{
	struct wd_rsa_sess *c = (struct wd_rsa_sess *)sess;
	struct wd_rsa_kg_out *kg_out;
	int kg_out_size;
	__u32 kz;

	if (!c) {
		WD_ERR("invalid: sess null at new rsa key gen out!\n");
		return NULL;
	}

	kz = c->key_size;
	if (!kz || kz > RSA_MAX_KEY_SIZE) {
		WD_ERR("invalid: new kg out key size error!\n");
		return NULL;
	}

	if (c->setup.is_crt)
		kg_out_size = CRT_GEN_PARAMS_SZ(c->key_size);
	else
		kg_out_size = GEN_PARAMS_SZ(c->key_size);

	kg_out = malloc(kg_out_size + sizeof(*kg_out));
	if (!kg_out) {
		WD_ERR("failed to malloc kg_out memory!\n");
		return NULL;
	}

	memset(kg_out, 0, kg_out_size + sizeof(*kg_out));
	kg_out->key_size = kz;
	kg_out->d = (void *)kg_out->data;
	kg_out->n = kg_out->d + kz;
	kg_out->size = kg_out_size;
	if (c->setup.is_crt) {
		kg_out->qinv = (void *)kg_out->n + kz;
		kg_out->dq = kg_out->qinv + CRT_PARAM_SZ(kz);
		kg_out->dp = kg_out->dq + CRT_PARAM_SZ(kz);
	}

	return kg_out;
}

void wd_rsa_del_kg_out(handle_t sess, struct wd_rsa_kg_out *kout)
{
	if (!kout) {
		WD_ERR("invalid: param null at del kg out!\n");
		return;
	}

	wd_memset_zero(kout->data, kout->size);
	del_kg(kout);
}

void wd_rsa_get_kg_out_params(struct wd_rsa_kg_out *kout, struct wd_dtb *d,
					struct wd_dtb *n)
{
	if (!kout) {
		WD_ERR("invalid: input null at get key gen params!\n");
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
		WD_ERR("invalid: input null at get key gen crt para!\n");
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

static void init_pkey2(struct wd_rsa_prikey2 *pkey2, __u32 ksz)
{
	__u32 hlf_ksz = CRT_PARAM_SZ(ksz);

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
			WD_ERR("failed to alloc sess prikey2!\n");
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
			WD_ERR("failed to alloc sess prikey1!\n");
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
		WD_ERR("failed to alloc sess pubkey!\n");
		return -WD_ENOMEM;
	}

	memset(sess->pubkey, 0, len);
	init_pubkey(sess->pubkey, sess->key_size);

	return WD_SUCCESS;
}

static void del_sess_key(struct wd_rsa_sess *sess)
{
	struct wd_rsa_prikey *prk = sess->prikey;
	struct wd_rsa_pubkey *pub = sess->pubkey;

	if (!prk || !pub) {
		WD_ERR("invalid: del sess key error, prk or pub NULL!\n");
		return;
	}

	if (sess->setup.is_crt)
		wd_memset_zero(prk->pkey2.data, CRT_PARAMS_SZ(sess->key_size));
	else
		wd_memset_zero(prk->pkey1.data, GEN_PARAMS_SZ(sess->key_size));
	free(sess->prikey);
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
		WD_ERR("invalid: alloc rsa sess setup NULL!\n");
		return(handle_t)0;
	}

	if (setup->key_bits != 1024 &&
		setup->key_bits != 2048 &&
		setup->key_bits != 3072 &&
		setup->key_bits != 4096) {
		WD_ERR("invalid: alloc rsa sess key_bit %u err!\n", setup->key_bits);
		return (handle_t)0;
	}

	sess = calloc(1, sizeof(struct wd_rsa_sess));
	if (!sess)
		return (handle_t)sess;

	memcpy(&sess->setup, setup, sizeof(*setup));
	sess->key_size = setup->key_bits >> BYTE_BITS_SHIFT;

	ret = create_sess_key(setup, sess);
	if (ret) {
		WD_ERR("failed to create rsa sess keys!\n");
		goto sess_err;
	}

	/* Some simple scheduler don't need scheduling parameters */
	sess->sched_key = (void *)wd_rsa_setting.sched.sched_init(
		     wd_rsa_setting.sched.h_sched_ctx, setup->sched_param);
	if (WD_IS_ERR(sess->sched_key)) {
		WD_ERR("failed to init session schedule key!\n");
		goto sched_err;
	}

	return (handle_t)sess;

sched_err:
	del_sess_key(sess);
sess_err:
	free(sess);
	return (handle_t)0;
}

void wd_rsa_free_sess(handle_t sess)
{
	struct wd_rsa_sess *sess_t = (struct wd_rsa_sess *)sess;

	if (!sess_t) {
		WD_ERR("invalid: free rsa sess param err!\n");
		return;
	}

	if (sess_t->sched_key)
		free(sess_t->sched_key);
	del_sess_key(sess_t);
	del_sess(sess_t);
}


bool wd_rsa_is_crt(handle_t sess)
{
	if (!sess) {
		WD_ERR("invalid: rsa is crt judge, sess NULL, return false!\n");
		return false;
	}

	return ((struct wd_rsa_sess *)sess)->setup.is_crt;
}

__u32 wd_rsa_get_key_bits(handle_t sess)
{
	if (!sess) {
		WD_ERR("invalid: get rsa key bits, sess NULL!\n");
		return 0;
	}

	return ((struct wd_rsa_sess *)sess)->setup.key_bits;
}

int wd_rsa_set_pubkey_params(handle_t sess, struct wd_dtb *e, struct wd_dtb *n)
{
	struct wd_rsa_sess *c = (struct wd_rsa_sess *)sess;

	if (!c || !c->pubkey || !c->pubkey->key_size) {
		WD_ERR("invalid: sess NULL in set rsa public key!\n");
		return -WD_EINVAL;
	}

	if (e) {
		if (!e->dsize || !e->data || e->dsize > c->pubkey->key_size) {
			WD_ERR("invalid: e err in set rsa public key!\n");
			return -WD_EINVAL;
		}

		c->pubkey->e.dsize = e->dsize;
		memset(c->pubkey->e.data, 0, c->pubkey->e.bsize);
		memcpy(c->pubkey->e.data, e->data, e->dsize);
	}

	if (n) {
		if (!n->dsize || !n->data || n->dsize > c->pubkey->key_size) {
			WD_ERR("invalid: n err in set rsa public key!\n");
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
		WD_ERR("invalid: input NULL in get rsa public key!\n");
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
	struct wd_rsa_sess *c = (struct wd_rsa_sess *)sess;

	if (!c || wd_rsa_is_crt(sess) || !c->prikey) {
		WD_ERR("invalid: sess err in set rsa private key1!\n");
		return -WD_EINVAL;
	}
	pkey1 = &c->prikey->pkey1;
	if (d) {
		if (!d->dsize || !d->data || d->dsize > pkey1->key_size) {
			WD_ERR("invalid: d err in set rsa private key1!\n");
			return -WD_EINVAL;
		}

		pkey1->d.dsize = d->dsize;
		memset(pkey1->d.data, 0, pkey1->d.bsize);
		memcpy(pkey1->d.data, d->data, d->dsize);
	}
	if (n) {
		if (!n->dsize || !n->data || n->dsize > pkey1->key_size) {
			WD_ERR("invalid: en err in set rsa private key1!\n");
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
		WD_ERR("invalid: pvk is NULL!\n");
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
	int ret = -WD_EINVAL;

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
	}

	return ret;
}

int wd_rsa_set_crt_prikey_params(handle_t sess, struct wd_dtb *dq,
			struct wd_dtb *dp, struct wd_dtb *qinv,
			struct wd_dtb *q, struct wd_dtb *p)
{
	struct wd_rsa_sess *c = (struct wd_rsa_sess *)sess;
	struct wd_rsa_prikey2 *pkey2;
	int ret = -WD_EINVAL;

	if (!sess || !wd_rsa_is_crt(sess)) {
		WD_ERR("invalid: sess err in set rsa crt private key2!\n");
		return ret;
	}

	if (!dq || !dp || !qinv || !q || !p) {
		WD_ERR("invalid: para err in set rsa crt private key2!\n");
		return ret;
	}

	pkey2 = &c->prikey->pkey2;
	ret = rsa_prikey2_param_set(pkey2, dq, WD_CRT_PRIKEY_DQ);
	if (ret) {
		WD_ERR("failed to set dq for rsa private key2!\n");
		return ret;
	}

	ret = rsa_prikey2_param_set(pkey2, dp, WD_CRT_PRIKEY_DP);
	if (ret) {
		WD_ERR("failed to set dp for rsa private key2!\n");
		return ret;
	}

	ret = rsa_prikey2_param_set(pkey2, qinv, WD_CRT_PRIKEY_QINV);
	if (ret) {
		WD_ERR("failed to set qinv for rsa private key2!\n");
		return ret;
	}

	ret = rsa_prikey2_param_set(pkey2, q, WD_CRT_PRIKEY_Q);
	if (ret) {
		WD_ERR("failed to set q for rsa private key2!\n");
		return ret;
	}

	ret = rsa_prikey2_param_set(pkey2, p, WD_CRT_PRIKEY_P);
	if (ret) {
		WD_ERR("failed to set p for rsa private key2!\n");
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
		WD_ERR("invalid: pvk is NULL!\n");
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
		WD_ERR("invalid: param is NULL!\n");
		return;
	}

	*pubkey = ((struct wd_rsa_sess *)sess)->pubkey;
}

void wd_rsa_get_prikey(handle_t sess, struct wd_rsa_prikey **prikey)
{
	if (!sess || !prikey) {
		WD_ERR("invalid: param is NULL!\n");
		return;
	}

	*prikey = ((struct wd_rsa_sess *)sess)->prikey;
}

static const struct wd_config_variable table[] = {
	{ .name = "WD_RSA_CTX_NUM",
	  .def_val = "sync:2@0,async:2@0",
	  .parse_fn = wd_parse_ctx_num
	},
	{ .name = "WD_RSA_ASYNC_POLL_EN",
	  .def_val = "0",
	  .parse_fn = wd_parse_async_poll_en
	}
};

static const struct wd_alg_ops wd_rsa_ops = {
	.alg_name = "rsa",
	.op_type_num = 1,
	.alg_init = wd_rsa_init,
	.alg_uninit = wd_rsa_uninit,
	.alg_poll_ctx = wd_rsa_poll_ctx
};

int wd_rsa_env_init(struct wd_sched *sched)
{
	wd_rsa_env_config.sched = sched;

	return wd_alg_env_init(&wd_rsa_env_config, table,
			       &wd_rsa_ops, ARRAY_SIZE(table), NULL);
}

void wd_rsa_env_uninit(void)
{
	return wd_alg_env_uninit(&wd_rsa_env_config, &wd_rsa_ops);
}

int wd_rsa_ctx_num_init(__u32 node, __u32 type, __u32 num, __u8 mode)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, num);
	if (ret)
		return ret;

	return wd_alg_env_init(&wd_rsa_env_config, table,
			       &wd_rsa_ops, ARRAY_SIZE(table), &ctx_attr);
}

void wd_rsa_ctx_num_uninit(void)
{
	return wd_alg_env_uninit(&wd_rsa_env_config, &wd_rsa_ops);
}

int wd_rsa_get_env_param(__u32 node, __u32 type, __u32 mode,
			 __u32 *num, __u8 *is_enable)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, 0);
	if (ret)
		return ret;

	return wd_alg_get_env_param(&wd_rsa_env_config,
				    ctx_attr, num, is_enable);
}
