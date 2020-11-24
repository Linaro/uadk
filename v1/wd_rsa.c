// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "wd.h"
#include "wd_rsa.h"
#include "wd_util.h"

#define WD_RSA_CTX_MSG_NUM		64
#define WD_RSA_MAX_CTX			256
#define RSA_BALANCE_THRHD	1280
#define RSA_RESEND_CNT	8

static __thread int balance;

struct wcrypto_rsa_cookie {
	struct wcrypto_cb_tag tag;
	struct wcrypto_rsa_msg msg;
};

struct wcrypto_rsa_ctx {
	struct wcrypto_rsa_cookie cookies[WD_RSA_CTX_MSG_NUM];
	__u8 cstatus[WD_RSA_CTX_MSG_NUM];
	int cidx;
	int key_size;
	int ctx_id;
	struct wd_queue *q;
	struct wcrypto_rsa_pubkey *pubkey;
	struct wcrypto_rsa_prikey *prikey;
	struct wcrypto_rsa_ctx_setup setup;
};

struct wcrypto_rsa_kg_in {
	__u8 *e;
	__u8 *p;
	__u8 *q;
	__u32 ebytes;
	__u32 pbytes;
	__u32 qbytes;
	__u32 key_size;
	void *data[];
};

struct wcrypto_rsa_kg_out {
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

struct wcrypto_rsa_pubkey {
	struct wd_dtb n;
	struct wd_dtb e;
	__u32 key_size;
	void *data[];
};

struct wcrypto_rsa_prikey1 {
	struct wd_dtb n;
	struct wd_dtb d;
	__u32 key_size;
	void *data[];
};

/* RSA crt private key */
struct wcrypto_rsa_prikey2 {
	struct wd_dtb p;
	struct wd_dtb q;
	struct wd_dtb dp;
	struct wd_dtb dq;
	struct wd_dtb qinv;
	__u32 key_size;
	void *data[];
};

struct wcrypto_rsa_prikey {
	struct wcrypto_rsa_prikey1 pkey1;
	struct wcrypto_rsa_prikey2 pkey2;
};

/* RSA CRT prikey param types */
enum wcrypto_rsa_crt_prikey_para {
	WD_CRT_PRIKEY_DQ,
	WD_CRT_PRIKEY_DP,
	WD_CRT_PRIKEY_QINV,
	WD_CRT_PRIKEY_Q,
	WD_CRT_PRIKEY_P
};

int wcrypto_rsa_kg_in_data(struct wcrypto_rsa_kg_in *ki, char **data)
{
	if (!ki || !data)
		return -WD_EINVAL;

	*data = (char *)ki->data;
	return (int)GEN_PARAMS_SZ(ki->key_size);
}

int wcrypto_rsa_kg_out_data(struct wcrypto_rsa_kg_out *ko, char **data)
{
	if (!ko || !data)
		return -WD_EINVAL;

	*data = (char *)ko->data;

	/* Todo: CRT need this size, but no CRT size is smaller */
	return (int)CRT_GEN_PARAMS_SZ(ko->key_size);
}

/* Create a RSA key generate operation input with parameter e, p and q */
struct wcrypto_rsa_kg_in *wcrypto_new_kg_in(void *ctx, struct wd_dtb *e,
				struct wd_dtb *p, struct wd_dtb *q)
{
	struct wcrypto_rsa_kg_in *kg_in;
	struct wcrypto_rsa_ctx *c = ctx;
	struct wd_mm_ops *ops;
	int kg_in_size;

	if (!c || !e || !p || !q) {
		WD_ERR("ctx ops->alloc kg_in memory fail!\n");
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
	ops = &c->setup.ops;
	kg_in_size = GEN_PARAMS_SZ(c->key_size);
	kg_in = ops->alloc(ops->usr, kg_in_size + sizeof(*kg_in));
	if (!kg_in) {
		WD_ERR("ctx ops->alloc kg_in memory fail!\n");
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

void wcrypto_get_rsa_kg_in_params(struct wcrypto_rsa_kg_in *kin, struct wd_dtb *e,
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

static void del_kg(void *ctx, void *k)
{
	struct wcrypto_rsa_ctx *c = ctx;
	struct wd_mm_ops  *ops;

	if (!c || !k) {
		WD_ERR("del key generate params err!\n");
		return;
	}

	ops = &c->setup.ops;
	if (ops->free)
		ops->free(ops->usr, k);
}

void wcrypto_del_kg_in(void *ctx, struct wcrypto_rsa_kg_in *ki)
{
	del_kg(ctx, ki);
}

struct wcrypto_rsa_kg_out *wcrypto_new_kg_out(void *ctx)
{
	struct wcrypto_rsa_kg_out *kg_out;
	struct wcrypto_rsa_ctx *c = ctx;
	struct wd_mm_ops *ops;
	int kg_out_size;
	int kz;

	if (!c) {
		WD_ERR("ctx null at new rsa key gen out!\n");
		return NULL;
	}

	kz = c->key_size;
	if (c->setup.is_crt)
		kg_out_size = CRT_GEN_PARAMS_SZ(c->key_size);
	else
		kg_out_size = GEN_PARAMS_SZ(c->key_size);

	ops = &c->setup.ops;
	kg_out = ops->alloc(ops->usr, kg_out_size + sizeof(*kg_out));
	if (!kg_out) {
		WD_ERR("ctx ops->alloc kg_in memory fail!\n");
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

void wcrypto_del_kg_out(void *ctx,  struct wcrypto_rsa_kg_out *kout)
{
	del_kg(ctx, kout);
}

void wcrypto_get_rsa_kg_out_params(struct wcrypto_rsa_kg_out *kout, struct wd_dtb *d,
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

void wcrypto_get_rsa_kg_out_crt_params(struct wcrypto_rsa_kg_out *kout,
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

static struct wcrypto_rsa_cookie *get_rsa_cookie(struct wcrypto_rsa_ctx *ctx)
{
	int idx = ctx->cidx;
	int cnt = 0;

	while (__atomic_test_and_set(&ctx->cstatus[idx], __ATOMIC_ACQUIRE)) {
		idx++;
		cnt++;
		if (idx == WD_RSA_CTX_MSG_NUM)
			idx = 0;
		if (cnt == WD_RSA_CTX_MSG_NUM)
			return NULL;
	}

	ctx->cidx = idx;
	return &ctx->cookies[idx];
}

static void put_rsa_cookie(struct wcrypto_rsa_ctx *ctx, struct wcrypto_rsa_cookie *cookie)
{
	int idx = ((uintptr_t)cookie - (uintptr_t)ctx->cookies) /
		sizeof(struct wcrypto_rsa_cookie);

	if (idx < 0 || idx >= WD_RSA_CTX_MSG_NUM) {
		WD_ERR("rsa cookie not exist!\n");
		return;
	}
	__atomic_clear(&ctx->cstatus[idx], __ATOMIC_RELEASE);
}

static void init_pkey2(struct wcrypto_rsa_prikey2 *pkey2, int ksz)
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

static void init_pkey1(struct wcrypto_rsa_prikey1 *pkey1, int ksz)
{
	pkey1->d.data = (char *)pkey1->data;
	pkey1->n.data = pkey1->d.data + ksz;
	pkey1->d.bsize = ksz;
	pkey1->n.bsize = ksz;
	pkey1->key_size = ksz;
}

static void init_pubkey(struct wcrypto_rsa_pubkey *pubkey, int ksz)
{
	pubkey->e.data = (char *)pubkey->data;
	pubkey->n.data = pubkey->e.data + ksz;
	pubkey->e.bsize = ksz;
	pubkey->n.bsize = ksz;
	pubkey->key_size = ksz;
}

static int create_ctx_key(struct wcrypto_rsa_ctx_setup *setup,
			struct wcrypto_rsa_ctx *ctx)
{
	struct wd_mm_ops *ops = &setup->ops;
	struct wcrypto_rsa_prikey2 *pkey2;
	struct wcrypto_rsa_prikey1 *pkey1;
	int len;

	if (setup->is_crt) {
		len = sizeof(struct wcrypto_rsa_prikey) +
			CRT_PARAMS_SZ(ctx->key_size);
		ctx->prikey = ops->alloc(ops->usr, len);
		if (!ctx->prikey) {
			WD_ERR("alloc prikey2 fail!\n");
			return -WD_ENOMEM;
		}
		pkey2 = &ctx->prikey->pkey2;
		memset(ctx->prikey, 0, len);
		init_pkey2(pkey2, ctx->key_size);

	} else {
		len = sizeof(struct wcrypto_rsa_prikey) +
			GEN_PARAMS_SZ(ctx->key_size);
		ctx->prikey = ops->alloc(ops->usr, len);
		if (!ctx->prikey) {
			WD_ERR("alloc prikey1 fail!\n");
			return -WD_ENOMEM;
		}
		pkey1 = &ctx->prikey->pkey1;
		memset(ctx->prikey, 0, len);
		init_pkey1(pkey1, ctx->key_size);
	}

	len = sizeof(struct wcrypto_rsa_pubkey) +
		GEN_PARAMS_SZ(ctx->key_size);
	ctx->pubkey = ops->alloc(ops->usr, len);
	if (!ctx->pubkey) {
		ops->free(ops->usr, ctx->prikey);
		WD_ERR("alloc pubkey fail!\n");
		return -WD_ENOMEM;
	}

	memset(ctx->pubkey, 0, len);
	init_pubkey(ctx->pubkey, ctx->key_size);

	return WD_SUCCESS;
}

static void del_ctx_key(struct wcrypto_rsa_ctx_setup *setup,
			struct wcrypto_rsa_ctx *ctx)
{
	struct wd_mm_ops *ops = &setup->ops;

	if (ops && ops->free) {
		if (ctx->prikey)
			ops->free(ops->usr, ctx->prikey);
		if (ctx->pubkey)
			ops->free(ops->usr, ctx->pubkey);
	}
}

struct wcrypto_rsa_ctx *create_ctx(struct wcrypto_rsa_ctx_setup *setup, int ctx_id)
{
	struct wcrypto_rsa_ctx *ctx;
	int i;

	ctx = calloc(1, sizeof(struct wcrypto_rsa_ctx));
	if (!ctx)
		return ctx;

	memcpy(&ctx->setup, setup, sizeof(*setup));
	ctx->ctx_id = ctx_id;
	ctx->key_size = setup->key_bits >> BYTE_BITS_SHIFT;
	for (i = 0; i < WD_RSA_CTX_MSG_NUM; i++) {
		if (setup->is_crt)
			ctx->cookies[i].msg.key_type = WCRYPTO_RSA_PRIKEY2;
		else
			ctx->cookies[i].msg.key_type = WCRYPTO_RSA_PRIKEY1;
		ctx->cookies[i].msg.data_fmt = setup->data_fmt;
		ctx->cookies[i].msg.key_bytes = ctx->key_size;
		ctx->cookies[i].msg.alg_type = WD_RSA;
		ctx->cookies[i].tag.ctx = ctx;
		ctx->cookies[i].tag.ctx_id = ctx_id;
		ctx->cookies[i].msg.usr_data = (__u64)&ctx->cookies[i].tag;
	}

	return ctx;
}

static void del_ctx(struct wcrypto_rsa_ctx *c)
{
	if (c)
		free(c);
}

/* Before initiate this context, we should get a queue from WD */
void *wcrypto_create_rsa_ctx(struct wd_queue *q, struct wcrypto_rsa_ctx_setup *setup)
{
	struct wcrypto_rsa_ctx *ctx;
	struct q_info *qinfo;
	int ret, cid;

	if (!q || !setup) {
		WD_ERR("create rsa ctx input param err!\n");
		return NULL;
	}
	qinfo = q->info;
	if (!setup->ops.alloc || !setup->ops.free) {
		WD_ERR("create rsa ctx user mm ops err!\n");
		return NULL;
	}
	if (strncmp(q->capa.alg, "rsa", strlen("rsa"))) {
		WD_ERR("create rsa ctx algorithm mismatching!\n");
		return NULL;
	}

	/*lock at ctx  creating/deleting */
	wd_spinlock(&qinfo->qlock);
	if (!qinfo->ops.alloc && !qinfo->ops.dma_map)
		memcpy(&qinfo->ops, &setup->ops, sizeof(setup->ops));
	if (qinfo->ops.usr != setup->ops.usr) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("Err mm ops in creating rsa ctx!\n");
		return NULL;
	}
	qinfo->ctx_num++;
	cid = qinfo->ctx_num;
	wd_unspinlock(&qinfo->qlock);
	if (cid > WD_RSA_MAX_CTX) {
		WD_ERR("err:create too many rsa ctx!\n");
		return NULL;
	}
	ctx = create_ctx(setup, cid);
	if (!ctx) {
		WD_ERR("create rsa ctx fail!\n");
		return ctx;
	}
	ctx->q = q;
	ret = create_ctx_key(setup, ctx);
	if (ret) {
		WD_ERR("fail creating rsa ctx keys!\n");
		del_ctx(ctx);
		return NULL;
	}

	return ctx;
}

bool wcrypto_rsa_is_crt(void *ctx)
{
	if (ctx)
		return ((struct wcrypto_rsa_ctx *)ctx)->setup.is_crt;
	else
		return WD_SUCCESS;
}

int wcrypto_rsa_key_bits(void *ctx)
{
	if (ctx)
		return ((struct wcrypto_rsa_ctx *)ctx)->setup.key_bits;
	else
		return WD_SUCCESS;
}

int wcrypto_set_rsa_pubkey_params(void *ctx, struct wd_dtb *e, struct wd_dtb *n)
{
	struct wcrypto_rsa_ctx *c = ctx;

	if (!ctx) {
		WD_ERR("ctx NULL in set rsa public key!\n");
		return -WD_EINVAL;
	}
	if (e) {
		if (e->dsize > c->pubkey->key_size || e->data) {
			WD_ERR("e err in set rsa public key!\n");
			return -WD_EINVAL;
		}

		c->pubkey->e.dsize = e->dsize;
		memset(c->pubkey->e.data, 0, c->pubkey->e.bsize);
		memcpy(c->pubkey->e.data, e->data, e->dsize);
	}
	if (n) {
		if (n->dsize > c->pubkey->key_size || n->data) {
			WD_ERR("n err in set rsa public key!\n");
			return -WD_EINVAL;
		}

		c->pubkey->n.dsize = n->dsize;
		memset(c->pubkey->n.data, 0, c->pubkey->n.bsize);
		memcpy(c->pubkey->n.data, n->data, n->dsize);

	}
	return WD_SUCCESS;
}

void wcrypto_get_rsa_pubkey_params(struct wcrypto_rsa_pubkey *pbk, struct wd_dtb **e,
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

int wcrypto_set_rsa_prikey_params(void *ctx, struct wd_dtb *d, struct wd_dtb *n)
{
	struct wcrypto_rsa_prikey1 *pkey1;
	struct wcrypto_rsa_ctx *c = ctx;

	if (!ctx  || wcrypto_rsa_is_crt(ctx)) {
		WD_ERR("ctx err in set rsa private key1!\n");
		return -WD_EINVAL;
	}
	pkey1 = &c->prikey->pkey1;
	if (d) {
		if (d->dsize > pkey1->key_size || d->data) {
			WD_ERR("d err in set rsa private key1!\n");
			return -WD_EINVAL;
		}

		pkey1->d.dsize = d->dsize;
		memset(pkey1->d.data, 0, pkey1->d.bsize);
		memcpy(pkey1->d.data, d->data, d->dsize);
	}
	if (n) {
		if (n->dsize > pkey1->key_size || n->data) {
			WD_ERR("en err in set rsa private key1!\n");
			return -WD_EINVAL;
		}

		pkey1->n.dsize = n->dsize;
		memset(pkey1->n.data, 0, pkey1->n.bsize);
		memcpy(pkey1->n.data, n->data, n->dsize);
	}
	return WD_SUCCESS;
}

void wcrypto_get_rsa_prikey_params(struct wcrypto_rsa_prikey *pvk, struct wd_dtb **d,
					struct wd_dtb **n)
{
	struct wcrypto_rsa_prikey1 *pkey1;

	if (pvk) {
		pkey1 = &pvk->pkey1;
		if (d)
			*d = &pkey1->d;
		if (n)
			*n = &pkey1->n;
	}
}

static int rsa_prikey2_param_set(struct wcrypto_rsa_prikey2 *pkey2,
				struct wd_dtb *param,
				enum wcrypto_rsa_crt_prikey_para type)
{
	int ret = WD_SUCCESS;

	if (param->dsize > pkey2->key_size || !param->data)
		return -WD_EINVAL;

	switch (type) {
	case WD_CRT_PRIKEY_DQ:
		if (param->dsize <= pkey2->dq.bsize) {
			pkey2->dq.dsize = param->dsize;
			memset(pkey2->dq.data, 0, pkey2->dq.bsize);
			memcpy(pkey2->dq.data, param->data, param->dsize);
		} else {
			ret = -WD_EINVAL;
		}
		break;

	case WD_CRT_PRIKEY_DP:
		if (param->dsize <= pkey2->dp.bsize) {
			pkey2->dp.dsize = param->dsize;
			memset(pkey2->dp.data, 0, pkey2->dp.bsize);
			memcpy(pkey2->dp.data, param->data, param->dsize);
		} else {
			ret = -WD_EINVAL;
		}
		break;

	case WD_CRT_PRIKEY_QINV:
		if (param->dsize <= pkey2->qinv.bsize) {
			pkey2->qinv.dsize = param->dsize;
			memset(pkey2->qinv.data, 0, pkey2->qinv.bsize);
			memcpy(pkey2->qinv.data, param->data, param->dsize);
		} else {
			ret = -WD_EINVAL;
		}
		break;

	case WD_CRT_PRIKEY_P:
		if (param->dsize <= pkey2->p.bsize) {
			pkey2->p.dsize = param->dsize;
			memset(pkey2->p.data, 0, pkey2->p.bsize);
			memcpy(pkey2->p.data, param->data, param->dsize);
		} else {
			ret = -WD_EINVAL;
		}
		break;

	case WD_CRT_PRIKEY_Q:
		if (param->dsize <= pkey2->q.bsize) {
			pkey2->q.dsize = param->dsize;
			memset(pkey2->q.data, 0, pkey2->q.bsize);
			memcpy(pkey2->q.data, param->data, param->dsize);
		} else {
			ret = -WD_EINVAL;
		}
		break;

	default:
		WD_ERR("%s: err type %d!\n", __func__, type);
		ret = -WD_EINVAL;
		break;
	}

	return ret;
}

int wcrypto_set_rsa_crt_prikey_params(void *ctx, struct wd_dtb *dq,
			struct wd_dtb *dp, struct wd_dtb *qinv,
			struct wd_dtb *q, struct wd_dtb *p)
{
	struct wcrypto_rsa_prikey2 *pkey2;
	struct wcrypto_rsa_ctx *c = ctx;
	int ret = -WD_EINVAL;

	if (!ctx || !wcrypto_rsa_is_crt(ctx)) {
		WD_ERR("ctx err in set rsa crt private key2!\n");
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

void wcrypto_get_rsa_crt_prikey_params(struct wcrypto_rsa_prikey *pvk,
		struct wd_dtb **dq,
		struct wd_dtb **dp, struct wd_dtb **qinv,
		struct wd_dtb **q, struct wd_dtb **p)
{
	struct wcrypto_rsa_prikey2 *pkey2;

	if (pvk) {
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
}

void wcrypto_get_rsa_pubkey(void *ctx, struct wcrypto_rsa_pubkey **pubkey)
{
	if (ctx && pubkey)
		*pubkey = ((struct wcrypto_rsa_ctx *)ctx)->pubkey;
}

void wcrypto_get_rsa_prikey(void *ctx, struct wcrypto_rsa_prikey **prikey)
{
	if (ctx && prikey)
		*prikey = ((struct wcrypto_rsa_ctx *)ctx)->prikey;
}

static int rsa_request_init(struct wcrypto_rsa_msg *req, struct wcrypto_rsa_op_data *op,
				struct wcrypto_rsa_ctx *c)
{
	__u8 *key = NULL;

	req->in = op->in;
	req->in_bytes = (__u16)op->in_bytes;
	req->out = op->out;
	req->op_type = op->op_type;
	req->result = WD_EINVAL;

	switch (req->op_type) {
	case WCRYPTO_RSA_SIGN:
		key = (__u8 *)c->prikey;
		break;
	case WCRYPTO_RSA_VERIFY:
		key = (__u8 *)c->pubkey;
		break;
	case WCRYPTO_RSA_GENKEY:
		key = (__u8 *)op->in;
		break;
	default:
		WD_ERR("rsa request op type err!\n");
		return -WD_EINVAL;
	}

	if (!key) {
		WD_ERR("rsa request key null!\n");
		return -WD_EINVAL;
	}

	req->key = key;

	return WD_SUCCESS;
}

int wcrypto_do_rsa(void *ctx, struct wcrypto_rsa_op_data *opdata, void *tag)
{
	struct wcrypto_rsa_msg *resp = NULL;
	struct wcrypto_rsa_ctx *ctxt = ctx;
	struct wcrypto_rsa_cookie *cookie;
	int ret = -WD_EINVAL;
	struct wcrypto_rsa_msg *req;
	uint32_t rx_cnt = 0;
	uint32_t tx_cnt = 0;

	cookie = get_rsa_cookie(ctxt);
	if (!cookie)
		return -WD_EBUSY;

	if (tag) {
		if (!ctxt->setup.cb) {
			WD_ERR("ctx call back is null!\n");
			goto fail_with_cookie;
		}
		cookie->tag.tag = tag;
	}

	req = &cookie->msg;
	ret = rsa_request_init(req, opdata, ctxt);
	if (ret)
		goto fail_with_cookie;

send_again:
	ret = wd_send(ctxt->q, req);
	if (ret == -WD_EBUSY) {
		tx_cnt++;
		usleep(1);
		if (tx_cnt < RSA_RESEND_CNT)
			goto send_again;
		else {
			WD_ERR("do rsa send cnt %u, exit!\n", tx_cnt);
			goto fail_with_cookie;
		}
	} else if (ret) {
		WD_ERR("do rsa wd_send err!\n");
		goto fail_with_cookie;
	}

	if (tag)
		return ret;

	resp = (void *)(uintptr_t)ctxt->ctx_id;
recv_again:
	ret = wd_recv(ctxt->q, (void **)&resp);
	if (!ret) {
		rx_cnt++;
		if (balance > RSA_BALANCE_THRHD)
			usleep(1);
		goto recv_again;
	} else if (ret < 0) {
		WD_ERR("do rsa wd_recv err!\n");
		goto fail_with_cookie;
	}

	balance = rx_cnt;
	opdata->out = (void *)resp->out;
	opdata->out_bytes = resp->out_bytes;
	opdata->status = resp->result;
	ret = GET_NEGATIVE(opdata->status);

fail_with_cookie:
	put_rsa_cookie(ctxt, cookie);
	return ret;
}

int wcrypto_rsa_poll(struct wd_queue *q, unsigned int num)
{
	struct wcrypto_rsa_msg *resp = NULL;
	struct wcrypto_rsa_ctx *ctx;
	struct wcrypto_cb_tag *tag;
	int count = 0;
	int ret;

	do {
		ret = wd_recv(q, (void **)&resp);
		if (ret == 0)
			break;
		else if (ret < 0) {
			WD_ERR("recv err at rsa poll!\n");
			return ret;
		}
		count++;
		tag = (void *)resp->usr_data;
		ctx = tag->ctx;
		ctx->setup.cb(resp, tag->tag);
		put_rsa_cookie(ctx, (struct wcrypto_rsa_cookie *)tag);
		resp = NULL;
	} while (--num);

	return count;
}

void wcrypto_del_rsa_ctx(void *ctx)
{
	struct wcrypto_rsa_ctx_setup *st;
	struct wcrypto_rsa_ctx *cx;
	struct q_info *qinfo;

	if (!ctx) {
		WD_ERR("Delete rsa ctx is NULL!\n");
		return;
	}
	cx = ctx;
	st = &cx->setup;
	qinfo = cx->q->info;
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	if (!qinfo->ctx_num) {
		memset(&qinfo->ops, 0, sizeof(qinfo->ops));
	} else if (qinfo->ctx_num < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("error:repeat del rsa ctx!\n");
		return;
	}

	wd_unspinlock(&qinfo->qlock);
	del_ctx_key(st, cx);
	del_ctx(cx);
}
