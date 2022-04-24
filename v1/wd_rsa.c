/*
 * Copyright 2019 Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/mman.h>

#include "wd.h"
#include "wd_util.h"
#include "wd_rsa.h"

#define RSA_BALANCE_THRHD	1280
#define RSA_RESEND_CNT	8
#define RSA_MAX_KEY_SIZE	512
#define RSA_RECV_MAX_CNT	60000000 // 1 min


static __thread int balance;

struct wcrypto_rsa_cookie {
	struct wcrypto_cb_tag tag;
	struct wcrypto_rsa_msg msg;
};

struct wcrypto_rsa_ctx {
	struct wd_cookie_pool pool;
	__u32 key_size;
	unsigned long ctx_id;
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
	__u32 size;
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

/* RSA CRT private key parameter types */
enum wcrypto_rsa_crt_prikey_para {
	WD_CRT_PRIKEY_DQ,
	WD_CRT_PRIKEY_DP,
	WD_CRT_PRIKEY_QINV,
	WD_CRT_PRIKEY_Q,
	WD_CRT_PRIKEY_P
};

int wcrypto_rsa_kg_in_data(struct wcrypto_rsa_kg_in *ki, char **data)
{
	if (!ki || !data) {
		WD_ERR("parameter is NULL!\n");
		return -WD_EINVAL;
	}

	*data = (char *)ki->data;
	return (int)GEN_PARAMS_SZ(ki->key_size);
}

int wcrypto_rsa_kg_out_data(struct wcrypto_rsa_kg_out *ko, char **data)
{
	if (!ko || !data) {
		WD_ERR("parameter is NULL!\n");
		return -WD_EINVAL;
	}

	*data = (char *)ko->data;

	return (int)ko->size;
}

static int kg_in_param_check(void *ctx, struct wd_dtb *e,
			     struct wd_dtb *p, struct wd_dtb *q)
{
	struct wcrypto_rsa_kg_in *kg_in;
	struct wcrypto_rsa_ctx *c = ctx;
	struct wd_mm_br *br;
	int kg_in_size;

	if (unlikely(!c || !e || !p || !q)) {
		WD_ERR("ctx br->alloc kg_in memory fail!\n");
		return -WD_EINVAL;
	}

	if (unlikely(!c->key_size || c->key_size > RSA_MAX_KEY_SIZE)) {
		WD_ERR("key size err at create kg in!\n");
		return -WD_EINVAL;
	}

	if (unlikely(e->dsize > c->key_size)) {
		WD_ERR("e para err at create kg in!\n");
		return -WD_EINVAL;
	}
	if (unlikely(p->dsize > CRT_PARAM_SZ(c->key_size))) {
		WD_ERR("p para err at create kg in!\n");
		return -WD_EINVAL;
	}
	if (unlikely(q->dsize > CRT_PARAM_SZ(c->key_size))) {
		WD_ERR("q para err at create kg in!\n");
		return -WD_EINVAL;
	}

	br = &c->setup.br;
	if (unlikely(!br->alloc)) {
		WD_ERR("new kg in user mm br err!\n");
		return -WD_EINVAL;
	}

	kg_in_size = GEN_PARAMS_SZ(c->key_size);
	if (unlikely(br->get_bufsize &&
	    br->get_bufsize(br->usr) < (kg_in_size + sizeof(*kg_in)))) {
		WD_ERR("Blk_size < need_size<0x%lx>.\n", (kg_in_size + sizeof(*kg_in)));
		return -WD_EINVAL;
	}

	return 0;
}

/* Create a RSA key generate operation input with parameter e, p and q */
struct wcrypto_rsa_kg_in *wcrypto_new_kg_in(void *ctx, struct wd_dtb *e,
				struct wd_dtb *p, struct wd_dtb *q)
{
	struct wcrypto_rsa_kg_in *kg_in;
	struct wcrypto_rsa_ctx *c = ctx;
	struct wd_mm_br *br;
	int kg_in_size, ret;

	ret = kg_in_param_check(ctx, e, p, q);
	if (unlikely(ret))
		return NULL;

	br = &c->setup.br;
	kg_in_size = GEN_PARAMS_SZ(c->key_size);
	kg_in = br->alloc(br->usr, kg_in_size + sizeof(*kg_in));
	if (unlikely(!kg_in)) {
		WD_ERR("ctx br->alloc kg_in memory fail!\n");
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
	struct wd_mm_br  *br;

	if (!c || !k) {
		WD_ERR("delete key generate parameters err!\n");
		return;
	}

	br = &c->setup.br;
	if (br->free)
		br->free(br->usr, k);
}

void wcrypto_del_kg_in(void *ctx, struct wcrypto_rsa_kg_in *ki)
{
	del_kg(ctx, ki);
}

struct wcrypto_rsa_kg_out *wcrypto_new_kg_out(void *ctx)
{
	struct wcrypto_rsa_kg_out *kg_out;
	struct wcrypto_rsa_ctx *c = ctx;
	struct wd_mm_br *br;
	int kg_out_size;
	__u32 kz;

	if (unlikely(!c)) {
		WD_ERR("ctx null at new rsa key gen out!\n");
		return NULL;
	}

	kz = c->key_size;
	if (unlikely(!kz || kz > RSA_MAX_KEY_SIZE)) {
		WD_ERR("new kg out key size error!\n");
		return NULL;
	}

	if (c->setup.is_crt)
		kg_out_size = CRT_GEN_PARAMS_SZ(c->key_size);
	else
		kg_out_size = GEN_PARAMS_SZ(c->key_size);

	br = &c->setup.br;
	if (unlikely(!br->alloc)) {
		WD_ERR("new kg out user mm br err!\n");
		return NULL;
	}
	if (unlikely(br->get_bufsize &&
	    br->get_bufsize(br->usr) < kg_out_size + sizeof(*kg_out))) {
		WD_ERR("blk_size < need_size<0x%lx>.\n", kg_out_size + sizeof(*kg_out));
		return NULL;
	}
	kg_out = br->alloc(br->usr, kg_out_size + sizeof(*kg_out));
	if (unlikely(!kg_out)) {
		WD_ERR("ctx br->alloc kg_in memory fail!\n");
		return NULL;
	}

	memset(kg_out, 0, kg_out_size + sizeof(*kg_out));
	kg_out->key_size = kz;
	kg_out->d = (void *)kg_out->data;
	kg_out->n = kg_out->d + kz;
	kg_out->size = (__u32)kg_out_size;
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
		WD_ERR("input null at get key gen parameters!\n");
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

void wcrypto_set_rsa_kg_out_crt_psz(struct wcrypto_rsa_kg_out *kout,
				    size_t qinv_sz,
				    size_t dq_sz,
				    size_t dp_sz)
{
	kout->qinvbytes = qinv_sz;
	kout->dqbytes = dq_sz;
	kout->dpbytes = dp_sz;
}

void wcrypto_set_rsa_kg_out_psz(struct wcrypto_rsa_kg_out *kout,
				size_t d_sz,
				size_t n_sz)
{
	kout->dbytes = d_sz;
	kout->nbytes = n_sz;
}

static void init_pkey2(struct wcrypto_rsa_prikey2 *pkey2, __u32 ksz)
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

static void init_pkey1(struct wcrypto_rsa_prikey1 *pkey1, __u32 ksz)
{
	pkey1->d.data = (char *)pkey1->data;
	pkey1->n.data = pkey1->d.data + ksz;
	pkey1->d.bsize = ksz;
	pkey1->n.bsize = ksz;
	pkey1->key_size = ksz;
}

static void init_pubkey(struct wcrypto_rsa_pubkey *pubkey, __u32 ksz)
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
	struct wd_mm_br *br = &setup->br;
	struct wcrypto_rsa_prikey2 *pkey2;
	struct wcrypto_rsa_prikey1 *pkey1;
	int len;

	if (setup->is_crt) {
		len = sizeof(struct wcrypto_rsa_prikey) +
			CRT_PARAMS_SZ(ctx->key_size);
		if (br->get_bufsize && br->get_bufsize(br->usr) < len) {
			WD_ERR("Blk_size < need_size<0x%x>.\n", len);
			return -WD_ENOMEM;
		}
		ctx->prikey = br->alloc(br->usr, len);
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
		if (br->get_bufsize && br->get_bufsize(br->usr) < len) {
			WD_ERR("Blk_size < need_size<0x%x>.\n", len);
			return -WD_ENOMEM;
		}
		ctx->prikey = br->alloc(br->usr, len);
		if (!ctx->prikey) {
			WD_ERR("alloc prikey1 fail!\n");
			return -WD_ENOMEM;
		}
		pkey1 = &ctx->prikey->pkey1;
		memset(ctx->prikey, 0, len);
		init_pkey1(pkey1, ctx->key_size);
	}

	len = sizeof(struct wcrypto_rsa_pubkey) + GEN_PARAMS_SZ(ctx->key_size);
	if (br->get_bufsize && br->get_bufsize(br->usr) < len) {
		br->free(br->usr, ctx->prikey);
		WD_ERR("Blk_size < need_size<0x%x>.\n", len);
		return -WD_ENOMEM;
	}
	ctx->pubkey = br->alloc(br->usr, len);
	if (!ctx->pubkey) {
		br->free(br->usr, ctx->prikey);
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
	struct wd_mm_br *br = &setup->br;

	if (br && br->free) {
		if (ctx->prikey)
			br->free(br->usr, ctx->prikey);
		if (ctx->pubkey)
			br->free(br->usr, ctx->pubkey);
	}
}

struct wcrypto_rsa_ctx *create_ctx(struct wcrypto_rsa_ctx_setup *setup, int ctx_id)
{
	struct wcrypto_rsa_cookie *cookie;
	struct wcrypto_rsa_ctx *ctx;
	int i, ret;

	ctx = calloc(1, sizeof(struct wcrypto_rsa_ctx));
	if (!ctx)
		return ctx;

	ret = wd_init_cookie_pool(&ctx->pool,
		sizeof(struct wcrypto_rsa_cookie), WD_HPRE_CTX_MSG_NUM);
	if (ret) {
		WD_ERR("fail to init cookie pool!\n");
		free(ctx);
		return NULL;
	}

	memcpy(&ctx->setup, setup, sizeof(*setup));
	ctx->ctx_id = ctx_id;
	ctx->key_size = setup->key_bits >> BYTE_BITS_SHIFT;
	for (i = 0; i < ctx->pool.cookies_num; i++) {
		cookie = (void *)((uintptr_t)ctx->pool.cookies +
			i * ctx->pool.cookies_size);
		if (setup->is_crt)
			cookie->msg.key_type = WCRYPTO_RSA_PRIKEY2;
		else
			cookie->msg.key_type = WCRYPTO_RSA_PRIKEY1;
		cookie->msg.data_fmt = setup->data_fmt;
		cookie->msg.key_bytes = ctx->key_size;
		cookie->msg.alg_type = WCRYPTO_RSA;
		cookie->tag.ctx = ctx;
		cookie->tag.ctx_id = ctx_id;
		cookie->msg.usr_data = (uintptr_t)&cookie->tag;
	}

	return ctx;
}

static void del_ctx(struct wcrypto_rsa_ctx *c)
{
	if (!c)
		return;

	wd_uninit_cookie_pool(&c->pool);
	free(c);
}

static int check_q_setup(struct wd_queue *q, struct wcrypto_rsa_ctx_setup *setup)
{
	if (!q || !setup) {
		WD_ERR("create rsa ctx input parameter err!\n");
		return -WD_EINVAL;
	}

	if (!setup->br.alloc || !setup->br.free) {
		WD_ERR("create rsa ctx user mm br err!\n");
		return -WD_EINVAL;
	}

	if (strcmp(q->capa.alg, "rsa")) {
		WD_ERR("create rsa ctx algorithm mismatching!\n");
		return -WD_EINVAL;
	}

	return 0;
}

/* Before initiate this context, we should get a queue from WD */
void *wcrypto_create_rsa_ctx(struct wd_queue *q, struct wcrypto_rsa_ctx_setup *setup)
{
	struct wcrypto_rsa_ctx *ctx;
	struct q_info *qinfo;
	__u32 cid = 0;
	int ret;

	ret = check_q_setup(q, setup);
	if (ret)
		return NULL;

	qinfo = q->qinfo;
	/* lock at ctx  creating/deleting */
	wd_spinlock(&qinfo->qlock);
	if (!qinfo->br.alloc && !qinfo->br.iova_map)
		memcpy(&qinfo->br, &setup->br, sizeof(setup->br));
	if (qinfo->br.usr != setup->br.usr) {
		WD_ERR("Err mm br in creating rsa ctx!\n");
		goto unlock;
	}

	if (qinfo->ctx_num >= WD_MAX_CTX_NUM) {
		WD_ERR("err:create too many rsa ctx!\n");
		goto unlock;
	}

	ret = wd_alloc_id(qinfo->ctx_id, WD_MAX_CTX_NUM, &cid, 0,
		WD_MAX_CTX_NUM);
	if (ret) {
		WD_ERR("err: alloc ctx id fail!\n");
		goto unlock;
	}
	qinfo->ctx_num++;
	wd_unspinlock(&qinfo->qlock);

	ctx = create_ctx(setup, cid + 1);
	if (!ctx) {
		WD_ERR("create rsa ctx fail!\n");
		goto free_ctx_id;
	}
	ctx->q = q;
	ret = create_ctx_key(setup, ctx);
	if (ret) {
		WD_ERR("fail creating rsa ctx keys!\n");
		goto delete_ctx;
	}

	return ctx;

delete_ctx:
	del_ctx(ctx);
free_ctx_id:
	wd_spinlock(&qinfo->qlock);
	wd_free_id(qinfo->ctx_id, WD_MAX_CTX_NUM, cid, WD_MAX_CTX_NUM);
	qinfo->ctx_num--;
unlock:
	wd_unspinlock(&qinfo->qlock);

	return NULL;
}

bool wcrypto_rsa_is_crt(const void *ctx)
{
	if (!ctx) {
		WD_ERR("rsa is crt judge, ctx NULL, return false!\n");
		return false;
	}

	return ((struct wcrypto_rsa_ctx *)ctx)->setup.is_crt;
}

int wcrypto_rsa_key_bits(const void *ctx)
{
	if (!ctx) {
		WD_ERR("get rsa key bits, ctx NULL!\n");
		return 0;
	}

	return ((struct wcrypto_rsa_ctx *)ctx)->setup.key_bits;
}

int wcrypto_set_rsa_pubkey_params(void *ctx, struct wd_dtb *e, struct wd_dtb *n)
{
	struct wcrypto_rsa_ctx *c = ctx;

	if (!ctx) {
		WD_ERR("ctx NULL in set rsa public key!\n");
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

	if (!ctx || wcrypto_rsa_is_crt(ctx)) {
		WD_ERR("ctx err in set rsa private key1!\n");
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

void wcrypto_get_rsa_prikey_params(struct wcrypto_rsa_prikey *pvk, struct wd_dtb **d,
					struct wd_dtb **n)
{
	struct wcrypto_rsa_prikey1 *pkey1;

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

static int rsa_prikey2_param_set(struct wcrypto_rsa_prikey2 *pkey2,
				 struct wd_dtb *param,
				 enum wcrypto_rsa_crt_prikey_para type)
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

void wcrypto_get_rsa_pubkey(void *ctx, struct wcrypto_rsa_pubkey **pubkey)
{
	if (!ctx || !pubkey) {
		WD_ERR("parameter is NULL!\n");
		return;
	}

	*pubkey = ((struct wcrypto_rsa_ctx *)ctx)->pubkey;
}

void wcrypto_get_rsa_prikey(void *ctx, struct wcrypto_rsa_prikey **prikey)
{
	if (!ctx || !prikey) {
		WD_ERR("parameter is NULL!\n");
		return;
	}

	*prikey = ((struct wcrypto_rsa_ctx *)ctx)->prikey;
}

static int rsa_request_init(struct wcrypto_rsa_msg *req, struct wcrypto_rsa_op_data *op,
				struct wcrypto_rsa_ctx *c)
{
	__u8 *key = NULL;

	req->in = op->in;
	req->in_bytes = (__u16)op->in_bytes;
	req->out = op->out;
	req->out_bytes = (__u16)op->out_bytes;
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

	if (unlikely(!key)) {
		WD_ERR("rsa request key null!\n");
		return -WD_EINVAL;
	}

	if (req->op_type == WCRYPTO_RSA_SIGN ||
		req->op_type == WCRYPTO_RSA_VERIFY) {
		if (unlikely(req->in_bytes != c->key_size)) {
			WD_ERR("sign or verf in_bytes != key_size!\n");
			return -WD_EINVAL;
		}
	}

	req->key = key;

	return WD_SUCCESS;
}

static int do_rsa_prepare(struct wcrypto_rsa_ctx *ctxt,
			  struct wcrypto_rsa_op_data *opdata,
			  struct wcrypto_rsa_cookie **cookie_addr,
			  struct wcrypto_rsa_msg **req_addr,
			  void *tag)
{
	struct wcrypto_rsa_cookie *cookie;
	struct wcrypto_rsa_msg *req;
	int ret;

	if (unlikely(!ctxt || !opdata)) {
		WD_ERR("input parameter err!\n");
		return -WD_EINVAL;
	}

	if (unlikely(tag && !ctxt->setup.cb)) {
		WD_ERR("ctx call back is null!\n");
		return -WD_EINVAL;
	}

	ret = wd_get_cookies(&ctxt->pool, (void **)&cookie, 1);
	if (ret)
		return ret;

	if (tag)
		cookie->tag.tag = tag;

	req = &cookie->msg;
	ret = rsa_request_init(req, opdata, ctxt);
	if (unlikely(ret)) {
		wd_put_cookies(&ctxt->pool, (void **)&cookie, 1);
		return ret;
	}

	*cookie_addr = cookie;
	*req_addr = req;

	return 0;
}

int wcrypto_do_rsa(void *ctx, struct wcrypto_rsa_op_data *opdata, void *tag)
{
	struct wcrypto_rsa_msg *resp = NULL;
	struct wcrypto_rsa_ctx *ctxt = ctx;
	struct wcrypto_rsa_cookie *cookie;
	struct wcrypto_rsa_msg *req;
	uint32_t rx_cnt = 0;
	uint32_t tx_cnt = 0;
	int ret;

	ret = do_rsa_prepare(ctxt, opdata, &cookie, &req, tag);
	if (unlikely(ret))
		return ret;

send_again:
	ret = wd_send(ctxt->q, req);
	if (ret == -WD_EBUSY) {
		usleep(1);
		if (tx_cnt++ < RSA_RESEND_CNT)
			goto send_again;
		else {
			WD_ERR("do rsa send cnt %u, exit!\n", tx_cnt);
			goto fail_with_cookie;
		}
	} else if (unlikely(ret)) {
		WD_ERR("do rsa wd_send err!\n");
		goto fail_with_cookie;
	}

	if (tag)
		return ret;

	resp = (void *)(uintptr_t)ctxt->ctx_id;
recv_again:
	ret = wd_recv(ctxt->q, (void **)&resp);
	if (!ret) {
		if (unlikely(rx_cnt++ >= RSA_RECV_MAX_CNT)) {
			WD_ERR("failed to recv: timeout!\n");
			return -WD_ETIMEDOUT;
		} else if (balance > RSA_BALANCE_THRHD) {
			usleep(1);
		}
		goto recv_again;
	} else if (unlikely(ret < 0)) {
		WD_ERR("do rsa wd_recv err!\n");
		goto fail_with_cookie;
	}

	balance = rx_cnt;
	opdata->out = (void *)resp->out;
	opdata->out_bytes = resp->out_bytes;
	opdata->status = resp->result;
	ret = GET_NEGATIVE(opdata->status);

fail_with_cookie:
	wd_put_cookies(&ctxt->pool, (void **)&cookie, 1);
	return ret;
}

int wcrypto_rsa_poll(struct wd_queue *q, unsigned int num)
{
	struct wcrypto_rsa_msg *resp = NULL;
	struct wcrypto_rsa_ctx *ctx;
	struct wcrypto_cb_tag *tag;
	int count = 0;
	int ret;

	if (unlikely(!q)) {
		WD_ERR("q is NULL!\n");
		return -WD_EINVAL;
	}

	do {
		ret = wd_recv(q, (void **)&resp);
		if (ret == 0)
			break;
		else if (unlikely(ret < 0)) {
			WD_ERR("recv err at rsa poll!\n");
			return ret;
		}
		count++;
		tag = (void *)(uintptr_t)resp->usr_data;
		ctx = tag->ctx;
		ctx->setup.cb(resp, tag->tag);
		wd_put_cookies(&ctx->pool, (void **)&tag, 1);
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
		WD_ERR("delete rsa parameter err!\n");
		return;
	}

	cx = ctx;
	st = &cx->setup;
	qinfo = cx->q->qinfo;

	wd_uninit_cookie_pool(&cx->pool);
	wd_spinlock(&qinfo->qlock);
	if (qinfo->ctx_num <= 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("error: repeat del rsa ctx!\n");
		return;
	}

	wd_free_id(qinfo->ctx_id, WD_MAX_CTX_NUM, cx->ctx_id - 1,
		WD_MAX_CTX_NUM);
	if (!(--qinfo->ctx_num))
		memset(&qinfo->br, 0, sizeof(qinfo->br));

	wd_unspinlock(&qinfo->qlock);
	del_ctx_key(st, cx);
	del_ctx(cx);
}
