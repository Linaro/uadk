/*
 * Copyright 2020 Huawei Technologies Co.,Ltd.All rights reserved.
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
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "wd.h"
#include "internal/wd_ecc_curve.h"
#include "wd_ecc.h"
#include "wd_util.h"

#define WD_ECC_CTX_MSG_NUM		64
#define WD_ECC_MAX_CTX			256
#define ECC_BALANCE_THRHD		1280
#define ECC_RECV_MAX_CNT		60000000
#define ECC_RESEND_CNT			8
#define BITS_TO_BYTES(bits)		(((bits) + 7) / 8)
#define ECC_MAX_KEY_SIZE		BITS_TO_BYTES(521)
#define ECC_MAX_HW_BITS			576
#define ECC_MAX_IN_NUM			4
#define ECC_MAX_OUT_NUM			4
#define CURVE_PARAM_NUM			6
#define ECC_MAX_IN_SIZE			(ECC_MAX_HW_BITS * ECC_MAX_IN_NUM)
#define ECC_MAX_OUT_SIZE		(ECC_MAX_HW_BITS * ECC_MAX_OUT_NUM)
#define WD_ARRAY_SIZE(array)		(sizeof(array) / sizeof(array[0]))
#define MAX_CURVE_SIZE			(ECC_MAX_KEY_SIZE * CURVE_PARAM_NUM)

#define WCRYPTO_X25519			0x1
#define WCRYPTO_X448			0x2

static __thread int balance;

enum wcrypto_ecc_curve_param_type {
	ECC_CURVE_P,
	ECC_CURVE_A,
	ECC_CURVE_B,
	ECC_CURVE_N,
	ECC_CURVE_G
};

struct wcrypto_ecc_dh_in {
	struct wcrypto_ecc_point pbk;
};

struct wcrypto_ecc_sign_in {
	struct wd_dtb e;
	struct wd_dtb k;
	__u8 k_set; /* 0 - not set 1 - set */
};

struct wcrypto_ecc_verf_in {
	struct wd_dtb e;
	struct wd_dtb s;
	struct wd_dtb r;
};

struct wcrypto_ecc_dh_out {
	struct wcrypto_ecc_point out;
};

struct wcrypto_ecc_sign_out {
	struct wd_dtb r;
	struct wd_dtb s;
};

typedef union {
	struct wcrypto_ecc_dh_in dh_in;
	struct wcrypto_ecc_sign_in sin;
	struct wcrypto_ecc_verf_in vin;
} wcrypto_ecc_in_param;

typedef union {
	struct wcrypto_ecc_dh_out dh_out;
	struct wcrypto_ecc_sign_out sout;
} wcrypto_ecc_out_param;

struct wcrypto_ecc_in {
	wcrypto_ecc_in_param param;
	__u32 size;
	char data[];
};

struct wcrypto_ecc_out {
	wcrypto_ecc_out_param param;
	__u32 size;
	char data[];
};

struct wcrypto_ecc_pubkey {
	struct wd_dtb p;
	struct wd_dtb a;
	struct wd_dtb b;
	struct wd_dtb n;
	struct wcrypto_ecc_point g;
	struct wcrypto_ecc_point pub;
	__u32 size;
	void *data;
};

struct wcrypto_ecc_prikey {
	struct wd_dtb p;
	struct wd_dtb a;
	struct wd_dtb d;
	struct wd_dtb b;
	struct wd_dtb n;
	struct wcrypto_ecc_point g;
	__u32 size;
	void *data;
};

struct wcrypto_ecc_key {
	struct wcrypto_ecc_pubkey *pubkey;
	struct wcrypto_ecc_prikey *prikey;
};

struct wcrypto_ecc_cookie {
	struct wcrypto_cb_tag tag;
	struct wcrypto_ecc_msg msg;
};

struct wcrypto_ecc_ctx {
	struct wcrypto_ecc_cookie cookies[WD_ECC_CTX_MSG_NUM];
	__u8 cstatus[WD_ECC_CTX_MSG_NUM];
	int cidx;
	__u32 key_size;
	int ctx_id;
	struct wd_queue *q;
	struct wcrypto_ecc_key key;
	struct wcrypto_ecc_ctx_setup setup;
};

struct wcrypto_ecc_curve_list {
	__u32 id;
	const char *name;
	__u32 key_bits;
	char data[MAX_CURVE_SIZE];
};

const static struct wcrypto_ecc_curve_list g_curve_list[] = {
	{ WCRYPTO_X25519, "x25519", 256, X25519_256_PARAM },
	{ WCRYPTO_X448, "x448", 448, X448_448_PARAM },
	{ WCRYPTO_SECP128R1, "secp128r1", 128, SECG_P128_R1_PARAM },
	{ WCRYPTO_SECP192K1, "secp192k1", 192, SECG_P192_K1_PARAM },
	{ WCRYPTO_SECP256K1, "secp256k1", 256, SECG_P256_K1_PARAM },
	{ WCRYPTO_BRAINPOOLP320R1, "bpP320r1", 320, BRAINPOOL_P320_R1_PARAM },
	{ WCRYPTO_BRAINPOOLP384R1, "bpP384r1", 384, BRAINPOOL_P384_R1_PARAM },
	{ WCRYPTO_SECP521R1, "secp521r1", 521, NIST_P521_R1_PARAM },
};

static void wd_memset_zero(void *data, __u32 size)
{
	char *s = (char *)data;

	if (!s || size <= 0)
		return;

	while (size--)
		*s++ = 0;
}

static void *br_alloc(struct wd_mm_br *br, __u32 size)
{
	if (!br->alloc)
		return NULL;

	return br->alloc(br->usr, size);
}

static void br_free(struct wd_mm_br *br, void *va)
{
	if (!br->free)
		return;

	return br->free(br->usr, va);
}

static __u32 get_hw_keysize(__u32 ksz)
{
	__u32 size = 0;

	if (ksz <= BITS_TO_BYTES(256))
		size = BITS_TO_BYTES(256);
	else if (ksz <= BITS_TO_BYTES(384))
		size = BITS_TO_BYTES(384);
	else if (ksz <= BITS_TO_BYTES(576))
		size = BITS_TO_BYTES(576);
	else
		WD_ERR("failed to get hw keysize : ksz = %d.\n", ksz);

	return size;
}

static void init_dtb_param(void *dtb, char *start,
			   __u32 dsz, __u32 bsz, __u32 num)
{
	struct wd_dtb *tmp = dtb;
	int i = 0;

	while (i++ < num) {
		tmp->data = start;
		tmp->dsize = dsz;
		tmp->bsize = bsz;
		tmp += 1;
		start += bsz;
	}
}

static void init_ecc_prikey(struct wcrypto_ecc_prikey *prikey,
			    __u32 ksz, __u32 bsz)
{
	init_dtb_param(prikey, prikey->data, ksz, bsz, ECC_PRIKEY_PARAM_NUM);
}

static void init_ecc_pubkey(struct wcrypto_ecc_pubkey *pubkey,
			    __u32 ksz, __u32 bsz)
{
	init_dtb_param(pubkey, pubkey->data, ksz, bsz, ECC_PUBKEY_PARAM_NUM);
}

static void release_ecc_prikey(struct wcrypto_ecc_ctx *ctx)
{
	struct wcrypto_ecc_prikey *prikey = ctx->key.prikey;
	struct wd_mm_br *br = &ctx->setup.br;

	wd_memset_zero(prikey->data, prikey->size);
	br_free(br, prikey->data);
	free(prikey);
	ctx->key.prikey = NULL;
}

static void release_ecc_pubkey(struct wcrypto_ecc_ctx *ctx)
{
	struct wcrypto_ecc_pubkey *pubkey = ctx->key.pubkey;
	struct wd_mm_br *br = &ctx->setup.br;

	br_free(br, pubkey->data);
	free(pubkey);
	ctx->key.pubkey = NULL;
}

static struct wcrypto_ecc_prikey *create_ecc_prikey(struct wcrypto_ecc_ctx *ctx)
{
	struct wd_mm_br *br = &ctx->setup.br;
	struct wcrypto_ecc_prikey *prikey;
	__u32 hsz, dsz;
	void *data;

	hsz = get_hw_keysize(ctx->key_size);
	prikey = malloc(sizeof(struct wcrypto_ecc_prikey));
	if (!prikey) {
		WD_ERR("failed to malloc!\n");
		return NULL;
	}

	dsz = ECC_PRIKEY_SZ(hsz);
	data = br_alloc(br, dsz);
	if (!data) {
		WD_ERR("failed to br alloc!\n");
		free(prikey);
		return NULL;
	}

	memset(data, 0, dsz);
	prikey->size = dsz;
	prikey->data = data;
	init_ecc_prikey(prikey, ctx->key_size, hsz);

	return prikey;
}

static struct wcrypto_ecc_pubkey *create_ecc_pubkey(struct wcrypto_ecc_ctx *ctx)
{
	struct wd_mm_br *br = &ctx->setup.br;
	struct wcrypto_ecc_pubkey *pubkey;
	__u32 hsz, dsz;
	void *data;

	hsz = get_hw_keysize(ctx->key_size);
	pubkey = malloc(sizeof(struct wcrypto_ecc_pubkey));
	if (!pubkey) {
		WD_ERR("failed to malloc!\n");
		return NULL;
	}

	dsz = ECC_PUBKEY_SZ(hsz);
	data = br_alloc(br, dsz);
	if (!data) {
		WD_ERR("failed to create br alloc!\n");
		free(pubkey);
		return NULL;
	}

	memset(data, 0, dsz);
	pubkey->size = dsz;
	pubkey->data = data;
	init_ecc_pubkey(pubkey, ctx->key_size, hsz);

	return pubkey;
}

static void release_ecc_in(struct wcrypto_ecc_ctx *ctx,
			   struct wcrypto_ecc_in *ecc_in)
{
	struct wd_mm_br *br = &ctx->setup.br;

	wd_memset_zero(ecc_in->data, ecc_in->size);
	br_free(br, ecc_in);
}

static struct wcrypto_ecc_in *create_ecc_in(struct wcrypto_ecc_ctx *ctx,
					    __u32 num)
{
	struct wd_mm_br *br = &ctx->setup.br;
	struct wcrypto_ecc_in *in;
	__u32 hsz, len;

	if (!ctx->key_size || ctx->key_size > ECC_MAX_KEY_SIZE) {
		WD_ERR("ctx key size %d error!\n", ctx->key_size);
		return NULL;
	}

	hsz = get_hw_keysize(ctx->key_size);
	len = sizeof(struct wcrypto_ecc_in) + hsz * num;
	in = br_alloc(br, len);
	if (!in) {
		WD_ERR("failed to br alloc!\n");
		return NULL;
	}

	memset(in, 0, len);
	in->size = hsz * num;
	init_dtb_param(in, in->data, ctx->key_size, hsz, num);

	return in;
}

static struct wcrypto_ecc_out *create_ecc_out(struct wcrypto_ecc_ctx *ctx,
					      __u32 num)
{
	struct wd_mm_br *br = &ctx->setup.br;
	struct wcrypto_ecc_out *out;
	__u32 hsz, len;

	if (!ctx->key_size || ctx->key_size > ECC_MAX_KEY_SIZE) {
		WD_ERR("ctx key size %d error!\n", ctx->key_size);
		return NULL;
	}

	hsz = get_hw_keysize(ctx->key_size);
	len = sizeof(struct wcrypto_ecc_out) + hsz * num;
	out = br_alloc(br, len);
	if (!out) {
		WD_ERR("failed to br alloc!\n");
		return NULL;
	}

	memset(out, 0, len);
	out->size = hsz * num;
	init_dtb_param(out, out->data, ctx->key_size, hsz, num);

	return out;
}

static int set_param_single(struct wd_dtb *dst, const struct wd_dtb *src)
{
	if (!src || !dst ||
		!src->data || !src->dsize || src->dsize > dst->dsize)
		return -WD_EINVAL;

	dst->dsize = src->dsize;
	memset(dst->data, 0, dst->bsize);
	memcpy(dst->data, src->data, src->dsize);

	return 0;
}

struct wcrypto_ecc_in *wcrypto_new_ecxdh_in(void *ctx,
					    struct wcrypto_ecc_point *in)
{
	struct wcrypto_ecc_ctx *cx = ctx;
	struct wcrypto_ecc_dh_in *dh_in;
	struct wcrypto_ecc_in *ecc_in;
	int ret;

	if (!cx || !in) {
		WD_ERR("new ecc dh in param error!\n");
		return NULL;
	}

	ecc_in = create_ecc_in(cx, ECDH_IN_PARAM_NUM);
	if (!ecc_in) {
		WD_ERR("failed to create ecc in!\n");
		return NULL;
	}

	dh_in = &ecc_in->param.dh_in;
	ret = set_param_single(&dh_in->pbk.x, &in->x);
	if (ret) {
		WD_ERR("failed to set ecdh in: x error!\n");
		release_ecc_in(ctx, ecc_in);
		return NULL;
	}

	ret = set_param_single(&dh_in->pbk.y, &in->y);
	if (ret) {
		WD_ERR("failed to set ecdh in: y error!\n");
		release_ecc_in(ctx, ecc_in);
		return NULL;
	}

	return ecc_in;
}

struct wcrypto_ecc_out *wcrypto_new_ecxdh_out(void *ctx)
{
	struct wcrypto_ecc_out *ecc_out;

	if (!ctx) {
		WD_ERR("new ecc dh out ctx NULL!\n");
		return NULL;
	}

	ecc_out = create_ecc_out(ctx, ECDH_OUT_PARAM_NUM);
	if (!ecc_out) {
		WD_ERR("failed to create ecc out!\n");
		return NULL;
	}

	return ecc_out;
}

int wcrypto_get_ecc_key_bits(void *ctx)
{
	if (!ctx) {
		WD_ERR("get ecc key bits, ctx NULL!\n");
		return -WD_EINVAL;
	}

	return ((struct wcrypto_ecc_ctx *)ctx)->setup.key_bits;
}

static int set_curve_param_single(struct wcrypto_ecc_key *key,
				  const struct wd_dtb *param,
				  __u32 type)
{
	struct wcrypto_ecc_prikey *pri = key->prikey;
	struct wcrypto_ecc_pubkey *pub = key->pubkey;
	struct wcrypto_ecc_point *g;
	int ret = -WD_EINVAL;

	switch (type) {
	case ECC_CURVE_P:
		ret = set_param_single(&pri->p, param);
		if (ret)
			return ret;

		ret = set_param_single(&pub->p, param);
		if (ret)
			return ret;
		break;
	case ECC_CURVE_A:
		ret = set_param_single(&pri->a, param);
		if (ret)
			return ret;

		ret = set_param_single(&pub->a, param);
		if (ret)
			return ret;
		break;
	case ECC_CURVE_B:
		ret = set_param_single(&pri->b, param);
		if (ret)
			return ret;

		ret = set_param_single(&pub->b, param);
		if (ret)
			return ret;
		break;
	case ECC_CURVE_N:
		ret = set_param_single(&pri->n, param);
		if (ret)
			return ret;

		ret = set_param_single(&pub->n, param);
		if (ret)
			return ret;
		break;
	case ECC_CURVE_G:
		g = (struct wcrypto_ecc_point *)param;
		ret = set_param_single(&pri->g.x, &g->x);
		if (ret)
			return ret;

		ret = set_param_single(&pri->g.y, &g->y);
		if (ret)
			return ret;

		ret = set_param_single(&pub->g.x, &g->x);
		if (ret)
			return ret;

		ret = set_param_single(&pub->g.y, &g->y);
		if (ret)
			return ret;
		break;
	default:
		break;
	}

	return ret;
}

static int set_curve_param(struct wcrypto_ecc_key *key,
			   const struct wcrypto_ecc_curve *param)
{
	int ret;

	ret = set_curve_param_single(key, &param->p, ECC_CURVE_P);
	if (ret) {
		WD_ERR("failed to set curve param: p error!\n");
		return -WD_EINVAL;
	}

	ret = set_curve_param_single(key, &param->a, ECC_CURVE_A);
	if (ret) {
		WD_ERR("failed to set curve param: a error!\n");
		return -WD_EINVAL;
	}

	ret = set_curve_param_single(key, &param->b, ECC_CURVE_B);
	if (ret) {
		WD_ERR("failed to set curve param: b error!\n");
		return -WD_EINVAL;
	}

	ret = set_curve_param_single(key, &param->n, ECC_CURVE_N);
	if (ret) {
		WD_ERR("failed to set curve param: n error!\n");
		return -WD_EINVAL;
	}

	ret = set_curve_param_single(key, (void *)&param->g, ECC_CURVE_G);
	if (ret) {
		WD_ERR("failed to set curve param: g error!\n");
		return -WD_EINVAL;
	}

	return 0;
}

const static struct wcrypto_ecc_curve_list *find_curve_list(__u32 id)
{
	int len = WD_ARRAY_SIZE(g_curve_list);
	int is_find = 0;
	int i = 0;

	while (i < len) {
		if (g_curve_list[i].id == id) {
			is_find = 1;
			break;
		}
		i++;
	}

	if (!is_find)
		return NULL;

	return &g_curve_list[i];
}

static int fill_param_by_id(struct wcrypto_ecc_curve *c,
			    __u16 key_bits, __u32 id)
{
	struct wcrypto_ecc_curve_list *item = NULL;
	__u32 key_size;

	item = (struct wcrypto_ecc_curve_list *)find_curve_list(id);
	if (!item) {
		WD_ERR("failed to find curve id %d!\n", id);
		return -WD_EINVAL;
	}

	if (item->key_bits != key_bits) {
		WD_ERR("curve %u and key bits %u not match!\n", id, key_bits);
		return -WD_EINVAL;
	}

	key_size = BITS_TO_BYTES(item->key_bits);
	init_dtb_param(c, item->data, key_size, key_size, CURVE_PARAM_NUM);

	return 0;
}

static int fill_user_curve_cfg(struct wcrypto_ecc_curve *param,
			       struct wcrypto_ecc_ctx_setup *setup,
			       const char *alg)
{
	struct wcrypto_ecc_curve *ppara = setup->cv.cfg.pparam;
	__u32 curve_id;
	int ret = 0;

	if (setup->cv.type == WCRYPTO_CV_CFG_ID) {
		curve_id = setup->cv.cfg.id;
		ret = fill_param_by_id(param, setup->key_bits, curve_id);
		dbg("set curve id %d\n", curve_id);
	} else if (setup->cv.type == WCRYPTO_CV_CFG_PARAM) {
		if (!ppara) {
			WD_ERR("fill curve cfg:pparam NULL!\n");
			return -WD_EINVAL;
		}

		memcpy(param, ppara, sizeof(struct wcrypto_ecc_curve));
		dbg("set curve by user param\n");
	} else {
		WD_ERR("fill curve cfg:type %d error!\n", setup->cv.type);
		return -WD_EINVAL;
	}

	if (!param->p.dsize ||
	     param->p.dsize > BITS_TO_BYTES(setup->key_bits)) {
		WD_ERR("fill curve cfg:dsize %d error!\n", param->p.dsize);
		return -WD_EINVAL;
	}

	return ret;
}

static int create_ctx_key(struct wcrypto_ecc_ctx_setup *setup,
			  struct wcrypto_ecc_ctx *ctx)
{
	struct wcrypto_ecc_curve c_param;
	struct wd_queue *q = NULL;
	int ret;

	memset(&c_param, 0, sizeof(struct wcrypto_ecc_curve));
	ctx->key.prikey = create_ecc_prikey(ctx);
	if (!ctx->key.prikey) {
		WD_ERR("failed to create ecc prikey!\n");
		return -WD_ENOMEM;
	}

	ctx->key.pubkey = create_ecc_pubkey(ctx);
	if (!ctx->key.pubkey) {
		WD_ERR("failed to create ecc pubkey!\n");
		ret = -WD_EINVAL;
		goto free_prikey;
	}

	q = ctx->q;
	ret = fill_user_curve_cfg(&c_param, setup, q->capa.alg);
	if (ret) {
		WD_ERR("failed to fill user curve cfg!\n");
		ret = -WD_EINVAL;
		goto free_pubkey;
	}

	ret = set_curve_param(&ctx->key, &c_param);
	if (ret) {
		WD_ERR("failed to set curve param!\n");
		ret = -WD_EINVAL;
		goto free_pubkey;
	}

	return 0;

free_pubkey:
	release_ecc_pubkey(ctx);

free_prikey:
	release_ecc_prikey(ctx);

	return ret;
}

static void setup_curve_cfg(struct wcrypto_ecc_ctx_setup *setup,
			    const char *alg)
{
	if (!strcmp(alg, "x25519")) {
		setup->key_bits = 256;
		setup->cv.type = WCRYPTO_CV_CFG_ID;
		setup->cv.cfg.id = WCRYPTO_X25519;
	} else if (!strcmp(alg, "x448")) {
		setup->key_bits = 448;
		setup->cv.type = WCRYPTO_CV_CFG_ID;
		setup->cv.cfg.id = WCRYPTO_X448;
	}
}

static int param_check(struct wd_queue *q, struct wcrypto_ecc_ctx_setup *setup)
{
	if (!q || !setup) {
		WD_ERR("input param error!\n");
		return -WD_EINVAL;
	}

	if (!setup->br.alloc || !setup->br.free) {
		WD_ERR("user mm br error!\n");
		return -WD_EINVAL;
	}

	if (strcmp(q->capa.alg, "ecdh") &&
	    strcmp(q->capa.alg, "ecdsa") &&
	    strcmp(q->capa.alg, "x25519") &&
	    strcmp(q->capa.alg, "x448")) {
		WD_ERR("alg %s mismatching!\n", q->capa.alg);
		return -WD_EINVAL;
	}

	setup_curve_cfg(setup, q->capa.alg);

	if (setup->key_bits != 128 &&
	    setup->key_bits != 192 &&
	    setup->key_bits != 256 &&
	    setup->key_bits != 320 &&
	    setup->key_bits != 384 &&
	    setup->key_bits != 448 &&
	    setup->key_bits != 521) {
		WD_ERR("key_bits %d error!\n", setup->key_bits);
		return -WD_EINVAL;
	}

	return 0;
}

static void del_ctx_key(struct wd_mm_br *br,
			struct wcrypto_ecc_ctx *ctx)
{
	if (!br->free)
		return;

	if (ctx->key.prikey) {
		wd_memset_zero(ctx->key.prikey->data, ctx->key.prikey->size);
		br->free(br->usr, ctx->key.prikey->data);
		free(ctx->key.prikey);
		ctx->key.prikey = NULL;
	}

	if (ctx->key.pubkey) {
		br->free(br->usr, ctx->key.pubkey->data);
		free(ctx->key.pubkey);
		ctx->key.pubkey = NULL;
	}
}

static void init_ctx_cookies(struct wcrypto_ecc_ctx *ctx,
			     struct wcrypto_ecc_ctx_setup *setup)
{
	uint32_t hsz = get_hw_keysize(ctx->key_size);
	struct q_info *qinfo = ctx->q->qinfo;
	int i;

	for (i = 0; i < WD_ECC_CTX_MSG_NUM; i++) {
		ctx->cookies[i].msg.curve_id = setup->cv.cfg.id;
		ctx->cookies[i].msg.data_fmt = setup->data_fmt;
		ctx->cookies[i].msg.key_bytes = hsz;
		ctx->cookies[i].msg.alg_type = qinfo->atype;
		ctx->cookies[i].tag.ctx = ctx;
		ctx->cookies[i].tag.ctx_id = ctx->ctx_id;
		ctx->cookies[i].msg.usr_data = (uintptr_t)&ctx->cookies[i].tag;
	}
}

/* Before initiate this context, we should get a queue from WD */
void *wcrypto_create_ecc_ctx(struct wd_queue *q,
			     struct wcrypto_ecc_ctx_setup *setup)
{
	struct wcrypto_ecc_ctx *ctx;
	struct q_info *qinfo;
	int ret, cid;

	if (param_check(q, setup))
		return NULL;

	qinfo = q->qinfo;
	/*lock at ctx  creating/deleting */
	wd_spinlock(&qinfo->qlock);
	if (!qinfo->br.alloc && !qinfo->br.iova_map)
		memcpy(&qinfo->br, &setup->br, sizeof(setup->br));
	if (qinfo->br.usr != setup->br.usr) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("Err mm br in creating ecc ctx!\n");
		return NULL;
	}

	if (qinfo->ctx_num >= WD_ECC_MAX_CTX) {
		WD_ERR("err:create too many ecc ctx!\n");
		wd_unspinlock(&qinfo->qlock);
		return NULL;
	}

	cid = wd_alloc_ctx_id(q, WD_ECC_MAX_CTX);
	if (cid < 0) {
		WD_ERR("failed to alloc ctx id!\n");
		wd_unspinlock(&qinfo->qlock);
		return NULL;
	}
	wd_unspinlock(&qinfo->qlock);

	ctx = malloc(sizeof(struct wcrypto_ecc_ctx));
	if (!ctx) {
		WD_ERR("failed to malloc!\n");
		goto free_ctx_id;
	}

	memset(ctx, 0, sizeof(struct wcrypto_ecc_ctx));
	memcpy(&ctx->setup, setup, sizeof(*setup));
	ctx->key_size = BITS_TO_BYTES(setup->key_bits);
	ctx->q = q;
	ctx->ctx_id = cid;
	ret = create_ctx_key(setup, ctx);
	if (ret) {
		WD_ERR("failed to create ecc ctx keys!\n");
		free(ctx);
		goto free_ctx_id;
	}

	init_ctx_cookies(ctx, setup);
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num++;
	wd_unspinlock(&qinfo->qlock);

	return ctx;

free_ctx_id:
	wd_spinlock(&qinfo->qlock);
	wd_free_ctx_id(q, cid);
	wd_unspinlock(&qinfo->qlock);

	return NULL;
}

void wcrypto_del_ecc_ctx(void *ctx)
{
	struct wcrypto_ecc_ctx *cx;
	struct wd_mm_br *br;
	struct q_info *qinfo;

	if (!ctx) {
		WD_ERR("Delete ecc param err!\n");
		return;
	}

	cx = ctx;
	br = &cx->setup.br;
	qinfo = cx->q->qinfo;
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	wd_free_ctx_id(cx->q, cx->ctx_id);
	if (!qinfo->ctx_num) {
		memset(&qinfo->br, 0, sizeof(qinfo->br));
	} else if (qinfo->ctx_num < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("error:repeat del ecc ctx!\n");
		return;
	}
	wd_unspinlock(&qinfo->qlock);

	del_ctx_key(br, cx);
	free(cx);
}

struct wcrypto_ecc_key *wcrypto_get_ecc_key(void *ctx)
{
	struct wcrypto_ecc_ctx *cx = ctx;

	if (!cx) {
		WD_ERR("get ecc key ctx NULL!\n");
		return NULL;
	}

	return &cx->key;
}

int wcrypto_set_ecc_prikey(struct wcrypto_ecc_key *ecc_key,
			   struct wd_dtb *prikey)
{
	struct wcrypto_ecc_prikey *ecc_prikey;
	int ret;

	if (!ecc_key || !prikey) {
		WD_ERR("set ecc prikey param NULL!\n");
		return -WD_EINVAL;
	}

	ecc_prikey = ecc_key->prikey;
	if (!ecc_prikey) {
		WD_ERR("ecc_prikey NULL!\n");
		return -WD_EINVAL;
	}

	ret = set_param_single(&ecc_prikey->d, prikey);
	if (ret) {
		WD_ERR("failed to set prikey!\n");
		return ret;
	}

	return WD_SUCCESS;
}

int wcrypto_get_ecc_prikey(struct wcrypto_ecc_key *ecc_key,
			   struct wd_dtb **prikey)
{
	struct wcrypto_ecc_prikey *ecc_prikey;

	if (!ecc_key || !prikey) {
		WD_ERR("get ecc prikey param err!\n");
		return -WD_EINVAL;
	}

	ecc_prikey = ecc_key->prikey;
	if (!ecc_prikey) {
		WD_ERR("ecc_prikey NULL!\n");
		return -WD_EINVAL;
	}

	*prikey = &ecc_prikey->d;

	return WD_SUCCESS;
}

int wcrypto_set_ecc_pubkey(struct wcrypto_ecc_key *ecc_key,
			   struct wcrypto_ecc_point *pubkey)
{
	struct wcrypto_ecc_pubkey *ecc_pubkey;
	int ret;

	if (!ecc_key || !pubkey) {
		WD_ERR("set ecc pubkey param err!\n");
		return -WD_EINVAL;
	}

	ecc_pubkey = ecc_key->pubkey;
	if (!ecc_pubkey) {
		WD_ERR("ecc_pubkey NULL!\n");
		return -WD_EINVAL;
	}

	ret = set_param_single(&ecc_pubkey->pub.x, &pubkey->x);
	if (ret) {
		WD_ERR("failed to set pubkey x!\n");
		return ret;
	}

	ret = set_param_single(&ecc_pubkey->pub.y, &pubkey->y);
	if (ret) {
		WD_ERR("failed to set pubkey y!\n");
		return ret;
	}

	return WD_SUCCESS;
}

int wcrypto_get_ecc_pubkey(struct wcrypto_ecc_key *ecc_key,
			   struct wcrypto_ecc_point **pubkey)
{
	struct wcrypto_ecc_pubkey *ecc_pubkey;

	if (!ecc_key || !pubkey) {
		WD_ERR("get ecc pubkey param err!\n");
		return -WD_EINVAL;
	}

	ecc_pubkey = ecc_key->pubkey;
	if (!ecc_pubkey) {
		WD_ERR("ecc_pubkey NULL!\n");
		return -WD_EINVAL;
	}

	*pubkey = &ecc_pubkey->pub;

	return WD_SUCCESS;
}

void wcrypto_get_ecc_prikey_params(struct wcrypto_ecc_key *key,
				  struct wd_dtb **p, struct wd_dtb **a,
				  struct wd_dtb **b, struct wd_dtb **n,
				  struct wcrypto_ecc_point **g,
				  struct wd_dtb **d)
{
	struct wcrypto_ecc_prikey *prk;

	if (!key || !key->prikey) {
		WD_ERR("input NULL in get ecc prikey param!\n");
		return;
	}

	prk = key->prikey;

	if (p)
		*p = &prk->p;

	if (a)
		*a = &prk->a;

	if (b)
		*b = &prk->b;

	if (n)
		*n = &prk->n;

	if (g)
		*g = &prk->g;

	if (d)
		*d = &prk->d;
}

void wcrypto_get_ecc_pubkey_params(struct wcrypto_ecc_key *key,
				  struct wd_dtb **p, struct wd_dtb **a,
				  struct wd_dtb **b, struct wd_dtb **n,
				  struct wcrypto_ecc_point **g,
				  struct wcrypto_ecc_point **pub)
{
	struct wcrypto_ecc_pubkey *pbk;

	if (!key || !key->pubkey) {
		WD_ERR("input NULL in get ecc pubkey param!\n");
		return;
	}

	pbk = key->pubkey;

	if (p)
		*p = &pbk->p;

	if (a)
		*a = &pbk->a;

	if (b)
		*b = &pbk->b;

	if (n)
		*n = &pbk->n;

	if (g)
		*g = &pbk->g;

	if (pub)
		*pub = &pbk->pub;
}

void wcrypto_get_ecxdh_out_params(struct wcrypto_ecc_out *out,
				  struct wcrypto_ecc_point **key)
{
	struct wcrypto_ecc_dh_out *dh_out = (void *)out;

	if (!dh_out) {
		WD_ERR("input NULL in get ecdh out!\n");
		return;
	}

	if (key)
		*key = &dh_out->out;
}

void wcrypto_get_ecxdh_in_params(struct wcrypto_ecc_in *in,
				 struct wcrypto_ecc_point **pbk)
{
	struct wcrypto_ecc_dh_in *dh_in = (void *)in;

	if (!in) {
		WD_ERR("input NULL in get ecdh in!\n");
		return;
	}

	if (pbk)
		*pbk = &dh_in->pbk;
}

void wcrypto_del_ecc_in(void *ctx, struct wcrypto_ecc_in *in)
{
	struct wcrypto_ecc_ctx *cx = ctx;
	__u32 bsz;

	if (!ctx || !in) {
		WD_ERR("del ecc in param error!\n");
		return;
	}

	bsz = in->size;
	if (!bsz || bsz > ECC_MAX_IN_SIZE) {
		WD_ERR("del ecc in: size %d err!\n", bsz);
		return;
	}

	wd_memset_zero(in->data, bsz);
	br_free(&cx->setup.br, in);
}

void wcrypto_del_ecc_out(void *ctx,  struct wcrypto_ecc_out *out)
{
	struct wcrypto_ecc_ctx *cx = ctx;
	__u32 bsz;

	if (!ctx || !out) {
		WD_ERR("del ecc out param error!\n");
		return;
	}

	bsz = out->size;
	if (!bsz || bsz > ECC_MAX_OUT_SIZE) {
		WD_ERR("del ecc out: size %d err!\n", bsz);
		return;
	}

	wd_memset_zero(out->data, bsz);
	br_free(&cx->setup.br, out);
}

static struct wcrypto_ecc_cookie *get_ecc_cookie(struct wcrypto_ecc_ctx *ctx)
{
	int idx = ctx->cidx;
	int cnt = 0;

	while (__atomic_test_and_set(&ctx->cstatus[idx], __ATOMIC_ACQUIRE)) {
		idx++;
		cnt++;
		if (idx == WD_ECC_CTX_MSG_NUM)
			idx = 0;
		if (cnt == WD_ECC_CTX_MSG_NUM)
			return NULL;
	}

	ctx->cidx = idx;
	return &ctx->cookies[idx];
}

static void put_ecc_cookie(struct wcrypto_ecc_ctx *ctx,
			   struct wcrypto_ecc_cookie *cookie)
{
	int idx = ((uintptr_t)cookie - (uintptr_t)ctx->cookies) /
		sizeof(struct wcrypto_ecc_cookie);

	if (idx < 0 || idx >= WD_ECC_CTX_MSG_NUM) {
		WD_ERR("ecc cookie not exist!\n");
		return;
	}
	__atomic_clear(&ctx->cstatus[idx], __ATOMIC_RELEASE);
}

static int ecc_request_init(struct wcrypto_ecc_msg *req,
			    struct wcrypto_ecc_op_data *op,
			    struct wcrypto_ecc_ctx *c, __u8 need_hash)
{
	__u8 *key = NULL;

	req->in_bytes = (__u16)op->in_bytes;
	req->out = op->out;
	req->op_type = op->op_type;
	req->result = WD_EINVAL;

	switch (req->op_type) {
	case WCRYPTO_ECXDH_GEN_KEY:
	case WCRYPTO_ECXDH_COMPUTE_KEY:
	case WCRYPTO_ECDSA_SIGN:
	case WCRYPTO_ECDSA_VERIFY:
		key = (__u8 *)&c->key;
		break;
	default:
		WD_ERR("ecc request op type = %d error!\n", req->op_type);
		return -WD_EINVAL;
	}
	req->key = key;

	if (req->op_type == WCRYPTO_ECXDH_GEN_KEY) {
		struct wcrypto_ecc_point *g;

		wcrypto_get_ecc_prikey_params((void *)key, NULL, NULL,
			NULL, NULL, &g, NULL);
		req->in = (void *)g;
	} else {
		req->in = op->in;
	}

	if (!req->in || (!req->out && req->op_type != WCRYPTO_ECDSA_VERIFY)) {
		WD_ERR("req in/out NULL!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int ecc_send(struct wcrypto_ecc_ctx *ctx, struct wcrypto_ecc_msg *req)
{
	uint32_t tx_cnt = 0;
	int ret;

	do {
		ret = wd_send(ctx->q, req);
		if (ret == -WD_EBUSY) {
			tx_cnt++;
			usleep(1);
			if (tx_cnt >= ECC_RESEND_CNT) {
				WD_ERR("failed to send: retry exit!\n");
				break;
			}
		} else if (ret) {
			WD_ERR("failed to send: send error = %d!\n", ret);
			break;
		}
	} while (ret);

	return ret;
}

static int ecc_sync_recv(struct wcrypto_ecc_ctx *ctx,
			 struct wcrypto_ecc_op_data *opdata)
{
	struct wcrypto_ecc_msg *resp = NULL;
	uint32_t rx_cnt = 0;
	int ret;

	resp = (void *)(uintptr_t)ctx->ctx_id;

	do {
		ret = wd_recv(ctx->q, (void **)&resp);
		if (!ret) {
			if (rx_cnt++ >= ECC_RECV_MAX_CNT) {
				WD_ERR("failed to recv: timeout!\n");
				return -WD_ETIMEDOUT;
			}

			if (balance > ECC_BALANCE_THRHD)
				usleep(1);
		} else if (ret < 0) {
			WD_ERR("failed to recv: error = %d!\n", ret);
			return ret;
		}
	} while (!ret);

	balance = rx_cnt;
	opdata->out = resp->out;
	opdata->out_bytes = resp->out_bytes;
	opdata->status = resp->result;
	ret = GET_NEGATIVE(opdata->status);

	return ret;
}

static int do_ecc(void *ctx, struct wcrypto_ecc_op_data *opdata, void *tag,
		  __u8 need_hash)
{
	struct wcrypto_ecc_ctx *ctxt = ctx;
	struct wcrypto_ecc_cookie *cookie;
	struct wcrypto_ecc_msg *req;
	int ret = -WD_EINVAL;

	if (!ctx) {
		WD_ERR("do ecc param null!\n");
		return -WD_EINVAL;
	}

	cookie = get_ecc_cookie(ctxt);
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
	ret = ecc_request_init(req, opdata, ctxt, need_hash);
	if (ret)
		goto fail_with_cookie;

	ret = ecc_send(ctxt, req);
	if (ret)
		goto fail_with_cookie;

	if (tag)
		return ret;

	ret = ecc_sync_recv(ctxt, opdata);

fail_with_cookie:
	put_ecc_cookie(ctxt, cookie);
	return ret;
}

static int ecc_poll(struct wd_queue *q, unsigned int num)
{
	struct wcrypto_ecc_msg *resp = NULL;
	struct wcrypto_ecc_ctx *ctx;
	struct wcrypto_cb_tag *tag;
	int count = 0;
	int ret;

	if (!q) {
		WD_ERR("q is NULL!\n");
		return -WD_EINVAL;
	}

	do {
		ret = wd_recv(q, (void **)&resp);
		if (ret == 0)
			break;
		else if (ret < 0) {
			WD_ERR("failed to recv: error = %d!\n", ret);
			return ret;
		}

		count++;
		tag = (void *)(uintptr_t)resp->usr_data;
		ctx = tag->ctx;
		ctx->setup.cb(resp, tag->tag);
		put_ecc_cookie(ctx, (struct wcrypto_ecc_cookie *)tag);
		resp = NULL;
	} while (--num);

	return count;
}

int wcrypto_do_ecxdh(void *ctx, struct wcrypto_ecc_op_data *opdata, void *tag)
{
	if (!opdata) {
		WD_ERR("do ecxdh: opdata null!\n");
		return -WD_EINVAL;
	}

	if (opdata->op_type != WCRYPTO_ECXDH_GEN_KEY &&
		opdata->op_type != WCRYPTO_ECXDH_COMPUTE_KEY) {
		WD_ERR("do ecxdh: op_type = %d error!\n", opdata->op_type);
		return -WD_EINVAL;
	}

	return do_ecc(ctx, opdata, tag, 0);
}

int wcrypto_ecxdh_poll(struct wd_queue *q, unsigned int num)
{
	return ecc_poll(q, num);
}

static void get_sign_out_params(struct wcrypto_ecc_out *out,
				struct wd_dtb **r, struct wd_dtb **s)
{
	struct wcrypto_ecc_sign_out *sout = (void *)out;

	if (!sout) {
		WD_ERR("input NULL in get ecc sign out!\n");
		return;
	}

	if (r)
		*r = &sout->r;

	if (s)
		*s = &sout->s;
}

void wcrypto_get_ecdsa_sign_out_params(struct wcrypto_ecc_out *out,
				       struct wd_dtb **r, struct wd_dtb **s)
{
	return get_sign_out_params(out, r, s);
}

static int set_sign_in_param(struct wcrypto_ecc_sign_in *sin,
			     struct wd_dtb *e,
			     struct wd_dtb *k)
{
	int ret;

	if (k) {
		ret = set_param_single(&sin->k, k);
		if (ret) {
			WD_ERR("set ecc sign in k err!\n");
			return ret;
		}
	}

	ret = set_param_single(&sin->e, e);
	if (ret)
		WD_ERR("set ecc sign e err!\n");

	return ret;
}

static int generate_random(struct wcrypto_ecc_ctx *ctx, struct wd_dtb *k)
{
	struct wcrypto_rand_mt rand = ctx->setup.rand;
	int ret;

	ret = rand.cb(k->data, k->dsize, rand.usr);
	if (ret)
		WD_ERR("failed to rand cb: ret = %d!\n", ret);

	return ret;
}

static struct wcrypto_ecc_in *new_sign_in(struct wcrypto_ecc_ctx *ctx,
					  struct wd_dtb *e, struct wd_dtb *k,
					  __u8 is_dgst)
{
	struct wcrypto_ecc_sign_in *sin;
	struct wcrypto_ecc_in *ecc_in;
	int ret;

	if (!ctx || !e) {
		WD_ERR("failed to new ecc sign in: ctx or e NULL!\n");
		return NULL;
	}

	ecc_in = create_ecc_in(ctx, ECC_SIGN_IN_PARAM_NUM);
	if (!ecc_in)
		return NULL;

	sin = &ecc_in->param.sin;
	if (!k && ctx->setup.rand.cb) {
		ret = generate_random(ctx, &sin->k);
		if (ret) {
			release_ecc_in(ctx, ecc_in);
			return NULL;
		}
	}

	if (k || ctx->setup.rand.cb)
		sin->k_set = 1;

	ret = set_sign_in_param(sin, e, k);
	if (ret) {
		release_ecc_in(ctx, ecc_in);
		return NULL;
	}

	return ecc_in;
}

struct wcrypto_ecc_in *wcrypto_new_ecdsa_sign_in(void *ctx,
						 struct wd_dtb *dgst,
						 struct wd_dtb *k)
{
	return new_sign_in(ctx, dgst, k, 1);
}

static int set_verf_in_param(struct wcrypto_ecc_verf_in *vin,
			     struct wd_dtb *e,
			     struct wd_dtb *r,
			     struct wd_dtb *s)
{
	int ret;

	ret = set_param_single(&vin->e, e);
	if (ret) {
		WD_ERR("set ecc vin e err!\n");
		return ret;
	}

	ret = set_param_single(&vin->s, s);
	if (ret) {
		WD_ERR("set ecc vin s err!\n");
		return ret;
	}

	ret = set_param_single(&vin->r, r);
	if (ret)
		WD_ERR("set ecc vin r err!\n");

	return ret;
}

static struct wcrypto_ecc_in *new_verf_in(struct wcrypto_ecc_ctx *ctx,
					  struct wd_dtb *e, struct wd_dtb *r,
					  struct wd_dtb *s, __u8 is_dgst)
{
	struct wcrypto_ecc_verf_in *vin;
	struct wcrypto_ecc_in *ecc_in;
	int ret;

	if (!ctx || !r || !e || !s) {
		WD_ERR("new ecc verf in param error!\n");
		return NULL;
	}

	ecc_in = create_ecc_in(ctx, ECC_VERF_IN_PARAM_NUM);
	if (!ecc_in)
		return NULL;

	vin = &ecc_in->param.vin;
	ret = set_verf_in_param(vin, e, r, s);
	if (ret) {
		release_ecc_in(ctx, ecc_in);
		return NULL;
	}

	return ecc_in;
}

struct wcrypto_ecc_in *wcrypto_new_ecdsa_verf_in(void *ctx,
						 struct wd_dtb *dgst,
						 struct wd_dtb *r,
						 struct wd_dtb *s)
{
	return new_verf_in(ctx, dgst, r, s, 1);
}

struct wcrypto_ecc_out *wcrypto_new_ecdsa_sign_out(void *ctx)
{
	struct wcrypto_ecc_out *ecc_out;

	if (!ctx) {
		WD_ERR("new ecc sout ctx NULL!\n");
		return NULL;
	}

	ecc_out = create_ecc_out(ctx, ECC_SIGN_OUT_PARAM_NUM);
	if (!ecc_out) {
		WD_ERR("create ecc out err!\n");
		return NULL;
	}

	return ecc_out;
}

void wcrypto_get_ecdsa_verf_in_params(struct wcrypto_ecc_in *in,
				      struct wd_dtb **dgst,
				      struct wd_dtb **r,
				      struct wd_dtb **s)
{
	struct wcrypto_ecc_verf_in *vin = (void *)in;

	if (!in) {
		WD_ERR("input NULL in get verf in!\n");
		return;
	}

	if (dgst)
		*dgst = &vin->e;

	if (r)
		*r = &vin->r;

	if (s)
		*s = &vin->s;
}

void wcrypto_get_ecdsa_sign_in_params(struct wcrypto_ecc_in *in,
				      struct wd_dtb **dgst,
				      struct wd_dtb **k)
{
	struct wcrypto_ecc_sign_in *sin = (void *)in;

	if (!in) {
		WD_ERR("input NULL in get sign in!\n");
		return;
	}

	if (dgst)
		*dgst = &sin->e;

	if (k)
		*k = &sin->k;
}

int wcrypto_do_ecdsa(void *ctx, struct wcrypto_ecc_op_data *opdata, void *tag)
{
	if (!opdata) {
		WD_ERR("do ecdsa: opdata null!\n");
		return -WD_EINVAL;
	}

	if (opdata->op_type != WCRYPTO_ECDSA_SIGN &&
	    opdata->op_type != WCRYPTO_ECDSA_VERIFY) {
		WD_ERR("do ecdsa: op_type = %d error!\n", opdata->op_type);
		return -WD_EINVAL;
	}

	return do_ecc(ctx, opdata, tag, 0);
}

int wcrypto_ecdsa_poll(struct wd_queue *q, unsigned int num)
{
	return ecc_poll(q, num);
}
