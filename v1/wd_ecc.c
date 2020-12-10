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
#define BYTES_TO_BITS(bytes)		((bytes) << 3)
#define ECC_MAX_KEY_BITS		521
#define ECC_MAX_KEY_SIZE		BITS_TO_BYTES(ECC_MAX_KEY_BITS)
#define ECC_MAX_IN_NUM			4
#define ECC_MAX_OUT_NUM			4
#define CURVE_PARAM_NUM			6
#define ECC_POINT_NUM			2
#define WD_ARRAY_SIZE(array)		(sizeof(array) / sizeof(array[0]))
#define MAX_CURVE_SIZE			(ECC_MAX_KEY_SIZE * CURVE_PARAM_NUM)
#define MAX_HASH_LENS			ECC_MAX_KEY_SIZE
#define SM2_KEY_SIZE			32

#define CURVE_X25519			0x1
#define CURVE_X448			0x2
#define CURVE_SM2P256			0x3

static __thread int balance;

struct curve_param_desc {
	__u32 type;
	__u32 prk_offset;
	__u32 pbk_offset;
};

enum wcrypto_ecc_curve_param_type {
	ECC_CURVE_P,
	ECC_CURVE_A,
	ECC_CURVE_B,
	ECC_CURVE_N,
	ECC_CURVE_G
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
	unsigned long ctx_id;
	struct wd_queue *q;
	struct wcrypto_ecc_key key;
	struct wcrypto_ecc_ctx_setup setup;
};

struct wcrypto_ecc_curve_list {
	__u32 id;
	char *name;
	__u32 key_bits;
	__u8 data[MAX_CURVE_SIZE];
};

static const struct wcrypto_ecc_curve_list g_curve_list[] = {
	{
		.id = CURVE_X25519,
		.name = "x25519",
		.key_bits = 256,
		.data = X25519_256_PARAM,
	}, {
		.id = CURVE_X448,
		.name = "x448",
		.key_bits = 448,
		.data = X448_448_PARAM,
	}, {
		.id = WCRYPTO_SECP128R1,
		.name = "secp128r1",
		.key_bits = 128,
		.data = SECG_P128_R1_PARAM,
	}, {
		.id = WCRYPTO_SECP192K1,
		.name = "secp192k1",
		.key_bits = 192,
		.data = SECG_P192_K1_PARAM,
	}, {
		.id = WCRYPTO_SECP256K1,
		.name = "secp256k1",
		.key_bits = 256,
		.data = SECG_P256_K1_PARAM,
	}, {
		.id = WCRYPTO_BRAINPOOLP320R1,
		.name = "bpP320r1",
		.key_bits = 320,
		.data = BRAINPOOL_P320_R1_PARAM,
	}, {
		.id = WCRYPTO_BRAINPOOLP384R1,
		.name = "bpP384r1",
		.key_bits = 384,
		.data = BRAINPOOL_P384_R1_PARAM,
	}, {
		.id = WCRYPTO_SECP521R1,
		.name = "secp521r1",
		.key_bits = 521,
		.data = NIST_P521_R1_PARAM,
	}, {
		.id = CURVE_SM2P256,
		.name = "sm2",
		.key_bits = 256,
		.data = SM2_P256_V1_PARAM,
	}
};

static const struct curve_param_desc g_cv_param_list[] = {
	{
		.type = ECC_CURVE_P,
		.prk_offset = (__u32)offsetof(struct wcrypto_ecc_prikey, p),
		.pbk_offset = (__u32)offsetof(struct wcrypto_ecc_pubkey, p),
	}, {
		.type = ECC_CURVE_A,
		.prk_offset = (__u32)offsetof(struct wcrypto_ecc_prikey, a),
		.pbk_offset = (__u32)offsetof(struct wcrypto_ecc_pubkey, a),
	}, {
		.type = ECC_CURVE_B,
		.prk_offset = (__u32)offsetof(struct wcrypto_ecc_prikey, b),
		.pbk_offset = (__u32)offsetof(struct wcrypto_ecc_pubkey, b),
	}, {
		.type = ECC_CURVE_N,
		.prk_offset = (__u32)offsetof(struct wcrypto_ecc_prikey, n),
		.pbk_offset = (__u32)offsetof(struct wcrypto_ecc_pubkey, n),
	}, {
		.type = ECC_CURVE_G,
		.prk_offset = (__u32)offsetof(struct wcrypto_ecc_prikey, g),
		.pbk_offset = (__u32)offsetof(struct wcrypto_ecc_pubkey, g),
	}
};

static int trans_to_binpad(char *dst, const char *src,
			   __u32 b_size, __u32 d_size, const char *p_name)
{
	int i = d_size - 1;
	int j;

	if (!dst || !src || !b_size || !d_size || b_size < d_size) {
		WD_ERR("%s: trans to binpad params err!\n", p_name);
		return -WD_EINVAL;
	}

	if (dst == src)
		return WD_SUCCESS;

	for (j = b_size - 1; j >= 0; j--, i--) {
		if (i >= 0)
			dst[j] = src[i];
		else
			dst[j] = 0;
	}

	return WD_SUCCESS;
}

static void wd_memset_zero(void *data, __u32 size)
{
	char *s = data;

	if (unlikely(!s))
		return;

	while (size--)
		*s++ = 0;
}

static void *br_alloc(struct wd_mm_br *br, __u64 size)
{
	if (unlikely(!br->alloc)) {
		WD_ERR("br alloc NULL!\n");
		return NULL;
	}

	if (br->get_bufsize && br->get_bufsize(br->usr) < size) {
		WD_ERR("Blk_size < need_size<0x%llx>.\n", size);
		return NULL;
	}

	return br->alloc(br->usr, size);
}

static void br_free(struct wd_mm_br *br, void *va)
{
	if (!br->free) {
		WD_ERR("br free NULL!\n");
		return;
	}

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
		WD_ERR("failed to get hw keysize : ksz = %u.\n", ksz);

	return size;
}

static __u32 get_hash_bytes(__u8 type)
{
	__u32 val = 0;

	switch (type) {
	case WCRYPTO_HASH_MD4:
	case WCRYPTO_HASH_MD5:
		val = BITS_TO_BYTES(128);
		break;
	case WCRYPTO_HASH_SHA1:
		val = BITS_TO_BYTES(160);
		break;
	case WCRYPTO_HASH_SHA224:
		val = BITS_TO_BYTES(224);
		break;
	case WCRYPTO_HASH_SHA256:
	case WCRYPTO_HASH_SM3:
		val = BITS_TO_BYTES(256);
		break;
	case WCRYPTO_HASH_SHA384:
		val = BITS_TO_BYTES(384);
		break;
	case WCRYPTO_HASH_SHA512:
		val = BITS_TO_BYTES(512);
		break;
	default:
		break;
	}

	return val;
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
	if (unlikely(!prikey)) {
		WD_ERR("failed to malloc!\n");
		return NULL;
	}

	memset(prikey, 0, sizeof(struct wcrypto_ecc_prikey));
	dsz = ECC_PRIKEY_SZ(hsz);
	data = br_alloc(br, dsz);
	if (unlikely(!data)) {
		WD_ERR("failed to br alloc, sz = %u!\n", dsz);
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
	if (unlikely(!pubkey)) {
		WD_ERR("failed to malloc!\n");
		return NULL;
	}

	memset(pubkey, 0, sizeof(struct wcrypto_ecc_pubkey));
	dsz = ECC_PUBKEY_SZ(hsz);
	data = br_alloc(br, dsz);
	if (unlikely(!data)) {
		WD_ERR("failed to br alloc, sz = %u!\n", dsz);
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

	if (unlikely(!ctx->key_size || ctx->key_size > ECC_MAX_KEY_SIZE)) {
		WD_ERR("ctx key size %u error!\n", ctx->key_size);
		return NULL;
	}

	hsz = get_hw_keysize(ctx->key_size);
	len = sizeof(struct wcrypto_ecc_in) + hsz * num;
	in = br_alloc(br, len);
	if (unlikely(!in)) {
		WD_ERR("failed to br alloc, sz = %u!\n", len);
		return NULL;
	}

	memset(in, 0, len);
	in->size = hsz * num;
	init_dtb_param(in, in->data, ctx->key_size, hsz, num);

	return in;
}

static struct wcrypto_ecc_in *create_sm2_sign_in(struct wcrypto_ecc_ctx *ctx,
						 __u32 m_len)
{
	struct wd_mm_br *br = &ctx->setup.br;
	struct wd_dtb *dgst, *k, *plaintext;
	struct wcrypto_ecc_in *in;
	__u32 hsz;
	__u64 len;

	if (unlikely(!ctx->key_size || ctx->key_size > ECC_MAX_KEY_SIZE)) {
		WD_ERR("ctx key size %u error!\n", ctx->key_size);
		return NULL;
	}

	hsz = get_hw_keysize(ctx->key_size);
	len = sizeof(struct wcrypto_ecc_in)
		+ ECC_SIGN_IN_PARAM_NUM * hsz + (__u64)m_len;
	in = br_alloc(br, len);
	if (unlikely(!in)) {
		WD_ERR("failed to br alloc, sz = %llu!\n", len);
		return NULL;
	}

	in->size = len - sizeof(struct wcrypto_ecc_in);
	dgst = (struct wd_dtb *)in;
	dgst->data = in->data;
	dgst->dsize = ctx->key_size;
	dgst->bsize = hsz;

	k = dgst + 1;
	k->data = dgst->data + hsz;
	k->dsize = ctx->key_size;
	k->bsize = hsz;

	plaintext = k + 1;
	plaintext->data = k->data + hsz;
	plaintext->dsize = m_len;
	plaintext->bsize = m_len;

	return in;
}

static struct wcrypto_ecc_in *create_sm2_enc_in(struct wcrypto_ecc_ctx *ctx,
						__u32 m_len)
{
	struct wd_mm_br *br = &ctx->setup.br;
	struct wd_dtb *k, *plaintext;
	struct wcrypto_ecc_in *in;
	__u32 ksz = ctx->key_size;
	__u64 len;

	if (unlikely(!ksz || ksz > ECC_MAX_KEY_SIZE)) {
		WD_ERR("ctx key size %u error!\n", ksz);
		return NULL;
	}

	len = sizeof(struct wcrypto_ecc_in) + ksz + m_len;
	in = br_alloc(br, len);
	if (unlikely(!in)) {
		WD_ERR("failed to br alloc, sz = %llu!\n", len);
		return NULL;
	}

	in->size = ksz + m_len;
	k = (struct wd_dtb *)in;
	k->data = in->data;
	k->dsize = ksz;
	k->bsize = ksz;

	plaintext = k + 1;
	plaintext->data = k->data + ksz;
	plaintext->dsize = m_len;
	plaintext->bsize = m_len;

	return in;
}

static void *create_sm2_ciphertext(struct wcrypto_ecc_ctx *ctx, __u32 m_len,
				   __u64 *len, __u32 st_sz)
{
	struct wcrypto_hash_mt *hash = &ctx->setup.hash;
	struct wcrypto_ecc_point *c1;
	__u32 ksz = ctx->key_size;
	struct wd_dtb *c3, *c2;
	__u32 h_byts;
	void *start;

	if (unlikely(!ksz || ksz > ECC_MAX_KEY_SIZE)) {
		WD_ERR("ctx key size %u error!\n", ksz);
		return NULL;
	}

	h_byts = get_hash_bytes(hash->type);
	if (!h_byts) {
		WD_ERR("failed to get hash bytes, type = %u!\n", hash->type);
		return NULL;
	}

	*len = st_sz + ECC_POINT_PARAM_NUM * ctx->key_size + m_len + h_byts;
	start = br_alloc(&ctx->setup.br, *len);
	if (unlikely(!start)) {
		WD_ERR("failed to br alloc, sz = %llu!\n", *len);
		return NULL;
	}

	c1 = (struct wcrypto_ecc_point *)start;
	c1->x.data = start + st_sz;
	c1->x.dsize = ksz;
	c1->x.bsize = ksz;
	c1->y.data = c1->x.data + ksz;
	c1->y.dsize = ksz;
	c1->y.bsize = ksz;

	c2 = (struct wd_dtb *)(c1 + 1);
	c2->data = c1->y.data + ksz;
	c2->dsize = m_len;
	c2->bsize = m_len;

	c3 = c2 + 1;
	c3->data = c2->data + m_len;
	c3->dsize = h_byts;
	c3->bsize = h_byts;

	return start;
}

static struct wcrypto_ecc_in *create_ecc_sign_in(struct wcrypto_ecc_ctx *ctx,
						 __u32 m_len, __u8 is_dgst)
{
	if (is_dgst)
		return create_ecc_in(ctx, ECC_SIGN_IN_PARAM_NUM);
	else
		return create_sm2_sign_in(ctx, m_len);
}

static struct wcrypto_ecc_out *create_ecc_out(struct wcrypto_ecc_ctx *ctx,
					      __u32 num)
{
	struct wd_mm_br *br = &ctx->setup.br;
	struct wcrypto_ecc_out *out;
	__u32 hsz, len;

	if (!ctx->key_size || ctx->key_size > ECC_MAX_KEY_SIZE) {
		WD_ERR("ctx key size %u error!\n", ctx->key_size);
		return NULL;
	}

	hsz = get_hw_keysize(ctx->key_size);
	len = sizeof(struct wcrypto_ecc_out) + hsz * num;
	out = br_alloc(br, len);
	if (unlikely(!out)) {
		WD_ERR("failed to br alloc, sz = %u!\n", len);
		return NULL;
	}

	memset(out, 0, len);
	out->size = hsz * num;
	init_dtb_param(out, out->data, ctx->key_size, hsz, num);

	return out;
}

static struct wcrypto_ecc_curve *create_ecc_curve(struct wcrypto_ecc_ctx *ctx)
{
	struct wcrypto_ecc_curve *cv;
	__u32 ksize, len;

	ksize = ctx->key_size;
	len = sizeof(*cv) + ksize * CURVE_PARAM_NUM;
	cv = malloc(len);
	if (unlikely(!cv)) {
		WD_ERR("failed to malloc!\n");
		return NULL;
	}

	init_dtb_param(cv, (void *)(cv + 1), ksize, ksize, CURVE_PARAM_NUM);

	return cv;
}

static struct wcrypto_ecc_point *create_ecc_pub(struct wcrypto_ecc_ctx *ctx)
{
	struct wcrypto_ecc_point *pub;
	__u32 ksize, len;

	ksize = ctx->key_size;
	len = sizeof(*pub) + ksize * ECC_POINT_NUM;
	pub = malloc(len);
	if (unlikely(!pub)) {
		WD_ERR("failed to malloc!\n");
		return NULL;
	}

	init_dtb_param(pub, (void *)(pub + 1), ksize, ksize, ECC_POINT_NUM);

	return pub;
}

static struct wd_dtb *create_ecc_d(struct wcrypto_ecc_ctx *ctx)
{
	struct wd_dtb *d;
	__u32 ksize, len;

	ksize = ctx->key_size;
	len = sizeof(*d) + ksize;
	d = malloc(len);
	if (unlikely(!d)) {
		WD_ERR("failed to malloc!\n");
		return NULL;
	}

	memset(d, 0, len);
	init_dtb_param(d, (void *)(d + 1), ksize, ksize, 1);

	return d;
}

static void release_ecc_curve(struct wcrypto_ecc_ctx *ctx)
{
	free(ctx->key.cv);
	ctx->key.cv = NULL;
}

static void release_ecc_pub(struct wcrypto_ecc_ctx *ctx)
{
	free(ctx->key.pub);
	ctx->key.pub = NULL;
}

static void release_ecc_d(struct wcrypto_ecc_ctx *ctx)
{
	wd_memset_zero(ctx->key.d + 1, ctx->key_size);
	free(ctx->key.d);
	ctx->key.d = NULL;
}

static int set_param_single(struct wd_dtb *dst, const struct wd_dtb *src,
			    const char *p_name)
{
	if (unlikely(!src || !src->data)) {
		WD_ERR("%s: src or data NULL!\n", p_name);
		return -WD_EINVAL;
	}

	if (unlikely(!src->dsize || src->dsize > dst->dsize)) {
		WD_ERR("%s: src dsz = %u error, dst dsz = %u!\n",
			p_name, src->dsize, dst->dsize);
		return -WD_EINVAL;
	}

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

	if (unlikely(!cx || !in)) {
		WD_ERR("new ecc dh in param error!\n");
		return NULL;
	}

	ecc_in = create_ecc_in(cx, ECDH_IN_PARAM_NUM);
	if (unlikely(!ecc_in)) {
		WD_ERR("failed to create ecc in!\n");
		return NULL;
	}

	dh_in = &ecc_in->param.dh_in;
	ret = set_param_single(&dh_in->pbk.x, &in->x, "ecdh in x");
	if (unlikely(ret)) {
		release_ecc_in(ctx, ecc_in);
		return NULL;
	}

	ret = set_param_single(&dh_in->pbk.y, &in->y, "ecdh in y");
	if (unlikely(ret)) {
		release_ecc_in(ctx, ecc_in);
		return NULL;
	}

	return ecc_in;
}

struct wcrypto_ecc_out *wcrypto_new_ecxdh_out(void *ctx)
{
	struct wcrypto_ecc_out *ecc_out;

	if (unlikely(!ctx)) {
		WD_ERR("new ecc dh out ctx NULL!\n");
		return NULL;
	}

	ecc_out = create_ecc_out(ctx, ECDH_OUT_PARAM_NUM);
	if (unlikely(!ecc_out))
		WD_ERR("failed to create ecc out!\n");

	return ecc_out;
}

int wcrypto_get_ecc_key_bits(const void *ctx)
{
	if (unlikely(!ctx)) {
		WD_ERR("get ecc key bits, ctx NULL!\n");
		return -WD_EINVAL;
	}

	return ((struct wcrypto_ecc_ctx *)ctx)->setup.key_bits;
}

static int set_curve_param_single(struct wcrypto_ecc_key *key,
				  const struct wd_dtb *param,
				  __u32 type)
{
	struct wcrypto_ecc_prikey *prk = key->prikey;
	struct wcrypto_ecc_pubkey *pbk = key->pubkey;
	struct wd_dtb *t1, *t2;
	int ret;

	t1 = (struct wd_dtb *)((char *)prk + g_cv_param_list[type].prk_offset);
	t2 = (struct wd_dtb *)((char *)pbk + g_cv_param_list[type].pbk_offset);

	/* set gy */
	if (type == ECC_CURVE_G) {
		ret = set_param_single(t1 + 1, param + 1, "set cv");
		if (unlikely(ret))
			return ret;

		ret = set_param_single(t2 + 1, param + 1, "set cv");
		if (unlikely(ret))
			return ret;
	}

	ret = set_param_single(t1, param, "set cv");
	if (unlikely(ret))
		return ret;

	return set_param_single(t2, param, "set cv");
}

static int set_curve_param(struct wcrypto_ecc_key *key,
			   const struct wcrypto_ecc_curve *param)
{
	int ret;

	ret = set_curve_param_single(key, &param->p, ECC_CURVE_P);
	if (unlikely(ret)) {
		WD_ERR("failed to set curve param: p error!\n");
		return -WD_EINVAL;
	}

	ret = set_curve_param_single(key, &param->a, ECC_CURVE_A);
	if (unlikely(ret)) {
		WD_ERR("failed to set curve param: a error!\n");
		return -WD_EINVAL;
	}

	ret = set_curve_param_single(key, &param->b, ECC_CURVE_B);
	if (unlikely(ret)) {
		WD_ERR("failed to set curve param: b error!\n");
		return -WD_EINVAL;
	}

	ret = set_curve_param_single(key, &param->n, ECC_CURVE_N);
	if (unlikely(ret)) {
		WD_ERR("failed to set curve param: n error!\n");
		return -WD_EINVAL;
	}

	ret = set_curve_param_single(key, (void *)&param->g, ECC_CURVE_G);
	if (unlikely(ret)) {
		WD_ERR("failed to set curve param: g error!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static const struct wcrypto_ecc_curve_list *find_curve_list(__u32 id)
{
	int len = WD_ARRAY_SIZE(g_curve_list);
	int i = 0;

	while (i < len) {
		if (g_curve_list[i].id == id)
			return &g_curve_list[i];
		i++;
	}

	return NULL;
}

static int fill_param_by_id(struct wcrypto_ecc_curve *c,
			    __u16 key_bits, __u32 id)
{
	const struct wcrypto_ecc_curve_list *item;
	__u32 key_size;

	item = find_curve_list(id);
	if (unlikely(!item)) {
		WD_ERR("failed to find curve id %u!\n", id);
		return -WD_EINVAL;
	}

	if (unlikely(item->key_bits != key_bits)) {
		WD_ERR("curve %u and key bits %hu not match!\n", id, key_bits);
		return -WD_EINVAL;
	}

	key_size = BITS_TO_BYTES(item->key_bits);
	memcpy(c->p.data, item->data, CURVE_PARAM_NUM * key_size);

	return 0;
}

static int set_key_cv(struct wcrypto_ecc_curve *dst,
		      struct wcrypto_ecc_curve *src)
{
	int ret;

	if (unlikely(!src)) {
		WD_ERR("set key cv: input param NULL!\n");
		return -WD_EINVAL;
	}

	ret = set_param_single(&dst->p, &src->p, "cv p");
	if (unlikely(ret))
		return ret;

	ret = set_param_single(&dst->a, &src->a, "cv a");
	if (unlikely(ret))
		return ret;

	ret = set_param_single(&dst->b, &src->b, "cv b");
	if (unlikely(ret))
		return ret;

	ret = set_param_single(&dst->g.x, &src->g.x, "cv gx");
	if (unlikely(ret))
		return ret;

	ret = set_param_single(&dst->g.y, &src->g.y, "cv gy");
	if (unlikely(ret))
		return ret;

	return set_param_single(&dst->n, &src->n, "cv n");
}

static int fill_user_curve_cfg(struct wcrypto_ecc_curve *param,
			       struct wcrypto_ecc_ctx_setup *setup,
			       const char *alg)
{
	struct wcrypto_ecc_curve *src_param = setup->cv.cfg.pparam;
	__u32 curve_id;
	int ret = 0;

	if (setup->cv.type == WCRYPTO_CV_CFG_ID) {
		curve_id = setup->cv.cfg.id;
		ret = fill_param_by_id(param, setup->key_bits, curve_id);
		dbg("set curve id %u\n", curve_id);
	} else if (setup->cv.type == WCRYPTO_CV_CFG_PARAM) {
		ret = set_key_cv(param, src_param);
		if (unlikely(ret)) {
			WD_ERR("failed to set key cv!\n");
			return ret;
		}
		dbg("set curve by user param\n");
	} else {
		WD_ERR("fill curve cfg:type %u error!\n", setup->cv.type);
		return -WD_EINVAL;
	}

	if (unlikely(!param->p.dsize ||
		param->p.dsize > BITS_TO_BYTES(setup->key_bits))) {
		WD_ERR("fill curve cfg:dsize %u error!\n", param->p.dsize);
		return -WD_EINVAL;
	}

	return ret;
}

static int create_ctx_key(struct wcrypto_ecc_ctx_setup *setup,
			  struct wcrypto_ecc_ctx *ctx)
{
	int ret = -WD_ENOMEM;

	ctx->key.prikey = create_ecc_prikey(ctx);
	if (unlikely(!ctx->key.prikey))
		return -WD_ENOMEM;

	ctx->key.pubkey = create_ecc_pubkey(ctx);
	if (unlikely(!ctx->key.pubkey))
		goto free_prikey;

	ctx->key.cv = create_ecc_curve(ctx);
	if (unlikely(!ctx->key.cv))
		goto free_pubkey;

	ctx->key.pub = create_ecc_pub(ctx);
	if (unlikely(!ctx->key.pub))
		goto free_curve;

	ctx->key.d = create_ecc_d(ctx);
	if (unlikely(!ctx->key.d))
		goto free_pub;

	ret = fill_user_curve_cfg(ctx->key.cv, setup, ctx->q->capa.alg);
	if (unlikely(ret)) {
		WD_ERR("failed to fill user curve cfg!\n");
		goto free_d;
	}

	ret = set_curve_param(&ctx->key, ctx->key.cv);
	if (unlikely(ret)) {
		WD_ERR("failed to set curve param!\n");
		goto free_d;
	}

	return 0;

free_d:
	release_ecc_d(ctx);

free_pub:
	release_ecc_pub(ctx);

free_curve:
	release_ecc_curve(ctx);

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
		setup->key_bits = 256; /* x25519 fixed key width */
		setup->cv.type = WCRYPTO_CV_CFG_ID;
		setup->cv.cfg.id = CURVE_X25519;
	} else if (!strcmp(alg, "x448")) {
		setup->key_bits = 448; /* x448 fixed key width */
		setup->cv.type = WCRYPTO_CV_CFG_ID;
		setup->cv.cfg.id = CURVE_X448;
	} else if ((!strcmp(alg, "sm2"))) {
		setup->key_bits = 256;
		setup->cv.type = WCRYPTO_CV_CFG_ID;
		setup->cv.cfg.id = CURVE_SM2P256;
	}
}

static bool is_alg_support(const char *alg)
{
	if (unlikely(strcmp(alg, "ecdh") &&
		strcmp(alg, "ecdsa") &&
		strcmp(alg, "x25519") &&
		strcmp(alg, "x448") &&
		strcmp(alg, "sm2")))
		return false;

	return true;
}

static bool is_key_width_support(__u32 key_bits)
{
	/* key bit width check */
	if (unlikely(key_bits != 128 &&
		key_bits != 192 &&
		key_bits != 256 &&
		key_bits != 320 &&
		key_bits != 384 &&
		key_bits != 448 &&
		key_bits != 521))
		return false;

	return true;
}

static int param_check(struct wd_queue *q, struct wcrypto_ecc_ctx_setup *setup)
{
	if (unlikely(!q || !setup)) {
		WD_ERR("input param error!\n");
		return -WD_EINVAL;
	}

	if (unlikely(!setup->br.alloc || !setup->br.free)) {
		WD_ERR("user mm br error!\n");
		return -WD_EINVAL;
	}

	if (unlikely(!is_alg_support(q->capa.alg))) {
		WD_ERR("alg %s mismatching!\n", q->capa.alg);
		return -WD_EINVAL;
	}

	setup_curve_cfg(setup, q->capa.alg);

	if (unlikely(!is_key_width_support(setup->key_bits))) {
		WD_ERR("key_bits %u error!\n", setup->key_bits);
		return -WD_EINVAL;
	}

	return 0;
}

static void del_ctx_key(struct wd_mm_br *br,
			struct wcrypto_ecc_ctx *ctx)
{
	if (unlikely(!br->free))
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
	__u32 hsz = get_hw_keysize(ctx->key_size);
	struct q_info *qinfo = ctx->q->qinfo;
	int i;

	for (i = 0; i < WD_ECC_CTX_MSG_NUM; i++) {
		ctx->cookies[i].msg.curve_id = setup->cv.cfg.id;
		ctx->cookies[i].msg.data_fmt = setup->data_fmt;
		ctx->cookies[i].msg.key_bytes = hsz;
		ctx->cookies[i].msg.hash_type = setup->hash.type;
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
	qinfo->hash = setup->hash;
	/* lock at ctx  creating/deleting */
	wd_spinlock(&qinfo->qlock);
	if (!qinfo->br.alloc && !qinfo->br.iova_map)
		memcpy(&qinfo->br, &setup->br, sizeof(setup->br));
	if (qinfo->br.usr != setup->br.usr) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("Err mm br in creating ecc ctx!\n");
		return NULL;
	}

	if (unlikely(qinfo->ctx_num >= WD_ECC_MAX_CTX)) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("err:create too many ecc ctx!\n");
		return NULL;
	}

	cid = wd_alloc_ctx_id(q, WD_ECC_MAX_CTX);
	if (unlikely(cid < 0)) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("failed to alloc ctx id!\n");
		return NULL;
	}
	qinfo->ctx_num++;
	wd_unspinlock(&qinfo->qlock);

	ctx = malloc(sizeof(struct wcrypto_ecc_ctx));
	if (unlikely(!ctx)) {
		WD_ERR("failed to malloc!\n");
		goto free_ctx_id;
	}

	memset(ctx, 0, sizeof(struct wcrypto_ecc_ctx));
	memcpy(&ctx->setup, setup, sizeof(*setup));
	ctx->key_size = BITS_TO_BYTES(setup->key_bits);
	ctx->q = q;
	ctx->ctx_id = cid;
	ret = create_ctx_key(setup, ctx);
	if (unlikely(ret)) {
		WD_ERR("failed to create ecc ctx keys!\n");
		free(ctx);
		goto free_ctx_id;
	}

	init_ctx_cookies(ctx, setup);

	return ctx;

free_ctx_id:
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	wd_free_ctx_id(q, cid);
	return NULL;
}

void wcrypto_del_ecc_ctx(void *ctx)
{
	struct wcrypto_ecc_ctx *cx;
	struct wd_mm_br *br;
	struct q_info *qinfo;

	if (unlikely(!ctx)) {
		WD_ERR("Delete ecc param err!\n");
		return;
	}

	cx = ctx;
	br = &cx->setup.br;
	qinfo = cx->q->qinfo;
	wd_spinlock(&qinfo->qlock);
	if (unlikely(qinfo->ctx_num <= 0)) {
		WD_ERR("error:repeat del ecc ctx ctx!\n");
		wd_unspinlock(&qinfo->qlock);
		return;
	}

	wd_free_ctx_id(cx->q, cx->ctx_id);
	if (!(--qinfo->ctx_num))
		memset(&qinfo->br, 0, sizeof(qinfo->br));
	wd_unspinlock(&qinfo->qlock);

	del_ctx_key(br, cx);
	free(cx);
}

struct wcrypto_ecc_key *wcrypto_get_ecc_key(void *ctx)
{
	struct wcrypto_ecc_ctx *cx = ctx;

	if (unlikely(!cx)) {
		WD_ERR("get ecc key ctx NULL!\n");
		return NULL;
	}

	return &cx->key;
}

int wcrypto_set_ecc_prikey(struct wcrypto_ecc_key *ecc_key,
			   struct wd_dtb *prikey)
{
	struct wcrypto_ecc_prikey *ecc_prikey;
	struct wd_dtb *d;
	int ret;

	if (unlikely(!ecc_key || !prikey)) {
		WD_ERR("set ecc prikey param NULL!\n");
		return -WD_EINVAL;
	}

	ecc_prikey = ecc_key->prikey;
	d = ecc_key->d;
	if (unlikely(!ecc_prikey || !d)) {
		WD_ERR("ecc_prikey or d NULL!\n");
		return -WD_EINVAL;
	}

	ret = set_param_single(&ecc_prikey->d, prikey, "ecc set prikey d");
	if (unlikely(ret))
		return ret;

	return set_param_single(d, prikey, "ecc set d");
}

int wcrypto_get_ecc_prikey(struct wcrypto_ecc_key *ecc_key,
			   struct wd_dtb **prikey)
{
	if (unlikely(!ecc_key || !prikey)) {
		WD_ERR("get ecc prikey param err!\n");
		return -WD_EINVAL;
	}

	*prikey = ecc_key->d;

	return WD_SUCCESS;
}

int wcrypto_set_ecc_pubkey(struct wcrypto_ecc_key *ecc_key,
			   struct wcrypto_ecc_point *pubkey)
{
	struct wcrypto_ecc_pubkey *ecc_pubkey;
	struct wcrypto_ecc_point *pub;
	int ret;

	if (unlikely(!ecc_key || !pubkey)) {
		WD_ERR("set ecc pubkey param err!\n");
		return -WD_EINVAL;
	}

	pub = ecc_key->pub;
	ecc_pubkey = ecc_key->pubkey;
	if (!ecc_pubkey || !pub) {
		WD_ERR("ecc_pubkey or pub NULL!\n");
		return -WD_EINVAL;
	}

	ret = set_param_single(&ecc_pubkey->pub.x, &pubkey->x, "ecc pubkey x");
	if (unlikely(ret))
		return ret;

	ret = set_param_single(&ecc_pubkey->pub.y, &pubkey->y, "ecc pubkey y");
	if (unlikely(ret))
		return ret;

	ret = trans_to_binpad(pub->x.data, pubkey->x.data,
			      pub->x.bsize, pubkey->x.dsize, "ecc pub x");
	if (unlikely(ret))
		return ret;

	return trans_to_binpad(pub->y.data, pubkey->y.data,
			      pub->y.bsize, pubkey->y.dsize, "ecc pub y");
}

int wcrypto_get_ecc_pubkey(struct wcrypto_ecc_key *ecc_key,
			   struct wcrypto_ecc_point **pubkey)
{
	if (unlikely(!ecc_key || !pubkey || !ecc_key->pub)) {
		WD_ERR("get ecc pubkey param err!\n");
		return -WD_EINVAL;
	}

	*pubkey = ecc_key->pub;

	return WD_SUCCESS;
}

int wcrypto_get_ecc_curve(struct wcrypto_ecc_key *ecc_key,
			   struct wcrypto_ecc_curve **cv)
{
	if (unlikely(!ecc_key || !cv || !ecc_key->cv)) {
		WD_ERR("get ecc pubkey param err!\n");
		return -WD_EINVAL;
	}

	*cv = ecc_key->cv;

	return WD_SUCCESS;
}

void wcrypto_get_ecc_prikey_params(struct wcrypto_ecc_key *key,
				  struct wd_dtb **p, struct wd_dtb **a,
				  struct wd_dtb **b, struct wd_dtb **n,
				  struct wcrypto_ecc_point **g,
				  struct wd_dtb **d)
{
	struct wcrypto_ecc_prikey *prk;

	if (unlikely(!key || !key->prikey)) {
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

	if (unlikely(!key || !key->pubkey)) {
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

	if (unlikely(!dh_out)) {
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

	if (unlikely(!ctx || !in)) {
		WD_ERR("del ecc in param error!\n");
		return;
	}

	bsz = in->size;
	if (unlikely(!bsz)) {
		WD_ERR("del ecc in: bsz 0!\n");
		return;
	}

	wd_memset_zero(in->data, bsz);
	br_free(&cx->setup.br, in);
}

void wcrypto_del_ecc_out(void *ctx,  struct wcrypto_ecc_out *out)
{
	struct wcrypto_ecc_ctx *cx = ctx;
	__u32 bsz;

	if (unlikely(!ctx || !out)) {
		WD_ERR("del ecc out param error!\n");
		return;
	}

	bsz = out->size;
	if (unlikely(!bsz)) {
		WD_ERR("del ecc out: bsz 0!\n");
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

	if (unlikely(idx < 0 || idx >= WD_ECC_CTX_MSG_NUM)) {
		WD_ERR("ecc cookie not exist!\n");
		return;
	}
	__atomic_clear(&ctx->cstatus[idx], __ATOMIC_RELEASE);
}

static int ecc_request_init(struct wcrypto_ecc_msg *req,
			    struct wcrypto_ecc_op_data *op,
			    struct wcrypto_ecc_ctx *c, __u8 need_hash)
{
	__u8 *key;

	req->in_bytes = (__u16)op->in_bytes;
	req->out = op->out;
	req->op_type = op->op_type;
	req->hash_type = c->setup.hash.type;
	req->result = WD_EINVAL;

	switch (req->op_type) {
	case WCRYPTO_ECXDH_GEN_KEY:
	case WCRYPTO_ECXDH_COMPUTE_KEY:
	case WCRYPTO_ECDSA_SIGN:
	case WCRYPTO_ECDSA_VERIFY:
	case WCRYPTO_SM2_ENCRYPT:
	case WCRYPTO_SM2_DECRYPT:
	case WCRYPTO_SM2_SIGN:
	case WCRYPTO_SM2_VERIFY:
	case WCRYPTO_SM2_KG:
		key = (__u8 *)&c->key;
		break;
	default:
		WD_ERR("ecc request op type = %hhu error!\n", req->op_type);
		return -WD_EINVAL;
	}
	req->key = key;

	if (req->op_type == WCRYPTO_ECXDH_GEN_KEY ||
		req->op_type == WCRYPTO_SM2_KG) {
		struct wcrypto_ecc_point *g = NULL;

		wcrypto_get_ecc_prikey_params((void *)key, NULL, NULL,
			NULL, NULL, &g, NULL);
		req->in = (void *)g;
	} else {
		req->in = op->in;
	}

	if (unlikely(!req->in ||
		(!req->out && (req->op_type != WCRYPTO_ECDSA_VERIFY &&
		req->op_type != WCRYPTO_SM2_VERIFY)))) {
		WD_ERR("req in/out NULL!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static void msg_pack(char *dst, __u64 dst_len, __u64 *out_len,
		     const void *src, __u32 src_len)
{
	if (unlikely(!src || !src_len))
		return;

	memcpy(dst + *out_len, src, src_len);
	*out_len += src_len;
}

static int ecc_send(struct wcrypto_ecc_ctx *ctx, struct wcrypto_ecc_msg *req)
{
	__u32 tx_cnt = 0;
	int ret;

	do {
		ret = wd_send(ctx->q, req);
		if (ret == -WD_EBUSY) {
			if (tx_cnt++ >= ECC_RESEND_CNT) {
				WD_ERR("failed to send: retry exit!\n");
				break;
			}
			usleep(1);
		} else if (unlikely(ret)) {
			WD_ERR("failed to send: send error = %d!\n", ret);
			break;
		}
	} while (ret);

	return ret;
}

static int ecc_sync_recv(struct wcrypto_ecc_ctx *ctx,
			 struct wcrypto_ecc_op_data *opdata)
{
	struct wcrypto_ecc_msg *resp;
	__u32 rx_cnt = 0;
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
		} else if (unlikely(ret < 0)) {
			WD_ERR("failed to recv: error = %d!\n", ret);
			return ret;
		}
	} while (!ret);

	balance = rx_cnt;
	opdata->out = resp->out;
	opdata->out_bytes = resp->out_bytes;
	opdata->status = resp->result;

	return GET_NEGATIVE(opdata->status);
}

static int do_ecc(void *ctx, struct wcrypto_ecc_op_data *opdata, void *tag,
		  __u8 need_hash)
{
	struct wcrypto_ecc_ctx *ctxt = ctx;
	struct wcrypto_ecc_cookie *cookie;
	struct wcrypto_ecc_msg *req;
	int ret = -WD_EINVAL;

	if (unlikely(!ctx)) {
		WD_ERR("do ecc param null!\n");
		return -WD_EINVAL;
	}

	cookie = get_ecc_cookie(ctxt);
	if (!cookie)
		return -WD_EBUSY;

	if (tag) {
		if (unlikely(!ctxt->setup.cb)) {
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
	if (unlikely(ret))
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

	do {
		ret = wd_recv(q, (void **)&resp);
		if (ret == 0)
			break;
		else if (unlikely(ret < 0)) {
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
	if (unlikely(!opdata)) {
		WD_ERR("do ecxdh: opdata null!\n");
		return -WD_EINVAL;
	}

	if (unlikely(opdata->op_type != WCRYPTO_ECXDH_GEN_KEY &&
		opdata->op_type != WCRYPTO_ECXDH_COMPUTE_KEY)) {
		WD_ERR("do ecxdh: op_type = %hhu error!\n", opdata->op_type);
		return -WD_EINVAL;
	}

	return do_ecc(ctx, opdata, tag, 0);
}

int wcrypto_ecxdh_poll(struct wd_queue *q, unsigned int num)
{
	if (unlikely(!q || (strcmp(q->capa.alg, "x25519") &&
		strcmp(q->capa.alg, "x448") &&
		strcmp(q->capa.alg, "ecdh")))) {
		WD_ERR("ecxdh poll: input param error!\n");
		return -WD_EINVAL;
	}

	return ecc_poll(q, num);
}

static void get_sign_out_params(struct wcrypto_ecc_out *out,
				struct wd_dtb **r, struct wd_dtb **s)
{
	struct wcrypto_ecc_sign_out *sout = (void *)out;

	if (unlikely(!sout)) {
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


static bool less_than_latter(struct wd_dtb *d, struct wd_dtb *n)
{
	int ret, shift;

	if (d->dsize != n->dsize)
		return d->dsize < n->dsize;

	shift = n->bsize - n->dsize;
	ret = memcmp(d->data + shift, n->data + shift, n->dsize);
	return ret < 0;
}

static bool is_all_zero(struct wd_dtb *p, struct wcrypto_ecc_ctx *ctx)
{
	int i;

	for (i = 0; i < p->dsize && i < ctx->key_size; i++) {
		if (p->data[i])
			return false;
	}

	return true;
}

static bool check_k_param(struct wd_dtb *k, struct wcrypto_ecc_ctx *ctx)
{
	struct wcrypto_ecc_curve *cv = NULL;
	int ret;

	if (unlikely(!k->data)) {
		WD_ERR("error: k->data NULL!\n");
		return false;
	}

	ret = wcrypto_get_ecc_curve(&ctx->key, &cv);
	if (unlikely(ret)) {
		WD_ERR("failed to get ecc curve!\n");
		return false;
	}

	if (unlikely(!less_than_latter(k, &cv->n))) {
		WD_ERR("error: k >= n\n");
		return false;
	}

	if (unlikely(is_all_zero(k, ctx))) {
		WD_ERR("error: k all zero\n");
		return false;
	}

	return true;
}

static int set_sign_in_param(struct wcrypto_ecc_sign_in *sin,
			     struct wd_dtb *dgst,
			     struct wd_dtb *k,
			     struct wd_dtb *plaintext,
			     struct wcrypto_ecc_ctx *ctx)
{
	int ret;

	if (k) {
		if (unlikely(!check_k_param(k, ctx)))
			return -WD_EINVAL;

		ret = set_param_single(&sin->k, k, "ecc sgn k");
		if (unlikely(ret))
			return ret;
	}

	if (dgst) {
		ret = set_param_single(&sin->dgst, dgst, "ecc sgn dgst");
		if (unlikely(ret))
			return ret;
	}

	if (plaintext && plaintext->dsize) {
		ret = set_param_single(&sin->plaintext, plaintext, "ecc sgn m");
		if (unlikely(ret))
			return ret;
	}

	return 0;
}

static int generate_random(struct wcrypto_ecc_ctx *ctx, struct wd_dtb *k)
{
	struct wcrypto_rand_mt *rand_mt = &ctx->setup.rand;
	int ret;

	ret = rand_mt->cb(k->data, k->dsize, rand_mt->usr);
	if (unlikely(ret))
		WD_ERR("failed to rand cb: ret = %d!\n", ret);

	return ret;
}

static int sm2_compute_za_hash(__u8 *za, __u32 *len, struct wd_dtb *id,
			       struct wcrypto_ecc_ctx *ctx)
{
	__u32 key_size = BITS_TO_BYTES(ctx->setup.key_bits);
	struct wcrypto_hash_mt *hash = &ctx->setup.hash;
	struct wcrypto_ecc_point *pub = ctx->key.pub;
	struct wcrypto_ecc_curve *cv = ctx->key.cv;
	__u16 id_bytes = 0;
	__u16 id_bits = 0;
	__u64 in_len = 0;
	__u32 hash_bytes;
	char *p_in;
	__u64 lens;
	__u8 temp;
	int ret;

	if (id && BYTES_TO_BITS(id->dsize) > UINT16_MAX) {
		WD_ERR("id lens = %u error!\n", id->dsize);
		return -WD_EINVAL;
	}

	if (id) {
		id_bits = BYTES_TO_BITS(id->dsize);
		id_bytes = id->dsize;
	}

#define REGULAR_LENS	(6 * key_size) /* a b xG yG xA yA */
	/* ZA = h(ENTL || ID || a || b || xG || yG || xA || yA) */
	lens = sizeof(__u16) + id_bytes + REGULAR_LENS;
	p_in = malloc(lens);
	if (unlikely(!p_in))
		return -WD_ENOMEM;

	memset(p_in, 0, lens);
	temp = id_bits >> 8;
	msg_pack(p_in, lens, &in_len, &temp, sizeof(__u8));
	temp = id_bits & 0xFF;
	msg_pack(p_in, lens, &in_len, &temp, sizeof(__u8));
	if (id)
		msg_pack(p_in, lens, &in_len, id->data, id_bytes);
	msg_pack(p_in, lens, &in_len, cv->a.data, key_size);
	msg_pack(p_in, lens, &in_len, cv->b.data, key_size);
	msg_pack(p_in, lens, &in_len, cv->g.x.data, key_size);
	msg_pack(p_in, lens, &in_len, cv->g.y.data, key_size);
	msg_pack(p_in, lens, &in_len, pub->x.data, key_size);
	msg_pack(p_in, lens, &in_len, pub->y.data, key_size);

	hash_bytes = get_hash_bytes(hash->type);
	*len = hash_bytes;
	ret = hash->cb((const char *)p_in, in_len,
			(void *)za, hash_bytes, hash->usr);

	free(p_in);

	return ret;
}

static int sm2_compute_digest(void *ctx, struct wd_dtb *hash_msg,
			      struct wd_dtb *plaintext, struct wd_dtb *id)
{
	struct wcrypto_ecc_ctx *cx = ctx;
	struct wcrypto_hash_mt *hash = &cx->setup.hash;
	__u8 za[SM2_KEY_SIZE] = {0};
	__u32 za_len = SM2_KEY_SIZE;
	__u32 hash_bytes;
	__u64 in_len = 0;
	char *p_in;
	__u64 lens;
	int ret;

	hash_bytes = get_hash_bytes(hash->type);
	if (unlikely(!hash_bytes || hash_bytes > SM2_KEY_SIZE)) {
		WD_ERR("hash type = %u error!\n", hash->type);
		return -WD_EINVAL;
	}

	ret = sm2_compute_za_hash(za, &za_len, id, ctx);
	if (unlikely(ret)) {
		WD_ERR("failed to compute za, ret = %d!\n", ret);
		return ret;
	}

	lens = plaintext->dsize + hash_bytes;
	p_in = malloc(lens);
	if (unlikely(!p_in))
		return -WD_ENOMEM;

	/* e = h(ZA || M) */
	memset(p_in, 0, lens);
	msg_pack(p_in, lens, &in_len, za, za_len);
	msg_pack(p_in, lens, &in_len, plaintext->data, plaintext->dsize);
	hash_msg->dsize = hash_bytes;
	ret = hash->cb((const char *)p_in, in_len, hash_msg->data,
			hash_bytes, hash->usr);
	if (unlikely(ret))
		WD_ERR("failed to compute e, ret = %d!\n", ret);

	free(p_in);

	return ret;
}

static struct wcrypto_ecc_in *new_sign_in(struct wcrypto_ecc_ctx *ctx,
					  struct wd_dtb *e, struct wd_dtb *k,
					  struct wd_dtb *id, __u8 is_dgst)
{
	struct wcrypto_ecc_ctx *cx = ctx;
	struct wcrypto_ecc_sign_in *sin;
	struct wd_dtb *plaintext = NULL;
	struct wd_dtb *hash_msg = NULL;
	struct wcrypto_ecc_in *ecc_in;
	int ret;

	if (unlikely(!ctx || !e)) {
		WD_ERR("failed to new ecc sign in: ctx or e NULL!\n");
		return NULL;
	}

	ecc_in = create_ecc_sign_in(cx, e->dsize, is_dgst);
	if (unlikely(!ecc_in))
		return NULL;

	sin = &ecc_in->param.sin;
	if (!k && cx->setup.rand.cb) {
		ret = generate_random(cx, &sin->k);
		if (unlikely(ret))
			goto release_in;
	}

	sin->k_set = 0;
	sin->dgst_set = 0;
	if (k || cx->setup.rand.cb)
		sin->k_set = 1;

	if (!is_dgst) {
		plaintext = e;
		if (cx->setup.hash.cb) {
			ret = sm2_compute_digest(cx, &sin->dgst, e, id);
			if (unlikely(ret))
				goto release_in;
			sin->dgst_set = 1;
		}
	} else {
		hash_msg = e;
		sin->dgst_set = 1;
	}

	ret = set_sign_in_param(sin, hash_msg, k, plaintext, ctx);
	if (unlikely(ret))
		goto release_in;

	return ecc_in;

release_in:
	release_ecc_in(ctx, ecc_in);

	return NULL;
}

struct wcrypto_ecc_in *wcrypto_new_ecdsa_sign_in(void *ctx,
						 struct wd_dtb *dgst,
						 struct wd_dtb *k)
{
	return new_sign_in(ctx, dgst, k, NULL, 1);
}

static int set_verf_in_param(struct wcrypto_ecc_verf_in *vin,
			     struct wd_dtb *dgst,
			     struct wd_dtb *r,
			     struct wd_dtb *s,
			     struct wd_dtb *plaintext)
{
	int ret;

	if (dgst) {
		ret = set_param_single(&vin->dgst, dgst, "ecc vrf dgst");
		if (unlikely(ret))
			return ret;
	}

	if (plaintext && plaintext->dsize) {
		ret = set_param_single(&vin->plaintext, plaintext, "ecc vrf m");
		if (unlikely(ret))
			return ret;
	}

	ret = set_param_single(&vin->s, s, "ecc vrf s");
	if (unlikely(ret))
		return ret;

	return set_param_single(&vin->r, r, "ecc vrf r");
}

static struct wcrypto_ecc_in *create_sm2_verf_in(struct wcrypto_ecc_ctx *ctx,
						 __u32 m_len)
{
	struct wd_dtb *dgst, *s, *r, *plaintext;
	struct wd_mm_br *br = &ctx->setup.br;
	struct wcrypto_ecc_in *in;
	__u64 len;
	__u32 hsz;

	if (unlikely(!ctx->key_size || ctx->key_size > ECC_MAX_KEY_SIZE)) {
		WD_ERR("ctx key size %u error!\n", ctx->key_size);
		return NULL;
	}

	hsz = get_hw_keysize(ctx->key_size);
	len = sizeof(struct wcrypto_ecc_in) + ECC_VERF_IN_PARAM_NUM * hsz +
		(__u64)m_len;
	in = br_alloc(br, len);
	if (unlikely(!in)) {
		WD_ERR("failed to br alloc, sz = %llu!\n", len);
		return NULL;
	}

	memset(in, 0, len);
	in->size = len - sizeof(struct wcrypto_ecc_in);
	dgst = (struct wd_dtb *)in;
	dgst->data = in->data;
	dgst->dsize = ctx->key_size;
	dgst->bsize = hsz;

	s = dgst + 1;
	s->data = dgst->data + hsz;
	s->dsize = ctx->key_size;
	s->bsize = hsz;

	r = s + 1;
	r->data = s->data + hsz;
	r->dsize = ctx->key_size;
	r->bsize = hsz;

	plaintext = r + 1;
	plaintext->data = r->data + hsz;
	plaintext->dsize = m_len;
	plaintext->bsize = m_len;

	return in;
}

static struct wcrypto_ecc_in *create_ecc_verf_in(struct wcrypto_ecc_ctx *ctx,
						 __u32 m_len, __u8 is_dgst)
{
	if (is_dgst)
		return create_ecc_in(ctx, ECC_VERF_IN_PARAM_NUM);
	else
		return create_sm2_verf_in(ctx, m_len);
}

static struct wcrypto_ecc_in *new_verf_in(void *ctx,
						      struct wd_dtb *e,
						      struct wd_dtb *r,
						      struct wd_dtb *s,
						      struct wd_dtb *id,
						      __u8 is_dgst)
{
	struct wcrypto_ecc_ctx *cx = ctx;
	struct wcrypto_ecc_verf_in *vin;
	struct wd_dtb *plaintext = NULL;
	struct wd_dtb *hash_msg = NULL;
	struct wcrypto_ecc_in *ecc_in;
	int ret;

	if (!cx || !r || !e || !s) {
		WD_ERR("new ecc verf in param error!\n");
		return NULL;
	}

	ecc_in = create_ecc_verf_in(cx, e->dsize, is_dgst);
	if (unlikely(!ecc_in))
		return NULL;

	vin = &ecc_in->param.vin;
	vin->dgst_set = 0;
	if (!is_dgst) {
		plaintext = e;
		if (cx->setup.hash.cb) {
			ret = sm2_compute_digest(cx, &vin->dgst, e, id);
			if (unlikely(ret))
				goto release_in;
			vin->dgst_set = 1;
		}
	} else {
		hash_msg = e;
		vin->dgst_set = 1;
	}

	ret = set_verf_in_param(vin, hash_msg, r, s, plaintext);
	if (unlikely(ret))
		goto release_in;

	return ecc_in;

release_in:
	release_ecc_in(ctx, ecc_in);

	return NULL;
}

struct wcrypto_ecc_in *wcrypto_new_ecdsa_verf_in(void *ctx,
						 struct wd_dtb *dgst,
						 struct wd_dtb *r,
						 struct wd_dtb *s)
{
	return new_verf_in(ctx, dgst, r, s, NULL, 1);
}

struct wcrypto_ecc_out *wcrypto_new_ecdsa_sign_out(void *ctx)
{
	struct wcrypto_ecc_out *ecc_out;

	if (unlikely(!ctx)) {
		WD_ERR("new ecc sout ctx NULL!\n");
		return NULL;
	}

	ecc_out = create_ecc_out(ctx, ECC_SIGN_OUT_PARAM_NUM);
	if (unlikely(!ecc_out))
		WD_ERR("create ecc out err!\n");

	return ecc_out;
}

void wcrypto_get_ecdsa_verf_in_params(struct wcrypto_ecc_in *in,
				      struct wd_dtb **dgst,
				      struct wd_dtb **r,
				      struct wd_dtb **s)
{
	struct wcrypto_ecc_verf_in *vin = (void *)in;

	if (unlikely(!in)) {
		WD_ERR("input NULL in get verf in!\n");
		return;
	}

	if (dgst)
		*dgst = &vin->dgst;

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

	if (unlikely(!in)) {
		WD_ERR("input NULL in get sign in!\n");
		return;
	}

	if (dgst)
		*dgst = &sin->dgst;

	if (k)
		*k = &sin->k;
}

int wcrypto_do_ecdsa(void *ctx, struct wcrypto_ecc_op_data *opdata, void *tag)
{
	if (unlikely(!opdata)) {
		WD_ERR("do ecdsa: opdata null!\n");
		return -WD_EINVAL;
	}

	if (unlikely(opdata->op_type != WCRYPTO_ECDSA_SIGN &&
	    opdata->op_type != WCRYPTO_ECDSA_VERIFY)) {
		WD_ERR("do ecdsa: op_type = %hhu error!\n", opdata->op_type);
		return -WD_EINVAL;
	}

	return do_ecc(ctx, opdata, tag, 0);
}

int wcrypto_ecdsa_poll(struct wd_queue *q, unsigned int num)
{
	if (unlikely(!q || strcmp(q->capa.alg, "ecdsa"))) {
		WD_ERR("sm2 poll: input param error!\n");
		return -WD_EINVAL;
	}

	return ecc_poll(q, num);
}

struct wcrypto_ecc_in *wcrypto_new_sm2_sign_in(void *ctx,
					       struct wd_dtb *e,
					       struct wd_dtb *k,
					       struct wd_dtb *id,
					       __u8 is_dgst)
{
	return new_sign_in(ctx, e, k, id, is_dgst);
}

struct wcrypto_ecc_in *wcrypto_new_sm2_verf_in(void *ctx,
					       struct wd_dtb *e,
					       struct wd_dtb *r,
					       struct wd_dtb *s,
					       struct wd_dtb *id,
					       __u8 is_dgst)
{
	return new_verf_in(ctx, e, r, s, id, is_dgst);
}

struct wcrypto_ecc_out *wcrypto_new_sm2_sign_out(void *ctx)
{
	return wcrypto_new_ecdsa_sign_out(ctx);
}

void wcrypto_get_sm2_sign_out_params(struct wcrypto_ecc_out *out,
				       struct wd_dtb **r,
				       struct wd_dtb **s)
{
	return get_sign_out_params(out, r, s);
}

struct wcrypto_ecc_out *wcrypto_new_sm2_kg_out(void *ctx)
{
	struct wcrypto_ecc_out *ecc_out;

	if (unlikely(!ctx)) {
		WD_ERR("new sm2 kg out ctx NULL!\n");
		return NULL;
	}

	ecc_out = create_ecc_out(ctx, SM2_KG_OUT_PARAM_NUM);
	if (unlikely(!ecc_out))
		WD_ERR("failed to create ecc out!\n");

	return ecc_out;
}

void wcrypto_get_sm2_kg_out_params(struct wcrypto_ecc_out *out,
				   struct wd_dtb **privkey,
				   struct wcrypto_ecc_point **pubkey)
{
	struct wcrypto_sm2_kg_out *kout = (void *)out;

	if (unlikely(!kout)) {
		WD_ERR("input NULL in get sm2 kg out!\n");
		return;
	}

	if (privkey)
		*privkey = &kout->priv;

	if (pubkey)
		*pubkey = &kout->pub;
}

struct wcrypto_ecc_in *wcrypto_new_sm2_enc_in(void *ctx,
					      struct wd_dtb *k,
					      struct wd_dtb *plaintext)
{
	struct wcrypto_ecc_ctx *cx = ctx;
	struct wcrypto_sm2_enc_in *ein;
	struct wcrypto_ecc_in *ecc_in;
	int ret;

	if (unlikely(!cx || !plaintext)) {
		WD_ERR("new sm2 enc in param error!\n");
		return NULL;
	}

	ecc_in = create_sm2_enc_in(cx, plaintext->dsize);
	if (unlikely(!ecc_in)) {
		WD_ERR("failed to create sm2 enc in!\n");
		return NULL;
	}

	ein = &ecc_in->param.ein;
	if (!k && cx->setup.rand.cb) {
		ret = generate_random(cx, &ein->k);
		if (unlikely(ret))
			goto fail_set_param;
	}

	if (k || cx->setup.rand.cb)
		ein->k_set = 1;

	if (k) {
		if (unlikely(!check_k_param(k, ctx)))
			goto fail_set_param;

		ret = set_param_single(&ein->k, k, "sm2 enc k");
		if (unlikely(ret))
			goto fail_set_param;
	}

	ret = set_param_single(&ein->plaintext, plaintext, "sm2 enc m");
	if (unlikely(ret))
		goto fail_set_param;

	return ecc_in;

fail_set_param:
	release_ecc_in(ctx, ecc_in);

	return NULL;
}

struct wcrypto_ecc_in *wcrypto_new_sm2_dec_in(void *ctx,
					      struct wcrypto_ecc_point *c1,
					      struct wd_dtb *c2,
					      struct wd_dtb *c3)
{
	__u32 struct_size = sizeof(struct wcrypto_ecc_in);
	struct wcrypto_ecc_ctx *cx = ctx;
	struct wcrypto_sm2_dec_in *din;
	struct wcrypto_ecc_in *ecc_in;
	__u64 len = 0;
	int ret;

	if (unlikely(!cx || !c1 || !c2 || !c3)) {
		WD_ERR("new sm2 dec in param error!\n");
		return NULL;
	}

	ecc_in = create_sm2_ciphertext(cx, c2->dsize, &len, struct_size);
	if (unlikely(!ecc_in)) {
		WD_ERR("failed to create sm2 dec in!\n");
		return NULL;
	}
	ecc_in->size = len - struct_size;

	din = &ecc_in->param.din;
	ret = set_param_single(&din->c1.x, &c1->x, "sm2 dec c1 x");
	if (unlikely(ret))
		goto fail_set_param;

	ret = set_param_single(&din->c1.y, &c1->y, "sm2 dec c1 y");
	if (unlikely(ret))
		goto fail_set_param;

	ret = set_param_single(&din->c2, c2, "sm2 dec c2");
	if (unlikely(ret))
		goto fail_set_param;

	ret = set_param_single(&din->c3, c3, "sm2 dec c3");
	if (unlikely(ret))
		goto fail_set_param;

	return ecc_in;

fail_set_param:
	release_ecc_in(ctx, ecc_in);

	return NULL;
}

struct wcrypto_ecc_out *wcrypto_new_sm2_enc_out(void *ctx, __u32 plaintext_len)
{
	__u32 struct_size = sizeof(struct wcrypto_ecc_out);
	struct wcrypto_ecc_ctx *cx = ctx;
	struct wcrypto_ecc_out *ecc_out;
	__u64 len = 0;

	if (unlikely(!cx)) {
		WD_ERR("new ecc sout ctx NULL!\n");
		return NULL;
	}

	ecc_out = create_sm2_ciphertext(cx, plaintext_len, &len, struct_size);
	if (unlikely(!ecc_out)) {
		WD_ERR("failed to create sm2 enc out!\n");
		return NULL;
	}
	ecc_out->size = len - struct_size;

	return ecc_out;
}

struct wcrypto_ecc_out *wcrypto_new_sm2_dec_out(void *ctx, __u32 plaintext_len)
{
	struct wcrypto_ecc_ctx *cx = ctx;
	struct wcrypto_sm2_dec_out *dout;
	struct wcrypto_ecc_out *ecc_out;
	struct wd_mm_br *br;
	__u64 len;

	if (unlikely(!ctx)) {
		WD_ERR("new ecc sout ctx NULL!\n");
		return NULL;
	}

	if (unlikely(!cx->key_size || cx->key_size > ECC_MAX_KEY_SIZE)) {
		WD_ERR("ctx key size %u error!\n", cx->key_size);
		return NULL;
	}

	br = &cx->setup.br;
	len = sizeof(*ecc_out) + plaintext_len;
	ecc_out = br_alloc(br, len);
	if (unlikely(!ecc_out)) {
		WD_ERR("failed to br alloc, sz = %llu!\n", len);
		return NULL;
	}
	memset(ecc_out, 0, len);
	ecc_out->size = plaintext_len;
	dout = &ecc_out->param.dout;
	dout->plaintext.data = ecc_out->data;
	dout->plaintext.dsize = plaintext_len;
	dout->plaintext.bsize = plaintext_len;

	return ecc_out;
}

void wcrypto_get_sm2_enc_out_params(struct wcrypto_ecc_out *out,
				    struct wcrypto_ecc_point **c1,
				    struct wd_dtb **c2,
				    struct wd_dtb **c3)
{
	struct wcrypto_sm2_enc_out *eout = (void *)out;

	if (unlikely(!eout)) {
		WD_ERR("input NULL in get sm2 enc out!\n");
		return;
	}

	if (c1)
		*c1 = &eout->c1;

	if (c2)
		*c2 = &eout->c2;

	if (c3)
		*c3 = &eout->c3;
}

void wcrypto_get_sm2_dec_out_params(struct wcrypto_ecc_out *out,
				    struct wd_dtb **plaintext)
{
	struct wcrypto_sm2_dec_out *dout = (void *)out;

	if (unlikely(!dout)) {
		WD_ERR("input NULL in get sm2 dec out!\n");
		return;
	}

	if (plaintext)
		*plaintext = &dout->plaintext;
}

int wcrypto_do_sm2(void *ctx, struct wcrypto_ecc_op_data *opdata, void *tag)
{
	struct wcrypto_ecc_out *out;
	struct wcrypto_ecc_in *in;

	if (unlikely(!opdata)) {
		WD_ERR("do sm2: opdata null!\n");
		return -WD_EINVAL;
	}

	if (unlikely(opdata->op_type != WCRYPTO_SM2_SIGN &&
		opdata->op_type != WCRYPTO_SM2_VERIFY &&
		opdata->op_type != WCRYPTO_SM2_KG &&
		opdata->op_type != WCRYPTO_SM2_ENCRYPT &&
		opdata->op_type != WCRYPTO_SM2_DECRYPT)) {
		WD_ERR("do sm2: op_type = %hhu error!\n", opdata->op_type);
		return -WD_EINVAL;
	}

	in = opdata->in;
	out = opdata->out;
	if (opdata->op_type == WCRYPTO_SM2_ENCRYPT &&
		out->param.eout.c2.dsize != in->param.ein.plaintext.dsize) {
		WD_ERR("do sm2: enc output c2 size != input plaintext size!\n");
		return -WD_EINVAL;
	} else if (opdata->op_type == WCRYPTO_SM2_DECRYPT &&
		out->param.dout.plaintext.dsize != in->param.din.c2.dsize) {
		WD_ERR("do sm2: dec output plaintext size != input c2 size!\n");
		return -WD_EINVAL;
	}

	return do_ecc(ctx, opdata, tag, 0);
}

int wcrypto_sm2_poll(struct wd_queue *q, unsigned int num)
{
	if (unlikely(!q || strcmp(q->capa.alg, "sm2"))) {
		WD_ERR("sm2 poll: input param error!\n");
		return -WD_EINVAL;
	}

	return ecc_poll(q, num);
}
