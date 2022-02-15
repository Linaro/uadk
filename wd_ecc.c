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

#include "wd_ecc.h"
#include "wd_util.h"
#include "include/drv/wd_ecc_drv.h"
#include "include/wd_ecc_curve.h"

#define WD_POOL_MAX_ENTRIES		1024
#define WD_ECC_CTX_MSG_NUM		64
#define WD_ECC_MAX_CTX			256
#define ECC_BALANCE_THRHD		1280
#define ECC_RECV_MAX_CNT		60000000
#define ECC_RESEND_CNT			8
#define ECC_MAX_HW_BITS			521
#define ECC_MAX_KEY_SIZE		BITS_TO_BYTES(ECC_MAX_HW_BITS)
#define ECC_MAX_IN_NUM			4
#define ECC_MAX_OUT_NUM			4
#define CURVE_PARAM_NUM			6
#define ECC_POINT_NUM			2
#define MAX_CURVE_SIZE			(ECC_MAX_KEY_SIZE * CURVE_PARAM_NUM)
#define MAX_HASH_LENS			ECC_MAX_KEY_SIZE
#define SM2_KEY_SIZE			32
#define GET_NEGATIVE(val)		(0 - (val))
#define ZA_PARAM_NUM  			6

static __thread int balance;

struct curve_param_desc {
	__u32 type;
	__u32 pri_offset;
	__u32 pub_offset;
};

enum wd_ecc_curve_param_type {
	ECC_CURVE_P,
	ECC_CURVE_A,
	ECC_CURVE_B,
	ECC_CURVE_N,
	ECC_CURVE_G
};

struct wd_ecc_sess {
	__u32 key_size;
	struct wd_ecc_key key;
	struct wd_ecc_sess_setup setup;
	void *sched_key;
};

struct wd_ecc_curve_list {
	__u32 id;
	const char *name;
	__u32 key_bits;
	__u8 data[MAX_CURVE_SIZE];
};

static struct wd_ecc_setting {
	struct wd_ctx_config_internal config;
	struct wd_sched sched;
	void *sched_ctx;
	const struct wd_ecc_driver *driver;
	void *priv;
	void *dlhandle;
	struct wd_async_msg_pool pool;
} wd_ecc_setting;

struct wd_env_config wd_ecc_env_config;

static const struct wd_ecc_curve_list curve_list[] = {
	/* parameter 3 is key width */
	{ WD_X25519, "x25519", 256, X25519_256_PARAM },
	{ WD_X448, "x448", 448, X448_448_PARAM },
	{ WD_SECP128R1, "secp128r1", 128, SECG_P128_R1_PARAM },
	{ WD_SECP192K1, "secp192k1", 192, SECG_P192_K1_PARAM },
	{ WD_SECP224R1, "secp224R1", 224, SECG_P224_R1_PARAM },
	{ WD_SECP256K1, "secp256k1", 256, SECG_P256_K1_PARAM },
	{ WD_BRAINPOOLP320R1, "bpP320r1", 320, BRAINPOOL_P320_R1_PARAM },
	{ WD_BRAINPOOLP384R1, "bpP384r1", 384, BRAINPOOL_P384_R1_PARAM },
	{ WD_SECP384R1, "secp384r1", 384, SECG_P384_R1_PARAM },
	{ WD_SECP521R1, "secp521r1", 521, SECG_P521_R1_PARAM },
	{ WD_SM2P256, "sm2", 256, SM2_P256_V1_PARAM }
};

static const struct curve_param_desc curve_pram_list[] = {
	{ ECC_CURVE_P, offsetof(struct wd_ecc_prikey, p), offsetof(struct wd_ecc_pubkey, p) },
	{ ECC_CURVE_A, offsetof(struct wd_ecc_prikey, a), offsetof(struct wd_ecc_pubkey, a) },
	{ ECC_CURVE_B, offsetof(struct wd_ecc_prikey, b), offsetof(struct wd_ecc_pubkey, b) },
	{ ECC_CURVE_N, offsetof(struct wd_ecc_prikey, n), offsetof(struct wd_ecc_pubkey, n) },
	{ ECC_CURVE_G, offsetof(struct wd_ecc_prikey, g), offsetof(struct wd_ecc_pubkey, g) }
};

#ifdef WD_STATIC_DRV
static void wd_ecc_set_static_drv(void)
{
	wd_ecc_setting.driver = wd_ecc_get_driver();
	if (!wd_ecc_setting.driver)
		WD_ERR("fail to get driver\n");
}
#else
static void __attribute__((constructor)) wd_ecc_open_driver(void)
{
	wd_ecc_setting.dlhandle = dlopen("libhisi_hpre.so", RTLD_NOW);
	if (!wd_ecc_setting.dlhandle)
		WD_ERR("failed to open libhisi_hpre.so\n");
}

static void __attribute__((destructor)) wd_ecc_close_driver(void)
{
	if (wd_ecc_setting.dlhandle)
		dlclose(wd_ecc_setting.dlhandle);
}
#endif

void wd_ecc_set_driver(struct wd_ecc_driver *drv)
{
	if (!drv) {
		WD_ERR("drv NULL\n");
		return;
	}

	wd_ecc_setting.driver = drv;
}

static int init_param_check(struct wd_ctx_config *config, struct wd_sched *sched)
{
	if (!config || !config->ctxs[0].ctx || !sched) {
		WD_ERR("config or sched NULL\n");
		return -WD_EINVAL;
	}

	if (!wd_is_sva(config->ctxs[0].ctx)) {
		WD_ERR("no sva, not do ecc init\n");
		return -WD_EINVAL;
	}

	return 0;
}

int wd_ecc_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	void *priv;
	int ret;

	if (init_param_check(config, sched))
		return -WD_EINVAL;

	ret = wd_init_ctx_config(&wd_ecc_setting.config, config);
	if (ret < 0) {
		WD_ERR("failed to set config, ret = %d!\n", ret);
		return ret;
	}

	ret = wd_init_sched(&wd_ecc_setting.sched, sched);
	if (ret < 0) {
		WD_ERR("failed to set sched, ret = %d!\n", ret);
		goto out;
	}

#ifdef WD_STATIC_DRV
	wd_ecc_set_static_drv();
#endif

	/* fix me: sadly find we allocate async pool for every ctx */
	ret = wd_init_async_request_pool(&wd_ecc_setting.pool,
					 config->ctx_num, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_ecc_msg));
	if (ret < 0) {
		WD_ERR("failed to initialize async req pool, ret = %d!\n", ret);
		goto out_sched;
	}

	/* initialize ctx related resources in specific driver */
	priv = calloc(1, wd_ecc_setting.driver->drv_ctx_size);
	if (!priv) {
		ret = -WD_ENOMEM;
		goto out_priv;
	}

	wd_ecc_setting.priv = priv;
	ret = wd_ecc_setting.driver->init(&wd_ecc_setting.config, priv,
					  wd_ecc_setting.driver->alg_name);
	if (ret < 0) {
		WD_ERR("failed to drv init, ret = %d\n", ret);
		goto out_init;
	}

	return 0;

out_init:
	free(priv);
out_priv:
	wd_uninit_async_request_pool(&wd_ecc_setting.pool);
out_sched:
	wd_clear_sched(&wd_ecc_setting.sched);
out:
	wd_clear_ctx_config(&wd_ecc_setting.config);
	return ret;
}

void wd_ecc_uninit(void)
{
	if (!wd_ecc_setting.priv) {
		WD_ERR("repeat uninit ecc\n");
		return;
	}

	/* driver uninit */
	wd_ecc_setting.driver->exit(wd_ecc_setting.priv);
	free(wd_ecc_setting.priv);
	wd_ecc_setting.priv = NULL;

	/* uninit async request pool */
	wd_uninit_async_request_pool(&wd_ecc_setting.pool);

	/* unset config, sched, driver */
	wd_clear_sched(&wd_ecc_setting.sched);
	wd_clear_ctx_config(&wd_ecc_setting.config);
}

static int trans_to_binpad(char *dst, const char *src,
			   int b_size, int d_size, const char *p_name)
{
	int i = d_size - 1;
	int j;

	if (unlikely(!dst || !src || !b_size || !d_size || b_size < d_size)) {
		WD_ERR("%s: trans to hpre bin params err!\n", p_name);
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

static __u32 get_key_bsz(__u32 ksz)
{
	__u32 size = 0;

	/* key width */
	if (ksz <= BITS_TO_BYTES(256))
		size = BITS_TO_BYTES(256);
	else if (ksz <= BITS_TO_BYTES(384))
		size = BITS_TO_BYTES(384);
	else if (ksz <= BITS_TO_BYTES(576))
		size = BITS_TO_BYTES(576);
	else
		WD_ERR("failed to get key buffer size : key size = %u.\n", ksz);

	return size;
}

static __u32 get_hash_bytes(__u8 type)
{
	__u32 val = 0;

	switch (type) {
	case WD_HASH_MD4:
	case WD_HASH_MD5:
		val = BITS_TO_BYTES(128); /* output width */
		break;
	case WD_HASH_SHA1:
		val = BITS_TO_BYTES(160);
		break;
	case WD_HASH_SHA224:
		val = BITS_TO_BYTES(224);
		break;
	case WD_HASH_SHA256:
	case WD_HASH_SM3:
		val = BITS_TO_BYTES(256);
		break;
	case WD_HASH_SHA384:
		val = BITS_TO_BYTES(384);
		break;
	case WD_HASH_SHA512:
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

static void init_ecc_prikey(struct wd_ecc_prikey *prikey,
			    __u32 ksz, __u32 bsz)
{
	init_dtb_param(prikey, prikey->data, ksz, bsz, ECC_PRIKEY_PARAM_NUM);
}

static void init_ecc_pubkey(struct wd_ecc_pubkey *pubkey,
			    __u32 ksz, __u32 bsz)
{
	init_dtb_param(pubkey, pubkey->data, ksz, bsz, ECC_PUBKEY_PARAM_NUM);
}

static void release_ecc_prikey(struct wd_ecc_sess *sess)
{
	struct wd_ecc_prikey *prikey = sess->key.prikey;

	wd_memset_zero(prikey->data, prikey->size);
	free(prikey->data);
	free(prikey);
	sess->key.prikey = NULL;
}

static void release_ecc_pubkey(struct wd_ecc_sess *sess)
{
	struct wd_ecc_pubkey *pubkey = sess->key.pubkey;

	free(pubkey->data);
	free(pubkey);
	sess->key.pubkey = NULL;
}

static struct wd_ecc_prikey *create_ecc_prikey(struct wd_ecc_sess *sess)
{
	struct wd_ecc_prikey *prikey;
	__u32 hsz, dsz;
	void *data;

	hsz = get_key_bsz(sess->key_size);
	prikey = malloc(sizeof(struct wd_ecc_prikey));
	if (!prikey) {
		WD_ERR("failed to malloc prikey!\n");
		return NULL;
	}

	dsz = ECC_PRIKEY_SZ(hsz);
	data = malloc(dsz);
	if (!data) {
		WD_ERR("failed to malloc prikey data, sz = %u!\n", dsz);
		free(prikey);
		return NULL;
	}

	memset(data, 0, dsz);
	prikey->size = dsz;
	prikey->data = data;
	init_ecc_prikey(prikey, sess->key_size, hsz);

	return prikey;
}

static struct wd_ecc_pubkey *create_ecc_pubkey(struct wd_ecc_sess *sess)
{
	struct wd_ecc_pubkey *pubkey;
	__u32 hsz, dsz;
	void *data;

	hsz = get_key_bsz(sess->key_size);
	pubkey = malloc(sizeof(struct wd_ecc_pubkey));
	if (!pubkey) {
		WD_ERR("failed to malloc!\n");
		return NULL;
	}

	dsz = ECC_PUBKEY_SZ(hsz);
	data = malloc(dsz);
	if (!data) {
		WD_ERR("failed to malloc pubkey data, sz = %u!\n", dsz);
		free(pubkey);
		return NULL;
	}

	memset(data, 0, dsz);
	pubkey->size = dsz;
	pubkey->data = data;
	init_ecc_pubkey(pubkey, sess->key_size, hsz);

	return pubkey;
}

static void release_ecc_in(struct wd_ecc_sess *sess,
			   struct wd_ecc_in *ecc_in)
{
	wd_memset_zero(ecc_in->data, ecc_in->size);
	free(ecc_in);
}

static struct wd_ecc_in *create_ecc_in(struct wd_ecc_sess *sess, __u32 num)
{
	struct wd_ecc_in *in;
	__u32 hsz, len;

	if (!sess->key_size || sess->key_size > ECC_MAX_KEY_SIZE) {
		WD_ERR("sess key size %u error!\n", sess->key_size);
		return NULL;
	}

	hsz = get_key_bsz(sess->key_size);
	len = sizeof(struct wd_ecc_in) + hsz * num;
	in = malloc(len);
	if (!in) {
		WD_ERR("failed to malloc ecc in, sz = %u!\n", len);
		return NULL;
	}

	memset(in, 0, len);
	in->size = hsz * num;
	init_dtb_param(in, in->data, sess->key_size, hsz, num);

	return in;
}

static struct wd_ecc_in *create_sm2_sign_in(struct wd_ecc_sess *sess,
						 __u64 m_len)
{
	struct wd_dtb *dgst, *k, *plaintext;
	__u32 ksz = sess->key_size;
	struct wd_ecc_in *in;
	__u64 len;

	if (ksz != SM2_KEY_SIZE) {
		WD_ERR("sess key size %u error!\n", ksz);
		return NULL;
	}

	len = sizeof(struct wd_ecc_in)
		+ ECC_SIGN_IN_PARAM_NUM * ksz + m_len;
	in = malloc(len);
	if (!in) {
		WD_ERR("failed to malloc sm2 sign in, sz = %llu!\n", len);
		return NULL;
	}

	memset(in, 0, len);
	in->size = len - sizeof(struct wd_ecc_in);
	dgst = (struct wd_dtb *)in;
	dgst->data = in->data;
	dgst->dsize = ksz;
	dgst->bsize = ksz;

	k = dgst + 1;
	k->data = dgst->data + ksz;
	k->dsize = ksz;
	k->bsize = ksz;

	plaintext = k + 1;
	plaintext->data = k->data + ksz;
	plaintext->dsize = m_len;
	plaintext->bsize = m_len;

	return in;
}

static struct wd_ecc_in *create_sm2_enc_in(struct wd_ecc_sess *sess,
					   __u64 m_len)
{
	struct wd_dtb *k, *plaintext;
	__u32 ksz = sess->key_size;
	struct wd_ecc_in *in;
	__u64 len;

	if (ksz != SM2_KEY_SIZE) {
		WD_ERR("sess key size %u error!\n", sess->key_size);
		return NULL;
	}

	len = sizeof(struct wd_ecc_in) + ksz + m_len;
	in = malloc(len);
	if (!in) {
		WD_ERR("failed to malloc sm2 enc in, sz = %llu!\n", len);
		return NULL;
	}

	memset(in, 0, len);
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

static void *create_sm2_ciphertext(struct wd_ecc_sess *sess, __u32 m_len,
				   __u64 *len, __u32 st_sz)
{
	struct wd_hash_mt *hash = &sess->setup.hash;
	__u32 ksz = sess->key_size;
	struct wd_ecc_point *c1;
	struct wd_dtb *c3, *c2;
	__u32 h_byts;
	void *start;

	if (unlikely(ksz != SM2_KEY_SIZE)) {
		WD_ERR("sess key size %u error!\n", ksz);
		return NULL;
	}

	h_byts = get_hash_bytes(hash->type);
	if (!h_byts) {
		WD_ERR("failed to get hash bytes, type = %u!\n", hash->type);
		return NULL;
	}

	*len = (__u64)st_sz + ECC_POINT_PARAM_NUM * (__u64)sess->key_size +
		(__u64)m_len + (__u64)h_byts;
	start = malloc(*len);
	if (unlikely(!start)) {
		WD_ERR("failed to alloc, sz = %llu!\n", *len);
		return NULL;
	}

	c1 = (struct wd_ecc_point *)start;
	c1->x.data = (char *)start + st_sz;
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

static struct wd_ecc_in *create_ecc_sign_in(struct wd_ecc_sess *sess,
					    __u64 m_len, __u8 is_dgst)
{
	if (is_dgst)
		return create_ecc_in(sess, ECC_SIGN_IN_PARAM_NUM);

	return create_sm2_sign_in(sess, m_len);
}

static struct wd_ecc_out *create_ecc_out(struct wd_ecc_sess *sess, __u32 num)
{
	struct wd_ecc_out *out;
	__u32 hsz, len;

	if (!sess->key_size || sess->key_size > ECC_MAX_KEY_SIZE) {
		WD_ERR("sess key size %u error!\n", sess->key_size);
		return NULL;
	}

	hsz = get_key_bsz(sess->key_size);
	len = sizeof(struct wd_ecc_out) + hsz * num;
	out = malloc(len);
	if (!out) {
		WD_ERR("failed to malloc out, sz = %u!\n", len);
		return NULL;
	}

	memset(out, 0, len);
	out->size = hsz * num;
	init_dtb_param(out, out->data, sess->key_size, hsz, num);

	return out;
}

static struct wd_ecc_curve *create_ecc_curve(struct wd_ecc_sess *sess)
{
	struct wd_ecc_curve *cv;
	__u32 ksize, len;

	ksize = sess->key_size;
	len = sizeof(*cv) + ksize * CURVE_PARAM_NUM;
	cv = malloc(len);
	if (!cv) {
		WD_ERR("failed to malloc curve!\n");
		return NULL;
	}

	memset(cv, 0, len);
	init_dtb_param(cv, (void *)(cv + 1), ksize, ksize, CURVE_PARAM_NUM);

	return cv;
}

static struct wd_ecc_point *create_ecc_pub(struct wd_ecc_sess *sess)
{
	struct wd_ecc_point *pub;
	__u32 ksize, len;

	ksize = sess->key_size;
	len = sizeof(*pub) + ksize * ECC_POINT_NUM;
	pub = malloc(len);
	if (!pub) {
		WD_ERR("failed to malloc pub!\n");
		return NULL;
	}

	memset(pub, 0, len);
	init_dtb_param(pub, (void *)(pub + 1), ksize, ksize, ECC_POINT_NUM);

	return pub;
}

static struct wd_dtb *create_ecc_d(struct wd_ecc_sess *sess)
{
	struct wd_dtb *d;
	__u32 ksize, len;

	ksize = sess->key_size;
	len = sizeof(*d) + ksize;
	d = malloc(len);
	if (!d) {
		WD_ERR("failed to malloc d!\n");
		return NULL;
	}

	memset(d, 0, len);
	init_dtb_param(d, (void *)(d + 1), ksize, ksize, 1);

	return d;
}

static void release_ecc_curve(struct wd_ecc_sess *sess)
{
	free(sess->key.cv);
	sess->key.cv = NULL;
}

static void release_ecc_pub(struct wd_ecc_sess *sess)
{
	free(sess->key.pub);
	sess->key.pub = NULL;
}

static void release_ecc_d(struct wd_ecc_sess *sess)
{
	wd_memset_zero(sess->key.d + 1, sess->key_size);
	free(sess->key.d);
	sess->key.d = NULL;
}

static int set_param_single(struct wd_dtb *dst, const struct wd_dtb *src,
			    const char *p_name)
{
	if (unlikely(!src || !src->data)) {
		WD_ERR("%s: src or data NULL!\n", p_name);
		return -WD_EINVAL;
	}

	if (!src->dsize || src->dsize > dst->dsize) {
		WD_ERR("%s: src dsz = %u error, dst dsz = %u!\n",
			p_name, src->dsize, dst->dsize);
		return -WD_EINVAL;
	}

	dst->dsize = src->dsize;
	memset(dst->data, 0, dst->bsize);
	memcpy(dst->data, src->data, src->dsize);

	return 0;
}

int wd_ecc_get_key_bits(handle_t sess)
{
	if (!sess) {
		WD_ERR("get ecc key bits, sess NULL!\n");
		return -WD_EINVAL;
	}

	return ((struct wd_ecc_sess *)sess)->setup.key_bits;
}

static int set_curve_param_single(struct wd_ecc_key *key,
				  const struct wd_dtb *param,
				  __u32 type)
{
	struct wd_ecc_prikey *pri = key->prikey;
	struct wd_ecc_pubkey *pub = key->pubkey;
	struct wd_dtb *tmp1, *tmp2;
	int ret;

	tmp1 = (struct wd_dtb *)((char *)pri +
		curve_pram_list[type].pri_offset);
	tmp2 = (struct wd_dtb *)((char *)pub +
		curve_pram_list[type].pub_offset);
	if (type == ECC_CURVE_G) {
		ret = set_param_single(tmp1 + 1, param + 1, "set cv");
		if (unlikely(ret))
			return ret;

		ret = set_param_single(tmp2 + 1, param + 1, "set cv");
		if (unlikely(ret))
			return ret;
	}

	ret = set_param_single(tmp1, param, "set cv");
	if (unlikely(ret))
		return ret;

	return set_param_single(tmp2, param, "set cv");
}

static int set_curve_param(struct wd_ecc_key *key,
			   const struct wd_ecc_curve *param)
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

static const struct wd_ecc_curve_list *find_curve_list(__u32 id)
{
	int len = ARRAY_SIZE(curve_list);
	int i = 0;

	while (i < len) {
		if (curve_list[i].id == id)
			return &curve_list[i];
		i++;
	}

	return NULL;
}

static int fill_param_by_id(struct wd_ecc_curve *c,
			    __u16 key_bits, __u32 id)
{
	struct wd_ecc_curve_list *item;
	__u32 key_size;

	item = (struct wd_ecc_curve_list *)find_curve_list(id);
	if (!item) {
		WD_ERR("failed to find curve id %u!\n", id);
		return -WD_EINVAL;
	}

	if (item->key_bits != key_bits) {
		WD_ERR("curve %u and key bits %u not match!\n", id, key_bits);
		return -WD_EINVAL;
	}

	key_size = BITS_TO_BYTES(item->key_bits);
	memcpy(c->p.data, item->data, CURVE_PARAM_NUM * key_size);

	return 0;
}

static void setup_curve_cfg(struct wd_ecc_sess_setup *setup)
{
	if (!strcmp(setup->alg, "x25519")) {
		setup->key_bits = 256; /* key width */
		setup->cv.type = WD_CV_CFG_ID;
		setup->cv.cfg.id = WD_X25519;
	} else if (!strcmp(setup->alg, "x448")) {
		setup->key_bits = 448;
		setup->cv.type = WD_CV_CFG_ID;
		setup->cv.cfg.id = WD_X448;
	} else if ((!strcmp(setup->alg, "sm2"))) {
		setup->key_bits = 256;
		setup->cv.type = WD_CV_CFG_ID;
		setup->cv.cfg.id = WD_SM2P256;
	}
}

static int set_key_cv(struct wd_ecc_curve *dst,
		      struct wd_ecc_curve *src)
{
	int ret;

	if (unlikely(!src)) {
		WD_ERR("set key cv: praram NULL!\n");
		return -WD_EINVAL;
	}

	ret = set_param_single(&dst->p, &src->p, "cv p");
	if (ret)
		return ret;

	ret = set_param_single(&dst->a, &src->a, "cv a");
	if (ret)
		return ret;

	ret = set_param_single(&dst->b, &src->b, "cv b");
	if (ret)
		return ret;

	ret = set_param_single(&dst->g.x, &src->g.x, "cv gx");
	if (ret)
		return ret;

	ret = set_param_single(&dst->g.y, &src->g.y, "cv gy");
	if (ret)
		return ret;

	return set_param_single(&dst->n, &src->n, "cv n");
}

static int fill_user_curve_cfg(struct wd_ecc_curve *param,
			       struct wd_ecc_sess_setup *setup)
{
	struct wd_ecc_curve *src_param = setup->cv.cfg.pparam;
	__u32 curve_id;
	int ret = 0;

	if (setup->cv.type == WD_CV_CFG_ID) {
		curve_id = setup->cv.cfg.id;
		ret = fill_param_by_id(param, setup->key_bits, curve_id);
		dbg("set curve id %u\n", curve_id);
	} else if (setup->cv.type == WD_CV_CFG_PARAM) {
		ret = set_key_cv(param, src_param);
		if (ret) {
			WD_ERR("failed to set key cv!\n");
			return ret;
		}
		dbg("set curve by user param\n");
	} else {
		WD_ERR("fill curve cfg:type %u error!\n", setup->cv.type);
		return -WD_EINVAL;
	}

	if (!param->p.dsize ||
	     param->p.dsize > BITS_TO_BYTES(setup->key_bits)) {
		WD_ERR("fill curve cfg:dsize %u error!\n", param->p.dsize);
		return -WD_EINVAL;
	}

	return ret;
}

static int create_sess_key(struct wd_ecc_sess_setup *setup,
			   struct wd_ecc_sess *sess)
{
	int ret = -WD_ENOMEM;

	sess->key.prikey = create_ecc_prikey(sess);
	if (!sess->key.prikey)
		return -WD_ENOMEM;

	sess->key.pubkey = create_ecc_pubkey(sess);
	if (!sess->key.pubkey)
		goto free_prikey;

	sess->key.cv = create_ecc_curve(sess);
	if (!sess->key.cv)
		goto free_pubkey;

	sess->key.pub = create_ecc_pub(sess);
	if (!sess->key.pub)
		goto free_curve;

	sess->key.d = create_ecc_d(sess);
	if (!sess->key.d)
		goto free_pub;

	ret = fill_user_curve_cfg(sess->key.cv, setup);
	if (ret) {
		WD_ERR("failed to fill user curve cfg!\n");
		goto free_d;
	}

	ret = set_curve_param(&sess->key, sess->key.cv);
	if (ret) {
		WD_ERR("failed to set curve param!\n");
		goto free_d;
	}

	return 0;

free_d:
	release_ecc_d(sess);

free_pub:
	release_ecc_pub(sess);

free_curve:
	release_ecc_curve(sess);

free_pubkey:
	release_ecc_pubkey(sess);

free_prikey:
	release_ecc_prikey(sess);

	return ret;
}

static bool is_key_width_support(__u32 key_bits)
{
	/* key bit width check */
	if (unlikely(key_bits != 128 && key_bits != 192 &&
	    key_bits != 224 && key_bits != 256 &&
	    key_bits != 320 && key_bits != 384 &&
	    key_bits != 448 && key_bits != 521))
		return false;

	return true;
}

static bool is_alg_support(const char *alg)
{
	if (unlikely(strcmp(alg, "ecdh") && strcmp(alg, "ecdsa") &&
		     strcmp(alg, "x25519") && strcmp(alg, "x448") &&
		     strcmp(alg, "sm2")))
		return false;

	return true;
}

static int setup_param_check(struct wd_ecc_sess_setup *setup)
{
	if (unlikely(!setup || !setup->alg)) {
		WD_ERR("input parameter error!\n");
		return -WD_EINVAL;
	}

	if (unlikely(!is_alg_support(setup->alg))) {
		WD_ERR("algorithms %s not supported!\n", setup->alg);
		return -WD_EINVAL;
	}

	setup_curve_cfg(setup);

	if (unlikely(!is_key_width_support(setup->key_bits))) {
		WD_ERR("key_bits %u error!\n", setup->key_bits);
		return -WD_EINVAL;
	}

	return 0;
}

static void del_sess_key(struct wd_ecc_sess *sess)
{
	if (sess->key.prikey) {
		wd_memset_zero(sess->key.prikey->data, sess->key.prikey->size);
		free(sess->key.prikey->data);
		free(sess->key.prikey);
		sess->key.prikey = NULL;
	}

	if (sess->key.pubkey) {
		free(sess->key.pubkey->data);
		free(sess->key.pubkey);
		sess->key.pubkey = NULL;
	}

	if (sess->key.cv)
		free(sess->key.cv);
	if (sess->key.pub)
		free(sess->key.pub);
	if (sess->key.d) {
		wd_memset_zero(sess->key.d + 1, sess->key_size);
		free(sess->key.d);
	}
}

handle_t wd_ecc_alloc_sess(struct wd_ecc_sess_setup *setup)
{
	struct wd_ecc_sess *sess;
	int ret;

	if (setup_param_check(setup))
		return (handle_t)0;

	sess = calloc(1, sizeof(struct wd_ecc_sess));
	if (!sess)
		return (handle_t)0;

	memcpy(&sess->setup, setup, sizeof(*setup));
	sess->key_size = BITS_TO_BYTES(setup->key_bits);

	ret = create_sess_key(setup, sess);
	if (ret) {
		WD_ERR("failed creat ecc sess keys!\n");
		goto sess_err;
	}

	/* Some simple scheduler don't need scheduling parameters */
	sess->sched_key = (void *)wd_ecc_setting.sched.sched_init(
		     wd_ecc_setting.sched.h_sched_ctx, setup->sched_param);
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

void wd_ecc_free_sess(handle_t sess)
{
	struct wd_ecc_sess *sess_t = (struct wd_ecc_sess *)sess;

	if (!sess_t) {
		WD_ERR("free ecc sess parameter err!\n");
		return;
	}

	if (sess_t->sched_key)
		free(sess_t->sched_key);
	del_sess_key(sess_t);
	free(sess_t);
}

struct wd_ecc_key *wd_ecc_get_key(handle_t sess)
{
	struct wd_ecc_sess *sess_t = (struct wd_ecc_sess *)sess;

	if (!sess_t) {
		WD_ERR("get ecc key sess NULL!\n");
		return NULL;
	}

	return &sess_t->key;
}

int wd_ecc_set_prikey(struct wd_ecc_key *ecc_key,
			   struct wd_dtb *prikey)
{
	struct wd_ecc_prikey *ecc_prikey;
	struct wd_dtb *d;
	int ret;

	if (!ecc_key || !prikey) {
		WD_ERR("set ecc prikey parameter NULL!\n");
		return -WD_EINVAL;
	}

	ecc_prikey = ecc_key->prikey;
	d = ecc_key->d;
	if (!ecc_prikey || !d) {
		WD_ERR("ecc_prikey or d NULL!\n");
		return -WD_EINVAL;
	}

	ret = set_param_single(&ecc_prikey->d, prikey, "set prikey d");
	if (ret)
		return ret;

	return set_param_single(d, prikey, "set d");
}

int wd_ecc_get_prikey(struct wd_ecc_key *ecc_key,
			   struct wd_dtb **prikey)
{
	if (!ecc_key || !prikey) {
		WD_ERR("get ecc prikey parameter err!\n");
		return -WD_EINVAL;
	}

	*prikey = ecc_key->d;

	return WD_SUCCESS;
}

int wd_ecc_set_pubkey(struct wd_ecc_key *ecc_key, struct wd_ecc_point *pubkey)
{
	struct wd_ecc_pubkey *ecc_pubkey;
	struct wd_ecc_point *pub;
	int ret;

	if (!ecc_key || !pubkey) {
		WD_ERR("set ecc pubkey parameter err!\n");
		return -WD_EINVAL;
	}

	pub = ecc_key->pub;
	ecc_pubkey = ecc_key->pubkey;
	if (!ecc_pubkey || !pub) {
		WD_ERR("ecc_pubkey or pub NULL!\n");
		return -WD_EINVAL;
	}

	ret = set_param_single(&ecc_pubkey->pub.x, &pubkey->x, "ecc pubkey x");
	if (ret)
		return ret;

	ret = set_param_single(&ecc_pubkey->pub.y, &pubkey->y, "ecc pubkey y");
	if (ret)
		return ret;

	ret = trans_to_binpad(pub->x.data, pubkey->x.data,
			      pub->x.bsize, pubkey->x.dsize, "ecc pub x");
	if (ret)
		return ret;

	return trans_to_binpad(pub->y.data, pubkey->y.data,
			       pub->y.bsize, pubkey->y.dsize, "ecc pub y");
}

int wd_ecc_get_pubkey(struct wd_ecc_key *ecc_key,
		      struct wd_ecc_point **pubkey)
{
	if (!ecc_key || !pubkey) {
		WD_ERR("get ecc pubkey parameter err!\n");
		return -WD_EINVAL;
	}

	*pubkey = ecc_key->pub;

	return WD_SUCCESS;
}

int wd_ecc_get_curve(struct wd_ecc_key *ecc_key,
		     struct wd_ecc_curve **cv)
{
	if (!ecc_key || !cv) {
		WD_ERR("get ecc pubkey parameter err!\n");
		return -WD_EINVAL;
	}

	*cv = ecc_key->cv;

	return WD_SUCCESS;
}

void wd_ecc_get_prikey_params(struct wd_ecc_key *key,
			      struct wd_dtb **p, struct wd_dtb **a,
			      struct wd_dtb **b, struct wd_dtb **n,
			      struct wd_ecc_point **g,
			      struct wd_dtb **d)
{
	struct wd_ecc_prikey *prk;

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

void wd_ecc_get_pubkey_params(struct wd_ecc_key *key,
			      struct wd_dtb **p, struct wd_dtb **a,
			      struct wd_dtb **b, struct wd_dtb **n,
			      struct wd_ecc_point **g,
			      struct wd_ecc_point **pub)
{
	struct wd_ecc_pubkey *pbk;

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

struct wd_ecc_in *wd_ecxdh_new_in(handle_t sess, struct wd_ecc_point *in)
{
	struct wd_ecc_sess *s = (struct wd_ecc_sess *)sess;
	struct wd_ecc_dh_in *dh_in;
	struct wd_ecc_in *ecc_in;
	int ret;

	if (!s || !in) {
		WD_ERR("new ecc dh in parameter error!\n");
		return NULL;
	}

	ecc_in = create_ecc_in(s, ECDH_IN_PARAM_NUM);
	if (!ecc_in)
		return NULL;

	dh_in = &ecc_in->param.dh_in;
	ret = set_param_single(&dh_in->pbk.x, &in->x, "ecc in x");
	if (ret)
		goto set_param_error;

	ret = set_param_single(&dh_in->pbk.y, &in->y, "ecc in y");
	if (ret)
		goto set_param_error;

	return ecc_in;

set_param_error:
	release_ecc_in(s, ecc_in);
	return NULL;
}

struct wd_ecc_out *wd_ecxdh_new_out(handle_t sess)
{
	struct wd_ecc_out *ecc_out;

	if (!sess) {
		WD_ERR("new ecc dh out sess NULL!\n");
		return NULL;
	}

	ecc_out = create_ecc_out((struct wd_ecc_sess *)sess, ECDH_OUT_PARAM_NUM);
	if (!ecc_out)
		return NULL;

	return ecc_out;
}

void wd_ecxdh_get_out_params(struct wd_ecc_out *out, struct wd_ecc_point **key)
{
	struct wd_ecc_dh_out *dh_out = (void *)out;

	if (!dh_out) {
		WD_ERR("input NULL in get ecdh out!\n");
		return;
	}

	if (key)
		*key = &dh_out->out;
}

void wd_ecc_del_in(handle_t sess, struct wd_ecc_in *in)
{
	__u32 bsz;

	if (!in) {
		WD_ERR("del ecc in parameter error!\n");
		return;
	}

	bsz = in->size;
	if (!bsz) {
		WD_ERR("del ecc in: bsz 0!\n");
		return;
	}

	wd_memset_zero(in->data, bsz);
	free(in);
}

void wd_ecc_del_out(handle_t sess,  struct wd_ecc_out *out)
{
	__u32 bsz;

	if (!out) {
		WD_ERR("del ecc out parameter error!\n");
		return;
	}

	bsz = out->size;
	if (!bsz) {
		WD_ERR("del ecc out: bsz 0!\n");
		return;
	}

	wd_memset_zero(out->data, bsz);
	free(out);
}

static int fill_ecc_msg(struct wd_ecc_msg *msg, struct wd_ecc_req *req,
			struct wd_ecc_sess *sess)
{
	void *key = NULL;

	memcpy(&msg->req, req, sizeof(msg->req));
	msg->hash = sess->setup.hash;
	msg->key_bytes = sess->key_size;
	msg->curve_id = sess->setup.cv.cfg.id;
	msg->result = WD_EINVAL;

	switch (req->op_type) {
	case WD_ECXDH_GEN_KEY:
	case WD_ECXDH_COMPUTE_KEY:
	case WD_ECDSA_SIGN:
	case WD_ECDSA_VERIFY:
	case WD_SM2_ENCRYPT:
	case WD_SM2_DECRYPT:
	case WD_SM2_SIGN:
	case WD_SM2_VERIFY:
	case WD_SM2_KG:
		key = &sess->key;
		break;
	default:
		WD_ERR("ecc request op type = %u error!\n", req->op_type);
		return -WD_EINVAL;
	}
	msg->key = key;

	if (req->op_type == WD_ECXDH_GEN_KEY ||
		req->op_type == WD_SM2_KG) {
		struct wd_ecc_point *g = NULL;

		wd_ecc_get_prikey_params((void *)key, NULL, NULL,
			NULL, NULL, &g, NULL);
		msg->req.src = g;
	}

	if (!msg->req.src || (!req->dst && (req->op_type != WD_ECDSA_VERIFY &&
		req->op_type != WD_SM2_VERIFY))) {
		WD_ERR("req in/out NULL!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static void msg_pack(char *dst, __u64 dst_len, __u64 *out_len,
		     const void *src, __u32 src_len)
{
	if (!src || !src_len)
		return;

	memcpy(dst + *out_len, src, src_len);
	*out_len += src_len;
}

static int ecc_send(handle_t ctx, struct wd_ecc_msg *msg)
{
	__u32 tx_cnt = 0;
	int ret;

	do {
		ret = wd_ecc_setting.driver->send(ctx, msg);
		if (ret == -WD_EBUSY) {
			if (tx_cnt++ >= ECC_RESEND_CNT) {
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
static int ecc_recv_sync(handle_t ctx, struct wd_ecc_msg *msg)
{
	struct wd_ecc_req *req = &msg->req;
	__u32 rx_cnt = 0;
	int ret;

	do {
		ret = wd_ecc_setting.driver->recv(ctx, msg);
		if (ret == -WD_EAGAIN) {
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
	} while (ret < 0);

	balance = rx_cnt;
	req->status = msg->result;
	req->dst_bytes = msg->req.dst_bytes;

	return GET_NEGATIVE(req->status);
}

int wd_do_ecc_sync(handle_t h_sess, struct wd_ecc_req *req)
{
	struct wd_ctx_config_internal *config = &wd_ecc_setting.config;
	handle_t h_sched_ctx = wd_ecc_setting.sched.h_sched_ctx;
	struct wd_ecc_sess *sess = (struct wd_ecc_sess *)h_sess;
	struct wd_ctx_internal *ctx;
	struct wd_ecc_msg msg;
	__u32 idx;
	int ret;

	if (unlikely(!h_sess || !req)) {
		WD_ERR("input parameter NULL!\n");
		return -WD_EINVAL;
	}

	idx = wd_ecc_setting.sched.pick_next_ctx(h_sched_ctx,
							    sess->sched_key,
							    CTX_MODE_SYNC);
	ret = wd_check_ctx(config, CTX_MODE_SYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	memset(&msg, 0, sizeof(struct wd_ecc_msg));
	ret = fill_ecc_msg(&msg, req, sess);
	if (unlikely(ret))
		return ret;

	pthread_spin_lock(&ctx->lock);
	ret = ecc_send(ctx->ctx, &msg);
	if (unlikely(ret))
		goto fail;

	ret = ecc_recv_sync(ctx->ctx, &msg);
fail:
	pthread_spin_unlock(&ctx->lock);

	return ret;
}

static void get_sign_out_params(struct wd_ecc_out *out,
				struct wd_dtb **r, struct wd_dtb **s)
{
	struct wd_ecc_sign_out *sout = (void *)out;

	if (!sout) {
		WD_ERR("input NULL in get ecc sign out!\n");
		return;
	}

	if (r)
		*r = &sout->r;

	if (s)
		*s = &sout->s;
}

void wd_sm2_get_sign_out_params(struct wd_ecc_out *out,
				struct wd_dtb **r, struct wd_dtb **s)
{
	return get_sign_out_params(out, r, s);
}

static int set_sign_in_param(struct wd_ecc_sign_in *sin,
			     struct wd_dtb *dgst,
			     struct wd_dtb *k,
			     struct wd_dtb *plaintext)
{
	int ret;

	if (k) {
		ret = set_param_single(&sin->k, k, "sign k");
		if (ret)
			return ret;
	}

	if (dgst) {
		ret = set_param_single(&sin->dgst, dgst, "sign dgst");
		if (ret)
			return ret;
	}

	if (plaintext && plaintext->dsize) {
		ret = set_param_single(&sin->plaintext, plaintext, "sign m");
		if (ret)
			return ret;
	}

	return 0;
}

static int generate_random(struct wd_ecc_sess *sess, struct wd_dtb *k)
{
	struct wd_rand_mt rand_t = sess->setup.rand;
	int ret;

	ret = rand_t.cb(k->data, k->dsize, rand_t.usr);
	if (ret)
		WD_ERR("failed to rand cb: ret = %d!\n", ret);

	return ret;
}

static int sm2_compute_za_hash(__u8 *za, __u32 *len, struct wd_dtb *id,
			       struct wd_ecc_sess *sess)

{
	__u32 key_size = BITS_TO_BYTES(sess->setup.key_bits);
	struct wd_hash_mt *hash = &sess->setup.hash;
	struct wd_ecc_point *pub = sess->key.pub;
	struct wd_ecc_curve *cv = sess->key.cv;
	__u16 id_bytes = 0;
	__u16 id_bits = 0;
	__u64 in_len = 0;
	__u32 hash_bytes;
	char *p_in;
	__u64 lens;
	__u8 temp;
	int ret;

	if (id && (!BYTES_TO_BITS(id->dsize) || !id->data ||
		   BYTES_TO_BITS(id->dsize) > UINT16_MAX)) {
		WD_ERR("id error: lens = %u!\n", id->dsize);
		return -WD_EINVAL;
	}

	if (id) {
		id_bits = BYTES_TO_BITS(id->dsize);
		id_bytes = id->dsize;
	}

	/* ZA = h(ENTL || ID || a || b || xG || yG || xA || yA) */
	lens = sizeof(__u16) + id_bytes + ZA_PARAM_NUM * key_size;
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

static int sm2_compute_digest(struct wd_ecc_sess *sess, struct wd_dtb *hash_msg,
			      struct wd_dtb *plaintext, struct wd_dtb *id)

{
	struct wd_hash_mt *hash = &sess->setup.hash;
	__u8 za[SM2_KEY_SIZE] = {0};
	__u32 za_len = SM2_KEY_SIZE;
	__u32 hash_bytes;
	__u64 in_len = 0;
	char *p_in;
	__u64 lens;
	int ret;

	hash_bytes = get_hash_bytes(hash->type);
	if (unlikely(!hash_bytes || hash_bytes > SM2_KEY_SIZE)) {
		WD_ERR("hash type = %hhu error!\n", hash->type);
		return -WD_EINVAL;
	}

	ret = sm2_compute_za_hash(za, &za_len, id, sess);
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

static struct wd_ecc_in *new_sign_in(struct wd_ecc_sess *sess,
				     struct wd_dtb *e, struct wd_dtb *k,
				     struct wd_dtb *id, __u8 is_dgst)
{
	struct wd_ecc_sess *sess_t = (struct wd_ecc_sess *)sess;
	struct wd_dtb *plaintext = NULL;
	struct wd_dtb *hash_msg = NULL;
	struct wd_ecc_sign_in *sin;
	struct wd_ecc_in *ecc_in;
	int ret;

	if (!sess || !e) {
		WD_ERR("failed to new ecc sign in: sess or e NULL!\n");
		return NULL;
	}

	ecc_in = create_ecc_sign_in(sess_t, e->dsize, is_dgst);
	if (!ecc_in)
		return NULL;

	sin = &ecc_in->param.sin;
	if (!k && sess_t->setup.rand.cb) {
		ret = generate_random(sess_t, &sin->k);
		if (ret)
			goto release_in;
	}

	if (k || sess_t->setup.rand.cb)
		sin->k_set = 1;

	if (!is_dgst) {
		plaintext = e;
		if (sess_t->setup.hash.cb) {
			ret = sm2_compute_digest(sess_t, &sin->dgst, e, id);
			if (ret)
				goto release_in;
			sin->dgst_set = 1;
		}
	} else {
		hash_msg = e;
		sin->dgst_set = 1;
	}

	ret = set_sign_in_param(sin, hash_msg, k, plaintext);
	if (ret)
		goto release_in;

	return ecc_in;

release_in:
	release_ecc_in(sess_t, ecc_in);

	return NULL;
}

static int set_verf_in_param(struct wd_ecc_verf_in *vin,
			     struct wd_dtb *dgst,
			     struct wd_dtb *r,
			     struct wd_dtb *s,
			     struct wd_dtb *plaintext)
{
	int ret;

	if (dgst) {
		ret = set_param_single(&vin->dgst, dgst, "vrf dgst");
		if (ret)
			return ret;
	}

	if (plaintext && plaintext->dsize) {
		ret = set_param_single(&vin->plaintext, plaintext, "vrf m");
		if (ret)
			return ret;
	}

	ret = set_param_single(&vin->s, s, "vrf s");
	if (ret)
		return ret;

	ret = set_param_single(&vin->r, r, "vrf r");
	if (ret)
		return ret;

	return 0;
}

static struct wd_ecc_in *create_sm2_verf_in(struct wd_ecc_sess *sess,
					    __u64 m_len)
{
	struct wd_dtb *dgst, *s, *r, *plaintext;
	struct wd_ecc_in *in;
	__u64 len;
	__u32 hsz;

	if (sess->key_size != SM2_KEY_SIZE) {
		WD_ERR("sess key size %u error!\n", sess->key_size);
		return NULL;
	}

	hsz = get_key_bsz(sess->key_size);
	len = sizeof(struct wd_ecc_in) + ECC_VERF_IN_PARAM_NUM * hsz +
		m_len;
	in = malloc(len);
	if (!in) {
		WD_ERR("failed to malloc sm2 verf in, sz = %llu!\n", len);
		return NULL;
	}

	memset(in, 0, len);
	in->size = len - sizeof(struct wd_ecc_in);
	dgst = (struct wd_dtb *)in;
	dgst->data = in->data;
	dgst->dsize = sess->key_size;
	dgst->bsize = hsz;

	s = dgst + 1;
	s->data = dgst->data + hsz;
	s->dsize = sess->key_size;
	s->bsize = hsz;

	r = s + 1;
	r->data = s->data + hsz;
	r->dsize = sess->key_size;
	r->bsize = hsz;

	plaintext = r + 1;
	plaintext->data = r->data + hsz;
	plaintext->dsize = m_len;
	plaintext->bsize = m_len;

	return in;
}

static struct wd_ecc_in *create_ecc_verf_in(struct wd_ecc_sess *sess,
					    __u64 m_len, __u8 is_dgst)
{
	if (is_dgst)
		return create_ecc_in(sess, ECC_VERF_IN_PARAM_NUM);
	else
		return create_sm2_verf_in(sess, m_len);
}

static struct wd_ecc_in *new_verf_in(handle_t sess,
				     struct wd_dtb *e,
				     struct wd_dtb *r,
				     struct wd_dtb *s,
				     struct wd_dtb *id,
				     __u8 is_dgst)
{
	struct wd_ecc_sess *sess_t = (struct wd_ecc_sess *)sess;
	struct wd_dtb *plaintext = NULL;
	struct wd_dtb *hash_msg = NULL;
	struct wd_ecc_verf_in *vin;
	struct wd_ecc_in *ecc_in;
	int ret;

	if (!sess_t || !r || !e || !s) {
		WD_ERR("new ecc verf in parameter error!\n");
		return NULL;
	}

	ecc_in = create_ecc_verf_in(sess_t, e->dsize, is_dgst);
	if (!ecc_in)
		return NULL;

	vin = &ecc_in->param.vin;

	if (!is_dgst) {
		plaintext = e;
		if (sess_t->setup.hash.cb) {
			ret = sm2_compute_digest(sess_t, &vin->dgst, e, id);
			if (ret)
				goto release_in;
			vin->dgst_set = 1;
		}
	} else {
		hash_msg = e;
		vin->dgst_set = 1;
	}

	ret = set_verf_in_param(vin, hash_msg, r, s, plaintext);
	if (ret)
		goto release_in;

	return ecc_in;

release_in:
	release_ecc_in(sess_t, ecc_in);

	return NULL;
}

struct wd_ecc_in *wd_sm2_new_sign_in(handle_t sess,
				     struct wd_dtb *e,
				     struct wd_dtb *k,
				     struct wd_dtb *id,
				     __u8 is_dgst)
{
	return new_sign_in((void *)sess, e, k, id, is_dgst);
}

struct wd_ecc_in *wd_sm2_new_verf_in(handle_t sess,
				     struct wd_dtb *e,
				     struct wd_dtb *r,
				     struct wd_dtb *s,
				     struct wd_dtb *id,
				     __u8 is_dgst)
{
	return new_verf_in(sess, e, r, s, id, is_dgst);
}

static struct wd_ecc_out *wd_ecc_new_sign_out(struct wd_ecc_sess *sess)
{
	struct wd_ecc_out *ecc_out;

	if (!sess) {
		WD_ERR("new ecc sout ctx NULL!\n");
		return NULL;
	}

	ecc_out = create_ecc_out(sess, ECC_SIGN_OUT_PARAM_NUM);
	if (!ecc_out)
		return NULL;

	return ecc_out;
}

struct wd_ecc_out *wd_sm2_new_sign_out(handle_t sess)
{
	return wd_ecc_new_sign_out((void *)sess);
}

struct wd_ecc_out *wd_sm2_new_kg_out(handle_t sess)
{
	struct wd_ecc_out *ecc_out;

	if (!sess) {
		WD_ERR("new sm2 kg out sess NULL!\n");
		return NULL;
	}

	ecc_out = create_ecc_out((struct wd_ecc_sess *)sess,
				 SM2_KG_OUT_PARAM_NUM);
	if (!ecc_out)
		return NULL;

	return ecc_out;
}

void wd_sm2_get_kg_out_params(struct wd_ecc_out *out,
			      struct wd_dtb **privkey,
			      struct wd_ecc_point **pubkey)
{
	struct wd_sm2_kg_out *kout = (void *)out;

	if (!kout) {
		WD_ERR("input NULL in get sm2 kg out!\n");
		return;
	}

	if (privkey)
		*privkey = &kout->priv;

	if (pubkey)
		*pubkey = &kout->pub;
}

struct wd_ecc_in *wd_sm2_new_enc_in(handle_t sess,
				    struct wd_dtb *k,
				    struct wd_dtb *plaintext)
{
	struct wd_ecc_sess *sess_t = (struct wd_ecc_sess *)sess;
	struct wd_sm2_enc_in *ein;
	struct wd_ecc_in *ecc_in;
	int ret;

	if (!sess_t || !plaintext) {
		WD_ERR("new sm2 enc in parameter error!\n");
		return NULL;
	}

	ecc_in = create_sm2_enc_in(sess_t, plaintext->dsize);
	if (!ecc_in) {
		WD_ERR("failed to create sm2 enc in!\n");
		return NULL;
	}

	ein = &ecc_in->param.ein;
	if (!k && sess_t->setup.rand.cb) {
		ret = generate_random(sess_t, &ein->k);
		if (ret)
			goto fail_set_param;
	}

	if (k || sess_t->setup.rand.cb)
		ein->k_set = 1;

	if (k) {
		ret = set_param_single(&ein->k, k, "ein k");
		if (ret)
			goto fail_set_param;
	}

	ret = set_param_single(&ein->plaintext, plaintext, "ein plaintext");
	if (ret)
		goto fail_set_param;

	return ecc_in;

fail_set_param:
	release_ecc_in(sess_t, ecc_in);

	return NULL;
}

struct wd_ecc_in *wd_sm2_new_dec_in(handle_t sess,
				    struct wd_ecc_point *c1,
				    struct wd_dtb *c2,
				    struct wd_dtb *c3)
{
	struct wd_ecc_sess *sess_t = (struct wd_ecc_sess *)sess;
	__u32 struct_size = sizeof(struct wd_ecc_in);
	struct wd_sm2_dec_in *din;
	struct wd_ecc_in *ecc_in;
	__u64 len = 0;
	int ret;

	if (!sess_t || !c1 || !c2 || !c3) {
		WD_ERR("new sm2 dec in parameter error!\n");
		return NULL;
	}

	ecc_in = create_sm2_ciphertext(sess_t, c2->dsize, &len, struct_size);
	if (!ecc_in) {
		WD_ERR("failed to create sm2 dec in!\n");
		return NULL;
	}
	ecc_in->size = len - struct_size;

	din = &ecc_in->param.din;
	ret = set_param_single(&din->c1.x, &c1->x, "c1 x");
	if (ret)
		goto fail_set_param;

	ret = set_param_single(&din->c1.y, &c1->y, "c1 y");
	if (ret)
		goto fail_set_param;

	ret = set_param_single(&din->c2, c2, "c2");
	if (ret)
		goto fail_set_param;

	ret = set_param_single(&din->c3, c3, "c3");
	if (ret)
		goto fail_set_param;

	return ecc_in;

fail_set_param:
	release_ecc_in(sess_t, ecc_in);

	return NULL;
}

struct wd_ecc_out *wd_sm2_new_enc_out(handle_t sess, __u32 plaintext_len)
{
	struct wd_ecc_sess *sess_t = (struct wd_ecc_sess *)sess;
	__u32 struct_size = sizeof(struct wd_ecc_out);
	struct wd_ecc_out *ecc_out;
	__u64 len = 0;

	if (!sess_t) {
		WD_ERR("new ecc sout sess NULL!\n");
		return NULL;
	}

	ecc_out = create_sm2_ciphertext(sess_t, plaintext_len, &len, struct_size);
	if (!ecc_out) {
		WD_ERR("failed to create sm2 enc out!\n");
		return NULL;
	}
	ecc_out->size = len - struct_size;

	return ecc_out;
}

struct wd_ecc_out *wd_sm2_new_dec_out(handle_t sess, __u32 plaintext_len)
{
	struct wd_ecc_sess *sess_t = (struct wd_ecc_sess *)sess;
	struct wd_sm2_dec_out *dout;
	struct wd_ecc_out *ecc_out;
	__u64 len;

	if (!sess || !plaintext_len) {
		WD_ERR("new ecc sout sess NULL!\n");
		return NULL;
	}

	if (sess_t->key_size != SM2_KEY_SIZE) {
		WD_ERR("sess key size %u error!\n", sess_t->key_size);
		return NULL;
	}

	len = sizeof(*ecc_out) + plaintext_len;
	ecc_out = malloc(len);
	if (!ecc_out) {
		WD_ERR("failed to malloc ecc_out, sz = %llu!\n", len);
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

void wd_sm2_get_enc_out_params(struct wd_ecc_out *out,
			       struct wd_ecc_point **c1,
			       struct wd_dtb **c2,
			       struct wd_dtb **c3)
{
	struct wd_sm2_enc_out *eout = (void *)out;

	if (!eout) {
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

void wd_sm2_get_dec_out_params(struct wd_ecc_out *out,
			       struct wd_dtb **plaintext)
{
	struct wd_sm2_dec_out *dout = (void *)out;

	if (!dout) {
		WD_ERR("input NULL in get sm2 dec out!\n");
		return;
	}

	if (plaintext)
		*plaintext = &dout->plaintext;
}


struct wd_ecc_in *wd_ecdsa_new_sign_in(handle_t sess,
				       struct wd_dtb *dgst,
				       struct wd_dtb *k)
{
	return new_sign_in((struct wd_ecc_sess *)sess, dgst, k, NULL, 1);
}

struct wd_ecc_out *wd_ecdsa_new_sign_out(handle_t sess)
{
	return wd_ecc_new_sign_out((void *)sess);
}

void wd_ecdsa_get_sign_out_params(struct wd_ecc_out *out,
				  struct wd_dtb **r, struct wd_dtb **s)
{
	return get_sign_out_params(out, r, s);
}

struct wd_ecc_in *wd_ecdsa_new_verf_in(handle_t sess,
				       struct wd_dtb *dgst,
				       struct wd_dtb *r,
				       struct wd_dtb *s)
{
	return new_verf_in(sess, dgst, r, s, NULL, 1);
}

int wd_do_ecc_async(handle_t sess, struct wd_ecc_req *req)
{
	struct wd_ctx_config_internal *config = &wd_ecc_setting.config;
	handle_t h_sched_ctx = wd_ecc_setting.sched.h_sched_ctx;
	struct wd_ecc_sess *sess_t = (struct wd_ecc_sess *)sess;
	struct wd_ecc_msg *msg = NULL;
	struct wd_ctx_internal *ctx;
	int ret, mid;
	int idx;

	if (unlikely(!req || !sess || !req->cb)) {
		WD_ERR("input parameter NULL!\n");
		return -WD_EINVAL;
	}

	idx = wd_ecc_setting.sched.pick_next_ctx(h_sched_ctx,
							    sess_t->sched_key,
							    CTX_MODE_ASYNC);
	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	mid = wd_get_msg_from_pool(&wd_ecc_setting.pool, idx, (void **)&msg);
	if (mid < 0)
		return -WD_EBUSY;

	ret = fill_ecc_msg(msg, req, (struct wd_ecc_sess *)sess);
	if (ret)
		goto fail_with_msg;
	msg->tag = mid;

	pthread_spin_lock(&ctx->lock);
	ret = ecc_send(ctx->ctx, msg);
	if (ret) {
		pthread_spin_unlock(&ctx->lock);
		goto fail_with_msg;
	}
	pthread_spin_unlock(&ctx->lock);

	ret = wd_add_task_to_async_queue(&wd_ecc_env_config, idx);
	if (ret)
		goto fail_with_msg;

	return 0;

fail_with_msg:
	wd_put_msg_to_pool(&wd_ecc_setting.pool, idx, mid);
	return ret;
}

int wd_ecc_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_ecc_setting.config;
	struct wd_ecc_msg recv_msg, *msg;
	struct wd_ctx_internal *ctx;
	struct wd_ecc_req *req;
	__u32 rcv_cnt = 0;
	int ret;

	if (unlikely(!count)) {
		WD_ERR("param count is NULL!");
		return -WD_EINVAL;
	}

	*count = 0;

	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (ret)
		return ret;

	ctx = config->ctxs + idx;

	do {
		ret = wd_ecc_setting.driver->recv(ctx->ctx, &recv_msg);
		if (ret == -WD_EAGAIN) {
			return ret;
		} else if (ret < 0) {
			WD_ERR("failed to async recv, ret = %d!\n", ret);
			*count = rcv_cnt;
			wd_put_msg_to_pool(&wd_ecc_setting.pool, idx,
					   recv_msg.tag);
			return ret;
		}
		rcv_cnt++;
		msg = wd_find_msg_in_pool(&wd_ecc_setting.pool, idx,
					  recv_msg.tag);
		if (!msg) {
			WD_ERR("get msg from pool is NULL!\n");
			return -WD_EINVAL;
		}

		msg->req.dst_bytes = recv_msg.req.dst_bytes;
		msg->req.status = recv_msg.result;
		req = &msg->req;
		req->cb(req);
		wd_put_msg_to_pool(&wd_ecc_setting.pool, idx, recv_msg.tag);
		*count = rcv_cnt;
	} while (--expt);

	return ret;
}

int wd_ecc_poll(__u32 expt, __u32 *count)
{
	handle_t h_sched_sess = wd_ecc_setting.sched.h_sched_ctx;

	return wd_ecc_setting.sched.poll_policy(h_sched_sess, expt, count);
}

static const struct wd_config_variable table[] = {
	{ .name = "WD_ECC_CTX_NUM",
	  .def_val = "sync:2@0,async:2@0",
	  .parse_fn = wd_parse_ctx_num
	},
	{ .name = "WD_ECC_ASYNC_POLL_EN",
	  .def_val = "0",
	  .parse_fn = wd_parse_async_poll_en
	}
};

static const struct wd_alg_ops wd_ecc_ops = {
	.alg_name = "sm2",
	.op_type_num = 1,
	.alg_init = wd_ecc_init,
	.alg_uninit = wd_ecc_uninit,
	.alg_poll_ctx = wd_ecc_poll_ctx
};

int wd_ecc_env_init(struct wd_sched *sched)
{
	wd_ecc_env_config.sched = sched;

	return wd_alg_env_init(&wd_ecc_env_config, table,
			       &wd_ecc_ops, ARRAY_SIZE(table), NULL);
}

void wd_ecc_env_uninit(void)
{
	return wd_alg_env_uninit(&wd_ecc_env_config, &wd_ecc_ops);
}

int wd_ecc_ctx_num_init(__u32 node, __u32 type, __u32 num, __u8 mode)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, num);
	if (ret)
		return ret;

	return wd_alg_env_init(&wd_ecc_env_config, table,
			      &wd_ecc_ops, ARRAY_SIZE(table), &ctx_attr);
}

void wd_ecc_ctx_num_uninit(void)
{
	return wd_alg_env_uninit(&wd_ecc_env_config, &wd_ecc_ops);
}

int wd_ecc_get_env_param(__u32 node, __u32 type, __u32 mode,
			 __u32 *num, __u8 *is_enable)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	ret = wd_set_ctx_attr(&ctx_attr, node, CTX_TYPE_INVALID, mode, 0);
	if (ret)
		return ret;

	return wd_alg_get_env_param(&wd_ecc_env_config,
				    ctx_attr, num, is_enable);
}
