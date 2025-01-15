// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2011-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*
 * Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include "drv/wd_cipher_drv.h"
#include "wd_cipher.h"
#include "isa_ce_sm4.h"

#define SM4_ENCRYPT	1
#define SM4_DECRYPT	0
#define MSG_Q_DEPTH	1024
#define INCREASE_BYTES	12
#define SM4_BLOCK_SIZE	16
#define MAX_BLOCK_NUM	(1U << 28)
#define CTR96_SHIFT_BITS	8
#define SM4_BYTES2BLKS(nbytes)	((nbytes) >> 4)
#define SM4_KEY_SIZE 16

#define GETU32(p) \
	((__u32)(p)[0] << 24 | (__u32)(p)[1] << 16 | (__u32)(p)[2] << 8 | (__u32)(p)[3])
#define PUTU32(p, v) \
	((p)[0] = (__u8)((v) >> 24), (p)[1] = (__u8)((v) >> 16), \
	 (p)[2] = (__u8)((v) >> 8), (p)[3] = (__u8)(v))

static int isa_ce_init(struct wd_alg_driver *drv, void *conf)
{
	struct wd_ctx_config_internal *config = conf;
	struct sm4_ce_drv_ctx *priv;

	/* Fallback init is NULL */
	if (!drv || !conf)
		return 0;

	priv = malloc(sizeof(struct sm4_ce_drv_ctx));
	if (!priv)
		return -WD_EINVAL;

	config->epoll_en = 0;
	memcpy(&priv->config, config, sizeof(struct wd_ctx_config_internal));
	drv->priv = priv;

	return WD_SUCCESS;
}

static void isa_ce_exit(struct wd_alg_driver *drv)
{
	if(!drv || !drv->priv)
		return;

	struct sm4_ce_drv_ctx *sctx = (struct sm4_ce_drv_ctx *)drv->priv;

	free(sctx);
	drv->priv = NULL;
}

/* increment upper 96 bits of 128-bit counter by 1 */
static void ctr96_inc(__u8 *counter)
{
	__u32 n = INCREASE_BYTES;
	__u32 c = 1;

	do {
		--n;
		c += counter[n];
		counter[n] = (__u8)c;
		c >>= CTR96_SHIFT_BITS;
	} while (n);
}

static void sm4_v8_ctr32_encrypt(__u8 *in, __u8 *out,
				 __u64 len, const struct SM4_KEY *key, __u8 *iv)
{
	__u8 ecount_buf[SM4_BLOCK_SIZE] = {0};
	__u64 blocks, offset;
	__u32 ctr32;
	__u32 n = 0;

	ctr32 = GETU32(iv + INCREASE_BYTES);
	while (len >= SM4_BLOCK_SIZE) {
		blocks = len / SM4_BLOCK_SIZE;
		/*
		 * 1<<28 is just a not-so-small yet not-so-large number...
		 * Below condition is practically never met, but it has to
		 * be checked for code correctness.
		 */
		if (blocks > MAX_BLOCK_NUM)
			blocks = MAX_BLOCK_NUM;
		/*
		 * As (*func) operates on 32-bit counter, caller
		 * has to handle overflow. 'if' below detects the
		 * overflow, which is then handled by limiting the
		 * amount of blocks to the exact overflow point...
		 */
		ctr32 += (__u32)blocks;
		if (ctr32 < blocks) {
			blocks -= ctr32;
			ctr32 = 0;
		}
		sm4_v8_ctr32_encrypt_blocks(in, out, blocks, key, iv);
		/* (*ctr) does not update iv, caller does: */
		PUTU32(iv + INCREASE_BYTES, ctr32);
		/* ... overflow was detected, propagate carry. */
		if (ctr32 == 0)
			ctr96_inc(iv);
		offset = blocks * SM4_BLOCK_SIZE;
		len -= offset;
		out += offset;
		in += offset;
	}
	if (len) {
		sm4_v8_ctr32_encrypt_blocks(ecount_buf, ecount_buf, 1, key, iv);
		++ctr32;
		PUTU32(iv + INCREASE_BYTES, ctr32);
		if (ctr32 == 0)
			ctr96_inc(iv);
		while (len--) {
			out[n] = in[n] ^ ecount_buf[n];
			++n;
		}
	}
}

static void sm4_ctr_encrypt(struct wd_cipher_msg *msg, const struct SM4_KEY *rkey_enc)
{
	sm4_v8_ctr32_encrypt(msg->in, msg->out, msg->in_bytes, rkey_enc, msg->iv);
}

static void sm4_cbc_encrypt(struct wd_cipher_msg *msg, const struct SM4_KEY *rkey_enc)
{
	sm4_v8_cbc_encrypt(msg->in, msg->out, msg->in_bytes, rkey_enc, msg->iv, SM4_ENCRYPT);
}

static void sm4_cbc_decrypt(struct wd_cipher_msg *msg, const struct SM4_KEY *rkey_dec)
{
	sm4_v8_cbc_encrypt(msg->in, msg->out, msg->in_bytes, rkey_dec, msg->iv, SM4_DECRYPT);
}

/*
 * In some situations, the cts mode can use cbc mode instead to imporve performance.
 */
static int sm4_cts_cbc_instead(struct wd_cipher_msg *msg)
{
	if (msg->in_bytes == SM4_BLOCK_SIZE)
		return true;

	if (!(msg->in_bytes % SM4_BLOCK_SIZE) && msg->mode != WD_CIPHER_CBC_CS3)
		return true;

	return false;
}

static void sm4_cts_cs1_mode_adapt(__u8 *cts_in, __u8 *cts_out,
				   const __u32 cts_bytes, const int enc)
{
	__u32 rsv_bytes = cts_bytes % SM4_BLOCK_SIZE;
	__u8 blocks[SM4_BLOCK_SIZE] = {0};

	if (enc == SM4_ENCRYPT) {
		memcpy(blocks, cts_out, SM4_BLOCK_SIZE);
		memcpy(cts_out, cts_out + SM4_BLOCK_SIZE, rsv_bytes);
		memcpy(cts_out + rsv_bytes, blocks, SM4_BLOCK_SIZE);
	} else {
		memcpy(blocks, cts_in + rsv_bytes, SM4_BLOCK_SIZE);
		memcpy(cts_in + SM4_BLOCK_SIZE, cts_in, rsv_bytes);
		memcpy(cts_in, blocks, SM4_BLOCK_SIZE);
	}
}

static void sm4_cts_cbc_crypt(struct wd_cipher_msg *msg,
			      const struct SM4_KEY *rkey_enc, const int enc)
{
	enum wd_cipher_mode mode = msg->mode;
	__u32 in_bytes = msg->in_bytes;
	__u8 *cts_in, *cts_out;
	__u32 cts_bytes;

	if (sm4_cts_cbc_instead(msg))
		return sm4_v8_cbc_encrypt(msg->in, msg->out, in_bytes, rkey_enc, msg->iv, enc);

	cts_bytes = in_bytes % SM4_BLOCK_SIZE + SM4_BLOCK_SIZE;
	if (cts_bytes == SM4_BLOCK_SIZE)
		cts_bytes += SM4_BLOCK_SIZE;

	in_bytes -= cts_bytes;
	if (in_bytes)
		sm4_v8_cbc_encrypt(msg->in, msg->out, in_bytes, rkey_enc, msg->iv, enc);

	cts_in = msg->in + in_bytes;
	cts_out = msg->out + in_bytes;

	if (enc == SM4_ENCRYPT) {
		sm4_v8_cbc_cts_encrypt(cts_in, cts_out, cts_bytes, rkey_enc, msg->iv);

		if (mode == WD_CIPHER_CBC_CS1)
			sm4_cts_cs1_mode_adapt(cts_in, cts_out, cts_bytes, enc);
	} else {
		if (mode == WD_CIPHER_CBC_CS1)
			sm4_cts_cs1_mode_adapt(cts_in, cts_out, cts_bytes, enc);

		sm4_v8_cbc_cts_decrypt(cts_in, cts_out, cts_bytes, rkey_enc, msg->iv);
	}
}

static void sm4_cbc_cts_encrypt(struct wd_cipher_msg *msg, const struct SM4_KEY *rkey_enc)
{
	sm4_cts_cbc_crypt(msg, rkey_enc, SM4_ENCRYPT);
}

static void sm4_cbc_cts_decrypt(struct wd_cipher_msg *msg, const struct SM4_KEY *rkey_enc)
{
	sm4_cts_cbc_crypt(msg, rkey_enc, SM4_DECRYPT);
}

static void sm4_ecb_encrypt(struct wd_cipher_msg *msg, const struct SM4_KEY *rkey_enc)
{
	sm4_v8_ecb_encrypt(msg->in, msg->out, msg->in_bytes, rkey_enc, SM4_ENCRYPT);
}

static void sm4_ecb_decrypt(struct wd_cipher_msg *msg, const struct SM4_KEY *rkey_dec)
{
	sm4_v8_ecb_encrypt(msg->in, msg->out, msg->in_bytes, rkey_dec, SM4_DECRYPT);
}

static void sm4_set_encrypt_key(const __u8 *userKey, struct SM4_KEY *key)
{
	sm4_v8_set_encrypt_key(userKey, key);
}

static void sm4_set_decrypt_key(const __u8 *userKey, struct SM4_KEY *key)
{
	sm4_v8_set_decrypt_key(userKey, key);
}

static void sm4_cfb_crypt(struct wd_cipher_msg *msg, const struct SM4_KEY *rkey, const int enc)
{
	unsigned char keydata[SM4_BLOCK_SIZE];
	const unsigned char *src = msg->in;
	unsigned char *dst = msg->out;
	__u32 nbytes = msg->in_bytes;
	__u32 blocks, bbytes;
	__u32 i = 0;

	blocks = SM4_BYTES2BLKS(nbytes);
	if (blocks) {
		if (enc == SM4_ENCRYPT)
			sm4_v8_cfb_encrypt_blocks(src, dst, blocks, rkey, msg->iv);
		else
			sm4_v8_cfb_decrypt_blocks(src, dst, blocks, rkey, msg->iv);

		bbytes = blocks * SM4_BLOCK_SIZE;
		dst += bbytes;
		src += bbytes;
		nbytes -= bbytes;
	}

	if (nbytes == 0)
		return;

	sm4_v8_crypt_block(msg->iv, keydata, rkey);
	while (nbytes > 0) {
		*dst++ = *src++ ^ keydata[i++];
		nbytes--;
	}

	/* store new IV  */
	if (enc == SM4_ENCRYPT) {
		if (msg->out_bytes >= msg->iv_bytes)
			memcpy(msg->iv, msg->out + msg->out_bytes -
				msg->iv_bytes, msg->iv_bytes);
		else
			memcpy(msg->iv, msg->out, msg->out_bytes);
	} else {
		if (msg->in_bytes >= msg->iv_bytes)
			memcpy(msg->iv, msg->in + msg->in_bytes -
				msg->iv_bytes, msg->iv_bytes);
		else
			memcpy(msg->iv, msg->in, msg->in_bytes);
	}
}

static void sm4_cfb_encrypt(struct wd_cipher_msg *msg, const struct SM4_KEY *rkey_enc)
{
	sm4_cfb_crypt(msg, rkey_enc, SM4_ENCRYPT);
}

static void sm4_cfb_decrypt(struct wd_cipher_msg *msg, const struct SM4_KEY *rkey_dec)
{
	sm4_cfb_crypt(msg, rkey_dec, SM4_DECRYPT);
}

static int sm4_xts_encrypt(struct wd_cipher_msg *msg, const struct SM4_KEY *rkey)
{
	struct SM4_KEY rkey2;

	if (msg->in_bytes < SM4_BLOCK_SIZE) {
		WD_ERR("invalid: cipher input length is wrong!\n");
		return -WD_EINVAL;
	}

	/* set key for tweak */
	sm4_set_encrypt_key(msg->key + SM4_KEY_SIZE, &rkey2);

	sm4_v8_xts_encrypt(msg->in, msg->out, msg->in_bytes,
				rkey, msg->iv, &rkey2);

	return 0;
}

static int sm4_xts_decrypt(struct wd_cipher_msg *msg, const struct SM4_KEY *rkey)
{
	struct SM4_KEY rkey2;

	if (msg->in_bytes < SM4_BLOCK_SIZE) {
		WD_ERR("invalid: cipher input length is wrong!\n");
		return -WD_EINVAL;
	}

	/* set key for tweak */
	sm4_set_encrypt_key(msg->key + SM4_KEY_SIZE, &rkey2);

	sm4_v8_xts_decrypt(msg->in, msg->out, msg->in_bytes,
				rkey, msg->iv, &rkey2);

	return 0;
}

static int isa_ce_cipher_send(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	struct wd_cipher_msg *msg = wd_msg;
	struct SM4_KEY rkey;
	int ret = 0;

	if (!msg) {
		WD_ERR("invalid: input sm4 msg is NULL!\n");
		return -WD_EINVAL;
	}

	if (msg->data_fmt == WD_SGL_BUF) {
		WD_ERR("invalid: SM4 CE driver do not support sgl data format!\n");
		return -WD_EINVAL;
	}

	if (msg->op_type == WD_CIPHER_ENCRYPTION || msg->mode == WD_CIPHER_CTR
		|| msg->mode == WD_CIPHER_CFB)
		sm4_set_encrypt_key(msg->key, &rkey);
	else
		sm4_set_decrypt_key(msg->key, &rkey);

	switch (msg->mode) {
	case WD_CIPHER_ECB:
		if (msg->op_type == WD_CIPHER_ENCRYPTION)
			sm4_ecb_encrypt(msg, &rkey);
		else
			sm4_ecb_decrypt(msg, &rkey);
		break;
	case WD_CIPHER_CBC:
		if (msg->op_type == WD_CIPHER_ENCRYPTION)
			sm4_cbc_encrypt(msg, &rkey);
		else
			sm4_cbc_decrypt(msg, &rkey);
		break;
	case WD_CIPHER_CBC_CS1:
	case WD_CIPHER_CBC_CS2:
	case WD_CIPHER_CBC_CS3:
		if (msg->op_type == WD_CIPHER_ENCRYPTION)
			sm4_cbc_cts_encrypt(msg, &rkey);
		else
			sm4_cbc_cts_decrypt(msg, &rkey);
		break;
	case WD_CIPHER_CTR:
		sm4_ctr_encrypt(msg, &rkey);
		break;
	case WD_CIPHER_CFB:
		if (msg->op_type == WD_CIPHER_ENCRYPTION)
			sm4_cfb_encrypt(msg, &rkey);
		else
			sm4_cfb_decrypt(msg, &rkey);
		break;
	case WD_CIPHER_XTS:
		if (msg->op_type == WD_CIPHER_ENCRYPTION)
			ret = sm4_xts_encrypt(msg, &rkey);
		else
			ret = sm4_xts_decrypt(msg, &rkey);
		break;
	default:
		WD_ERR("The current block cipher mode is not supported!\n");
		return -WD_EINVAL;
	}

	return ret;
}

static int isa_ce_cipher_recv(struct wd_alg_driver *drv, handle_t ctx, void *wd_msg)
{
	return 0;
}

static int cipher_send(struct wd_alg_driver *drv, handle_t ctx, void *msg)
{
	return isa_ce_cipher_send(drv, ctx, msg);
}

static int cipher_recv(struct wd_alg_driver *drv, handle_t ctx, void *msg)
{
	return isa_ce_cipher_recv(drv, ctx, msg);
}

#define GEN_CE_ALG_DRIVER(ce_alg_name, alg_type) \
{\
	.drv_name = "isa_ce_sm4",\
	.alg_name = (ce_alg_name),\
	.calc_type = UADK_ALG_CE_INSTR,\
	.mode = UADK_DRV_SYNCONLY,\
	.priority = 200,\
	.op_type_num = 1,\
	.fallback = 0,\
	.init = isa_ce_init,\
	.exit = isa_ce_exit,\
	.send = alg_type##_send,\
	.recv = alg_type##_recv,\
}

static struct wd_alg_driver cipher_alg_driver[] = {
	GEN_CE_ALG_DRIVER("cbc(sm4)", cipher),
	GEN_CE_ALG_DRIVER("cbc-cs1(sm4)", cipher),
	GEN_CE_ALG_DRIVER("cbc-cs2(sm4)", cipher),
	GEN_CE_ALG_DRIVER("cbc-cs3(sm4)", cipher),
	GEN_CE_ALG_DRIVER("ctr(sm4)", cipher),
	GEN_CE_ALG_DRIVER("cfb(sm4)", cipher),
	GEN_CE_ALG_DRIVER("xts(sm4)", cipher),
	GEN_CE_ALG_DRIVER("ecb(sm4)", cipher),
};

static void __attribute__((constructor)) isa_ce_probe(void)
{
	__u32 alg_num, i;
	int ret;

	WD_INFO("Info: register SM4 CE alg drivers!\n");

	alg_num = ARRAY_SIZE(cipher_alg_driver);
	for (i = 0; i < alg_num; i++) {
		ret = wd_alg_driver_register(&cipher_alg_driver[i]);
		if (ret && ret != -WD_ENODEV)
			WD_ERR("Error: register SM4 CE %s failed!\n",
				cipher_alg_driver[i].alg_name);
	}
}

static void __attribute__((destructor)) isa_ce_remove(void)
{
	__u32 alg_num, i;

	WD_INFO("Info: unregister SM4 CE alg drivers!\n");
	alg_num = ARRAY_SIZE(cipher_alg_driver);
	for (i = 0; i < alg_num; i++)
		wd_alg_driver_unregister(&cipher_alg_driver[i]);
}
