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
 * Copyright 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include <stdlib.h>
#include <sys/auxv.h>
#include <pthread.h>
#include "drv/isa_ce_sm3.h"
#include "drv/wd_digest_drv.h"
#include "wd_digest.h"
#include "wd_util.h"

typedef void (sm3_ce_block_fn)(__u32 word_reg[SM3_STATE_WORDS],
				const unsigned char *src, size_t blocks);

static int sm3_ce_drv_init(struct wd_alg_driver *drv, void *conf);
static void sm3_ce_drv_exit(struct wd_alg_driver *drv);
static int sm3_ce_drv_send(struct wd_alg_driver *drv, handle_t ctx, void *digest_msg);
static int sm3_ce_drv_recv(struct wd_alg_driver *drv, handle_t ctx, void *digest_msg);
static int sm3_ce_get_usage(void *param);

static struct wd_alg_driver sm3_ce_alg_driver = {
	.drv_name = "isa_ce_sm3",
	.alg_name = "sm3",
	.calc_type = UADK_ALG_CE_INSTR,
	.mode = UADK_DRV_SYNCONLY,
	.priority = 200,
	.queue_num = 1,
	.op_type_num = 1,
	.fallback = 0,
	.init = sm3_ce_drv_init,
	.exit = sm3_ce_drv_exit,
	.send = sm3_ce_drv_send,
	.recv = sm3_ce_drv_recv,
	.get_usage = sm3_ce_get_usage,
};

static void __attribute__((constructor)) sm3_ce_probe(void)
{
	int ret;

	WD_INFO("Info: register SM3 CE alg driver!\n");
	ret = wd_alg_driver_register(&sm3_ce_alg_driver);
	if (ret && ret != -WD_ENODEV)
		WD_ERR("Error: register SM3 CE failed!\n");
}

static void __attribute__((destructor)) sm3_ce_remove(void)
{
	wd_alg_driver_unregister(&sm3_ce_alg_driver);
}

static int sm3_ce_get_usage(void *param)
{
	return WD_SUCCESS;
}

static inline void sm3_ce_init(struct sm3_ce_ctx *sctx)
{
	sctx->word_reg[0] = SM3_IVA;
	sctx->word_reg[1] = SM3_IVB;
	sctx->word_reg[2] = SM3_IVC;
	sctx->word_reg[3] = SM3_IVD;
	sctx->word_reg[4] = SM3_IVE;
	sctx->word_reg[5] = SM3_IVF;
	sctx->word_reg[6] = SM3_IVG;
	sctx->word_reg[7] = SM3_IVH;
}

static void trans_output_result(__u8 *out_digest, __u32 *word_reg)
{
	size_t i;

	for (i = 0; i < SM3_STATE_WORDS; i++)
		PUTU32_TO_U8(out_digest + i * WORD_TO_CHAR_OFFSET, word_reg[i]);
}

static void sm3_ce_init_ex(struct sm3_ce_ctx *sctx, __u8 *iv, __u16 iv_bytes)
{
	size_t i;

	if (iv_bytes != SM3_DIGEST_SIZE) {
		WD_ERR("invalid iv size: %u\n", iv_bytes);
		return;
	}

	for (i = 0; i < SM3_STATE_WORDS; i++)
		PUTU8_TO_U32(sctx->word_reg[i], iv + i * WORD_TO_CHAR_OFFSET);
}

static void sm3_ce_update(struct sm3_ce_ctx *sctx, const __u8 *data,
			  size_t data_len, sm3_ce_block_fn *block_fn)
{
	size_t remain_data_len, blk_num;

	/* Get the data num that need compute currently */
	sctx->num &= (SM3_BLOCK_SIZE - 1);

	if (sctx->num) {
		remain_data_len = SM3_BLOCK_SIZE - sctx->num;
		/* If data_len does not enough a block size, then leave it to final */
		if (data_len < remain_data_len) {
			memcpy(sctx->block + sctx->num, data, data_len);
			sctx->num += data_len;
			return;
		}

		memcpy(sctx->block + sctx->num, data, remain_data_len);
		block_fn(sctx->word_reg, sctx->block, 1);
		sctx->nblocks++;
		data += remain_data_len;
		data_len -= remain_data_len;
	}

	/* Group the filled msg by 512-bits (64-bytes) */
	blk_num = data_len / SM3_BLOCK_SIZE;
	if (blk_num) {
		block_fn(sctx->word_reg, data, blk_num);
		sctx->nblocks += blk_num;
		data += SM3_BLOCK_SIZE * blk_num;
		data_len -= SM3_BLOCK_SIZE * blk_num;
	}

	sctx->num = data_len;
	if (data_len)
		memcpy(sctx->block, data, data_len);
}

static void sm3_ce_final(struct sm3_ce_ctx *sctx, __u8 *md,
			sm3_ce_block_fn *block_fn)
{
	size_t i, offset1, offset2;
	__u64 nh, nl;

	sctx->num &= (SM3_BLOCK_SIZE - 1);
	sctx->block[sctx->num] = SM3_PADDING_BYTE;

	if (sctx->num <= SM3_BLOCK_SIZE - BIT_TO_BLOCK_OFFSET) {
		memset(sctx->block + sctx->num + 1, 0, SM3_BLOCK_SIZE - sctx->num - 9);
	} else {
		memset(sctx->block + sctx->num + 1, 0, SM3_BLOCK_SIZE - sctx->num - 1);
		block_fn(sctx->word_reg, sctx->block, 1);
		memset(sctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	/*
	 * Put the length of the message in bits into the last
	 * 64-bits (penultimate two words).
	 */
	offset2 = SM3_BLOCK_SIZE - WORD_TO_CHAR_OFFSET * 2;
	offset1 = SM3_BLOCK_SIZE - WORD_TO_CHAR_OFFSET;
	nh = sctx->nblocks >> NH_OFFSET;
	nl = (sctx->nblocks << BIT_TO_BLOCK_OFFSET) + (sctx->num << BIT_TO_BYTE_OFFSET);
	PUTU32_TO_U8(sctx->block + offset2 , nh);
	PUTU32_TO_U8(sctx->block + offset1, nl);

	block_fn(sctx->word_reg, sctx->block, 1);
	for (i = 0; i < SM3_STATE_WORDS; i++)
		PUTU32_TO_U8(md + i * WORD_TO_CHAR_OFFSET, sctx->word_reg[i]);
}

static int do_sm3_ce(struct wd_digest_msg *msg, __u8 *out_digest)
{
	enum hash_block_type block_type;
	struct sm3_ce_ctx sctx = {0};
	size_t data_len, iv_len;
	__u8 *data, *iv;

	block_type = get_hash_block_type(msg);
	data_len = msg->in_bytes;
	data = msg->in;
	iv_len = SM3_DIGEST_SIZE;
	/* Use last output as the iv in current cycle */
	iv = msg->out;

	switch(block_type) {
	case HASH_SINGLE_BLOCK:
		sm3_ce_init(&sctx);
		sm3_ce_update(&sctx, data, data_len, sm3_ce_block_compress);
		sm3_ce_final(&sctx, out_digest, sm3_ce_block_compress);
		break;
	case HASH_FIRST_BLOCK:
		sm3_ce_init(&sctx);
		sm3_ce_update(&sctx, data, data_len, sm3_ce_block_compress);
		trans_output_result(out_digest, sctx.word_reg);
		break;
	case HASH_MIDDLE_BLOCK:
		sm3_ce_init_ex(&sctx, iv, iv_len);
		sm3_ce_update(&sctx, data, data_len, sm3_ce_block_compress);
		/* Transform the middle result without final padding */
		trans_output_result(out_digest, sctx.word_reg);
		break;
	case HASH_END_BLOCK:
		sm3_ce_init_ex(&sctx, iv, iv_len);
		sm3_ce_update(&sctx, data, data_len, sm3_ce_block_compress);
		/* Put the whole message length in last 64-bits */
		sctx.nblocks = msg->long_data_len / SM3_BLOCK_SIZE;
		sm3_ce_final(&sctx, out_digest, sm3_ce_block_compress);
		break;
	default:
		WD_ERR("Invalid block type!\n");
		return -WD_EINVAL;
	}

	if (msg->out_bytes < SM3_DIGEST_SIZE)
		memcpy(msg->out, out_digest, msg->out_bytes);
	else
		memcpy(msg->out, out_digest, SM3_DIGEST_SIZE);

	memset(&sctx, 0, sizeof(struct sm3_ce_ctx));

	return WD_SUCCESS;
}

static void sm3_hmac_key_padding(struct hmac_sm3_ctx *hctx,
				 const __u8 *key, size_t key_len)
{
	size_t i;

	if (key_len <= SM3_BLOCK_SIZE) {
		memcpy(hctx->key, key, key_len);
		memset(hctx->key + key_len, 0, SM3_BLOCK_SIZE - key_len);
	} else {
		sm3_ce_init(&hctx->sctx);
		sm3_ce_update(&hctx->sctx, key, key_len, sm3_ce_block_compress);
		sm3_ce_final(&hctx->sctx, hctx->key, sm3_ce_block_compress);
		/* Pad key to SM3_BLOCK_SIZE after hash */
		memset(hctx->key + SM3_DIGEST_SIZE, 0,
			SM3_BLOCK_SIZE - SM3_DIGEST_SIZE);
	}

	for (i = 0; i < SM3_BLOCK_SIZE; i++) {
		hctx->key[i] ^= IPAD_DATA;
	}
}

static void sm3_ce_hmac_init(struct hmac_sm3_ctx *hctx, const __u8 *key, size_t key_len)
{
	sm3_hmac_key_padding(hctx, key, key_len);

	/* Ipadded key is the first block to hash in first cycle */
	sm3_ce_init(&hctx->sctx);
	sm3_ce_update(&hctx->sctx, hctx->key, SM3_BLOCK_SIZE, sm3_ce_block_compress);
}

static void sm3_ce_hmac_update(struct hmac_sm3_ctx *hctx, const __u8 *data, size_t data_len)
{
	sm3_ce_update(&hctx->sctx, data, data_len, sm3_ce_block_compress);
}

static void sm3_ce_hmac_final(struct hmac_sm3_ctx *hctx, __u8 *out_hmac)
{
	__u8 digest[SM3_DIGEST_SIZE] = {0};
	size_t i;

	for (i = 0; i < SM3_BLOCK_SIZE; i++) {
		hctx->key[i] ^= (IPAD_DATA ^ OPAD_DATA);
	}

	/* Compute the last data from update process */
	sm3_ce_final(&hctx->sctx, digest, sm3_ce_block_compress);

	/* Opadded key is the first block to hash in second cycle */
	memset(&hctx->sctx, 0, sizeof(struct sm3_ce_ctx));
	sm3_ce_init(&hctx->sctx);
	sm3_ce_update(&hctx->sctx, hctx->key, SM3_BLOCK_SIZE, sm3_ce_block_compress);

	/* Compute the the first cycle result */
	sm3_ce_update(&hctx->sctx, digest, SM3_DIGEST_SIZE, sm3_ce_block_compress);
	sm3_ce_final(&hctx->sctx, out_hmac, sm3_ce_block_compress);
}

static int do_hmac_sm3_ce(struct wd_digest_msg *msg, __u8 *out_hmac)
{
	size_t data_len, key_len, iv_len;
	enum hash_block_type block_type;
	struct hmac_sm3_ctx hctx = {0};
	__u8 *data, *key, *iv;

	data_len = msg->in_bytes;
	data = msg->in;
	key = msg->key;
	key_len = msg->key_bytes;
	iv_len = SM3_DIGEST_SIZE;
	/* Use last output as the iv in current cycle */
	iv = msg->out;

	if (!key_len) {
		WD_ERR("invalid hmac key_len is 0!\n");
		return -WD_EINVAL;
	}

	block_type = get_hash_block_type(msg);
	switch(block_type) {
	case HASH_SINGLE_BLOCK:
		sm3_ce_hmac_init(&hctx, key, key_len);
		sm3_ce_hmac_update(&hctx, data, data_len);
		sm3_ce_hmac_final(&hctx, out_hmac);
		break;
	case HASH_FIRST_BLOCK:
		sm3_ce_hmac_init(&hctx, key, key_len);
		sm3_ce_hmac_update(&hctx, data, data_len);
		trans_output_result(out_hmac, hctx.sctx.word_reg);
		break;
	case HASH_MIDDLE_BLOCK:
		sm3_ce_init_ex(&(hctx.sctx), iv, iv_len);
		sm3_ce_hmac_update(&hctx, data, data_len);
		trans_output_result(out_hmac, hctx.sctx.word_reg);
		break;
	case HASH_END_BLOCK:
		sm3_hmac_key_padding(&hctx, key, key_len);
		sm3_ce_init_ex(&(hctx.sctx), iv, iv_len);
		sm3_ce_hmac_update(&hctx, data, data_len);
		hctx.sctx.nblocks = msg->long_data_len / SM3_BLOCK_SIZE + KEY_BLOCK_NUM;
		sm3_ce_hmac_final(&hctx, out_hmac);
		break;
	default:
		WD_ERR("Invalid block type!\n");
		return -WD_EINVAL;
	}

	if (msg->out_bytes < SM3_DIGEST_SIZE)
		memcpy(msg->out, out_hmac, msg->out_bytes);
	else
		memcpy(msg->out, out_hmac, SM3_DIGEST_SIZE);

	memset(&hctx, 0, sizeof(struct hmac_sm3_ctx));

	return WD_SUCCESS;
}

static int sm3_ce_drv_send(struct wd_alg_driver *drv, handle_t ctx, void *digest_msg)
{
	struct wd_digest_msg *msg = (struct wd_digest_msg *)digest_msg;
	__u8 digest[SM3_DIGEST_SIZE] = {0};
	int ret;

	if (!msg) {
		WD_ERR("invalid: digest_msg is NULL!\n");
		return -WD_EINVAL;
	}

	if (msg->data_fmt == WD_SGL_BUF) {
		WD_ERR("invalid: SM3 CE driver do not support sgl data format!\n");
		return -WD_EINVAL;
	}

	if (msg->mode == WD_DIGEST_NORMAL) {
		ret = do_sm3_ce(msg, digest);
	} else if (msg->mode == WD_DIGEST_HMAC) {
		ret = do_hmac_sm3_ce(msg, digest);
	} else {
		WD_ERR("invalid digest mode!\n");
		ret = -WD_EINVAL;
	}

	return ret;
}

static int sm3_ce_drv_recv(struct wd_alg_driver *drv, handle_t ctx, void *digest_msg)
{
	return WD_SUCCESS;
}

static int sm3_ce_drv_init(struct wd_alg_driver *drv, void *conf)
{
	struct wd_ctx_config_internal *config = (struct wd_ctx_config_internal *)conf;
	struct sm3_ce_drv_ctx *priv;

	/* Fallback init is NULL */
	if (!drv || !conf)
		return 0;

	priv = malloc(sizeof(struct sm3_ce_drv_ctx));
	if (!priv)
		return -WD_EINVAL;

	config->epoll_en = 0;
	memcpy(&priv->config, config, sizeof(struct wd_ctx_config_internal));
	drv->priv = priv;

	return WD_SUCCESS;
}

static void sm3_ce_drv_exit(struct wd_alg_driver *drv)
{
	if(!drv || !drv->priv)
		return;

	struct sm3_ce_drv_ctx *sctx = (struct sm3_ce_drv_ctx *)drv->priv;

	free(sctx);
	drv->priv = NULL;
}
