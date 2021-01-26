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
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "wd.h"
#include "wd_aead.h"
#include "wd_util.h"

#define WCRYPTO_AEAD_CTX_MSG_NUM	1024
#define WCRYPTO_AEAD_MAX_CTX		256
#define MAX_AEAD_KEY_SIZE		64
#define MAX_AEAD_MAC_SIZE		64
#define MAX_CIPHER_KEY_SIZE		64
#define MAX_AEAD_AUTH_SIZE		64
#define MAX_AEAD_ASSOC_SIZE		65536
#define MAX_HMAC_KEY_SIZE		128
#define MAX_AEAD_RETRY_CNT		2000000
#define AEAD_SLEEP_INTERVAL		0xf

#define DES_KEY_SIZE 8
#define SM4_KEY_SIZE 16
#define SEC_3DES_2KEY_SIZE (2 * DES_KEY_SIZE)
#define SEC_3DES_3KEY_SIZE (3 * DES_KEY_SIZE)

#define AES_BLOCK_SIZE 16
#define GCM_BLOCK_SIZE 12

#define MAX_BURST_NUM	16

#define DES_WEAK_KEY_NUM 4
static __u64 des_weak_key[DES_WEAK_KEY_NUM] = {
	0x0101010101010101, 0xFEFEFEFEFEFEFEFE,
	0xE0E0E0E0F1F1F1F1, 0x1F1F1F1F0E0E0E0E
};

static int g_aead_mac_len[WCRYPTO_MAX_DIGEST_TYPE] = {
	WCRYPTO_SM3_LEN, WCRYPTO_MD5_LEN, WCRYPTO_SHA1_LEN,
	WCRYPTO_SHA256_LEN, WCRYPTO_SHA224_LEN,
	WCRYPTO_SHA384_LEN, WCRYPTO_SHA512_LEN,
	WCRYPTO_SHA512_224_LEN, WCRYPTO_SHA512_256_LEN
};

struct wcrypto_aead_cookie {
	struct wcrypto_aead_tag tag;
	struct wcrypto_aead_msg msg;
};

struct wcrypto_aead_ctx {
	struct wcrypto_aead_cookie cookies[WCRYPTO_AEAD_CTX_MSG_NUM];
	__u8 cstatus[WCRYPTO_AEAD_CTX_MSG_NUM];
	int cidx;
	unsigned long ctx_id;
	void *ckey;
	void *akey;
	__u16 ckey_bytes;
	__u16 akey_bytes;
	__u16 auth_size;
	__u16 iv_blk_size;
	struct wd_queue *q;
	struct wcrypto_aead_ctx_setup setup;
};

static void put_aead_cookies(struct wcrypto_aead_ctx *ctx,
			     struct wcrypto_aead_cookie **cookies, __u32 num)
{
	__u32 i;
	int idx;

	for (i = 0; i < num; i++) {
		idx = ((uintptr_t)cookies[i] - (uintptr_t)ctx->cookies) /
			sizeof(struct wcrypto_aead_cookie);
		if (idx < 0 || idx >= WCRYPTO_AEAD_CTX_MSG_NUM) {
			WD_ERR("aead cookie not exist!\n");
			continue;
		}

		__atomic_clear(&ctx->cstatus[idx], __ATOMIC_RELEASE);
	}
}

static int get_aead_cookies(struct wcrypto_aead_ctx *ctx,
			    struct wcrypto_aead_cookie **cookies, __u32 num)
{
	int idx = ctx->cidx;
	int cnt = 0;
	__u32 i;

	for (i = 0; i < num; i++) {
		while (__atomic_test_and_set(&ctx->cstatus[idx],
					     __ATOMIC_ACQUIRE)) {
			idx++;
			cnt++;
			if (idx == WCRYPTO_AEAD_CTX_MSG_NUM)
				idx = 0;
			if (cnt == WCRYPTO_AEAD_CTX_MSG_NUM)
				goto fail_with_cookies;
		}

		cookies[i] = &ctx->cookies[idx];
	}

	return WD_SUCCESS;

fail_with_cookies:
	put_aead_cookies(ctx, cookies, i);
	return -WD_EBUSY;
}

static void del_ctx_key(struct wcrypto_aead_ctx *ctx)
{
	struct wd_mm_br *br = &(ctx->setup.br);
	__u8 tmp[MAX_CIPHER_KEY_SIZE] = { 0 };

	/**
	 * When data_fmt is 'WD_SGL_BUF',  'akey' and 'ckey' is a sgl, and if u
	 * want to clear the SGL buffer, we can only use 'wd_sgl_cp_from_pbuf'
	 * whose 'pbuf' is all zero.
	 */
	if (ctx->ckey) {
		if (ctx->setup.data_fmt == WD_FLAT_BUF)
			memset(ctx->ckey, 0, MAX_CIPHER_KEY_SIZE);
		else if (ctx->setup.data_fmt == WD_SGL_BUF)
			wd_sgl_cp_from_pbuf(ctx->ckey, 0, tmp, MAX_CIPHER_KEY_SIZE);
	}

	if (ctx->akey) {
		if (ctx->setup.data_fmt == WD_FLAT_BUF)
			memset(ctx->akey, 0, MAX_AEAD_KEY_SIZE);
		else if (ctx->setup.data_fmt == WD_SGL_BUF)
			wd_sgl_cp_from_pbuf(ctx->akey, 0, tmp, MAX_AEAD_KEY_SIZE);
	}

	if (br && br->free) {
		if (ctx->ckey)
			br->free(br->usr, ctx->ckey);
		if (ctx->akey)
			br->free(br->usr, ctx->akey);
	}
}

static int get_iv_block_size(int mode)
{
	int ret;

	/* AEAD just used AES and SM4 algorithm */
	switch (mode) {
	case WCRYPTO_CIPHER_CBC:
	case WCRYPTO_CIPHER_CTR:
	case WCRYPTO_CIPHER_XTS:
	case WCRYPTO_CIPHER_OFB:
	case WCRYPTO_CIPHER_CFB:
	case WCRYPTO_CIPHER_CCM:
		ret = AES_BLOCK_SIZE;
		break;
	case WCRYPTO_CIPHER_GCM:
		ret = GCM_BLOCK_SIZE;
		break;
	default:
		ret = 0;
	}

	return ret;
}

static int create_ctx_para_check(struct wd_queue *q,
	struct wcrypto_aead_ctx_setup *setup)
{
	if (!q || !setup) {
		WD_ERR("input param is NULL\n");
		return -WD_EINVAL;
	}

	if (!setup->br.alloc || !setup->br.free ||
		!setup->br.iova_map || !setup->br.iova_unmap) {
		WD_ERR("fail to create cipher ctx user mm br!\n");
		return -WD_EINVAL;
	}
	if (!q->capa.alg || strcmp(q->capa.alg, "aead")) {
		WD_ERR("fail to matching algorithm! %s\n", q->capa.alg);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static void init_aead_cookie(struct wcrypto_aead_ctx *ctx,
	struct wcrypto_aead_ctx_setup *setup)
{
	int i;

	for (i = 0; i < WCRYPTO_AEAD_CTX_MSG_NUM; i++) {
		ctx->cookies[i].msg.alg_type = WCRYPTO_AEAD;
		ctx->cookies[i].msg.calg = setup->calg;
		ctx->cookies[i].msg.cmode = setup->cmode;
		ctx->cookies[i].msg.dalg = setup->dalg;
		ctx->cookies[i].msg.dmode = setup->dmode;
		ctx->cookies[i].msg.data_fmt = setup->data_fmt;
		ctx->cookies[i].tag.wcrypto_tag.ctx = ctx;
		ctx->cookies[i].tag.wcrypto_tag.ctx_id = ctx->ctx_id;
		ctx->cookies[i].msg.usr_data = (uintptr_t)&ctx->cookies[i].tag;
	}
}

/* Before initiate this context, we should get a queue from WD */
void *wcrypto_create_aead_ctx(struct wd_queue *q,
	struct wcrypto_aead_ctx_setup *setup)
{
	struct q_info *qinfo;
	struct wcrypto_aead_ctx *ctx;
	int ctx_id;

	if (create_ctx_para_check(q, setup))
		return NULL;

	qinfo = q->qinfo;
	/* lock at ctx creating/deleting */
	wd_spinlock(&qinfo->qlock);
	if (!qinfo->br.alloc && !qinfo->br.iova_map)
		memcpy(&qinfo->br, &setup->br, sizeof(qinfo->br));

	if (qinfo->br.usr != setup->br.usr) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("Err mm br in creating aead ctx!\n");
		return NULL;
	}

	if (qinfo->ctx_num >= WCRYPTO_AEAD_MAX_CTX) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("err: create too many aead ctx!\n");
		return NULL;
	}

	ctx_id = wd_alloc_ctx_id(q, WCRYPTO_AEAD_MAX_CTX);
	if (ctx_id < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("fail to alloc ctx id!\n");
		return NULL;
	}
	qinfo->ctx_num++;
	wd_unspinlock(&qinfo->qlock);

	ctx = malloc(sizeof(struct wcrypto_aead_ctx));
	if (!ctx) {
		WD_ERR("fail to alloc ctx memory!\n");
		goto free_ctx_id;
	}
	memset(ctx, 0, sizeof(struct wcrypto_aead_ctx));
	memcpy(&ctx->setup, setup, sizeof(ctx->setup));
	ctx->q = q;
	ctx->ctx_id = ctx_id;
	ctx->ckey = setup->br.alloc(setup->br.usr, MAX_CIPHER_KEY_SIZE);
	if (!ctx->ckey) {
		WD_ERR("fail to alloc cipher ctx key!\n");
		free(ctx);
		goto free_ctx_id;
	}
	ctx->akey = setup->br.alloc(setup->br.usr, MAX_AEAD_KEY_SIZE);
	if (!ctx->akey) {
		WD_ERR("fail to alloc authenticate ctx key!\n");
		setup->br.free(setup->br.usr, ctx->ckey);
		free(ctx);
		goto free_ctx_id;
	}

	ctx->iv_blk_size = get_iv_block_size(setup->cmode);
	init_aead_cookie(ctx, setup);

	return ctx;

free_ctx_id:
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	wd_free_ctx_id(q, ctx_id);
	wd_unspinlock(&qinfo->qlock);
	return NULL;
}

int wcrypto_aead_setauthsize(void *ctx, __u16 authsize)
{
	struct wcrypto_aead_ctx *ctxt = ctx;
	int ret = WD_SUCCESS;

	if (!ctx) {
		WD_ERR("input param is NULL!\n");
		return -WD_EINVAL;
	}

	if (authsize > MAX_AEAD_AUTH_SIZE) {
		WD_ERR("fail to check authsize!\n");
		return -WD_EINVAL;
	}

	ctxt->auth_size = authsize;

	return ret;
}

int wcrypto_aead_getauthsize(void *ctx)
{
	struct wcrypto_aead_ctx *ctxt = ctx;

	if (!ctx) {
		WD_ERR("input param is NULL!\n");
		return -WD_EINVAL;
	}

	return ctxt->auth_size;
}

int wcrypto_aead_get_maxauthsize(void *ctx)
{
	struct wcrypto_aead_ctx *ctxt = ctx;

	if (!ctx) {
		WD_ERR("input param is NULL!\n");
		return -WD_EINVAL;
	}

	if (ctxt->setup.cmode == WCRYPTO_CIPHER_CCM ||
		ctxt->setup.cmode == WCRYPTO_CIPHER_GCM)
		return WCRYPTO_CCM_GCM_LEN;

	if (ctxt->setup.dalg >= WCRYPTO_MAX_DIGEST_TYPE) {
		WD_ERR("fail to check authenticate alg!\n");
		return -WD_EINVAL;
	}

	return g_aead_mac_len[ctxt->setup.dalg];
}

static int is_des_weak_key(const __u64 *key, __u16 keylen)
{
	int i;

	for (i = 0; i < DES_WEAK_KEY_NUM; i++)
		if (*key == des_weak_key[i])
			return 1;

	return 0;
}

static int aes_key_len_check(__u16 length)
{
	switch (length) {
	case AES_KEYSIZE_128:
	case AES_KEYSIZE_192:
	case AES_KEYSIZE_256:
		return WD_SUCCESS;
	default:
		return -WD_EINVAL;
	}
}

static int cipher_key_len_check(int alg, __u16 length)
{
	int ret = WD_SUCCESS;

	switch (alg) {
	case WCRYPTO_CIPHER_SM4:
		if (length != SM4_KEY_SIZE)
			ret = -WD_EINVAL;
		break;
	case WCRYPTO_CIPHER_AES:
		ret = aes_key_len_check(length);
		break;
	case WCRYPTO_CIPHER_DES:
		if (length != DES_KEY_SIZE)
			ret = -WD_EINVAL;
		break;
	case WCRYPTO_CIPHER_3DES:
		if (length != SEC_3DES_2KEY_SIZE && length != SEC_3DES_3KEY_SIZE)
			ret = -WD_EINVAL;
		break;
	default:
		return -WD_EINVAL;
	}

	return ret;
}

int wcrypto_set_aead_ckey(void *ctx, __u8 *key, __u16 key_len)
{
	struct wcrypto_aead_ctx *ctxt = ctx;
	__u16 length = key_len;
	int ret;

	if (!ctx || !key) {
		WD_ERR("input param is NULL!\n");
		return -WD_EINVAL;
	}

	if (ctxt->setup.cmode == WCRYPTO_CIPHER_XTS)
		length = key_len / XTS_MODE_KEY_DIVISOR;

	ret = cipher_key_len_check(ctxt->setup.calg, length);
	if (ret != WD_SUCCESS) {
		WD_ERR("fail to check key length, alg = %u\n", ctxt->setup.calg);
		return ret;
	}

	if (ctxt->setup.calg == WCRYPTO_CIPHER_DES &&
		is_des_weak_key((__u64 *)key, length)) {
		WD_ERR("input des weak key!\n");
		return -WD_EINVAL;
	}

	ctxt->ckey_bytes = key_len;

	if (ctxt->setup.data_fmt == WD_SGL_BUF)
		wd_sgl_cp_from_pbuf(ctxt->ckey, 0, key, key_len);
	else
		memcpy(ctxt->ckey, key, key_len);

	return ret;
}

int wcrypto_set_aead_akey(void *ctx, __u8 *key, __u16 key_len)
{
	struct wcrypto_aead_ctx *ctxt = ctx;

	if (!ctx || !key) {
		WD_ERR("input param is NULL!\n");
		return -WD_EINVAL;
	}

	if (key_len > MAX_HMAC_KEY_SIZE) {
		WD_ERR("fail to check key length!\n");
		return -WD_EINVAL;
	}

	ctxt->akey_bytes = key_len;

	if (ctxt->setup.data_fmt == WD_SGL_BUF)
		wd_sgl_cp_from_pbuf(ctxt->akey, 0, key, key_len);
	else
		memcpy(ctxt->akey, key, key_len);

	return WD_SUCCESS;
}

static void aead_requests_uninit(struct wcrypto_aead_msg **req,
				struct wcrypto_aead_ctx *ctx, __u32 num)
{
	int i;

	for (i = 0; i < num; i++) {
		if (req[i]->aiv)
			ctx->setup.br.free(ctx->setup.br.usr, req[i]->aiv);
	}
}

static int aead_requests_init(struct wcrypto_aead_msg **req,
			     struct wcrypto_aead_op_data **op,
			     struct wcrypto_aead_ctx *ctx, __u32 num)
{
	struct wd_sec_udata *udata;
	int ret = -WD_EINVAL;
	__u32 i;

	for (i = 0; i < num; i++) {
		req[i]->calg = ctx->setup.calg;
		req[i]->cmode = ctx->setup.cmode;
		req[i]->dalg = ctx->setup.dalg;
		req[i]->dmode = ctx->setup.dmode;
		req[i]->ckey = ctx->ckey;
		req[i]->ckey_bytes = ctx->ckey_bytes;
		req[i]->akey = ctx->akey;
		req[i]->akey_bytes = ctx->akey_bytes;
		req[i]->op_type = op[i]->op_type;
		req[i]->iv = op[i]->iv;
		req[i]->iv_bytes = op[i]->iv_bytes;
		req[i]->in = op[i]->in;
		req[i]->in_bytes = op[i]->in_bytes;
		req[i]->out = op[i]->out;
		req[i]->out_bytes = op[i]->out_bytes;
		req[i]->assoc_bytes = op[i]->assoc_size;
		req[i]->auth_bytes = ctx->auth_size;
		udata = op[i]->priv;
		if (udata && udata->key) {
			req[i]->ckey = udata->key;
			req[i]->ckey_bytes = udata->key_bytes;
		}

		if (unlikely(op[i]->op_type == WCRYPTO_CIPHER_ENCRYPTION_DIGEST &&
		   op[i]->out_buf_bytes < op[i]->out_bytes + ctx->auth_size)) {
			WD_ERR("fail to check out buffer length %u!\n", i);
			goto err_uninit_requests;
		}

		if (unlikely(op[i]->iv_bytes != ctx->iv_blk_size ||
		    op[i]->iv_bytes == 0)) {
			WD_ERR("fail to check IV length %u!\n", i);
			goto err_uninit_requests;
		}

		req[i]->aiv = ctx->setup.br.alloc(ctx->setup.br.usr,
						  MAX_AEAD_KEY_SIZE);
		if (unlikely(!req[i]->aiv)) {
			WD_ERR("fail to alloc auth iv memory %u!\n", i);
			ret = -WD_ENOMEM;
			goto err_uninit_requests;
		}
	}

	return WD_SUCCESS;

err_uninit_requests:
	aead_requests_uninit(req, ctx, i);
	return ret;
}

static int aead_recv_sync(struct wcrypto_aead_ctx *ctx,
			  struct wcrypto_aead_op_data **opdata, __u32 num)
{
	struct wcrypto_aead_msg *resp[WCRYPTO_MAX_BURST_NUM];
	__u32 recv_count = 0;
	__u64 rx_cnt = 0;
	__u32 i;
	int ret;

	for (i = 0; i < num; i++)
		resp[i] = (void *)(uintptr_t)ctx->ctx_id;

	while (true) {
		ret = wd_burst_recv(ctx->q, (void **)resp, num - recv_count);
		if (ret >= 0) {
			recv_count += ret;
			if (recv_count == num)
				break;

			if (++rx_cnt > MAX_AEAD_RETRY_CNT)
				break;

			if (!(rx_cnt & AEAD_SLEEP_INTERVAL))
				usleep(1);
		} else {
			WD_ERR("fail to do aead wcrypto_recv!\n");
			return ret;
		}
	}

	for (i = 0; i < recv_count; i++) {
		opdata[i]->out = (void *)resp[i]->out;
		opdata[i]->out_bytes = resp[i]->out_bytes;
		opdata[i]->status = resp[i]->result;
	}

	return recv_count;
}

static int param_check(struct wcrypto_aead_ctx *ctx,
		       struct wcrypto_aead_op_data **opdata,
		       void **tag, __u32 num)
{
	__u32 i;

	if (unlikely(!ctx || !opdata || !num || num > WCRYPTO_MAX_BURST_NUM)) {
		WD_ERR("input param err!\n");
		return -WD_EINVAL;
	}

	for (i = 0; i < num; i++) {
		if (unlikely(!opdata[i])) {
			WD_ERR("opdata[%u] is NULL!\n", i);
			return -WD_EINVAL;
		}

		if (unlikely(tag && !tag[i])) {
			WD_ERR("tag[%u] is NULL!\n", i);
			return -WD_EINVAL;
		}
	}

	if (unlikely(tag && !ctx->setup.cb)) {
		WD_ERR("ctx call back is NULL!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

int wcrypto_burst_aead(void *ctx, struct wcrypto_aead_op_data **opdata,
		       void **tag, __u32 num)
{
	struct wcrypto_aead_cookie *cookies[WCRYPTO_MAX_BURST_NUM];
	struct wcrypto_aead_msg *req[WCRYPTO_MAX_BURST_NUM];
	struct wcrypto_aead_ctx *ctxt = ctx;
	__u32 i;
	int ret;

	if (param_check(ctxt, opdata, tag, num))
		return -WD_EINVAL;

	ret = get_aead_cookies(ctxt, cookies, num);
	if (unlikely(ret)) {
		WD_ERR("failed to get cookies %d!\n", ret);
		return ret;
	}

	for (i = 0; i < num; i++) {
		cookies[i]->tag.priv = opdata[i]->priv;
		req[i] = &cookies[i]->msg;
		if (tag)
			cookies[i]->tag.wcrypto_tag.tag = tag[i];
	}

	ret = aead_requests_init(req, opdata, ctxt, num);
	if (unlikely(ret))
		goto fail_with_cookies;

	ret = wd_burst_send(ctxt->q, (void **)req, num);
	if (unlikely(ret)) {
		WD_ERR("failed to send req %d!\n", ret);
		goto fail_with_send;
	}

	if (tag)
		return ret;

	ret = aead_recv_sync(ctxt, opdata, num);

fail_with_send:
	aead_requests_uninit(req, ctxt, num);
fail_with_cookies:
	put_aead_cookies(ctxt, cookies, num);
	return ret;
}

int wcrypto_do_aead(void *ctx, struct wcrypto_aead_op_data *opdata, void *tag)
{
	if (!tag)
		return wcrypto_burst_aead(ctx, &opdata, NULL, 1);
	else
		return wcrypto_burst_aead(ctx, &opdata, &tag, 1);
}

int wcrypto_aead_poll(struct wd_queue *q, unsigned int num)
{
	struct wcrypto_aead_ctx *ctx;
	struct wcrypto_aead_msg *resp = NULL;
	struct wcrypto_aead_tag *tag;
	int count = 0;
	int ret;

	if (unlikely(!q)) {
		WD_ERR("queue is NULL!\n");
		return -WD_EINVAL;
	}

	do {
		resp = NULL;
		ret = wd_recv(q, (void **)&resp);
		if (ret == 0)
			break;
		else if (ret == -WD_HW_EACCESS) {
			if (!resp) {
				WD_ERR("fail to recv req_cache!\n");
				return ret;
			}
			resp->result = WD_HW_EACCESS;
		} else if (ret < 0) {
			WD_ERR("fail to poll aead!\n");
			return ret;
		}
		count++;
		tag = (void *)(uintptr_t)resp->usr_data;
		ctx = tag->wcrypto_tag.ctx;
		ctx->setup.cb(resp, tag->wcrypto_tag.tag);
		aead_requests_uninit(&resp, ctx, 1);
		put_aead_cookies(ctx, (struct wcrypto_aead_cookie **)&tag, 1);
	} while (--num);

	return count;
}

void wcrypto_del_aead_ctx(void *ctx)
{
	struct wcrypto_aead_ctx *ctxt;
	struct q_info *qinfo;

	if (!ctx) {
		WD_ERR("Delete aead ctx is NULL!\n");
		return;
	}
	ctxt = ctx;
	qinfo = ctxt->q->qinfo;
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	wd_free_ctx_id(ctxt->q, ctxt->ctx_id);
	if (!qinfo->ctx_num)
		memset(&qinfo->br, 0, sizeof(qinfo->br));
	if (qinfo->ctx_num < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("fail to delete aead ctx!\n");
		return;
	}
	wd_unspinlock(&qinfo->qlock);
	del_ctx_key(ctxt);
	free(ctx);
}
