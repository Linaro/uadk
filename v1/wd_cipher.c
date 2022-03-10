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

#include "v1/wd.h"
#include "v1/wd_cipher.h"
#include "v1/wd_util.h"

#define MAX_CIPHER_KEY_SIZE		64
#define MAX_CIPHER_RETRY_CNT		20000000

#define DES_KEY_SIZE 8
#define SM4_KEY_SIZE 16
#define SEC_3DES_2KEY_SIZE (2 * DES_KEY_SIZE)
#define SEC_3DES_3KEY_SIZE (3 * DES_KEY_SIZE)

#define CBC_3DES_BLOCK_SIZE 8
#define CBC_AES_BLOCK_SIZE 16
#define DES_WEAK_KEY_NUM 4
static __u64 des_weak_key[DES_WEAK_KEY_NUM] = {0x0101010101010101, 0xFEFEFEFEFEFEFEFE,
	0xE0E0E0E0F1F1F1F1, 0x1F1F1F1F0E0E0E0E};

struct wcrypto_cipher_cookie {
	struct wcrypto_cipher_tag tag;
	struct wcrypto_cipher_msg msg;
};

struct wcrypto_cipher_ctx {
	struct wd_cookie_pool pool;
	unsigned long ctx_id;
	void *key;
	__u32 key_bytes;
	__u32 iv_blk_size;
	struct wd_queue *q;
	struct wcrypto_cipher_ctx_setup setup;
};

static void del_ctx_key(struct wcrypto_cipher_ctx *ctx)
{
	struct wd_mm_br *br = &(ctx->setup.br);
	__u8 tmp[MAX_CIPHER_KEY_SIZE] = { 0 };

	/**
	 * When data_fmt is 'WD_SGL_BUF',  'akey' and 'ckey' is a sgl, and if u
	 * want to clear the SGL buffer, we can only use 'wd_sgl_cp_from_pbuf'
	 * whose 'pbuf' is all zero.
	 */
	if (ctx->key) {
		if (ctx->setup.data_fmt == WD_FLAT_BUF)
			memset(ctx->key, 0, MAX_CIPHER_KEY_SIZE);
		else if (ctx->setup.data_fmt == WD_SGL_BUF)
			wd_sgl_cp_from_pbuf(ctx->key, 0, tmp, MAX_CIPHER_KEY_SIZE);
	}

	if (br && br->free && ctx->key)
		br->free(br->usr, ctx->key);
}

static __u32 get_iv_block_size(int alg, int mode)
{
	__u32 iv_block_size = CBC_AES_BLOCK_SIZE;

	switch (mode) {
	case WCRYPTO_CIPHER_CBC:
	case WCRYPTO_CIPHER_OFB:
		if (alg == WCRYPTO_CIPHER_3DES ||
		    alg == WCRYPTO_CIPHER_DES)
			iv_block_size = CBC_3DES_BLOCK_SIZE;
		break;
	case WCRYPTO_CIPHER_XTS:
	case WCRYPTO_CIPHER_CFB:
	case WCRYPTO_CIPHER_CTR:
		break;
	default:
		iv_block_size = 0;
		break;
	}

	return iv_block_size;
}

static int create_ctx_para_check(struct wd_queue *q,
	struct wcrypto_cipher_ctx_setup *setup)
{
	if (!q || !setup) {
		WD_ERR("%s: input param err!\n", __func__);
		return -WD_EINVAL;
	}

	if (!setup->br.alloc || !setup->br.free ||
		!setup->br.iova_map || !setup->br.iova_unmap) {
		WD_ERR("create cipher ctx user mm br err!\n");
		return -WD_EINVAL;
	}
	if (strcmp(q->capa.alg, "cipher") &&
		strcmp(q->capa.alg, "xts(aes)") &&
		strcmp(q->capa.alg, "xts(sm4)")) {
		WD_ERR("%s: algorithm mismatching!\n", __func__);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static void init_cipher_cookie(struct wcrypto_cipher_ctx *ctx,
	struct wcrypto_cipher_ctx_setup *setup)
{
	struct wcrypto_cipher_cookie *cookie;
	int i;

	for (i = 0; i < ctx->pool.cookies_num; i++) {
		cookie = (void *)((uintptr_t)ctx->pool.cookies +
			i * ctx->pool.cookies_size);
		cookie->msg.alg_type = WCRYPTO_CIPHER;
		cookie->msg.alg = setup->alg;
		cookie->msg.data_fmt = setup->data_fmt;
		cookie->msg.mode = setup->mode;
		cookie->tag.wcrypto_tag.ctx = ctx;
		cookie->tag.wcrypto_tag.ctx_id = ctx->ctx_id;
		cookie->msg.usr_data = (uintptr_t)&cookie->tag;
	}
}

static int setup_qinfo(struct wcrypto_cipher_ctx_setup *setup,
		       struct q_info *qinfo, __u32 *ctx_id)
{
	int ret;

	/* lock at ctx creating/deleting */
	wd_spinlock(&qinfo->qlock);
	if (!qinfo->br.alloc && !qinfo->br.iova_map)
		memcpy(&qinfo->br, &setup->br, sizeof(qinfo->br));

	if (qinfo->br.usr != setup->br.usr) {
		WD_ERR("Err mm br in creating cipher ctx!\n");
		goto unlock;
	}

	if (qinfo->ctx_num >= WD_MAX_CTX_NUM) {
		WD_ERR("err:create too many cipher ctx!\n");
		goto unlock;
	}

	ret = wd_alloc_id(qinfo->ctx_id, WD_MAX_CTX_NUM, ctx_id, 0,
		WD_MAX_CTX_NUM);
	if (ret) {
		WD_ERR("err: alloc ctx id fail!\n");
		goto unlock;
	}
	qinfo->ctx_num++;
	wd_unspinlock(&qinfo->qlock);

	return 0;
unlock:
	wd_unspinlock(&qinfo->qlock);
	return -WD_EINVAL;
}

/* Before initiate this context, we should get a queue from WD */
void *wcrypto_create_cipher_ctx(struct wd_queue *q,
	struct wcrypto_cipher_ctx_setup *setup)
{
	struct q_info *qinfo;
	struct wcrypto_cipher_ctx *ctx;
	__u32 ctx_id = 0;
	int ret;

	if (create_ctx_para_check(q, setup))
		return NULL;

	qinfo = q->qinfo;
	ret = setup_qinfo(setup, qinfo, &ctx_id);
	if (ret)
		return NULL;

	ctx = malloc(sizeof(struct wcrypto_cipher_ctx));
	if (!ctx) {
		WD_ERR("Alloc ctx memory fail!\n");
		goto free_ctx_id;
	}
	memset(ctx, 0, sizeof(struct wcrypto_cipher_ctx));
	memcpy(&ctx->setup, setup, sizeof(ctx->setup));
	ctx->q = q;
	ctx->ctx_id = ctx_id + 1;
	ctx->key = setup->br.alloc(setup->br.usr, MAX_CIPHER_KEY_SIZE);
	if (!ctx->key) {
		WD_ERR("alloc cipher ctx key fail!\n");
		goto free_ctx;
	}

	ctx->iv_blk_size = get_iv_block_size(setup->alg, setup->mode);

	ret = wd_init_cookie_pool(&ctx->pool,
		sizeof(struct wcrypto_cipher_cookie), WD_CTX_MSG_NUM);
	if (ret) {
		WD_ERR("fail to init cookie pool!\n");
		goto free_ctx_key;
	}
	init_cipher_cookie(ctx, setup);

	return ctx;

free_ctx_key:
	setup->br.free(setup->br.usr, ctx->key);
free_ctx:
	free(ctx);
free_ctx_id:
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	wd_free_id(qinfo->ctx_id, WD_MAX_CTX_NUM, ctx_id, WD_MAX_CTX_NUM);
	wd_unspinlock(&qinfo->qlock);

	return NULL;
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

static int cipher_key_len_check(struct wcrypto_cipher_ctx_setup *setup,
					__u16 length)
{
	int ret = WD_SUCCESS;

	if (setup->mode == WCRYPTO_CIPHER_XTS) {
		if (length != AES_KEYSIZE_128 && length != AES_KEYSIZE_256) {
			WD_ERR("unsupported XTS key length, length = %u.\n",
				length);
			return -WD_EINVAL;
		}
	}

	switch (setup->alg) {
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
		if ((length != SEC_3DES_2KEY_SIZE) && (length != SEC_3DES_3KEY_SIZE))
			ret = -WD_EINVAL;
		break;
	default:
		WD_ERR("cipher input alg err, alg is %d.\n", setup->alg);
		return -WD_EINVAL;
	}

	return ret;
}

int wcrypto_set_cipher_key(void *ctx, __u8 *key, __u16 key_len)
{
	struct wcrypto_cipher_ctx *ctxt = ctx;
	__u16 length = key_len;
	int ret;

	if (!ctx || !key) {
		WD_ERR("%s: input param err!\n", __func__);
		return -WD_EINVAL;
	}

	if (ctxt->setup.mode == WCRYPTO_CIPHER_XTS)
		length = key_len >> XTS_MODE_KEY_SHIFT;

	ret = cipher_key_len_check(&ctxt->setup, length);
	if (ret != WD_SUCCESS) {
		WD_ERR("%s: input key length err!\n", __func__);
		return ret;
	}

	if (ctxt->setup.alg == WCRYPTO_CIPHER_DES &&
		is_des_weak_key((__u64 *)key, length)) {
		WD_ERR("%s: des weak key!\n", __func__);
		return -WD_EINVAL;
	}

	ctxt->key_bytes = key_len;

	if (ctxt->setup.data_fmt == WD_SGL_BUF)
		wd_sgl_cp_from_pbuf(ctxt->key, 0, key, key_len);
	else
		memcpy(ctxt->key, key, key_len);

	return ret;
}

static int cipher_requests_init(struct wcrypto_cipher_msg **req,
				struct wcrypto_cipher_op_data **op,
				struct wcrypto_cipher_ctx *c, __u32 num)
{
	struct wd_sec_udata *udata;
	__u32 i;

	for (i = 0; i < num; i++) {
		req[i]->alg = c->setup.alg;
		req[i]->mode = c->setup.mode;
		req[i]->key = c->key;
		req[i]->key_bytes = c->key_bytes;
		req[i]->op_type = op[i]->op_type;
		req[i]->iv = op[i]->iv;
		req[i]->iv_bytes = op[i]->iv_bytes;
		req[i]->in = op[i]->in;
		req[i]->in_bytes = op[i]->in_bytes;
		req[i]->out = op[i]->out;
		req[i]->out_bytes = op[i]->out_bytes;
		udata = op[i]->priv;
		if (udata && udata->key) {
			req[i]->key = udata->key;
			req[i]->key_bytes = udata->key_bytes;
		}

		if (unlikely(op[i]->iv_bytes != c->iv_blk_size)) {
			WD_ERR("fail to check IV length %u!\n", i);
			return -WD_EINVAL;
		}
	}

	return WD_SUCCESS;
}

static int cipher_recv_sync(struct wcrypto_cipher_ctx *c_ctx,
		struct wcrypto_cipher_op_data **c_opdata, __u32 num)
{
	struct wcrypto_cipher_msg *resp[WCRYPTO_MAX_BURST_NUM];
	__u32 recv_count = 0;
	__u64 rx_cnt = 0;
	__u32 i;
	int ret;

	for (i = 0; i < num; i++)
		resp[i] = (void *)(uintptr_t)c_ctx->ctx_id;

	while (true) {
		ret = wd_burst_recv(c_ctx->q, (void **)(resp + recv_count),
				    num - recv_count);
		if (ret > 0) {
			recv_count += ret;
			if (recv_count == num)
				break;

			rx_cnt = 0;
		} else if (ret == 0) {
			if (++rx_cnt > MAX_CIPHER_RETRY_CNT) {
				WD_ERR("%s:wcrypto_recv timeout, num = %u, recv_count = %u!\n",
					__func__, num, recv_count);
				break;
			}
		} else {
			WD_ERR("do cipher wcrypto_recv error!\n");
			return ret;
		}
	}

	for (i = 0; i < recv_count; i++) {
		c_opdata[i]->out = (void *)resp[i]->out;
		c_opdata[i]->out_bytes = resp[i]->out_bytes;
		c_opdata[i]->status = resp[i]->result;
	}

	return recv_count;
}

static int param_check(struct wcrypto_cipher_ctx *c_ctx,
		       struct wcrypto_cipher_op_data **c_opdata,
		       void **tag, __u32 num)
{
	__u32 i;

	if (unlikely(!c_ctx || !c_opdata || !num || num > WCRYPTO_MAX_BURST_NUM)) {
		WD_ERR("input param err!\n");
		return -WD_EINVAL;
	}

	for (i = 0; i < num; i++) {
		if (unlikely(!c_opdata[i])) {
			WD_ERR("cipher opdata[%u] is NULL!\n", i);
			return -WD_EINVAL;
		}

		if (unlikely(tag && !tag[i])) {
			WD_ERR("tag[%u] is NULL!\n", i);
			return -WD_EINVAL;
		}
	}

	if (unlikely(tag && !c_ctx->setup.cb)) {
		WD_ERR("cipher ctx call back is NULL!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

int wcrypto_burst_cipher(void *ctx, struct wcrypto_cipher_op_data **c_opdata,
			 void **tag, __u32 num)
{
	struct wcrypto_cipher_cookie *cookies[WCRYPTO_MAX_BURST_NUM] = {NULL};
	struct wcrypto_cipher_msg *req[WCRYPTO_MAX_BURST_NUM];
	struct wcrypto_cipher_ctx *ctxt = ctx;
	__u32 i;
	int ret;

	if (param_check(ctxt, c_opdata, tag, num))
		return -WD_EINVAL;

	ret = wd_get_cookies(&ctxt->pool, (void **)cookies, num);
	if (unlikely(ret)) {
		WD_ERR("failed to get cookies %d!\n", ret);
		return ret;
	}

	for (i = 0; i < num; i++) {
		cookies[i]->tag.priv = c_opdata[i]->priv;
		req[i] = &cookies[i]->msg;
		if (tag)
			cookies[i]->tag.wcrypto_tag.tag = tag[i];
	}

	ret = cipher_requests_init(req, c_opdata, ctxt, num);
	if (unlikely(ret))
		goto fail_with_cookies;

	ret = wd_burst_send(ctxt->q, (void **)req, num);
	if (unlikely(ret)) {
		WD_ERR("failed to send req %d!\n", ret);
		goto fail_with_cookies;
	}

	if (tag)
		return ret;

	ret = cipher_recv_sync(ctxt, c_opdata, num);

fail_with_cookies:
	wd_put_cookies(&ctxt->pool, (void **)cookies, num);
	return ret;
}

int wcrypto_do_cipher(void *ctx, struct wcrypto_cipher_op_data *opdata,
		void *tag)
{
	int ret;

	if (!tag) {
		ret = wcrypto_burst_cipher(ctx, &opdata, NULL, 1);
		if (likely(ret == 1))
			return GET_NEGATIVE(opdata->status);
		if (unlikely(ret == 0))
			return -WD_ETIMEDOUT;
	} else {
		ret = wcrypto_burst_cipher(ctx, &opdata, &tag, 1);
	}

	return ret;
}

int wcrypto_cipher_poll(struct wd_queue *q, unsigned int num)
{
	struct wcrypto_cipher_msg *cipher_resp = NULL;
	struct wcrypto_cipher_ctx *ctx;
	struct wcrypto_cipher_tag *tag;
	int count = 0;
	int ret;

	if (unlikely(!q)) {
		WD_ERR("q is NULL!\n");
		return -WD_EINVAL;
	}

	do {
		cipher_resp = NULL;
		ret = wd_recv(q, (void **)&cipher_resp);
		if (ret == 0)
			break;
		else if (ret == -WD_HW_EACCESS) {
			if (!cipher_resp) {
				WD_ERR("the cipher recv err from req_cache!\n");
				return ret;
			}
			cipher_resp->result = WD_HW_EACCESS;
		} else if (ret < 0) {
			WD_ERR("recv err at cipher poll!\n");
			return ret;
		}
		count++;
		tag = (void *)(uintptr_t)cipher_resp->usr_data;
		ctx = tag->wcrypto_tag.ctx;
		ctx->setup.cb(cipher_resp, tag->wcrypto_tag.tag);
		wd_put_cookies(&ctx->pool, (void **)&tag, 1);
	} while (--num);

	return count;
}

void wcrypto_del_cipher_ctx(void *ctx)
{
	struct q_info *qinfo;
	struct wcrypto_cipher_ctx *c_ctx;

	if (!ctx) {
		WD_ERR("Delete cipher ctx is NULL!\n");
		return;
	}
	c_ctx = ctx;
	qinfo = c_ctx->q->qinfo;
	wd_uninit_cookie_pool(&c_ctx->pool);
	wd_spinlock(&qinfo->qlock);
	if (qinfo->ctx_num <= 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("error:repeat del cipher ctx!\n");
		return;
	}
	wd_free_id(qinfo->ctx_id, WD_MAX_CTX_NUM, c_ctx->ctx_id - 1,
		WD_MAX_CTX_NUM);
	if (!(--qinfo->ctx_num))
		memset(&qinfo->br, 0, sizeof(qinfo->br));

	wd_unspinlock(&qinfo->qlock);
	del_ctx_key(c_ctx);
	free(ctx);
}
