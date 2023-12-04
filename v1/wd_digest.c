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
#include "wd_digest.h"

#define MAX_HMAC_KEY_SIZE	128
#define MAX_DIGEST_RETRY_CNT	20000000
#define SEC_SHA1_ALIGN_SZ	64
#define SEC_SHA512_ALIGN_SZ	128
#define SEC_GMAC_IV_LEN	16

struct wcrypto_digest_cookie {
	struct wcrypto_digest_tag tag;
	struct wcrypto_digest_msg msg;
};

struct wcrypto_digest_ctx {
	struct wd_cookie_pool pool;
	unsigned long ctx_id;
	void *key;
	__u32 key_bytes;
	__u64 io_bytes;
	__u8 align_sz;
	struct wd_queue *q;
	struct wcrypto_digest_ctx_setup setup;
};

static __u32 g_digest_mac_len[WCRYPTO_MAX_DIGEST_TYPE] = {
	WCRYPTO_DIGEST_SM3_LEN, WCRYPTO_DIGEST_MD5_LEN, WCRYPTO_DIGEST_SHA1_LEN,
	WCRYPTO_DIGEST_SHA256_LEN, WCRYPTO_DIGEST_SHA224_LEN,
	WCRYPTO_DIGEST_SHA384_LEN, WCRYPTO_DIGEST_SHA512_LEN,
	WCRYPTO_DIGEST_SHA512_224_LEN, WCRYPTO_DIGEST_SHA512_256_LEN,
	WCRYPTO_AES_XCBC_MAC_96_LEN, WCRYPTO_AES_XCBC_PRF_128_LEN,
	WCRYPTO_AES_CMAC_LEN, WCRYPTO_AES_GMAC_LEN
};

static __u32 g_digest_mac_full_len[WCRYPTO_MAX_DIGEST_TYPE] = {
	WCRYPTO_DIGEST_SM3_FULL_LEN, WCRYPTO_DIGEST_MD5_FULL_LEN,
	WCRYPTO_DIGEST_SHA1_FULL_LEN, WCRYPTO_DIGEST_SHA256_FULL_LEN,
	WCRYPTO_DIGEST_SHA224_FULL_LEN, WCRYPTO_DIGEST_SHA384_FULL_LEN,
	WCRYPTO_DIGEST_SHA512_FULL_LEN, WCRYPTO_DIGEST_SHA512_224_FULL_LEN,
	WCRYPTO_DIGEST_SHA512_256_FULL_LEN
};

static void del_ctx_key(struct wcrypto_digest_ctx *ctx)
{
	struct wd_mm_br *br = &(ctx->setup.br);
	__u8 tmp[MAX_HMAC_KEY_SIZE] = { 0 };

	/**
	 * When data_fmt is 'WD_SGL_BUF',  'akey' and 'ckey' is a sgl, and if u
	 * want to clear the SGL buffer, we can only use 'wd_sgl_cp_from_pbuf'
	 * whose 'pbuf' is all zero.
	 */
	if (ctx->key && ctx->key_bytes) {
		if (ctx->setup.data_fmt == WD_FLAT_BUF)
			memset(ctx->key, 0, MAX_HMAC_KEY_SIZE);
		else if (ctx->setup.data_fmt == WD_SGL_BUF)
			wd_sgl_cp_from_pbuf(ctx->key, 0, tmp, MAX_HMAC_KEY_SIZE);
	}

	if (br && br->free && ctx->key)
		br->free(br->usr, ctx->key);
}

static int create_ctx_para_check(struct wd_queue *q,
	struct wcrypto_digest_ctx_setup *setup)
{
	if (!q || !q->qinfo || !setup) {
		WD_ERR("%s: input param err!\n", __func__);
		return -WD_EINVAL;
	}
	if (setup->mode == WCRYPTO_DIGEST_HMAC) {
		if (!setup->br.alloc || !setup->br.free ||
			!setup->br.iova_map || !setup->br.iova_unmap) {
			WD_ERR("create digest ctx user mm br err!\n");
			return -WD_EINVAL;
		}
	}

	if (strcmp(q->capa.alg, "digest")) {
		WD_ERR("%s: algorithm mismatching!\n", __func__);
		return -WD_EINVAL;
	}

	if (setup->alg >= WCRYPTO_MAX_DIGEST_TYPE) {
		WD_ERR("invalid: the alg %d does not support!\n", setup->alg);
		return -WD_EINVAL;
	}

	if (setup->mode == WCRYPTO_DIGEST_NORMAL &&
	    setup->alg >= WCRYPTO_AES_XCBC_MAC_96) {
		WD_ERR("invalid: the alg %d does not support normal mode!\n", setup->alg);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int init_digest_cookie(struct wcrypto_digest_ctx *ctx,
			      struct wcrypto_digest_ctx_setup *setup)
{
	struct wcrypto_digest_cookie *cookie;
	__u32 flags = ctx->q->capa.flags;
	__u32 cookies_num, i;
	int ret;

	cookies_num = wd_get_ctx_cookies_num(flags, WD_CTX_COOKIES_NUM);
	ret = wd_init_cookie_pool(&ctx->pool,
		sizeof(struct wcrypto_digest_cookie), cookies_num);
	if (ret) {
		WD_ERR("failed to init cookie pool!\n");
		return ret;
	}

	for (i = 0; i < cookies_num; i++) {
		cookie = (void *)((uintptr_t)ctx->pool.cookies +
			i * ctx->pool.cookies_size);
		cookie->msg.alg_type = WCRYPTO_DIGEST;
		cookie->msg.alg = setup->alg;
		cookie->msg.mode = setup->mode;
		cookie->msg.data_fmt = setup->data_fmt;
		cookie->tag.long_data_len = 0;
		cookie->tag.priv = NULL;
		cookie->tag.wcrypto_tag.ctx = ctx;
		cookie->tag.wcrypto_tag.ctx_id = ctx->ctx_id;
		cookie->msg.usr_data = (uintptr_t)&cookie->tag;
	}

	return 0;
}

static int setup_qinfo(struct wcrypto_digest_ctx_setup *setup,
		       struct q_info *qinfo, __u32 *ctx_id)
{
	int ret;

	/* lock at ctx creating/deleting */
	wd_spinlock(&qinfo->qlock);
	if (!qinfo->br.alloc && !qinfo->br.iova_map)
		memcpy(&qinfo->br, &setup->br, sizeof(qinfo->br));
	if (qinfo->br.usr != setup->br.usr) {
		WD_ERR("Err mm br in creating digest ctx!\n");
		goto unlock;
	}

	if (qinfo->ctx_num >= WD_MAX_CTX_NUM) {
		WD_ERR("err:create too many digest ctx!\n");
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
void *wcrypto_create_digest_ctx(struct wd_queue *q,
		struct wcrypto_digest_ctx_setup *setup)
{
	struct q_info *qinfo;
	struct wcrypto_digest_ctx *ctx;
	__u32 ctx_id = 0;
	int ret;

	if (create_ctx_para_check(q, setup))
		return NULL;

	qinfo = q->qinfo;
	ret = setup_qinfo(setup, qinfo, &ctx_id);
	if (ret)
		return NULL;

	ctx = malloc(sizeof(struct wcrypto_digest_ctx));
	if (!ctx) {
		WD_ERR("Alloc ctx memory fail!\n");
		goto free_ctx_id;
	}
	memset(ctx, 0, sizeof(struct wcrypto_digest_ctx));
	memcpy(&ctx->setup, setup, sizeof(ctx->setup));
	ctx->q = q;
	ctx->ctx_id = ctx_id + 1;
	if (setup->mode == WCRYPTO_DIGEST_HMAC) {
		ctx->key = setup->br.alloc(setup->br.usr, MAX_HMAC_KEY_SIZE);
		if (!ctx->key) {
			WD_ERR("alloc digest ctx key fail!\n");
			goto free_ctx;
		}
	}

	if (setup->alg >= WCRYPTO_SHA384)
		ctx->align_sz = SEC_SHA512_ALIGN_SZ;
	else
		ctx->align_sz = SEC_SHA1_ALIGN_SZ;

	ret = init_digest_cookie(ctx, setup);
	if (ret)
		goto free_ctx_key;

	return ctx;

free_ctx_key:
	if (setup->mode == WCRYPTO_DIGEST_HMAC)
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

static void digest_requests_init(struct wcrypto_digest_msg **req,
				struct wcrypto_digest_op_data **op,
				struct wcrypto_digest_ctx *c, __u32 num)
{
	__u32 i;

	for (i = 0; i < num; i++) {
		req[i]->has_next = op[i]->has_next;
		req[i]->key = c->key;
		req[i]->key_bytes = c->key_bytes;
		req[i]->in = op[i]->in;
		req[i]->in_bytes = op[i]->in_bytes;
		req[i]->out = op[i]->out;
		req[i]->out_bytes = op[i]->out_bytes;
		req[i]->iv = op[i]->iv;
		c->io_bytes += op[i]->in_bytes;
	}
}

static int digest_hmac_key_check(enum wcrypto_digest_alg alg, __u16 key_len)
{
	switch (alg) {
	case WCRYPTO_SM3 ... WCRYPTO_SHA224:
		if (key_len > (MAX_HMAC_KEY_SIZE >> 1)) {
			WD_ERR("failed to check alg %u key bytes, key_len = %u\n", alg, key_len);
			return -WD_EINVAL;
		}
		break;
	case WCRYPTO_SHA384 ... WCRYPTO_SHA512_256:
		break;
	case WCRYPTO_AES_XCBC_MAC_96:
	case WCRYPTO_AES_XCBC_PRF_128:
	case WCRYPTO_AES_CMAC:
		if (key_len != AES_KEYSIZE_128) {
			WD_ERR("failed to check alg %u key bytes, key_len = %u\n", alg, key_len);
			return -WD_EINVAL;
		}
		break;
	case WCRYPTO_AES_GMAC:
		if (key_len != AES_KEYSIZE_128 &&
		    key_len != AES_KEYSIZE_192 &&
		    key_len != AES_KEYSIZE_256) {
			WD_ERR("failed to check alg %u key bytes, key_len = %u\n", alg, key_len);
			return -WD_EINVAL;
		}
		break;
	default:
		WD_ERR("failed to check digest key bytes, invalid alg type = %d\n", alg);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

int wcrypto_set_digest_key(void *ctx, __u8 *key, __u16 key_len)
{
	struct wcrypto_digest_ctx *ctxt = ctx;
	int ret;

	if (!ctx || !key) {
		WD_ERR("%s(): input param err!\n", __func__);
		return -WD_EINVAL;
	}

	if (key_len == 0 || key_len > MAX_HMAC_KEY_SIZE) {
		WD_ERR("%s: input key length err, key_len = %u!\n", __func__, key_len);
		return -WD_EINVAL;
	}

	ret = digest_hmac_key_check(ctxt->setup.alg, key_len);
	if (ret)
		return ret;

	ctxt->key_bytes = key_len;

	if (ctxt->setup.data_fmt == WD_SGL_BUF)
		wd_sgl_cp_from_pbuf(ctxt->key, 0, key, key_len);
	else
		memcpy(ctxt->key, key, key_len);

	return WD_SUCCESS;
}

static int digest_recv_sync(struct wcrypto_digest_ctx *d_ctx,
			    struct wcrypto_digest_op_data **d_opdata, __u32 num)
{
	struct wcrypto_digest_msg *resp[WCRYPTO_MAX_BURST_NUM];
	__u32 recv_count = 0;
	__u64 rx_cnt = 0;
	__u32 i;
	int ret;

	for (i = 0; i < num; i++)
		resp[i] = (void *)(uintptr_t)d_ctx->ctx_id;

	while (true) {
		ret = wd_burst_recv(d_ctx->q, (void **)(resp + recv_count),
				    num - recv_count);
		if (ret > 0) {
			recv_count += ret;
			if (recv_count == num)
				break;

			rx_cnt = 0;
		} else if (ret == 0) {
			if (++rx_cnt > MAX_DIGEST_RETRY_CNT) {
				WD_ERR("%s:wcrypto_recv timeout, num = %u, recv_count = %u!\n",
					__func__, num, recv_count);
				break;
			}
		} else {
			WD_ERR("do digest wcrypto_recv error!\n");
			return ret;
		}
	}

	for (i = 0; i < recv_count; i++) {
		d_opdata[i]->out = (void *)resp[i]->out;
		d_opdata[i]->out_bytes = resp[i]->out_bytes;
		d_opdata[i]->status = resp[i]->result;
	}

	return recv_count;
}

static int stream_mode_param_check(struct wcrypto_digest_ctx *d_ctx,
				   struct wcrypto_digest_op_data *d_opdata, __u32 num)
{
	enum wcrypto_digest_alg alg = d_ctx->setup.alg;

	if (unlikely(num != 1)) {
		WD_ERR("invalid: wcrypto_burst_digest does not support stream mode, num = %u!\n",
			num);
		return -WD_EINVAL;
	}

	if (unlikely(d_opdata->in_bytes % d_ctx->align_sz)) {
		WD_ERR("invalid: digest stream mode must be %u-byte aligned!\n", d_ctx->align_sz);
		return -WD_EINVAL;
	}

	if (unlikely(d_opdata->out_bytes < g_digest_mac_full_len[alg])) {
		WD_ERR("invalid: digest stream mode out buffer space is not enough!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int block_mode_param_check(struct wcrypto_digest_ctx *d_ctx,
				  struct wcrypto_digest_op_data *d_opdata)
{
	enum wcrypto_digest_alg alg = d_ctx->setup.alg;

	if (unlikely(d_opdata->out_bytes > g_digest_mac_len[alg])) {
		WD_ERR("invalid: failed to check digest mac length!\n");
		return -WD_EINVAL;
	}

	if (unlikely(d_ctx->setup.alg == WCRYPTO_AES_GMAC &&
		(!d_opdata->iv || d_opdata->iv_bytes != SEC_GMAC_IV_LEN))) {
		WD_ERR("invalid: failed to check digest aes_gmac iv length, iv_bytes = %u\n",
			d_opdata->iv_bytes);
		return -WD_EINVAL;
	}

	return 0;
}

static int param_check(struct wcrypto_digest_ctx *d_ctx,
		       struct wcrypto_digest_op_data **d_opdata,
		       void **tag, __u32 num)
{
	__u32 i;
	int ret;

	if (unlikely(!d_ctx || !d_opdata || !num || num > WCRYPTO_MAX_BURST_NUM)) {
		WD_ERR("invalid: input param err!\n");
		return -WD_EINVAL;
	}

	for (i = 0; i < num; i++) {
		if (unlikely(!d_opdata[i])) {
			WD_ERR("invalid: digest opdata[%u] is NULL!\n", i);
			return -WD_EINVAL;
		}

		if (unlikely(!d_opdata[i]->out_bytes)) {
			WD_ERR("invalid: digest mac length is 0.\n");
			return -WD_EINVAL;
		}

		ret = wd_check_src_dst(d_opdata[i]->in, d_opdata[i]->in_bytes,
				       d_opdata[i]->out, d_opdata[i]->out_bytes);
		if (unlikely(ret)) {
			WD_ERR("invalid: src/dst addr is NULL when src/dst size is non-zero!\n");
			return -WD_EINVAL;
		}

		if (d_opdata[i]->has_next)
			ret = stream_mode_param_check(d_ctx, d_opdata[i], num);
		else
			ret = block_mode_param_check(d_ctx, d_opdata[i]);
		if (unlikely(ret))
			return ret;

		if (unlikely(tag && !tag[i])) {
			WD_ERR("invalid: tag[%u] is NULL!\n", i);
			return -WD_EINVAL;
		}
	}

	if (unlikely(tag && !d_ctx->setup.cb)) {
		WD_ERR("invalid: digest ctx call back is NULL!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

int wcrypto_burst_digest(void *d_ctx, struct wcrypto_digest_op_data **opdata,
			 void **tag, __u32 num)
{
	struct wcrypto_digest_cookie *cookies[WCRYPTO_MAX_BURST_NUM] = {NULL};
	struct wcrypto_digest_msg *req[WCRYPTO_MAX_BURST_NUM] = {NULL};
	struct wcrypto_digest_ctx *ctxt = d_ctx;
	__u32 i;
	int ret;

	if (param_check(ctxt, opdata, tag, num))
		return -WD_EINVAL;

	ret = wd_get_cookies(&ctxt->pool, (void **)cookies, num);
	if (unlikely(ret))
		return ret;

	for (i = 0; i < num; i++) {
		cookies[i]->tag.priv = opdata[i]->priv;
		req[i] = &cookies[i]->msg;
		if (tag)
			cookies[i]->tag.wcrypto_tag.tag = tag[i];
	}

	digest_requests_init(req, opdata, d_ctx, num);
	/* when num is 1, wcrypto_burst_digest supports stream mode */
	if (num == 1 && !opdata[0]->has_next) {
		cookies[0]->tag.long_data_len = ctxt->io_bytes;
		ctxt->io_bytes = 0;
	}

	ret = wd_burst_send(ctxt->q, (void **)req, num);
	if (unlikely(ret)) {
		WD_ERR("failed to send req %d!\n", ret);
		goto fail_with_cookies;
	}

	if (tag)
		return ret;

	ret = digest_recv_sync(ctxt, opdata, num);

fail_with_cookies:
	wd_put_cookies(&ctxt->pool, (void **)cookies, num);
	return ret;
}

int wcrypto_do_digest(void *ctx, struct wcrypto_digest_op_data *opdata,
		      void *tag)
{
	int ret;

	if (!tag) {
		ret = wcrypto_burst_digest(ctx, &opdata, NULL, 1);
		if (likely(ret == 1))
			return GET_NEGATIVE(opdata->status);
		if (unlikely(ret == 0))
			return -WD_ETIMEDOUT;
	} else {
		ret = wcrypto_burst_digest(ctx, &opdata, &tag, 1);
	}

	return ret;
}

int wcrypto_digest_poll(struct wd_queue *q, unsigned int num)
{
	struct wcrypto_digest_msg *digest_resp = NULL;
	struct wcrypto_digest_ctx *ctx;
	struct wcrypto_digest_tag *tag;
	unsigned int tmp = num;
	int count = 0;
	int ret;

	if (unlikely(!q)) {
		WD_ERR("q is NULL!\n");
		return -WD_EINVAL;
	}

	do {
		digest_resp = NULL;
		ret = wd_recv(q, (void **)&digest_resp);
		if (ret == 0)
			break;
		else if (ret == -WD_HW_EACCESS) {
			if (!digest_resp) {
				WD_ERR("the digest recv err from req_cache!\n");
				return ret;
			}
			digest_resp->result = WD_HW_EACCESS;
		} else if (ret < 0) {
			WD_ERR("recv err at digest poll!\n");
			return ret;
		}

		count++;
		tag = (void *)(uintptr_t)digest_resp->usr_data;
		ctx = tag->wcrypto_tag.ctx;
		ctx->setup.cb(digest_resp, tag->wcrypto_tag.tag);
		wd_put_cookies(&ctx->pool, (void **)&tag, 1);
	} while (--tmp);

	return count;
}

void wcrypto_del_digest_ctx(void *ctx)
{
	struct q_info *qinfo;
	struct wcrypto_digest_ctx *d_ctx;

	if (!ctx) {
		WD_ERR("Delete digest ctx is NULL!\n");
		return;
	}
	d_ctx = ctx;
	qinfo = d_ctx->q->qinfo;
	wd_uninit_cookie_pool(&d_ctx->pool);
	wd_spinlock(&qinfo->qlock);
	if (qinfo->ctx_num <= 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("error: repeat del digest ctx!\n");
		return;
	}
	wd_free_id(qinfo->ctx_id, WD_MAX_CTX_NUM, d_ctx->ctx_id - 1,
		WD_MAX_CTX_NUM);
	if (!(--qinfo->ctx_num))
		memset(&qinfo->br, 0, sizeof(qinfo->br));
	wd_unspinlock(&qinfo->qlock);
	del_ctx_key(d_ctx);
	free(ctx);
}
