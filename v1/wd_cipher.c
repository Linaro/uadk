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
#include "wd_cipher.h"
#include "wd_util.h"

#define WCRYPTO_CIPHER_CTX_MSG_NUM	1024
#define WCRYPTO_CIPHER_MAX_CTX		256
#define MAX_CIPHER_KEY_SIZE		64
#define MAX_CIPHER_RETRY_CNT	20000000

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
	struct wcrypto_cipher_cookie cookies[WCRYPTO_CIPHER_CTX_MSG_NUM];
	__u8 cstatus[WCRYPTO_CIPHER_CTX_MSG_NUM];
	int cidx;
	unsigned long ctx_id;
	void *key;
	__u32 key_bytes;
	__u32 iv_blk_size;
	struct wd_queue *q;
	struct wcrypto_cipher_ctx_setup setup;
};

static void put_cipher_cookies(struct wcrypto_cipher_ctx *ctx,
			       struct wcrypto_cipher_cookie **cookies,
			       __u32 num)
{
	int i, idx;

	for (i = 0; i < num; i++) {
		idx = ((uintptr_t)cookies[i] - (uintptr_t)ctx->cookies) /
			sizeof(struct wcrypto_cipher_cookie);
		if (idx < 0 || idx >= WCRYPTO_CIPHER_CTX_MSG_NUM) {
			WD_ERR("cipher cookie not exist!\n");
			continue;
		}

		__atomic_clear(&ctx->cstatus[idx], __ATOMIC_RELEASE);
	}
}

static int get_cipher_cookies(struct wcrypto_cipher_ctx *ctx,
			      struct wcrypto_cipher_cookie **cookies,
			      __u32 num)
{
	int idx = ctx->cidx;
	int cnt = 0;
	int i;

	for (i = 0; i < num; i++) {
		while (__atomic_test_and_set(&ctx->cstatus[idx],
					     __ATOMIC_ACQUIRE)) {
			idx++;
			cnt++;
			if (idx == WCRYPTO_CIPHER_CTX_MSG_NUM)
				idx = 0;
			if (cnt == WCRYPTO_CIPHER_CTX_MSG_NUM)
				goto fail_with_cookies;
		}

		cookies[i] = &ctx->cookies[idx];
	}

	ctx->cidx = idx;

	return 0;

fail_with_cookies:
	put_cipher_cookies(ctx, cookies, i);
	return -WD_EBUSY;
}

static void del_ctx_key(struct wcrypto_cipher_ctx *ctx)
{
	struct wd_mm_br *br = &(ctx->setup.br);

	if (ctx->key)
		memset(ctx->key, 0, MAX_CIPHER_KEY_SIZE);

	if (br && br->free && ctx->key)
		br->free(br->usr, ctx->key);
}

static __u32 get_iv_block_size(int alg, int mode)
{
	switch (mode) {
	case WCRYPTO_CIPHER_CBC:
	case WCRYPTO_CIPHER_OFB:
		if (alg == WCRYPTO_CIPHER_3DES ||
		    alg == WCRYPTO_CIPHER_DES)
			return CBC_3DES_BLOCK_SIZE;
	case WCRYPTO_CIPHER_XTS:
	case WCRYPTO_CIPHER_CFB:
		return CBC_AES_BLOCK_SIZE;
	default:
		return 0;
	}
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
	if (strncmp(q->capa.alg, "cipher", strlen("cipher")) &&
		strncmp(q->capa.alg, "xts(aes)", strlen("xts(aes)")) &&
		strncmp(q->capa.alg, "xts(sm4)", strlen("xts(sm4)"))) {
		WD_ERR("%s: algorithm mismatching!\n", __func__);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static void init_cipher_cookie(struct wcrypto_cipher_ctx *ctx,
	struct wcrypto_cipher_ctx_setup *setup)
{
	int i;

	for (i = 0; i < WCRYPTO_CIPHER_CTX_MSG_NUM; i++) {
		ctx->cookies[i].msg.alg_type = WCRYPTO_CIPHER;
		ctx->cookies[i].msg.alg = setup->alg;
		ctx->cookies[i].msg.data_fmt = setup->data_fmt;
		ctx->cookies[i].msg.mode = setup->mode;
		ctx->cookies[i].tag.wcrypto_tag.ctx = ctx;
		ctx->cookies[i].tag.wcrypto_tag.ctx_id = ctx->ctx_id;
		ctx->cookies[i].msg.usr_data = (uintptr_t)&ctx->cookies[i].tag;
	}
}

/* Before initiate this context, we should get a queue from WD */
void *wcrypto_create_cipher_ctx(struct wd_queue *q,
	struct wcrypto_cipher_ctx_setup *setup)
{
	struct q_info *qinfo;
	struct wcrypto_cipher_ctx *ctx;
	int ctx_id;

	if (create_ctx_para_check(q, setup))
		return NULL;

	qinfo = q->qinfo;
	/* lock at ctx creating/deleting */
	wd_spinlock(&qinfo->qlock);
	if (!qinfo->br.alloc && !qinfo->br.iova_map)
		memcpy(&qinfo->br, &setup->br, sizeof(setup->br));

	if (qinfo->br.usr != setup->br.usr) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("Err mm br in creating cipher ctx!\n");
		return NULL;
	}

	if (qinfo->ctx_num >= WCRYPTO_CIPHER_MAX_CTX) {
		WD_ERR("err:create too many cipher ctx!\n");
		wd_unspinlock(&qinfo->qlock);
		return NULL;
	}

	qinfo->ctx_num++;
	ctx_id = wd_alloc_ctx_id(q, WCRYPTO_CIPHER_MAX_CTX);
	if (ctx_id < 0) {
		WD_ERR("err: alloc ctx id fail!\n");
		wd_unspinlock(&qinfo->qlock);
		return NULL;
	}

	wd_unspinlock(&qinfo->qlock);

	ctx = malloc(sizeof(struct wcrypto_cipher_ctx));
	if (!ctx) {
		WD_ERR("Alloc ctx memory fail!\n");
		return ctx;
	}
	memset(ctx, 0, sizeof(struct wcrypto_cipher_ctx));
	memcpy(&ctx->setup, setup, sizeof(*setup));
	ctx->q = q;
	ctx->ctx_id = ctx_id;
	ctx->key = setup->br.alloc(setup->br.usr, MAX_CIPHER_KEY_SIZE);
	if (!ctx->key) {
		WD_ERR("alloc cipher ctx key fail!\n");
		free(ctx);
		return NULL;
	}

	ctx->iv_blk_size = get_iv_block_size(setup->alg, setup->mode);
	init_cipher_cookie(ctx, setup);

	return ctx;
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
		if ((length != SEC_3DES_2KEY_SIZE) && (length != SEC_3DES_3KEY_SIZE))
			ret = -WD_EINVAL;
		break;
	default:
		WD_ERR("%s: input alg err!\n", __func__);
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
		length = key_len / XTS_MODE_KEY_DIVISOR;

	ret = cipher_key_len_check(ctxt->setup.alg, length);
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
	memcpy(ctxt->key, key, key_len);

	return ret;
}

static int cipher_request_init(struct wcrypto_cipher_msg **req,
				struct wcrypto_cipher_op_data **op,
				struct wcrypto_cipher_ctx *c, __u32 num)
{
	struct wd_sec_udata *udata;
	int i;

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

		if (op[i]->iv_bytes != c->iv_blk_size) {
			WD_ERR("fail to check IV length!\n");
			return -WD_EINVAL;
		}
	}

	return WD_SUCCESS;
}

static int cipher_recv_sync(struct wcrypto_cipher_ctx *ctx,
		struct wcrypto_cipher_op_data **opdata, __u32 num)
{
	struct wcrypto_cipher_msg *resp[WCRYPTO_MAX_BURST_NUM];
	__u32 recv_count = 0;
	__u64 rx_cnt = 0;
	int i, ret;

	for (i = 0; i < num; i++)
		resp[i] = (void *)(uintptr_t)ctx->ctx_id;

	while (true) {
		ret = wd_burst_recv(ctx->q, (void **)resp, num - recv_count);
		if (ret >= 0) {
			recv_count += ret;
			if (recv_count == num)
				break;

			if (++rx_cnt > MAX_CIPHER_RETRY_CNT) {
				WD_ERR("wcrypto_recv timeout error!\n");
				break;
			}
			usleep(1);
		} else {
			WD_ERR("do cipher wcrypto_recv error!\n");
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

static int param_check(struct wcrypto_cipher_ctx *ctx,
		       struct wcrypto_cipher_op_data **opdata,
		       void **tag, __u32 num)
{
	int i;

	if (unlikely(!ctx || !opdata || !num || num > WCRYPTO_MAX_BURST_NUM)) {
		WD_ERR("input param err!\n");
		return -WD_EINVAL;
	}

	for (i = 0; i < num; i++) {
		if (unlikely(!opdata[i])) {
			WD_ERR("opdata[%d] is NULL!\n", i);
			return -WD_EINVAL;
		}

		if (unlikely(tag && !tag[i])) {
			WD_ERR("tag[%d] is NULL!\n", i);
			return -WD_EINVAL;
		}
	}

	if (unlikely(tag && !ctx->setup.cb)) {
		WD_ERR("ctx call back is null!\n");
		return -WD_EINVAL;
	}

	return 0;
}

int wcrypto_burst_cipher(void *ctx, struct wcrypto_cipher_op_data **opdata,
			 void **tag, __u32 num)
{
	struct wcrypto_cipher_cookie *cookies[WCRYPTO_MAX_BURST_NUM] = {NULL};
	struct wcrypto_cipher_msg *req[WCRYPTO_MAX_BURST_NUM];
	struct wcrypto_cipher_ctx *ctxt = ctx;
	int i, ret;

	if (param_check(ctxt, opdata, tag, num))
		return -WD_EINVAL;

	ret = get_cipher_cookies(ctx, cookies, num);
	if (ret) {
		WD_ERR("failed to get cookies %d!\n", ret);
		return ret;
	}

	for (i = 0; i < num; i++) {
		cookies[i]->tag.priv = opdata[i]->priv;
		req[i] = &cookies[i]->msg;
		if (tag)
			cookies[i]->tag.wcrypto_tag.tag = tag[i];
	}

	ret = cipher_request_init(req, opdata, ctx, num);
	if (ret)
		goto fail_with_cookies;

	ret = wd_burst_send(ctxt->q, (void **)req, num);
	if (ret) {
		WD_ERR("failed to send req %d!\n", ret);
		goto fail_with_cookies;
	}

	if (tag)
		return ret;

	ret = cipher_recv_sync(ctxt, opdata, num);

fail_with_cookies:
	put_cipher_cookies(ctxt, cookies, num);
	return ret;
}

int wcrypto_do_cipher(void *ctx, struct wcrypto_cipher_op_data *opdata,
		void *tag)
{
	if (!tag)
		return wcrypto_burst_cipher(ctx, &opdata, NULL, 1);
	else
		return wcrypto_burst_cipher(ctx, &opdata, &tag, 1);
}

int wcrypto_cipher_poll(struct wd_queue *q, unsigned int num)
{
	struct wcrypto_cipher_ctx *ctx;
	struct wcrypto_cipher_msg *resp = NULL;
	struct wcrypto_cipher_tag *tag;
	int ret;
	int count = 0;

	if (unlikely(!q)) {
		WD_ERR("q is NULL!\n");
		return -WD_EINVAL;
	}

	do {
		resp = NULL;
		ret = wd_recv(q, (void **)&resp);
		if (ret == 0)
			break;
		else if (ret == -WD_HW_EACCESS) {
			if (!resp) {
				WD_ERR("recv err from req_cache!\n");
				return ret;
			}
			resp->result = WD_HW_EACCESS;
		} else if (ret < 0) {
			WD_ERR("recv err at cipher poll!\n");
			return ret;
		}
		count++;
		tag = (void *)(uintptr_t)resp->usr_data;
		ctx = tag->wcrypto_tag.ctx;
		ctx->setup.cb(resp, tag->wcrypto_tag.tag);
		put_cipher_cookies(ctx, (struct wcrypto_cipher_cookie **)&tag, 1);
	} while (--num);

	return count;
}

void wcrypto_del_cipher_ctx(void *ctx)
{
	struct q_info *qinfo;
	struct wcrypto_cipher_ctx *cx;

	if (!ctx) {
		WD_ERR("Delete cipher ctx is NULL!\n");
		return;
	}
	cx = ctx;
	qinfo = cx->q->qinfo;
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	wd_free_ctx_id(cx->q, cx->ctx_id);
	if (!qinfo->ctx_num)
		memset(&qinfo->br, 0, sizeof(qinfo->br));
	if (qinfo->ctx_num < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("errer:repeat del cipher ctx!\n");
		return;
	}
	wd_unspinlock(&qinfo->qlock);
	del_ctx_key(cx);
	free(ctx);
}
