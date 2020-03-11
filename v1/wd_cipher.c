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

#define DES_WEAK_KEY_NUM 4
__u64 des_weak_key[DES_WEAK_KEY_NUM] = {0x0101010101010101, 0xFEFEFEFEFEFEFEFE,
	0xE0E0E0E0F1F1F1F1, 0x1F1F1F1F0E0E0E0E};

struct wcrypto_cipher_cookie {
	struct wcrypto_cipher_tag tag;
	struct wcrypto_cipher_msg msg;
};

struct wcrypto_cipher_ctx {
	struct wcrypto_cipher_cookie cookies[WCRYPTO_CIPHER_CTX_MSG_NUM];
	__u8 cstatus[WCRYPTO_CIPHER_CTX_MSG_NUM];
	int cidx;
	int ctx_id;
	void *key;
	__u32 key_bytes;
	struct wd_queue *q;
	struct wcrypto_cipher_ctx_setup setup;
};

static struct wcrypto_cipher_cookie *get_cipher_cookie(struct wcrypto_cipher_ctx *ctx)
{
	int idx = ctx->cidx;
	int cnt = 0;

	while (__atomic_test_and_set(&ctx->cstatus[idx], __ATOMIC_ACQUIRE)) {
		idx++;
		cnt++;
		if (idx == WCRYPTO_CIPHER_CTX_MSG_NUM)
			idx = 0;
		if (cnt == WCRYPTO_CIPHER_CTX_MSG_NUM)
			return NULL;
	}

	ctx->cidx = idx;
	return &ctx->cookies[idx];
}

static void put_cipher_cookie(struct wcrypto_cipher_ctx *ctx,
	struct wcrypto_cipher_cookie *cookie)
{
	int idx = ((uintptr_t)cookie - (uintptr_t)ctx->cookies) /
		sizeof(struct wcrypto_cipher_cookie);

	if (idx < 0 || idx >= WCRYPTO_CIPHER_CTX_MSG_NUM) {
		WD_ERR("cipher cookie not exist!\n");
		return;
	}
	__atomic_clear(&ctx->cstatus[idx], __ATOMIC_RELEASE);
}

static void del_ctx_key(struct wcrypto_cipher_ctx *ctx)
{
	struct wd_mm_br *br = &(ctx->setup.br);

	if (ctx->key)
		memset(ctx->key, 0, MAX_CIPHER_KEY_SIZE);

	if (br && br->free && ctx->key)
		br->free(br->usr, ctx->key);
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

static int cipher_request_init(struct wcrypto_cipher_msg *req,
	struct wcrypto_cipher_op_data *op, struct wcrypto_cipher_ctx *c)
{
	struct wd_sec_udata *udata = op->priv;

	req->alg = c->setup.alg;
	req->mode = c->setup.mode;
	req->key = c->key;
	req->key_bytes = c->key_bytes;
	req->op_type = op->op_type;
	req->iv = op->iv;
	req->iv_bytes = op->iv_bytes;
	req->in = op->in;
	req->in_bytes = op->in_bytes;
	req->out = op->out;
	req->out_bytes = op->out_bytes;
	if (udata && udata->key) {
		req->key = udata->key;
		req->key_bytes = udata->key_bytes;
	}

	return WD_SUCCESS;
}

static int cipher_recv_sync(struct wcrypto_cipher_ctx *ctx,
		struct wcrypto_cipher_op_data *opdata)
{
	struct wcrypto_cipher_msg *resp;
	__u64 recv_count = 0;
	int ret;

	resp = (void *)(uintptr_t)ctx->ctx_id;
	while (true) {
		ret = wd_recv(ctx->q, (void **)&resp);
		if (ret == 0) {
			if (++recv_count > MAX_CIPHER_RETRY_CNT) {
				WD_ERR("%s:wcrypto_recv timeout fail!\n", __func__);
				ret = -WD_ETIMEDOUT;
				break;
			}
		} else if (ret < 0) {
			WD_ERR("do cipher wcrypto_recv err!\n");
			break;
		} else {
			opdata->out = (void *)resp->out;
			opdata->out_bytes = resp->out_bytes;
			opdata->status = resp->result;
			ret = GET_NEGATIVE(opdata->status);
			break;
		}
	}

	return ret;
}

int wcrypto_do_cipher(void *ctx, struct wcrypto_cipher_op_data *opdata,
		void *tag)
{
	struct wcrypto_cipher_msg *req;
	struct wcrypto_cipher_ctx *ctxt = ctx;
	struct wcrypto_cipher_cookie *cookie;
	int ret = -WD_EINVAL;

	if (!ctx || !opdata) {
		WD_ERR("%s: input param err!\n", __func__);
		return -WD_EINVAL;
	}

	cookie = get_cipher_cookie(ctxt);
	if (!cookie)
		return -WD_EBUSY;
	if (tag) {
		if (!ctxt->setup.cb) {
			WD_ERR("ctx call back is null!\n");
			goto fail_with_cookie;
		}
		cookie->tag.wcrypto_tag.tag = tag;
	}
	cookie->tag.priv = opdata->priv;

	req = &cookie->msg;
	ret = cipher_request_init(req, opdata, ctxt);
	if (ret)
		goto fail_with_cookie;

	ret = wd_send(ctxt->q, req);
	if (ret) {
		WD_ERR("do cipher wcrypto_send err!\n");
		goto fail_with_cookie;
	}

	if (tag)
		return ret;

	ret = cipher_recv_sync(ctxt, opdata);

fail_with_cookie:
	put_cipher_cookie(ctxt, cookie);
	return ret;
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
		put_cipher_cookie(ctx, (struct wcrypto_cipher_cookie *)tag);
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
