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
#include "wd_digest.h"
#include "wd_util.h"

#define WD_DIGEST_CTX_MSG_NUM	1024
#define WD_DIGEST_MAX_CTX		256
#define MAX_HMAC_KEY_SIZE		128
#define MAX_DIGEST_RETRY_CNT	20000000

struct wcrypto_digest_cookie {
	struct wcrypto_digest_tag tag;
	struct wcrypto_digest_msg msg;
};

struct wcrypto_digest_ctx {
	struct wcrypto_digest_cookie cookies[WD_DIGEST_CTX_MSG_NUM];
	__u8 cstatus[WD_DIGEST_CTX_MSG_NUM];
	int cidx;
	int ctx_id;
	void *key;
	__u32 key_bytes;
	__u64 io_bytes;
	struct wd_queue *q;
	struct wcrypto_digest_ctx_setup setup;
};

static struct wcrypto_digest_cookie *get_digest_cookie(struct wcrypto_digest_ctx *ctx)
{
	int idx = ctx->cidx;
	int cnt = 0;

	while (__atomic_test_and_set(&ctx->cstatus[idx], __ATOMIC_ACQUIRE)) {
		idx++;
		cnt++;
		if (idx == WD_DIGEST_CTX_MSG_NUM)
			idx = 0;
		if (cnt == WD_DIGEST_CTX_MSG_NUM)
			return NULL;
	}

	ctx->cidx = idx;
	return &ctx->cookies[idx];
}

static void put_digest_cookie(struct wcrypto_digest_ctx *ctx,
		struct wcrypto_digest_cookie *cookie)
{
	int idx = ((uintptr_t)cookie - (uintptr_t)ctx->cookies) /
		sizeof(struct wcrypto_digest_cookie);

	if (idx < 0 || idx >= WD_DIGEST_CTX_MSG_NUM) {
		WD_ERR("digest cookie not exist!\n");
		return;
	}
	__atomic_clear(&ctx->cstatus[idx], __ATOMIC_RELEASE);
}

static void del_ctx_key(struct wcrypto_digest_ctx *ctx)
{
	struct wd_mm_br *br = &(ctx->setup.br);

	if (ctx->key)
		memset(ctx->key, 0, MAX_HMAC_KEY_SIZE);

	if (br && br->free && ctx->key)
		br->free(br->usr, ctx->key);
}

static int create_ctx_para_check(struct wd_queue *q,
	struct wcrypto_digest_ctx_setup *setup)
{
	if (!q || !setup) {
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

	if (strncmp(q->capa.alg, "digest", strlen("digest"))) {
		WD_ERR("%s: algorithm mismatching!\n", __func__);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static void init_digest_cookie(struct wcrypto_digest_ctx *ctx,
	struct wcrypto_digest_ctx_setup *setup)
{
	int i;

	for (i = 0; i < WD_DIGEST_CTX_MSG_NUM; i++) {
		ctx->cookies[i].msg.alg_type = WCRYPTO_DIGEST;
		ctx->cookies[i].msg.alg = setup->alg;
		ctx->cookies[i].msg.mode = setup->mode;
		ctx->cookies[i].msg.data_fmt = setup->data_fmt;
		ctx->cookies[i].tag.wcrypto_tag.ctx = ctx;
		ctx->cookies[i].tag.wcrypto_tag.ctx_id = ctx->ctx_id;
		ctx->cookies[i].msg.usr_data = (uintptr_t)&ctx->cookies[i].tag;
	}
}

/* Before initiate this context, we should get a queue from WD */
void *wcrypto_create_digest_ctx(struct wd_queue *q,
		struct wcrypto_digest_ctx_setup *setup)
{
	struct q_info *qinfo;
	struct wcrypto_digest_ctx *ctx;
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
		WD_ERR("Err mm br in creating digest ctx!\n");
		return NULL;
	}

	if (qinfo->ctx_num >= WD_DIGEST_MAX_CTX) {
		WD_ERR("err:create too many digest ctx!\n");
		wd_unspinlock(&qinfo->qlock);
		return NULL;
	}

	qinfo->ctx_num++;
	ctx_id = wd_alloc_ctx_id(q, WD_DIGEST_MAX_CTX);
	if (ctx_id < 0) {
		WD_ERR("err: alloc ctx id fail!\n");
		wd_unspinlock(&qinfo->qlock);
		return NULL;
	}

	wd_unspinlock(&qinfo->qlock);

	ctx = malloc(sizeof(struct wcrypto_digest_ctx));
	if (!ctx) {
		WD_ERR("Alloc ctx memory fail!\n");
		return ctx;
	}
	memset(ctx, 0, sizeof(struct wcrypto_digest_ctx));
	memcpy(&ctx->setup, setup, sizeof(*setup));
	ctx->q = q;
	ctx->ctx_id = ctx_id;
	if (setup->mode == WCRYPTO_DIGEST_HMAC) {
		ctx->key = setup->br.alloc(setup->br.usr, MAX_HMAC_KEY_SIZE);
		if (!ctx->key) {
			WD_ERR("alloc digest ctx key fail!\n");
			free(ctx);
			return NULL;
		}
	}

	init_digest_cookie(ctx, setup);

	return ctx;
}

static int digest_request_init(struct wcrypto_digest_msg *req,
		struct wcrypto_digest_op_data *op, struct wcrypto_digest_ctx *c)
{
	req->has_next = op->has_next;
	req->key = c->key;
	req->key_bytes = c->key_bytes;
	req->in = op->in;
	req->in_bytes = op->in_bytes;
	req->out = op->out;
	req->out_bytes = op->out_bytes;
	c->io_bytes += op->in_bytes;

	return WD_SUCCESS;
}

int wcrypto_set_digest_key(void *ctx, __u8 *key, __u16 key_len)
{
	struct wcrypto_digest_ctx *ctxt = ctx;

	if (!ctx || !key) {
		WD_ERR("%s(): input param err!\n", __func__);
		return -WD_EINVAL;
	}

	ctxt->key_bytes = key_len;
	memcpy(ctxt->key, key, key_len);

	return WD_SUCCESS;
}

static int digest_recv_sync(struct wcrypto_digest_ctx *ctx,
		struct wcrypto_digest_op_data *opdata)
{
	struct wcrypto_digest_msg *resp;
	__u64 recv_count = 0;
	int ret;

	resp = (void *)(uintptr_t)ctx->ctx_id;
	while (true) {
		ret = wd_recv(ctx->q, (void **)&resp);
		if (ret == 0) {
			if (++recv_count > MAX_DIGEST_RETRY_CNT) {
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

int wcrypto_do_digest(void *ctx, struct wcrypto_digest_op_data *opdata,
		void *tag)
{
	struct wcrypto_digest_msg *req;
	struct wcrypto_digest_ctx *ctxt = ctx;
	struct wcrypto_digest_cookie *cookie;
	int ret = -WD_EINVAL;

	if (!ctx || !opdata) {
		WD_ERR("%s: input param err!\n", __func__);
		return -WD_EINVAL;
	}

	cookie = get_digest_cookie(ctxt);
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
	ret = digest_request_init(req, opdata, ctxt);
	if (ret)
		goto fail_with_cookie;

	if (!opdata->has_next) {
		cookie->tag.long_data_len = ctxt->io_bytes;
		ctxt->io_bytes = 0;
	}
	ret = wd_send(ctxt->q, req);
	if (ret) {
		WD_ERR("do digest wcrypto_send err!\n");
		goto fail_with_cookie;
	}

	if (tag)
		return ret;

	ret = digest_recv_sync(ctxt, opdata);

fail_with_cookie:
	put_digest_cookie(ctxt, cookie);
	return ret;
}

int wcrypto_digest_poll(struct wd_queue *q, unsigned int num)
{
	struct wcrypto_digest_ctx *ctx;
	struct wcrypto_digest_msg *resp = NULL;
	struct wcrypto_digest_tag *tag;
	int ret;
	int count = 0;

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
			WD_ERR("recv err at digest poll!\n");
			return ret;
		}
		count++;
		tag = (void *)(uintptr_t)resp->usr_data;
		ctx = tag->wcrypto_tag.ctx;
		ctx->setup.cb(resp, tag->wcrypto_tag.tag);
		put_digest_cookie(ctx, (struct wcrypto_digest_cookie *)tag);
	} while (--num);

	return count;
}

void wcrypto_del_digest_ctx(void *ctx)
{
	struct q_info *qinfo;
	struct wcrypto_digest_ctx *cx;

	if (!ctx) {
		WD_ERR("Delete digest ctx is NULL!\n");
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
		WD_ERR("errer:repeat del digest ctx!\n");
		return;
	}
	wd_unspinlock(&qinfo->qlock);
	del_ctx_key(cx);
	free(ctx);
}
