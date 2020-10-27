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
#include "wd_rng.h"
#include "wd_util.h"

#define MAX_NUM		10
#define WD_RNG_MAX_CTX	256
#define RNG_RESEND_CNT	8
#define RNG_RECV_CNT	8

struct wcrypto_rng_cookie {
	struct wcrypto_cb_tag tag;
	struct wcrypto_rng_msg msg;
};

struct wcrypto_rng_ctx {
	struct wcrypto_rng_cookie cookies[WD_RNG_CTX_MSG_NUM];
	__u8 cstatus[WD_RNG_CTX_MSG_NUM];
	unsigned long ctx_id;
	int cidx;
	struct wd_queue *q;
	struct wcrypto_rng_ctx_setup setup;
};

static struct wcrypto_rng_cookie *get_rng_cookie(struct wcrypto_rng_ctx *ctx)
{
	int idx = ctx->cidx;
	int cnt = 0;

	while (__atomic_test_and_set(&ctx->cstatus[idx], __ATOMIC_ACQUIRE)) {
		idx++;
		cnt++;
		if (idx == WD_RNG_CTX_MSG_NUM)
			idx = 0;
		if (cnt == WD_RNG_CTX_MSG_NUM)
			return NULL;
	}

	ctx->cidx = idx;
	return &ctx->cookies[idx];
}

static void put_rng_cookie(struct wcrypto_rng_ctx *ctx,
				struct wcrypto_rng_cookie *cookie)
{
	int idx = ((uintptr_t)cookie - (uintptr_t)ctx->cookies) /
		sizeof(struct wcrypto_rng_cookie);

	if (idx < 0 || idx >= WD_RNG_CTX_MSG_NUM) {
		WD_ERR("trng cookie not exist!\n");
		return;
	}
	__atomic_clear(&ctx->cstatus[idx], __ATOMIC_RELEASE);
}

void *wcrypto_create_rng_ctx(struct wd_queue *q,
			struct wcrypto_rng_ctx_setup *setup)
{
	struct wcrypto_rng_ctx *ctx;
	struct q_info *qinfo;
	int i, ctx_id;

	if (!q || !setup) {
		WD_ERR("input param err!\n");
		return NULL;
	}

	qinfo = q->qinfo;
	if (strncmp(q->capa.alg, "trng", strlen("trng"))) {
		WD_ERR("algorithm mismatch!\n");
		return NULL;
	}

	/* lock at ctx creating */
	wd_spinlock(&qinfo->qlock);
	if (qinfo->ctx_num >= WD_RNG_MAX_CTX) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("create too many trng ctx!\n");
		return NULL;
	}

	ctx_id = wd_alloc_ctx_id(q, WD_RNG_MAX_CTX);
	if (ctx_id < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("err: alloc ctx id fail!\n");
		return NULL;
	}
	qinfo->ctx_num++;
	wd_unspinlock(&qinfo->qlock);

	ctx = calloc(1, sizeof(struct wcrypto_rng_ctx));
	if (!ctx) {
		WD_ERR("alloc ctx memory fail!\n");
		goto free_ctx_id;
	}
	memcpy(&ctx->setup, setup, sizeof(*setup));
	ctx->q = q;
	ctx->ctx_id = ctx_id;
	for (i = 0; i < WD_RNG_CTX_MSG_NUM; i++) {
		ctx->cookies[i].msg.alg_type = WCRYPTO_RNG;
		ctx->cookies[i].tag.ctx = ctx;
		ctx->cookies[i].tag.ctx_id = ctx_id;
		ctx->cookies[i].msg.usr_tag = (uintptr_t)&ctx->cookies[i].tag;
	}

	return ctx;

free_ctx_id:
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	wd_free_ctx_id(q, ctx_id);
	wd_unspinlock(&qinfo->qlock);
	return NULL;
}

void wcrypto_del_rng_ctx(void *ctx)
{
	struct wcrypto_rng_ctx *cx;
	struct q_info *qinfo;

	if (!ctx) {
		WD_ERR("delete trng ctx is NULL!\n");
		return;
	}

	cx = ctx;
	qinfo = cx->q->qinfo;

	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	wd_free_ctx_id(cx->q, cx->ctx_id);
	if (qinfo->ctx_num < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("repeat del trng ctx!\n");
		return;
	}
	wd_unspinlock(&qinfo->qlock);

	free(ctx);
}

int wcrypto_rng_poll(struct wd_queue *q, unsigned int num)
{
	struct wcrypto_rng_msg *resp = NULL;
	struct wcrypto_rng_ctx *ctx;
	struct wcrypto_cb_tag *tag;
	int count = 0;
	int ret;

	if (!q) {
		WD_ERR("%s(): input param err!\n", __func__);
		return -WD_EINVAL;
	}

	do {
		ret = wd_recv(q, (void **)&resp);
		if (!ret)
			break;

		if (ret == -WD_EINVAL) {
			WD_ERR("recv err at trng poll!\n");
			return ret;
		}

		count++;
		tag = (void *)(uintptr_t)resp->usr_tag;
		ctx = tag->ctx;
		ctx->setup.cb(resp, tag->tag);
		put_rng_cookie(ctx, (struct wcrypto_rng_cookie *)tag);
		resp = NULL;
	} while (--num);

	return count;
}

int wcrypto_do_rng(void *ctx, struct wcrypto_rng_op_data *opdata, void *tag)
{
	struct wcrypto_rng_ctx *ctxt = ctx;
	struct wcrypto_rng_cookie *cookie;
	struct wcrypto_rng_msg *resp;
	struct wcrypto_rng_msg *req;
	uint32_t tx_cnt = 0;
	uint32_t rx_cnt = 0;
	int ret = 0;

	if (!ctx || !opdata) {
		WD_ERR("input param err!\n");
		return -WD_EINVAL;
	}

	cookie = get_rng_cookie(ctxt);
	if (!cookie)
		return -WD_EBUSY;

	if (tag) {
		if (!ctxt->setup.cb) {
			WD_ERR("ctx call back is null!\n");
			goto fail_with_cookie;
		}
		cookie->tag.tag = tag;
	}

	req = &cookie->msg;
	req->in_bytes = opdata->in_bytes;
	req->out = opdata->out;
send_again:
	ret = wd_send(ctxt->q, req);
	if (ret) {
		if (++tx_cnt > RNG_RESEND_CNT) {
			WD_ERR("do trng send cnt %u, exit!\n", tx_cnt);
			goto fail_with_cookie;
		}
		usleep(1);
		goto send_again;
	}

	if (tag)
		return ret;

	resp = (void *)(uintptr_t)ctxt->ctx_id;
recv_again:
	ret = wd_recv(ctxt->q, (void **)&resp);
	if (!ret) {
		if (++rx_cnt > RNG_RECV_CNT) {
			WD_ERR("do trng recv cnt %u, exit!\n", rx_cnt);
			goto fail_with_cookie;
		}
		usleep(1);
		goto recv_again;
	}

	if (ret < 0) {
		WD_ERR("do trng recv err!\n");
		goto fail_with_cookie;
	}

	opdata->out_bytes = resp->out_bytes;
fail_with_cookie:
	put_rng_cookie(ctxt, cookie);
	return   ret;
}
