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
#define RNG_RESEND_CNT	8
#define RNG_RECV_CNT	8

struct wcrypto_rng_cookie {
	struct wcrypto_cb_tag tag;
	struct wcrypto_rng_msg msg;
};

struct wcrypto_rng_ctx {
	struct wd_cookie_pool pool;
	unsigned long ctx_id;
	struct wd_queue *q;
	struct wcrypto_rng_ctx_setup setup;
};

static int wcrypto_setup_qinfo(struct wcrypto_rng_ctx_setup *setup,
			       struct wd_queue *q, __u32 *ctx_id)
{
	struct q_info *qinfo;
	int ret = -WD_EINVAL;

	if (!q || !setup) {
		WD_ERR("input parameter err!\n");
		return ret;
	}

	if (strcmp(q->capa.alg, "trng")) {
		WD_ERR("algorithm mismatch!\n");
		return ret;
	}
        qinfo = q->qinfo;
	/* lock at ctx creating */
	wd_spinlock(&qinfo->qlock);
	if (qinfo->ctx_num >= WD_MAX_CTX_NUM) {
		WD_ERR("create too many trng ctx!\n");
		goto unlock;
	}

	ret = wd_alloc_id(qinfo->ctx_id, WD_MAX_CTX_NUM, ctx_id, 0,
		WD_MAX_CTX_NUM);
	if (ret) {
		WD_ERR("err: alloc ctx id fail!\n");
		goto unlock;
	}
	qinfo->ctx_num++;
	ret = WD_SUCCESS;
unlock:
	wd_unspinlock(&qinfo->qlock);
	return ret;
}

void *wcrypto_create_rng_ctx(struct wd_queue *q,
			struct wcrypto_rng_ctx_setup *setup)
{
	struct wcrypto_rng_cookie *cookie;
	struct wcrypto_rng_ctx *ctx;
	struct q_info *qinfo;
	__u32 ctx_id = 0;
	int i, ret;

	if (wcrypto_setup_qinfo(setup, q, &ctx_id))
		return NULL;

	ctx = calloc(1, sizeof(struct wcrypto_rng_ctx));
	if (!ctx) {
		WD_ERR("alloc ctx memory fail!\n");
		goto free_ctx_id;
	}
	memcpy(&ctx->setup, setup, sizeof(*setup));
	ctx->q = q;
	ctx->ctx_id = ctx_id + 1;

	ret = wd_init_cookie_pool(&ctx->pool,
		sizeof(struct wcrypto_rng_cookie), WD_RNG_CTX_MSG_NUM);
	if (ret) {
		WD_ERR("fail to init cookie pool!\n");
		free(ctx);
		goto free_ctx_id;
	}
	for (i = 0; i < ctx->pool.cookies_num; i++) {
		cookie = (void *)((uintptr_t)ctx->pool.cookies +
			i * ctx->pool.cookies_size);
		cookie->msg.alg_type = WCRYPTO_RNG;
		cookie->tag.ctx = ctx;
		cookie->tag.ctx_id = ctx->ctx_id;
		cookie->msg.usr_tag = (uintptr_t)&cookie->tag;
	}

	return ctx;

free_ctx_id:
        qinfo = q->qinfo;
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	wd_free_id(qinfo->ctx_id, WD_MAX_CTX_NUM, ctx_id, WD_MAX_CTX_NUM);
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

	wd_uninit_cookie_pool(&cx->pool);
	wd_spinlock(&qinfo->qlock);
	wd_free_id(qinfo->ctx_id, WD_MAX_CTX_NUM, cx->ctx_id - 1,
		WD_MAX_CTX_NUM);
	qinfo->ctx_num--;
	if (qinfo->ctx_num < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("repeat delete trng ctx!\n");
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
		WD_ERR("%s(): input parameter err!\n", __func__);
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
		wd_put_cookies(&ctx->pool, (void **)&tag, 1);
		resp = NULL;
	} while (--num);

	return count;
}

static int wcrypto_do_prepare(struct wcrypto_rng_cookie **cookie_addr,
			      struct wcrypto_rng_op_data *opdata,
			      struct wcrypto_rng_msg **req_addr,
			      struct wcrypto_rng_ctx *ctxt,
			      void *tag)
{
	struct wcrypto_rng_cookie *cookie;
	struct wcrypto_rng_msg *req;
	int ret;

	if (!ctxt || !opdata) {
		WD_ERR("input parameter err!\n");
		return -WD_EINVAL;
	}

	ret = wd_get_cookies(&ctxt->pool, (void **)&cookie, 1);
	if (ret)
		return ret;

	if (tag) {
		if (!ctxt->setup.cb) {
			WD_ERR("ctx call back is null!\n");
			wd_put_cookies(&ctxt->pool, (void **)&cookie, 1);
			return -WD_EINVAL;
		}
		cookie->tag.tag = tag;
	}

	req = &cookie->msg;
	req->in_bytes = opdata->in_bytes;
	req->out = opdata->out;
	*cookie_addr = cookie;
	*req_addr = req;

	return 0;
}

int wcrypto_do_rng(void *ctx, struct wcrypto_rng_op_data *opdata, void *tag)
{
	struct wcrypto_rng_ctx *ctxt = ctx;
	struct wcrypto_rng_cookie *cookie;
	struct wcrypto_rng_msg *req;
	struct wcrypto_rng_msg *resp;
	uint32_t tx_cnt = 0;
	uint32_t rx_cnt = 0;
	int ret = 0;

	ret = wcrypto_do_prepare(&cookie, opdata, &req, ctxt, tag);
	if (ret)
		return ret;

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
			ret = -WD_ETIMEDOUT;
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
	ret = WD_SUCCESS;
fail_with_cookie:
	wd_put_cookies(&ctxt->pool, (void **)&cookie, 1);
	return ret;
}
