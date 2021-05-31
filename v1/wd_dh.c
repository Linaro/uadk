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
#include "wd_dh.h"
#include "wd_util.h"

#define WD_DH_G2		2
#define DH_BALANCE_THRHD		1280
#define DH_RESEND_CNT	8
#define DH_RECV_MAX_CNT	60000000 // 1 min

static __thread int balance;

struct wcrypto_dh_cookie {
	struct wcrypto_cb_tag tag;
	struct wcrypto_dh_msg msg;
};

struct wcrypto_dh_ctx {
	struct wd_cookie_pool pool;
	__u32 key_size;
	unsigned long ctx_id;
	struct wd_queue *q;
	struct wd_dtb g;
	struct wcrypto_dh_ctx_setup setup;
};

static int create_ctx_param_check(struct wd_queue *q,
				  struct wcrypto_dh_ctx_setup *setup)
{
	if (!q || !setup) {
		WD_ERR("%s(): input parameter err!\n", __func__);
		return -WD_EINVAL;
	}

	if (!setup->br.alloc || !setup->br.free) {
		WD_ERR("create dh ctx user mm br err!\n");
		return -WD_EINVAL;
	}

	if (strcmp(q->capa.alg, "dh")) {
		WD_ERR("%s(): algorithm mismatch!\n", __func__);
		return -WD_EINVAL;
	}

	return 0;
}

static int wcrypto_init_dh_cookie(struct wcrypto_dh_ctx *ctx)
{
	struct wcrypto_dh_ctx_setup *setup = &ctx->setup;
	struct wcrypto_dh_cookie *cookie;
	int ret, i;

	ret = wd_init_cookie_pool(&ctx->pool,
		sizeof(struct wcrypto_dh_cookie), WD_HPRE_CTX_MSG_NUM);
	if (ret) {
		WD_ERR("fail to init cookie pool!\n");
		return ret;
	}

	for (i = 0; i < ctx->pool.cookies_num; i++) {
		cookie = (void *)((uintptr_t)ctx->pool.cookies +
			i * ctx->pool.cookies_size);
		cookie->msg.is_g2 = (__u8)setup->is_g2;
		cookie->msg.data_fmt = setup->data_fmt;
		cookie->msg.key_bytes = ctx->key_size;
		cookie->msg.alg_type = WCRYPTO_DH;
		cookie->tag.ctx = ctx;
		cookie->tag.ctx_id = ctx->ctx_id;
		cookie->msg.usr_data = (uintptr_t)&cookie->tag;
	}

	return 0;
}

/* Before initiate this context, we should get a queue from WD */
void *wcrypto_create_dh_ctx(struct wd_queue *q, struct wcrypto_dh_ctx_setup *setup)
{
	struct wcrypto_dh_ctx *ctx;
	struct q_info *qinfo;
	__u32 ctx_id = 0;
	int ret;

	ret = create_ctx_param_check(q, setup);
	if (ret)
		return NULL;

	qinfo = q->qinfo;
	/* lock at ctx creating */
	wd_spinlock(&qinfo->qlock);

	if (!qinfo->br.alloc && !qinfo->br.iova_map)
		memcpy(&qinfo->br, &setup->br, sizeof(setup->br));

	if (qinfo->br.usr != setup->br.usr) {
		WD_ERR("err: qinfo and setup mm br.usr mismatch!\n");
		goto unlock;
	}

	if (qinfo->ctx_num >= WD_MAX_CTX_NUM) {
		WD_ERR("err: create too many dh ctx!\n");
		goto unlock;
	}

	ret = wd_alloc_id(qinfo->ctx_id, WD_MAX_CTX_NUM,
			&ctx_id, 0, WD_MAX_CTX_NUM);
	if (ret) {
		WD_ERR("err: alloc ctx id fail!\n");
		goto unlock;
	}
	qinfo->ctx_num++;
	wd_unspinlock(&qinfo->qlock);

	ctx = malloc(sizeof(struct wcrypto_dh_ctx));
	if (!ctx) {
		WD_ERR("alloc ctx memory fail!\n");
		goto free_ctx_id;
	}

	memset(ctx, 0, sizeof(struct wcrypto_dh_ctx));
	memcpy(&ctx->setup, setup, sizeof(*setup));
	ctx->q = q;
	ctx->ctx_id = ctx_id + 1;
	ctx->key_size = setup->key_bits >> BYTE_BITS_SHIFT;

	if (setup->br.get_bufsize &&
	    setup->br.get_bufsize(setup->br.usr) < ctx->key_size) {
		WD_ERR("Blk_size < need_size<0x%x>.\n", ctx->key_size);
		goto free_ctx;
	}
	ctx->g.data = ctx->setup.br.alloc(ctx->setup.br.usr, ctx->key_size);
	ctx->g.bsize = ctx->key_size;

	ret = wcrypto_init_dh_cookie(ctx);
	if (ret)
		goto free_ctx;

	return ctx;

free_ctx:
	free(ctx);
free_ctx_id:
	wd_free_id(qinfo->ctx_id, WD_MAX_CTX_NUM, ctx_id, WD_MAX_CTX_NUM);
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
unlock:
	wd_unspinlock(&qinfo->qlock);

	return NULL;
}

bool wcrypto_dh_is_g2(const void *ctx)
{
	if (!ctx) {
		WD_ERR("dh is g2 judge, ctx NULL, return false!\n");
		return false;
	}

	return ((struct wcrypto_dh_ctx *)ctx)->setup.is_g2;
}

int wcrypto_dh_key_bits(const void *ctx)
{
	if (!ctx) {
		WD_ERR("get dh key bits, ctx NULL!\n");
		return 0;
	}

	return ((struct wcrypto_dh_ctx *)ctx)->setup.key_bits;
}

int wcrypto_set_dh_g(void *ctx, struct wd_dtb *g)
{
	struct wcrypto_dh_ctx *cx = ctx;

	if (!cx || !g) {
		WD_ERR("parameter NULL!\n");
		return -WD_EINVAL;
	}

	if (g->dsize
		&& g->bsize <= cx->g.bsize
		&& g->dsize <= cx->g.bsize) {
		memset(cx->g.data, 0, g->bsize);
		memcpy(cx->g.data, g->data, g->dsize);
		cx->g.dsize = g->dsize;
		if (*g->data != WD_DH_G2 && cx->setup.is_g2)
			return -WD_EINVAL;
		return WD_SUCCESS;
	}

	return -WD_EINVAL;
}

void wcrypto_get_dh_g(void *ctx, struct wd_dtb **g)
{
	if (!ctx || !g) {
		WD_ERR("parameter NULL!\n");
		return;
	}

	*g = &((struct wcrypto_dh_ctx *)ctx)->g;
}

static int dh_request_init(struct wcrypto_dh_msg *req, struct wcrypto_dh_op_data *op,
				struct wcrypto_dh_ctx *c)
{
	req->x_p = (__u8 *)op->x_p;
	req->xbytes = (__u16)op->xbytes;
	req->pbytes = (__u16)op->pbytes;
	req->out = (__u8 *)op->pri;
	req->op_type = op->op_type;
	req->result = WD_EINVAL;

	if (op->op_type == WCRYPTO_DH_PHASE1) {
		req->g = (__u8 *)c->g.data;
		req->gbytes = c->g.dsize;
	} else {
		req->g = (__u8 *)op->pv;
		req->gbytes = op->pvbytes;
	}

	if (unlikely(!req->g)) {
		WD_ERR("request dh g is NULL!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int do_dh_param_check(void *ctx, struct wcrypto_dh_op_data *opdata, void *tag)
{
	struct wcrypto_dh_ctx *ctxt = ctx;

	if (unlikely(!ctx || !opdata)) {
		WD_ERR("input parameter err!\n");
		return -WD_EINVAL;
	}

	if (unlikely(tag && !ctxt->setup.cb)) {
		WD_ERR("ctx call back is null!\n");
		return -WD_EINVAL;
	}

	return 0;
}

int wcrypto_do_dh(void *ctx, struct wcrypto_dh_op_data *opdata, void *tag)
{
	struct wcrypto_dh_cookie *cookie = NULL;
	struct wcrypto_dh_msg *resp = NULL;
	struct wcrypto_dh_ctx *ctxt = ctx;
	struct wcrypto_dh_msg *req;
	uint32_t rx_cnt = 0;
	uint32_t tx_cnt = 0;
	int ret;

	ret = do_dh_param_check(ctx, opdata, tag);
	if (unlikely(ret))
		return ret;

	ret = wd_get_cookies(&ctxt->pool, (void **)&cookie, 1);
	if (ret)
		return ret;

	if (tag)
		cookie->tag.tag = tag;

	req = &cookie->msg;
	ret = dh_request_init(req, opdata, ctxt);
	if (unlikely(ret))
		goto fail_with_cookie;

send_again:
	ret = wd_send(ctxt->q, req);
	if (ret == -WD_EBUSY) {
		tx_cnt++;
		usleep(1);
		if (tx_cnt < DH_RESEND_CNT)
			goto send_again;
		else {
			WD_ERR("do dh send cnt %u, exit!\n", tx_cnt);
			goto fail_with_cookie;
		}
	} else if (unlikely(ret)) {
		WD_ERR("do dh wd_send err!\n");
		goto fail_with_cookie;
	}

	if (tag)
		return ret;

	resp = (void *)(uintptr_t)ctxt->ctx_id;
recv_again:
	ret = wd_recv(ctxt->q, (void **)&resp);
	if (!ret) {
		rx_cnt++;
		if (unlikely(rx_cnt >= DH_RECV_MAX_CNT)) {
			WD_ERR("failed to receive: timeout!\n");
			return -WD_ETIMEDOUT;
		} else if (balance > DH_BALANCE_THRHD) {
			usleep(1);
		}
		goto recv_again;
	} else if (unlikely(ret < 0)) {
		WD_ERR("do dh wd_recv err!\n");
		goto fail_with_cookie;
	}

	balance = rx_cnt;
	opdata->pri = (void *)resp->out;
	opdata->pri_bytes = resp->out_bytes;
	opdata->status = resp->result;
	ret = GET_NEGATIVE(opdata->status);

fail_with_cookie:
	wd_put_cookies(&ctxt->pool, (void **)&cookie, 1);
	return ret;
}

int wcrypto_dh_poll(struct wd_queue *q, unsigned int num)
{
	struct wcrypto_dh_msg *resp = NULL;
	struct wcrypto_dh_ctx *ctx;
	struct wcrypto_cb_tag *tag;
	int count = 0;
	int ret;

	if (unlikely(!q)) {
		WD_ERR("q is NULL!\n");
		return -WD_EINVAL;
	}

	do {
		ret = wd_recv(q, (void **)&resp);
		if (ret == 0)
			break;
		else if (unlikely(ret < 0)) {
			WD_ERR("receive err at dh poll!\n");
			return ret;
		}

		count++;
		tag = (void *)(uintptr_t)resp->usr_data;
		ctx = tag->ctx;
		ctx->setup.cb(resp, tag->tag);
		wd_put_cookies(&ctx->pool, (void **)&tag, 1);
		resp = NULL;
	} while (--num);

	return count;
}

void wcrypto_del_dh_ctx(void *ctx)
{
	struct wcrypto_dh_ctx_setup *st;
	struct wcrypto_dh_ctx *cx;
	struct q_info *qinfo;

	if (!ctx) {
		WD_ERR("delete dh parameter err!\n");
		return;
	}

	cx = ctx;
	qinfo = cx->q->qinfo;
	st = &cx->setup;

	wd_uninit_cookie_pool(&cx->pool);
	wd_spinlock(&qinfo->qlock);
	if (qinfo->ctx_num <= 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("error: repeat del dh ctx!\n");
		return;
	}

	wd_free_id(qinfo->ctx_id, WD_MAX_CTX_NUM, cx->ctx_id - 1,
		WD_MAX_CTX_NUM);

	if (!(--qinfo->ctx_num))
		memset(&qinfo->br, 0, sizeof(qinfo->br));
	wd_unspinlock(&qinfo->qlock);

	if (st->br.free && cx->g.data)
		st->br.free(st->br.usr, cx->g.data);

	free(ctx);
}
