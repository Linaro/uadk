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

#define WD_DH_CTX_MSG_NUM	64
#define WD_DH_G2		2
#define WD_DH_MAX_CTX		256
#define DH_BALANCE_THRHD		1280
#define DH_RESEND_CNT	8
#define DH_RECV_MAX_CNT	60000000 // 1 min

static __thread int balance;

struct wcrypto_dh_cookie {
	struct wcrypto_cb_tag tag;
	struct wcrypto_dh_msg msg;
};

struct wcrypto_dh_ctx {
	struct wcrypto_dh_cookie cookies[WD_DH_CTX_MSG_NUM];
	__u8 cstatus[WD_DH_CTX_MSG_NUM];
	int cidx;
	__u32 key_size;
	unsigned long ctx_id;
	struct wd_queue *q;
	struct wd_dtb g;
	struct wcrypto_dh_ctx_setup setup;
};

static struct wcrypto_dh_cookie *get_dh_cookie(struct wcrypto_dh_ctx *ctx)
{
	int idx = ctx->cidx;
	int cnt = 0;

	while (__atomic_test_and_set(&ctx->cstatus[idx], __ATOMIC_ACQUIRE)) {
		idx++;
		cnt++;
		if (idx == WD_DH_CTX_MSG_NUM)
			idx = 0;
		if (cnt == WD_DH_CTX_MSG_NUM)
			return NULL;
	}

	ctx->cidx = idx;
	return &ctx->cookies[idx];
}

static void put_dh_cookie(struct wcrypto_dh_ctx *ctx, struct wcrypto_dh_cookie *cookie)
{
	int idx = ((uintptr_t)cookie - (uintptr_t)ctx->cookies) /
		sizeof(struct wcrypto_dh_cookie);

	if (unlikely(idx < 0 || idx >= WD_DH_CTX_MSG_NUM)) {
		WD_ERR("dh cookie not exist!\n");
		return;
	}
	__atomic_clear(&ctx->cstatus[idx], __ATOMIC_RELEASE);
}

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

/* Before initiate this context, we should get a queue from WD */
void *wcrypto_create_dh_ctx(struct wd_queue *q, struct wcrypto_dh_ctx_setup *setup)
{
	struct wcrypto_dh_ctx *ctx;
	struct q_info *qinfo;
	int i, ctx_id, ret;

	ret = create_ctx_param_check(q, setup);
	if (ret)
		return NULL;

	qinfo = q->qinfo;
	/* lock at ctx creating */
	wd_spinlock(&qinfo->qlock);

	if (!qinfo->br.alloc && !qinfo->br.iova_map)
		memcpy(&qinfo->br, &setup->br, sizeof(setup->br));

	if (qinfo->br.usr != setup->br.usr) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("err: qinfo and setup mm br.usr mismatch!\n");
		return NULL;
	}

	if (qinfo->ctx_num >= WD_DH_MAX_CTX) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("err: create too many dh ctx!\n");
		return NULL;
	}

	ctx_id = wd_alloc_ctx_id(q, WD_DH_MAX_CTX);
	if (ctx_id < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("err: alloc ctx id fail!\n");
		return NULL;
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
	ctx->ctx_id = ctx_id;
	ctx->key_size = setup->key_bits >> BYTE_BITS_SHIFT;
	for (i = 0; i < WD_DH_CTX_MSG_NUM; i++) {
		ctx->cookies[i].msg.is_g2 = (__u8)setup->is_g2;
		ctx->cookies[i].msg.data_fmt = setup->data_fmt;
		ctx->cookies[i].msg.key_bytes = ctx->key_size;
		ctx->cookies[i].msg.alg_type = WCRYPTO_DH;
		ctx->cookies[i].tag.ctx = ctx;
		ctx->cookies[i].tag.ctx_id = ctx_id;
		ctx->cookies[i].msg.usr_data = (uintptr_t)&ctx->cookies[i].tag;
	}

	if (setup->br.get_bufsize &&
	    setup->br.get_bufsize(setup->br.usr) < ctx->key_size) {
		WD_ERR("Blk_size < need_size<0x%x>.\n", ctx->key_size);
		free(ctx);
		goto free_ctx_id;
	}
	ctx->g.data = ctx->setup.br.alloc(ctx->setup.br.usr, ctx->key_size);
	ctx->g.bsize = ctx->key_size;
	return ctx;

free_ctx_id:
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	wd_free_ctx_id(q, ctx_id);
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
	struct wcrypto_dh_ctx *ctxt = ctx;
	struct wcrypto_dh_cookie *cookie;
	struct wcrypto_dh_msg *resp = NULL;
	int ret = -WD_EINVAL;
	struct wcrypto_dh_msg *req;
	uint32_t rx_cnt = 0;
	uint32_t tx_cnt = 0;

	ret = do_dh_param_check(ctx, opdata, tag);
	if (unlikely(ret))
		return ret;

	cookie = get_dh_cookie(ctxt);
	if (!cookie)
		return -WD_EBUSY;

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
	put_dh_cookie(ctxt, cookie);
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
		put_dh_cookie(ctx, (struct wcrypto_dh_cookie *)tag);
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

	wd_spinlock(&qinfo->qlock);
	if (qinfo->ctx_num <= 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("error: repeat del dh ctx!\n");
		return;
	}
	wd_free_ctx_id(cx->q, cx->ctx_id);
	if (!(--qinfo->ctx_num))
		memset(&qinfo->br, 0, sizeof(qinfo->br));
	wd_unspinlock(&qinfo->qlock);

	if (st->br.free && cx->g.data)
		st->br.free(st->br.usr, cx->g.data);

	free(ctx);
}
