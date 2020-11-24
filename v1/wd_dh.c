// SPDX-License-Identifier: GPL-2.0+
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

static __thread int balance;

struct wcrypto_dh_cookie {
	struct wcrypto_cb_tag tag;
	struct wcrypto_dh_msg msg;
};

struct wcrypto_dh_ctx {
	struct wcrypto_dh_cookie cookies[WD_DH_CTX_MSG_NUM];
	__u8 cstatus[WD_DH_CTX_MSG_NUM];
	int cidx;
	int key_size;
	int ctx_id;
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

	if (idx < 0 || idx >= WD_DH_CTX_MSG_NUM) {
		WD_ERR("dh cookie not exist!\n");
		return;
	}
	__atomic_clear(&ctx->cstatus[idx], __ATOMIC_RELEASE);
}

/* Before initiate this context, we should get a queue from WD */
void *wcrypto_create_dh_ctx(struct wd_queue *q, struct wcrypto_dh_ctx_setup *setup)
{
	struct wcrypto_dh_ctx *ctx;
	struct q_info *qinfo;
	int i, ctx_id;

	if (!q || !setup) {
		WD_ERR("%s(): input param err!\n", __func__);
		return NULL;
	}

	qinfo = q->info;
	if (strncmp(q->capa.alg, "dh", strlen("dh"))) {
		WD_ERR("%s(): algorithm mismatch!\n", __func__);
		return NULL;
	}

	/* lock at ctx creating */
	wd_spinlock(&qinfo->qlock);

	if (!qinfo->ops.alloc && !qinfo->ops.dma_map)
		memcpy(&qinfo->ops, &setup->ops, sizeof(setup->ops));

	if (qinfo->ops.usr != setup->ops.usr) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("err: qinfo and setup mm ops.usr mismatch!\n");
		return NULL;
	}

	qinfo->ctx_num++;
	ctx_id = qinfo->ctx_num;
	wd_unspinlock(&qinfo->qlock);

	if (ctx_id > WD_DH_MAX_CTX) {
		WD_ERR("err: create too many dh ctx!\n");
		return NULL;
	}

	ctx = malloc(sizeof(struct wcrypto_dh_ctx));
	if (!ctx) {
		WD_ERR("alloc ctx memory fail!\n");
		return ctx;
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
		ctx->cookies[i].msg.alg_type = WD_DH;
		ctx->cookies[i].tag.ctx = ctx;
		ctx->cookies[i].tag.ctx_id = ctx_id;
		ctx->cookies[i].msg.usr_data = (__u64)&ctx->cookies[i].tag;
	}

	ctx->g.data = ctx->setup.ops.alloc(ctx->setup.ops.usr, ctx->key_size);
	ctx->g.bsize = ctx->key_size;
	return ctx;
}

bool wcrypto_dh_is_g2(void *ctx)
{
	if (ctx)
		return ((struct wcrypto_dh_ctx *)ctx)->setup.is_g2;

	return false;
}

int wcrypto_dh_key_bits(void *ctx)
{
	if (ctx)
		return ((struct wcrypto_dh_ctx *)ctx)->setup.key_bits;

	return 0;
}

int wcrypto_set_dh_g(void *ctx, struct wd_dtb *g)
{
	struct wcrypto_dh_ctx *cx = ctx;

	if (ctx && g && g->dsize
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
	if (ctx && g)
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

	if (!req->g) {
		WD_ERR("request dh g is NULL!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
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

	if (!ctx || !opdata) {
		WD_ERR("input param err!\n");
		return ret;
	}

	cookie = get_dh_cookie(ctxt);
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
	ret = dh_request_init(req, opdata, ctxt);
	if (ret)
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
	} else if (ret) {
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
		if (balance > DH_BALANCE_THRHD)
			usleep(1);
		goto recv_again;
	} else if (ret < 0) {
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

	do {
		ret = wd_recv(q, (void **)&resp);
		if (ret == 0)
			break;
		else if (ret < 0) {
			WD_ERR("recv err at dh poll!\n");
			return ret;
		}

		count++;
		tag = (void *)resp->usr_data;
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
		WD_ERR("Delete dh ctx is NULL!\n");
		return;
	}

	cx = ctx;
	qinfo = cx->q->info;
	st = &cx->setup;

	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;

	if (!qinfo->ctx_num) {
		memset(&qinfo->ops, 0, sizeof(qinfo->ops));
	} else if (qinfo->ctx_num < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("error:repeat del dh ctx!\n");
		return;
	}

	wd_unspinlock(&qinfo->qlock);

	if (st->ops.free && &cx->g.data)
		st->ops.free(st->ops.usr, &cx->g.data);

	free(ctx);
}
