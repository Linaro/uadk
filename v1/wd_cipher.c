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
#include "wd_cipher.h"
#include "wd_util.h"

#define WCRYPTO_CIPHER_CTX_MSG_NUM	64
#define WCRYPTO_CIPHER_MAX_CTX		256
#define MAX_CIPHER_KEY_SIZE		64
#define MAX_CIPHER_RETRY_CNT	20000000

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
	int idx = ctx->cidx, cnt = 0;

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
	int idx = ((unsigned long)cookie - (unsigned long)ctx->cookies) /
		sizeof(struct wcrypto_cipher_cookie);

	if (idx < 0 || idx >= WCRYPTO_CIPHER_CTX_MSG_NUM) {
		WD_ERR("cipher cookie not exist!\n");
		return;
	}
	__atomic_clear(&ctx->cstatus[idx], __ATOMIC_RELEASE);
}

static void del_ctx_key(struct wcrypto_cipher_ctx *ctx)
{
	struct wd_mm_ops *ops = &(ctx->setup.ops);

	if (ops && ops->free && ctx->key)
		ops->free(ops->usr, ctx->key);
}

/* Before initiate this context, we should get a queue from WD */
void *wcrypto_create_cipher_ctx(struct wd_queue *q,
	struct wcrypto_cipher_ctx_setup *setup)
{
	struct q_info *qinfo;
	struct wcrypto_cipher_ctx *ctx;
	int i, ctx_id;

	if (!q || !setup) {
		WD_ERR("%s(): input param err!\n", __func__);
		return NULL;
	}
	qinfo = q->info;
	if (!setup->ops.alloc || !setup->ops.free ||
		!setup->ops.dma_map || !setup->ops.dma_unmap) {
		WD_ERR("create cipher ctx user mm ops err!\n");
		return NULL;
	}
	if (strncmp(q->capa.alg, "cipher", strlen("cipher"))) {
		WD_ERR("%s(): algorithm mismatching!\n", __func__);
		return NULL;
	}

	/*lock at ctx  creating/deleting */
	wd_spinlock(&qinfo->qlock);
	if (!qinfo->ops.alloc && !qinfo->ops.dma_map)
		memcpy(&qinfo->ops, &setup->ops, sizeof(setup->ops));

	if (qinfo->ops.usr != setup->ops.usr) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("Err mm ops in creating cipher ctx!\n");
		return NULL;
	}
	qinfo->ctx_num++;
	ctx_id = qinfo->ctx_num;
	wd_unspinlock(&qinfo->qlock);
	if (ctx_id > WCRYPTO_CIPHER_MAX_CTX) {
		WD_ERR("err:create too many cipher ctx!\n");
		return NULL;
	}

	ctx = malloc(sizeof(struct wcrypto_cipher_ctx));
	if (!ctx) {
		WD_ERR("Alloc ctx memory fail!\n");
		return ctx;
	}
	memset(ctx, 0, sizeof(struct wcrypto_cipher_ctx));
	memcpy(&ctx->setup, setup, sizeof(*setup));
	ctx->q = q;
	ctx->ctx_id = ctx_id;
	ctx->key = setup->ops.alloc(setup->ops.usr, MAX_CIPHER_KEY_SIZE);
	if (!ctx->key) {
		WD_ERR("alloc cipher ctx key fail!\n");
		free(ctx);
		return NULL;
	}
	for (i = 0; i < WCRYPTO_CIPHER_CTX_MSG_NUM; i++) {
		ctx->cookies[i].msg.alg_type = WD_CIPHER;
		ctx->cookies[i].msg.alg = setup->alg;
		ctx->cookies[i].msg.data_fmt = setup->data_fmt;
		ctx->cookies[i].msg.mode = setup->mode;
		ctx->cookies[i].tag.wcrypto_tag.ctx = ctx;
		ctx->cookies[i].tag.wcrypto_tag.ctx_id = ctx_id;
		ctx->cookies[i].msg.usr_data = (__u64)&ctx->cookies[i].tag;
	}

	return ctx;
}

int wcrypto_set_cipher_key(void *ctx, __u8 *key, __u16 key_len)
{
	struct wcrypto_cipher_ctx *ctxt = ctx;

	if (!ctx || !key) {
		WD_ERR("%s(): input param err!\n", __func__);
		return -WD_EINVAL;
	}

	ctxt->key_bytes = key_len;
	memcpy(ctxt->key, key, key_len);

	return WD_SUCCESS;
}

static int cipher_request_init(struct wcrypto_cipher_msg *req,
	struct wcrypto_cipher_op_data *op, struct wcrypto_cipher_ctx *c)
{
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

	return WD_SUCCESS;
}
int wcrypto_do_cipher(void *ctx, struct wcrypto_cipher_op_data *opdata,
		void *tag)
{
	struct wcrypto_cipher_msg *resp = NULL, *req;
	struct wcrypto_cipher_ctx *ctxt = ctx;
	struct wcrypto_cipher_cookie *cookie;
	int ret = -WD_EINVAL;
	__u64 recv_count = 0;

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

	resp = (void *)(uintptr_t)ctxt->ctx_id;
recv_again:
	ret = wd_recv(ctxt->q, (void **)&resp);
	if (!ret) {
		if (++recv_count > MAX_CIPHER_RETRY_CNT) {
			WD_ERR("%s:wcrypto_recv timeout fail!\n", __func__);
			ret = -WD_ETIMEDOUT;
			goto fail_with_cookie;
		}
		goto recv_again;
	} else if (ret < 0) {
		WD_ERR("do cipher wcrypto_recv err!\n");
		goto fail_with_cookie;
	}
	opdata->out = (void *)resp->out;
	opdata->out_bytes = resp->out_bytes;
	opdata->status = resp->result;
	ret = WD_SUCCESS;

fail_with_cookie:
	put_cipher_cookie(ctxt, cookie);
	return ret;
}

int wcrypto_cipher_poll(struct wd_queue *q, unsigned int num)
{
	struct wcrypto_cipher_ctx *ctx;
	struct wcrypto_cipher_msg *resp = NULL;
	struct wcrypto_cipher_tag *tag;
	int ret, count = 0;

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
		}
		else if (ret < 0) {
			WD_ERR("recv err at cipher poll!\n");
			return ret;
		}
		count++;
		tag = (void *)resp->usr_data;
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
	qinfo = cx->q->info;
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	if (!qinfo->ctx_num)
		memset(&qinfo->ops, 0, sizeof(qinfo->ops));
	if (qinfo->ctx_num < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("errer:repeat del cipher ctx!\n");
		return;
	}
	wd_unspinlock(&qinfo->qlock);
	del_ctx_key(cx);
	free(ctx);
}
