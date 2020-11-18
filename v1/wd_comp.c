// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2019. Hisilicon Tech Co. Ltd. All Rights Reserved. */
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
#include "wd_util.h"
#include "wd_comp.h"

#define MAX_ALG_LEN 32
#define MAX_RETRY_COUNTS 200000000
#define WD_COMP_MAX_CTX		256
#define WD_COMP_CTX_MSGCACHE_NUM 512

struct wcrypto_comp_cache {
	struct wcrypto_cb_tag tag;
	struct wcrypto_comp_msg msg;
};

struct wcrypto_comp_ctx {
	struct wcrypto_comp_cache caches[WD_COMP_CTX_MSGCACHE_NUM];
	__u8 cstatus[WD_COMP_CTX_MSGCACHE_NUM];
	int c_tail;  /* start index for every search */
	int ctx_id;
	struct wd_queue *q;
	struct wcrypto_comp_msg *msg;
	wcrypto_cb cb;
	struct wcrypto_comp_op_data *udata;
};

static struct wcrypto_comp_cache *get_comp_cache(struct wcrypto_comp_ctx *ctx)
{
	int idx = ctx->c_tail;
	int cnt = 0;

	while (__atomic_test_and_set(&ctx->cstatus[idx], __ATOMIC_ACQUIRE)) {
		idx++;
		cnt++;
		if (idx == WD_COMP_CTX_MSGCACHE_NUM)
			idx = 0;
		if (cnt == WD_COMP_CTX_MSGCACHE_NUM)
			return NULL;
	}

	ctx->c_tail = idx;
	return &ctx->caches[idx];
}

static void put_comp_cache(struct wcrypto_comp_ctx *ctx,
			     struct wcrypto_comp_cache *cache)
{
	int idx = ((uintptr_t)cache - (uintptr_t)ctx->caches) /
		sizeof(struct wcrypto_comp_cache);

	if (idx < 0 || idx >= WD_COMP_CTX_MSGCACHE_NUM) {
		WD_ERR("comp cache not exist!\n");
		return;
	}
	__atomic_clear(&ctx->cstatus[idx], __ATOMIC_RELEASE);
}

static int fill_comp_msg(struct wcrypto_comp_ctx *ctx, struct wcrypto_comp_msg *msg,
						struct wcrypto_comp_op_data *opdata)
{
	msg->avail_out = opdata->avail_out;
	msg->src = opdata->in;
	msg->dst = opdata->out;
	msg->in_size = opdata->in_len;
	msg->flush_type = opdata->flush;
	msg->stream_pos = opdata->stream_pos;
	msg->isize = opdata->isize;
	msg->checksum = opdata->checksum;
	msg->tag = ctx->ctx_id;
	msg->status = 0;

	return WD_SUCCESS;
}

/**
 * wcrypto_create_comp_ctx()- create a compress context on the wrapdrive queue.
 * @q: wrapdrive queue, need requested by user.
 * @setup:setup data of user
 */
void *wcrypto_create_comp_ctx(struct wd_queue *q, struct wcrypto_comp_ctx_setup *setup)
{
	struct wcrypto_comp_ctx *ctx;
	struct q_info *qinfo;
	int ctx_id, i;

	if (!q || !setup) {
		WD_ERR("err, input param invalid!\n");
		return NULL;
	}

	if (strlen(q->capa.alg) > MAX_ALG_LEN) {
		WD_ERR("err, alg len invalid!\n");
		return NULL;
	}

	if (strncmp(q->capa.alg, "zlib", strlen("zlib")) &&
	    strncmp(q->capa.alg, "gzip", strlen("gzip"))) {
		WD_ERR("alg mismatching!\n");
		return NULL;
	}

	qinfo = q->info;

	/* lock at ctx  creating/deleting */
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num++;
	ctx_id = qinfo->ctx_num;
	wd_unspinlock(&qinfo->qlock);
	if (ctx_id > WD_COMP_MAX_CTX) {
		WD_ERR("err:create too many comp ctx!\n");
		return NULL;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		WD_ERR("alloc ctx  fail!\n");
		return ctx;
	}

	ctx->q = q;
	ctx->ctx_id = ctx_id;
	for (i = 0; i < WD_COMP_CTX_MSGCACHE_NUM; i++) {
		ctx->caches[i].msg.comp_lv = setup->comp_lv;
		ctx->caches[i].msg.win_size = setup->win_size;
		ctx->caches[i].msg.alg_type = setup->alg_type;
		ctx->caches[i].msg.stream_mode = setup->stream_mode;
		ctx->caches[i].msg.ctx_buf = setup->ctx_buf;
		ctx->caches[i].tag.ctx = ctx;
		ctx->caches[i].tag.ctx_id = ctx_id;
		ctx->caches[i].msg.udata = (__u64)&ctx->caches[i].tag;
	}
	ctx->cb = setup->cb;

	return ctx;
}

/**
 * wcrypto_do_comp() - syn/asynchronous compressing/decompressing operation
 * @ctx: context of user
 * @opdata: operational data
 * @tag: asynchronous:uesr_tag; synchronous:NULL.
 */
int wcrypto_do_comp(void *ctx, struct wcrypto_comp_op_data *opdata, void *tag)
{
	struct wcrypto_comp_ctx *cctx = ctx;
	struct wcrypto_comp_msg *msg, *resp;
	struct wcrypto_comp_cache *cache;
	__u64 recv_count = 0;
	int ret;

	if (!ctx || !opdata) {
		WD_ERR("input param err!\n");
		return -EINVAL;
	}

	cache = get_comp_cache(cctx);
	if (!cache)
		return -WD_EBUSY;

	msg = &cache->msg;
	if (tag) {
		if (!cctx->cb) {
			WD_ERR("ctx call back is null!\n");
			ret = -WD_EINVAL;
			goto err_put_cache;
		}
		cache->tag.tag = tag;
	}

	ret = fill_comp_msg(cctx, msg, opdata);
	if (ret) {
		ret = -WD_EINVAL;
		goto err_put_cache;
	}

	ret = wd_send(cctx->q, msg);
	if (ret < 0) {
		WD_ERR("wd_send err!\n");
		goto err_put_cache;
	}

	if (tag)
		return ret;

	resp = (void *)(uintptr_t)cctx->ctx_id;
recv_again:
	ret = wd_recv(cctx->q, (void **)&resp);
	if (ret == -WD_HW_ERR) {
		WD_ERR("wd_recv hw err!\n");
		goto err_put_cache;
	} else if (ret == 0) {
		if (++recv_count > MAX_RETRY_COUNTS) {
			WD_ERR("wd_recv timeout fail!\n");
			ret = -ETIMEDOUT;
			goto err_put_cache;
		}
		goto recv_again;
	}

	opdata->consumed = resp->in_cons;
	opdata->produced = resp->produced;
	opdata->flush = resp->flush_type;
	opdata->status = resp->status;
	opdata->isize = resp->isize;
	opdata->checksum = resp->checksum;
	ret = WD_SUCCESS;

err_put_cache:
	put_comp_cache(cctx, cache);
	return ret;
}

/**
 * wcrypto_comp_poll() - poll operation for asynchronous operation
 * @q:wrapdrive queue
 * @num:how many respondings this poll has to get, 0 means get all finishings
 */
int wcrypto_comp_poll(struct wd_queue *q, int num)
{
	struct wcrypto_comp_msg *resp = NULL;
	struct wcrypto_comp_ctx *ctx;
	struct wcrypto_cb_tag *tag;
	int count = 0;
	int ret;

	do {
		ret = wd_recv(q, (void **)&resp);
		if (ret == -WD_HW_ERR) {
			WD_ERR("wd_recv hw err!\n");
			return ret;
		} else if (ret == 0) {
			WD_ERR("wd_recv need again!\n");
			break;
		}

		count++;
		tag = (void *)resp->udata;
		ctx = tag->ctx;
		ctx->cb(resp, tag->tag);
		put_comp_cache(ctx, (struct wcrypto_comp_cache *)tag);
		resp = NULL;
	} while (--num);

	return count;
}

/**
 * wcrypto_del_comp_ctx() -  free compress context
 * @ctx: the context to be free
 */
void wcrypto_del_comp_ctx(void *ctx)
{
	struct wcrypto_comp_ctx *cctx = ctx;
	struct q_info *qinfo;

	if (!cctx)
		return;

	qinfo = cctx->q->info;

	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	if (qinfo->ctx_num < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("error:repeat del comp ctx!\n");
		return;
	}
	wd_unspinlock(&qinfo->qlock);

	free(cctx);
}

