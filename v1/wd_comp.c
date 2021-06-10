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
#include "wd_util.h"
#include "wd_comp.h"

#define MAX_ALG_LEN			32
#define MAX_RETRY_COUNTS		200000000

struct wcrypto_comp_cookie {
	struct wcrypto_comp_tag tag;
	struct wcrypto_comp_msg msg;
};

struct wcrypto_comp_ctx {
	struct wd_cookie_pool pool;
	unsigned long ctx_id;
	void *ctx_buf; /* extra memory for stream mode */
	struct wd_queue *q;
	wcrypto_cb cb;
};

static void fill_comp_msg(struct wcrypto_comp_ctx *ctx,
			 struct wcrypto_comp_msg *msg,
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
}

static int set_comp_ctx_br(struct q_info *qinfo, struct wd_mm_br *br)
{
	if (!br->alloc || !br->free ||
	    !br->iova_map || !br->iova_unmap) {
		WD_ERR("err: invalid mm br in ctx_setup!\n");
		return -WD_EINVAL;
	}

	if (qinfo->br.usr && (qinfo->br.usr != br->usr)) {
		WD_ERR("err: qinfo and setup mm br.usr mismatch!\n");
		return -WD_EINVAL;
	}

	if (!qinfo->br.alloc && !qinfo->br.iova_map)
		memcpy(&qinfo->br, br, sizeof(qinfo->br));

	return WD_SUCCESS;
}

static int init_comp_ctx(struct wcrypto_comp_ctx *ctx, int ctx_id,
			 struct wcrypto_comp_ctx_setup *setup)
{
	int cache_num = ctx->pool.cookies_num;
	struct wcrypto_comp_cookie *cookie;
	int i;

	if (setup->stream_mode == WCRYPTO_COMP_STATEFUL) {
		cache_num = 1;
		ctx->ctx_buf = setup->br.alloc(setup->br.usr, MAX_CTX_RSV_SIZE);
		if (!ctx->ctx_buf) {
			WD_ERR("err: fail to alloc compress ctx buffer!\n");
			return -WD_ENOMEM;
		}
	}

	for (i = 0; i < cache_num; i++) {
		cookie = (void *)((uintptr_t)ctx->pool.cookies +
			i * ctx->pool.cookies_size);
		cookie->msg.comp_lv = setup->comp_lv;
		cookie->msg.op_type = setup->op_type;
		cookie->msg.win_size = setup->win_size;
		cookie->msg.alg_type = setup->alg_type;
		cookie->msg.stream_mode = setup->stream_mode;
		cookie->msg.data_fmt = setup->data_fmt;
		cookie->msg.ctx_buf = ctx->ctx_buf;
		cookie->tag.wcrypto_tag.ctx = ctx;
		cookie->tag.wcrypto_tag.ctx_id = ctx_id;
		cookie->msg.udata = (uintptr_t)&cookie->tag;
	}

	ctx->cb = setup->cb;
	ctx->ctx_id = ctx_id;

	return WD_SUCCESS;
}

/**
 * wcrypto_create_comp_ctx()- create a compress context on the warpdrive queue.
 * @q: warpdrive queue, need requested by user.
 * @setup: setup data of user
 */
void *wcrypto_create_comp_ctx(struct wd_queue *q,
			      struct wcrypto_comp_ctx_setup *setup)
{
	struct wcrypto_comp_ctx *ctx;
	struct q_info *qinfo;
	__u32 ctx_id = 0;
	int ret;

	if (!q || !setup) {
		WD_ERR("err, input parameter invalid!\n");
		return NULL;
	}

	if (strcmp(q->capa.alg, "zlib") &&
	    strcmp(q->capa.alg, "gzip") &&
	    strcmp(q->capa.alg, "deflate") &&
	    strcmp(q->capa.alg, "lz77_zstd")) {
		WD_ERR("algorithm mismatch!\n");
		return NULL;
	}

	qinfo = q->qinfo;

	/* lock at ctx creating/deleting */
	wd_spinlock(&qinfo->qlock);

	ret = set_comp_ctx_br(qinfo, &setup->br);
	if (ret) {
		WD_ERR("err: fail to set compress ctx br!\n");
		goto unlock;
	}

	if (qinfo->ctx_num >= WD_MAX_CTX_NUM) {
		WD_ERR("err: create too many compress ctx!\n");
		goto unlock;
	}

	ret = wd_alloc_id(qinfo->ctx_id, WD_MAX_CTX_NUM, &ctx_id, 0,
		WD_MAX_CTX_NUM);
	if (ret) {
		WD_ERR("err: alloc ctx id fail!\n");
		goto unlock;
	}
	qinfo->ctx_num++;
	wd_unspinlock(&qinfo->qlock);

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		WD_ERR("alloc ctx fail!\n");
		goto free_ctx_id;
	}

	ret = wd_init_cookie_pool(&ctx->pool,
			sizeof(struct wcrypto_comp_cookie), WD_CTX_MSG_NUM);
	if (ret) {
		WD_ERR("fail to init cookie pool!\n");
		goto free_ctx_buf;
	}

	ctx->q = q;
	ret = init_comp_ctx(ctx, ctx_id + 1, setup);
	if (ret) {
		WD_ERR("err: fail to init compress ctx!\n");
		wd_uninit_cookie_pool(&ctx->pool);
		goto free_ctx_buf;
	}

	return ctx;

free_ctx_buf:
	free(ctx);
free_ctx_id:
	wd_free_id(qinfo->ctx_id, WD_MAX_CTX_NUM, ctx_id, WD_MAX_CTX_NUM);
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
unlock:
	wd_unspinlock(&qinfo->qlock);
	return NULL;
}

/**
 * wcrypto_do_comp() - syn/asynchronous compressing/decompressing operation
 * @ctx: context of user
 * @opdata: operational data
 * @tag: asynchronous:uesr_tag; synchronous:NULL.
 */
int wcrypto_do_comp(void *ctx, struct wcrypto_comp_op_data *opdata, void *tag)
{
	struct wcrypto_comp_cookie *cookie = NULL;
	struct wcrypto_comp_ctx *cctx = ctx;
	struct wcrypto_comp_msg *msg, *resp;
	__u64 recv_count = 0;
	int ret;

	if (!ctx || !opdata) {
		WD_ERR("input parameter err!\n");
		return -EINVAL;
	}

	ret = wd_get_cookies(&cctx->pool, (void **)&cookie, 1);
	if (ret)
		return ret;

	msg = &cookie->msg;
	if (tag) {
		if (!cctx->cb) {
			WD_ERR("ctx call back is null!\n");
			ret = -WD_EINVAL;
			goto err_put_cookie;
		}
		cookie->tag.wcrypto_tag.tag = tag;
	}

	cookie->tag.priv = opdata->priv;

	fill_comp_msg(cctx, msg, opdata);
	ret = wd_send(cctx->q, msg);
	if (ret < 0) {
		WD_ERR("wd_send err!\n");
		goto err_put_cookie;
	}

	if (tag)
		return ret;

	resp = (void *)(uintptr_t)cctx->ctx_id;
recv_again:
	ret = wd_recv(cctx->q, (void **)&resp);
	if (ret == -WD_HW_EACCESS) {
		WD_ERR("wd_recv hw err!\n");
		goto err_put_cookie;
	} else if (ret == 0) {
		if (++recv_count > MAX_RETRY_COUNTS) {
			WD_ERR("wd_recv timeout fail!\n");
			ret = -ETIMEDOUT;
			goto err_put_cookie;
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

err_put_cookie:
	wd_put_cookies(&cctx->pool, (void **)&cookie, 1);
	return ret;
}

/**
 * wcrypto_comp_poll() - poll operation for asynchronous operation
 * @q:wrapdrive queue
 * @num:how many respondences this poll has to get, 0 means get all finishings
 */
int wcrypto_comp_poll(struct wd_queue *q, unsigned int num)
{
	struct wcrypto_comp_msg *resp = NULL;
	struct wcrypto_comp_ctx *ctx;
	struct wcrypto_comp_tag *tag;
	int count = 0;
	int ret;

	if (!q) {
		WD_ERR("%s(): input parameter err!\n", __func__);
		return -WD_EINVAL;
	}

	do {
		ret = wd_recv(q, (void **)&resp);
		if (ret == 0) {
			break;
		} else if (ret == -WD_HW_EACCESS) {
			if (!resp) {
				WD_ERR("recv err from req_cache!\n");
				return ret;
			}
			resp->status = WD_HW_EACCESS;
		} else if (ret < 0) {
			WD_ERR("recv err at qm receive!\n");
			return ret;
		}

		count++;
		tag = (void *)(uintptr_t)resp->udata;
		ctx = tag->wcrypto_tag.ctx;
		ctx->cb(resp, tag->wcrypto_tag.tag);
		wd_put_cookies(&ctx->pool, (void **)&tag, 1);
		resp = NULL;
	} while (--num);

	return ret < 0 ? ret : count;
}

/**
 * wcrypto_del_comp_ctx() -  free compress context
 * @ctx: the context to be free
 */
void wcrypto_del_comp_ctx(void *ctx)
{
	struct wcrypto_comp_ctx *cctx = ctx;
	struct q_info *qinfo;
	struct wd_mm_br *br;

	if (!cctx) {
		WD_ERR("delete compress ctx is NULL!\n");
		return;
	}

	qinfo = cctx->q->qinfo;
	br = &qinfo->br;
	if (br && br->free && cctx->ctx_buf)
		br->free(br->usr, cctx->ctx_buf);

	wd_uninit_cookie_pool(&cctx->pool);
	wd_spinlock(&qinfo->qlock);
	wd_free_id(qinfo->ctx_id, WD_MAX_CTX_NUM, cctx->ctx_id -1,
		WD_MAX_CTX_NUM);
	qinfo->ctx_num--;
	if (!qinfo->ctx_num) {
		memset(&qinfo->br, 0, sizeof(qinfo->br));
	} else if (qinfo->ctx_num < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("error: repeat delete compress ctx!\n");
		return;
	}
	wd_unspinlock(&qinfo->qlock);

	free(cctx);
}

