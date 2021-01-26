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
#define WD_COMP_MAX_CTX			256
#define WD_COMP_CTX_MSGCACHE_NUM	1024

struct wcrypto_comp_cache {
	struct wcrypto_comp_tag tag;
	struct wcrypto_comp_msg msg;
};

struct wcrypto_comp_ctx {
	struct wcrypto_comp_cache caches[WD_COMP_CTX_MSGCACHE_NUM];
	__u8 cstatus[WD_COMP_CTX_MSGCACHE_NUM];
	int c_tail; /* start index for every search */
	unsigned long ctx_id;
	void *ctx_buf; /* extra memory for stream mode */
	struct wd_queue *q;
	wcrypto_cb cb;
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
	int cache_num = WD_COMP_CTX_MSGCACHE_NUM;
	int i;

	if (setup->stream_mode == WCRYPTO_COMP_STATEFUL) {
		cache_num = 1;
		ctx->ctx_buf = setup->br.alloc(setup->br.usr, MAX_CTX_RSV_SIZE);
		if (!ctx->ctx_buf) {
			WD_ERR("err: fail to alloc comp ctx buffer!\n");
			return -WD_ENOMEM;
		}
	}

	for (i = 0; i < cache_num; i++) {
		ctx->caches[i].msg.comp_lv = setup->comp_lv;
		ctx->caches[i].msg.op_type = setup->op_type;
		ctx->caches[i].msg.win_size = setup->win_size;
		ctx->caches[i].msg.alg_type = setup->alg_type;
		ctx->caches[i].msg.stream_mode = setup->stream_mode;
		ctx->caches[i].msg.data_fmt = setup->data_fmt;
		ctx->caches[i].msg.ctx_buf = ctx->ctx_buf;
		ctx->caches[i].tag.wcrypto_tag.ctx = ctx;
		ctx->caches[i].tag.wcrypto_tag.ctx_id = ctx_id;
		ctx->caches[i].msg.udata = (uintptr_t)&ctx->caches[i].tag;
	}

	ctx->cb = setup->cb;
	ctx->ctx_id = ctx_id;

	return WD_SUCCESS;
}

/**
 * wcrypto_create_comp_ctx()- create a compress context on the wrapdrive queue.
 * @q: wrapdrive queue, need requested by user.
 * @setup:setup data of user
 */
void *wcrypto_create_comp_ctx(struct wd_queue *q,
			      struct wcrypto_comp_ctx_setup *setup)
{
	struct wcrypto_comp_ctx *ctx;
	struct q_info *qinfo;
	int ctx_id, ret;

	if (!q || !setup) {
		WD_ERR("err, input param invalid!\n");
		return NULL;
	}

	if (strncmp(q->capa.alg, "zlib", strlen("zlib")) &&
	    strncmp(q->capa.alg, "gzip", strlen("gzip")) &&
	    strncmp(q->capa.alg, "deflate", strlen("deflate")) &&
	    strncmp(q->capa.alg, "lz77_zstd", strlen("lz77_zstd"))) {
		WD_ERR("alg mismatching!\n");
		return NULL;
	}

	qinfo = q->qinfo;

	/* lock at ctx creating/deleting */
	wd_spinlock(&qinfo->qlock);

	ret = set_comp_ctx_br(qinfo, &setup->br);
	if (ret) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("err: fail to set comp ctx br!\n");
		return NULL;
	}

	if (qinfo->ctx_num >= WD_COMP_MAX_CTX) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("err:create too many comp ctx!\n");
		return NULL;
	}

	ctx_id = wd_alloc_ctx_id(q, WD_COMP_MAX_CTX);
	if (ctx_id < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("err: alloc ctx id fail!\n");
		return NULL;
	}
	qinfo->ctx_num++;
	wd_unspinlock(&qinfo->qlock);

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		WD_ERR("alloc ctx  fail!\n");
		goto free_ctx_id;
	}

	ctx->q = q;
	ret = init_comp_ctx(ctx, ctx_id, setup);
	if (ret) {
		WD_ERR("err: fail to init comp ctx!\n");
		goto free_ctx_buf;
	}

	return ctx;

free_ctx_buf:
	free(ctx);
free_ctx_id:
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	wd_free_ctx_id(q, ctx_id);
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
		cache->tag.wcrypto_tag.tag = tag;
	}

	cache->tag.priv = opdata->priv;

	fill_comp_msg(cctx, msg, opdata);
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
	if (ret == -WD_HW_EACCESS) {
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
		WD_ERR("%s(): input param err!\n", __func__);
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
		put_comp_cache(ctx, (struct wcrypto_comp_cache *)tag);
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
		WD_ERR("delete comp ctx is NULL!\n");
		return;
	}

	qinfo = cctx->q->qinfo;
	br = &qinfo->br;
	if (br && br->free && cctx->ctx_buf)
		br->free(br->usr, cctx->ctx_buf);

	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	wd_free_ctx_id(cctx->q, cctx->ctx_id);
	if (!qinfo->ctx_num) {
		memset(&qinfo->br, 0, sizeof(qinfo->br));
	} else if (qinfo->ctx_num < 0) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("error:repeat del comp ctx!\n");
		return;
	}
	wd_unspinlock(&qinfo->qlock);

	free(cctx);
}

