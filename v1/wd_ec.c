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
#include "wd_util.h"
#include "wd_ec.h"

#define WCRYPTO_EC_CTX_MSG_NUM		512
#define WCRYPTO_EC_MAX_CTX		256
#define WCRYPTO_EC_MAX_RETRY_CNT	10000000
#define WCRYPTO_EC_INVALID_FLAG		0x7f

struct wcrypto_ec_cache {
	struct wcrypto_ec_tag tag;
	struct wcrypto_ec_msg msg;
	struct wcrypto_ec_table table;
};

struct wcrypto_ec_ctx {
	struct wcrypto_ec_cache caches[WCRYPTO_EC_CTX_MSG_NUM];
	__u8 cstatus[WCRYPTO_EC_CTX_MSG_NUM];
	int cidx;
	int ctx_id;
	struct wd_queue *q;
	wcrypto_cb cb;
	__u8 *tbl_buf;

};

static int alloc_tbl_mem(__u8 *buf, struct wd_queue *q,
	struct wcrypto_ec_table *ec_table)
{
	ec_table->src_addr = (struct rde_src_tbl *)buf;
	ec_table->src_addr_pa = (__u64)wd_dma_map(q,
		(void *)ec_table->src_addr, 0);
	if (!ec_table->src_addr_pa)
		return -WD_ENOMEM;

	ec_table->src_tag_addr =
		(struct rde_src_tag_tbl *)(buf + sizeof(struct rde_src_tbl));
	ec_table->src_tag_addr_pa = (__u64)wd_dma_map(q,
		(void *)ec_table->src_tag_addr, 0);
	if (!ec_table->src_tag_addr_pa)
		return -WD_ENOMEM;

	ec_table->dst_addr =
		(struct rde_dst_tbl *)((__u8 *)ec_table->src_tag_addr +
		sizeof(struct rde_src_tag_tbl));
	ec_table->dst_addr_pa = (__u64)wd_dma_map(q,
		(void *)ec_table->dst_addr, 0);
	if (!ec_table->dst_addr_pa)
		return -WD_ENOMEM;

	ec_table->dst_tag_addr =
		(struct rde_dst_tag_tbl *)((__u8 *)ec_table->dst_addr +
		sizeof(struct rde_dst_tbl));
	ec_table->dst_tag_addr_pa = (__u64)wd_dma_map(q,
		(void *)ec_table->dst_tag_addr, 0);
	if (!ec_table->dst_tag_addr_pa)
		return -WD_ENOMEM;

	ec_table->matrix = (__u8 *)ec_table->dst_tag_addr +
		sizeof(struct rde_dst_tag_tbl);
	ec_table->matrix_pa = (__u64)wd_dma_map(q,
		(void *)ec_table->matrix, 0);
	if (!ec_table->matrix_pa)
		return -WD_ENOMEM;

	return 0;
}

static struct wcrypto_ec_cache *get_ec_cache(struct wcrypto_ec_ctx *ctx)
{
	int idx = ctx->cidx, cnt = 0;

	while (__atomic_test_and_set(&ctx->cstatus[idx], __ATOMIC_ACQUIRE)) {
		idx++;
		cnt++;
		if (idx == WCRYPTO_EC_CTX_MSG_NUM)
			idx = 0;
		if (cnt == WCRYPTO_EC_CTX_MSG_NUM)
			return NULL;
	}

	ctx->cidx = idx;
	return &ctx->caches[idx];
}

static void put_ec_cache(struct wcrypto_ec_ctx *ctx,
	struct wcrypto_ec_cache *cache)
{
	int idx = ((unsigned long)cache - (unsigned long)ctx->caches) /
		sizeof(struct wcrypto_ec_cache);

	if (idx < 0 || idx >= WCRYPTO_EC_CTX_MSG_NUM) {
		WD_ERR("ec cache not exist!\n");
		return;
	}
	__atomic_clear(&ctx->cstatus[idx], __ATOMIC_RELEASE);
}

void *wcrypto_create_ec_ctx(struct wd_queue *q,
	struct wcrypto_ec_ctx_setup *setup)
{
	struct q_info *qinfo;
	struct wcrypto_ec_ctx *ctx;
	int ctx_id, i;

	if (!q || !setup) {
		WD_ERR("%s():  input param invalid!\n", __func__);
		return NULL;
	}

	if (strncmp(q->capa.alg, "rde", strlen("rde"))) {
		WD_ERR("%s(): alg mismatching!\n", __func__);
		return NULL;
	}

	qinfo = q->info;
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num++;
	ctx_id = qinfo->ctx_num;
	wd_unspinlock(&qinfo->qlock);
	if (ctx_id > WCRYPTO_EC_MAX_CTX) {
		WD_ERR("%s() create too mant ctx!\n", __func__);
		return NULL;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		WD_ERR("%s() alloc ctx fail!\n", __func__);
		return NULL;
	}
	ctx->q = q;
	ctx->ctx_id = ctx_id;
	ctx->cb = setup->cb;
	ctx->tbl_buf = wd_reserve_memory(ctx->q,
		WCRYPTO_EC_CTX_MSG_NUM * RDE_TLB_MEMSIZE);
	if (!ctx->tbl_buf) {
		WD_ERR("%s() reserve memory fail!\n", __func__);
		return NULL;
	}
	for (i = 0; i < WCRYPTO_EC_CTX_MSG_NUM; i++) {
		ctx->caches[i].msg.alg_type = WD_EC;
		ctx->caches[i].msg.ec_type = setup->ec_type;
		ctx->caches[i].msg.data_fmt = setup->data_fmt;
		ctx->caches[i].msg.result = WCRYPTO_EC_INVALID_FLAG;
		ctx->caches[i].tag.wcrypto_tag.ctx = ctx;
		ctx->caches[i].tag.wcrypto_tag.ctx_id = ctx_id;
		if (alloc_tbl_mem(ctx->tbl_buf + i * RDE_TLB_MEMSIZE,
			ctx->q, &ctx->caches[i].table))
			return NULL;
		ctx->caches[i].tag.tbl_addr = (__u64)&ctx->caches[i].table;
		ctx->caches[i].msg.usr_data = (__u64)&ctx->caches[i].tag;
	}

	return ctx;
}

static void fill_ec_msg(struct wcrypto_ec_ctx *ctx,
	struct wcrypto_ec_msg *msg,
	struct wcrypto_ec_op_data *opdata)
{
	msg->alg_blk_size = opdata->alg_blk_size;
	msg->block_num = opdata->block_num;
	msg->block_size = opdata->block_size;
	msg->coef_matrix = opdata->coef_matrix;
	msg->coef_matrix_len = opdata->coef_matrix_len;
	msg->coef_matrix_load = opdata->coef_matrix_load;
	msg->in = opdata->in;
	msg->in_disk_num = opdata->in_disk_num;
	msg->out = opdata->out;
	msg->out_disk_num = opdata->out_disk_num;
	msg->op_type = opdata->op_type;
	msg->result = WCRYPTO_EC_INVALID_FLAG;
	msg->cid = ctx->ctx_id;
}

int wcrypto_do_ec(void *ctx, struct wcrypto_ec_op_data *opdata, void *tag)
{
	struct wcrypto_ec_ctx *cctx;
	struct wcrypto_ec_msg *msg, *resp;
	struct wcrypto_ec_cache *cache;
	__u64 recv_count = 0;
	int ret = -WD_EINVAL;

	if (!ctx || !opdata) {
		WD_ERR("%s(): input param err!\n", __func__);
		return -WD_EINVAL;
	}

	cctx = ctx;
	cache = get_ec_cache(cctx);
	if (!cache)
		return -WD_EBUSY;
	if (tag) {
		if (!cctx->cb) {
			WD_ERR("%s() ctx callback is null!\n", __func__);
			goto cache_fail;
		}
		cache->tag.wcrypto_tag.tag = tag;
	}

	if (opdata->priv)
		cache->tag.priv_data = (__u64)opdata->priv;
	else
		cache->tag.priv_data = 0;

	msg = &cache->msg;
	fill_ec_msg(cctx, msg, opdata);
	ret = wd_send(cctx->q, msg);
	if (ret) {
		WD_ERR("%s():wd_send fail!(ret:%d)\n", __func__, ret);
		goto cache_fail;
	}

	if (tag)
		return ret;

	resp = (void *)(uintptr_t)cctx->ctx_id;
recv_again:
	ret = wd_recv(cctx->q, (void **)&resp);
	if (ret == -WD_HW_EACCESS || ret == -EIO) {
		WD_ERR("%s():wd_recv fail!(ret:%d)\n", __func__, ret);
		goto cache_fail;
	} else if (ret == 0) {
		if (++recv_count > WCRYPTO_EC_MAX_RETRY_CNT) {
			WD_ERR("%s():wd_recv timeout!\n", __func__);
			ret = -WD_ETIMEDOUT;
			goto cache_fail;
		}
		goto recv_again;
	}

	opdata->status = resp->result;
	ret = WD_SUCCESS;

cache_fail:
	put_ec_cache(cctx, cache);
	return ret;
}

int wcrypto_ec_poll(struct wd_queue *q, int num)
{
	struct wcrypto_ec_ctx *ctx;
	struct wcrypto_ec_msg *resp = NULL;
	struct wcrypto_ec_tag *tag;
	int count = 0;
	int ret;

	if (!q || num <= 0) {
		WD_ERR("%s(): input param err!\n", __func__);
		return -WD_EINVAL;
	}

	do {
		ret = wd_recv(q, (void **)&resp);
		if (ret == -WD_HW_EACCESS) {
			if (!resp) {
				WD_ERR("%s(): poll from req_chche end!\n",
					__func__);
				break;
			}
			resp->result = WD_HW_EACCESS;
		} else if (ret == -EIO) {
			WD_ERR("%s():io err!\n", __func__);
			break;
		} else if (ret == 0)
			break;
		if (resp) {
			tag = (void *)resp->usr_data;
			ctx = tag->wcrypto_tag.ctx;
			ctx->cb(resp, tag->wcrypto_tag.tag);
			put_ec_cache(ctx, (struct wcrypto_ec_cache *)tag);
			resp = NULL;
			count++;
		}

	} while (--num);

	return ((ret == 0) ? count : ret);
}

void wcrypto_del_ec_ctx(void *ctx)
{
	struct q_info *qinfo;
	struct wcrypto_ec_ctx *cctx;

	if (!ctx) {
		WD_ERR("%s(): input param err!\n", __func__);
		return;
	}

	cctx = ctx;
	qinfo = cctx->q->info;
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	if (qinfo->ctx_num < 0) {
		WD_ERR("%s(): repeat del comp ctx!\n", __func__);
		wd_unspinlock(&qinfo->qlock);
		return;
	}
	wd_unspinlock(&qinfo->qlock);

	free(cctx);
}

