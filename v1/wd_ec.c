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
#include "wd_ec.h"
#include "wd_util.h"

#define EC_MAX_RETRY_CNT	10000000
#define EC_INVALID_FLAG	0x7f

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
	__u8 *tbl_buf;
	struct wd_queue *q;
	struct wcrypto_ec_ctx_setup setup;
};

static void alloc_tbl_mem(__u8 *buf, __u8 *pa,
	struct wcrypto_ec_table *ec_table)
{
	ec_table->src_addr = (struct src_tbl *)buf;
	ec_table->src_addr_pa = (__u64)pa;

	ec_table->src_tag_addr =
		(struct src_tag_tbl *)(buf + sizeof(struct src_tbl));
	ec_table->src_tag_addr_pa = (__u64)(pa + sizeof(struct src_tbl));

	ec_table->dst_addr =
		(struct dst_tbl *)((__u8 *)ec_table->src_tag_addr +
		sizeof(struct src_tag_tbl));
	ec_table->dst_addr_pa =
		(__u64)((__u8 *)ec_table->src_tag_addr_pa +
		sizeof(struct src_tag_tbl));

	ec_table->dst_tag_addr =
		(struct dst_tag_tbl *)((__u8 *)ec_table->dst_addr +
		sizeof(struct dst_tbl));
	ec_table->dst_tag_addr_pa =
		(__u64)((__u8 *)ec_table->dst_addr_pa +
		sizeof(struct dst_tbl));

	ec_table->matrix = (__u8 *)ec_table->dst_tag_addr +
		sizeof(struct dst_tag_tbl);
	ec_table->matrix_pa =
		(__u64)((__u8 *)ec_table->dst_tag_addr_pa +
		sizeof(struct dst_tag_tbl));
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

static int wcrypto_check_ctx_para(struct wd_queue *q,
	struct wcrypto_ec_ctx_setup *setup)
{
	if (!q || !setup) {
		WD_ERR("%s():  input param invalid!\n", __func__);
		return -WD_EINVAL;
	}

	if (!setup->br.alloc || !setup->br.free ||
		!setup->br.iova_map || !setup->br.iova_unmap) {
		WD_ERR("%s(): wd_mm_br should not be NULL!\n", __func__);
		return -WD_EINVAL;
	}

	if (strncmp(q->capa.alg, "rde", strlen("rde"))) {
		WD_ERR("%s(): alg mismatching!\n", __func__);
		return -WD_EINVAL;
	}

	return 0;
}

void *wcrypto_create_ec_ctx(struct wd_queue *q,
	struct wcrypto_ec_ctx_setup *setup)
{
	struct q_info *qinfo;
	struct wcrypto_ec_ctx *ctx;
	int ctx_id, i;
	__u8 *pa;

	if (wcrypto_check_ctx_para(q, setup))
		return NULL;

	qinfo = q->qinfo;
	wd_spinlock(&qinfo->qlock);
	if (!qinfo->br.alloc && !qinfo->br.iova_map)
		memcpy(&qinfo->br, &setup->br, sizeof(setup->br));

	if (qinfo->br.usr != setup->br.usr) {
		wd_unspinlock(&qinfo->qlock);
		WD_ERR("%s(): config different br!\n", __func__);
		return NULL;
	}
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
	memcpy(&ctx->setup, setup, sizeof(*setup));
	ctx->q = q;
	ctx->ctx_id = ctx_id;
	ctx->tbl_buf = setup->br.alloc(setup->br.usr,
		WCRYPTO_EC_CTX_MSG_NUM * WCRYPTO_EC_TBl_SIZE);
	if (!ctx->tbl_buf) {
		WD_ERR("%s() reserve memory fail!\n", __func__);
		free(ctx);
		return NULL;
	}

	pa = setup->br.iova_map(setup->br.usr, (void *)ctx->tbl_buf,
		WCRYPTO_EC_CTX_MSG_NUM * WCRYPTO_EC_TBl_SIZE);
	if (!pa) {
		WD_ERR("%s() iova_map fail!\n", __func__);
		setup->br.free(setup->br.usr, (void *)ctx->tbl_buf);
		free(ctx);
		return NULL;
	}

	for (i = 0; i < WCRYPTO_EC_CTX_MSG_NUM; i++) {
		ctx->caches[i].msg.alg_type = WCRYPTO_EC;
		ctx->caches[i].msg.ec_type = setup->ec_type;
		ctx->caches[i].msg.data_fmt = setup->data_fmt;
		ctx->caches[i].msg.result = EC_INVALID_FLAG;
		ctx->caches[i].tag.wcrypto_tag.ctx = ctx;
		ctx->caches[i].tag.wcrypto_tag.ctx_id = ctx_id;
		alloc_tbl_mem(ctx->tbl_buf + i * WCRYPTO_EC_TBl_SIZE,
			pa + i * WCRYPTO_EC_TBl_SIZE, &ctx->caches[i].table);
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
	msg->result = EC_INVALID_FLAG;
	msg->cid = ctx->ctx_id;
}

int wcrypto_do_ec(void *ctx, struct wcrypto_ec_op_data *opdata, void *tag)
{
	struct wcrypto_ec_ctx *cctx;
	struct wcrypto_ec_msg *msg, *resp;
	struct wcrypto_ec_cache *cache;
	__u64 rx_cnt = 0;
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
		if (!cctx->setup.cb) {
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
	if (ret < 0) {
		WD_ERR("%s():wd_recv fail!(ret:%d)\n", __func__, ret);
		goto cache_fail;
	} else if (ret == 0) {
		if (++rx_cnt > EC_MAX_RETRY_CNT) {
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
		} else if (ret == -WD_EIO) {
			WD_ERR("%s():io err!\n", __func__);
			break;
		} else if (ret == 0)
			break;
		if (resp) {
			tag = (void *)resp->usr_data;
			ctx = tag->wcrypto_tag.ctx;
			ctx->setup.cb(resp, tag->wcrypto_tag.tag);
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
	struct wd_mm_br *br;

	if (!ctx) {
		WD_ERR("%s(): input param err!\n", __func__);
		return;
	}

	cctx = ctx;
	qinfo = cctx->q->qinfo;
	wd_spinlock(&qinfo->qlock);
	qinfo->ctx_num--;
	if (!qinfo->ctx_num)
		memset(&qinfo->br, 0, sizeof(qinfo->br));
	if (qinfo->ctx_num < 0) {
		WD_ERR("%s(): repeat del comp ctx!\n", __func__);
		wd_unspinlock(&qinfo->qlock);
		return;
	}
	wd_unspinlock(&qinfo->qlock);

	br = &cctx->setup.br;
	if (br && br->free)
		br->free(br->usr, (void *)cctx->tbl_buf);
	free(cctx);
}

