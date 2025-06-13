// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2022 Huawei Technologies Co.,Ltd. All rights reserved.
 */

/* ===   Dependencies   === */
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <numa.h>

#include "wd.h"
#include "wd_comp.h"
#include "wd_sched.h"
#include "wd_util.h"
#include "drv/wd_comp_drv.h"
#include "wd_zlibwrapper.h"

#define max(a, b)		((a) > (b) ? (a) : (b))

enum uadk_init_status {
	WD_ZLIB_UNINIT,
	WD_ZLIB_INIT,
};

enum alg_win_bits {
	DEFLATE_MIN_WBITS = -15,
	DEFLATE_4K_WBITS = 12,
	DEFLATE_MAX_WBITS = -8,
	ZLIB_MIN_WBITS = 8,
	ZLIB_4K_WBITS = 12,
	ZLIB_MAX_WBITS = 15,
	GZIP_MIN_WBITS = 24,
	GZIP_4K_WBITS = 28,
	GZIP_MAX_WBITS = 31,
};

struct wd_zlibwrapper_config {
	int count;
	int status;
};

static pthread_mutex_t wd_zlib_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct wd_zlibwrapper_config zlib_config = {0};

static void wd_zlib_unlock(void)
{
	pthread_mutex_unlock(&wd_zlib_mutex);
	zlib_config.status = WD_ZLIB_UNINIT;
}

static int wd_zlib_uadk_init(void)
{
	struct wd_ctx_params cparams = {0};
	struct wd_ctx_nums *ctx_set_num;
	int ret, i;

	if (zlib_config.status == WD_ZLIB_INIT)
		return 0;

	ctx_set_num = calloc(WD_DIR_MAX, sizeof(*ctx_set_num));
	if (!ctx_set_num) {
		WD_ERR("failed to alloc ctx_set_size!\n");
		return Z_MEM_ERROR;
	}

	cparams.op_type_num = WD_DIR_MAX;
	cparams.ctx_set_num = ctx_set_num;
	cparams.bmp = numa_allocate_nodemask();
	if (!cparams.bmp) {
		WD_ERR("failed to create nodemask!\n");
		ret = Z_MEM_ERROR;
		goto out_freectx;
	}

	numa_bitmask_setall(cparams.bmp);

	for (i = 0; i < WD_DIR_MAX; i++)
		ctx_set_num[i].sync_ctx_num = WD_DIR_MAX;

	ret = wd_comp_init2_("zlib", 0, 0, &cparams);
	if (ret && ret != -WD_EEXIST) {
		ret = Z_STREAM_ERROR;
		goto out_freebmp;
	}

	ret = 0;
	zlib_config.status = WD_ZLIB_INIT;

out_freebmp:
	numa_free_nodemask(cparams.bmp);

out_freectx:
	free(ctx_set_num);

	return ret;
}

static void wd_zlib_uadk_uninit(void)
{
	wd_comp_uninit2();
	zlib_config.status = WD_ZLIB_UNINIT;
}

static int wd_zlib_analy_alg(int windowbits, int *alg, int *windowsize)
{
	switch (windowbits) {
		case DEFLATE_MIN_WBITS ... DEFLATE_MAX_WBITS:
			*alg = WD_DEFLATE;
			windowbits = -windowbits;
			*windowsize = max(windowbits - DEFLATE_4K_WBITS, WD_COMP_WS_4K);
		case GZIP_MIN_WBITS ... GZIP_MAX_WBITS:
			*alg = WD_GZIP;
			*windowsize = max(windowbits - GZIP_4K_WBITS, WD_COMP_WS_4K);
		case ZLIB_MIN_WBITS ... ZLIB_MAX_WBITS:
			*alg = WD_ZLIB;
			*windowsize = max(windowbits - ZLIB_4K_WBITS, WD_COMP_WS_4K);
		default:
			return Z_STREAM_ERROR;
	}

	*windowsize = *windowsize == WD_COMP_WS_24K ? WD_COMP_WS_32K : *windowsize;

	return Z_OK;
}

static int wd_zlib_alloc_sess(z_streamp strm, int level, int windowbits, enum wd_comp_op_type type)
{
	struct wd_comp_sess_setup setup = {0};
	struct sched_params sparams = {0};
	int windowsize, alg, ret;
	handle_t h_sess;

	ret = wd_zlib_analy_alg(windowbits, &alg, &windowsize);
	if (ret < 0) {
		WD_ERR("invalid: windowbits is %d!\n", windowbits);
		return ret;
	}

	setup.comp_lv = level == Z_DEFAULT_COMPRESSION ? WD_COMP_L6 : level;
	setup.alg_type = alg;
	setup.win_sz = windowsize;
	setup.op_type = type;
	sparams.type = type;
	setup.sched_param = &sparams;

	h_sess = wd_comp_alloc_sess(&setup);
	if (!h_sess) {
		WD_ERR("failed to alloc comp sess!\n");
		return Z_STREAM_ERROR;
	}
	strm->reserved = (__u64)h_sess;

	return Z_OK;
}

static void wd_zlib_free_sess(z_streamp strm)
{
	wd_comp_free_sess((handle_t)strm->reserved);
}

static int wd_zlib_init(z_streamp strm, int level, int windowbits, enum wd_comp_op_type type)
{
	int ret;

	if (unlikely(!strm))
		return Z_STREAM_ERROR;

	pthread_mutex_lock(&wd_zlib_mutex);
	ret = wd_zlib_uadk_init();
	if (unlikely(ret < 0))
		goto out_unlock;

	strm->total_in = 0;
	strm->total_out = 0;

	ret = wd_zlib_alloc_sess(strm, level, windowbits, type);
	if (unlikely(ret < 0))
		goto out_uninit;

	__atomic_add_fetch(&zlib_config.count, 1, __ATOMIC_RELAXED);
	pthread_mutex_unlock(&wd_zlib_mutex);

	return Z_OK;

out_uninit:
	wd_zlib_uadk_uninit();

out_unlock:
	pthread_mutex_unlock(&wd_zlib_mutex);

	return ret;
}

static int wd_zlib_uninit(z_streamp strm)
{
	int ret;

	if (unlikely(!strm))
		return Z_STREAM_ERROR;

	wd_zlib_free_sess(strm);

	pthread_mutex_lock(&wd_zlib_mutex);

	ret = __atomic_sub_fetch(&zlib_config.count, 1, __ATOMIC_RELAXED);
	if (ret != 0)
		goto out_unlock;

	wd_zlib_uadk_uninit();

out_unlock:
	pthread_mutex_unlock(&wd_zlib_mutex);

	return Z_OK;
}

static int wd_zlib_do_request(z_streamp strm, int flush, enum wd_comp_op_type type)
{
	handle_t h_sess = strm->reserved;
	struct wd_comp_req req = {0};
	__u32 src_len = strm->avail_in;
	__u32 dst_len = strm->avail_out;
	int ret;

	if (unlikely(flush != Z_SYNC_FLUSH && flush != Z_FINISH)) {
		WD_ERR("invalid: flush is %d!\n", flush);
		return Z_STREAM_ERROR;
	}

	req.src = (void *)strm->next_in;
	req.src_len = strm->avail_in;
	req.dst = (void *)strm->next_out;
	req.dst_len = strm->avail_out;
	req.op_type = type;
	req.data_fmt = WD_FLAT_BUF;
	req.last = (flush == Z_FINISH) ? 1 : 0;

	ret = wd_do_comp_strm(h_sess, &req);
	if (unlikely(ret || req.status == WD_IN_EPARA)) {
		WD_ERR("failed to do compress, ret = %d, req.status = %u!\n", ret, req.status);
		return Z_STREAM_ERROR;
	}

	strm->avail_in = src_len - req.src_len;
	strm->avail_out = dst_len - req.dst_len;
	strm->total_in += req.src_len;
	strm->total_out += req.dst_len;
	strm->next_in += req.src_len;
	strm->next_out += req.dst_len;

	if (type == WD_DIR_COMPRESS && flush == Z_FINISH && req.src_len == src_len)
		ret = Z_STREAM_END;
	else if (type == WD_DIR_DECOMPRESS && req.status == WD_STREAM_END)
		ret = Z_STREAM_END;

	return ret;
}

/* ===   Compression   === */
int wd_deflate_init(z_streamp strm, int level, int windowbits)
{
	pthread_atfork(NULL, NULL, wd_zlib_unlock);

	return wd_zlib_init(strm, level, windowbits, WD_DIR_COMPRESS);
}

int wd_deflate(z_streamp strm, int flush)
{
	if (unlikely(!strm))
		return Z_STREAM_ERROR;

	return wd_zlib_do_request(strm, flush, WD_DIR_COMPRESS);
}

int wd_deflate_reset(z_streamp strm)
{
	if (unlikely(!strm))
		return Z_STREAM_ERROR;

	wd_comp_reset_sess((handle_t)strm->reserved);

	strm->total_in = 0;
	strm->total_out = 0;

	return Z_OK;
}

int wd_deflate_end(z_streamp strm)
{
	return wd_zlib_uninit(strm);
}

/* ===   Decompression   === */
int wd_inflate_init(z_streamp strm, int  windowbits)
{
	pthread_atfork(NULL, NULL, wd_zlib_unlock);

	return wd_zlib_init(strm, 0, windowbits, WD_DIR_DECOMPRESS);
}

int wd_inflate(z_streamp strm, int flush)
{
	if (unlikely(!strm))
		return Z_STREAM_ERROR;

	return wd_zlib_do_request(strm, flush, WD_DIR_DECOMPRESS);
}

int wd_inflate_reset(z_streamp strm)
{
	if (!strm)
		return Z_STREAM_ERROR;

	wd_comp_reset_sess((handle_t)strm->reserved);

	strm->total_in = 0;
	strm->total_out = 0;

	return Z_OK;
}

int wd_inflate_end(z_streamp strm)
{
	return wd_zlib_uninit(strm);
}
