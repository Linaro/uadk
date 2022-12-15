// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2022 Huawei Technologies Co.,Ltd. All rights reserved.
 */

/* ===   Dependencies   === */
#define _GNU_SOURCE

#include <errno.h>
#include <math.h>
#include <numa.h>
#include <stdlib.h>
#include <stdio.h>

#include "wd.h"
#include "wd_comp.h"
#include "wd_sched.h"
#include "wd_util.h"
#include "wd_zlibwrapper.h"
#include "drv/wd_comp_drv.h"

#define max(a, b)		((a) > (b) ? (a) : (b))

enum uadk_init_status {
	WD_ZLIB_UNINIT,
	WD_ZLIB_INIT,
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

static int wd_zlib_init(void)
{
	struct wd_ctx_nums *ctx_set_num;
	struct wd_ctx_params cparams;
	int ret, i;

	if (zlib_config.status == WD_ZLIB_INIT)
		return 0;

	ctx_set_num = calloc(WD_DIR_MAX, sizeof(*ctx_set_num));
	if (!ctx_set_num) {
		WD_ERR("failed to alloc ctx_set_size!\n");
		return -WD_ENOMEM;
	}

	cparams.op_type_num = WD_DIR_MAX;
	cparams.ctx_set_num = ctx_set_num;
	cparams.bmp = numa_allocate_nodemask();
	if (!cparams.bmp) {
		WD_ERR("failed to create nodemask!\n");
		ret = -WD_ENOMEM;
		goto out_freectx;
	}

	numa_bitmask_setall(cparams.bmp);

	for (i = 0; i < WD_DIR_MAX; i++)
		ctx_set_num[i].sync_ctx_num = 2;

	ret = wd_comp_init2_("zlib", 0, 0, &cparams);
	if (ret)
		goto out_freebmp;

	zlib_config.status = WD_ZLIB_INIT;

out_freebmp:
	numa_free_nodemask(cparams.bmp);

out_freectx:
	free(ctx_set_num);

	return ret;
}

static void wd_zlib_uninit(void)
{
	wd_comp_uninit2();
	zlib_config.status = WD_ZLIB_UNINIT;
}

static int wd_zlib_analy_alg(int windowbits, int *alg, int *windowsize)
{
	static const int ZLIB_MAX_WBITS = 15;
	static const int ZLIB_MIN_WBITS = 8;
	static const int GZIP_MAX_WBITS = 31;
	static const int GZIP_MIN_WBITS = 24;
	static const int DEFLATE_MAX_WBITS = -8;
	static const int DEFLATE_MIN_WBITS = -15;
	static const int WBINS_ZLIB_4K = 12;
	static const int WBINS_GZIP_4K = 27;
	static const int WBINS_DEFLATE_4K = -12;
	int ret = Z_STREAM_ERROR;

	if ((windowbits >= ZLIB_MIN_WBITS) && (windowbits <= ZLIB_MAX_WBITS)) {
		*alg = WD_ZLIB;
		*windowsize = max(windowbits - WBINS_ZLIB_4K, WD_COMP_WS_4K);
		ret = Z_OK;
	} else if ((windowbits >= GZIP_MIN_WBITS) && (windowbits <= GZIP_MAX_WBITS)) {
		*alg = WD_GZIP;
		*windowsize = max(windowbits - WBINS_GZIP_4K, WD_COMP_WS_4K);
		ret = Z_OK;
	} else if ((windowbits >= DEFLATE_MIN_WBITS) && (windowbits <= DEFLATE_MAX_WBITS)) {
		*alg = WD_DEFLATE;
		*windowsize = max(windowbits - WBINS_DEFLATE_4K, WD_COMP_WS_4K);
		ret = Z_OK;
	}

	return ret;
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

	setup.comp_lv = level;
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

static int wd_zlib_do_request(z_streamp strm, int flush, enum wd_comp_op_type type)
{
	handle_t h_sess = strm->reserved;
	struct wd_comp_req req = {0};
	int src_len = strm->avail_in;
	int dst_len = strm->avail_out;
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
	if (unlikely(ret)) {
		WD_ERR("failed to do compress(%d)!\n", ret);
		return Z_STREAM_ERROR;
	}

	strm->avail_in = src_len - req.src_len;
	strm->avail_out = dst_len - req.dst_len;
	strm->total_in += req.src_len;
	strm->total_out += req.dst_len;

	if (flush == Z_FINISH && req.src_len == src_len)
		ret = Z_STREAM_END;

	return ret;
}

/* ===   Compression   === */
int wd_deflateInit_(z_streamp strm, int level, const char *version, int stream_size)

{
	return wd_deflateInit2_(strm, level, Z_DEFLATED, MAX_WBITS, DEF_MEM_LEVEL,
				Z_DEFAULT_STRATEGY, version, stream_size);
}

int wd_deflateInit2_(z_streamp strm, int level, int method, int windowBits,
		     int memLevel, int strategy, const char *version, int stream_size)
{
	int ret;

	pthread_atfork(NULL, NULL, wd_zlib_unlock);

	pthread_mutex_lock(&wd_zlib_mutex);
	ret = wd_zlib_init();
	if (unlikely(ret < 0))
		goto out_unlock;

	strm->total_in = 0;
	strm->total_out = 0;

	ret = wd_zlib_alloc_sess(strm, level, windowBits, WD_DIR_COMPRESS);
	if (unlikely(ret < 0))
		goto out_uninit;

	__atomic_add_fetch(&zlib_config.count, 1, __ATOMIC_RELAXED);
	pthread_mutex_unlock(&wd_zlib_mutex);

	return 0;

out_uninit:
	wd_zlib_uninit();

out_unlock:
	pthread_mutex_unlock(&wd_zlib_mutex);

	return ret;
}

int wd_deflate(z_streamp strm, int flush)
{
	return wd_zlib_do_request(strm, flush, WD_DIR_COMPRESS);
}

int wd_deflateReset(z_streamp strm)
{
	wd_comp_reset_sess((handle_t)strm->reserved);

	strm->total_in = 0;
	strm->total_out = 0;

	return Z_OK;
}

int wd_deflateEnd(z_streamp strm)
{
	int ret;

	wd_zlib_free_sess(strm);

	pthread_mutex_lock(&wd_zlib_mutex);

	ret = __atomic_sub_fetch(&zlib_config.count, 1, __ATOMIC_RELAXED);
	if (ret != 0)
		goto out_unlock;

	wd_zlib_uninit();

out_unlock:
	pthread_mutex_unlock(&wd_zlib_mutex);

	return Z_OK;
}

/* ===   Decompression   === */
int wd_inflateInit_(z_streamp strm, const char *version, int stream_size)
{
	return wd_inflateInit2_(strm, MAX_WBITS, version, stream_size);
}

int wd_inflateInit2_(z_streamp strm, int  windowBits, const char *version, int stream_size)
{
	int ret;

	pthread_atfork(NULL, NULL, wd_zlib_unlock);

	pthread_mutex_lock(&wd_zlib_mutex);
	ret = wd_zlib_init();
	if (unlikely(ret < 0))
		goto out_unlock;

	strm->total_in = 0;
	strm->total_out = 0;

	ret = wd_zlib_alloc_sess(strm, 0, windowBits, WD_DIR_DECOMPRESS);
	if (unlikely(ret < 0))
		goto out_uninit;

	__atomic_add_fetch(&zlib_config.count, 1, __ATOMIC_RELAXED);
	pthread_mutex_unlock(&wd_zlib_mutex);

	return 0;

out_uninit:
	wd_zlib_uninit();

out_unlock:
	pthread_mutex_unlock(&wd_zlib_mutex);

	return ret;
}

int wd_inflate(z_streamp strm, int flush)
{
	return wd_zlib_do_request(strm, flush, WD_DIR_DECOMPRESS);
}

int wd_inflateReset(z_streamp strm)
{
	wd_comp_reset_sess((handle_t)strm->reserved);

	strm->total_in = 0;
	strm->total_out = 0;

	return Z_OK;
}

int wd_inflateEnd(z_streamp strm)
{
	int ret;

	wd_zlib_free_sess(strm);

	pthread_mutex_lock(&wd_zlib_mutex);

	ret = __atomic_sub_fetch(&zlib_config.count, 1, __ATOMIC_RELAXED);
	if (ret != 0)
		goto out_unlock;

	wd_zlib_uninit();

out_unlock:
	pthread_mutex_unlock(&wd_zlib_mutex);

	return Z_OK;
}
