// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2021 Linaro ltd.
 */

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "drv/wd_comp_drv.h"
#include "wd_comp.h"

#define WD_POOL_MAX_ENTRIES		1024
#define HW_CTX_SIZE			(64 * 1024)
#define STREAM_CHUNK			(128 * 1024)

#define swap_byte(x) \
	((((x) & 0x000000ff) << 24) | \
	(((x) & 0x0000ff00) <<  8) | \
	(((x) & 0x00ff0000) >>  8) | \
	(((x) & 0xff000000) >> 24))

#define cpu_to_be32(x) swap_byte(x)

static char *wd_comp_alg_name[WD_COMP_ALG_MAX] = {
	"zlib", "gzip", "deflate", "lz77_zstd"
};

struct wd_comp_sess {
	enum wd_comp_alg_type alg_type;
	enum wd_comp_level comp_lv;
	enum wd_comp_winsz_type win_sz;
	enum wd_comp_strm_pos stream_pos;
	__u32 isize;
	__u32 checksum;
	__u8 *ctx_buf;
	void *sched_key;
};

struct wd_comp_setting {
	enum wd_status status;
	struct wd_ctx_config_internal config;
	struct wd_sched sched;
	struct wd_async_msg_pool pool;
	struct wd_alg_driver *driver;
	void *priv;
	void *dlhandle;
	void *dlh_list;
} wd_comp_setting;

struct wd_env_config wd_comp_env_config;
static struct wd_init_attrs wd_comp_init_attrs;

static void wd_comp_close_driver(void)
{
	if (wd_comp_setting.dlhandle) {
		wd_release_drv(wd_comp_setting.driver);
		dlclose(wd_comp_setting.dlhandle);
		wd_comp_setting.dlhandle = NULL;
	}
}

static int wd_comp_open_driver(void)
{
	struct wd_alg_driver *driver = NULL;
	char lib_path[PATH_MAX];
	const char *alg_name = "zlib";
	int ret;

	ret = wd_get_lib_file_path("libhisi_zip.so", lib_path, false);
	if (ret)
		return ret;

	wd_comp_setting.dlhandle = dlopen(lib_path, RTLD_NOW);
	if (!wd_comp_setting.dlhandle) {
		WD_ERR("failed to open libhisi_zip.so, %s\n", dlerror());
		return -WD_EINVAL;
	}

	driver = wd_request_drv(alg_name, false);
	if (!driver) {
		wd_comp_close_driver();
		WD_ERR("failed to get %s driver support\n", alg_name);
		return -WD_EINVAL;
	}

	wd_comp_setting.driver = driver;

	return 0;
}

static void wd_comp_clear_status(void)
{
	wd_alg_clear_init(&wd_comp_setting.status);
}

static bool wd_comp_alg_check(const char *alg_name)
{
	int i;

	for (i = 0; i < WD_COMP_ALG_MAX; i++) {
		/* Some algorithms do not support all modes */
		if (!wd_comp_alg_name[i] || !strlen(wd_comp_alg_name[i]))
			continue;
		if (!strcmp(alg_name, wd_comp_alg_name[i]))
			return true;
	}

	return false;
}

static int wd_comp_init_nolock(struct wd_ctx_config *config, struct wd_sched *sched)
{
	int ret;

	ret = wd_set_epoll_en("WD_COMP_EPOLL_EN",
			      &wd_comp_setting.config.epoll_en);
	if (ret < 0)
		return ret;

	ret = wd_init_ctx_config(&wd_comp_setting.config, config);
	if (ret < 0)
		return ret;

	ret = wd_init_sched(&wd_comp_setting.sched, sched);
	if (ret < 0)
		goto out_clear_ctx_config;

	/* fix me: sadly find we allocate async pool for every ctx */
	ret = wd_init_async_request_pool(&wd_comp_setting.pool,
					 config->ctx_num, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_comp_msg));
	if (ret < 0)
		goto out_clear_sched;

	ret = wd_alg_init_driver(&wd_comp_setting.config,
					wd_comp_setting.driver,
					&wd_comp_setting.priv);
	if (ret)
		goto out_clear_pool;

	return 0;

out_clear_pool:
	wd_uninit_async_request_pool(&wd_comp_setting.pool);
out_clear_sched:
	wd_clear_sched(&wd_comp_setting.sched);
out_clear_ctx_config:
	wd_clear_ctx_config(&wd_comp_setting.config);
	return ret;
}

static int wd_comp_uninit_nolock(void)
{
	void *priv = wd_comp_setting.priv;

	if (!priv)
		return -WD_EINVAL;

	/* Uninit async request pool */
	wd_uninit_async_request_pool(&wd_comp_setting.pool);

	/* Unset config, sched, driver */
	wd_clear_sched(&wd_comp_setting.sched);

	wd_alg_uninit_driver(&wd_comp_setting.config,
		 wd_comp_setting.driver, &priv);

	return 0;
}

int wd_comp_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	bool flag;
	int ret;

	pthread_atfork(NULL, NULL, wd_comp_clear_status);

	flag = wd_alg_try_init(&wd_comp_setting.status);
	if (!flag)
		return -WD_EEXIST;

	ret = wd_init_param_check(config, sched);
	if (ret)
		goto out_clear_init;

	ret = wd_comp_open_driver();
	if (ret)
		goto out_clear_init;

	ret = wd_comp_init_nolock(config, sched);
	if (ret)
		goto out_clear_driver;

	wd_alg_set_init(&wd_comp_setting.status);

	return 0;

out_clear_driver:
	wd_comp_close_driver();
out_clear_init:
	wd_alg_clear_init(&wd_comp_setting.status);
	return ret;
}

void wd_comp_uninit(void)
{
	int ret;

	ret = wd_comp_uninit_nolock();
	if (ret)
		return;

	wd_comp_close_driver();
	wd_alg_clear_init(&wd_comp_setting.status);
}

int wd_comp_init2_(char *alg, __u32 sched_type, int task_type, struct wd_ctx_params *ctx_params)
{
	struct wd_ctx_nums comp_ctx_num[WD_DIR_MAX] = {0};
	struct wd_ctx_params comp_ctx_params;
	int ret = -WD_EINVAL;
	bool flag;

	pthread_atfork(NULL, NULL, wd_comp_clear_status);

	flag = wd_alg_try_init(&wd_comp_setting.status);
	if (!flag)
		return -WD_EEXIST;

	if (!alg || sched_type >= SCHED_POLICY_BUTT ||
	    task_type < 0 || task_type >= TASK_MAX_TYPE) {
		WD_ERR("invalid: input param is wrong!\n");
		goto out_uninit;
	}

	flag = wd_comp_alg_check(alg);
	if (!flag) {
		WD_ERR("invalid: comp:%s unsupported!\n", alg);
		goto out_uninit;
	}

	/*
	 * Driver lib file path could set by env param.
	 * then open tham by wd_dlopen_drv()
	 * use NULL means dynamic query path
	 */
	wd_comp_setting.dlh_list = wd_dlopen_drv(NULL);
	if (!wd_comp_setting.dlh_list) {
		WD_ERR("fail to open driver lib files.\n");
		goto out_uninit;
	}

	while (ret != 0) {
		memset(&wd_comp_setting.config, 0, sizeof(struct wd_ctx_config_internal));

		/* Get alg driver and dev name */
		wd_comp_setting.driver = wd_alg_drv_bind(task_type, alg);
		if (!wd_comp_setting.driver) {
			WD_ERR("failed to bind %s driver.\n", alg);
			goto out_dlclose;
		}

		comp_ctx_params.ctx_set_num = comp_ctx_num;
		ret = wd_ctx_param_init(&comp_ctx_params, ctx_params,
					wd_comp_setting.driver, WD_COMP_TYPE, WD_DIR_MAX);
		if (ret) {
			if (ret == -WD_EAGAIN) {
				wd_disable_drv(wd_comp_setting.driver);
				wd_alg_drv_unbind(wd_comp_setting.driver);
				continue;
			}
			goto out_unbind_drv;
		}

		wd_comp_init_attrs.alg = alg;
		wd_comp_init_attrs.sched_type = sched_type;
		wd_comp_init_attrs.driver = wd_comp_setting.driver;
		wd_comp_init_attrs.ctx_params = &comp_ctx_params;
		wd_comp_init_attrs.alg_init = wd_comp_init_nolock;
		wd_comp_init_attrs.alg_poll_ctx = wd_comp_poll_ctx;
		ret = wd_alg_attrs_init(&wd_comp_init_attrs);
		if (ret) {
			if (ret == -WD_ENODEV) {
				wd_disable_drv(wd_comp_setting.driver);
				wd_alg_drv_unbind(wd_comp_setting.driver);
				wd_ctx_param_uninit(&comp_ctx_params);
				continue;
			}
			WD_ERR("fail to init alg attrs.\n");
			goto out_params_uninit;
		}
	}

	wd_alg_set_init(&wd_comp_setting.status);
	wd_ctx_param_uninit(&comp_ctx_params);

	return 0;

out_params_uninit:
	wd_ctx_param_uninit(&comp_ctx_params);
out_unbind_drv:
	wd_alg_drv_unbind(wd_comp_setting.driver);
out_dlclose:
	wd_dlclose_drv(wd_comp_setting.dlh_list);
out_uninit:
	wd_alg_clear_init(&wd_comp_setting.status);
	return ret;
}

void wd_comp_uninit2(void)
{
	int ret;

	ret = wd_comp_uninit_nolock();
	if (ret)
		return;

	wd_alg_attrs_uninit(&wd_comp_init_attrs);
	wd_alg_drv_unbind(wd_comp_setting.driver);
	wd_dlclose_drv(wd_comp_setting.dlh_list);
	wd_comp_setting.dlh_list = NULL;
	wd_alg_clear_init(&wd_comp_setting.status);
}

struct wd_comp_msg *wd_comp_get_msg(__u32 idx, __u32 tag)
{
	return wd_find_msg_in_pool(&wd_comp_setting.pool, idx, tag);
}

int wd_comp_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_comp_setting.config;
	struct wd_ctx_internal *ctx;
	struct wd_comp_msg resp_msg;
	struct wd_comp_msg *msg;
	struct wd_comp_req *req;
	__u64 recv_count = 0;
	__u32 tmp = expt;
	int ret;

	if (unlikely(!count)) {
		WD_ERR("invalid: comp poll count is 0!\n");
		return -WD_EINVAL;
	}

	*count = 0;

	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (unlikely(ret))
		return ret;

	ctx = config->ctxs + idx;

	do {
		ret = wd_comp_setting.driver->recv(ctx->ctx, &resp_msg);
		if (unlikely(ret < 0)) {
			if (ret == -WD_HW_EACCESS)
				WD_ERR("wd comp recv hw error!\n");
			return ret;
		}

		recv_count++;

		msg = wd_find_msg_in_pool(&wd_comp_setting.pool, idx,
					  resp_msg.tag);
		if (unlikely(!msg)) {
			WD_ERR("failed to get msg from pool!\n");
			return -WD_EINVAL;
		}

		req = &msg->req;
		req->src_len = msg->in_cons;
		req->dst_len = msg->produced;
		req->cb(req, req->cb_param);

		/* free msg cache to msg_pool */
		wd_put_msg_to_pool(&wd_comp_setting.pool, idx, resp_msg.tag);
		*count = recv_count;
	} while (--tmp);

	return ret;
}

static int wd_comp_check_sess_params(struct wd_comp_sess_setup *setup)
{
	if (setup->alg_type >= WD_COMP_ALG_MAX)  {
		WD_ERR("invalid: alg_type is %d!\n", setup->alg_type);
		return -WD_EINVAL;
	}

	if (setup->op_type >= WD_DIR_MAX)  {
		WD_ERR("invalid: op_type is %d!\n", setup->op_type);
		return -WD_EINVAL;
	}

	if (setup->op_type == WD_DIR_DECOMPRESS)
		return WD_SUCCESS;

	if (setup->comp_lv > WD_COMP_L15) {
		WD_ERR("invalid: comp_lv is %d!\n", setup->comp_lv);
		return -WD_EINVAL;
	}

	if (setup->win_sz > WD_COMP_WS_32K) {
		WD_ERR("invalid: win_sz is %d!\n", setup->win_sz);
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

handle_t wd_comp_alloc_sess(struct wd_comp_sess_setup *setup)
{
	struct wd_comp_sess *sess;
	int ret;

	if (!setup)
		return (handle_t)0;

	ret = wd_comp_check_sess_params(setup);
	if (ret)
		return (handle_t)0;

	sess = calloc(1, sizeof(struct wd_comp_sess));
	if (!sess)
		return (handle_t)0;

	sess->ctx_buf = calloc(1, HW_CTX_SIZE);
	if (!sess->ctx_buf)
		goto sess_err;

	sess->alg_type = setup->alg_type;
	sess->comp_lv = setup->comp_lv;
	sess->win_sz = setup->win_sz;
	sess->stream_pos = WD_COMP_STREAM_NEW;

	/* Some simple scheduler don't need scheduling parameters */
	sess->sched_key = (void *)wd_comp_setting.sched.sched_init(
		     wd_comp_setting.sched.h_sched_ctx, setup->sched_param);
	if (WD_IS_ERR(sess->sched_key)) {
		WD_ERR("failed to init session schedule key!\n");
		goto sched_err;
	}

	return (handle_t)sess;

sched_err:
	free(sess->ctx_buf);
sess_err:
	free(sess);
	return (handle_t)0;
}

void wd_comp_free_sess(handle_t h_sess)
{
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;

	if (!sess)
		return;

	if (sess->ctx_buf)
		free(sess->ctx_buf);

	if (sess->sched_key)
		free(sess->sched_key);

	free(sess);
}

int wd_comp_reset_sess(handle_t h_sess)
{
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;

	if (!sess) {
		WD_ERR("invalid: sess is NULL!\n");
		return -WD_EINVAL;
	}

	sess->stream_pos = WD_COMP_STREAM_NEW;
	memset(sess->ctx_buf, 0, HW_CTX_SIZE);

	return 0;
}

static void fill_comp_msg(struct wd_comp_sess *sess, struct wd_comp_msg *msg,
			  struct wd_comp_req *req)
{
	memcpy(&msg->req, req, sizeof(struct wd_comp_req));

	msg->alg_type = sess->alg_type;
	msg->comp_lv = sess->comp_lv;
	msg->win_sz = sess->win_sz;
	msg->avail_out = req->dst_len;

	/* if is last 1: flush end; other: sync flush */
	msg->req.last = 1;
}

static int wd_comp_check_buffer(struct wd_comp_req *req)
{
	if (req->data_fmt == WD_FLAT_BUF) {
		if (unlikely(!req->src || !req->dst)) {
			WD_ERR("invalid: src or dst is NULL!\n");
			return -WD_EINVAL;
		}
	} else if (req->data_fmt == WD_SGL_BUF) {
		if (unlikely(!req->list_src || !req->list_dst)) {
			WD_ERR("invalid: list_src or list_dst is NULL!\n");
			return -WD_EINVAL;
		}
	}

	if (!req->dst_len) {
		WD_ERR("invalid: dst_len is NULL!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int wd_comp_check_params(struct wd_comp_sess *sess,
				struct wd_comp_req *req,
				__u8 mode)
{
	int ret;

	if (unlikely(!sess || !req)) {
		WD_ERR("invalid: sess or req is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(req->data_fmt > WD_SGL_BUF)) {
		WD_ERR("invalid: data_fmt is %d!\n", req->data_fmt);
		return -WD_EINVAL;
	}

	ret = wd_comp_check_buffer(req);
	if (unlikely(ret))
		return ret;

	if (unlikely(req->op_type != WD_DIR_COMPRESS &&
		     req->op_type != WD_DIR_DECOMPRESS)) {
		WD_ERR("invalid: op_type is %d!\n", req->op_type);
		return -WD_EINVAL;
	}

	if (unlikely(mode == CTX_MODE_ASYNC && !req->cb)) {
		WD_ERR("invalid: async comp cb is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(mode == CTX_MODE_ASYNC && !req->cb_param)) {
		WD_ERR("invalid: async comp cb param is NULL!\n");
		return -WD_EINVAL;
	}

	if (unlikely(mode == CTX_MODE_SYNC && req->cb)) {
		WD_ERR("invalid: sync comp cb should be NULL!\n");
		return -WD_EINVAL;
	}

	return 0;
}

static int wd_comp_sync_job(struct wd_comp_sess *sess,
			    struct wd_comp_req *req,
			    struct wd_comp_msg *msg)
{
	struct wd_ctx_config_internal *config = &wd_comp_setting.config;
	handle_t h_sched_ctx = wd_comp_setting.sched.h_sched_ctx;
	struct wd_msg_handle msg_handle;
	struct wd_ctx_internal *ctx;
	__u32 idx;
	int ret;

	idx = wd_comp_setting.sched.pick_next_ctx(h_sched_ctx,
						  sess->sched_key,
						  CTX_MODE_SYNC);
	ret = wd_check_ctx(config, CTX_MODE_SYNC, idx);
	if (unlikely(ret))
		return ret;

	wd_dfx_msg_cnt(config, WD_CTX_CNT_NUM, idx);
	ctx = config->ctxs + idx;

	msg_handle.send = wd_comp_setting.driver->send;
	msg_handle.recv = wd_comp_setting.driver->recv;

	pthread_spin_lock(&ctx->lock);
	ret = wd_handle_msg_sync(&msg_handle, ctx->ctx, msg,
				 NULL, config->epoll_en);
	pthread_spin_unlock(&ctx->lock);

	return ret;
}

int wd_do_comp_sync(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	struct wd_comp_msg msg;
	int ret;

	ret = wd_comp_check_params(sess, req, CTX_MODE_SYNC);
	if (unlikely(ret))
		return ret;

	if (unlikely(!req->src_len)) {
		WD_ERR("invalid: req src_len is 0!\n");
		return -WD_EINVAL;
	}

	memset(&msg, 0, sizeof(struct wd_comp_msg));

	fill_comp_msg(sess, &msg, req);
	msg.ctx_buf = sess->ctx_buf;
	msg.stream_mode = WD_COMP_STATELESS;

	ret = wd_comp_sync_job(sess, req, &msg);
	if (unlikely(ret))
		return ret;

	req->src_len = msg.in_cons;
	req->dst_len = msg.produced;
	req->status = msg.req.status;

	return 0;
}

int wd_do_comp_sync2(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	struct wd_comp_req strm_req;
	__u32 chunk = STREAM_CHUNK;
	__u32 total_avail_in;
	__u32 total_avail_out;
	int ret;

	ret = wd_comp_check_params(sess, req, CTX_MODE_SYNC);
	if (unlikely(ret))
		return ret;

	if (unlikely(!req->src_len)) {
		WD_ERR("invalid: req src_len is 0!\n");
		return -WD_EINVAL;
	}

	total_avail_in = req->src_len;
	total_avail_out = req->dst_len;
	/* strm_req and req share the same src and dst buffer */
	memcpy(&strm_req, req, sizeof(struct wd_comp_req));
	req->dst_len = 0;
	strm_req.last = 0;

	do {
		strm_req.src_len = total_avail_in > chunk ? chunk :
				   total_avail_in;
		strm_req.dst_len = total_avail_out > chunk ? chunk :
				   total_avail_out;
		if (req->op_type == WD_DIR_COMPRESS) {
			/* find the last chunk to compress */
			if (total_avail_in <= chunk)
				strm_req.last = 1;
		}

		ret = wd_do_comp_strm(h_sess, &strm_req);
		if (unlikely(ret < 0 || strm_req.status == WD_IN_EPARA)) {
			WD_ERR("wd comp, invalid or incomplete data! ret = %d, status = %u!\n",
			       ret, strm_req.status);
			return ret;
		}

		req->dst_len += strm_req.dst_len;
		strm_req.dst += strm_req.dst_len;
		total_avail_out -= strm_req.dst_len;

		strm_req.src += strm_req.src_len;
		total_avail_in -= strm_req.src_len;

		/*
		 * When a stream request end, 'stream_pos' will be reset as
		 * 'WD_COMP_STREAM_NEW' in wd_do_comp_strm.
		 */
	} while (sess->stream_pos != WD_COMP_STREAM_NEW);

	req->status = 0;

	return 0;
}

static unsigned int bit_reverse(register unsigned int target)
{
	register unsigned int x = target;

	x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
	x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
	x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
	x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));

	return ((x >> 16) | (x << 16));
}

/**
 * append_store_block() - output an fixed store block when input
 * a empty block as last stream block. And supplement the packet
 * tail according to the protocol.
 * @sess:	The session which request will be sent to.
 * @req:	The last request which is empty.
 */
static int append_store_block(struct wd_comp_sess *sess,
			      struct wd_comp_req *req)
{
	unsigned char store_block[5] = {0x1, 0x00, 0x00, 0xff, 0xff};
	int blocksize = ARRAY_SIZE(store_block);
	__u32 checksum = sess->checksum;
	__u32 isize = sess->isize;

	if (sess->alg_type == WD_ZLIB) {
		if (unlikely(req->dst_len < blocksize + sizeof(checksum)))
			return -WD_EINVAL;
		memcpy(req->dst, store_block, blocksize);
		req->dst_len = blocksize;
		checksum = (__u32) cpu_to_be32(checksum);
		 /* if zlib, ADLER32 */
		memcpy(req->dst + blocksize, &checksum, sizeof(checksum));
		req->dst_len += sizeof(checksum);
	} else if (sess->alg_type == WD_GZIP) {
		if (unlikely(req->dst_len < blocksize +
		    sizeof(checksum) + sizeof(isize)))
			return -WD_EINVAL;
		memcpy(req->dst, store_block, blocksize);
		req->dst_len = blocksize;
		checksum = ~checksum;
		checksum = bit_reverse(checksum);
		/* if gzip, CRC32 and ISIZE */
		memcpy(req->dst + blocksize, &checksum, sizeof(checksum));
		memcpy(req->dst + blocksize + sizeof(checksum),
		       &isize, sizeof(isize));
		req->dst_len += sizeof(checksum);
		req->dst_len += sizeof(isize);
	}

	req->status = 0;
	sess->stream_pos = WD_COMP_STREAM_NEW;

	return 0;
}

static void wd_do_comp_strm_end_check(struct wd_comp_sess *sess,
				      struct wd_comp_req *req,
				      __u32 src_len)
{
	if (req->op_type == WD_DIR_COMPRESS && req->last == 1 &&
	    req->src_len == src_len)
		sess->stream_pos = WD_COMP_STREAM_NEW;
	else if (req->op_type == WD_DIR_DECOMPRESS &&
		 req->status == WD_STREAM_END)
		sess->stream_pos = WD_COMP_STREAM_NEW;
}

int wd_do_comp_strm(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	struct wd_comp_msg msg;
	__u32 src_len;
	int ret;

	ret = wd_comp_check_params(sess, req, CTX_MODE_SYNC);
	if (unlikely(ret))
		return ret;

	if (unlikely(req->data_fmt > WD_FLAT_BUF)) {
		WD_ERR("invalid: data_fmt is %d!\n", req->data_fmt);
		return -WD_EINVAL;
	}

	if (sess->alg_type <= WD_GZIP && req->op_type == WD_DIR_COMPRESS &&
	    req->last == 1 && req->src_len == 0)
		return append_store_block(sess, req);

	fill_comp_msg(sess, &msg, req);
	msg.stream_pos = sess->stream_pos;
	msg.ctx_buf = sess->ctx_buf;
	msg.isize = sess->isize;
	msg.checksum = sess->checksum;
	/* fill true flag */
	msg.req.last = req->last;
	msg.stream_mode = WD_COMP_STATEFUL;

	src_len = req->src_len;

	ret = wd_comp_sync_job(sess, req, &msg);
	if (unlikely(ret))
		return ret;

	req->src_len = msg.in_cons;
	req->dst_len = msg.produced;
	req->status = msg.req.status;
	sess->isize = msg.isize;
	sess->checksum = msg.checksum;

	sess->stream_pos = WD_COMP_STREAM_OLD;

	wd_do_comp_strm_end_check(sess, req, src_len);

	return 0;
}

int wd_do_comp_async(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_ctx_config_internal *config = &wd_comp_setting.config;
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	handle_t h_sched_ctx = wd_comp_setting.sched.h_sched_ctx;
	struct wd_ctx_internal *ctx;
	struct wd_comp_msg *msg;
	int tag, ret;
	__u32 idx;

	ret = wd_comp_check_params(sess, req, CTX_MODE_ASYNC);
	if (unlikely(ret))
		return ret;

	if (unlikely(!req->src_len)) {
		WD_ERR("invalid: req src_len is 0!\n");
		return -WD_EINVAL;
	}

	idx = wd_comp_setting.sched.pick_next_ctx(h_sched_ctx,
						  sess->sched_key,
						  CTX_MODE_ASYNC);
	ret = wd_check_ctx(config, CTX_MODE_ASYNC, idx);
	if (unlikely(ret))
		return ret;

	ctx = config->ctxs + idx;

	tag = wd_get_msg_from_pool(&wd_comp_setting.pool, idx, (void **)&msg);
	if (unlikely(tag < 0)) {
		WD_ERR("failed to get msg from pool!\n");
		return -WD_EBUSY;
	}
	fill_comp_msg(sess, msg, req);
	msg->tag = tag;
	msg->stream_mode = WD_COMP_STATELESS;

	ret = wd_comp_setting.driver->send(ctx->ctx, msg);
	if (unlikely(ret < 0)) {
		WD_ERR("wd comp send error, ret = %d!\n", ret);
		goto fail_with_msg;
	}

	wd_dfx_msg_cnt(config, WD_CTX_CNT_NUM, idx);
	ret = wd_add_task_to_async_queue(&wd_comp_env_config, idx);
	if (unlikely(ret))
		goto fail_with_msg;

	return 0;

fail_with_msg:
	wd_put_msg_to_pool(&wd_comp_setting.pool, idx, msg->tag);

	return ret;
}

int wd_comp_poll(__u32 expt, __u32 *count)
{
	handle_t h_sched_ctx;
	struct wd_sched *sched;

	if (unlikely(!count)) {
		WD_ERR("invalid: comp poll count is NULL!\n");
		return -WD_EINVAL;
	}

	h_sched_ctx = wd_comp_setting.sched.h_sched_ctx;
	sched = &wd_comp_setting.sched;

	return sched->poll_policy(h_sched_ctx, expt, count);
}

static const struct wd_config_variable table[] = {
	{ .name = "WD_COMP_CTX_NUM",
	  .def_val = "sync-comp:1@0,sync-decomp:1@0,async-comp:1@0,async-decomp:1@0",
	  .parse_fn = wd_parse_ctx_num
	},
	{ .name = "WD_COMP_ASYNC_POLL_EN",
	  .def_val = "0",
	  .parse_fn = wd_parse_async_poll_en
	},
	{ .name = "WD_COMP_ASYNC_POLL_NUM",
	  .def_val = "1@0",
	  .parse_fn = wd_parse_async_poll_num
	}
};

static const struct wd_alg_ops wd_comp_ops = {
	.alg_name = "zlib",
	.op_type_num = 2,
	.alg_init = wd_comp_init,
	.alg_uninit = wd_comp_uninit,
	.alg_poll_ctx = wd_comp_poll_ctx
};

int wd_comp_env_init(struct wd_sched *sched)
{
	wd_comp_env_config.sched = sched;

	return wd_alg_env_init(&wd_comp_env_config, table,
			       &wd_comp_ops, ARRAY_SIZE(table), NULL);
}

void wd_comp_env_uninit(void)
{
	wd_alg_env_uninit(&wd_comp_env_config, &wd_comp_ops);
}

int wd_comp_ctx_num_init(__u32 node, __u32 type, __u32 num, __u8 mode)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	if (type >= WD_DIR_MAX) {
		WD_ERR("invalid: op_type is %u!\n", type);
		return -WD_EINVAL;
	}

	ret = wd_set_ctx_attr(&ctx_attr, node, type, mode, num);
	if (ret)
		return ret;

	return wd_alg_env_init(&wd_comp_env_config, table,
			       &wd_comp_ops, ARRAY_SIZE(table), &ctx_attr);
}

void wd_comp_ctx_num_uninit(void)
{
	wd_alg_env_uninit(&wd_comp_env_config, &wd_comp_ops);
}

int wd_comp_get_env_param(__u32 node, __u32 type, __u32 mode,
			  __u32 *num, __u8 *is_enable)
{
	struct wd_ctx_attr ctx_attr;
	int ret;

	if (!num || !is_enable) {
		WD_ERR("invalid: num or is_enable is NULL!\n");
		return -WD_EINVAL;
	}

	if (type >= WD_DIR_MAX) {
		WD_ERR("invalid: op_type is %u!\n", type);
		return -WD_EINVAL;
	}

	ret = wd_set_ctx_attr(&ctx_attr, node, type, mode, 0);
	if (ret)
		return ret;

	return wd_alg_get_env_param(&wd_comp_env_config,
				    ctx_attr, num, is_enable);
}
