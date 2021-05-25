// SPDX-License-Identifier: Apache-2.0
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "drv/wd_comp_drv.h"
#include "wd_comp.h"
#include "wd_util.h"

#define WD_POOL_MAX_ENTRIES		1024
#define MAX_RETRY_COUNTS		200000000
#define HW_CTX_SIZE			(64 * 1024)
#define STREAM_CHUNK			(128 * 1024)

#define POLL_SIZE			2500000
#define POLL_TIME			1000

#define swap_byte(x) \
	((((x) & 0x000000ff) << 24) | \
	(((x) & 0x0000ff00) <<  8) | \
	(((x) & 0x00ff0000) >>  8) | \
	(((x) & 0xff000000) >> 24))

#define cpu_to_be32(x) swap_byte(x)

struct wd_comp_sess {
	int	alg_type;
	struct sched_key	key;
	__u8	*ctx_buf;
	__u8	stream_pos;
	__u32	isize;
	__u32	checksum;
};

struct wd_comp_setting {
	struct wd_ctx_config_internal config;
	struct wd_sched sched;
	struct wd_comp_driver *driver;
	void *priv;
	struct wd_async_msg_pool pool;
} wd_comp_setting;

#ifdef WD_STATIC_DRV
extern struct wd_comp_driver wd_comp_hisi_zip;
static void wd_comp_set_static_drv(void)
{
	/*
	 * Fix me: a parameter can be introduced to decide to choose
	 * specific driver. Same as dynamic case.
	 */
	wd_comp_setting.driver = &wd_comp_hisi_zip;
}
#else
static void __attribute__((constructor)) wd_comp_open_driver(void)
{
	void *driver;

	driver = dlopen("libhisi_zip.so", RTLD_NOW);
	if (!driver)
		WD_ERR("Fail to open libhisi_zip.so\n");
}
#endif

void wd_comp_set_driver(struct wd_comp_driver *drv)
{
	wd_comp_setting.driver = drv;
}

int wd_comp_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	void *priv;
	int ret;

	/* wd_comp_init() could only be invoked once for one process. */
	if (wd_comp_setting.config.ctx_num) {
		WD_ERR("invalid, comp init() should only be invokoed once!\n");
		return 0;
	}

	if (!config || !sched) {
		WD_ERR("invalid params, config or sched is NULL!\n");
		return -WD_EINVAL;
	}

	if (!wd_is_sva(config->ctxs[0].ctx)) {
		WD_ERR("err, non sva, please check system!\n");
		return -WD_EINVAL;
	}

	ret = wd_init_ctx_config(&wd_comp_setting.config, config);
	if (ret < 0) {
		WD_ERR("failed to set config, ret = %d!\n", ret);
		return ret;
	}
	ret = wd_init_sched(&wd_comp_setting.sched, sched);
	if (ret < 0) {
		WD_ERR("failed to set sched, ret = %d!\n", ret);
		goto out;
	}
	/*
	 * Fix me: ctx could be passed into wd_comp_set_static_drv to help to
	 * choose static compiled vendor driver. For dynamic vendor driver,
	 * wd_comp_open_driver will be called in the process of opening
	 * libwd_comp.so to load related driver dynamic library. Vendor driver
	 * pointer will be passed to wd_comp_setting.driver in the process of
	 * opening of vendor driver dynamic library. A configure file could be
	 * introduced to help to define which vendor driver lib should be
	 * loaded.
	 */
#ifdef WD_STATIC_DRV
	wd_comp_set_static_drv();
#endif

	/* fix me: sadly find we allocate async pool for every ctx */
	ret = wd_init_async_request_pool(&wd_comp_setting.pool,
					 config->ctx_num, WD_POOL_MAX_ENTRIES,
					 sizeof(struct wd_comp_msg));
	if (ret < 0) {
		WD_ERR("failed to init req pool, ret = %d!\n", ret);
		goto out_sched;
	}
	/* init ctx related resources in specific driver */
	priv = calloc(1, wd_comp_setting.driver->drv_ctx_size);
	if (!priv) {
		ret = -WD_ENOMEM;
		goto out_priv;
	}
	wd_comp_setting.priv = priv;
	ret = wd_comp_setting.driver->init(&wd_comp_setting.config, priv);
	if (ret < 0) {
		WD_ERR("failed to do driver init, ret = %d!\n", ret);
		goto out_init;
	}
	return 0;

out_init:
	free(priv);
out_priv:
	wd_uninit_async_request_pool(&wd_comp_setting.pool);
out_sched:
	wd_clear_sched(&wd_comp_setting.sched);
out:
	wd_clear_ctx_config(&wd_comp_setting.config);
	return ret;
}

void wd_comp_uninit(void)
{
	void *priv = wd_comp_setting.priv;

	if (!priv)
		return;

	wd_comp_setting.driver->exit(priv);
	free(priv);
	wd_comp_setting.priv = NULL;

	/* uninit async request pool */
	wd_uninit_async_request_pool(&wd_comp_setting.pool);

	/* unset config, sched, driver */
	wd_clear_sched(&wd_comp_setting.sched);
	wd_clear_ctx_config(&wd_comp_setting.config);
}

struct wd_comp_msg *wd_comp_get_msg(__u32 idx, __u32 tag)
{
	return wd_find_msg_in_pool(&wd_comp_setting.pool, idx, tag);
}

int wd_comp_poll_ctx(__u32 idx, __u32 expt, __u32 *count)
{
	struct wd_ctx_config_internal *config = &wd_comp_setting.config;
	void *priv = wd_comp_setting.priv;
	struct wd_ctx_internal *ctx;
	struct wd_comp_msg resp_msg;
	struct wd_comp_msg *msg;
	struct wd_comp_req *req;
	__u64 recv_count = 0;
	int ret;

	if (unlikely(idx >= config->ctx_num || !count)) {
		WD_ERR("comp poll input index is error or count is NULL\n");
		return -WD_EINVAL;
	}
	ctx = config->ctxs + idx;

	do {
		ret = wd_comp_setting.driver->comp_recv(ctx->ctx, &resp_msg,
							priv);
		if (ret < 0) {
			if (ret == -WD_HW_EACCESS)
				WD_ERR("wd comp recv hw err!\n");
			break;
		}

		recv_count++;

		msg = wd_find_msg_in_pool(&wd_comp_setting.pool, idx,
					  resp_msg.tag);
		if (!msg) {
			WD_ERR("get msg from pool is NULL!\n");
			break;
		}

		req = &msg->req;
		req->src_len = msg->in_cons;
		req->dst_len = msg->produced;
		if (req->cb)
			req->cb(req, req->cb_param);

		/* free msg cache to msg_pool */
		wd_put_msg_to_pool(&wd_comp_setting.pool, idx, resp_msg.tag);

	} while (--expt);

	*count = recv_count;

	return ret;
}

handle_t wd_comp_alloc_sess(struct wd_comp_sess_setup *setup)
{
	struct wd_comp_sess *sess;

	if (!setup)
		return (handle_t)0;

	sess = calloc(1, sizeof(struct wd_comp_sess));
	if (!sess)
		return (handle_t)0;

	if (setup->mode == CTX_MODE_SYNC) {
		sess->ctx_buf = calloc(1, HW_CTX_SIZE);
		if (!sess->ctx_buf) {
			free(sess);
			return (handle_t)0;
		}
	}

	sess->alg_type = setup->alg_type;
	sess->stream_pos = WD_COMP_STREAM_NEW;

	sess->key.mode = setup->mode;
	sess->key.type = setup->op_type;
	sess->key.numa_id = 0;

	return (handle_t)sess;
}

void wd_comp_free_sess(handle_t h_sess)
{
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;

	if (!sess)
		return;

	if (sess->ctx_buf)
		free(sess->ctx_buf);

	free(sess);
}

static unsigned int bit_reverse(register unsigned int x)
{
	x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
	x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
	x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
	x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));

	return((x >> 16) | (x << 16));
}

/* output an empty store block */
static int append_store_block(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	char store_block[5] = {0x1, 0x00, 0x00, 0xff, 0xff};
	__u32 checksum = sess->checksum;
	__u32 isize = sess->isize;

	memcpy(req->dst, store_block, 5);
	req->dst_len = 5;

	if (sess->alg_type == WD_ZLIB) { /*if zlib, ADLER32*/
		checksum = (__u32) cpu_to_be32(checksum);
		memcpy(req->dst + 5, &checksum, 4);
		req->dst_len += 4;
	} else if (sess->alg_type == WD_GZIP) {
		checksum = ~checksum;
		checksum = bit_reverse(checksum);
		/* if gzip, CRC32 and ISIZE */
		memcpy(req->dst + 5, &checksum, 4);
		memcpy(req->dst + 9, &isize, 4);
		req->dst_len += 8;
	} else if (sess->alg_type >= WD_COMP_ALG_MAX) {
		WD_ERR("in append store block, wrong alg type %d.\n", sess->alg_type);
		return -WD_EINVAL;
	}

	return 0;
}

static void fill_comp_msg(struct wd_comp_sess *sess, struct wd_comp_msg *msg,
			  struct wd_comp_req *req)
{
	memcpy(&msg->req, req, sizeof(struct wd_comp_req));

	msg->alg_type = sess->alg_type;
	msg->avail_out = req->dst_len;

	/* if is last 1: flush end; other: sync flush */
	msg->req.last = 1;
}

static int wd_comp_check_params(handle_t h_sess, struct wd_comp_req *req,
				__u8 mode)
{
	if (!h_sess || !req) {
		WD_ERR("invalid: sess or req is NULL!\n");
		return -WD_EINVAL;
	}

	if (mode == CTX_MODE_ASYNC && !req->cb) {
		WD_ERR("async comp input cb is NULL!\n");
		return -WD_EINVAL;
	}

	if (mode == CTX_MODE_ASYNC && !req->cb_param) {
		WD_ERR("async comp input cb param is NULL!\n");
		return -WD_EINVAL;
	}

	if (mode == CTX_MODE_SYNC && req->cb) {
		WD_ERR("sync comp input cb should be NULL!\n");
		return -WD_EINVAL;
	}

	return 0;
}

int wd_do_comp_sync(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_ctx_config_internal *config = &wd_comp_setting.config;
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	handle_t h_sched_ctx = wd_comp_setting.sched.h_sched_ctx;
	void *priv = wd_comp_setting.priv;
	struct wd_ctx_internal *ctx;
	struct wd_comp_msg msg;
	__u64 recv_count = 0;
	__u32 idx;
	int ret;

	ret = wd_comp_check_params(h_sess, req, CTX_MODE_SYNC);
	if (ret) {
		WD_ERR("fail to check params!\n");
		return ret;
	}

	if (!req->src_len) {
		WD_ERR("invalid: req src_len is 0!\n");
		return -WD_EINVAL;
	}

	if (req->data_fmt > WD_SGL_BUF) {
		WD_ERR("invalid: data_fmt is %d!\n", req->data_fmt);
		return -WD_EINVAL;
	}

	memset(&msg, 0, sizeof(struct wd_comp_msg));

	idx = wd_comp_setting.sched.pick_next_ctx(h_sched_ctx,
						  req,
						  &sess->key);
	if (idx >= config->ctx_num) {
		WD_ERR("fail to pick a proper ctx!\n");
		return -WD_EINVAL;
	}
	ctx = config->ctxs + idx;
	if (ctx->ctx_mode != CTX_MODE_SYNC) {
		WD_ERR("ctx %u mode = %hhu error!\n", idx, ctx->ctx_mode);
		return -WD_EINVAL;
	}

	fill_comp_msg(sess, &msg, req);
	msg.ctx_buf = sess->ctx_buf;
	msg.stream_mode = WD_COMP_STATELESS;

	pthread_spin_lock(&ctx->lock);

	ret = wd_comp_setting.driver->comp_send(ctx->ctx, &msg, priv);
	if (ret < 0) {
		WD_ERR("wd comp send err(%d)!\n", ret);
		goto err_out;
	}

	if (req->src_len >= POLL_SIZE) {
		ret = wd_ctx_wait(ctx->ctx, POLL_TIME);
		if (ret < 0) {
			WD_ERR("wd ctx wait fail(%d)!\n", ret);
			goto err_out;
		}
	}

	do {
		ret = wd_comp_setting.driver->comp_recv(ctx->ctx, &msg, priv);
		if (ret == -WD_HW_EACCESS) {
			WD_ERR("wd comp recv hw err!\n");
			goto err_out;
		} else if (ret == -WD_EAGAIN) {
			if (++recv_count > MAX_RETRY_COUNTS) {
				WD_ERR("wd comp recv timeout fail!\n");
				ret = -WD_ETIMEDOUT;
				goto err_out;
			}
		}
	} while (ret == -WD_EAGAIN);

	pthread_spin_unlock(&ctx->lock);

	req->src_len = msg.in_cons;
	req->dst_len = msg.produced;
	req->status = msg.req.status;

	return 0;

err_out:
	pthread_spin_unlock(&ctx->lock);
	return ret;
}

int wd_do_comp_sync2(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	struct wd_comp_req strm_req;
	__u32 chunk = STREAM_CHUNK;
	__u32 total_avail_in;
	__u32 total_avail_out;
	int ret;

	ret = wd_comp_check_params(h_sess, req, CTX_MODE_SYNC);
	if (ret) {
		WD_ERR("fail to check params!\n");
		return ret;
	}

	if (req->op_type != WD_DIR_COMPRESS &&
	    req->op_type != WD_DIR_DECOMPRESS) {
		WD_ERR("invalid: op_type is %hhu!\n", req->op_type);
		return -WD_EINVAL;
	}

	if (!req->src_len) {
		WD_ERR("invalid: req src_len is 0!\n");
		return -WD_EINVAL;
	}

	dbg("do, op_type = %hhu, in =%u, out_len =%u\n",
	    req->op_type, req->src_len, req->dst_len);

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
		dbg("do, strm start, in =%u, out_len =%u\n",
		    strm_req.src_len, strm_req.dst_len);
		ret = wd_do_comp_strm(h_sess, &strm_req);
		if (ret < 0 || strm_req.status == WD_IN_EPARA) {
			WD_ERR("wd comp, invalid or incomplete data! "
			       "ret(%d), req.status(%u)\n",
			       ret, strm_req.status);
			return ret;
		}
		req->dst_len += strm_req.dst_len;
		strm_req.dst += strm_req.dst_len;
		dbg("do, strm end, in =%u, out_len =%u\n",
		    strm_req.src_len, strm_req.dst_len);
		total_avail_out -= strm_req.dst_len;

		strm_req.src += strm_req.src_len;
		total_avail_in -= strm_req.src_len;

		/*
		 * When a stream request end, 'stream_pos' will be reset as
		 * 'WD_COMP_STREAM_NEW' in wd_do_comp_strm.
		 */
	} while (sess->stream_pos != WD_COMP_STREAM_NEW);

	if (req->op_type == WD_DIR_COMPRESS &&
	    strm_req.src_len == 0 &&
	    strm_req.last == 1) {
		dbg("append_store, src_len=%u, dst_len=%u\n",
		    req->src_len, req->dst_len);
		ret = append_store_block(h_sess, &strm_req);
		req->dst_len += strm_req.dst_len;
		req->status = 0;
		return 0;
	}

	dbg("end, in =%u, out_len =%u\n", req->src_len, req->dst_len);

	req->status = 0;

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
	struct wd_ctx_config_internal *config = &wd_comp_setting.config;
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	handle_t h_sched_ctx = wd_comp_setting.sched.h_sched_ctx;
	void *priv = wd_comp_setting.priv;
	struct wd_ctx_internal *ctx;
	struct wd_comp_msg msg;
	__u64 recv_count = 0;
	__u32 src_len;
	__u32 idx;
	int ret;

	ret = wd_comp_check_params(h_sess, req, CTX_MODE_SYNC);
	if (ret) {
		WD_ERR("fail to check params!\n");
		return ret;
	}

	if (req->data_fmt > WD_FLAT_BUF) {
		WD_ERR("invalid: data_fmt is %d!\n", req->data_fmt);
		return -WD_EINVAL;
	}

	idx = wd_comp_setting.sched.pick_next_ctx(h_sched_ctx,
						  req,
						  &sess->key);
	if (idx >= config->ctx_num) {
		WD_ERR("fail to pick a proper ctx!\n");
		return -WD_EINVAL;
	}
	ctx = config->ctxs + idx;
	if (ctx->ctx_mode != CTX_MODE_SYNC) {
		WD_ERR("ctx %u mode = %hhu error!\n", idx, ctx->ctx_mode);
		return -WD_EINVAL;
	}

	fill_comp_msg(sess, &msg, req);
	msg.stream_pos = sess->stream_pos;
	msg.ctx_buf = sess->ctx_buf;
	msg.isize = sess->isize;
	msg.checksum = sess->checksum;
	/* fill true flag */
	msg.req.last = req->last;
	msg.stream_mode = WD_COMP_STATEFUL;

	src_len = req->src_len;

	pthread_spin_lock(&ctx->lock);

	ret = wd_comp_setting.driver->comp_send(ctx->ctx, &msg, priv);
	if (ret < 0) {
		WD_ERR("wd comp send err(%d)!\n", ret);
		goto err_out;
	}

	if (req->src_len >= POLL_SIZE) {
		ret = wd_ctx_wait(ctx->ctx, POLL_TIME);
		if (ret < 0) {
			WD_ERR("wd ctx wait fail(%d)!\n", ret);
			goto err_out;
		}
	}

	do {
		ret = wd_comp_setting.driver->comp_recv(ctx->ctx, &msg, priv);
		if (ret == -WD_HW_EACCESS) {
			WD_ERR("wd comp recv hw err!\n");
			goto err_out;
		} else if (ret == -WD_EAGAIN) {
			if (++recv_count > MAX_RETRY_COUNTS) {
				WD_ERR("wd comp recv timeout fail!\n");
				ret = -WD_ETIMEDOUT;
				goto err_out;
			}
		}
	} while (ret == -WD_EAGAIN);

	pthread_spin_unlock(&ctx->lock);

	req->src_len = msg.in_cons;
	req->dst_len = msg.produced;
	req->status = msg.req.status;
	sess->isize = msg.isize;
	sess->checksum = msg.checksum;

	sess->stream_pos = WD_COMP_STREAM_OLD;

	wd_do_comp_strm_end_check(sess, req, src_len);

	return 0;

err_out:
	pthread_spin_unlock(&ctx->lock);
	return ret;
}

int wd_do_comp_async(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_ctx_config_internal *config = &wd_comp_setting.config;
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	handle_t h_sched_ctx = wd_comp_setting.sched.h_sched_ctx;
	void *priv = wd_comp_setting.priv;
	struct wd_ctx_internal *ctx;
	struct wd_comp_msg *msg;
	int tag, ret;
	__u32 idx;

	ret = wd_comp_check_params(h_sess, req, CTX_MODE_ASYNC);
	if (ret) {
		WD_ERR("fail to check params!\n");
		return ret;
	}

	if (!req->src_len) {
		WD_ERR("invalid: req src_len is 0!\n");
		return -WD_EINVAL;
	}

	if (req->data_fmt > WD_SGL_BUF) {
		WD_ERR("invalid: data_fmt is %d!\n", req->data_fmt);
		return -WD_EINVAL;
	}

	idx = wd_comp_setting.sched.pick_next_ctx(h_sched_ctx,
						  req,
						  &sess->key);
	if (idx >= config->ctx_num) {
		WD_ERR("fail to pick a proper ctx!\n");
		return -WD_EINVAL;
	}
	ctx = config->ctxs + idx;
	if (ctx->ctx_mode != CTX_MODE_ASYNC) {
		WD_ERR("ctx %u mode = %hhu error!\n", idx, ctx->ctx_mode);
		return -WD_EINVAL;
	}

	tag = wd_get_msg_from_pool(&wd_comp_setting.pool, idx, (void **)&msg);
	if (tag < 0) {
		WD_ERR("busy, failed to get msg from pool!\n");
		return -WD_EBUSY;
	}
	fill_comp_msg(sess, msg, req);
	msg->tag = tag;
	msg->stream_mode = WD_COMP_STATELESS;

	pthread_spin_lock(&ctx->lock);

	ret = wd_comp_setting.driver->comp_send(ctx->ctx, msg, priv);
	if (ret < 0) {
		WD_ERR("wd comp send err(%d)!\n", ret);
		wd_put_msg_to_pool(&wd_comp_setting.pool, idx, msg->tag);
	}

	pthread_spin_unlock(&ctx->lock);

	return ret;
}

int wd_comp_poll(__u32 expt, __u32 *count)
{
	handle_t h_sched_ctx;
	struct wd_sched *sched;

	h_sched_ctx = wd_comp_setting.sched.h_sched_ctx;
	sched = &wd_comp_setting.sched;

	return sched->poll_policy(h_sched_ctx, expt, count);
}
