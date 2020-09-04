// SPDX-License-Identifier: Apache-2.0
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "wd_comp.h"

#include <dlfcn.h>
#include "include/drv/wd_comp_drv.h"

#define WD_POOL_MAX_ENTRIES		1024
#define WD_HW_EACCESS			62
#define MAX_RETRY_COUNTS		200000000

#define HW_CTX_SIZE			(64 * 1024)

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

struct msg_pool {
	struct wd_comp_msg msg[WD_POOL_MAX_ENTRIES];
	int used[WD_POOL_MAX_ENTRIES];
	int head;
	int tail;
};

struct wd_async_msg_pool {
	struct msg_pool *pools;
	int pool_nums;
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

	/* Fix me: vendor driver should be put in /usr/lib/wd/ */
	driver = dlopen("/usr/lib/wd/libhisi_zip.so", RTLD_NOW);
	if (!driver)
		WD_ERR("Fail to open libhisi_zip.so\n");
}
#endif

void wd_comp_set_driver(struct wd_comp_driver *drv)
{
	wd_comp_setting.driver = drv;
}

static void clone_ctx_to_internal(struct wd_ctx *ctx,
				  struct wd_ctx_internal *ctx_in)
{
	ctx_in->ctx = ctx->ctx;
	ctx_in->op_type = ctx->op_type;
	ctx_in->ctx_mode = ctx->ctx_mode;
}

static int init_global_ctx_setting(struct wd_ctx_config *cfg)
{
	struct wd_ctx_internal *ctxs;
	int i;

	if (!cfg->ctx_num) {
		WD_ERR("invalid params, ctx_num is 0!\n");
		return -EINVAL;
	}

	ctxs = calloc(1, cfg->ctx_num * sizeof(struct wd_ctx_internal));
	if (!ctxs)
		return -ENOMEM;

	for (i = 0; i < cfg->ctx_num; i++) {
		if (!cfg->ctxs[i].ctx) {
			WD_ERR("invalid params, ctx is NULL!\n");
			free(ctxs);
			return -EINVAL;
		}

		clone_ctx_to_internal(cfg->ctxs + i, ctxs + i);
		pthread_mutex_init(&ctxs[i].lock, NULL);
	}

	wd_comp_setting.config.ctxs = ctxs;

	/* Can't copy with the size of priv structure. */
	wd_comp_setting.config.priv = cfg->priv;
	wd_comp_setting.config.ctx_num = cfg->ctx_num;

	return 0;
}

static int copy_sched_to_global_setting(struct wd_sched *sched)
{
	if (!sched->name)
		return -EINVAL;

	wd_comp_setting.sched.name = strdup(sched->name);
	wd_comp_setting.sched.pick_next_ctx = sched->pick_next_ctx;
	wd_comp_setting.sched.poll_policy = sched->poll_policy;

	return 0;
}

static void clear_sched_in_global_setting(void)
{
	char *name = (char *)wd_comp_setting.sched.name;

	if (name)
		free(name);
	wd_comp_setting.sched.name = NULL;
	wd_comp_setting.sched.pick_next_ctx = NULL;
	wd_comp_setting.sched.poll_policy = NULL;
}

static void clear_config_in_global_setting(void)
{
	int i;

	for (i = 0; i < wd_comp_setting.config.ctx_num; i++)
		pthread_mutex_destroy(&wd_comp_setting.config.ctxs[i].lock);
	wd_comp_setting.config.priv = NULL;
	wd_comp_setting.config.ctx_num = 0;
	free(wd_comp_setting.config.ctxs);
}

/* Each context has a msg pool. */
static int wd_init_async_request_pool(struct wd_async_msg_pool *pool)
{
	struct msg_pool *p;
	int i, num;

	num = wd_comp_setting.config.ctx_num;

	pool->pools = calloc(1, num * sizeof(struct msg_pool));
	if (!pool->pools)
		return -ENOMEM;

	pool->pool_nums = num;
	for (i = 0; i < num; i++) {
		p = &pool->pools[i];
		p->head = 0;
		p->tail = 0;
	}

	return 0;
}

static void wd_uninit_async_request_pool(struct wd_async_msg_pool *pool)
{
	struct msg_pool *p;
	int i, j;

	for (i = 0; i < pool->pool_nums; i++) {
		p = &pool->pools[i];
		for (j = 0; j < WD_POOL_MAX_ENTRIES; j++) {
			if (p->used[j])
				WD_ERR("entry #%d isn't released from reqs pool.\n", j);
		}
	}

	free(pool->pools);
	pool->pools = NULL;
	pool->pool_nums = 0;
}

static struct wd_comp_req *wd_get_req_from_pool(struct wd_async_msg_pool *pool,
						handle_t h_ctx,
						struct wd_comp_msg *msg)
{
	struct wd_comp_msg *c_msg;
	struct msg_pool *p;
	int found = 0;
	int i;

	/* tag value start from 1 */
	if (msg->tag == 0 || msg->tag > WD_POOL_MAX_ENTRIES) {
		WD_ERR("invalid msg cache tag(%d)\n", msg->tag);
		return NULL;
	}
	for (i = 0; i < wd_comp_setting.config.ctx_num; i++) {
		if (h_ctx == wd_comp_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found) {
		WD_ERR("ctx handle not fonud!\n");
		return NULL;
	}
	p = &pool->pools[i];
	c_msg = &p->msg[msg->tag - 1];
	c_msg->req.src_len = msg->in_cons;
	c_msg->req.dst_len = msg->produced;
	c_msg->req.status = msg->req.status;
	c_msg->isize = msg->isize;
	c_msg->checksum = msg->checksum;
	c_msg->tag = msg->tag;
	memcpy(&msg->req, &c_msg->req, sizeof(struct wd_comp_req));

	return &msg->req;
}

static struct wd_comp_msg *wd_get_msg_from_pool(struct wd_async_msg_pool *pool,
						handle_t h_ctx,
						struct wd_comp_req *req)
{
	struct wd_comp_msg *msg;
	struct msg_pool *p;
	int found = 0;
	int cnt = 0;
	int idx = 0;
	int i;

	for (i = 0; i < wd_comp_setting.config.ctx_num; i++) {
		if (h_ctx == wd_comp_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found) {
		WD_ERR("ctx handle not fonud!\n");
		return NULL;
	}
	p = &pool->pools[i];

	while (__atomic_test_and_set(&p->used[idx], __ATOMIC_ACQUIRE)) {
		idx = (idx + 1) % WD_POOL_MAX_ENTRIES;
		cnt++;
		if (cnt == WD_POOL_MAX_ENTRIES)
			return NULL;
	}

	msg = &p->msg[idx];
	memcpy(&msg->req, req, sizeof(struct wd_comp_req));
	msg->tag = idx + 1;

	return msg;
}

static void wd_put_msg_to_pool(struct wd_async_msg_pool *pool,
			       handle_t h_ctx,
			       struct wd_comp_msg *msg)
{
	struct msg_pool *p;
	int found = 0;
	int i;

	/* tag value start from 1 */
	if (!msg->tag || msg->tag > WD_POOL_MAX_ENTRIES) {
		WD_ERR("invalid msg cache idx(%d)\n", msg->tag);
		return;
	}
	for (i = 0; i < wd_comp_setting.config.ctx_num; i++) {
		if (h_ctx == wd_comp_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found) {
		WD_ERR("ctx handle not fonud!\n");
		return;
	}

	p = &pool->pools[i];

	__atomic_clear(&p->used[msg->tag - 1], __ATOMIC_RELEASE);
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
		return -EINVAL;
	}

	if (!wd_is_sva(config->ctxs[0].ctx)) {
		WD_ERR("err, non sva, please check system!\n");
		return -EINVAL;
	}

	ret = init_global_ctx_setting(config);
	if (ret < 0) {
		WD_ERR("failed to set config, ret = %d!\n", ret);
		return ret;
	}
	ret = copy_sched_to_global_setting(sched);
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

	/* init async request pool */
	ret = wd_init_async_request_pool(&wd_comp_setting.pool);
	if (ret < 0) {
		WD_ERR("failed to init req pool, ret = %d!\n", ret);
		goto out_sched;
	}
	/* init ctx related resources in specific driver */
	priv = calloc(1, wd_comp_setting.driver->drv_ctx_size);
	if (!priv) {
		ret = -ENOMEM;
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
	clear_sched_in_global_setting();
out:
	clear_config_in_global_setting();
	return ret;
}

void wd_comp_uninit(void)
{
	void *priv;

	/* driver uninit */
	priv = wd_comp_setting.priv;
	if (!priv)
		return;

	wd_comp_setting.driver->exit(priv);
	free(priv);
	priv = NULL;

	/* uninit async request pool */
	wd_uninit_async_request_pool(&wd_comp_setting.pool);

	/* unset config, sched, driver */
	clear_sched_in_global_setting();
	clear_config_in_global_setting();
}

int wd_comp_poll_ctx(handle_t h_ctx, __u32 expt, __u32 *count)
{
	struct wd_comp_msg resp_msg;
	struct wd_comp_req *req;
	__u64 recv_count = 0;
	int ret;

	do {
		ret = wd_comp_setting.driver->comp_recv(h_ctx, &resp_msg);
		if (ret < 0) {
			if (ret == -WD_HW_EACCESS)
				WD_ERR("wd comp recv hw err!\n");
			break;
		}

		recv_count++;
		req = wd_get_req_from_pool(&wd_comp_setting.pool,
					   h_ctx, &resp_msg);
		if (!req) {
			WD_ERR("get req from pool is NULL!\n");
			break;
		}
		req->cb(req, req->cb_param);

		/* free msg cache to msg_pool */
		wd_put_msg_to_pool(&wd_comp_setting.pool, h_ctx, &resp_msg);

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
	} else {
		WD_ERR("in append store block, wrong alg type %d.\n", sess->alg_type);
		return -EINVAL;
	}

	return 0;
}

static void fill_comp_msg(struct wd_comp_msg *msg, struct wd_comp_req *req)
{
	memcpy(&msg->req, req, sizeof(struct wd_comp_req));
	msg->avail_out = req->dst_len;

	/* if is last 1: flush end; other: sync flush */
	msg->req.last = 1;
}

int wd_do_comp_sync(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_ctx_config_internal *config = &wd_comp_setting.config;
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	handle_t h_sched_ctx = wd_comp_setting.sched.h_sched_ctx;
	struct wd_comp_msg msg, resp_msg;
	struct wd_ctx_internal *ctx;
	__u64 recv_count = 0;
	int index, ret;

	if (!sess || !req) {
		WD_ERR("invalid: sess or req is NULL!\n");
		return -EINVAL;
	}

	if (!req->src_len) {
		WD_ERR("invalid: req src_len is 0!\n");
		return -EINVAL;
	}

	index = wd_comp_setting.sched.pick_next_ctx(h_sched_ctx, req, 0);
	if (index > config->ctx_num) {
		WD_ERR("fail to pick a proper ctx!\n");
		return -EINVAL;
	}
	ctx = config->ctxs + index;

	fill_comp_msg(&msg, req);
	msg.ctx_buf = sess->ctx_buf;
	msg.alg_type = sess->alg_type;
	msg.stream_mode = WD_COMP_STATELESS;

	pthread_mutex_lock(&ctx->lock);

	ret = wd_comp_setting.driver->comp_send(ctx->ctx, &msg);
	if (ret < 0) {
		pthread_mutex_unlock(&ctx->lock);
		WD_ERR("wd comp send err(%d)!\n", ret);
		return ret;
	}
	resp_msg.ctx_buf = sess->ctx_buf;
	do {
		ret = wd_comp_setting.driver->comp_recv(ctx->ctx, &resp_msg);
		if (ret == -WD_HW_EACCESS) {
			pthread_mutex_unlock(&ctx->lock);
			WD_ERR("wd comp recv hw err!\n");
			return ret;
		} else if (ret == -EAGAIN) {
			if (++recv_count > MAX_RETRY_COUNTS) {
				pthread_mutex_unlock(&ctx->lock);
				WD_ERR("wd comp recv timeout fail!\n");
				return -ETIMEDOUT;
			}
		}
	} while (ret == -EAGAIN);

	pthread_mutex_unlock(&ctx->lock);

	req->src_len = resp_msg.in_cons;
	req->dst_len = resp_msg.produced;
	req->status = resp_msg.req.status;

	return 0;
}

#define STREAM_CHUNK (128 * 1024)

int wd_do_comp_sync2(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_comp_req strm_req;
	__u32 total_avail_out = req->dst_len;
	__u32 chunk = STREAM_CHUNK;
	__u32 avail_in = 0;
	__u32 avail_out;
	int ret;

	if (!h_sess || !req) {
		WD_ERR("invalid: sess or req is NULL!\n");
		return -EINVAL;
	}
	if (req->op_type != WD_DIR_COMPRESS &&
	    req->op_type != WD_DIR_DECOMPRESS) {
		WD_ERR("invalid: op_type is %d!\n", req->op_type);
		return -EINVAL;
	}

	if (!req->src_len) {
		WD_ERR("invalid: req src_len is 0!\n");
		return -EINVAL;
	}

	dbg("do, op_type = %d, in =%d, out_len =%d\n", req->op_type, req->src_len, req->dst_len);

	avail_out = req->dst_len > chunk ? chunk : req->dst_len;
	memcpy(&strm_req, req, sizeof(struct wd_comp_req));
	req->dst_len = 0;

	if (req->op_type == WD_DIR_COMPRESS) {
		do {
			if (req->src_len > chunk) {
				strm_req.src_len = chunk;
				req->src_len -= chunk;
			} else {
				strm_req.src_len = req->src_len;
				req->src_len = 0;
			}
			strm_req.last = (strm_req.src_len == chunk) ? 0 : 1;
			avail_in = strm_req.src_len;
			do {
				if (strm_req.src_len == 0 && strm_req.last == 1) {
				dbg("append_store, src_len = %d, dst_len =%d\n", req->src_len, req->dst_len);
					ret = append_store_block(h_sess, &strm_req);
					req->dst_len += strm_req.dst_len;
					req->status = 0;
					return 0;
				}
				dbg("do, compstrm start, in =%d, out_len =%d\n", strm_req.src_len, strm_req.dst_len);
				if (req->dst_len + strm_req.src_len > total_avail_out)
					return -ENOMEM;
				strm_req.dst_len = avail_out;
				ret = wd_do_comp_strm(h_sess, &strm_req);
				if (ret < 0)
					return ret;
				req->dst_len += strm_req.dst_len;
				strm_req.dst += strm_req.dst_len;
				dbg("do, compstrm end, in =%d, out_len =%d\n", strm_req.src_len, strm_req.dst_len);

				strm_req.src += strm_req.src_len;
				avail_in -= strm_req.src_len;
				strm_req.src_len = avail_in;
			} while (strm_req.src_len > 0);

		} while (strm_req.last != 1);
	} else {
		do {
			if (req->src_len > chunk) {
				strm_req.src_len = chunk;
				req->src_len -= chunk;
			} else {
				strm_req.src_len = req->src_len;
				req->src_len = 0;
			}
			strm_req.last = 0;
			avail_in = strm_req.src_len;
			do {
				dbg("do, decompstrm start, in =%d, out_len =%d\n", strm_req.src_len, strm_req.dst_len);
				if (req->dst_len + strm_req.src_len > total_avail_out) {
					dbg("err, outsize =%u, avail_out =%u, total_avail_out =%u\n", req->dst_len, avail_out, total_avail_out);
					return -ENOMEM;
				}
				strm_req.dst_len = avail_out;
				ret = wd_do_comp_strm(h_sess, &strm_req);
				if (ret < 0)
					return ret;
				req->dst_len += strm_req.dst_len;
				strm_req.dst += strm_req.dst_len;
				dbg("do, decompstrm end, in =%d, out_len =%d\n", strm_req.src_len, strm_req.dst_len);

				strm_req.src += strm_req.src_len;
				avail_in -= strm_req.src_len;
				strm_req.src_len = avail_in;
			} while (strm_req.src_len > 0);

		} while (strm_req.status != WD_DECOMP_END);
	}

	dbg("end, in =%d, out_len =%d\n", req->src_len, req->dst_len);

	req->status = 0;

	return 0;
}


int wd_do_comp_strm(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_ctx_config_internal *config = &wd_comp_setting.config;
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	handle_t h_sched_ctx = wd_comp_setting.sched.h_sched_ctx;
	struct wd_comp_msg msg, resp_msg;
	struct wd_ctx_internal *ctx;
	__u64 recv_count = 0;
	int index, ret;

	if (!sess || !req) {
		WD_ERR("sess or req is NULL!\n");
		return -EINVAL;
	}

	index = wd_comp_setting.sched.pick_next_ctx(h_sched_ctx, req, 0);
	if (index > config->ctx_num) {
		WD_ERR("fail to pick a proper ctx!\n");
		return -EINVAL;
	}
	ctx = config->ctxs + index;

	fill_comp_msg(&msg, req);
	msg.stream_pos = sess->stream_pos;
	msg.ctx_buf = sess->ctx_buf;
	msg.alg_type = sess->alg_type;
	msg.isize = sess->isize;
	msg.checksum = sess->checksum;
	/* fill true flag */
	msg.req.last = req->last;
	msg.stream_mode = WD_COMP_STATEFUL;
	sess->isize = resp_msg.isize;
	sess->checksum = resp_msg.checksum;

	pthread_mutex_lock(&ctx->lock);

	ret = wd_comp_setting.driver->comp_send(ctx->ctx, &msg);
	if (ret < 0) {
		pthread_mutex_unlock(&ctx->lock);
		WD_ERR("wd comp send err(%d)!\n", ret);
		return ret;
	}
	resp_msg.ctx_buf = sess->ctx_buf;
	do {
		ret = wd_comp_setting.driver->comp_recv(ctx->ctx, &resp_msg);
		if (ret == -WD_HW_EACCESS) {
			pthread_mutex_unlock(&ctx->lock);
			WD_ERR("wd comp recv hw err!\n");
			return ret;
		} else if (ret == -EAGAIN) {
			if (++recv_count > MAX_RETRY_COUNTS) {
				pthread_mutex_unlock(&ctx->lock);
				WD_ERR("wd comp recv timeout fail!\n");
				return -ETIMEDOUT;
			}
		}
	} while (ret == -EAGAIN);

	pthread_mutex_unlock(&ctx->lock);

	req->src_len = resp_msg.in_cons;
	req->dst_len = resp_msg.produced;
	req->status = resp_msg.req.status;

	sess->stream_pos = WD_COMP_STREAM_OLD;

	if (req->status == WD_IN_EPARA) {
		WD_ERR("wd comp, invalid or incomplete deflate data!\n");
		return -EINVAL;
	}

	return 0;
}

int wd_do_comp_async(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_ctx_config_internal *config = &wd_comp_setting.config;
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	handle_t h_sched_ctx = wd_comp_setting.sched.h_sched_ctx;
	struct wd_ctx_internal *ctx;
	struct wd_comp_msg *msg;
	int index, ret = 0;

	if (!sess || !req) {
		WD_ERR("sess or req is NULL!\n");
		return -EINVAL;
	}

	index = wd_comp_setting.sched.pick_next_ctx(h_sched_ctx, req, 0);
	if (index > config->ctx_num) {
		WD_ERR("fail to pick a proper ctx!\n");
		return -EINVAL;
	}
	ctx = config->ctxs + index;

	msg = wd_get_msg_from_pool(&wd_comp_setting.pool, ctx->ctx, req);
	if (!msg) {
		WD_ERR("busy, failed to get msg from pool!\n");
		return -EBUSY;
	}
	fill_comp_msg(msg, req);
	msg->alg_type = sess->alg_type;

	pthread_mutex_lock(&ctx->lock);

	ret = wd_comp_setting.driver->comp_send(ctx->ctx, msg);
	if (ret < 0) {
		WD_ERR("wd comp send err(%d)!\n", ret);
		wd_put_msg_to_pool(&wd_comp_setting.pool, ctx->ctx, msg);
	}

	pthread_mutex_unlock(&ctx->lock);

	return ret;
}

int wd_comp_poll(__u32 expt, __u32 *count)
{
	int ret;

	*count = 0;

	return wd_comp_setting.sched.poll_policy(0, 0, expt, count);
}
