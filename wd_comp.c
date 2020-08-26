/* SPDX-License-Identifier: Apache-2.0 */
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "wd_comp.h"

#include <dlfcn.h>
#include "include/drv/wd_comp_drv.h"

#define WD_POOL_MAX_ENTRIES		1024
#define WD_HW_EACCESS 			62
#define MAX_RETRY_COUNTS		200000000

#define HW_CTX_SIZE			(64 * 1024)

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
	struct wd_ctx_config config;
	struct wd_sched sched;
	struct wd_comp_driver *driver;
	void *priv;
	struct wd_async_msg_pool pool;
} wd_comp_setting;

extern struct wd_comp_driver wd_comp_hisi_zip;

#ifdef WD_STATIC_DRV
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

static int copy_config_to_global_setting(struct wd_ctx_config *cfg)
{
	struct wd_ctx *ctxs;
	int i;

	if (cfg->ctx_num == 0) {
		WD_ERR("invalid params, ctx_num is NULL!\n");
		return -EINVAL;
	}

	ctxs = calloc(1, cfg->ctx_num * sizeof(struct wd_ctx));
	if (!ctxs)
		return -ENOMEM;

	for (i = 0; i < cfg->ctx_num; i++) {
		if (!cfg->ctxs[i].ctx) {
			WD_ERR("invalid params, ctx is NULL!\n");
			return -EINVAL;
		}
	}

	memcpy(ctxs, cfg->ctxs, cfg->ctx_num * sizeof(struct wd_ctx));
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

	free(name);
	name = NULL;
	wd_comp_setting.sched.pick_next_ctx = NULL;
	wd_comp_setting.sched.poll_policy = NULL;
}

static void clear_config_in_global_setting(void)
{
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
	int i, j, num;

	num = pool->pool_nums;
	for (i = 0; i < num; i++) {
		p = &pool->pools[i];
		for (j = 0; j < WD_POOL_MAX_ENTRIES; j++) {
			if (p->used[j])
				WD_ERR("Entry #%d isn't released from reqs "
					"pool.\n", j);
			memset(&p->msg[j], 0, sizeof(struct wd_comp_msg));
		}
		p->head = 0;
		p->tail = 0;
	}

	free(pool->pools);
}

static struct wd_comp_req *wd_get_req_from_pool(struct wd_async_msg_pool *pool,
						handle_t h_ctx,
						struct wd_comp_msg *msg)
{
	struct msg_pool *p;
	struct wd_comp_msg *c_msg;
	int i, found = 0;
	int idx;

	if (msg->tag < 0 || msg->tag >= WD_POOL_MAX_ENTRIES) {
		WD_ERR("invalid msg cache idx(%d)\n", msg->tag);
		return NULL;
	}
	for (i = 0; i < wd_comp_setting.config.ctx_num; i++) {
		if (h_ctx == wd_comp_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found) {
		WD_ERR("ctx handler not fonud!\n");
		return NULL;
	}
	p = &pool->pools[i];

	idx = msg->tag;
	c_msg = &p->msg[idx];
	c_msg->req.src_len = msg->in_cons;
	c_msg->req.dst_len = msg->produced;
	c_msg->status = msg->status;
	c_msg->isize = msg->isize;
	c_msg->checksum = msg->checksum;
	c_msg->tag = msg->tag;
	memcpy(&msg->req, &c_msg->req, sizeof(struct wd_comp_req));
	msg->sess = c_msg->sess;
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
	int i;

	for (i = 0; i < wd_comp_setting.config.ctx_num; i++) {
		if (h_ctx == wd_comp_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found) {
		WD_ERR("ctx handler not fonud!\n");
		return NULL;
	}
	p = &pool->pools[i];

	while (__atomic_test_and_set(&p->used[p->tail], __ATOMIC_ACQUIRE)){
		p->tail = (p->tail + 1) % WD_POOL_MAX_ENTRIES;
		cnt++;
		/* full */
		if (cnt == WD_POOL_MAX_ENTRIES)
			return NULL;
	}
	/* get msg from msg_pool[] */
	msg = &p->msg[p->tail];
	memcpy(&msg->req, req, sizeof(struct wd_comp_req));
	msg->tag = p->tail;

	return msg;
}

static void wd_put_msg_to_pool(struct wd_async_msg_pool *pool,
			       handle_t h_ctx,
			       struct wd_comp_msg *msg)
{
	struct msg_pool *p;
	int found = 0;
	int i;

	if (msg->tag < 0 || msg->tag >= WD_POOL_MAX_ENTRIES) {
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
		WD_ERR("ctx handler not fonud!\n");
		return;
	}

	p = &pool->pools[i];

	__atomic_clear(&p->used[msg->tag], __ATOMIC_RELEASE);
}

int wd_comp_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	void *priv;
	int ret;

	/* wd_comp_init() could only be invoked once for one process. */
	if (wd_comp_setting.config.ctx_num)
		return 0;

	if (!config || !sched)
		return -EINVAL;

	/* set config and sched */
	ret = copy_config_to_global_setting(config);
	if (ret < 0)
		return ret;
	ret = copy_sched_to_global_setting(sched);
	if (ret < 0)
		goto out;

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
	if (ret < 0)
		goto out_sched;

	/* init ctx related resources in specific driver */
	priv = calloc(1, wd_comp_setting.driver->drv_ctx_size);
	if (!priv) {
		ret = -ENOMEM;
		goto out_priv;
	}
	wd_comp_setting.priv = priv;
	ret = wd_comp_setting.driver->init(&wd_comp_setting.config, priv);
	if (ret < 0)
		goto out_init;

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

	/* uninit async request pool */
	wd_uninit_async_request_pool(&wd_comp_setting.pool);

	/* unset config, sched, driver */
	clear_sched_in_global_setting();
	clear_config_in_global_setting();
}

int wd_comp_poll_ctx(handle_t h_ctx, __u32 expt, __u32 *count)
{
	struct wd_comp_req *req;
	struct wd_comp_msg resp_msg;
	__u32 recv_count = 0;
	int ret;

	do {
		ret = wd_comp_setting.driver->comp_recv(h_ctx, &resp_msg);
		if (ret == -WD_HW_EACCESS) {
			WD_ERR("wd comp recv hw err!\n");
			break;
		} else if (ret == -WD_EBUSY || ret == -EAGAIN) {
			continue;
		}

		recv_count++;
		req = wd_get_req_from_pool(&wd_comp_setting.pool, h_ctx, &resp_msg);
		req->status = STATUS_OUT_DRAINED | STATUS_OUT_READY | STATUS_IN_EMPTY;
		req->flag = FLAG_INPUT_FINISH;

		req->cb(req, req->cb_param);
		expt--;

		/* free msg cache to msg_pool */
		wd_put_msg_to_pool(&wd_comp_setting.pool, h_ctx, &resp_msg);

	} while (expt);

	*count = recv_count;

	return ret;
}

handle_t wd_comp_alloc_sess(struct wd_comp_sess_setup *setup)
{
	struct wd_comp_sess *sess;

	if (setup == NULL)
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

static void fill_comp_msg(struct wd_comp_sess *sess,
			 struct wd_comp_msg *msg,
			 struct wd_comp_req *req)
{
	msg->ctx_buf = sess->ctx_buf;
	memcpy(&msg->req, req, sizeof(struct wd_comp_req));
	msg->avail_out = req->dst_len;
	msg->src = req->src;
	msg->dst = req->dst;
	msg->in_size = req->src_len;
	/* if is last 1: flush end; other: sync flush */
	msg->flush_type = WD_FINISH;
	/* if is first 1: new start; 0: old */
	msg->stream_pos = WD_COMP_STREAM_NEW;
	msg->status = 0;
}

int wd_do_comp(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_ctx_config *config = &wd_comp_setting.config;
	struct wd_comp_msg msg, resp_msg;
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	__u64 recv_count = 0;
	handle_t h_ctx;
	int ret;

	h_ctx = wd_comp_setting.sched.pick_next_ctx(config, req, 0);

	fill_comp_msg(sess, &msg, req);
	msg.ctx_buf = sess->ctx_buf;
	msg.alg_type = sess->alg_type;

	ret = wd_comp_setting.driver->comp_send(h_ctx, &msg);
	if (ret < 0) {
		WD_ERR("wd_send err!\n");
	}

	resp_msg.ctx_buf = sess->ctx_buf;
	do {
		ret = wd_comp_setting.driver->comp_recv(h_ctx, &resp_msg);
		if (ret == -WD_HW_EACCESS) {
			WD_ERR("wd_recv hw err!\n");
			return ret;
		} else if ((ret == -WD_EBUSY) || (ret == -EAGAIN)) {
			if (++recv_count > MAX_RETRY_COUNTS) {
				WD_ERR("wd_recv timeout fail!\n");
				return -ETIMEDOUT;
			}
		}
	} while (ret < 0);

	req->src_len = resp_msg.in_cons;
	req->dst_len = resp_msg.produced;
	req->status = STATUS_OUT_DRAINED | STATUS_OUT_READY | STATUS_IN_EMPTY;
	req->flag = FLAG_INPUT_FINISH;
	//req->flush = resp->flush_type;
	//req->status = resp->status;
	//req->isize = resp->isize;
	//req->checksum = resp->checksum;

	return 0;
}

int wd_do_comp_strm(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_ctx_config *config = &wd_comp_setting.config;
	struct wd_comp_msg msg, resp_msg;
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	__u64 recv_count = 0;
	handle_t h_ctx;
	int ret;

	h_ctx = wd_comp_setting.sched.pick_next_ctx(config, req, 0);

	fill_comp_msg(sess, &msg, req);
	msg.stream_pos = sess->stream_pos;
	msg.ctx_buf = sess->ctx_buf;
	msg.alg_type = sess->alg_type;
	/* fill true flag */
	msg.flush_type = req->last;
	msg.stream_mode = WD_COMP_STATEFUL;
	ret = wd_comp_setting.driver->comp_send(h_ctx, &msg);
	if (ret < 0) {
		WD_ERR("wd_send err!\n");
	}

	resp_msg.ctx_buf = sess->ctx_buf;
	do {
		ret = wd_comp_setting.driver->comp_recv(h_ctx, &resp_msg);
		if (ret == -WD_HW_EACCESS) {
			WD_ERR("wd_recv hw err!\n");
			goto err_recv;
		} else if (ret == -WD_EBUSY || ret == -EAGAIN) {
			if (++recv_count > MAX_RETRY_COUNTS) {
				WD_ERR("wd_recv timeout fail!\n");
				return -ETIMEDOUT;
			}
		}
	} while (ret < 0);

	req->src_len = resp_msg.in_cons;
	req->dst_len = resp_msg.produced;
	req->status = resp_msg.req.status;
	//req->flush = resp->flush_type;
	//req->isize = resp->isize;
	//req->checksum = resp->checksum;

	sess->stream_pos = WD_COMP_STREAM_OLD;

	return 0;
err_recv:
	return ret;
}

int wd_do_comp_async(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_ctx_config *config = &wd_comp_setting.config;
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	struct wd_comp_msg *msg;
	handle_t h_ctx;
	int ret;

	h_ctx = wd_comp_setting.sched.pick_next_ctx(config, req, 0);

	msg = wd_get_msg_from_pool(&wd_comp_setting.pool, h_ctx, req);
	fill_comp_msg(sess, msg, req);
	msg->alg_type = sess->alg_type;

	ret = wd_comp_setting.driver->comp_send(h_ctx, msg);
	if (ret < 0) {
		WD_ERR("wd_send err!\n");
		wd_put_msg_to_pool(&wd_comp_setting.pool, h_ctx, msg);
		return ret;
	}

	return 0;

}

int wd_comp_poll(__u32 *count)
{
	struct wd_ctx_config *config = &wd_comp_setting.config;
	int ret;

	ret = wd_comp_setting.sched.poll_policy(config);
	if (ret < 0)
		return ret;
	*count = ret;
	return 0;
}
