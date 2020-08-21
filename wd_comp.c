/* SPDX-License-Identifier: Apache-2.0 */
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "hisi_comp.h"
#include "wd_comp.h"

#include <dlfcn.h>
#include "include/drv/wd_comp_drv.h"

#define WD_POOL_MAX_ENTRIES		1024
#define WD_HW_EACCESS 			62
#define MAX_RETRY_COUNTS		1000	//200000000

#define WD_COMP_BUF_MIN			(1 << 12)	// 4KB
#define WD_COMP_BUF_MIN_MASK		0xFFF
#define WD_COMP_BUF_MAX			(1 << 23)	// 8MB
#define WD_COMP_BUF_MAX_MASK		0x7FFFFF

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

	if (cfg->ctx_num <= 0)
		return -EINVAL;

	ctxs = calloc(1, cfg->ctx_num * sizeof(struct wd_ctx));
	if (!ctxs)
		return -ENOMEM;

	for (i = 0; i < cfg->ctx_num; i++) {
		if (!cfg->ctxs[i].ctx)
			return -EINVAL;
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
	wd_comp_setting.sched.pick_next_ctx = NULL;
	wd_comp_setting.sched.poll_policy = NULL;
}

static void clear_config_in_global_setting(void)
{
	wd_comp_setting.config.priv = NULL;
	wd_comp_setting.config.ctx_num = 0;
	free(wd_comp_setting.config.ctxs);
}

/* Each context has a reqs pool. */
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

	for (i = 0; i < wd_comp_setting.config.ctx_num; i++) {
		if (h_ctx == wd_comp_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found)
		return NULL;

	p = &pool->pools[i];
	/* empty */
	if (p->head == p->tail)
		return NULL;
	idx = msg->tag;
	c_msg = &p->msg[idx];
	c_msg->req->src_len = msg->in_cons;
	c_msg->req->dst_len = msg->produced;
	c_msg->status = msg->status;
	c_msg->isize = msg->isize;
	c_msg->checksum = msg->checksum;
	c_msg->tag = msg->tag;
	msg->req = c_msg->req;
	msg->sess = c_msg->sess;
	return msg->req;
}

static struct wd_comp_msg *wd_get_msg_from_pool(struct wd_async_msg_pool *pool,
						handle_t h_ctx,
						struct wd_comp_req *req)
{
	struct msg_pool *p;
	struct wd_comp_msg *msg;
	int i, t, found = 0;

	for (i = 0; i < wd_comp_setting.config.ctx_num; i++) {
		if (h_ctx == wd_comp_setting.config.ctxs[i].ctx) {
			found = 1;
			break;
		}
	}
	if (!found)
		return NULL;

	p = &pool->pools[i];
/*
	TODO  use bitmap to get idx for use
*/
	t = (p->tail + 1) % WD_POOL_MAX_ENTRIES;
	/* full */
	if (p->head == t)
		return NULL;
	/* get msg from msg_pool[] */
	msg = &p->msg[p->tail];
	msg->req = req;
	msg->tag = p->tail;
	p->tail = t;

	return msg;
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
	wd_comp_setting.driver->exit(priv);
	free(priv);

	/* uninit async request pool */
	wd_uninit_async_request_pool(&wd_comp_setting.pool);

	/* unset config, sched, driver */
	clear_sched_in_global_setting();
	clear_config_in_global_setting();
}

handle_t wd_comp_alloc_sess(struct wd_comp_sess_setup *setup)
{
	struct wd_comp_sess *sess;

	if (setup == NULL)
		return (handle_t)0;
	sess = calloc(1, sizeof(struct wd_comp_sess));
	if (!sess)
		return (handle_t)0;
	sess->alg_type = setup->alg_type;
	sess->swap_in = calloc(1, WD_COMP_BUF_MIN);
	if (!sess->swap_in)
		goto out;
	sess->swap_out = calloc(1, WD_COMP_BUF_MIN);
	if (!sess->swap_out)
		goto out_swap;
	sess->ctx_buf = calloc(1, HW_CTX_SIZE);
	if (!sess->ctx_buf)
		goto out_ctx;
	return (handle_t)sess;
out_ctx:
	free(sess->swap_out);
out_swap:
	free(sess->swap_in);
out:
	free(sess);
	return (handle_t)0;
}

void wd_comp_free_sess(handle_t h_sess)
{
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;

	/* allocated in comp_prepare() */
	free(sess->ctx_buf);
	free(sess->swap_in);
	free(sess->swap_out);
	free(sess);
}

static inline int need_swap(struct wd_comp_sess *sess, int buf_size)
{
	if (buf_size < WD_COMP_BUF_MIN)
		return 1;
	return 0;
}

static inline int need_split(struct wd_comp_sess *sess, int buf_size)
{
	if (buf_size > WD_COMP_BUF_MAX)
		return 1;
	return 0;
}

static inline int is_in_swap(struct wd_comp_sess *sess, void *addr, void *swap)
{
	if (((uint64_t)addr & ~WD_COMP_BUF_MIN_MASK) ==
	    ((uint64_t)swap & ~WD_COMP_BUF_MIN_MASK))
		return 1;
	return 0;
}

/*
 * sess->next_in & sess->next_out are updated if split.
 * req->src & req->dst won't be changed even if split.
 */
static int comp_prepare(struct wd_comp_sess *sess,
			struct wd_comp_msg *msg,
			struct wd_comp_req *req
			)
{
	int /*  skipped = 0, */templen;

	/* Check whether it's the first operation in the session. */
	if (!sess->begin)
		msg->stream_pos = 1;

	req->status = 0;

	/* Update loaded_in & avail_in */
	if (sess->loaded_in && sess->avail_in) {
		/* src data is cached */
		if (sess->avail_in >= req->src_len) {
			templen = req->src_len;
			req->status |= STATUS_IN_EMPTY;
		} else {
			templen = sess->avail_in;
			req->status |= STATUS_IN_PART_USE;
		}
		if (is_in_swap(sess, sess->next_in, sess->swap_in))
			memcpy(sess->next_in + sess->loaded_in,
			       req->src,
			       templen
			       );
		else if (sess->next_in != req->src) {
			/*
			 * It's not using SWAP_IN, use previous req->src as
			 * cached src address. So the new coming src data must
			 * be continuous.
			 */
			req->status = 0;
			return -EINVAL;
		}
		sess->avail_in -= templen;
		sess->loaded_in += templen;
	} else if (!sess->loaded_in) {
		if (need_swap(sess, req->src_len)) {
			/* Store a new request in SWAP_IN. */
			sess->next_in = sess->swap_in;
			sess->avail_in = WD_COMP_BUF_MIN;
			memcpy(sess->next_in, req->src, req->src_len);
			sess->avail_in -= req->src_len;
			sess->loaded_in += req->src_len;
			req->status |= STATUS_IN_EMPTY;
		} else {
			sess->next_in = req->src;
			sess->avail_in = req->src_len;
			if (sess->avail_in >= req->src_len) {
				templen = req->src_len;
				req->status |= STATUS_IN_EMPTY;
			} else {
				templen = sess->avail_in;
				req->status |= STATUS_IN_PART_USE;
			}
			sess->avail_in -= templen;
			sess->loaded_in += templen;
		}
	}

	if (sess->undrained)
		return 0;

	/* Set avail_out */
	if (need_swap(sess, req->dst_len)) {
		sess->avail_out = WD_COMP_BUF_MIN;
		sess->next_out = sess->swap_out;
	} else if (need_split(sess, req->dst_len)) {
		sess->next_out = req->dst;
		sess->avail_out = WD_COMP_BUF_MAX;
	} else {
		sess->next_out = req->dst;
		sess->avail_out = req->dst_len;
	}

	if (sess->loaded_in) {
		if (!sess->avail_in)
			sess->full = 1;
		/* no more data */
		if (!req->src_len && (req->flag = FLAG_INPUT_FINISH))
			sess->full = 1;
		msg->in_size = sess->loaded_in;
	}
	msg->op_type = req->op_type;
	msg->src = sess->next_in;
	msg->dst = sess->next_out;
	msg->avail_out = sess->avail_out;
	msg->ctx_buf = sess->ctx_buf;
	msg->req = req;
	msg->sess = sess;

#if 0
	if (!sess->load_head && req->op_type == WD_DIR_DECOMPRESS) {
		if (sess->alg_type == WD_ZLIB)
			skipped = 2;
		else if (sess->alg_type == WD_GZIP)
			skipped = 10;
		if (sess->loaded_in >= skipped) {
			sess->skipped = skipped;
			sess->load_head = 1;
		}
	}
#endif
	return 0;
}

static void comp_post(struct wd_comp_sess *sess,
		      struct wd_comp_req *req
		      )
{
	int templen;

	if (sess->undrained) {
		if (sess->undrained >= req->dst_len)
			templen = req->dst_len;
		else
			templen = sess->undrained;
		if (is_in_swap(sess, sess->next_out, sess->swap_out))
			memcpy(req->dst, sess->next_out, templen);
		sess->next_out += templen;
		req->dst_len = templen;
		sess->undrained -= templen;
		req->status |= STATUS_OUT_READY;
	}
	if (!sess->undrained) {
		if (req->status & STATUS_OUT_READY)
			req->status |= STATUS_OUT_DRAINED;
		sess->next_out = NULL;
	}
	if (!sess->loaded_in)
		sess->next_in = NULL;
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

	ret = comp_prepare(sess, &msg, req);
	if (ret < 0)
	        return ret;
	msg.alg_type = sess->alg_type;

	if (sess->loaded_in) {
		if (req->flag & FLAG_INPUT_FINISH)
			msg.flush_type = 1;
		else if (sess->full) {
			msg.flush_type = 0;
			sess->full = 0;
		} else {
			comp_post(sess, req);
			return 0;
		}
		ret = wd_comp_setting.driver->comp_send(h_ctx, &msg);
		if (ret < 0) {
			WD_ERR("wd_send err!\n");
			return ret;
		}
		sess->begin = 1;

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
		if (req->src_len == resp_msg.in_cons) {
			req->status &= ~STATUS_IN_PART_USE;
		        req->status |= STATUS_IN_EMPTY;
		} else if (req->src_len > resp_msg.in_cons) {
			req->status &= ~STATUS_IN_EMPTY;
		        req->status |= STATUS_IN_PART_USE;
		}
		if (resp_msg.produced)
		        sess->undrained += resp_msg.produced;
		req->src_len = resp_msg.in_cons;
		sess->loaded_in -= resp_msg.in_cons;
		sess->next_in += resp_msg.in_cons;
	}
	comp_post(sess, req);

	return 0;
}

int wd_do_comp_strm(handle_t h_sess, struct wd_comp_req *req)
{
	return 0;
}

int wd_do_comp_async(handle_t h_sess, struct wd_comp_req *req)
{
	struct wd_ctx_config *config = &wd_comp_setting.config;
	struct wd_comp_msg *msg;
	struct wd_comp_sess *sess = (struct wd_comp_sess *)h_sess;
	handle_t h_ctx;
	int ret;

	h_ctx = wd_comp_setting.sched.pick_next_ctx(config, req, 0);

	msg = wd_get_msg_from_pool(&wd_comp_setting.pool, h_ctx, req);
	ret = comp_prepare(sess, msg, req);
	if (ret < 0)
		return ret;
	msg->alg_type = sess->alg_type;

	req->status = 0;
	if (sess->loaded_in) {
		if (req->flag & FLAG_INPUT_FINISH)
			msg->flush_type = 1;
		else if (sess->full) {
			msg->flush_type = 0;
			sess->full = 0;
		} else {
			comp_post(sess, req);
			return 0;
		}
		ret = wd_comp_setting.driver->comp_send(h_ctx, msg);
		if (ret < 0) {
			WD_ERR("wd_send err!\n");
			return ret;
		}
		sess->begin = 1;
	}

	return 0;
}

__u32 wd_comp_poll_ctx(handle_t h_ctx, __u32 num)
{
	struct wd_comp_sess *sess;
	struct wd_comp_req *req;
	struct wd_comp_msg resp_msg;
	__u64 recv_count = 0;
	int ret;

	do {
		ret = wd_comp_setting.driver->comp_recv(h_ctx, &resp_msg);
		if (ret == -WD_HW_EACCESS) {
			WD_ERR("wd_recv hw err!\n");
			goto err_recv;
		} else if ((ret == -WD_EBUSY) || (ret == -EAGAIN)) {
			if (++recv_count > MAX_RETRY_COUNTS) {
				WD_ERR("wd_recv timeout fail!\n");
				ret = -ETIMEDOUT;
				goto err_recv;
			}
		}
	} while (ret < 0);

	req = wd_get_req_from_pool(&wd_comp_setting.pool, h_ctx, &resp_msg);
	sess = resp_msg.sess;
	if (!sess->loaded_in)
		return -EINVAL;

	if (req->src_len == resp_msg.in_cons) {
		req->status &= ~STATUS_IN_PART_USE;
	        req->status |= STATUS_IN_EMPTY;
	} else if (req->src_len > resp_msg.in_cons) {
		req->status &= ~STATUS_IN_EMPTY;
	        req->status |= STATUS_IN_PART_USE;
	}
	if (resp_msg.produced)
	        sess->undrained += resp_msg.produced;
	req->src_len = resp_msg.in_cons;
	sess->loaded_in -= resp_msg.in_cons;
	sess->next_in += resp_msg.in_cons;

	comp_post(sess, req);

	req->cb(req->cb_param);

	/*TODO free idx of msg_pool  */

	/* Return polled number. Now hack it to 1. */
	return 1;
err_recv:
	return ret;
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
