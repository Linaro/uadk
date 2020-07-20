/* SPDX-License-Identifier: Apache-2.0 */
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "hisi_comp.h"
#include "wd_comp.h"

#define SYS_CLASS_DIR	"/sys/class/uacce"

/* remove node p */
#define RM_NODE(head, prev, p)	do {					\
					if (!prev) {			\
						head = p->next;		\
						free(p->info);		\
						free(p);		\
						p = head->next;		\
					} else if (p->next) {		\
						prev->next = p->next;	\
						free(p->info);		\
						free(p);		\
						p = p->next;		\
					} else {			\
						free(p->info);		\
						free(p);		\
						p = NULL;		\
						prev->next = NULL;	\
					}				\
				} while (0)

/*
 * If multiple algorithms are supported in one accelerator, the names of
 * multiple algorithms are all stored in "alg_name" field. And they're
 * separatered by '\n' symbol.
 */
static struct wd_alg_comp wd_alg_comp_list[] = {
	{
		.drv_name	= "hisi_zip",
		.alg_name	= "zlib\ngzip",
		.init		= hisi_comp_init,
		.exit		= hisi_comp_exit,
		.prep		= hisi_comp_prep,
		.deflate	= hisi_comp_deflate,
		.inflate	= hisi_comp_inflate,
		.async_poll	= hisi_comp_poll,
		.strm_deflate	= hisi_strm_deflate,
		.strm_inflate	= hisi_strm_inflate,
	},
};

static inline int is_accel_avail(wd_dev_mask_t *dev_mask, int idx)
{
	int	offs, ret;

	offs = idx >> 3;
	ret = dev_mask->mask[offs] & (1 << (idx % 8));
	return ret;
}

static inline int match_alg_name(char *dev_alg_name, char *alg_name)
{
	char	*sub;
	int	found;

	sub = strtok(dev_alg_name, "\n");
	found = 0;
	while (sub) {
		if (!strncmp(sub, alg_name, strlen(alg_name))) {
			found = 1;
			break;
		}
		sub = strtok(NULL, "\n");
	}
	return found;
}

handle_t wd_alg_comp_alloc_sess(char *alg_name, uint32_t mode,
				 wd_dev_mask_t *dev_mask)
{
	struct uacce_dev_list	*head = NULL, *p, *prev;
	wd_dev_mask_t		*mask = NULL;
	struct wd_comp_sess	*sess = NULL;
	int	i, found, max = 0, ret;
	char	*dev_name;
#if HAVE_PERF
	struct timespec	ts_time1 = {0, 0}, ts_time2 = {0, 0}, ts_time3 = {0, 0};
#endif

#if HAVE_PERF
	clock_gettime(CLOCK_REALTIME, &ts_time1);
#endif
	if (!alg_name)
		return 0;
	mask = calloc(1, sizeof(wd_dev_mask_t));
	if (!mask)
		return (handle_t)sess;
	head = wd_list_accels(mask);
	if (!head) {
		WD_ERR("Failed to get any accelerators in system!\n");
		return (handle_t)sess;
	}
	/* merge two masks */
	if (dev_mask && (dev_mask->magic == WD_DEV_MASK_MAGIC) &&
	    dev_mask->len && (dev_mask->len <= mask->len)) {
		for (i = 0; i < mask->len; i++)
			mask->mask[i] &= dev_mask->mask[i];
	}
	for (p = head, prev = NULL; p; ) {
		if (!is_accel_avail(mask, p->info->node_id)) {
			RM_NODE(head, prev, p);
			continue;
		}
		found = match_alg_name(p->info->algs, alg_name);
		if (found) {
			if (p->info->avail_instn <= max) {
				prev = p;
				p = p->next;
				continue;
			}
			/* move to head */
			max = p->info->avail_instn;
			if (p == head) {
				prev = p;
				p = p->next;
			} else {
				prev->next = p->next;
				p->next = head;
				head = p;
				p = prev->next;
			}
		} else {
			wd_clear_mask(mask, p->info->node_id);
			RM_NODE(head, prev, p);
		}
	}
	for (p = head, i = 0; p; p = p->next) {
		/* mount driver */
		dev_name = wd_get_accel_name(p->info->dev_root, 1);
		found = 0;
		for (i = 0; i < ARRAY_SIZE(wd_alg_comp_list); i++) {
			if (!strncmp(dev_name, wd_alg_comp_list[i].drv_name,
				     strlen(dev_name))) {
				found = 1;
				break;
			}
		}
		free(dev_name);
		if (found)
			break;
	}
	if (!found)
		goto out;
	sess = calloc(1, (sizeof(struct wd_comp_sess)));
	if (!sess)
		goto out;
	sess->mode = mode;
	sess->alg_name = strdup(alg_name);
	dev_name = wd_get_accel_name(p->info->dev_root, 0);
	snprintf(sess->node_path, MAX_DEV_NAME_LEN, "/dev/%s", dev_name);
	free(dev_name);
	sess->dev_mask = mask;
	sess->drv = &wd_alg_comp_list[i];
#if HAVE_PERF
	clock_gettime(CLOCK_REALTIME, &ts_time2);
#endif
	if (sess->drv->init) {
		ret = sess->drv->init(sess);
		if (ret)
			WD_ERR("fail to init session (%d)\n", ret);
	}
#if HAVE_PERF
	clock_gettime(CLOCK_REALTIME, &ts_time3);
	printf("comp: allocate session %ldus, init session %ldus\n",
		(ts_time2.tv_sec - ts_time1.tv_sec) * 1000000 +
		(ts_time2.tv_nsec - ts_time1.tv_nsec) / 1000,
		(ts_time3.tv_sec - ts_time2.tv_sec) * 1000000 +
		(ts_time3.tv_nsec - ts_time2.tv_nsec) / 1000);
#endif
out:
	while (head) {
		p = head;
		head = head->next;
		free(p->info);
		free(p);
	}
	return (handle_t)sess;
}

void wd_alg_comp_free_sess(handle_t handle)
{
	struct wd_comp_sess *sess = (struct wd_comp_sess *)handle;

	if (!sess)
		return;

	if (sess->drv->exit)
		sess->drv->exit(sess);

	if (sess->dev_mask->mask)
		free(sess->dev_mask->mask);

	if (sess->dev_mask)
		free(sess->dev_mask);

	free(sess->alg_name);
	free(sess);
}

int wd_alg_compress(handle_t handle, struct wd_comp_arg *arg)
{
	struct wd_comp_sess	*sess = (struct wd_comp_sess *)handle;
	int	ret = -EINVAL;

	if (!arg)
		return ret;
	arg->flag |= FLAG_DEFLATE;
	if (sess->drv->prep) {
		ret = sess->drv->prep(sess, arg);
		if (ret)
			return ret;
	}
	if (sess->drv->deflate)
		ret = sess->drv->deflate(sess, arg);
	return ret;
}

int wd_alg_decompress(handle_t handle, struct wd_comp_arg *arg)
{
	struct wd_comp_sess	*sess = (struct wd_comp_sess *)handle;
	int	ret = -EINVAL;

	if (!arg)
		return ret;
	arg->flag &= ~FLAG_DEFLATE;
	if (sess->drv->prep) {
		ret = sess->drv->prep(sess, arg);
		if (ret)
			return ret;
	}
	if (sess->drv->inflate)
		ret = sess->drv->inflate(sess, arg);
	return ret;
}

int wd_alg_strm_compress(handle_t handle, struct wd_comp_strm *strm)
{
	struct wd_comp_sess	*sess = (struct wd_comp_sess *)handle;
	struct wd_comp_arg	*arg = &strm->arg;
	int	ret = -EINVAL;

	if (!strm || !strm->in || !strm->out || !strm->out_sz)
		return ret;
	if ((sess->mode & MODE_STREAM) == 0)
		return ret;

	strm->arg.src = strm->in;
	strm->arg.src_len = strm->in_sz;
	strm->arg.dst = strm->out;
	strm->arg.dst_len = strm->out_sz;
	strm->arg.flag |= FLAG_DEFLATE;
	strm->arg.status = 0;
	if (sess->drv->prep) {
		ret = sess->drv->prep(sess, arg);
		if (ret)
			return ret;
	}
	if (sess->drv->strm_deflate) {
		ret = sess->drv->strm_deflate(sess, strm);
	}
	return ret;
}

int wd_alg_strm_decompress(handle_t handle, struct wd_comp_strm *strm)
{
	struct wd_comp_sess	*sess = (struct wd_comp_sess *)handle;
	struct wd_comp_arg	*arg = &strm->arg;
	int	ret = -EINVAL;

	if (!strm || !strm->in || !strm->out || !strm->out_sz)
		return ret;
	if ((sess->mode & MODE_STREAM) == 0)
		return ret;

	strm->arg.src = strm->in;
	strm->arg.src_len = strm->in_sz;
	strm->arg.dst = strm->out;
	strm->arg.dst_len = strm->out_sz;
	strm->arg.flag &= ~FLAG_DEFLATE;
	strm->arg.status = 0;
	if (sess->drv->prep) {
		ret = sess->drv->prep(sess, arg);
		if (ret)
			return ret;
	}
	if (sess->drv->strm_inflate)
		ret = sess->drv->strm_inflate(sess, strm);
	return ret;
}

/* new code */
struct wd_async_req_pool {
};

struct wd_comp_setting {
	struct wd_ctx_config config;
	struct wd_sched sched;
	void *sched_ctx;
	struct wd_comp_driver *driver;
	void *priv;
	struct wd_async_req_pool pool;
} wd_comp_setting;

struct wd_comp_driver {
	const char *drv_name;
	const char *alg_name;
	__u32 drv_ctx_size;
	int (*init)(struct wd_ctx_config *config, void *priv);
	void (*exit)(void *priv);
	int (*comp_sync)(handle_t ctx, struct wd_comp_req *req);
	int (*comp_async)(handle_t ctx, struct wd_comp_req *req);
	/* fix me: req here may be changed */
	int (*comp_recv_async)(handle_t ctx, struct wd_comp_req *req);
	int (*poll)(handle_t ctx, __u32 num);
};

static struct wd_comp_driver wd_comp_driver_list[] = {
	{
		.drv_name		= "hisi_zip",
		.alg_name		= "zlib\ngzip",
		.drv_ctx_size		= sizeof(struct hisi_zip_ctx),
		.init			= hisi_zip_init,
		.exit			= hisi_zip_exit,
		.comp_sync		= hisi_zip_comp_sync,
		.comp_async		= hisi_zip_comp_async,
		.comp_recv_async	= hisi_zip_comp_recv_async,
		.poll			= hisi_zip_poll,
	},
};

static void copy_config_to_global_setting(struct wd_ctx_config *config)
{
}

static void copy_sched_to_global_setting(struct wd_sched *sched)
{
}

static struct wd_comp_driver *find_comp_driver(const char *driver)
{
	return NULL;
}

static void clear_sched_in_global_setting(struct wd_sched *sched)
{
}

static void clear_config_in_global_setting(struct wd_ctx_config *config)
{
}

int wd_init_async_request_pool(struct wd_async_req_pool *pool)
{
	return 0;
}

void wd_uninit_async_request_pool(struct wd_async_req_pool *pool)
{
}

int wd_put_req_into_pool(struct wd_async_req_pool *pool,
			 struct wd_comp_req *req)
{
	return 0;
}

struct wd_comp_req *wd_get_req_from_pool(struct wd_async_req_pool *pool,
					 struct wd_comp_req req)
{
	return NULL;
}

int wd_comp_init(struct wd_ctx_config *config, struct wd_sched *sched)
{
	struct wd_comp_driver *driver;
	const char *driver_name;
	handle_t h_ctx;
	void *priv;

	if (!config || !sched)
		return -EINVAL;

	/* set config and sched */
	copy_config_to_global_setting(config);
	copy_sched_to_global_setting(sched);

	/* find driver and set driver */
	h_ctx = config->ctxs[0].ctx;
	driver_name = wd_get_driver_name(h_ctx);
	driver = find_comp_driver(driver_name);

	wd_comp_setting.driver = driver;

	/* alloc sched context memory */
	wd_comp_setting.sched_ctx = calloc(1, sched->sched_ctx_size);

	/* init async request pool */
	wd_init_async_request_pool(&wd_comp_setting.pool);

	/* init ctx related resources in specific driver */
	priv = calloc(1, wd_comp_setting.driver->drv_ctx_size);
	wd_comp_setting.priv = priv;
	wd_comp_setting.driver->init(&wd_comp_setting.config, priv);

	return 0;
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

	free(wd_comp_setting.sched_ctx);

	/* unset config, sched, driver */
	wd_comp_setting.driver = NULL;
	clear_sched_in_global_setting(&wd_comp_setting.sched);
	clear_config_in_global_setting(&wd_comp_setting.config);
}

handle_t wd_comp_alloc_sess(struct wd_comp_sess_setup *setup)
{
	return 0;
}

void wd_comp_free_sess(handle_t sess) {}

int wd_comp_scompress(handle_t sess, struct wd_comp_req *req)
{
	struct wd_ctx_config *config = &wd_comp_setting.config;
	void *sched_ctx = wd_comp_setting.sched_ctx;
	handle_t h_ctx;

	h_ctx = wd_comp_setting.sched.pick_next_ctx(config, sched_ctx, req);

	wd_comp_setting.driver->comp_sync(h_ctx, req);

	return 0;
}

int wd_comp_acompress(handle_t sess, struct wd_comp_req *req)
{
	struct wd_ctx_config *config = &wd_comp_setting.config;
	void *sched_ctx = wd_comp_setting.sched_ctx;
	handle_t h_ctx;

	h_ctx = wd_comp_setting.sched.pick_next_ctx(config, sched_ctx, req);

	wd_put_req_into_pool(&wd_comp_setting.pool, req);

	wd_comp_setting.driver->comp_async(h_ctx, req);

	return 0;
}

__u32 wd_comp_poll(void)
{
	struct wd_ctx_config *config = &wd_comp_setting.config;
	void *sched_ctx = wd_comp_setting.sched_ctx;

	wd_comp_setting.sched.poll_policy(config, sched_ctx);

	return 0;
}

__u32 wd_comp_poll_ctx(handle_t ctx, __u32 num)
{
	struct wd_comp_req req, *req_p;

	wd_comp_setting.driver->comp_recv_async(ctx, &req);

	req_p = wd_get_req_from_pool(&wd_comp_setting.pool, req);

	req_p->cb(0);

	return 0;
}
