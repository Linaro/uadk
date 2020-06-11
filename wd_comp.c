/* SPDX-License-Identifier: Apache-2.0 */
#include <dirent.h>
#include <errno.h>
#include <string.h>

#include "hisi_comp.h"
#include "wd_comp.h"
#include "wd_alg_common.h"

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

handle_t wd_alg_comp_alloc_sess(char *alg_name, uint32_t mode,
				 wd_dev_mask_t *dev_mask)
{
	struct uacce_dev_list	*head = NULL, *p, *prev;
	wd_dev_mask_t		*mask = NULL;
	struct wd_comp_sess	*sess = NULL;
	int	i, found, max = 0, ret;
	char	*dev_name;

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
	if (sess->drv->init) {
		ret = sess->drv->init(sess);
		if (ret)
			WD_ERR("fail to init session (%d)\n", ret);
	}
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
