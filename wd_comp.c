/* SPDX-License-Identifier: Apache-2.0 */
#include <dirent.h>
#include <errno.h>
#include <string.h>

#include "drv/hisi_comp.h"
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
		.deflate	= hisi_comp_deflate,
		.inflate	= hisi_comp_inflate,
		.async_poll	= hisi_comp_poll,
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

handler_t wd_alg_comp_alloc_sess(char *alg_name, wd_dev_mask_t *dev_mask)
{
	struct uacce_dev_list	*head = NULL, *p, *prev;
	wd_dev_mask_t		*mask = NULL;
	struct wd_comp_sess	*sess = NULL;
	int	i, found, max = 0, ret;
	char	*dev_name;

	mask = malloc(sizeof(wd_dev_mask_t));
	if (!mask)
		return (handler_t)sess;
	head = list_accels(mask);
	if (!head) {
		WD_ERR("Failed to get any accelerators in system!\n");
		return (handler_t)sess;
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
			clear_mask(mask, p->info->node_id);
			RM_NODE(head, prev, p);
		}
	}
	for (p = head, i = 0; p; p = p->next) {
		/* mount driver */
		dev_name = get_accel_name(p->info->dev_root, 1);
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
	sess = malloc(sizeof(struct wd_comp_sess));
	if (!sess)
		goto out;
	sess->alg_name = strdup(alg_name);
	dev_name = get_accel_name(p->info->dev_root, 0);
	snprintf(sess->node_path, MAX_DEV_NAME_LEN, "/dev/%s", dev_name);
	free(dev_name);
	sess->dev_mask = mask;
	sess->drv = &wd_alg_comp_list[i];
	ret = sess->drv->init(sess);
	if (ret)
		WD_ERR("fail to init session (%d)\n", ret);
out:
	while (head) {
		p = head;
		head = head->next;
		free(p);
	}
	return (handler_t)sess;
}

void wd_alg_comp_free_sess(handler_t handle)
{
	struct wd_comp_sess	*sess = (struct wd_comp_sess *)handle;

	sess->drv->exit(sess);
	free(sess->dev_mask->mask);
	free(sess->dev_mask);
	free(sess);
}

int wd_alg_compress(handler_t handler, struct wd_comp_arg *arg)
{
	struct wd_comp_sess	*sess = (struct wd_comp_sess *)handler;

	return sess->drv->deflate(sess, arg);
}

int wd_alg_decompress(handler_t handler, struct wd_comp_arg *arg)
{
	struct wd_comp_sess	*sess = (struct wd_comp_sess *)handler;

	return sess->drv->inflate(sess, arg);
}
