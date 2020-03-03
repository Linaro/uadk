/* SPDX-License-Identifier: Apache-2.0 */
#include <dirent.h>
#include <errno.h>
#include <string.h>

#include "drv/hisi_comp.h"
#include "wd_comp.h"

#define SYS_CLASS_DIR	"/sys/class/uacce"

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

/* remove node p */
static inline void rm_node(struct uacce_dev_list *head,
			   struct uacce_dev_list *prev,
			   struct uacce_dev_list *p)
{
	if (!prev) {
		head = p->next;
		free(p);
		p = head->next;
	} else if (p->next) {
		prev->next = p->next;
		free(p);
		p = p->next;
	} else {
		free(p);
		p = NULL;
		prev->next = p;
	}
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
	struct uacce_dev_list	*head, *p, *prev;
	wd_dev_mask_t		accel_mask;
	struct wd_comp_sess	*sess = NULL;
	int	i, found, max = 0;

	head = wd_list_accels(&accel_mask);
	if (!head) {
		WD_ERR("Failed to get any accelerators in system!\n");
		goto out;
	}
	/* merge two masks */
	if (dev_mask && (dev_mask->magic == WD_DEV_MASK_MAGIC) &&
	    dev_mask->len && (dev_mask->len <= accel_mask.len)) {
		for (i = 0; i < accel_mask.len; i++)
			accel_mask.mask[i] &= dev_mask->mask[i];
	}
	for (p = head, prev = NULL; p; ) {
		if (!is_accel_avail(&accel_mask, p->info->node_id)) {
			rm_node(head, prev, p);
			continue;
		}
		found = match_alg_name(head->info->algs, alg_name);
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
			/* the mask bit isn't cleared temporarly */
			//wd_clear_mask(&accel_mask, head->info->node_id);
			rm_node(head, prev, p);
		}
	}
	for (p = head, i = 0; p; p = p->next) {
		printf("p node:%d, instan:%d, name:%s, alg_path:%s, dev_root:%s\n", p->info->node_id, p->info->avail_instn, p->info->name, p->info->alg_path, p->info->dev_root);
		/* mount driver */
	}
out:
	return (handler_t)sess;
}
