/* SPDX-License-Identifier: Apache-2.0 */
#include "hisi_sec.h"
#include "wd_digest.h"

struct wd_alg_digest {
	char	*drv_name;
	char	*alg_name;
	int	(*init)(struct wd_digest_sess *sess);
	void	(*exit)(struct wd_digest_sess *sess);
	int	(*prep)(struct wd_digest_sess *sess, struct wd_digest_arg *arg);
	void	(*fini)(struct wd_digest_sess *sess);
	int	(*set_key)(struct wd_digest_sess *sess, const __u8 *key, __u32 key_len);
	int	(*digest)(struct wd_digest_sess *sess, struct wd_digest_arg *arg);
	int	(*async_poll)(struct wd_digest_sess *sess, struct wd_digest_arg *arg);
} wd_alg_digest_list[] = {
	{
		.drv_name	= "hisi_sec",
		.alg_name	= "digest",
		.init		= hisi_digest_init,
		.exit		= hisi_digest_exit,
		.prep		= hisi_digest_prep,
		.fini		= hisi_digest_fini,
		.set_key	= hisi_digest_set_key,
		.digest		= hisi_digest_digest,
		.async_poll	= hisi_digest_poll,
	},
};

handle_t wd_alg_digest_alloc_sess(struct wd_digest_sess_setup *setup,
				  wd_dev_mask_t *dev_mask)
{
	struct uacce_dev_list	*head = NULL, *p, *prev;
	wd_dev_mask_t		*mask = NULL;
	struct wd_digest_sess	*sess = NULL;
	int	i, found, max = 0, ret;
	char	*dev_name;

	if (!setup->alg_name)
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
		found = match_alg_name(p->info->algs, setup->alg_name);
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
		for (i = 0; i < ARRAY_SIZE(wd_alg_digest_list); i++) {
			if (!strncmp(dev_name, wd_alg_digest_list[i].drv_name,
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
	sess = calloc(1, (sizeof(struct wd_digest_sess)));
	if (!sess)
		goto out;

	sess->alg = setup->alg;
	sess->mode = setup->mode;
	sess->alg_name = strdup(setup->alg_name);
	dev_name = wd_get_accel_name(p->info->dev_root, 0);
	snprintf(sess->node_path, MAX_DEV_NAME_LEN, "/dev/%s", dev_name);
	free(dev_name);
	sess->dev_mask = mask;
	sess->drv = &wd_alg_digest_list[i];
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

	return 0;
}

void wd_alg_digest_free_sess(handle_t handle)
{
	struct wd_digest_sess *sess = (struct wd_digest_sess *)handle;

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

int wd_alg_do_digest(handle_t handle, struct wd_digest_arg *arg)
{
	struct wd_digest_sess *sess = (struct wd_digest_sess *)handle;

	if (!arg || !sess->drv->digest)
		return -EINVAL;

	return sess->drv->digest(sess, arg);
}

int wd_alg_set_digest_key(handle_t handle, __u8 *key, __u32 key_len)
{
	struct wd_digest_sess *sess = (struct wd_digest_sess *)handle;

	/* fix me: need check key_len */
	if (!key)
		return -EINVAL;

	return sess->drv->set_key(sess, key, key_len);
}

int wd_alg_digest_poll(handle_t handle, __u32 count)
{
	return 0;
}
