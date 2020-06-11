/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_ALG_COMMON_H
#define __WD_ALG_COMMON_H

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

enum wd_buff_type {
	WD_BUF_NONE,
	WD_FLAT_BUF,
	WD_SGL_BUF,
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
#endif /* __WD_ALG_COMMON_H */
