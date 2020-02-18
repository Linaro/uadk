// SPDX-License-Identifier: GPL-2.0
#ifndef __WD_INTERNAL_H
#define __WD_INTERNAL_H

#include "wd.h"

struct uacce_dev_info {
	/* sysfs node content */
	int		flags;
	int		avail_instn;
	char		api[WD_NAME_SIZE];
	char		algs[MAX_ATTR_STR_SIZE];
	unsigned long	qfrs_offs[UACCE_QFRT_MAX];

	char		name[WD_NAME_SIZE];
	char		alg_path[PATH_STR_SIZE];
	char		dev_root[PATH_STR_SIZE];

	int		node_id;
	int		iommu_type;
	/*
	int		ref;
	int		is_load;
	*/
};

struct wd_drv {
	char	drv_name[MAX_DEV_NAME_LEN];
	int	(*alloc_ctx)(struct wd_ctx *ctx);
	void	(*free_ctx)(struct wd_ctx *ctx);
	int	(*send)(struct wd_ctx *ctx, void *req);
	int	(*recv)(struct wd_ctx *ctx, void **resp);
};

extern struct uacce_dev_info *read_uacce_sysfs(char *dev_name);

extern int hisi_qm_alloc_ctx(struct wd_ctx *ctx);
extern void hisi_qm_free_ctx(struct wd_ctx *ctx);
extern int hisi_qm_send(struct wd_ctx *ctx, void *req);
extern int hisi_qm_recv(struct wd_ctx *ctx, void **resp);

#endif /* __WD_INTERNAL_H */
