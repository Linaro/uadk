/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_COMP_H
#define __WD_COMP_H

#include "config.h"
#include "wd.h"

typedef unsigned long long int	handler_t;

struct wd_alg_comp;

struct wd_comp_sess {
	char			*alg_name;	/* zlib or gzip */
	char			node_path[MAX_DEV_NAME_LEN];
	wd_dev_mask_t		dev_mask;
	struct wd_alg_comp	*drv;
	void			*priv;
};

struct wd_alg_comp {
	char	*drv_name;
	char	*alg_name;
	int	(*init)(struct wd_comp_sess *sess);
	void	(*exit)(struct wd_comp_sess *sess);
	int	(*deflate)(struct wd_comp_sess *sess);
	int	(*inflate)(struct wd_comp_sess *sess);
	int	(*async_poll)(struct wd_comp_sess *sess);
};

extern handler_t wd_alg_comp_alloc_sess(char *alg_name,
					wd_dev_mask_t *dev_mask);

#endif /* __WD_COMP_H */
