/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_COMP_H
#define __WD_COMP_H

#include "config.h"
#include "wd.h"

typedef void *wd_alg_comp_cb_t(void *cb_param);

struct wd_alg_comp;

#define MODE_STREAM		(1 << 0)
#define MODE_INITED		(1 << 1)

#define FLAG_DEFLATE		(1 << 0)
#define FLAG_INPUT_FINISH	(1 << 1)

#define STATUS_OUT_READY	(1 << 0)	// data is ready in OUT buffer
#define STATUS_OUT_DRAINED	(1 << 1)	// all data is drained out
#define STATUS_IN_PART_USE	(1 << 2)
#define STATUS_IN_EMPTY		(1 << 3)

struct wd_comp_sess {
	char			*alg_name;	/* zlib or gzip */
	char			node_path[MAX_DEV_NAME_LEN + 1];
	wd_dev_mask_t		*dev_mask;
	struct wd_alg_comp	*drv;
	uint32_t		mode;
	void			*priv;
};

struct wd_comp_arg {
	void			*src;
	size_t			src_len;
	void			*dst;
	size_t			dst_len;
	wd_alg_comp_cb_t	*cb;
	void			*cb_param;
	uint32_t		flag;
	uint32_t		status;
};

struct wd_comp_strm {
	struct wd_comp_arg	arg;
	void			*in;
	void			*out;
	size_t			in_sz;		/* size of IN */
	/*
	 * Available size in OUT before compress or decompress.
	 * Used size in OUT after compress or decompress.
	 */
	size_t			out_sz;
	size_t			total_out;
};

struct wd_alg_comp {
	char	*drv_name;
	char	*alg_name;
	int	(*init)(struct wd_comp_sess *sess);
	void	(*exit)(struct wd_comp_sess *sess);
	int	(*prep)(struct wd_comp_sess *sess, struct wd_comp_arg *arg);
	void	(*fini)(struct wd_comp_sess *sess);
	int	(*deflate)(struct wd_comp_sess *sess, struct wd_comp_arg *arg);
	int	(*inflate)(struct wd_comp_sess *sess, struct wd_comp_arg *arg);
	int	(*async_poll)(struct wd_comp_sess *sess,
			      struct wd_comp_arg *arg);
	int	(*strm_deflate)(struct wd_comp_sess *sess,
				struct wd_comp_strm *strm);
	int	(*strm_inflate)(struct wd_comp_sess *sess,
				struct wd_comp_strm *strm);
};

extern handle_t wd_alg_comp_alloc_sess(char *alg_name, uint32_t mode,
					wd_dev_mask_t *dev_mask);
extern void wd_alg_comp_free_sess(handle_t handle);
extern int wd_alg_compress(handle_t handle, struct wd_comp_arg *arg);
extern int wd_alg_decompress(handle_t handle, struct wd_comp_arg *arg);
extern int wd_alg_strm_compress(handle_t handle, struct wd_comp_strm *strm);
extern int wd_alg_strm_decompress(handle_t handle, struct wd_comp_strm *strm);

#endif /* __WD_COMP_H */
