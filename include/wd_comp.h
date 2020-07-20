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

enum {
	CTX_TYPE_COMP = 0,
	CTX_TYPE_DECOMP,
};

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

/* new code */
struct wd_comp_req {
	void			*src;
	size_t			src_len;
	void			*dst;
	size_t			dst_len;
	wd_alg_comp_cb_t	*cb;
	void			*cb_param;
	uint32_t		flag;
	uint32_t		status;
};

/**
 * struct wd_comp_ctx - Define one ctx and related type.
 * @ctx:	The ctx itself.
 * @type:	Define this ctx is used for compression or decompression.
 *		0: compression; 1: decompression.
 */
struct wd_comp_ctx {
	handle_t ctx;
	__u8 type;
};

/**
 * struct wd_ctx_config - Define a ctx set and its related attributes, which
 *			  will be used in the scope of current process.
 * @ctx_num:	The ctx number in below ctx array.
 * @ctxs:	Point to a ctx array, length is above ctx_num.
 * @priv:	The attributes of ctx defined by user, which is used by user
 *		defined scheduler.
 */
struct wd_ctx_config {
	int ctx_num;
	struct wd_comp_ctx  *ctxs;
	void *priv;
};

/**
 * struct wd_comp_sched - Define a scheduler.
 * @name:		Name of this scheduler.
 * @sched_ctx_size:	Size of the context of this scheduler. Wd_comp will
 *			allocate this size of memory for scheduler to store
 *			its context data internally.
 * @pick_next_ctx:	Pick the proper ctx which a request will be sent to.
 *			config points to the ctx config; sched_ctx points to
 *			scheduler context; req points to the request. Return
 *			the proper ctx handler.
 *			(fix me: modify req to request?)
 * @poll_policy:	Define the polling policy. config points to the ctx
 *			config; sched_ctx points to scheduler context; Return
 *			number of polled request.
 */
struct wd_sched {
	const char *name;
	__u32 sched_ctx_size;
	handle_t (*pick_next_ctx)(struct wd_ctx_config *config,
				  void *sched_ctx, struct wd_comp_req *req);
	__u32 (*poll_policy)( struct wd_ctx_config *config, void *sched_ctx);
};

/**
 * wd_comp_init() - Initialise ctx configuration and scheduler.
 * @ config:	    User defined ctx configuration.
 * @ sched:	    User defined scheduler.
 */
extern int wd_comp_init(struct wd_ctx_config *config, struct wd_sched *sched);

/**
 * wd_comp_uninit() - Un-initialise ctx configuration and scheduler.
 */
extern void wd_comp_uninit(void);

/* fix me: stub to pass compile */
struct wd_comp_sess_setup {
	int mode;	// BLOCK mode or STEAM mode
};
/**
 * wd_comp_alloc_sess() - Allocate a wd comp session.
 * @setup:	Parameters to setup this session.
 */
extern handle_t wd_comp_alloc_sess(struct wd_comp_sess_setup *setup);

/**
 * wd_comp_free_sess() - Free  a wd comp session.
 * @ sess: The sess to be freed.
 */
extern void wd_comp_free_sess(handle_t sess);

/**
 * wd_comp_scompress() - Send a sync compression request.
 * @sess:	The session which request will be sent to.
 * @req:	Request.
 */
extern int wd_comp_scompress(handle_t sess, struct wd_comp_req *req);

/**
 * wd_comp_acompress() - Send an async compression request.
 * @sess:	The session which request will be sent to.
 * @req:	Request.
 */
extern int wd_comp_acompress(handle_t sess, struct wd_comp_req *req);

/**
 * wd_comp_poll() - Poll finished request.
 *
 * This function will call poll_policy function which is registered to wd comp
 * by user.
 */
extern __u32 wd_comp_poll(void);

/**
 * wd_comp_poll_ctx() - Poll a ctx.
 * @ctx:	The ctx which will be polled.
 * @num:	Max number of requests to poll. If 0, polled all finished
 * 		requests in this ctx.
 * Return the number of polled requests finally.
 *
 * This is a help function which can be used by user's poll_policy function.
 * User defines polling policy in poll_policiy, when it needs to poll a
 * specific ctx, this function should be used.
 */
extern __u32 wd_comp_poll_ctx(handle_t ctx, __u32 num);

#endif /* __WD_COMP_H */
