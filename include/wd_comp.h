/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_COMP_H
#define __WD_COMP_H

#include <stdbool.h>

#include "config.h"
#include "wd.h"
#include "wd_alg_common.h"

#define MODE_STREAM		(1 << 0)
#define MODE_INITED		(1 << 1)

#define FLAG_DEFLATE		(1 << 0)
#define FLAG_INPUT_FINISH	(1 << 1)

/*
 * Status in request.
 * HW occupies the lower 16-bit, and SW occupies the higher 16-bit.
 */
#define STATUS_HW_MASK		0xFFFF
#define STATUS_OUT_READY	(1 << 16)	// data is ready in OUT buffer
#define STATUS_OUT_DRAINED	(1 << 17)	// all data is drained out
#define STATUS_IN_PART_USE	(1 << 18)
#define STATUS_IN_EMPTY		(1 << 19)

enum {
	CTX_TYPE_COMP = 0,
	CTX_TYPE_DECOMP,
};

enum wd_comp_mode {
	CTX_MODE_SYNC = 0,
	CTX_MODE_ASYNC,
};

enum wd_comp_alg_type {
	WD_ZLIB = 1,
	WD_GZIP,
};

enum wd_comp_op_type {
	WD_DIR_COMPRESS,	/* session for compression */
	WD_DIR_DECOMPRESS,	/* session for decompression */
};

struct wd_comp_sess {
	int	alg_type;
	__u8	*ctx_buf;
	__u8	stream_pos;
};

struct wd_comp_req;

typedef void *wd_alg_comp_cb_t(struct wd_comp_req *req, void *cb_param);

struct wd_comp_req {
	void			*src;
	size_t			src_len;
	void			*dst;
	size_t			dst_len;
	wd_alg_comp_cb_t	*cb;
	void			*cb_param;
	__u8			op_type;     /* denoted by wd_comp_op_type */
	uint32_t		flag;
	uint32_t		last;
	uint32_t		status;
};


/**
 * struct wd_comp_sched - Define a scheduler.
 * @name:		Name of this scheduler.
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
	handle_t (*pick_next_ctx)(struct wd_ctx_config *config, void *req, void *key);
	__u32 (*poll_policy)( struct wd_ctx_config *config);
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
	int alg_type;	// ZLIB or GZIP
	enum wd_comp_mode mode;
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


extern int wd_do_comp_sync(handle_t sess, struct wd_comp_req *req);

extern int wd_do_comp_strm(handle_t sess, struct wd_comp_req *req);

extern int wd_do_comp_async(handle_t h_sess, struct wd_comp_req *req);

extern int wd_comp_poll(__u32 *count);


/**
 * wd_do_comp() - Send a sync compression request.
 * @sess:	The session which request will be sent to.
 * @req:	Request.
 */
extern int wd_do_comp(handle_t sess, struct wd_comp_req *req);

/**
 * wd_do_comp_async() - Send an async compression request.
 * @sess:	The session which request will be sent to.
 * @req:	Request.
 */
extern int wd_do_comp_async(handle_t sess, struct wd_comp_req *req);

/**
 * wd_comp_poll() - Poll finished request.
 *
 * This function will call poll_policy function which is registered to wd comp
 * by user.

extern __u32 wd_comp_poll(void);
*/


/**
 * wd_comp_poll_ctx() - Poll a ctx.
 * @ctx:	The ctx which will be polled.
 * @expt:	Max number of requests to poll. If 0, polled all finished
 * 		requests in this ctx.
 * @count:	Return the number of polled requests finally.
 *
 * This is a help function which can be used by user's poll_policy function.
 * User defines polling policy in poll_policiy, when it needs to poll a
 * specific ctx, this function should be used.
 */
extern int wd_comp_poll_ctx(handle_t ctx, __u32 expt, __u32 *count);

#endif /* __WD_COMP_H */
