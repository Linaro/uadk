/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_COMP_H
#define __WD_COMP_H

#include <stdbool.h>

#include "wd.h"
#include "wd_alg_common.h"

enum wd_comp_alg_type {
	WD_DEFLATE,
	WD_ZLIB,
	WD_GZIP,
	WD_LZ77_ZSTD,
	WD_COMP_ALG_MAX,
};

enum wd_comp_op_type {
	WD_DIR_COMPRESS,	/* session for compression */
	WD_DIR_DECOMPRESS,	/* session for decompression */
};

enum wd_comp_level {
	WD_COMP_L1 = 1, /* Compression level 1 */
	WD_COMP_L2,     /* Compression level 2 */
	WD_COMP_L3,     /* Compression level 3 */
	WD_COMP_L4,     /* Compression level 4 */
	WD_COMP_L5,     /* Compression level 5 */
	WD_COMP_L6,     /* Compression level 6 */
	WD_COMP_L7,     /* Compression level 7 */
	WD_COMP_L8,     /* Compression level 8 */
	WD_COMP_L9,     /* Compression level 9 */
};

enum wd_comp_winsz_type {
	WD_COMP_WS_4K,  /* 4k bytes window size */
	WD_COMP_WS_8K,  /* 8k bytes window size */
	WD_COMP_WS_16K, /* 16k bytes window size */
	WD_COMP_WS_32K, /* 32k bytes window size */
};

struct wd_comp_req;

typedef void *wd_alg_comp_cb_t(struct wd_comp_req *req, void *cb_param);

struct wd_comp_req {
	union {
		void			*src;
		struct wd_datalist	*list_src;
	};
	__u32			src_len;
	union {
		void			*dst;
		struct wd_datalist	*list_dst;
	};
	__u32			dst_len;
	wd_alg_comp_cb_t	*cb;
	void			*cb_param;
	__u8			op_type;     /* denoted by wd_comp_op_type */
	__u8			data_fmt;    /* denoted by wd_buff_type */
	__u32			last;
	__u32			status;
	void			*priv;
};

/**
 * The output format defined by hardware and drivers should fill the format
 * @literals_start:address of the literals data output by the hardware
 * @sequences_start:address of the sequences data output by the hardware
 * @lit_num:the size of literals
 * @seq_num:the size of sequences
 * @lit_length_overflow_cnt:the count of the literal length overflow
 * @lit_length_overflow_pos:the position of the literal length overflow
 * @freq:address of the frequency about sequences members
 */
struct wd_lz77_zstd_data {
	void *literals_start;
	void *sequences_start;
	__u32 lit_num;
	__u32 seq_num;
	__u32 lit_length_overflow_cnt;
	__u32 lit_length_overflow_pos;
	void *freq;
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

struct wd_comp_sess_setup {
	enum wd_comp_alg_type alg_type; /* Denoted by enum wd_comp_alg_type */
	enum wd_comp_level comp_lv; /* Denoted by enum wd_comp_level */
	enum wd_comp_winsz_type win_sz; /* Denoted by enum wd_comp_winsz_type */
	enum wd_comp_op_type op_type;
	enum wd_ctx_mode mode;
};

/**
 * wd_comp_alloc_sess() - Allocate a wd comp session.
 * @setup:	Parameters to setup this session.
 */
extern handle_t wd_comp_alloc_sess(struct wd_comp_sess_setup *setup);

/**
 * wd_comp_free_sess() - Free  a wd comp session.
 * @h_sess: The sess to be freed.
 */
extern void wd_comp_free_sess(handle_t h_sess);

/**
 * wd_do_comp_sync() - Send a sync compression request.
 * @h_sess:	The session which request will be sent to.
 * @req:	Request.
 */
extern int wd_do_comp_sync(handle_t h_sess, struct wd_comp_req *req);

extern int wd_do_comp_strm(handle_t h_sess, struct wd_comp_req *req);


/**
 * wd_do_comp_async() - Send an async compression request.
 * @h_sess:	The session which request will be sent to.
 * @req:	Request.
 */
extern int wd_do_comp_async(handle_t h_sess, struct wd_comp_req *req);

/**
 * wd_comp_poll_ctx() - Poll a ctx.
 * @index:	The index of ctx which will be polled.
 * @expt:	Max number of requests to poll. If 0, polled all finished
 * 		requests in this ctx.
 * @count:	Return the number of polled requests finally.
 *
 * This is a help function which can be used by user's poll_policy function.
 * User defines polling policy in poll_policiy, when it needs to poll a
 * specific ctx, this function should be used.
 */
extern int wd_comp_poll_ctx(__u32 index, __u32 expt, __u32 *count);

extern int wd_comp_poll(__u32 expt, __u32 *count);

/**
 * wd_do_comp_sync2() - advanced sync compression interface, can do u32 size input.
 * @h_sess:	The session which request will be sent to.
 * @req:	Request.
 */
extern int wd_do_comp_sync2(handle_t h_sess, struct wd_comp_req *req);


#endif /* __WD_COMP_H */
