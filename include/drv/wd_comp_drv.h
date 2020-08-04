/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_COMP_DRV_H
#define __WD_COMP_DRV_H

#include "../wd_comp.h"

/* fixme wd_comp_msg */
struct wd_comp_msg {
	struct wd_comp_req req;
	__u32 tag_id;
	__u8 alg_type;   /* Denoted by enum wcrypto_comp_alg_type */
	__u8 op_type;    /* Denoted by enum wcrypto_comp_op_type */
	__u8 flush_type; /* Denoted by enum wcrypto_comp_flush_type */
	__u8 stream_mode;/* Denoted by enum wcrypto_comp_state */
	__u8 stream_pos; /* Denoted by enum wcrypto_stream_status */
	__u8 comp_lv;    /* Denoted by enum wcrypto_comp_level */
	__u8 data_fmt;   /* Data format, denoted by enum wd_buff_type */
	__u8 win_sz;     /* Denoted by enum wcrypto_comp_win_type */
	__u32 in_size;   /* Input data bytes */
	__u32 avail_out; /* Output buffer size */
	__u32 in_cons;   /* consumed bytes of input data */
	__u32 produced;  /* produced bytes of current operation */
	__u8 *src;       /* Input data VA, buf should be DMA-able. */
	__u8 *dst;       /* Output data VA pointer */
	__u32 tag;       /* User-defined request identifier */
	__u32 win_size;  /* Denoted by enum wcrypto_comp_win_type */
	__u32 status;    /* Denoted by error code and enum wcrypto_op_result */
	__u32 isize;	 /* Denoted by gzip isize */
	__u32 checksum;  /* Denoted by zlib/gzip CRC */
	__u32 ctx_priv0; /* Denoted HW priv */
	__u32 ctx_priv1; /* Denoted HW priv */
	__u32 ctx_priv2; /* Denoted HW priv */
	void *ctx_buf;   /* Denoted HW ctx cache, for stream mode */
	__u64 udata;     /* Input user tag, indentify data of stream/user */
};

struct wd_comp_driver {
	const char *drv_name;
	const char *alg_name;
	__u32 drv_ctx_size;
	int (*init)(struct wd_ctx_config *config, void *priv);
	void (*exit)(void *priv);
	int (*comp_send)(handle_t ctx, struct wd_comp_msg *msg);
	int (*comp_recv)(handle_t ctx, struct wd_comp_msg *msg);
};

void wd_comp_set_driver(struct wd_comp_driver *drv);

#define WD_COMP_SET_DRIVER(drv)						      \
extern const struct wd_comp_driver wd_comp_##drv __attribute__((alias(#drv)));\
static void __attribute__((constructor)) set_driver(void)		      \
{									      \
	wd_comp_set_driver(&drv);					      \
}

#endif /* __WD_COMP_DRV_H */
