/* SPDX-License-Identifier: Apache-2.0 */
#ifndef	__HISI_COMP_H
#define	__HISI_COMP_H

#include "hisi_qm_udrv.h"
#include "include/zip_usr_if.h"
#include "smm.h"
#include "wd.h"
#include "wd_comp.h"
#include "wd_sched.h"

#define	ZLIB		0
#define	GZIP		1

#define DEFLATE		0
#define INFLATE		1

#define ASIZE		(2 * 512 * 1024)
#define HW_CTX_SIZE	(64*1024)

extern int hisi_comp_init(struct wd_comp_sess *sess);
extern void hisi_comp_exit(struct wd_comp_sess *sess);
extern int hisi_comp_prep(struct wd_comp_sess *sess,
			  struct wd_comp_arg *arg);
extern int hisi_comp_deflate(struct wd_comp_sess *sess,
			     struct wd_comp_arg *arg);
extern int hisi_comp_inflate(struct wd_comp_sess *sess,
			     struct wd_comp_arg *arg);
extern int hisi_comp_poll(struct wd_comp_sess *sess,
			  struct wd_comp_arg *arg);
extern int hisi_strm_deflate(struct wd_comp_sess *sess,
			     struct wd_comp_strm *strm);
extern int hisi_strm_inflate(struct wd_comp_sess *sess,
			     struct wd_comp_strm *strm);

/* new code */
struct hisi_zip_ctx {
	struct wd_ctx_config	config;
};

extern int hisi_zip_init(struct wd_ctx_config *config, void *priv);
extern void hisi_zip_exit(void *priv);


/*
* to do: put wd_comp_msg temporarily, should be move to a internal head file
*        together with wd_comp_driver definition.
*/
/* fixme wd_comp_msg */
struct wd_comp_msg {
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

extern int hisi_zip_comp_send(handle_t ctx, struct wd_comp_msg *msg);
extern int hisi_zip_comp_recv(handle_t ctx, struct wd_comp_msg *recv_msg);



#endif	/* __HISI_COMP_H */
