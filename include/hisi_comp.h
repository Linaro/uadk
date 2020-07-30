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

/*
 * to do: put wd_comp_msg temporarily, should be move to a internal head file
 *        together with wd_comp_driver definition.
 */
struct wd_comp_msg {};

extern int hisi_zip_init(struct wd_ctx_config *config, void *priv);
extern void hisi_zip_exit(void *priv);
extern int hisi_zip_comp_send(handle_t ctx, struct wd_comp_msg *msg);
extern int hisi_zip_comp_recv(handle_t ctx, struct wd_comp_msg *msg);

#endif	/* __HISI_COMP_H */
