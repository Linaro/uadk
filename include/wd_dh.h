/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_DH_H
#define __WD_DH_H

#include <stdbool.h>

#include "wd.h"
#include "wd_alg_common.h"

#define BYTE_BITS			8
#define BYTE_BITS_SHIFT			3
#define GET_NEGATIVE(val)		(0 - (val))

typedef void (*wd_dh_cb_t)(void *cb_param);

enum wd_dh_op_type {

	WD_DH_INVALID, /* invalid DH operation */
	WD_DH_PHASE1, /* Phase1 DH key generate */
	WD_DH_PHASE2 /* Phase2 DH key compute */
};

struct wd_dh_sess_setup {
	__u16 key_bits; /* DH key bites */
	bool is_g2; /* is g2 mode or not */
	__u8 mode; /* sync or async mode, denoted by enum wd_ctx_mode */
};

struct wd_dh_req {
	void *x_p; /* x and p*/

	/* it is g, but it is PV at phase 2 */
	void *pv;

	/* phase 1&&2 output */
	void *pri;
	__u16 pri_bytes; /* output bytes */

	__u16 pbytes; /* p bytes */
	__u16 xbytes; /* x bytes */
	__u16 pvbytes; /* pv bytes */
	wd_dh_cb_t cb;
	void *cb_param;
	int status; /* output status */
	__u8 op_type; /* operational type */
	__u8 data_fmt; /* data format denoted by enum wd_buff_type */
};

int wd_dh_get_mode(handle_t sess, __u8 *alg_mode);
__u32 wd_dh_key_bits(handle_t sess);
int wd_dh_set_g(handle_t sess, struct wd_dtb *g);
void wd_dh_get_g(handle_t sess, struct wd_dtb **g);
handle_t wd_dh_alloc_sess(struct wd_dh_sess_setup *setup);
void wd_dh_free_sess(handle_t sess);
int wd_do_dh_async(handle_t sess, struct wd_dh_req *req);
int wd_do_dh_sync(handle_t sess, struct wd_dh_req *req);
int wd_dh_poll_ctx(__u32 pos, __u32 expt, __u32 *count);
int wd_dh_poll(__u32 expt, __u32 *count);
int wd_dh_init(struct wd_ctx_config *config, struct wd_sched *sched);
void wd_dh_uninit(void);

#endif /* __WD_DH_H */
