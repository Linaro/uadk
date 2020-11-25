/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __WD_DH_H
#define __WD_DH_H

#include <stdlib.h>
#include <errno.h>

enum wcrypto_dh_op_type {
	WCRYPTO_DH_INVALID,
	WCRYPTO_DH_PHASE1,
	WCRYPTO_DH_PHASE2,
};

struct wcrypto_dh_ctx_setup {
	wcrypto_cb cb;
	__u16 data_fmt;
	__u16 key_bits;
	bool is_g2;
	struct wd_mm_ops ops;
};

struct wcrypto_dh_op_data {
	void *x_p; /* x and p */

	/* it is PV at phase 2 */
	void *pv;

	/* phase 1&&2 output */
	void *pri;
	__u16 pri_bytes;

	__u16 pbytes;
	__u16 xbytes;
	__u16 pvbytes;
	enum wcrypto_dh_op_type op_type;
	__u32 status;
};

struct wcrypto_dh_msg {
	__u8 alg_type:3;	/* Denoted by enum wcrypto_type */
	__u8 op_type:2;	/* Denoted by enum wcrypto_dh_op_type */
	__u8 data_fmt:1;	/* Data format, denoted by enum wd_buff_type */
	__u8 is_g2:2;	/* g2 mode of phase 1 */
	__u8 result;	/* Data format, denoted by enum wcrypto_op_result */
	__u16 key_bytes;	/* Key size */
	__u8 *x_p;	/* This is Xa and p data in order. */
	__u8 *g;		/* This is PV also at phase 2. */
	__u8 *out;	/* Result address */
	__u16 xbytes;	/* parameter Xa size */
	__u16 pbytes;	/* parameter p size */
	__u16 gbytes;	/* parameter g size */
	__u16 out_bytes;	/* output parameter size */
	__u64 usr_data;	/* user identifier */
};


void *wcrypto_create_dh_ctx(struct wd_queue *q, struct wcrypto_dh_ctx_setup *setup);
bool wcrypto_dh_is_g2(void *ctx);
int wcrypto_dh_key_bits(void *ctx);

/* Asynchronous/sync mode APIs of DH */
int wcrypto_do_dh(void *ctx, struct wcrypto_dh_op_data *opdata, void *tag);
int wcrypto_dh_poll(struct wd_queue *q, unsigned int num);
void wcrypto_del_dh_ctx(void *ctx);
int wcrypto_set_dh_g(void *ctx, struct wd_dtb *g);
void wcrypto_get_dh_g(void *ctx, struct wd_dtb **g);
#endif
