/*
 * Copyright 2019 Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __WD_DH_H
#define __WD_DH_H

#include <stdlib.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

enum wcrypto_dh_op_type {
	WCRYPTO_DH_INVALID, /* invalid DH operation */
	WCRYPTO_DH_PHASE1, /* Phase1 DH key generate */
	WCRYPTO_DH_PHASE2 /* Phase2 DH key compute */
};

struct wcrypto_dh_ctx_setup {
	wcrypto_cb cb; /* call back function from user */
	__u16 data_fmt; /* data format denoted by enum wd_buff_type */
	__u16 key_bits; /* DH key bites */
	bool is_g2; /* is g2 mode or not */
	struct wd_mm_br br; /* memory operations from user */
};

struct wcrypto_dh_op_data {
	void *x_p; /* x and p, should be DMA buffer */

	/* it is g, but it is PV at phase 2, should be DMA buffer */
	void *pv;

	/* phase 1&&2 output, should be DMA buffer */
	void *pri;
	__u16 pri_bytes; /* output bytes */

	__u16 pbytes; /* p bytes */
	__u16 xbytes; /* x bytes */
	__u16 pvbytes; /* pv bytes */
	enum wcrypto_dh_op_type op_type; /* operational type */
	__u32 status; /* output status */
};

struct wcrypto_dh_msg {
	__u8 alg_type:3; /* Denoted by enum wcrypto_type */
	__u8 op_type:2; /* Denoted by enum wcrypto_dh_op_type */
	__u8 data_fmt:1; /* Data format, denoted by enum wd_buff_type */
	__u8 is_g2:2; /* g2 mode of phase 1 */
	__u8 result; /* Data format, denoted by WD error code */
	__u16 key_bytes; /* Key size */
	__u8 *x_p; /* This is Xa and p data in order. Should be DMA buffer */
	__u8 *g; /* This is PV also at phase 2. Should be DMA buffer*/
	__u8 *out; /* Result address, should be DMA buffer */
	__u16 xbytes; /* parameter Xa size */
	__u16 pbytes; /* parameter p size */
	__u16 gbytes; /* parameter g size */
	__u16 out_bytes; /* output parameter size */
	__u64 usr_data; /* user identifier: struct wcrypto_cb_tag */
};

void *wcrypto_create_dh_ctx(struct wd_queue *q, struct wcrypto_dh_ctx_setup *setup);
bool wcrypto_dh_is_g2(const void *ctx);
int wcrypto_dh_key_bits(const void *ctx);

/* Asynchronous/sync mode APIs of DH */
int wcrypto_do_dh(void *ctx, struct wcrypto_dh_op_data *opdata, void *tag);
int wcrypto_dh_poll(struct wd_queue *q, unsigned int num);
void wcrypto_del_dh_ctx(void *ctx);
int wcrypto_set_dh_g(void *ctx, struct wd_dtb *g);
void wcrypto_get_dh_g(void *ctx, struct wd_dtb **g);

#ifdef __cplusplus
}
#endif

#endif
