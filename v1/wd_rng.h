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

#ifndef __WD_RNG_H
#define __WD_RNG_H

#define WD_RNG_CTX_MSG_NUM	256

struct wcrypto_rng_ctx_setup {
	wcrypto_cb cb;		/* call back function from user */
};

struct wcrypto_rng_msg {
	__u8 *out;		/* Result address */
	__u64 usr_tag;
	int tag;
	__u32 out_bytes;	/* output bytes */
	__u32 in_bytes;		/* input bytes */
	__u8 alg_type;		/* Denoted by enum wcrypto_type */
};

struct wcrypto_rng_op_data {
	void *out;		/* output */
	__u32 in_bytes;		/* input bytes */
	__u32 out_bytes;	/* output bytes */
};

void *wcrypto_create_rng_ctx(struct wd_queue *q,
				struct wcrypto_rng_ctx_setup *setup);
void wcrypto_del_rng_ctx(void *ctx);
int wcrypto_do_rng(void *ctx, struct wcrypto_rng_op_data *opdata, void *tag);
int wcrypto_rng_poll(struct wd_queue *q, unsigned int num);

#endif
