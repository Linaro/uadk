/*
 * Copyright 2018-2019 Huawei Technologies Co.,Ltd.All rights reserved.
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

#include "../config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "wd_sched.h"
#include "wd_dummy_usr_if.h"
#include "dummy_hw_usr_if.h"

#define CPSZ 4096

#define SYS_ERR_COND(cond, msg) if(cond) { \
	perror(msg); \
	exit(EXIT_FAILURE); }

struct wd_dummy_cpy_msg *msgs;

int wd_dummy_memcpy(struct wd_queue *q, void *dst, void *src, size_t size)
{
	struct wd_dummy_cpy_msg req, *resp;
	int ret;

	req.src_addr = src;
	req.tgt_addr = dst;
	req.size = size;

	ret = wd_send(q, (void *)&req);
	if (ret)
		return ret;

	return wd_recv_sync(q, (void **)&resp, 1000);
}

static void wd_dummy_sched_init_cache(struct wd_scheduler *sched, int i)
{
	sched->msgs[i].msg = &msgs[i];
	msgs[i].src_addr = sched->msgs[i].data_in;
	msgs[i].tgt_addr = sched->msgs[i].data_out;
	msgs[i].size = sched->msg_data_size;
}

static int input_num = 10;
static int wd_dummy_sched_input(struct wd_msg *msg, void *priv)
{
	SYS_ERR_COND(input_num <= 0, "input");
	input_num--;
	memset(msg->data_in, '0'+input_num, CPSZ);
	memset(msg->data_out, 'x', CPSZ);

	return 0;
}

static int wd_dummy_sched_output(struct wd_msg *msg, void *priv)
{
	int i;
	char *in, *out;

	for (i = 0; i < CPSZ; i++) {
		in = (char *)msg->data_in;
		out = (char *)msg->data_out;
		if(in[i] != out[i]) {
			printf("verify result fail on %d\n", i);
			break;
		}

	}
	printf("verify result (%d) success (remained=%d)\n", in[0], input_num);

	return 0;
}

struct wd_scheduler sched = {
	.q_num = 1,
	.ss_region_size = 0,
	.msg_cache_num = 4,
	.msg_data_size = CPSZ,
	.init_cache = wd_dummy_sched_init_cache,
	.input = wd_dummy_sched_input,
	.output = wd_dummy_sched_output,
};

int main(int argc, char *argv[])
{
	int ret, i;
	int max_step = 20;

	sched.qs = calloc(sched.q_num, sizeof(*sched.qs));
	SYS_ERR_COND(!sched.qs, "calloc");

	msgs = calloc(sched.msg_cache_num, sizeof(*msgs));
	SYS_ERR_COND(!msgs, "calloc");

	for (i = 0; i < sched.q_num; i++)
		sched.qs[i].capa.alg = "memcpy";

	ret = wd_sched_init(&sched);
	SYS_ERR_COND(ret, "wd_sched_init");

	while(input_num || !wd_sched_empty(&sched)) {
		ret = wd_sched_work(&sched, input_num);
		SYS_ERR_COND(ret < 0, "wd_sched_work");
		SYS_ERR_COND(max_step-- < 0, "max_step");
	}

	wd_sched_fini(&sched);
	free(sched.qs);
	return EXIT_SUCCESS;
}
