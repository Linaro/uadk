// SPDX-License-Identifier: GPL-2.0
#include "../config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "../wd.h"
#include "wd_dummy_usr_if.h"
#include "dummy_hw_usr_if.h"

#define CPSZ 4096

#define SYS_ERR_COND(cond, msg) if(cond) { \
	perror(msg); \
	exit(EXIT_FAILURE); }

void *shm;

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

int wd_dummy_request_memcpy_queue(struct wd_queue *q, int max_copy_size)
{
	q->capa.alg = "memcpy";
	return wd_request_queue(q);
}

static void test_fork() {
	pid_t pid = fork();

	SYS_ERR_COND(pid<0, "fork");

	if (!pid) {
		sleep(1);
		exit(0);
	}
}

static void _do_test(struct wd_queue *q)
{
	int ret, i;
	char *s, *t;

	//init user data (to be copied)
	s = shm;
	SYS_ERR_COND(!s, "malloc saddr");
	memset(s, 'x', CPSZ);

	t = shm+CPSZ;
	SYS_ERR_COND(!t, "malloc taddr");
	memset(t, 'y', CPSZ);

	test_fork();

	ret = wd_dummy_memcpy(q, t, s, CPSZ);
	SYS_ERR_COND(ret, "acce cpy");

	//verify result
	for (i = 0; i < CPSZ; i++) {
		if(t[i] != 'x') {
			printf("verify result fail on %d\n", i);
			break;
		}

	}

	if (i == CPSZ)
		printf("test success\n");
}

#define REP_TEST 2
int main(int argc, char *argv[])
{
	struct wd_queue q;
	int ret, i;

	ret = wd_dummy_request_memcpy_queue(&q, 4096);
	SYS_ERR_COND(ret, "wd_request_queue");

	shm = wd_reserve_memory(&q, CPSZ*4);
	SYS_ERR_COND(!shm, "preserve memory");

	for (i = 0; i < REP_TEST; i++)
		_do_test(&q);

	wd_release_queue(&q);

	return EXIT_SUCCESS;
}
