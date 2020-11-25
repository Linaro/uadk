/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include "bmm_test.h"
#include "../../wd.h"
#include "../../wd_bmm.h"
#include "../../wd_rsa.h"
#include "../../wd_dh.h"

//#define USERS

void *wd_alloc_test();
void *wd_getfreeNum_test();
void *wd_blk_alloc_failures_test();
void *my_alloc(void *usr, size_t size);
void *my_dma_map(void *usr, void *va, size_t sz);

struct wd_blkpool *pool;

int test_alloc_free(unsigned int blk_sz, unsigned short blk_num,
		    unsigned short align_sz);

int main(int argc, char *argv[])
{
	if (argc != 4) {
		printf("u can input ur own params,like this:\n");
		printf("%s blk_sz blk_num align_sz\n", argv[0]);

		printf("now we go as:\n %s 64, 64, 64\n\n", argv[0]);
		test_alloc_free(64, 64, 64);
		return 0;
	}

	unsigned int blk_sz = atoi(argv[1]);
	unsigned short blk_num = atoi(argv[2]);
	unsigned short align_sz = atoi(argv[3]);

	test_alloc_free(blk_sz, blk_num, align_sz);

	return 0;
}

int test_alloc_free(unsigned int blk_sz, unsigned short blk_num,
		    unsigned short align_sz)
{
	struct wd_blkpool_setup wsetup;
	pthread_t pid[64];
	struct wd_queue q;
	int ret = 0;
	int i = 0;

	memset((void *)&q, 0, sizeof(q));
	q.capa.alg = "rsa";
	ret = wd_request_queue(&q);
	if (ret) {
		printf("request queue fail!\n");
		return ret;
	}

	memset(&wsetup, 0, sizeof(wsetup));
	wsetup.block_size = blk_sz; //key_size;
	wsetup.block_num = blk_num;
	wsetup.align_size = align_sz;

#ifdef USERS
	/* for user's memory */
	wsetup.ops.alloc = (void *)my_alloc;
	wsetup.ops.dma_map = (void *)my_dma_map;
#endif

	pool = wd_blkpool_create(&q, &wsetup);
	if (!pool) {
		printf("%s(): create ctx pool fail!\n", __func__);
		goto release_q;
	}

	ret = pthread_create(&pid[0], NULL, wd_getfreeNum_test, NULL);
	if (ret != 0)
		printf("can't create thread: %s\n", strerror(ret));

	ret = pthread_create(&pid[1], NULL, wd_blk_alloc_failures_test, NULL);
	if (ret != 0)
		printf("can't create thread: %s\n", strerror(ret));

	for (i = 3; i < 64; i++) {
		ret = pthread_create(&pid[i], NULL, wd_alloc_test, NULL);
		if (ret != 0)
			printf("can't create thread: %s\n", strerror(ret));

		sleep(1);
	}

	while (1)
		sleep(1);

	for (i = 0; i < 64; i++)
		pthread_join(pid[i], NULL);

release_q:
	wd_release_queue(&q);

	return 0;
}

void *wd_alloc_test()
{
	void *blk;

	while (1) {
		blk = wd_alloc_blk(pool);
		printf("---alloc blk = %p\n", blk);

		printf("dma_map %p = %p\n", blk, wd_blk_dma_map(pool, blk));

		sleep(3);
		if (blk) {
			wd_free_blk(pool, blk);
			printf("--- now free blk = 0x%p\n", blk);
		}
	sleep(2);
	}
}

void *wd_getfreeNum_test()
{
	int num = 0;

	while (1) {
		num = wd_get_free_blk_num(pool);
		printf("free num = %d\n", num);
		sleep(1);
	}
}

void *wd_blk_alloc_failures_test()
{
	int num;

	while (1) {
		num = wd_blk_alloc_failures(pool);
		printf("alloc_fail_num = %d\n", num);
		sleep(1);
	}
}

void *my_alloc(void *usr, size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (!ptr)
		return NULL;

	return ptr;
}

void *my_dma_map(void *usr, void *va, size_t sz)
{
	return NULL;
}
