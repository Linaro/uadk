/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __HISI_TEST_HPRE_H
#define __HISI_TEST_HPRE_H



enum alg_op_type {
	HPRE_ALG_INVLD_TYPE,
	RSA_KEY_GEN,
	RSA_PUB_EN,
	RSA_PRV_DE,
	MAX_RSA_SYNC_TYPE,
	RSA_ASYNC_EN,
	RSA_ASYNC_DE,
	RSA_ASYNC_GEN,
	MAX_RSA_ASYNC_TYPE,
	DH_GEN,
	DH_ASYNC_GEN,
	MAX_DH_TYPE,
	HPRE_MAX_OP_TYPE
};

enum alg_op_mode {
	HPRE_ALG_INVLD_MODE,
	RSA_COM_MD,
	RSA_CRT_MD,
	DH_COM_MD,
	DH_G2,
	HPRE_MAX_OP_MODE,
};



struct hpre_queue_mempool {
	struct wd_queue *q;
	void *base;
	unsigned int *bitmap;
	unsigned int block_size;
	unsigned int block_num;
	unsigned int mem_size;
	unsigned int block_align_size;
	unsigned int free_num;
	unsigned int fail_times;
	unsigned long long index;
	sem_t	sem;
	int dev;
};

struct hpre_queue_mempool *hpre_test_mempool_create(struct wd_queue *q,
			unsigned int block_size, unsigned int block_num);
void hpre_test_mempool_destroy(struct hpre_queue_mempool *pool);
void *hpre_test_alloc_buf(struct hpre_queue_mempool *pool, size_t sz);
void hpre_test_free_buf(struct hpre_queue_mempool *pool, void *buf);
#endif
