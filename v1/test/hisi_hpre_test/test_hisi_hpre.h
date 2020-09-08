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
	DH_COMPUTE,
	DH_ASYNC_COMPUTE,
	MAX_DH_TYPE,
	ECDH_GEN,
	ECDH_COMPUTE,
	ECDH_ASYNC_GEN,
	ECDH_ASYNC_COMPUTE,
	MAX_ECDH_TYPE,
	ECDSA_SIGN,
	ECDSA_VERF,
	ECDSA_ASYNC_SIGN,
	ECDSA_ASYNC_VERF,
	MAX_ECDSA_TYPE,
	X25519_GEN,
	X25519_COMPUTE,
	X25519_ASYNC_GEN,
	X25519_ASYNC_COMPUTE,
	X448_GEN,
	X448_COMPUTE,
	X448_ASYNC_GEN,
	X448_ASYNC_COMPUTE,
	SM2_SIGN,
	SM2_VERF,
	SM2_ENC,
	SM2_DEC,
	SM2_KG,
	SM2_ASYNC_SIGN,
	SM2_ASYNC_VERF,
	SM2_ASYNC_ENC,
	SM2_ASYNC_DEC,
	SM2_ASYNC_KG,
	MAX_ECC_TYPE,
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
