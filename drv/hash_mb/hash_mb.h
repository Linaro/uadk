/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2023 Huawei Technologies Co.,Ltd. All rights reserved. */
#ifndef __HASH_MB_H
#define __HASH_MB_H

#include <stdbool.h>
#include <stdint.h>
#include "drv/wd_digest_drv.h"
#include "wd_digest.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HASH_BLOCK_SIZE		64
#define HASH_DIGEST_NWORDS	32

#if __STDC_VERSION__ >= 201112L
#	define	 __ALIGN_END	__attribute__((aligned(64)))
#else
#	define __ALIGN_END	__aligned(64)
#endif

struct hash_pad {
	__u8 pad[HASH_BLOCK_SIZE * 2];
	__u32 pad_len;
};

struct hash_opad {
	__u8 opad[HASH_BLOCK_SIZE];
	__u32 opad_size;
};

struct hash_job {
	void *buffer;
	__u64 len;
	__u8  result_digest[HASH_DIGEST_NWORDS] __ALIGN_END;
	struct hash_pad pad;
	struct hash_opad opad;
	struct hash_job *next;
	struct wd_digest_msg *msg;
	bool is_transfer;
};

void sm3_mb_sve(int blocks, int total_lanes, struct hash_job **job_vec);
void sm3_mb_asimd_x4(struct hash_job *job1, struct hash_job *job2,
			 struct hash_job *job3, struct hash_job *job4, int len);
void sm3_mb_asimd_x1(struct hash_job *job, int len);
int sm3_mb_sve_max_lanes(void);
void md5_mb_sve(int blocks, int total_lanes, struct hash_job **job_vec);
void md5_mb_asimd_x4(struct hash_job *job1, struct hash_job *job2,
			 struct hash_job *job3, struct hash_job *job4, int len);
void md5_mb_asimd_x1(struct hash_job *job, int len);
int md5_mb_sve_max_lanes(void);

#ifdef __cplusplus
}
#endif

#endif /* __HASH_MB_H */

