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

#ifndef __WD_H
#define __WD_H

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include "internal/uacce.h"
#include "../include/wd_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_VAL_SIZE		16
#define PATH_STR_SIZE		256
#define MAX_ATTR_STR_SIZE	256
#define WD_NAME_SIZE		64
#define WCRYPTO_MAX_BURST_NUM	16

/* WD error code */
#define	WD_SUCCESS		0
#define	WD_STREAM_END		1
#define	WD_STREAM_START		2
#define	WD_EIO			EIO
#define	WD_EAGAIN		EAGAIN
#define	WD_ENOMEM		ENOMEM
#define	WD_EACCESS		EACCESS
#define	WD_EBUSY		EBUSY
#define	WD_ENODEV		ENODEV
#define	WD_EINVAL		EINVAL
#define	WD_ETIMEDOUT	ETIMEDOUT
#define	WD_ADDR_ERR		61
#define	WD_HW_EACCESS		62
#define	WD_SGL_ERR		63
#define	WD_VERIFY_ERR		64
#define	WD_OUT_EPARA		66
#define	WD_IN_EPARA		67
#define	WD_ENOPROC		68

typedef void (*wcrypto_cb)(const void *msg, void *tag);

typedef void (*wd_log)(const char *format, ...);

struct wcrypto_cb_tag {
	void *ctx; /* user: context or other user relatives */
	void *tag; /* to store user tag */
	int ctx_id; /* user id: context ID or other user identifier */
};

struct wcrypto_paras {
	 /* 0--encipher/compress .etc, 1 ---decipher/decomp .etc */
	__u8 direction;
	__u8 is_poll;

	 /* to be extended */
};

/* memory APIs for Algorithm Layer */
typedef void *(*wd_alloc)(void *usr, size_t size);
typedef void (*wd_free)(void *usr, void *va);

 /* memory VA to DMA address map */
typedef void *(*wd_map)(void *usr, void *va, size_t sz);
typedef void (*wd_unmap)(void *usr, void *va, void *dma, size_t sz);
typedef __u32 (*wd_bufsize)(void *usr);

/* Memory from user, it is given at ctx creating. */
struct wd_mm_br {
	wd_alloc alloc; /* Memory allocation */
	wd_free free; /* Memory free */
	wd_map iova_map; /* get iova from user space VA */

	/* destroy the mapping between the PA of VA and iova */
	wd_unmap iova_unmap;
	void *usr; /* data for the above operations */
	wd_bufsize get_bufsize; /* optional */
};

/* Warpdrive data buffer */
struct wd_dtb {
	char *data; /* data/buffer start address */
	__u32 dsize; /* data size */
	__u32 bsize; /* buffer size */
};

enum wcrypto_type {
	WCRYPTO_RSA,
	WCRYPTO_DH,
	WCRYPTO_CIPHER,
	WCRYPTO_DIGEST,
	WCRYPTO_COMP,
	WCRYPTO_EC,
	WCRYPTO_RNG,
	WCRYPTO_ECDH,
	WCRYPTO_X25519,
	WCRYPTO_X448,
	WCRYPTO_ECDSA,
	WCRYPTO_SM2,
	WCRYPTO_AEAD,
	WCRYPTO_MAX_ALG
};

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#ifndef WD_ERR
#ifndef WITH_LOG_FILE
extern wd_log log_out;

#define __WD_FILENAME__ (strrchr(__FILE__, '/') ?	\
		((char *)((uintptr_t)strrchr(__FILE__, '/') + 1)) : __FILE__)

#define WD_ERR(format, args...)	\
	(log_out ? log_out("[%s, %d, %s]:"format,	\
	__WD_FILENAME__, __LINE__, __func__, ##args) : 	\
	fprintf(stderr, format, ##args))
#else
extern FILE *flog_fd;
#define WD_ERR(format, args...)				\
	if (!flog_fd)					\
		flog_fd = fopen(WITH_LOG_FILE, "a+");	\
	if (flog_fd)					\
		fprintf(flog_fd, format, ##args);	\
	else						\
		fprintf(stderr, "log %s not exists!",	\
			WITH_LOG_FILE);
#endif
#endif

#define WD_CAPA_PRIV_DATA_SIZE	64

/* Capabilities */
struct wd_capa {
	/* Algorithm name */
	const char *alg;
	/* throughput capability */
	int throughput;
	/* latency capability */
	int latency;
	/* other capabilities */
	__u32 flags;

	/* For algorithm parameters, now it is defined in extending notions */
	struct wcrypto_paras priv;
};

struct wd_queue {
	struct wd_capa capa;
	/* if denote dev name, get its Q */
	char dev_path[PATH_STR_SIZE];
	/* if denote dev node mask, get its Q */
	unsigned int node_mask;
	/* queue private */
	void *qinfo;
};

extern int wd_request_queue(struct wd_queue *q);
extern void wd_release_queue(struct wd_queue *q);
extern int wd_send(struct wd_queue *q, void *req);
extern int wd_recv(struct wd_queue *q, void **resp);
extern int wd_wait(struct wd_queue *q, __u16 ms);
extern int wd_recv_sync(struct wd_queue *q, void **resp, __u16 ms);
extern void *wd_reserve_memory(struct wd_queue *q, size_t size);
extern int wd_share_reserved_memory(struct wd_queue *q,
				    struct wd_queue *target_q);
extern int wd_get_available_dev_num(const char *algorithm);
extern int wd_get_node_id(struct wd_queue *q);
extern void *wd_iova_map(struct wd_queue *q, void *va, size_t sz);
extern void wd_iova_unmap(struct wd_queue *q, void *va, void *dma, size_t sz);
extern void *wd_dma_to_va(struct wd_queue *q, void *dma);
extern int wd_register_log(wd_log log);

#ifdef __cplusplus
}
#endif

#endif
