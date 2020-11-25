/* SPDX-License-Identifier: GPL-2.0 */
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
#include "include/uacce.h"

#define SYS_VAL_SIZE		16
#define PATH_STR_SIZE		256
#define MAX_ATTR_STR_SIZE	256
#define WD_NAME_SIZE		64

#define WD_HW_ERR		62

/* WD error code */
#define	WD_SUCCESS		0
#define	WD_STREAM_END		1
#define	WD_EAGAIN		EAGAIN
#define	WD_ENOMEM		ENOMEM
#define	WD_EACCESS		EACCESS
#define	WD_EBUSY		EBUSY
#define	WD_ENODEV		ENODEV
#define	WD_EINVAL		EINVAL
#define	WD_ETIMEDOUT		ETIMEDOUT
#define	WD_MSG_PARA_ERR	61
#define	WD_HW_EACCESS		62
#define	WD_SGL_ERR		63
#define	WD_VERIFY_ERR		64

typedef void (*wcrypto_cb)(const void *msg, void *tag);

struct wcrypto_cb_tag {
	void *ctx;
	void *tag;
	int ctx_id;
};

struct wcrypto_paras {
	 /* 0--encipher/compress .etc, 1 ---decipher/decomp .etc */
	__u8 direction;

	 /* to be extended */
};

/* memory APIs for Algorithm Layer */
typedef void *(*wd_alloc)(void *usr, size_t size);
typedef void (*wd_free)(void *usr, void *va);

 /* memory VA to DMA address map */
typedef void *(*wd_dmap)(void *usr, void *va, size_t sz);
typedef void (*wd_undmap)(void *usr, void *va, void *dma, size_t sz);

/* Memory from user, it is given at ctx creating. */
struct wd_mm_ops {
	wd_alloc alloc;
	wd_free free;
	wd_dmap dma_map;
	wd_undmap dma_unmap;
	void *usr; /* data for the above operations */
};

/* Warpdrive data buffer */
struct wd_dtb {
	char *data; /* data/buffer start address */
	__u32 dsize; /* data size */
	__u32 bsize; /* buffer size */
};

enum wcrypto_type {
	WD_RSA,
	WD_DH,
	WD_CIPHER,
	WD_DIGEST,
	WD_COMP,
	WD_EC,
	WD_RNG,
	WD_MAX_ALG,
};

enum wd_buff_type {
	WD_FLAT_BUF,
	WD_SGL_BUF,
};

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#ifndef WD_ERR
#ifndef WITH_LOG_FILE
#define WD_ERR(format, args...) fprintf(stderr, format, ##args)
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
	const char *alg;
	int throughput;
	int latency;
	__u32 flags;
	__u8 priv[WD_CAPA_PRIV_DATA_SIZE]; /* For algorithm parameters */
};

struct wd_queue {
	struct wd_capa capa;
	char dev_path[PATH_STR_SIZE]; /* if denote dev name, get its Q */
	void *info; /* queue private */
};

extern int wd_request_queue(struct wd_queue *q);
extern void wd_release_queue(struct wd_queue *q);
extern int wd_send(struct wd_queue *q, void *req);
extern int wd_recv(struct wd_queue *q, void **resp);
extern int wd_recv_sync(struct wd_queue *q, void **resp, __u16 ms);
extern void *wd_reserve_memory(struct wd_queue *q, size_t size);
extern int wd_share_reserved_memory(struct wd_queue *q,
				    struct wd_queue *target_q);
extern int wd_get_available_dev_num(const char *algorithm);
extern int wd_get_node_id(struct wd_queue *q);
extern void *wd_dma_map(struct wd_queue *q, void *va, size_t sz);
extern void wd_dma_unmap(struct wd_queue *q, void *va, void *dma, size_t sz);
extern void *wd_dma_to_va(struct wd_queue *q, void *dma);
#endif
