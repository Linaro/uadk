#ifndef WD_ALG_COMMON_H
#define WD_ALG_COMMON_H

#include <asm/types.h>
#include <pthread.h>
#include "wd.h"

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

#ifdef DEBUG_LOG
#define dbg(msg, ...) fprintf(stderr, msg, ##__VA_ARGS__)
#else
#define dbg(msg, ...)
#endif

/* Required compiler attributes */
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define BYTE_BITS_SHIFT		3
#define BITS_TO_BYTES(bits)	(((bits) + 7) >> 3)
#define BYTES_TO_BITS(bytes)	((bytes) << 3)

struct wd_lock {
	__u32 lock;
};

enum wd_ctx_mode {
	CTX_MODE_SYNC = 0,
	CTX_MODE_ASYNC,
};

enum wd_buff_type {
	WD_FLAT_BUF,
	WD_SGL_BUF,
};

/**
 * struct wd_ctx - Define one ctx and related type.
 * @ctx:	The ctx itself.
 * @op_type:	Define the operation type of this specific ctx.
 *		e.g. 0: compression; 1: decompression.
 * @ctx_mode:   Define this ctx is used for synchronization of asynchronization
 *		1: synchronization; 0: asynchronization;
 */
struct wd_ctx {
	handle_t ctx;
	__u8 op_type;
	__u8 ctx_mode;
};

/**
 * struct wd_ctx_config - Define a ctx set and its related attributes, which
 *			  will be used in the scope of current process.
 * @ctx_num:	The ctx number in below ctx array.
 * @ctxs:	Point to a ctx array, length is above ctx_num.
 * @priv:	The attributes of ctx defined by user, which is used by user
 *		defined scheduler.
 */
struct wd_ctx_config {
	__u32 ctx_num;
	struct wd_ctx *ctxs;
	void *priv;
};

/**
 * sched_key - The key if schedule region.
 * @numa_id: The numa_id map the hardware.
 * @mode: Sync mode:0, async_mode:1
 * @type: Service type , the value must smaller than type_num.
 */
struct sched_key {
	int numa_id;
	__u8 mode;
	__u8 type;
};

struct wd_ctx_internal {
	handle_t ctx;
	__u8 op_type;
	__u8 ctx_mode;
	pthread_spinlock_t lock;
};

struct wd_ctx_config_internal {
	__u32 ctx_num;
	struct wd_ctx_internal *ctxs;
	void *priv;
};

/**
 * struct wd_comp_sched - Define a scheduler.
 * @name:		Name of this scheduler.
 * @pick_next_ctx:	Pick the proper ctx which a request will be sent to.
 *			config points to the ctx config; sched_ctx points to
 *			scheduler context; req points to the request. Return
 *			the proper ctx pos in wd_ctx_config.
 *			(fix me: modify req to request?)
 * @poll_policy:	Define the polling policy. config points to the ctx
 *			config; sched_ctx points to scheduler context; Return
 *			number of polled request.
 */
struct wd_sched {
	const char *name;
	__u32 (*pick_next_ctx)(handle_t h_sched_ctx,
				  const void *req,
				  const struct sched_key *key);
	int (*poll_policy)(handle_t h_sched_ctx, __u32 expect, __u32 *count);
	handle_t h_sched_ctx;
};

struct wd_sgl {
	void *data;
	__u32 len;
	struct wd_sgl *next;
};

static inline void wd_spinlock(struct wd_lock *lock)
{
	while (__atomic_test_and_set(&lock->lock, __ATOMIC_ACQUIRE))
		while (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED));
}

static inline void wd_unspinlock(struct wd_lock *lock)
{
	__atomic_clear(&lock->lock, __ATOMIC_RELEASE);
}


#endif
