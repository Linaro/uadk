/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <sys/auxv.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "hash_mb.h"

#define MIN(a, b)		(((a) > (b)) ? (b) : (a))
#define IPAD_VALUE		0x36
#define OPAD_VALUE		0x5C
#define HASH_KEY_LEN		64
#define HASH_BLOCK_OFFSET	6
#define HASH_BLOCK_SIZE		64
#define HASH_PADLENGTHFIELD_SIZE 56
#define HASH_PADDING_SIZE	120
#define HASH_HIGH_32BITS	32
#define HASH_PADDING_BLOCKS	2
#define HASH_NENO_PROCESS_JOBS	4
#define HASH_TRY_PROCESS_COUNT	16
#define BYTES_TO_BITS_OFFSET	3

#define MD5_DIGEST_DATA_SIZE	16
#define SM3_DIGEST_DATA_SIZE	32
#define HASH_MAX_LANES		32
#define SM3_MAX_LANES		16

#define PUTU32(p, V) \
	((p)[0] = (uint8_t)((V) >> 24), \
	 (p)[1] = (uint8_t)((V) >> 16), \
	 (p)[2] = (uint8_t)((V) >>  8), \
	 (p)[3] = (uint8_t)(V))

struct hash_mb_ops {
	int (*max_lanes)(void);
	void (*asimd_x4)(struct hash_job *job1, struct hash_job *job2,
			 struct hash_job *job3, struct hash_job *job4, int len);
	void (*asimd_x1)(struct hash_job *job, int len);
	void (*sve)(int blocks, int total_lanes, struct hash_job **job_vec);
	__u8 *iv_data;
	int iv_bytes;
	int max_jobs;
};

struct hash_mb_poll_queue {
	struct hash_job *head;
	struct hash_job *tail;
	pthread_spinlock_t s_lock;
	const struct hash_mb_ops *ops;
	__u32 job_num;
};

struct hash_mb_queue {
	struct hash_mb_poll_queue sm3_poll_queue;
	struct hash_mb_poll_queue md5_poll_queue;
	pthread_spinlock_t r_lock;
	struct hash_job *recv_head;
	struct hash_job *recv_tail;
	__u32 complete_cnt;
	__u8 ctx_mode;
};

struct hash_mb_ctx {
	struct wd_ctx_config_internal config;
};

static __u8 sm3_iv_data[SM3_DIGEST_DATA_SIZE] = {
	0x73, 0x80, 0x16, 0x6f, 0x49, 0x14, 0xb2, 0xb9,
	0x17, 0x24, 0x42, 0xd7, 0xda, 0x8a, 0x06, 0x00,
	0xa9, 0x6f, 0x30, 0xbc, 0x16, 0x31, 0x38, 0xaa,
	0xe3, 0x8d, 0xee, 0x4d, 0xb0, 0xfb, 0x0e, 0x4e,
};

static __u8 md5_iv_data[MD5_DIGEST_DATA_SIZE] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};

static struct hash_mb_ops md5_ops = {
	.max_lanes = md5_mb_sve_max_lanes,
	.asimd_x4 = md5_mb_asimd_x4,
	.asimd_x1 = md5_mb_asimd_x1,
	.sve = md5_mb_sve,
	.iv_data = md5_iv_data,
	.iv_bytes = MD5_DIGEST_DATA_SIZE,
	.max_jobs = HASH_MAX_LANES,
};

static struct hash_mb_ops sm3_ops = {
	.max_lanes = sm3_mb_sve_max_lanes,
	.asimd_x4 = sm3_mb_asimd_x4,
	.asimd_x1 = sm3_mb_asimd_x1,
	.sve = sm3_mb_sve,
	.iv_data = sm3_iv_data,
	.iv_bytes = SM3_DIGEST_DATA_SIZE,
	.max_jobs = SM3_MAX_LANES,
};

static void hash_mb_uninit_poll_queue(struct hash_mb_poll_queue *poll_queue)
{
	pthread_spin_destroy(&poll_queue->s_lock);
}

static void hash_mb_queue_uninit(struct wd_ctx_config_internal *config, int ctx_num)
{
	struct hash_mb_queue *mb_queue;
	struct wd_soft_ctx *ctx;
	int i;

	for (i = 0; i < ctx_num; i++) {
		ctx = (struct wd_soft_ctx *)config->ctxs[i].ctx;
		mb_queue = ctx->priv;
		pthread_spin_destroy(&mb_queue->r_lock);
		hash_mb_uninit_poll_queue(&mb_queue->sm3_poll_queue);
		hash_mb_uninit_poll_queue(&mb_queue->md5_poll_queue);
		free(mb_queue);
	}
}

static int hash_mb_init_poll_queue(struct hash_mb_poll_queue *poll_queue)
{
	int ret;

	ret = pthread_spin_init(&poll_queue->s_lock, PTHREAD_PROCESS_SHARED);
	if (ret) {
		WD_ERR("failed to init s_lock!\n");
		return ret;
	}

	poll_queue->head = NULL;
	poll_queue->tail = NULL;
	poll_queue->job_num = 0;

	return WD_SUCCESS;
}

static int hash_mb_queue_init(struct wd_ctx_config_internal *config)
{
	struct hash_mb_queue *mb_queue;
	int ctx_num = config->ctx_num;
	struct wd_soft_ctx *ctx;
	int i, ret;

	for (i = 0; i < ctx_num; i++) {
		mb_queue = calloc(1, sizeof(struct hash_mb_queue));
		if (!mb_queue) {
			ret = -WD_ENOMEM;
			goto free_mb_queue;
		}

		mb_queue->ctx_mode = config->ctxs[i].ctx_mode;
		ctx = (struct wd_soft_ctx *)config->ctxs[i].ctx;
		ctx->priv = mb_queue;
		ret = hash_mb_init_poll_queue(&mb_queue->sm3_poll_queue);
		if (ret)
			goto free_mem;

		ret = hash_mb_init_poll_queue(&mb_queue->md5_poll_queue);
		if (ret)
			goto uninit_sm3_poll;

		ret = pthread_spin_init(&mb_queue->r_lock, PTHREAD_PROCESS_SHARED);
		if (ret) {
			WD_ERR("failed to init r_lock!\n");
			goto uninit_md5_poll;
		}

		mb_queue->sm3_poll_queue.ops = &sm3_ops;
		mb_queue->md5_poll_queue.ops = &md5_ops;
		mb_queue->recv_head = NULL;
		mb_queue->recv_tail = NULL;
		mb_queue->complete_cnt = 0;
	}

	return WD_SUCCESS;

uninit_md5_poll:
	hash_mb_uninit_poll_queue(&mb_queue->md5_poll_queue);
uninit_sm3_poll:
	hash_mb_uninit_poll_queue(&mb_queue->sm3_poll_queue);
free_mem:
	free(mb_queue);
free_mb_queue:
	hash_mb_queue_uninit(config, i);
	return ret;
}

static int hash_mb_init(struct wd_alg_driver *drv, void *conf)
{
	struct wd_ctx_config_internal *config = conf;
	struct hash_mb_ctx *priv;
	int ret;

	priv = malloc(sizeof(struct hash_mb_ctx));
	if (!priv)
		return -WD_ENOMEM;

	/* multibuff does not use epoll. */
	config->epoll_en = 0;
	memcpy(&priv->config, config, sizeof(struct wd_ctx_config_internal));

	ret = hash_mb_queue_init(config);
	if (ret) {
		free(priv);
		return ret;
	}

	drv->priv = priv;

	return WD_SUCCESS;
}

static void hash_mb_exit(struct wd_alg_driver *drv)
{
	struct hash_mb_ctx *priv = (struct hash_mb_ctx *)drv->priv;

	if (!priv)
		return;

	hash_mb_queue_uninit(&priv->config, priv->config.ctx_num);
	free(priv);
	drv->priv = NULL;
}

static void hash_mb_pad_data(struct hash_pad *hash_pad, __u8 *in, __u32 partial,
		     __u64 total_len, bool transfer)
{
	__u64 size = total_len << BYTES_TO_BITS_OFFSET;
	__u8 *buffer = hash_pad->pad;

	if (partial)
		memcpy(buffer, in, partial);

	buffer[partial++] = 0x80;
	if (partial <= HASH_PADLENGTHFIELD_SIZE) {
		memset(buffer + partial, 0, HASH_PADLENGTHFIELD_SIZE - partial);
		if (transfer) {
			PUTU32(buffer + HASH_PADLENGTHFIELD_SIZE, size >> HASH_HIGH_32BITS);
			PUTU32(buffer + HASH_PADLENGTHFIELD_SIZE + sizeof(__u32), size);
		} else {
			memcpy(buffer + HASH_PADLENGTHFIELD_SIZE, &size, sizeof(__u64));
		}
		hash_pad->pad_len = 1;
	} else {
		memset(buffer + partial, 0, HASH_PADDING_SIZE - partial);
		if (transfer) {
			PUTU32(buffer + HASH_PADDING_SIZE, size >> HASH_HIGH_32BITS);
			PUTU32(buffer + HASH_PADDING_SIZE + sizeof(__u32), size);
		} else {
			memcpy(buffer + HASH_PADDING_SIZE, &size, sizeof(__u64));
		}
		hash_pad->pad_len = HASH_PADDING_BLOCKS;
	}
}

static inline void hash_xor(__u8 *key_out, __u8 *key_in, __u32 key_len, __u8 xor_value)
{
	__u32 i;

	for (i = 0; i < HASH_KEY_LEN; i++) {
		if (i < key_len)
			key_out[i] = key_in[i] ^ xor_value;
		else
			key_out[i] = xor_value;
	}
}

static int hash_middle_block_process(struct hash_mb_poll_queue *poll_queue,
				     struct wd_digest_msg *d_msg,
				     struct hash_job *job)
{
	__u8 *buffer = d_msg->partial_block + d_msg->partial_bytes;
	__u64 length = (__u64)d_msg->partial_bytes + d_msg->in_bytes;

	if (length < HASH_BLOCK_SIZE) {
		memcpy(buffer, d_msg->in, d_msg->in_bytes);
		d_msg->partial_bytes = length;
		return -WD_EAGAIN;
	}

	if (d_msg->partial_bytes) {
		memcpy(buffer, d_msg->in, HASH_BLOCK_SIZE - d_msg->partial_bytes);
		job->buffer = d_msg->partial_block;
		poll_queue->ops->asimd_x1(job, 1);
		length = d_msg->in_bytes - (HASH_BLOCK_SIZE - d_msg->partial_bytes);
		buffer = d_msg->in + (HASH_BLOCK_SIZE - d_msg->partial_bytes);
	} else {
		buffer = d_msg->in;
	}

	job->len = length >> HASH_BLOCK_OFFSET;
	d_msg->partial_bytes = length & (HASH_BLOCK_SIZE - 1);
	if (d_msg->partial_bytes)
		memcpy(d_msg->partial_block, buffer + (job->len << HASH_BLOCK_OFFSET),
			d_msg->partial_bytes);

	if (!job->len) {
		memcpy(d_msg->out, job->result_digest, poll_queue->ops->iv_bytes);
		return -WD_EAGAIN;
	}

	job->buffer = buffer;
	job->pad.pad_len = 0;

	return WD_SUCCESS;
}

static void hash_signle_block_process(struct wd_digest_msg *d_msg,
				      struct hash_job *job, __u64 total_len)
{
	__u32 hash_partial = d_msg->in_bytes & (HASH_BLOCK_SIZE - 1);
	__u8 *buffer;

	job->len = d_msg->in_bytes >> HASH_BLOCK_OFFSET;
	buffer = d_msg->in + (job->len << HASH_BLOCK_OFFSET);
	hash_mb_pad_data(&job->pad, buffer, hash_partial, total_len, job->is_transfer);
	if (!job->len) {
		job->buffer = job->pad.pad;
		job->len = job->pad.pad_len;
		job->pad.pad_len = 0;
		return;
	}

	job->buffer = d_msg->in;
}

static void hash_final_block_process(struct hash_mb_poll_queue *poll_queue,
				     struct wd_digest_msg *d_msg,
				     struct hash_job *job)
{
	__u8 *buffer = d_msg->partial_block + d_msg->partial_bytes;
	__u64 length = (__u64)d_msg->partial_bytes + d_msg->in_bytes;
	__u32 hash_partial = length & (HASH_BLOCK_SIZE - 1);
	__u64 total_len = d_msg->long_data_len;

	if (job->opad.opad_size)
		total_len += HASH_BLOCK_SIZE;

	if (!d_msg->partial_bytes) {
		hash_signle_block_process(d_msg, job, total_len);
		return;
	}

	if (length <= HASH_BLOCK_SIZE) {
		memcpy(buffer, d_msg->in, d_msg->in_bytes);
		job->len = length >> HASH_BLOCK_OFFSET;
		buffer = d_msg->partial_block + (job->len << HASH_BLOCK_OFFSET);
		hash_mb_pad_data(&job->pad, buffer, hash_partial, total_len, job->is_transfer);
		if (!job->len) {
			job->buffer = job->pad.pad;
			job->len = job->pad.pad_len;
			job->pad.pad_len = 0;
			return;
		}

		job->buffer = d_msg->partial_block;
		return;
	}

	memcpy(buffer, d_msg->in, (HASH_BLOCK_SIZE - d_msg->partial_bytes));
	job->buffer = d_msg->partial_block;
	poll_queue->ops->asimd_x1(job, 1);
	job->buffer = d_msg->in + (HASH_BLOCK_SIZE - d_msg->partial_bytes);
	length = d_msg->in_bytes - (HASH_BLOCK_SIZE - d_msg->partial_bytes);
	job->len = length >> HASH_BLOCK_OFFSET;
	buffer = job->buffer + (job->len << HASH_BLOCK_OFFSET);
	hash_partial = length & (HASH_BLOCK_SIZE - 1);
	hash_mb_pad_data(&job->pad, buffer, hash_partial, total_len, job->is_transfer);
	if (!job->len) {
		job->buffer = job->pad.pad;
		job->len = job->pad.pad_len;
		job->pad.pad_len = 0;
	}
}

static int hash_first_block_process(struct wd_digest_msg *d_msg,
				    struct hash_job *job,
				    __u32 iv_bytes)
{
	__u8 *buffer;

	job->len = d_msg->in_bytes >> HASH_BLOCK_OFFSET;
	d_msg->partial_bytes = d_msg->in_bytes & (HASH_BLOCK_SIZE - 1);
	if (d_msg->partial_bytes) {
		buffer = d_msg->in + (job->len << HASH_BLOCK_OFFSET);
		memcpy(d_msg->partial_block, buffer, d_msg->partial_bytes);
	}

	/*
	 * Long hash mode, if first block is less than HASH_BLOCK_SIZE,
	 * copy ikey hash result to out.
	 */
	if (!job->len) {
		memcpy(d_msg->out, job->result_digest, iv_bytes);
		return -WD_EAGAIN;
	}
	job->buffer = d_msg->in;
	job->pad.pad_len = 0;

	return WD_SUCCESS;
}

static int hash_do_partial(struct hash_mb_poll_queue *poll_queue,
				struct wd_digest_msg *d_msg, struct hash_job *job)
{
	enum hash_block_type bd_type = get_hash_block_type(d_msg);
	__u64 total_len = d_msg->in_bytes;
	int ret = WD_SUCCESS;

	switch (bd_type) {
	case HASH_FIRST_BLOCK:
		ret = hash_first_block_process(d_msg, job, poll_queue->ops->iv_bytes);
		break;
	case HASH_MIDDLE_BLOCK:
		ret = hash_middle_block_process(poll_queue, d_msg, job);
		break;
	case HASH_END_BLOCK:
		hash_final_block_process(poll_queue, d_msg, job);
		break;
	case HASH_SINGLE_BLOCK:
		if (job->opad.opad_size)
			total_len += HASH_BLOCK_SIZE;
		hash_signle_block_process(d_msg, job, total_len);
		break;
	}

	return ret;
}

static void hash_mb_init_iv(struct hash_mb_poll_queue *poll_queue,
			    struct wd_digest_msg *d_msg, struct hash_job *job)
{
	enum hash_block_type bd_type = get_hash_block_type(d_msg);
	__u8 key_ipad[HASH_KEY_LEN];
	__u8 key_opad[HASH_KEY_LEN];

	job->opad.opad_size = 0;
	switch (bd_type) {
	case HASH_FIRST_BLOCK:
		memcpy(job->result_digest, poll_queue->ops->iv_data, poll_queue->ops->iv_bytes);
		if (d_msg->mode != WD_DIGEST_HMAC)
			return;

		hash_xor(key_ipad, d_msg->key, d_msg->key_bytes, IPAD_VALUE);
		job->buffer = key_ipad;
		poll_queue->ops->asimd_x1(job, 1);
		break;
	case HASH_MIDDLE_BLOCK:
		memcpy(job->result_digest, d_msg->out, poll_queue->ops->iv_bytes);
		break;
	case HASH_END_BLOCK:
		if (d_msg->mode != WD_DIGEST_HMAC) {
			memcpy(job->result_digest, d_msg->out, poll_queue->ops->iv_bytes);
			return;
		}
		memcpy(job->result_digest, poll_queue->ops->iv_data, poll_queue->ops->iv_bytes);
		hash_xor(key_opad, d_msg->key, d_msg->key_bytes, OPAD_VALUE);
		job->buffer = key_opad;
		poll_queue->ops->asimd_x1(job, 1);
		memcpy(job->opad.opad, job->result_digest, poll_queue->ops->iv_bytes);
		job->opad.opad_size = poll_queue->ops->iv_bytes;
		memcpy(job->result_digest, d_msg->out, poll_queue->ops->iv_bytes);
		break;
	case HASH_SINGLE_BLOCK:
		memcpy(job->result_digest, poll_queue->ops->iv_data, poll_queue->ops->iv_bytes);
		if (d_msg->mode != WD_DIGEST_HMAC)
			return;

		hash_xor(key_ipad, d_msg->key, d_msg->key_bytes, IPAD_VALUE);
		hash_xor(key_opad, d_msg->key, d_msg->key_bytes, OPAD_VALUE);
		job->buffer = key_opad;
		poll_queue->ops->asimd_x1(job, 1);
		memcpy(job->opad.opad, job->result_digest, poll_queue->ops->iv_bytes);
		job->opad.opad_size = poll_queue->ops->iv_bytes;
		job->buffer = key_ipad;
		memcpy(job->result_digest, poll_queue->ops->iv_data, poll_queue->ops->iv_bytes);
		poll_queue->ops->asimd_x1(job, 1);
		break;
	}
}

static void hash_do_sync(struct hash_mb_poll_queue *poll_queue, struct hash_job *job)
{
	__u32 iv_bytes = poll_queue->ops->iv_bytes;
	__u32 length;

	poll_queue->ops->asimd_x1(job, job->len);

	if (job->pad.pad_len) {
		job->buffer = job->pad.pad;
		poll_queue->ops->asimd_x1(job, job->pad.pad_len);
	}

	if (job->opad.opad_size) {
		job->buffer = job->opad.opad + job->opad.opad_size;
		memcpy(job->buffer, job->result_digest, iv_bytes);
		memcpy(job->result_digest, job->opad.opad, iv_bytes);
		length = HASH_BLOCK_SIZE + iv_bytes;
		hash_mb_pad_data(&job->pad, job->buffer, iv_bytes, length, job->is_transfer);
		job->buffer = job->pad.pad;
		poll_queue->ops->asimd_x1(job, job->pad.pad_len);
	}
}

static void hash_mb_add_job_tail(struct hash_mb_poll_queue *poll_queue, struct hash_job *job)
{
	pthread_spin_lock(&poll_queue->s_lock);
	if (poll_queue->job_num) {
		poll_queue->tail->next = job;
		poll_queue->tail = job;
	} else {
		poll_queue->head = job;
		poll_queue->tail = job;
	}
	poll_queue->job_num++;
	pthread_spin_unlock(&poll_queue->s_lock);
}

static void hash_mb_add_job_head(struct hash_mb_poll_queue *poll_queue, struct hash_job *job)
{
	pthread_spin_lock(&poll_queue->s_lock);
	if (poll_queue->job_num) {
		job->next = poll_queue->head;
		poll_queue->head = job;
	} else {
		poll_queue->head = job;
		poll_queue->tail = job;
	}
	poll_queue->job_num++;
	pthread_spin_unlock(&poll_queue->s_lock);
}

static int hash_mb_check_param(struct hash_mb_queue *mb_queue, struct wd_digest_msg *d_msg)
{
	if (unlikely(mb_queue->ctx_mode == CTX_MODE_ASYNC && d_msg->has_next)) {
		WD_ERR("invalid: async mode not supports long hash!\n");
		return -WD_EINVAL;
	}

	if (unlikely(d_msg->data_fmt != WD_FLAT_BUF)) {
		WD_ERR("invalid: hash multibuffer not supports sgl mode!\n");
		return -WD_EINVAL;
	}

	return WD_SUCCESS;
}

static int hash_mb_send(struct wd_alg_driver *drv, handle_t ctx, void *drv_msg)
{
	struct wd_soft_ctx *s_ctx = (struct wd_soft_ctx *)ctx;
	struct hash_mb_queue *mb_queue = s_ctx->priv;
	struct wd_digest_msg *d_msg = drv_msg;
	struct hash_mb_poll_queue *poll_queue;
	struct hash_job hash_sync_job;
	struct hash_job *hash_job;
	int ret;

	ret = hash_mb_check_param(mb_queue, d_msg);
	if (ret)
		return ret;

	if (mb_queue->ctx_mode == CTX_MODE_ASYNC) {
		hash_job = malloc(sizeof(struct hash_job));
		if (unlikely(!hash_job))
			return -WD_ENOMEM;
	} else {
		hash_job = &hash_sync_job;
	}

	switch (d_msg->alg) {
	case WD_DIGEST_SM3:
		poll_queue = &mb_queue->sm3_poll_queue;
		hash_job->is_transfer = true;
		break;
	case WD_DIGEST_MD5:
		poll_queue = &mb_queue->md5_poll_queue;
		hash_job->is_transfer = false;
		break;
	default:
		WD_ERR("invalid: alg type %u not support!\n", d_msg->alg);
		if (mb_queue->ctx_mode == CTX_MODE_ASYNC)
			free(hash_job);
		return -WD_EINVAL;
	}

	hash_mb_init_iv(poll_queue, d_msg, hash_job);
	/* If block not need process, return directly. */
	ret = hash_do_partial(poll_queue, d_msg, hash_job);
	if (ret == -WD_EAGAIN) {
		if (mb_queue->ctx_mode == CTX_MODE_ASYNC)
			free(hash_job);

		d_msg->result = WD_SUCCESS;
		return WD_SUCCESS;
	}

	if (mb_queue->ctx_mode == CTX_MODE_SYNC) {
		hash_do_sync(poll_queue, hash_job);
		memcpy(d_msg->out, hash_job->result_digest, d_msg->out_bytes);
		d_msg->result = WD_SUCCESS;
		return WD_SUCCESS;
	}

	hash_job->msg = d_msg;
	hash_mb_add_job_tail(poll_queue, hash_job);

	return WD_SUCCESS;
}

static struct hash_job *hash_mb_find_complete_job(struct hash_mb_queue *mb_queue)
{
	struct hash_job *job;

	pthread_spin_lock(&mb_queue->r_lock);
	if (!mb_queue->complete_cnt) {
		pthread_spin_unlock(&mb_queue->r_lock);
		return NULL;
	}

	job = mb_queue->recv_head;
	mb_queue->recv_head = job->next;
	mb_queue->complete_cnt--;
	pthread_spin_unlock(&mb_queue->r_lock);

	return job;
}

static int hash_recv_complete_job(struct hash_mb_queue *mb_queue, struct wd_digest_msg *msg)
{
	struct hash_mb_poll_queue *poll_queue;
	struct hash_job *hash_job;
	__u32 total_len;

	hash_job = hash_mb_find_complete_job(mb_queue);
	if (!hash_job)
		return -WD_EAGAIN;

	if (!hash_job->opad.opad_size) {
		msg->tag = hash_job->msg->tag;
		memcpy(hash_job->msg->out, hash_job->result_digest, hash_job->msg->out_bytes);
		free(hash_job);
		msg->result = WD_SUCCESS;
		return WD_SUCCESS;
	}

	if (hash_job->msg->alg == WD_DIGEST_SM3)
		poll_queue = &mb_queue->sm3_poll_queue;
	else
		poll_queue = &mb_queue->md5_poll_queue;
	hash_job->buffer = hash_job->opad.opad + poll_queue->ops->iv_bytes;
	memcpy(hash_job->buffer, hash_job->result_digest, poll_queue->ops->iv_bytes);
	total_len = poll_queue->ops->iv_bytes + HASH_BLOCK_SIZE;
	hash_mb_pad_data(&hash_job->pad, hash_job->buffer, poll_queue->ops->iv_bytes,
			 total_len, hash_job->is_transfer);
	memcpy(hash_job->result_digest, hash_job->opad.opad, poll_queue->ops->iv_bytes);
	hash_job->opad.opad_size = 0;
	hash_job->buffer = hash_job->pad.pad;
	hash_job->len = hash_job->pad.pad_len;
	hash_job->pad.pad_len = 0;

	hash_mb_add_job_head(poll_queue, hash_job);

	return -WD_EAGAIN;
}

static struct hash_job *hash_mb_get_job(struct hash_mb_poll_queue *poll_queue)
{
	struct hash_job *job;

	pthread_spin_lock(&poll_queue->s_lock);
	if (!poll_queue->job_num) {
		pthread_spin_unlock(&poll_queue->s_lock);
		return NULL;
	}

	job = poll_queue->head;
	poll_queue->head = job->next;
	poll_queue->job_num--;
	pthread_spin_unlock(&poll_queue->s_lock);

	return job;
}

static void hash_mb_add_finish_job(struct hash_mb_queue *mb_queue, struct hash_job *job)
{
	pthread_spin_lock(&mb_queue->r_lock);
	if (mb_queue->complete_cnt) {
		mb_queue->recv_tail->next = job;
		mb_queue->recv_tail = job;
	} else {
		mb_queue->recv_head = job;
		mb_queue->recv_tail = job;
	}
	mb_queue->complete_cnt++;
	pthread_spin_unlock(&mb_queue->r_lock);
}

static struct hash_mb_poll_queue *hash_get_poll_queue(struct hash_mb_queue *mb_queue)
{
	if (!mb_queue->sm3_poll_queue.job_num &&
	    !mb_queue->md5_poll_queue.job_num)
		return NULL;

	if (mb_queue->md5_poll_queue.job_num >= mb_queue->sm3_poll_queue.job_num)
		return &mb_queue->md5_poll_queue;

	return &mb_queue->sm3_poll_queue;
}

static int hash_mb_do_jobs(struct hash_mb_queue *mb_queue)
{
	struct hash_mb_poll_queue *poll_queue = hash_get_poll_queue(mb_queue);
	struct hash_job *job_vecs[HASH_MAX_LANES];
	__u64 len = 0;
	int maxjobs;
	int j = 0;
	int i = 0;

	if (!poll_queue)
		return -WD_EAGAIN;

	maxjobs = poll_queue->ops->max_lanes();
	maxjobs = MIN(maxjobs, poll_queue->ops->max_jobs);
	while (j < maxjobs) {
		job_vecs[j] = hash_mb_get_job(poll_queue);
		if (!job_vecs[j])
			break;

		if (!j)
			len = job_vecs[j]->len;
		else
			len = MIN(job_vecs[j]->len, len);
		j++;
	}

	if (!j)
		return -WD_EAGAIN;

	if (j > HASH_NENO_PROCESS_JOBS) {
		poll_queue->ops->sve(len, j, job_vecs);
	} else if (j == HASH_NENO_PROCESS_JOBS) {
		poll_queue->ops->asimd_x4(job_vecs[0], job_vecs[1],
					  job_vecs[2], job_vecs[3], len);
	} else {
		while (i < j)
			poll_queue->ops->asimd_x1(job_vecs[i++], len);
	}

	for (i = 0; i < j; i++) {
		if (job_vecs[i]->len == len) {
			if (!job_vecs[i]->pad.pad_len) {
				hash_mb_add_finish_job(mb_queue, job_vecs[i]);
			} else {
				job_vecs[i]->buffer = job_vecs[i]->pad.pad;
				job_vecs[i]->len = job_vecs[i]->pad.pad_len;
				job_vecs[i]->pad.pad_len = 0;
				hash_mb_add_job_head(poll_queue, job_vecs[i]);
			}
		} else {
			job_vecs[i]->len -= len;
			job_vecs[i]->buffer += len << HASH_BLOCK_OFFSET;
			hash_mb_add_job_head(poll_queue, job_vecs[i]);
		}
	}

	return WD_SUCCESS;
}

static int hash_mb_recv(struct wd_alg_driver *drv, handle_t ctx, void *drv_msg)
{
	struct wd_soft_ctx *s_ctx = (struct wd_soft_ctx *)ctx;
	struct hash_mb_queue *mb_queue = s_ctx->priv;
	struct wd_digest_msg *msg = drv_msg;
	int ret, i = 0;

	if (mb_queue->ctx_mode == CTX_MODE_SYNC)
		return WD_SUCCESS;

	while (i++ < HASH_TRY_PROCESS_COUNT) {
		ret = hash_recv_complete_job(mb_queue, msg);
		if (!ret)
			return WD_SUCCESS;

		ret = hash_mb_do_jobs(mb_queue);
		if (ret)
			return ret;
	}

	return -WD_EAGAIN;
}

static int hash_mb_get_usage(void *param)
{
	return 0;
}

#define GEN_HASH_ALG_DRIVER(hash_alg_name) \
{\
	.drv_name = "hash_mb",\
	.alg_name = (hash_alg_name),\
	.calc_type = UADK_ALG_SVE_INSTR,\
	.priority = 100,\
	.queue_num = 1,\
	.op_type_num = 1,\
	.fallback = 0,\
	.init = hash_mb_init,\
	.exit = hash_mb_exit,\
	.send = hash_mb_send,\
	.recv = hash_mb_recv,\
	.get_usage = hash_mb_get_usage,\
}

static struct wd_alg_driver hash_mb_driver[] = {
	GEN_HASH_ALG_DRIVER("sm3"),
	GEN_HASH_ALG_DRIVER("md5"),
};

static void __attribute__((constructor)) hash_mb_probe(void)
{
	size_t alg_num = ARRAY_SIZE(hash_mb_driver);
	size_t i;
	int ret;

	WD_INFO("Info: register hash_mb alg drivers!\n");
	for (i = 0; i < alg_num; i++) {
		ret = wd_alg_driver_register(&hash_mb_driver[i]);
		if (ret && ret != -WD_ENODEV)
			WD_ERR("Error: register hash multibuff %s failed!\n",
				hash_mb_driver[i].alg_name);
	}
}

static void __attribute__((destructor)) hash_mb_remove(void)
{
	size_t alg_num = ARRAY_SIZE(hash_mb_driver);
	size_t i;

	WD_INFO("Info: unregister hash_mb alg drivers!\n");
	for (i = 0; i < alg_num; i++)
		wd_alg_driver_unregister(&hash_mb_driver[i]);
}

