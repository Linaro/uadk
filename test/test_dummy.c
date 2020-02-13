/* SPDX-License-Identifier: Apache-2.0 */
#include "../config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef WD_SCHED
#include "../wd_sched.h"
#else
#include "wd.h"
#include "smm.h"
#endif
#include "wd_dummy_usr_if.h"
#include "dummy_hw_usr_if.h"

#define CPSZ 4096

#define SYS_ERR_COND(cond, msg) if(cond) { \
	perror(msg); \
	exit(EXIT_FAILURE); }

struct wd_dummy_cpy_msg *msgs;

#if 0
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
#endif

#ifdef WD_SCHED
static void wd_dummy_sched_init_cache(struct wd_scheduler *sched, int i,
				      void *priv)
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
#else
struct wd_msg {
	void *data_in;
	void *data_out;
	void *msg;	/* the hw share buffer itself */
};

struct wd_dummy_priv {
	struct wd_queue		*qs;
	int			q_num;
	int			q_send_idx;
	int			q_recv_idx;
	struct wd_msg		*caches;
	int			cache_num;
	int			cache_size;
	int			avail_cache;
	int			c_send_idx;
	int			c_recv_idx;
	struct wd_dummy_cpy_msg	*msgs;
	void			*src;
	void			*dst;
	void			*ss_region;
	int			input_num;
};

int wd_dummy_init(struct wd_dummy_priv *priv)
{
	size_t	ss_region_size;
	int	i, ret;

	priv->input_num		= 10;
	priv->q_num		= 1;
	priv->q_send_idx	= 0;
	priv->q_recv_idx	= 0;
	priv->cache_num		= 4;
	priv->cache_size	= CPSZ;
	priv->avail_cache	= priv->cache_num;
	priv->c_send_idx	= 0;
	priv->c_recv_idx	= 0;

	priv->qs = calloc(priv->q_num, sizeof(struct wd_queue));
	SYS_ERR_COND(!priv->qs, "calloc qs");

	priv->caches = calloc(priv->cache_num, sizeof(struct wd_msg));
	SYS_ERR_COND(!priv->caches, "calloc caches");

	priv->msgs = calloc(priv->cache_num, sizeof(struct wd_dummy_cpy_msg));
	SYS_ERR_COND(!priv->msgs, "calloc msgs");

	ss_region_size = priv->cache_num * CPSZ * 2 + 4096;
	for (i = 0; i < priv->q_num; i++) {
		priv->qs[i].capa.alg = "memcpy";
		ret = wd_request_queue(&priv->qs[i]);
		if (ret) {
			fprintf(stderr, "Failed to request queue (%d)\n", ret);
			return ret;
		}
	}

	priv->ss_region = wd_reserve_memory(&priv->qs[0], ss_region_size);
	if (priv->ss_region == NULL) {
		ret = -ENOMEM;
		return ret;
	}

	ret = smm_init(priv->ss_region, ss_region_size, 0xF);
	if (ret)
		goto out;

	for (i = 0; i < priv->cache_num; i++) {
		priv->caches[i].data_in	= smm_alloc(priv->ss_region,
						    priv->cache_size);
		priv->caches[i].data_out = smm_alloc(priv->ss_region,
						     priv->cache_size);
		priv->caches[i].msg	= &priv->msgs[i];
		priv->msgs[i].src_addr	= priv->caches[i].data_in;
		priv->msgs[i].tgt_addr	= priv->caches[i].data_out;
		priv->msgs[i].size	= priv->cache_size;
	}

	return ret;
out:
	wd_release_queue(&priv->qs[0]);
	return ret;
}

int wd_dummy_input(struct wd_dummy_priv *priv, int msg_idx)
{
	int value;

	value = '0' + --priv->input_num;
	memset(priv->caches[msg_idx].data_in, value, priv->cache_size);
	memset(priv->caches[msg_idx].data_out, 'x', priv->cache_size);
	return 0;
}

int wd_dummy_verify_output(struct wd_dummy_priv *priv, int msg_idx)
{
	int	i, left;
	char	*in, *out;

	in	= (char *)priv->caches[msg_idx].data_in;
	out	= (char *)priv->caches[msg_idx].data_out;

	for (i = 0; i < priv->cache_size; i++) {
		if (in[i] != out[i]) {
			printf("Verify result failure on %d\n", i);
			break;
		}
	}
	left = priv->input_num;
	printf("Verify result (%d) successfully (remained=%d)\n", in[0], left);
	return 0;
}

int wd_dummy_work(struct wd_dummy_priv *priv, int remained_task)
{
	int	ret;

	if (priv->avail_cache && remained_task) {
		wd_dummy_input(priv, priv->c_send_idx);
		do {
			ret = wd_send(&priv->qs[priv->q_send_idx],
				      priv->caches[priv->c_send_idx].msg
				      );
			if (ret == -EBUSY) {
				usleep(1);
				continue;
			} else if (ret < 0) {
				return ret;
			}
		} while (ret);
		priv->q_send_idx = (priv->q_send_idx + 1) % priv->q_num;
		priv->c_send_idx = (priv->c_send_idx + 1) % priv->cache_num;
		priv->avail_cache--;
	} else {
		do {
			ret = wd_recv_sync(&priv->qs[priv->q_recv_idx],
					   &priv->caches[priv->c_recv_idx].msg,
					   1000
					   );
			if ((ret == -EAGAIN) || (ret == -EBUSY)) {
				usleep(1);
				continue;
			} else if (ret == -EIO) {
				return ret;
			}
		} while (ret);
		wd_dummy_verify_output(priv, priv->c_recv_idx);
		priv->q_recv_idx = (priv->q_recv_idx + 1) % priv->q_num;
		priv->c_recv_idx = (priv->c_recv_idx + 1) % priv->cache_num;
		priv->avail_cache++;
	}
	return priv->avail_cache;
}

int wd_dummy_fini(struct wd_dummy_priv *priv)
{
	int i;

	for (i = 0; i < priv->q_num; i++)
		wd_release_queue(&priv->qs[i]);
	free(priv->msgs);
	free(priv->qs);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	struct wd_dummy_priv *priv;

	priv = calloc(1, sizeof(struct wd_dummy_priv));
	if (priv == NULL)
		return -ENOMEM;

	wd_dummy_init(priv);
	while (priv->input_num) {
		ret = wd_dummy_work(priv, priv->input_num);
		SYS_ERR_COND(ret < 0, "wd_dummy_work");
	}
	wd_dummy_fini(priv);
	free(priv);
	return 0;
}
#endif
