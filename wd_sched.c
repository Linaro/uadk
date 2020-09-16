/* SPDX-License-Identifier: Apache-2.0 */
#include "config.h"
#include "wd_sched.h"
#include "smm.h"

#define USE_POLL

/*
 * In SVA scenario, a whole user buffer could be divided into multiple frames.
 * In NOSVA scenario, data from a whole user buffer should be copied into
 * swap buffer of multiple frames first.
 * Each size of each frame should match sched->msg_data_size.
 * sched->input() and sched->output() need to check the size of each frame.
 */
static int __init_cache(struct wd_scheduler *sched)
{
	int i;
	int ret = -ENOMEM;

	sched->msgs = calloc(sched->msg_cache_num, sizeof(*sched->msgs));
	if (!sched->msgs)
		return ret;

	sched->stat = calloc(sched->q_num, sizeof(*sched->stat));
	if (!sched->stat)
		goto err_with_msgs;

	for (i = 0; i < sched->msg_cache_num; i++) {
		sched->msgs[i].next_in = NULL;
		sched->msgs[i].next_out = NULL;

		if (sched->init_cache)
			sched->init_cache(sched, i, sched->priv);
	}

	return 0;

err_with_msgs:
	free(sched->msgs);
	return ret;
}

static void __fini_cache(struct wd_scheduler *sched)
{
	free(sched->stat);
	free(sched->msgs);
}

int wd_sched_init(struct wd_scheduler *sched, char *node_path)
{
	int ret;

	sched->cl = sched->msg_cache_num;

	ret = __init_cache(sched);
	if (ret)
		return ret;

	return 0;
}

void wd_sched_fini(struct wd_scheduler *sched)
{
	__fini_cache(sched);
	if (!wd_is_nosva(sched->qs[0]) && sched->ss_region)
		free(sched->ss_region);
}

static int wd_recv_sync(struct wd_scheduler *sched, handle_t h_ctx,
			void **resp, __u16 ms)
{
	int ret;

	while (1) {
		ret = sched->hw_recv(h_ctx, resp);
		if (ret == -EBUSY) {
			ret = wd_wait(h_ctx, ms);
			if (ret)
				return ret;
		} else
			return ret;
	}
}

static int __sync_send(struct wd_scheduler *sched) {
	int ret;

	dbg("send ci(%d) to q(%d): %p\n", sched->c_h, sched->q_h,
	    sched->msgs[sched->c_h].msg);
	do {
		sched->stat[sched->q_h].send++;
		ret = sched->hw_send(sched->qs[sched->q_h],
				     sched->msgs[sched->c_h].msg);
		if (ret == -EBUSY) {
			usleep(1);
			sched->stat[sched->q_h].send_retries++;
			continue;
		}
		if (ret)
			return ret;
	} while (ret);

	sched->q_h = (sched->q_h + 1) % sched->q_num;
	return 0;
}

static int __poll_wait(struct wd_scheduler *sched) {
	void *recv_msg;
	int ret;
	int ms = 1000;

	dbg("recv, ci(%d) from q(%d): %p\n", sched->c_t, sched->q_t,
	    sched->msgs[sched->c_h].msg);
	ret = wd_wait(sched->qs[sched->q_t], ms);
	if (ret > 0) {
		do {
			handle_t h_ctx = sched->qs[sched->q_t];
			ret = sched->hw_recv(h_ctx, &recv_msg);
			if (ret == -EIO)
				return ret;
			if (ret == -EAGAIN) {
				sched->stat[sched->q_t].recv_retries++;
				break;
			}

			sched->stat[sched->q_t].recv++;
			sched->q_t = (sched->q_t + 1) % sched->q_num;

			if (recv_msg != sched->msgs[sched->c_t].msg) {
				fprintf(stderr, "recv msg %p and input %p mismatch\n",
						recv_msg, sched->msgs[sched->c_t].msg);
				return -EINVAL;
			}

			ret = sched->output(&sched->msgs[sched->c_t], sched->priv);
			if (ret)
				return ret;

			sched->c_t = (sched->c_t + 1) % sched->msg_cache_num;
			sched->cl++;
		} while(!ret);

	}

	return ret;
}

static int __sync_wait(struct wd_scheduler *sched) {
	void *recv_msg;
	int ret;

	dbg("recv, ci(%d) from q(%d): %p\n", sched->c_t, sched->q_t,
	    sched->msgs[sched->c_h].msg);
	do {
		sched->stat[sched->q_t].recv++;
		ret = wd_recv_sync(sched, sched->qs[sched->q_t],
				   &recv_msg, 1000);
		if (ret == -EAGAIN) {
			usleep(1);
			sched->stat[sched->q_t].recv_retries++;
			continue;
		} else if (ret == -EIO)
			return ret;

		if (recv_msg != sched->msgs[sched->c_t].msg) {
			fprintf(stderr, "recv msg %p and input %p mismatch\n",
				recv_msg, sched->msgs[sched->c_t].msg);
			return -EINVAL;
		}
	} while (ret);

	sched->q_t = (sched->q_t + 1) % sched->q_num;
	return 0;
}

/* return number of msg in the sent cache or negative errno */
int wd_sched_work(struct wd_scheduler *sched, unsigned long remained)
{
	int ret;

#define MOV_INDEX(id) do { \
	sched->id = (sched->id + 1) % sched->msg_cache_num; \
} while(0)

	dbg("sched: cl=%d, data_remained=%d\n", sched->cl, remained);

	if (sched->cl && remained) {
		ret = sched->input(&sched->msgs[sched->c_h], sched->priv);
		if (ret)
			return ret;

		ret = __sync_send(sched);
		if (ret)
			return ret;

		MOV_INDEX(c_h);
		sched->cl--;
	} else {
#ifdef USE_POLL
		ret = __poll_wait(sched);
		if (ret && ret != -EAGAIN)
			return ret;
#else

		ret = __sync_wait(sched);
		if (ret)
			return ret;

		ret = sched->output(&sched->msgs[sched->c_t], sched->priv);
		if (ret)
			return ret;

		MOV_INDEX(c_t);
		sched->cl++;
#endif
	}

	return sched->cl;
}

