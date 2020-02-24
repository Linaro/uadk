/* SPDX-License-Identifier: Apache-2.0 */
#include "config.h"
#include <sys/poll.h>
#include "wd_sched.h"
#include "smm.h"

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
		sched->msgs[i].data_in = smm_alloc(sched->ss_region,
						   sched->msg_data_size);
		sched->msgs[i].data_out = smm_alloc(sched->ss_region,
						    sched->msg_data_size);

		if (!sched->msgs[i].data_in || !sched->msgs[i].data_out) {
			dbg("not enough data ss_region memory "
			    "for cache %d (bs=%d)\n", i, sched->msg_data_size);
			goto err_with_stat;
		}

		if (sched->init_cache)
			sched->init_cache(sched, i, sched->priv);
	}

	return 0;

err_with_stat:
	free(sched->stat);
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
	int ret, i, j;

	for (i = 0; i < sched->q_num; i++) {
		ret = wd_request_ctx(&sched->qs[i], node_path);
		if (ret)
			goto out_ctx;
		ret = sched->hw_alloc(&sched->qs[i], sched->data);
		if (ret)
			goto out_hw_ctx;
		ret = wd_start_ctx(&sched->qs[i]);
		if (ret)
			goto out_start;
	}

	if (!sched->ss_region_size)
		sched->ss_region_size = 4096 + /* add 1 page extra */
			sched->msg_cache_num * sched->msg_data_size * 2;

	if (wd_is_nosva(&sched->qs[0]))
		sched->ss_region = wd_reserve_mem(&sched->qs[0],
						  sched->ss_region_size);
	else
		sched->ss_region = malloc(sched->ss_region_size);

	if (!sched->ss_region) {
		ret = -ENOMEM;
		goto out_region;
	}

	sched->cl = sched->msg_cache_num;

	ret = smm_init(sched->ss_region, sched->ss_region_size, 0xF);
	if (ret)
		goto out_smm;

	ret = __init_cache(sched);
	if (ret)
		goto out_smm;

	return 0;

out_smm:
	if (!wd_is_nosva(&sched->qs[0]) && sched->ss_region)
		free(sched->ss_region);
out_region:
	for (i = 0; i < sched->q_num; i++) {
		wd_stop_ctx(&sched->qs[i]);
		sched->hw_free(&sched->qs[i]);
		wd_release_ctx(&sched->qs[i]);
	}
	return ret;
out_start:
	sched->hw_free(&sched->qs[i]);
out_hw_ctx:
	for (j = i - 1; j >= 0; j--) {
		wd_stop_ctx(&sched->qs[j]);
		sched->hw_free(&sched->qs[j]);
	}
	wd_release_ctx(&sched->qs[i]);
out_ctx:
	for (j = i - 1; j >= 0; j--)
		wd_release_ctx(&sched->qs[j]);
	return ret;
}

void wd_sched_fini(struct wd_scheduler *sched)
{
	int i;

	__fini_cache(sched);
	if (!wd_is_nosva(&sched->qs[0]) && sched->ss_region)
		free(sched->ss_region);
	for (i = sched->q_num - 1; i >= 0; i--) {
		wd_stop_ctx(&sched->qs[i]);
		sched->hw_free(&sched->qs[i]);
		wd_release_ctx(&sched->qs[i]);
	}
}

static int wd_wait(struct wd_ctx *ctx, __u16 ms)
{
	struct pollfd	fds[1];
	int ret;

	fds[0].fd = ctx->fd;
	fds[0].events = POLLIN;
	ret = poll(fds, 1, ms);
	if (ret == -1)
		return -errno;
	return 0;
}

static int wd_recv_sync(struct wd_scheduler *sched, struct wd_ctx *ctx,
			void **resp, __u16 ms)
{
	int ret;

	while (1) {
		ret = sched->hw_recv(ctx, resp);
		if (ret == -EBUSY) {
			ret = wd_wait(ctx, ms);
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
		ret = sched->hw_send(&sched->qs[sched->q_h],
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

static int __sync_wait(struct wd_scheduler *sched) {
	void *recv_msg;
	int ret;

	dbg("recv, ci(%d) from q(%d): %p\n", sched->c_t, sched->q_t,
	    sched->msgs[sched->c_h].msg);
	do {
		sched->stat[sched->q_t].recv++;
		ret = wd_recv_sync(sched, &sched->qs[sched->q_t],
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
		ret = __sync_wait(sched);
		if (ret)
			return ret;

		ret = sched->output(&sched->msgs[sched->c_t], sched->priv);
		if (ret)
			return ret;

		MOV_INDEX(c_t);
		sched->cl++;
	}

	return sched->cl;
}

