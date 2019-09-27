// SPDX-License-Identifier: Apache-2.0
#include "config.h"
#include "wd_util.h"
#include "wd_sched.h"
#include "smm.h"

#define EXTRA_SIZE		4096
#define WD_WAIT_MS		1000

static int __init_cache(struct wd_scheduler *sched)
{
	int i;
	int ret = -ENOMEM;

	sched->msgs = calloc(sched->msg_cache_num, sizeof(*sched->msgs));
	if (!sched->msgs) {
		WD_ERR("calloc for sched->msgs fail!\n");
		return ret;
	}
	sched->stat = calloc(sched->q_num, sizeof(*sched->stat));
	if (!sched->stat) {
		WD_ERR("calloc for sched->stat fail!\n");
		goto err_with_msgs;
	}
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
			sched->init_cache(sched, i);
	}

	return 0;

err_with_stat:
	free(sched->stat);
	sched->stat = NULL;
err_with_msgs:
	free(sched->msgs);
	sched->msgs = NULL;
	return ret;
}

static void __fini_cache(struct wd_scheduler *sched)
{
	if (sched->stat) {
		free(sched->stat);
		sched->stat = NULL;
	}
	if (sched->msgs) {
		free(sched->msgs);
		sched->msgs = NULL;
	}
}

static int wd_sched_preinit(struct wd_scheduler *sched)
{
	int ret, i, j;
	unsigned int flags = 0;
	struct q_info *qinfo;

	for (i = 0; i < sched->q_num; i++) {
		ret = wd_request_queue(&sched->qs[i]);
		if (ret) {
			WD_ERR("fail to request queue!\n");
			goto out_with_queues;
		}
	}

	if (!sched->ss_region_size)
		sched->ss_region_size = EXTRA_SIZE + /* add 1 page extra */
			sched->msg_cache_num * (sched->msg_data_size << 0x1);

	qinfo = sched->qs[0].info;
	flags = qinfo->dev_flags;
	if (flags & UACCE_DEV_PASID)
		sched->ss_region = malloc(sched->ss_region_size);
	else
		sched->ss_region = wd_reserve_memory(&sched->qs[0],
				   sched->ss_region_size);

	if (!sched->ss_region) {
		WD_ERR("fail to alloc sched ss region mem!\n");
		ret = -ENOMEM;
		goto out_with_queues;
	}

	return 0;

out_with_queues:
	if (flags & UACCE_DEV_PASID) {
		if (sched->ss_region) {
			free(sched->ss_region);
			sched->ss_region = NULL;
		}
	}
	for (j = i-1; j >= 0; j--)
		wd_release_queue(&sched->qs[j]);
	return ret;
}


int wd_sched_init(struct wd_scheduler *sched)
{
	int ret, j, k;
	unsigned int flags;
	struct q_info *qinfo;

	ret = wd_sched_preinit(sched);
	if (ret < 0)
		return -EINVAL;

	qinfo = sched->qs[0].info;
	flags = qinfo->dev_flags;
	if (!(flags & UACCE_DEV_PASID)) {
		for (k = 1; k < sched->q_num; k++) {
			ret = wd_share_reserved_memory(&sched->qs[0],
						       &sched->qs[k]);
			if (ret) {
				WD_ERR("fail to share queue reserved mem!\n");
				goto out_with_queues;
			}
		}
	}

	sched->cl = sched->msg_cache_num;

	ret = smm_init(sched->ss_region, sched->ss_region_size, 0xF);
	if (ret) {
		WD_ERR("fail to init smm!\n");
		goto out_with_queues;
	}

	ret = __init_cache(sched);
	if (ret) {
		WD_ERR("fail to init caches!\n");
		goto out_with_queues;
	}

	return 0;

out_with_queues:
	if (flags & UACCE_DEV_PASID) {
		if (sched->ss_region) {
			free(sched->ss_region);
			sched->ss_region = NULL;
		}
	}
	for (j = sched->q_num - 1; j >= 0; j--)
		wd_release_queue(&sched->qs[j]);
	return ret;
}

void wd_sched_fini(struct wd_scheduler *sched)
{
	int i;
	struct q_info *qinfo = sched->qs[0].info;
	unsigned int flags = qinfo->dev_flags;

	__fini_cache(sched);
	if (flags & UACCE_DEV_PASID) {
		if (sched->ss_region) {
			free(sched->ss_region);
			sched->ss_region = NULL;
		}
	}
	for (i = sched->q_num - 1; i >= 0; i--)
		wd_release_queue(&sched->qs[i]);
}

static int __sync_send(struct wd_scheduler *sched)
{
	int ret;

	dbg("send ci(%d) to q(%d): %p\n", sched->c_h, sched->q_h,
	    sched->msgs[sched->c_h].msg);
	do {
		sched->stat[sched->q_h].send++;
		ret = wd_send(&sched->qs[sched->q_h],
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

static int __sync_wait(struct wd_scheduler *sched)
{
	void *recv_msg = NULL;
	int ret;

	dbg("recv, ci(%d) from q(%d): %p\n", sched->c_t, sched->q_t,
	    sched->msgs[sched->c_h].msg);
	do {
		sched->stat[sched->q_t].recv++;
		ret = wd_recv(&sched->qs[sched->q_t], &recv_msg);
		if (ret == 0) {
			sched->stat[sched->q_t].recv_retries++;
			continue;
		} else if (ret == -WD_EIO  || ret == -WD_HW_EACCESS)
			return ret;

		if (recv_msg != sched->msgs[sched->c_t].msg) {
			fprintf(stderr, "recv msg %p and input %p mismatch\n",
				recv_msg, sched->msgs[sched->c_t].msg);
			return -EINVAL;
		}
	} while (!ret);

	sched->q_t = (sched->q_t + 1) % sched->q_num;
	return 0;
}

/* return number of msg in the sent cache or negative errno */
int wd_sched_work(struct wd_scheduler *sched, int remained)
{
	int ret;

#define MOV_INDEX(id) do { \
	sched->id = (sched->id + 1) % sched->msg_cache_num; \
} while (0)

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

