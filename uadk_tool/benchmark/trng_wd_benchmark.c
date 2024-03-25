/* SPDX-License-Identifier: Apache-2.0 */

#include <numa.h>
#include "uadk_benchmark.h"

#include "trng_wd_benchmark.h"
#include "v1/wd.h"
#include "v1/wd_rng.h"

struct thread_bd_res {
	struct wd_queue *queue;
	void *out;
	__u32 in_bytes;
};

struct thread_queue_res {
	struct thread_bd_res *bd_res;
};

struct wd_thread_res {
	u32 td_id;
	u32 pollid;
};

struct trng_async_tag {
	void *ctx;
	int optype;
};

static unsigned int g_thread_num;
static struct thread_queue_res g_thread_queue;

static int init_trng_wd_queue(struct acc_option *options)
{
	int i, ret;

	g_thread_queue.bd_res = malloc(g_thread_num * sizeof(struct thread_bd_res));
	if (!g_thread_queue.bd_res) {
		printf("failed to malloc thread res memory!\n");
		return -ENOMEM;
	}

	for (i = 0; i < g_thread_num; i++) {
		g_thread_queue.bd_res[i].queue = malloc(sizeof(struct wd_queue));
		if (!g_thread_queue.bd_res[i].queue) {
			ret = -ENOMEM;
			goto free_mem;
		}

		g_thread_queue.bd_res[i].queue->capa.alg = options->algclass;
		/* nodemask need to be clean */
		g_thread_queue.bd_res[i].queue->node_mask = 0x0;
		memset(g_thread_queue.bd_res[i].queue->dev_path, 0x0, PATH_STR_SIZE);
		if (strlen(options->device) != 0) {
			ret = snprintf(g_thread_queue.bd_res[i].queue->dev_path,
					PATH_STR_SIZE, "%s", options->device);
			if (ret < 0) {
				WD_ERR("failed to copy dev file path!\n");
				return -WD_EINVAL;
			}
		}

		g_thread_queue.bd_res[i].in_bytes = options->pktlen;
		g_thread_queue.bd_res[i].out = malloc(options->pktlen);
		if (!g_thread_queue.bd_res[i].queue) {
			free(g_thread_queue.bd_res[i].queue);
			ret = -ENOMEM;
			goto free_mem;
		}

		ret = wd_request_queue(g_thread_queue.bd_res[i].queue);
		if (ret) {
			printf("failed to request queue %d, ret = %d!\n", i, ret);
			free(g_thread_queue.bd_res[i].out);
			free(g_thread_queue.bd_res[i].queue);
			goto free_mem;
		}
	}

	return 0;

free_mem:
	for (i = i - 1; i >= 0; i--) {
		wd_release_queue(g_thread_queue.bd_res[i].queue);
		free(g_thread_queue.bd_res[i].out);
		free(g_thread_queue.bd_res[i].queue);
	}

	free(g_thread_queue.bd_res);
	return ret;
}

static void uninit_trng_wd_queue(void)
{
	int j;

	for (j = 0; j < g_thread_num; j++) {
		wd_release_queue(g_thread_queue.bd_res[j].queue);
		free(g_thread_queue.bd_res[j].out);
		free(g_thread_queue.bd_res[j].queue);
	}

	free(g_thread_queue.bd_res);
}

static void *trng_wd_sync_run(void *arg)
{
	struct wd_thread_res *pdata = (struct wd_thread_res *)arg;
	struct wcrypto_rng_ctx_setup trng_setup;
	struct wcrypto_rng_op_data opdata;
	struct wd_queue *queue;
	void *ctx = NULL;
	u32 count = 0;
	int ret;

	queue = g_thread_queue.bd_res[pdata->td_id].queue;
	ctx = wcrypto_create_rng_ctx(queue, &trng_setup);
	if (!ctx)
		return NULL;

	memset(&opdata, 0, sizeof(opdata));
	opdata.in_bytes = g_thread_queue.bd_res[pdata->td_id].in_bytes;
	opdata.out = g_thread_queue.bd_res[pdata->td_id].out;
	opdata.op_type = WCRYPTO_TRNG_GEN;

	do {
		ret = wcrypto_do_rng(ctx, &opdata, NULL);
		if (ret) {
			printf("failed to do rng task, ret: %d\n", ret);
			goto ctx_release;
		}

		count++;
		if (get_run_state() == 0)
			break;
	} while (true);

ctx_release:
	wcrypto_del_rng_ctx(ctx);
	add_recv_data(count, opdata.in_bytes);

	return NULL;
}

static void trng_wd_sync_threads(void)
{
	struct wd_thread_res threads_args[THREADS_NUM];
	pthread_t tdid[THREADS_NUM];
	int i, ret;

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].td_id = i;
		ret = pthread_create(&tdid[i], NULL, trng_wd_sync_run, &threads_args[i]);
		if (ret) {
			printf("failed to create sync thread!\n");
			return;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(tdid[i], NULL);
		if (ret) {
			printf("failed to join sync thread!\n");
			return;
		}
	}
}

void *wd_trng_poll(void *data)
{
	struct wd_thread_res *pdata = (struct wd_thread_res *)data;
	struct wd_queue *queue;
	u32 last_time = 2; // poll need one more recv time
	u32 count = 0;
	u32 in_bytes;
	int recv;

	in_bytes = g_thread_queue.bd_res[pdata->pollid].in_bytes;
	queue = g_thread_queue.bd_res[pdata->pollid].queue;

	while (last_time) {
		recv = wcrypto_rng_poll(queue, ACC_QUEUE_SIZE);
		if (recv < 0) {
			printf("failed to recv bd, ret: %d!\n", recv);
			goto recv_error;
		}
		count += recv;

		if (get_run_state() == 0)
			last_time--;
	}

recv_error:
	add_recv_data(count, in_bytes);

	return NULL;
}

static void *trng_async_cb(const void *msg, void *tag)
{
	return NULL;
}

static void *wd_trng_async_run(void *arg)
{
	struct wd_thread_res *pdata = (struct wd_thread_res *)arg;
	struct wcrypto_rng_ctx_setup trng_setup;
	struct wcrypto_rng_op_data opdata;
	struct trng_async_tag *tag = NULL;
	struct wd_queue *queue;
	void *ctx = NULL;
	int ret, i;

	memset(&opdata, 0, sizeof(opdata));

	queue = g_thread_queue.bd_res[pdata->td_id].queue;
	trng_setup.cb = (void *)trng_async_cb;

	ctx = wcrypto_create_rng_ctx(queue, &trng_setup);
	if (!ctx)
		return NULL;

	opdata.in_bytes = g_thread_queue.bd_res[pdata->td_id].in_bytes;
	opdata.out = g_thread_queue.bd_res[pdata->td_id].out;
	opdata.op_type = WCRYPTO_TRNG_GEN;

	tag = malloc(sizeof(*tag) * MAX_POOL_LENTH);
	if (!tag) {
		printf("failed to malloc dh tag!\n");
		goto free_ctx;
	}
	tag->ctx = ctx;

	do {
		ret = wcrypto_do_rng(ctx, &opdata, tag);
		if (ret && ret != -WD_EBUSY) {
			printf("failed to send trng task, ret = %d!\n", ret);
			break;
		}

		if (get_run_state() == 0)
			break;
	} while (true);

	/* Release memory after all tasks are complete. */
	i = 0;
	while (get_recv_time() != g_thread_num) {
		if (i++ >= MAX_TRY_CNT) {
			printf("failed to wait poll thread finish!\n");
			break;
		}

		usleep(SEND_USLEEP);
	}

	if (tag)
		free(tag);
free_ctx:
	wcrypto_del_rng_ctx(ctx);
	add_send_complete();

	return NULL;
}

static void trng_wd_async_threads(void)
{
	struct wd_thread_res threads_args[THREADS_NUM];
	pthread_t tdid[THREADS_NUM];
	pthread_t pollid[THREADS_NUM];
	int i, ret;

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].pollid = i;
		/* poll thread */
		ret = pthread_create(&pollid[i], NULL, wd_trng_poll, &threads_args[i]);
		if (ret) {
			printf("failed to create poll thread!\n");
			return;
		}
	}

	for (i = 0; i < g_thread_num; i++) {
		threads_args[i].td_id = i;
		ret = pthread_create(&tdid[i], NULL, wd_trng_async_run, &threads_args[i]);
		if (ret) {
			printf("failed to create async thread!\n");
			return;
		}
	}

	/* join thread */
	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(tdid[i], NULL);
		if (ret) {
			printf("failed to join async thread!\n");
			return;
		}
	}

	for (i = 0; i < g_thread_num; i++) {
		ret = pthread_join(pollid[i], NULL);
		if (ret) {
			printf("failed to join poll thread!\n");
			return;
		}
	}
}

int trng_wd_benchmark(struct acc_option *options)
{
	u32 ptime;
	int ret;

	g_thread_num = options->threads;

	ret = init_trng_wd_queue(options);
	if (ret)
		return ret;

	get_pid_cpu_time(&ptime);
	time_start(options->times);
	if (options->syncmode)
		trng_wd_async_threads();
	else
		trng_wd_sync_threads();
	cal_perfermance_data(options, ptime);

	uninit_trng_wd_queue();

	return 0;
}
