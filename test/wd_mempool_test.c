/*
 * We consider three problems: 1. Rate of memory usage;
 * 2. performance of alloc/free; 3. memory fragmentation.
 *
 * 1. mempool create from huge page
 * 2. mempool create from mmap + pin
 *
 * 3. mempool create from huge page, blk pool small block size
 * 4. mempool create from huge page, blk pool big block size
 *
 * 5. mempool create from mmap + pin, blk pool small block size
 * 6. mempool create from mmap + pin, blk pool big block size
 */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/time.h>

#include "hisi_sec_test/test_hisi_sec.h"
#include "wd.h"
#include "wd_cipher.h"
#include "sched_sample.h"

#define WD_MEM_MAX_THREAD	20
#define WD_MEM_MAX_BUF_SIZE	256

#define SEC_TST_PRT printf
#define HW_CTX_SIZE (24 * 1024)
#define BUFF_SIZE 1024
#define IV_SIZE   256
#define THREADS_NUM     64
#define SVA_THREADS     64
#define USE_CTX_NUM     64
#define BYTES_TO_MB     20

#define SCHED_SINGLE "sched_single"
#define SCHED_NULL_CTX_SIZE     4
#define TEST_WORD_LEN   4096
#define MAX_ALGO_PER_TYPE 12
#define MIN_SVA_BD_NUM 1

static struct wd_ctx_config g_ctx_cfg;

static long long int g_times;
static unsigned int g_thread_num;
static unsigned int g_blknum;
static unsigned int g_syncmode;
static unsigned int g_ctxnum;
static pthread_spinlock_t lock = 0;
static __u32 last_ctx = 0;

struct test_option {
	unsigned long mp_size;
	int node;
	unsigned long blk_size[WD_MEM_MAX_THREAD];
	unsigned long blk_num[WD_MEM_MAX_THREAD];
	unsigned long sleep_value[WD_MEM_MAX_THREAD];
	unsigned long perf;
	unsigned thread_num;
	__u32 algclass;
	__u32 algtype;
	__u32 optype;
	__u32 pktlen;
	__u32 keylen;
	__u32 times;
	__u32 syncmode;
	__u32 xmulti;
	__u32 ctxnum;
	__u32 block;
	__u32 blknum;
};

struct sva_bd {
	char *src;
	char *dst;
};

struct sva_bd_pool {
	struct sva_bd *bds;
};

struct test_opt_per_thread {
	unsigned long mp_size;
	int tid;
	int flag;
	int mode;
	int cpu_id;
	int node;
	unsigned long blk_size;
	unsigned long blk_num;
	unsigned long sleep_value;
	unsigned thread_num;
	struct wd_cipher_req *req;
	struct wd_cipher_sess_setup *setup;
	struct timeval start_tval;
	unsigned long long send_task_num;
	unsigned long long recv_task_num;
	struct sva_bd_pool *bd_pool;

	handle_t mp, bp;
};

static pthread_t system_test_thrds[THREADS_NUM];
static struct test_opt_per_thread thr_data[THREADS_NUM];

static void show_help(void)
{
	printf(" --mp_size <size>	 mempool size\n"
			" --node <node>	 numa node of mempool\n"
			" --blk_size_array <\"size1 size2 ...\">\n"
			"			 size of each block pool\n"
			" --blk_num_array <\"num1 num2 ...\">\n"
			"			 block num of each block pool\n"
			" --sleep_value <\"value1 value2 ...\">\n"
			"			 test thread will sleep some time between\n"
			"			 allocating and freeing memory, these values\n"
			"			 are for this purpose\n"
			" --perf <mode>	 0 for mempool, 1 for block pool, 2 for sec's alg perf\n"
			" --multi <num>  pthread num\n"
			" --times <num>  if perf is 2, this is times for sec's alg in every pthread\n"
			" --ctxnum <num> ctx num\n"
			"			 in blkpool\n"
			" --path	     file's path\n"
			" --help		 show this help\n");
}

static int parse_value_in_string(unsigned long *array, unsigned long num,
		char *string)
{
	char str[WD_MEM_MAX_BUF_SIZE];
	char *tmp, *str_t;
	int i = 0;

	strncpy(str, string, WD_MEM_MAX_BUF_SIZE - 1);
	str[WD_MEM_MAX_BUF_SIZE - 1] = '\0';
	str_t = str;

	while ((tmp = strtok(str_t, " ")) && i < num) {
		array[i++] = strtol(tmp, NULL, 0);
		str_t = NULL;
	}

	if (i == num) {
		WD_ERR("Input parameter more than %lu\n", num);
		return -1;
	}

	return 0;
}

void dump_parse(struct test_option *opt)
{
	int i;
	char perf_str[3][16] = {"mempool test", "blkpool test", "perf test"};

	printf("---------------------------------------\n");
	printf(" This is %s\n", perf_str[opt->perf]);
	printf(" mp_size: %lu\n", opt->mp_size);
	printf(" node: %d\n", opt->node);
	printf(" thread_num: %u\n\n", g_thread_num);
	for (i = 0; i < g_thread_num; i++) {
		printf(" pthread %d:", i + 1);
		printf("blk_size-%lu ", opt->blk_size[i]);
		printf("blk_num-%lu ", opt->blk_num[i]);
		printf("sleep_value-%lu\n", opt->sleep_value[i]);
	}

	printf("---------------------------------------\n");
}

static int test_sec_option_convert(struct test_option *option);

static int parse_cmd_line(int argc, char *argv[], struct test_option *opt)
{
	int option_index = 0;
	int c, ret;

	static struct option long_options[] = {
		{"mp_size",		required_argument, 0, 1},
		{"node",		required_argument, 0, 2},
		{"blk_size_array", 	required_argument, 0, 3},
		{"blk_num_array", 	required_argument, 0, 4},
		{"sleep_value",		required_argument, 0, 5},
		{"perf",		required_argument, 0, 6},
		{"multi",		required_argument, 0, 7},
		{"times",		required_argument, 0, 8},
		{"sync",		no_argument,       0, 9},
		{"async",		no_argument,       0, 10},
		{"ctxnum",		required_argument, 0, 11},
		{"help",		no_argument,       0, 12},
		{0, 0, 0, 0}
	};


	opt->syncmode = 0;
	while (1) {
		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 1:
				opt->mp_size = strtol(optarg, NULL, 0);
				break;
			case 2:
				opt->node = strtol(optarg, NULL, 0);
				break;
			case 3:
				parse_value_in_string(opt->blk_size, WD_MEM_MAX_THREAD,
						optarg);
				break;
			case 4:
				parse_value_in_string(opt->blk_num, WD_MEM_MAX_THREAD,
						optarg);
				break;
			case 5:
				parse_value_in_string(opt->sleep_value,
						WD_MEM_MAX_THREAD, optarg);
				break;
			case 6:
				opt->perf = strtol(optarg, NULL, 0);
				break;
			case 7:
				opt->xmulti = strtol(optarg, NULL, 0);
				break;
			case 8:
				opt->times = strtol(optarg, NULL, 0);
				break;
			case 9:
				opt->syncmode = 0;
				break;
			case 10:
				opt->syncmode = 1;
				break;
			case 11:
				opt->ctxnum = strtol(optarg, NULL, 0);
				break;
			case 12:
				show_help();
				return -1;
			default:
				printf("bad input parameter, exit\n");
				show_help();
				return -1;
		}
	}

	ret = test_sec_option_convert(opt);
	if (ret)
		return ret;

	dump_parse(opt);
	return 0;
}

static void dump_mp_bp(struct wd_mempool_stats *mp_s, struct wd_pool_stats *bp_s)
{
	printf("---------------------------------------\n");
	printf("dump mp bp info:\n");
	printf("mp page_type	    : %s\n", mp_s->page_type ? "pin" : "hugepage");
	printf("mp page_size	    : %lu\n", mp_s->page_size);
	printf("mp page_num	    : %lu\n", mp_s->page_num);
	printf("mp blk_size	    : %lu\n", mp_s->blk_size);
	printf("mp blk_num	    : %lu\n", mp_s->blk_num);
	printf("mp free_blk_num	    : %lu\n", mp_s->free_blk_num);
	printf("mp blk_usage_rate   : %lu%%\n\n", mp_s->blk_usage_rate);

	printf("bp block_size	    : %lu\n", bp_s->block_size);
	printf("bp block_num	    : %lu\n", bp_s->block_num);
	printf("bp free_block_num   : %lu\n", bp_s->free_block_num);
	printf("bp block_usage_rate : %lu%%\n", bp_s->block_usage_rate);
	printf("bp mem_waste_rate   : %lu%%\n\n", bp_s->mem_waste_rate);
	printf("---------------------------------------\n");
}

void *alloc_free_thread(void *data)
{
	struct test_opt_per_thread *opt = data;
	int i, j;
	char *p;

	/* fix me: temporarily make iterate num to 100 */
	for (i = 0; i < 100; i++) {
		p = wd_block_alloc(opt->bp);
		if (!p) {
			printf("Fail to alloc mem\n");
		}

		for (j = 0; j < 10; j++) {
			*(p + j) = 8;
		}

		sleep(opt->sleep_value);

		wd_block_free(opt->bp, p);
	}

	printf("alloc_free_thread successful\n");
	return NULL;
}

static int test_blkpool(struct test_option *opt)
{
	struct test_opt_per_thread per_thread_opt[WD_MEM_MAX_THREAD] = {0};
	pthread_t threads[WD_MEM_MAX_THREAD];
	int i, bp_thread_num = g_thread_num;
	handle_t mp, bp;

	mp = wd_mempool_create(opt->mp_size, opt->node);
	if (WD_IS_ERR(mp)) {
		printf("Fail to create mempool, err(%lld)!\n", WD_HANDLE_ERR(mp));
		return -1;
	}

	bp = wd_pool_create(mp, opt->blk_size[0], opt->blk_num[0]);
	if (WD_IS_ERR(bp)) {
		printf("Fail to create blkpool, err(%lld)!\n", WD_HANDLE_ERR(bp));
		return -1;
	}

	for (i = 0; i < bp_thread_num; i++) {
		per_thread_opt[i].mp = mp;
		per_thread_opt[i].bp = bp;
		per_thread_opt[i].sleep_value = opt->sleep_value[i];

		pthread_create(&threads[i], NULL, alloc_free_thread,
				&per_thread_opt[i]);
	}

	for (i = 0; i < bp_thread_num; i++) {
		pthread_join(threads[i], NULL);
	}

	wd_pool_destory(bp);
	wd_mempool_destory(mp);

	return 0;
}

void *blk_test_thread(void *data)
{
	struct test_opt_per_thread *opt = data;
	struct wd_pool_stats bp_stats = {0};
	struct wd_mempool_stats mp_stats = {0};
	handle_t mp, bp;

	mp = wd_mempool_create(opt->mp_size, opt->node);
	if (WD_IS_ERR(mp)) {
		printf("Fail to create mempool, err %lld\n", WD_HANDLE_ERR(mp));
		return (void *)-1;
	}

	bp = wd_pool_create(mp, opt->blk_size, opt->blk_num);
	if (WD_IS_ERR(bp)) {
		printf("Fail to create blkpool, err %lld\n", WD_HANDLE_ERR(bp));
		return (void *)-1;
	}


	char *block = wd_block_alloc(bp);
	if (!block) {
		printf("Fail to alloc block\n");
		return (void *)-1;
	}

	int i, j;
	j = opt->blk_size / 10;
	for (i = 0;i < j;i++)
		strcpy(block + i * 10, "xaaxaaxaax");

	printf("please check memory about numa, input any key and Entry key then go on:");
	j = scanf("%d", &i);

	sleep(opt->sleep_value);
	/* fix me: need a opt? */
	if (1) {
		wd_mempool_stats(mp, &mp_stats);
		wd_pool_stats(bp, &bp_stats);
		dump_mp_bp(&mp_stats, &bp_stats);
	}

	wd_block_free(bp, block);
	wd_pool_destory(bp);
	wd_mempool_destory(mp);

	printf("test mempool successful!\n");
	return NULL;
}

static int test_mempool(struct test_option *opt)
{
	struct test_opt_per_thread per_thread_opt[WD_MEM_MAX_THREAD] = {0};
	pthread_t threads[WD_MEM_MAX_THREAD];
	int i, bp_thread_num = g_thread_num;

	printf("mempool(thread_num=%d) is testing...\n", bp_thread_num);

	for (i = 0; i < bp_thread_num; i++) {
		per_thread_opt[i].mp_size = opt->mp_size;
		per_thread_opt[i].node = opt->node;
		per_thread_opt[i].blk_size = opt->blk_size[i];
		per_thread_opt[i].blk_num = opt->blk_num[i];
		per_thread_opt[i].sleep_value = opt->sleep_value[i];

		pthread_create(&threads[i], NULL, blk_test_thread,
				&per_thread_opt[i]);
	}

	for (i = 0; i < bp_thread_num; i++) {
		pthread_join(threads[i], NULL);
	}

	return 0;
}

static __u32 sva_sched_pick_next_ctx(handle_t h_sched_ctx, const void *req,
                                        const struct sched_key *key)
{
        __u32 index;

        pthread_spin_lock(&lock);
        if (++last_ctx == g_ctx_cfg.ctx_num)
                last_ctx = 0;
        index = last_ctx;
        pthread_spin_unlock(&lock);

        return index;
}

static int sva_sched_poll_policy(handle_t h_sched_ctx, __u32 expect,
                                 __u32 *count)
{
        int recv = 0;
        int ret = 0;
        __u32 cnt;
        int i;

        if (unlikely(g_ctx_cfg.ctxs[0].ctx_mode != CTX_MODE_ASYNC)) {
                SEC_TST_PRT("ctx mode is not AYNC!\n");
                *count = 0;
                return -1;
        }

        for (i = 0; i < g_ctx_cfg.ctx_num; i++) {
                ret = wd_cipher_poll_ctx(i, 1, &cnt);
                /* ret is 0 means no error and recv 1 finished task */
                if (!ret)
                        recv++;
                /* here is an error, return ret and recv num currently */
                else if (ret != -EAGAIN)
                        break;
        }

        *count = recv;

        return ret;
}

static int sva_init_ctx_config(int type, int mode)
{
	struct uacce_dev_list *list;
	struct wd_sched sched;
	struct wd_ctx *ctx_attr;
	int ret;
	int i;

	list = wd_get_accel_list("cipher");
	if (!list)
		return -ENODEV;

	memset(&g_ctx_cfg, 0, sizeof(struct wd_ctx_config));
	if (g_ctxnum > USE_CTX_NUM)
		SEC_TST_PRT("ctx nums request too much!\n");

	ctx_attr = malloc(g_ctxnum * sizeof(struct wd_ctx));
	if (!ctx_attr) {
		SEC_TST_PRT("malloc ctx_attr memory fail!\n");
		return -ENOMEM;
	}
	memset(ctx_attr, 0, g_ctxnum * sizeof(struct wd_ctx));

	/* Just use first found dev to test here */
	for (i = 0; i < g_ctxnum; i++) {
		ctx_attr[i].ctx = wd_request_ctx(list->dev);
		if (!ctx_attr[i].ctx) {
			ret = -EINVAL;
			SEC_TST_PRT("Fail to request ctx!\n");
			goto out;
		}
		ctx_attr[i].op_type = type;
		ctx_attr[i].ctx_mode = mode;
	}

	g_ctx_cfg.ctx_num = g_ctxnum;
	g_ctx_cfg.ctxs = ctx_attr;
	sched.name = "sched_multi";
	sched.pick_next_ctx = sva_sched_pick_next_ctx;
	sched.poll_policy = sva_sched_poll_policy;
	/*cipher init*/
	ret = wd_cipher_init(&g_ctx_cfg, &sched);
	if (ret) {
		SEC_TST_PRT("Fail to cipher ctx!\n");
		goto out;
	}
	wd_free_list_accels(list);

	return 0;
out:
	free(ctx_attr);
	return ret;
}

static void sva_uninit_config(void)
{
	int i;

	wd_cipher_uninit();
	for (i = 0; i < g_ctx_cfg.ctx_num; i++)
		wd_release_ctx(g_ctx_cfg.ctxs[i].ctx);
	free(g_ctx_cfg.ctxs);
}

static void *async_cb(struct wd_cipher_req *req, void *data)
{
	return NULL;
}

static void *sva_sec_cipher_sync(void *arg)
{
	struct test_opt_per_thread *pdata = (struct test_opt_per_thread *)arg;
	struct wd_cipher_sess_setup *setup = pdata->setup;
        struct wd_cipher_req *req = pdata->req;
        struct cipher_testvec *tv = &aes_cbc_perf_128[0];;
        struct timeval cur_tval;
        unsigned long Perf = 0, pktlen;
        handle_t        h_sess;
        float speed, time_used;
        unsigned int count = 0;
        int cnt = g_times;
        int ret;
        int j;

        gettimeofday(&pdata->start_tval, NULL);
        h_sess = wd_cipher_alloc_sess(setup);
        if (!h_sess)
                return NULL;

        pktlen = BUFF_SIZE;
        ret = wd_cipher_set_key(h_sess, (const __u8*)tv->key, tv->klen);
        if (ret) {
                SEC_TST_PRT("test sec cipher set key is failed!\n");
                goto out;;
        }
        /* run task */
        while (cnt) {
                j = count % g_blknum;
                req->src = pdata->bd_pool->bds[j].src;
                req->dst = pdata->bd_pool->bds[j].dst;
                ret = wd_do_cipher_sync(h_sess, req);
                cnt--;
                pdata->send_task_num++;
                count++;
        }

        gettimeofday(&cur_tval, NULL);
        time_used = (float)((cur_tval.tv_sec - pdata->start_tval.tv_sec) * 1000000 +
                                cur_tval.tv_usec - pdata->start_tval.tv_usec);
        speed = pdata->send_task_num / time_used * 1000000;
        Perf = speed * pktlen / 1024; //B->KB
        SEC_TST_PRT("Sync Mode thread time_used:%0.0f us, Perf: %ld KB/s\n",
                        time_used, Perf);

out:
        wd_cipher_free_sess(h_sess);
        return NULL;
}

static int sva_sync_create_threads(int thread_num, struct wd_cipher_req *reqs,
		struct wd_cipher_sess_setup *setups, struct test_opt_per_thread *tds)
{
	int thread_id = (int)syscall(__NR_gettid);
	struct timeval start_tval, cur_tval;
	unsigned long Perf = 0;
	float speed, time_used;
	pthread_attr_t attr;
	int i, ret;

	if (thread_num > SVA_THREADS) {
		SEC_TST_PRT("can't creat %d threads", thread_num);
		return -EINVAL;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	gettimeofday(&start_tval, NULL);
	for (i = 0; i < thread_num; i++) {
		thr_data[i].tid = i;
		thr_data[i].req = &reqs[i];
		thr_data[i].setup = &setups[i];
		thr_data[i].bd_pool = tds[i].bd_pool;
		ret = pthread_create(&system_test_thrds[i], &attr,
				sva_sec_cipher_sync, &thr_data[i]);
		if (ret) {
			SEC_TST_PRT("Failed to create thread, ret:%d\n", ret);
			return ret;
		}
	}

	thr_data[i].tid = i;
	pthread_attr_destroy(&attr);
	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
	}

	gettimeofday(&cur_tval, NULL);
	time_used = (double)((cur_tval.tv_sec - start_tval.tv_sec) * 1000000 +
			cur_tval.tv_usec - start_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%llu\n", time_used, g_times * g_thread_num);
	speed = g_times * g_thread_num / time_used * 1000000;
	Perf = speed * BUFF_SIZE / 1024; //B->KB
	SEC_TST_PRT("Sync mode avg Pro-%d, thread_id-%d, speed:%f ops, Perf: %ld KB/s\n",
			getpid(), thread_id, speed, Perf);

	return 0;
}

static void *sva_sec_cipher_async(void *arg)
{
	struct test_opt_per_thread *pdata = (struct test_opt_per_thread *)arg;
	struct wd_cipher_sess_setup *setup = pdata->setup;
	struct wd_cipher_req *req = pdata->req;
        struct cipher_testvec *tv = &aes_cbc_perf_128[0];;
	unsigned int count = 0;
        int cnt = g_times;
        handle_t h_sess;
        int ret;
        int j, i;

	setup->alg = WD_CIPHER_AES;
        setup->mode = WD_CIPHER_CBC;

	h_sess = wd_cipher_alloc_sess(setup);
        if (!h_sess)
                return NULL;

        ret = wd_cipher_set_key(h_sess, (const __u8*)tv->key, tv->klen);
        if (ret) {
                SEC_TST_PRT("test sec cipher set key is failed!\n");
                goto out;;
        }
	i = cnt;
        /* run task */
        do {
try_do_again:
                j = count % g_blknum;
                req->src = pdata->bd_pool->bds[j].src;
                req->dst = pdata->bd_pool->bds[j].dst;
                ret = wd_do_cipher_async(h_sess, req);
		i--;
                if (ret == -EBUSY) { // busy
                        usleep(100);
                        goto try_do_again;
                } else if (ret) {
                        SEC_TST_PRT("test sec cipher send req is error!\n");
                        goto out;
                }
                cnt--;
                count++;
        } while (cnt);

        ret = 0;
out:
        wd_cipher_free_sess(h_sess);
        return NULL;
}

static void *sva_poll_func(void *arg)
{
	__u32 count = 0;
	__u32 recv = 0;
	int ret;

	int expt = g_times * g_thread_num;

	while (1) {
		ret = wd_cipher_poll(1, &count);
		if (ret < 0 && ret != -EAGAIN) {
			SEC_TST_PRT("poll ctx recv: %u\n", recv);
			break;
		}

		recv += count;
		if (expt == recv) {
			break;
		}
	}

	pthread_exit(NULL);
	return NULL;
}

static int sva_async_create_threads(int thread_num, struct wd_cipher_req *reqs,
		struct wd_cipher_sess_setup *setups, struct test_opt_per_thread *tds)
{
	int thread_id = (int)syscall(__NR_gettid);
	struct timeval start_tval, cur_tval;
	unsigned long Perf = 0;
	float speed, time_used;
	pthread_attr_t attr;
	int i, ret;

	if (thread_num > SVA_THREADS) {
		SEC_TST_PRT("can't creat %d threads", thread_num);
		return -EINVAL;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	gettimeofday(&start_tval, NULL);
	for (i = 0; i < thread_num; i++) {
		thr_data[i].tid = i;
		thr_data[i].req = &reqs[i];
		thr_data[i].setup = &setups[i];
		thr_data[i].bd_pool = tds[i].bd_pool;
		ret = pthread_create(&system_test_thrds[i], &attr, sva_sec_cipher_async, &thr_data[i]);
		if (ret) {
			SEC_TST_PRT("Failed to create thread, ret:%d\n", ret);
			return ret;
		}
	}

	ret = pthread_create(&system_test_thrds[i], &attr, sva_poll_func, NULL);
	if (ret) {
		SEC_TST_PRT("Failed to create poll thread, ret:%d\n", ret);
		return ret;
	}
	pthread_attr_destroy(&attr);
	for (i = 0; i < thread_num; i++) {
		ret = pthread_join(system_test_thrds[i], NULL);
		if (ret) {
			SEC_TST_PRT("Join %dth thread fail!\n", i);
			return ret;
		}
	}
	// asyn_thread_exit = 1;
	ret = pthread_join(system_test_thrds[i], NULL);
	if (ret) {
		SEC_TST_PRT("Join %dth thread fail!\n", i);
		return ret;
	}

	gettimeofday(&cur_tval, NULL);
	time_used = (double)((cur_tval.tv_sec - start_tval.tv_sec) * 1000000 +
			cur_tval.tv_usec - start_tval.tv_usec);
	SEC_TST_PRT("time_used:%0.0f us, send task num:%llu\n", time_used, g_times * g_thread_num);
	speed = g_times * g_thread_num / time_used * 1000000;
	Perf = speed * BUFF_SIZE / 1024; //B->KB
	SEC_TST_PRT("Async mode Pro-%d, thread_id-%d, speed:%f ops, Perf: %ld KB/s\n",
			getpid(), thread_id, speed, Perf);

	return 0;
}


int init_bd_pool(struct test_opt_per_thread *td)
{
	struct cipher_testvec *tv = &aes_cbc_perf_128[0];
	int i, j = 0;

	td->bd_pool = malloc(sizeof(struct sva_bd_pool));
	if (!td->bd_pool) {
                SEC_TST_PRT("init bd pool alloc thread failed!\n");
                return -ENOMEM;
        }
        td->bd_pool->bds = malloc(g_times * sizeof(struct sva_bd));
	if (!td->bd_pool->bds) {
                SEC_TST_PRT("init bd pool bds alloc thread failed!\n");
                free(td->bd_pool);
                return -ENOMEM;
        }

        for (i = 0; i < g_times; i++) {
                td->bd_pool->bds[i].src = wd_block_alloc(td->bp);
                if (!td->bd_pool->bds[i].src) {
                        SEC_TST_PRT("block(%u) fail to alloc src mem!!\n", i);
                        goto src_fail;
                }

                td->bd_pool->bds[i].dst = wd_block_alloc(td->bp);
		if (!td->bd_pool->bds[i].dst) {
                        SEC_TST_PRT("block(%u) fail to alloc dst mem!!\n", i);
                        goto dst_fail;
                }
                memcpy(td->bd_pool->bds[i].src, tv->ptext, tv->len);
        }

        return 0;

src_fail:
	for (j = 0;j < i; j++) {
                wd_block_free(td->bp, td->bd_pool->bds[i].dst);
dst_fail:
                wd_block_free(td->bp, td->bd_pool->bds[i].src);
        }
	free(td->bd_pool->bds);
	free(td->bd_pool);

	return -ENOMEM;
}

void free_bd_pool(struct test_opt_per_thread *td)
{
        int i;

	for (i = 0; i < g_times; i++) {
		wd_block_free(td->bp, td->bd_pool->bds[i].dst);
		wd_block_free(td->bp, td->bd_pool->bds[i].src);
	}

	free(td->bd_pool->bds);
	free(td->bd_pool);
}

static int test_sec_perf(struct test_option *opt)
{
	struct test_opt_per_thread datas[WD_MEM_MAX_THREAD] = {0};
	struct wd_cipher_sess_setup setup[WD_MEM_MAX_THREAD];
	struct wd_cipher_req req[WD_MEM_MAX_THREAD];
	struct cipher_testvec *tv = &aes_cbc_perf_128[0];
	handle_t mp;
	int i;
	int ret = 0;

	int bp_thread_num = g_thread_num;

	memset(datas, 0, sizeof(struct test_opt_per_thread) * WD_MEM_MAX_THREAD);
	memset(req, 0, sizeof(struct wd_cipher_req) * WD_MEM_MAX_THREAD);
	memset(setup, 0, sizeof(struct wd_cipher_sess_setup) * WD_MEM_MAX_THREAD);

	if (g_syncmode == 0)
		ret = sva_init_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC);
	else
		ret = sva_init_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_ASYNC);
	if (ret) {
		SEC_TST_PRT("fail to init ctx config!\n");
		goto init_ctx_fail;
	}

	SEC_TST_PRT("test alg: %s(128)\n", "cbc(aes)");
	mp = wd_mempool_create(opt->mp_size, opt->node);
	if (WD_IS_ERR(mp)) {
		SEC_TST_PRT("node(%u) mem_size(%lu), fail to create memory pool, err(%lld)!\n",
							opt->node, opt->mp_size, WD_HANDLE_ERR(mp));
		goto mp_fail;
	}

	for (i = 0; i < bp_thread_num; i++) {
		datas[i].bp = wd_pool_create(mp, opt->blk_size[i], opt->blk_num[i]);
		if (WD_IS_ERR(datas[i].bp)) {
			SEC_TST_PRT("blk_size(%lu) blk_num(%lu), thread(%u) is fail to create blk_pool, err(%lld)\n",
									opt->blk_size[i], opt->blk_num[i], i, WD_HANDLE_ERR(datas[i].bp));
			goto bp_fail;
		}

		SEC_TST_PRT("blk_size(%lu) blk_num(%lu), thread(%u) is success to create blk_pool!!\n", opt->blk_size[i], opt->blk_num[i], i);

		ret = init_bd_pool(&datas[i]);
		if (ret < 0){
			SEC_TST_PRT("thread(%u) fail to alloc bd!!\n", i);
			goto init_bd_pool_fail;
		}
		SEC_TST_PRT("thread(%u) success to alloc bd pool!!\n", i);

		req[i].src = wd_block_alloc(datas[i].bp);
		if (!req[i].src) {
			SEC_TST_PRT("thread(%u) fail to alloc src mem!!\n", i);
			goto src_fail;
		}

		memcpy(req[i].src, tv->ptext, opt->pktlen);
		req[i].in_bytes = BUFF_SIZE;

		req[i].dst = wd_block_alloc(datas[i].bp);
		if (!req[i].dst) {
			SEC_TST_PRT("thread(%u) fail to alloc dst mem!!\n", i);
			goto dst_fail;
		}
		req[i].out_bytes = tv->len;
		req[i].out_buf_bytes = opt->blk_size[i];

		req[i].iv = wd_block_alloc(datas[i].bp);
		if (!req[i].iv) {
			SEC_TST_PRT("thread(%u) fail to alloc iv mem!!\n", i);
			goto iv_fail;
		}
		memcpy(req[i].iv, tv->iv, strlen(tv->iv));
		req[i].iv_bytes = strlen(tv->iv);

		/* config arg */
		setup[i].alg = WD_CIPHER_AES;
		setup[i].mode = WD_CIPHER_CBC;

		req[i].op_type = WD_CIPHER_ENCRYPTION;
		req[i].cb = async_cb;
		req[i].cb_param = &datas[i];
	}

	if (g_syncmode == 0)
		ret = sva_sync_create_threads(bp_thread_num, req, setup, datas);
	else
		ret = sva_async_create_threads(bp_thread_num, req, setup, datas);

	i--;
	do {
bp_fail:
		wd_block_free(datas[i].bp, req[i].iv);
iv_fail:
		wd_block_free(datas[i].bp, req[i].dst);
dst_fail:
		wd_block_free(datas[i].bp, req[i].src);
src_fail:
		free_bd_pool(&datas[i]);
init_bd_pool_fail:
		wd_pool_destory(datas[i].bp);
		i--;
	} while(i >= 0);

	wd_mempool_destory(mp);

mp_fail:
	sva_uninit_config();
init_ctx_fail:
	return -1;

}

static int test_sec_option_convert(struct test_option *option)
{
	unsigned long long sum_size = 0;
	int i;

	if (option->syncmode > 1) {
		show_help();
		return -EINVAL;
	}

	g_times = option->times ? option->times :
		(BUFF_SIZE * BUFF_SIZE);

	g_thread_num = option->xmulti ? option->xmulti : 1;
	g_syncmode = option->syncmode;
	g_ctxnum = option->ctxnum;

	for (i = 0;i < g_thread_num;i++)
		sum_size = option->blk_size[i] * option->blk_num[i];

	if (sum_size > option->mp_size) {
		printf("Mempool size is too small!\n");
		option->mp_size = sum_size;
	}

	return 0;
}
int main(int argc, char *argv[])
{
	struct test_option opt = {0};
	int ret;

	ret = parse_cmd_line(argc, argv, &opt);
	if (ret < 0)
		return -1;

	if (!opt.perf)
		return test_mempool(&opt);
	else if (opt.perf == 1)
		return test_blkpool(&opt);
	else
		return test_sec_perf(&opt);
}
