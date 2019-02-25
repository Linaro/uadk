#include "ut.c"

#include "../wd_sched.c"

static ut_cnt_def_range(100, 110, get_q);
int wd_request_queue(struct wd_queue *q) {
	static int tc_101_cnt = 0;

	if (testcase == 101 && tc_101_cnt++==5) {
		return -1;
	}

	ut_cnt_add_range(100, 110, get_q);
	return 0;
}

void wd_release_queue(struct wd_queue *q) {
	ut_cnt_sub_range(100, 110, get_q);
}

void *wd_reserve_memory(struct wd_queue *q, size_t size) {
	return NULL;
}

int wd_share_reserved_memory(struct wd_queue *q, struct wd_queue *target_q) {
	return 0;
}

int wd_send(struct wd_queue *q, void *req) {
	return 0;
}

int wd_recv_sync(struct wd_queue *q, void **resp, __u16 ms) {
	return 0;
}

int smm_init(void *pt_addr, size_t size, int align_mask) {
	return 0;
}

void *smm_alloc(void *pt_addr, size_t size) {
	return malloc(size);
}

static void _sched_init_cache(struct wd_scheduler *sched, int i)
{
}

static int _sched_input(struct wd_msg *msg, void *priv)
{
	return 0;
}

static int _sched_output(struct wd_msg *msg, void *priv)
{
	return 0;
}

#define Q_NUM 10
#define MSG_CACHE_NUM 8
#define MSG_DATA_SIZE 32

void case_init(void) {
#define Q_NUM 10
#define MSG_CACHE_NUM 8
#define MSG_DATA_SIZE 32
	int ret, i;
	struct wd_queue qs[Q_NUM];
	struct wd_scheduler sched = {
		.q_num = Q_NUM,
		.ss_region_size = 0,
		.msg_cache_num = MSG_CACHE_NUM,
		.msg_data_size = MSG_DATA_SIZE,
		.init_cache = _sched_init_cache,
		.input = _sched_input,
		.output = _sched_output,
		.qs = qs,
	};

	for (i=0; i<Q_NUM; i++) {
		qs[i].dev_flags = UACCE_DEV_PASID;
	}

	//test to pass
	ret = wd_sched_init(&sched);
	ut_assert(!ret);
	wd_sched_fini(&sched);
	ut_check_cnt_range(100, 110, get_q);

	//fail in the middle of get queue
	testcase = 101;
	ret = wd_sched_init(&sched);
	ut_assert(ret);
	ut_check_cnt_range(100, 110, get_q);
}

int main(void) {
	test(100, case_init);
	return 0;
}
