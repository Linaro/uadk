#include "ut.c"

#include "../wd_sched.c"

static ut_cnt_def_range(100, 110, get_q);
int wd_request_queue(struct wd_queue *q) {
	static int tc_101_cnt = 0;

	if (testcase == 101 && tc_101_cnt++==2) {
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

struct wd_queue *last_used_sq, *last_used_rq;
int wd_send(struct wd_queue *q, void *req) {
	last_used_sq = q;
	return 0;
}

int wd_recv_sync(struct wd_queue *q, void **resp, __u16 ms) {
	last_used_rq = q;
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

#define Q_NUM 3
#define MSG_CACHE_NUM 4
#define MSG_DATA_SIZE 32
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

void common_init(void) {
	int i;

	for (i=0; i<Q_NUM; i++) {
		qs[i].dev_flags = UACCE_DEV_PASID;
	}
}

void case_init(void) {
	int ret;

	common_init();

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

int get_qi(struct wd_queue *q) {
	int i;
	for (i=0; i<Q_NUM; i++) {
		if (&qs[i] == q)
			return i;
	}

	return -1;
}

void ut_check_and_reset_last_queue(int sqi, int rqi) {
	if (sqi >= 0)
		ut_assert_str(&qs[sqi] == last_used_sq, "sqi=%d expect %d\n",
				get_qi(last_used_sq), sqi);
	else
		ut_assert(last_used_sq == NULL);

	if (rqi >= 0)
		ut_assert_str(&qs[rqi] == last_used_rq, "rqi=%d, expect %d\n",
				get_qi(last_used_rq), rqi);
	else
		ut_assert(last_used_rq == NULL);

	last_used_rq = last_used_sq = NULL;
}

void case_sched(void) {
	int ret;

	common_init();
	ret = wd_sched_init(&sched);
	ut_assert(!ret);

	ut_check_and_reset_last_queue(-1, -1);
	ret = wd_sched_work(&sched, 1); //c0, q0
	ut_assert(ret == 3);
	ut_check_and_reset_last_queue(0, -1);

	ret = wd_sched_work(&sched, 1); //c1, q1
	ut_assert(ret == 2);
	ut_check_and_reset_last_queue(1, -1);

	ret = wd_sched_work(&sched, 1); //c2, q2
	ut_assert(ret == 1);
	ut_check_and_reset_last_queue(2, -1);

	ret = wd_sched_work(&sched, 1); //c3, q0
	ut_assert(ret == 0);
	ut_check_and_reset_last_queue(0, -1);

	//cache is out now
	ret = wd_sched_work(&sched, 1); //should recv
	ut_assert(ret == 1);
	ut_check_and_reset_last_queue(-1, 0);

	ret = wd_sched_work(&sched, 0); //recv one more
	ut_assert(ret == 2);
	ut_check_and_reset_last_queue(-1, 1);

	//send 2 more and recv 1
	ret = wd_sched_work(&sched, 1); //send
	ret = wd_sched_work(&sched, 1); //send
	ret = wd_sched_work(&sched, 1); //recv
	ut_assert(ret == 1);
}

int main(void) {
	test(100, case_init);
	test(120, case_sched);
	return 0;
}
