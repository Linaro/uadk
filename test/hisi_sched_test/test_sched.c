#include <stdio.h>
#include <stdlib.h>
#include <sched_sample.h>

#define SCHED_TEST_CTX_NUM 100
#define SCHED_TEST_TYPE_NUM 4

struct wd_ctx_config g_sched_test_cfg;

int sched_test_init()
{
	__u32 i;

	/* Simulate user ctx allocing behavior. */
	g_sched_test_cfg.ctx_num = SCHED_TEST_CTX_NUM;
	g_sched_test_cfg.priv = NULL;
	g_sched_test_cfg.ctxs = calloc(1, sizeof(struct wd_ctx) * SCHED_TEST_CTX_NUM);
	if (!g_sched_test_cfg.ctxs) {
		printf("sched_test ctx alloc failed\n");
		return SCHED_ERROR;
	}

	for (i = 0; i < SCHED_TEST_CTX_NUM; i++) {
		g_sched_test_cfg.ctxs[i].ctx = i;
	}

	return SCHED_SUCCESS;
}

static void sched_test_exit()
{
	free(g_sched_test_cfg.ctxs);
}

static int user_poll_func_stub_succee(handle_t h_ctx, __u32 expect, __u32 *count)
{
	*count = expect;
	return SCHED_SUCCESS;
}

static int user_poll_func_stub_fail(handle_t h_ctx, __u32 expect, __u32 *count)
{
	return SCHED_SUCCESS;
}

static void sched_test_case1(const char *name) {
	int ret;

	ret = sample_sched_init(SCHED_POLICY_BUTT, SCHED_TEST_TYPE_NUM, user_poll_func_stub_succee);
	if (ret != SCHED_PARA_INVALID) {
		printf("case: %s failure, error case SCHED_POLICY_BUTT\n", name);
		return;
	}

	ret = sample_sched_init(SCHED_POLICY_RR, SCHED_TEST_TYPE_NUM, NULL);
	if (ret != SCHED_PARA_INVALID) {
		printf("case: %s failure, error case NULL FUNC POINTER\n", name);
		return;
	}
	
	printf("case: %s success.\n", name);
}

void main()
{
	int ret;

	ret = sched_test_init();
	if (ret != SCHED_SUCCESS) {
		return;
	}

	sched_test_case1("Init para valid test");

	sched_test_exit();
}
