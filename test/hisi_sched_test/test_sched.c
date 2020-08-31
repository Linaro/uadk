// SPDX-License-Identifier: Apache-2.0
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
		g_sched_test_cfg.ctxs[i].ctx = i + 1;
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

static int sched_test_case1(const char *name)
{
	int ret;

	ret = sample_sched_init(SCHED_POLICY_BUTT, SCHED_TEST_TYPE_NUM, user_poll_func_stub_succee);
	if (ret != SCHED_PARA_INVALID) {
		printf("CASE 1: %s failure, sched_type check failed\n", name);
		return SCHED_ERROR;
	}

	ret = sample_sched_init(SCHED_POLICY_RR, SCHED_TEST_TYPE_NUM, NULL);
	if (ret != SCHED_PARA_INVALID) {
		printf("CASE 1: %s failure, func check failed\n", name);
		return SCHED_ERROR;
	}
	
	printf("CASE 1: %s success.\n", name);
	return SCHED_SUCCESS;
}

static int sched_test_case2(const char *name)
{
	int ret;

	ret = sample_sched_init(SCHED_POLICY_RR, SCHED_TEST_TYPE_NUM, user_poll_func_stub_succee);
	if (ret) {
		printf("CASE 2: %s failure, error case SCHED_POLICY_BUTT\n", name);
		return SCHED_ERROR;
	}

	ret = sample_sched_fill_region(MAX_NUMA_NUM, 0, 0, 0, 0);
	if (ret != SCHED_PARA_INVALID) {
		printf("CASE 2: %s failure, numa check failed\n", name);
		return SCHED_ERROR;
	}

	ret = sample_sched_fill_region(0, 2, 0, 0, 0);
	if (ret != SCHED_PARA_INVALID) {
		printf("CASE 2: %s failure, mode check failed\n", name);
		return SCHED_ERROR;
	}

	ret = sample_sched_fill_region(0, 0, SCHED_TEST_TYPE_NUM, 0, 0);
	if (ret != SCHED_PARA_INVALID) {
		printf("CASE 2: %s failure, type check failed\n", name);
		return SCHED_ERROR;
	}

	printf("CASE 2: %s success.\n", name);
	return SCHED_SUCCESS;
}

static int sched_test_case3(const char *name)
{
	int ret;
	int i;
	char req[] = "Request stub";
	handle_t ctx;
	struct sched_key key;

	ret = sample_sched_init(SCHED_POLICY_RR, SCHED_TEST_TYPE_NUM, user_poll_func_stub_succee);
	if (ret) {
		printf("CASE 3: %s failure, sample_sched_init\n", name);
		return SCHED_ERROR;
	}

	/* case: numa:0, mode:0, type:0, ctxs:0-99 */
	ret = sample_sched_fill_region(0, 0, 0, 0, 99);
	if (ret) {
		printf("CASE 3: %s failure, sample_sched_fill_region\n", name);
		return SCHED_ERROR;
	}

	/* Test the pick next value */
	key.numa_id = 0;
	key.mode = 0;
	key.type = 0;
	for (i = 0; i < SCHED_TEST_CTX_NUM; i++) {
		ctx = sample_sched_pick_next_ctx((const struct wd_ctx_config*)&g_sched_test_cfg, req, &key);
		if (!ctx) {
			printf("CASE 3: %s failure, sample_sched_pick_next_ctx\n", name);
			return SCHED_ERROR;
		}

		/* 0-99 pos to 1-100 ctx, reference the sched_test_init */
		if (ctx != i + 1) {
			printf("CASE 3: %s failure, ctx check failed\n", name);
			return SCHED_ERROR;
		}
	}

	/* Test times bigger than SCHED_TEST_CTX_NUM, the ctx must start from 1 */
	ctx = sample_sched_pick_next_ctx((const struct wd_ctx_config*)&g_sched_test_cfg, req, &key);
	if (ctx != 1) {
		printf("CASE 3: %s failure, ctx cycle check failed\n", name);
		return SCHED_ERROR;
	}

	printf("CASE 3: %s success.\n", name);
	return SCHED_SUCCESS;
}

int sched_test_case4(const char *name)
{
	int ret;
	__u32 count = 0;

	ret = sample_sched_init(SCHED_POLICY_RR, SCHED_TEST_TYPE_NUM, user_poll_func_stub_succee);
	if (ret) {
		printf("CASE 4: %s failure, sample_sched_init\n", name);
		return SCHED_ERROR;
	}

	/* case: numa:1, mode:1, type:1, ctxs:25-75 */
	ret = sample_sched_fill_region(1, 1, 1, 25, 75);
	if (ret) {
		printf("CASE 4: %s failure, sample_sched_fill_region\n", name);
		return SCHED_ERROR;
	}

	/* 100 is expect poll times */
	ret = sample_sched_poll_policy((const struct wd_ctx_config*)&g_sched_test_cfg, 100, &count);
	if (ret || count != 100) {
		printf("CASE 4: %s failure, sample_sched_poll_policy, count = %u\n", name, count);
		return SCHED_ERROR;
	}

	printf("CASE 4: %s success.\n", name);
	return SCHED_SUCCESS;
}

int sched_test_case5(const char *name)
{
	int ret;
	__u32 count = 0;

	ret = sample_sched_init(SCHED_POLICY_RR, SCHED_TEST_TYPE_NUM, user_poll_func_stub_fail);
	if (ret) {
		printf("CASE 5: %s failure, sample_sched_init\n", name);
		return SCHED_ERROR;
	}

	/* case: numa:2, mode:1, type:3, ctxs: 0-5 */
	ret = sample_sched_fill_region(2, 1, 3, 0, 5);
	if (ret) {
		printf("CASE 5: %s failure, sample_sched_fill_region\n", name);
		return SCHED_ERROR;
	}

	/* 100 is expect poll times */
	ret = sample_sched_poll_policy((const struct wd_ctx_config*)&g_sched_test_cfg, 1, &count);
	if (ret || count != 0) {
		printf("CASE 5: %s failure, sample_sched_poll_policy, count = %u\n", name, count);
		return SCHED_ERROR;
	}

	printf("CASE 5: %s success.\n", name);
	return SCHED_SUCCESS;
}


void main()
{
	int i;
	int ret;
	int fail = 0;
	int total = 0;
	struct test_case {
		const char *name;
		int (*func)(const char *name);
	}test_case[] = {
			{"Init boundary test",  sched_test_case1},
			{"Fill boundary test",  sched_test_case2},
			{"Picknext RR test ",   sched_test_case3},
			{"Poll RR test",        sched_test_case4},
			{"Poll RR safety test", sched_test_case5},
	};

	sched_test_init();

	for (i = 0; i < sizeof(test_case) / sizeof(struct test_case); i++) {
		total++;
		ret = test_case[i].func(test_case[i].name);
		if (ret)
			fail++;
	}

	sched_test_exit();

	printf("Total   Num: %d.\n", total);
	printf("SUCCESS Num: %d.\n", total - fail);
	printf("Failed  Num: %d.\n", fail);
}
