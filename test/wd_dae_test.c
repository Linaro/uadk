// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <limits.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <numa.h>
#include "include/wd_agg.h"
#include "include/wd_sched.h"

#define MAX_KEY_COLS_NUM	16
#define MAX_AGG_COLS_NUM	16
#define MAX_COLS_NUM		32
#define MAX_LINE_LENGTH		512
#define MAX_SIGNLE_DATA_LENGTH	512
#define MAX_COLS		64
#define S_TO_US_TIME		1000000
#define HASH_TABLE_ROW_NUM	65536
#define DEFAULT_ROW_NUM		30000
#define THREADS_NUM		64

struct agg_perf_info {
	__u32 std_row_num;
	__u32 ext_row_num;
	__u32 req_row_num;
	int case_id;
};

struct agg_case_info {
	__u32 key_cols_num;
	__u32 agg_cols_num;
	__u32 out_agg_cols_num;
	__u32 alg_num[MAX_KEY_COLS_NUM];
	__u16 key_data_info[MAX_KEY_COLS_NUM];
	__u16 agg_data_info[MAX_AGG_COLS_NUM];
	bool is_count_all;
	enum wd_dae_data_type count_all_type;
	enum wd_dae_data_type key_type[MAX_KEY_COLS_NUM];
	enum wd_dae_data_type agg_input_type[MAX_AGG_COLS_NUM];
	enum wd_dae_data_type agg_output_type[MAX_AGG_COLS_NUM][WD_AGG_ALG_TYPE_MAX];
	enum wd_agg_alg agg_alg[MAX_AGG_COLS_NUM][WD_AGG_ALG_TYPE_MAX];
	__u16 row_size;
};

struct agg_usr_data {
	__u32 std_num;
	__u32 ext_num;
	__u32 all_num;
	__u32 req_input_num;
	__u32 key_row_num;
	__u32 req_output_num;
	__u32 case_index;
	__u32 perf_test;
	__u32 thread_num;
	__u32 rehash_rate;
	__u32 rehash_output_num;
	char case_name[64];
};

struct agg_case_data {
	char case_name[10][64];
	__u32 case_num;
	__u32 case_index;
};

struct dae_thread_res {
	struct timeval begin_time;
	struct timeval end_time;
	int td_id;
};

struct dae_pool {
	struct wd_dae_col_addr *agg_cols;
	struct wd_dae_col_addr *out_agg_cols;
	struct wd_dae_col_addr *key_cols;
	struct wd_dae_col_addr *out_key_cols;
	__u32 row_num;
};

static struct agg_case_data agg_case[] = {
	{{"sql1-case1", "sql1-case3", "sql65-case1", "sql65-case2", "sql65-case4"}, 5, 0},
	{{"sql1-case2"}, 1, 1},
	{{"sql1-case4", "sql65-case3"}, 2, 2},
	{{"sql22-case1"}, 1, 3},
	{{"sql23a-case1"}, 1, 4},
	{{"sql23a-case2", "sql23a-case3"}, 2, 5},
	{{"sql23a-case4", "sql23a-case6"}, 2, 6},
	{{"sql23a-case5"}, 1, 7},
	{{"sql47-case1", "sql47-case2"}, 2, 8},
	{{"sql51-case1", "sql51-case2", "sql51-case3", "sql51-case4"}, 4, 9},
	{{"sql64-case1"}, 1, 10},
	{{"sql64-case3"}, 1, 11},
	{{"sql67-case1"}, 1, 12},
	{{"sql67-case2"}, 1, 13},
	{{"sql78-case1", "sql78-case2"}, 2, 14},
	{{"q1"}, 1, 15},
	{{"q15", "q18"}, 2, 16},
	{{"minmax_case1", "minmax_case2"}, 2, 17},
	{{"minmax_case3"}, 1, 18},
	{{"minmax_case4"}, 1, 19},
};

static struct agg_case_info agg_perf_data[] = {
	{
		.key_cols_num = 2,
		.agg_cols_num = 1,
		.out_agg_cols_num = 1,
		.alg_num = {1},
		.key_data_info = {0, 0},
		.agg_data_info = {0},
		.key_type = {WD_DAE_LONG, WD_DAE_LONG},
		.agg_input_type = {WD_DAE_LONG},
		.agg_output_type = {{WD_DAE_LONG}},
		.agg_alg = {{WD_AGG_SUM}},
		.row_size = 27,
	}, {
		.key_cols_num = 1,
		.agg_cols_num = 1,
		.out_agg_cols_num = 2,
		.alg_num = {2},
		.key_data_info = {0},
		.agg_data_info = {529},
		.key_type = {WD_DAE_LONG},
		.agg_input_type = {WD_DAE_SHORT_DECIMAL},
		.agg_output_type = {{WD_DAE_LONG_DECIMAL, WD_DAE_LONG}},
		.agg_alg = {{WD_AGG_SUM, WD_AGG_COUNT}},
		.row_size = 26,
	}, {
		.key_cols_num = 1,
		.agg_cols_num = 1,
		.out_agg_cols_num = 2,
		.alg_num = {2},
		.key_data_info = {0},
		.agg_data_info = {529},
		.key_type = {WD_DAE_LONG},
		.agg_input_type = {WD_DAE_LONG_DECIMAL},
		.agg_output_type = {{WD_DAE_LONG_DECIMAL, WD_DAE_LONG}},
		.agg_alg = {{WD_AGG_SUM, WD_AGG_COUNT}},
		.row_size = 35,
	}, {
		.key_cols_num = 5,
		.agg_cols_num = 1,
		.out_agg_cols_num = 2,
		.alg_num = {2},
		.key_data_info = {0, 0, 0, 0, 0},
		.agg_data_info = {0},
		.key_type = {WD_DAE_VARCHAR, WD_DAE_VARCHAR, WD_DAE_VARCHAR,
			     WD_DAE_VARCHAR, WD_DAE_LONG},
		.agg_input_type = {WD_DAE_LONG},
		.agg_output_type = {{WD_DAE_LONG, WD_DAE_LONG}},
		.agg_alg = {{WD_AGG_SUM, WD_AGG_COUNT}},
		.row_size = 124,
	}, {
		.key_cols_num = 3,
		.agg_cols_num = 0,
		.out_agg_cols_num = 1,
		.alg_num = {0},
		.key_data_info = {0, 0, 0},
		.is_count_all = true,
		.count_all_type = WD_DAE_LONG,
		.key_type = {WD_DAE_VARCHAR, WD_DAE_LONG, WD_DAE_INT},
		.row_size = 51,
	}, {
		.key_cols_num = 1,
		.agg_cols_num = 1,
		.out_agg_cols_num = 1,
		.alg_num = {1},
		.key_data_info = {0},
		.agg_data_info = {529},
		.key_type = {WD_DAE_LONG},
		.agg_input_type = {WD_DAE_SHORT_DECIMAL},
		.agg_output_type = {{WD_DAE_LONG_DECIMAL}},
		.agg_alg = {{WD_AGG_SUM}},
		.row_size = 26,
	}, {
		.key_cols_num = 1,
		.agg_cols_num = 1,
		.out_agg_cols_num = 1,
		.alg_num = {1},
		.key_data_info = {0},
		.agg_data_info = {529},
		.key_type = {WD_DAE_LONG},
		.agg_input_type = {WD_DAE_LONG_DECIMAL},
		.agg_output_type = {{WD_DAE_LONG_DECIMAL}},
		.agg_alg = {{WD_AGG_SUM}},
		.row_size = 28,
	}, {
		.key_cols_num = 3,
		.agg_cols_num = 1,
		.out_agg_cols_num = 1,
		.alg_num = {1},
		.key_data_info = {0, 0, 0},
		.agg_data_info = {0},
		.key_type = {WD_DAE_VARCHAR, WD_DAE_LONG, WD_DAE_DATE},
		.agg_input_type = {WD_DAE_LONG},
		.agg_output_type = {{WD_DAE_LONG}},
		.agg_alg = {{WD_AGG_COUNT}},
		.row_size = 60,
	}, {
		.key_cols_num = 6,
		.agg_cols_num = 1,
		.out_agg_cols_num = 1,
		.alg_num = {1},
		.key_data_info = {0, 0, 0, 0, 0, 0},
		.agg_data_info = {0},
		.key_type = {WD_DAE_VARCHAR, WD_DAE_VARCHAR, WD_DAE_VARCHAR,
			     WD_DAE_VARCHAR, WD_DAE_INT, WD_DAE_INT},
		.agg_input_type = {WD_DAE_LONG},
		.agg_output_type = {{WD_DAE_LONG}},
		.agg_alg = {{WD_AGG_SUM}},
		.row_size = 92,
	}, {
		.key_cols_num = 2,
		.agg_cols_num = 1,
		.out_agg_cols_num = 1,
		.alg_num = {1},
		.key_data_info = {0, 0},
		.agg_data_info = {0},
		.key_type = {WD_DAE_LONG, WD_DAE_DATE},
		.agg_input_type = {WD_DAE_LONG},
		.agg_output_type = {{WD_DAE_LONG}},
		.agg_alg = {{WD_AGG_SUM}},
		.row_size = 23,
	}, {
		.key_cols_num = 1,
		.agg_cols_num = 2,
		.out_agg_cols_num = 2,
		.alg_num = {1, 1},
		.key_data_info = {0},
		.agg_data_info = {0, 529},
		.key_type = {WD_DAE_LONG},
		.agg_input_type = {WD_DAE_LONG, WD_DAE_SHORT_DECIMAL},
		.agg_output_type = {{WD_DAE_LONG}, {WD_DAE_LONG_DECIMAL}},
		.agg_alg = {{WD_AGG_SUM}, {WD_AGG_SUM}},
		.row_size = 35,
	}, {
		.key_cols_num = 1,
		.agg_cols_num = 2,
		.out_agg_cols_num = 2,
		.alg_num = {1, 1},
		.key_data_info = {0},
		.agg_data_info = {0, 529},
		.key_type = {WD_DAE_LONG},
		.agg_input_type = {WD_DAE_LONG, WD_DAE_LONG_DECIMAL},
		.agg_output_type = {{WD_DAE_LONG}, {WD_DAE_LONG_DECIMAL}},
		.agg_alg = {{WD_AGG_SUM}, {WD_AGG_SUM}},
		.row_size = 37,
	}, {
		.key_cols_num = 9,
		.agg_cols_num = 1,
		.out_agg_cols_num = 1,
		.alg_num = {1},
		.key_data_info = {0, 0, 0, 0, 0, 0, 0, 0, 0},
		.agg_data_info = {529},
		.key_type = {WD_DAE_VARCHAR, WD_DAE_VARCHAR, WD_DAE_VARCHAR, WD_DAE_VARCHAR,
			    WD_DAE_INT, WD_DAE_INT, WD_DAE_INT, WD_DAE_VARCHAR, WD_DAE_LONG},
		.agg_input_type = {WD_DAE_SHORT_DECIMAL},
		.agg_output_type = {{WD_DAE_LONG_DECIMAL}},
		.agg_alg = {{WD_AGG_SUM}},
		.row_size = 162,
	}, {
		.key_cols_num = 9,
		.agg_cols_num = 1,
		.out_agg_cols_num = 1,
		.alg_num = {1},
		.key_data_info = {0, 0, 0, 0, 0, 0, 0, 0, 0},
		.agg_data_info = {529},
		.key_type = {WD_DAE_VARCHAR, WD_DAE_VARCHAR,
			     WD_DAE_VARCHAR, WD_DAE_VARCHAR,
			     WD_DAE_INT, WD_DAE_INT, WD_DAE_INT,
			     WD_DAE_VARCHAR, WD_DAE_LONG},
		.agg_input_type = {WD_DAE_LONG_DECIMAL},
		.agg_output_type = {{WD_DAE_LONG_DECIMAL}},
		.agg_alg = {{WD_AGG_SUM}},
		.row_size = 172,
	}, {
		.key_cols_num = 3,
		.agg_cols_num = 3,
		.out_agg_cols_num = 3,
		.alg_num = {1, 1, 1},
		.key_data_info = {0, 0, 0},
		.agg_data_info = {0, 0, 0},
		.key_type = {WD_DAE_INT, WD_DAE_LONG, WD_DAE_LONG},
		.agg_input_type = {WD_DAE_LONG, WD_DAE_LONG, WD_DAE_LONG},
		.agg_output_type = {{WD_DAE_LONG}, {WD_DAE_LONG}, {WD_DAE_LONG}},
		.agg_alg = {{WD_AGG_SUM}, {WD_AGG_SUM}, {WD_AGG_SUM}},
		.row_size = 50,
	}, {
		.key_cols_num = 2,
		.agg_cols_num = 5,
		.out_agg_cols_num = 9,
		.alg_num = {2, 2, 2, 1, 1},
		.key_data_info = {1, 1},
		.agg_data_info = {527, 527, 527, 527, 527},
		.is_count_all = true,
		.count_all_type = WD_DAE_LONG,
		.key_type = {WD_DAE_CHAR, WD_DAE_CHAR},
		.agg_input_type = {WD_DAE_LONG_DECIMAL, WD_DAE_LONG_DECIMAL, WD_DAE_LONG_DECIMAL,
				  WD_DAE_LONG_DECIMAL, WD_DAE_LONG_DECIMAL},
		.agg_output_type = {{WD_DAE_LONG_DECIMAL, WD_DAE_LONG},
				    {WD_DAE_LONG_DECIMAL, WD_DAE_LONG},
				    {WD_DAE_LONG_DECIMAL, WD_DAE_LONG},
				    {WD_DAE_LONG_DECIMAL},
				    {WD_DAE_LONG_DECIMAL}},
		.agg_alg = {{WD_AGG_SUM, WD_AGG_COUNT}, {WD_AGG_SUM, WD_AGG_COUNT},
			    {WD_AGG_SUM, WD_AGG_COUNT}, {WD_AGG_SUM}, {WD_AGG_SUM}},
		.row_size = 89,
	}, {
		.key_cols_num = 1,
		.agg_cols_num = 1,
		.out_agg_cols_num = 1,
		.alg_num = {1},
		.key_data_info = {527},
		.agg_data_info = {527},
		.key_type = {WD_DAE_LONG_DECIMAL},
		.agg_input_type = {WD_DAE_LONG_DECIMAL},
		.agg_output_type = {{WD_DAE_LONG_DECIMAL}},
		.agg_alg = {{WD_AGG_SUM}},
		.row_size = 34,
	}, {
		.key_cols_num = 6,
		.agg_cols_num = 6,
		.out_agg_cols_num = 6,
		.alg_num = {1, 1, 1, 1, 1, 1},
		.key_data_info = {0, 0, 0, 0, 0, 0},
		.agg_data_info = {0, 0, 0, 0, 0, 0},
		.key_type = {WD_DAE_VARCHAR, WD_DAE_VARCHAR, WD_DAE_VARCHAR,
			     WD_DAE_INT, WD_DAE_INT, WD_DAE_INT},
		.agg_input_type = {WD_DAE_LONG, WD_DAE_LONG, WD_DAE_LONG,
				   WD_DAE_LONG, WD_DAE_LONG, WD_DAE_LONG},
		.agg_output_type = {{WD_DAE_LONG}, {WD_DAE_LONG}, {WD_DAE_LONG},
				    {WD_DAE_LONG}, {WD_DAE_LONG}, {WD_DAE_LONG}},
		.agg_alg = {{WD_AGG_MIN}, {WD_AGG_MAX}, {WD_AGG_MIN},
			    {WD_AGG_MAX}, {WD_AGG_MIN}, {WD_AGG_MAX}},
	}, {
		.key_cols_num = 3,
		.agg_cols_num = 3,
		.out_agg_cols_num = 3,
		.alg_num = {1, 1, 1},
		.key_data_info = {0, 0, 0},
		.agg_data_info = {0, 0, 0},
		.key_type = {WD_DAE_INT, WD_DAE_LONG, WD_DAE_LONG},
		.agg_input_type = {WD_DAE_LONG, WD_DAE_LONG, WD_DAE_LONG},
		.agg_output_type = {{WD_DAE_LONG}, {WD_DAE_LONG}, {WD_DAE_LONG}},
		.agg_alg = {{WD_AGG_MIN}, {WD_AGG_MIN}, {WD_AGG_MIN}},
	}, {
		.key_cols_num = 3,
		.agg_cols_num = 3,
		.out_agg_cols_num = 3,
		.alg_num = {1, 1, 1},
		.key_data_info = {0, 0, 0},
		.agg_data_info = {0, 0, 0},
		.key_type = {WD_DAE_INT, WD_DAE_LONG, WD_DAE_LONG},
		.agg_input_type = {WD_DAE_LONG, WD_DAE_LONG, WD_DAE_LONG},
		.agg_output_type = {{WD_DAE_LONG}, {WD_DAE_LONG}, {WD_DAE_LONG}},
		.agg_alg = {{WD_AGG_MAX}, {WD_AGG_MAX}, {WD_AGG_MAX}},
	}
};

static __u32 g_req_num;
static __u32 g_actual_req_num;
static struct agg_usr_data g_usr_data;
struct dae_pool **g_pool;
static __u64 g_total_row;

static int getvarchar(char *fields[], char *ptr, int *idx)
{
	char *start = strstr(fields[*idx], "'''");
	int len, count = 0;
	int i = *idx;
	char *end;

	start = strstr(fields[i++], "'''");
	start += 3;
	while (true) {
		end = strstr(start, "'''");
		if (end)
			break;
		len = strlen(start);
		memcpy(ptr, start, len);
		ptr += len;
		*ptr = ',';
		ptr++;
		count += len + 1;
		start = fields[i++];
	}

	len = strlen(start) - 3;
	count += len;
	memcpy(ptr, start, len);
	*idx = i;
	return count;
}

static void splitLine(char *line, char *fields[], char *delimiter)
{
	char *token = strtok(line, delimiter);
	int col = 0;

	while (token != NULL) {
		fields[col++] = token;
		token = strtok(NULL, delimiter);
	}
}

static void agg_get_value_data(struct wd_dae_col_addr *col_addr, char *fields[],
				enum wd_dae_data_type type, __u32 row_idx,
				__u16 data_info, int *idx)
{
	int *int_value, *offset;
	long *long_value;
	int vchar_len;
	int i = *idx;
	__u8 *empty;
	char *ptr;

	empty = (__u8 *)col_addr->empty;
	empty[row_idx] = atoi(fields[i++]);
	col_addr->empty_size += 1;

	switch (type) {
	case WD_DAE_DATE:
	case WD_DAE_INT:
		int_value = (int *)col_addr->value;
		int_value[row_idx] = atoi(fields[i++]);
		col_addr->value_size += 4;
		break;
	case WD_DAE_LONG:
	case WD_DAE_SHORT_DECIMAL:
		long_value = (long *)col_addr->value;
		long_value[row_idx] = atol(fields[i++]);
		col_addr->value_size += 8;
		break;
	case WD_DAE_LONG_DECIMAL:
		long_value = (long *)((char *)col_addr->value + col_addr->value_size);
		*long_value = strtol(fields[i++], NULL, 16);
		col_addr->value_size += 16;
		break;
	case WD_DAE_CHAR:
		ptr = (char *)col_addr->value;
		memcpy(ptr + col_addr->value_size, fields[i++], data_info);
		col_addr->value_size += data_info;
		break;
	case WD_DAE_VARCHAR:
		ptr = (char *)col_addr->value + col_addr->value_size;
		offset = (int *)col_addr->offset;
		vchar_len = getvarchar(fields, ptr, &i);
		offset[row_idx + 1] = offset[row_idx] + vchar_len;
		col_addr->value_size += vchar_len;
		col_addr->offset_size += 4;
		i++;
		break;
	default:
		break;
	}

	*idx = i;
}

static int agg_read_data(FILE *file, struct dae_pool *pool)
{
	struct agg_case_info *perf_data = &agg_perf_data[g_usr_data.case_index];
	char tmp_line[MAX_LINE_LENGTH];
	char line[MAX_LINE_LENGTH];
	char *fields[MAX_COLS];
	char *step_fields[2];
	bool has_vchar = false;
	__u32 i, row_idx = 0;
	__u64 count_row = 0;
	int j, k = 0;
	int count = 0;
	size_t len;
	fpos_t pos;

	fgetpos(file, &pos);
	k = 1;
	while (fgets(line, sizeof(line), file)) {
		memcpy(tmp_line, line, MAX_LINE_LENGTH);
		len = strlen(tmp_line);
		splitLine(tmp_line, step_fields, "=");
		if (len != strlen(step_fields[0])) {
			count = atoi(step_fields[1]);
			has_vchar = true;
			continue;
		}
		if (!count && has_vchar)
			continue;

		splitLine(line, fields, ",");
		j = 0;
		for (i = 0; i < perf_data->key_cols_num; i++) {
			agg_get_value_data(&pool->key_cols[i], fields, perf_data->key_type[i],
					   row_idx, perf_data->key_data_info[i], &j);
		}

		for (i = 0; i < perf_data->agg_cols_num; i++) {
			agg_get_value_data(&pool->agg_cols[i], fields, perf_data->agg_input_type[i],
					   row_idx, perf_data->agg_data_info[i], &j);
		}
		row_idx++;
		count_row++;
		count--;
		if (count_row >= g_usr_data.all_num)
			break;
		if (row_idx >= g_usr_data.req_input_num) {
			pool->row_num = row_idx;
			row_idx = 0;
			if (k >= g_req_num)
				goto out;
			pool++;
			k++;
		}
	}
	if (row_idx)
		pool->row_num = row_idx;
	else
		k--;
out:
	g_total_row = count_row;

	return k;
}

static int agg_prepare_data(struct dae_pool *pool)
{
	char path[64] = "/tmp/";
	FILE *file;
	int len;

	len = strlen(path);
	strcpy(path + len, g_usr_data.case_name);
	len = strlen(path);
	strcpy(path + len, ".txt");
	file = fopen(path, "r");
	if (!file) {
		printf("Error opening file path %s!\n", path);
		return -1;
	}

	g_actual_req_num = agg_read_data(file, pool);

	fclose(file);
	printf("test input data %llu row num, req num = %u!\n", g_total_row, g_actual_req_num);

	return 0;
}

static int agg_get_data_from_file(void)
{
	int i, ret;

	for (i = 0; i < g_usr_data.thread_num; i++) {
		ret = agg_prepare_data(g_pool[i]);
		if (ret)
			return ret;
	}

	return 0;
}

static int agg_alloc_table_addr(struct wd_dae_hash_table *table, struct wd_dae_hash_table *new_table, __u32 row_size)
{
	if (table) {
		new_table->std_table_row_num = g_usr_data.rehash_rate * table->std_table_row_num;
		new_table->ext_table_row_num = g_usr_data.rehash_rate * table->ext_table_row_num;
	} else {
		new_table->std_table_row_num = g_usr_data.std_num;
		new_table->ext_table_row_num = g_usr_data.ext_num;
	}

	new_table->table_row_size = row_size;
	new_table->std_table = malloc(row_size * new_table->std_table_row_num);
	if (!new_table->std_table)
		return -WD_ENOMEM;

	new_table->ext_table = malloc(row_size * new_table->ext_table_row_num);
	if (!new_table->ext_table) {
		free(new_table->std_table);
		return -WD_ENOMEM;
	}

	return 0;
}

static void agg_free_table_addr(struct wd_dae_hash_table *table)
{
	free(table->std_table);
	free(table->ext_table);
}

static void agg_free_sess(handle_t h_sess, struct wd_dae_hash_table *table)
{
	agg_free_table_addr(table);
	wd_agg_free_sess(h_sess);
}

static handle_t agg_alloc_sess(struct wd_dae_hash_table *table)
{
	struct agg_case_info *data_info = &agg_perf_data[g_usr_data.case_index];
	struct wd_key_col_info key_cols_info[MAX_KEY_COLS_NUM];
	struct wd_agg_col_info agg_cols_info[MAX_KEY_COLS_NUM];
	struct wd_agg_sess_setup setup;
	__u32 i, j, row_size;
	handle_t sess;
	int ret;

	setup.key_cols_num = data_info->key_cols_num;
	setup.key_cols_info = key_cols_info;
	for (i = 0; i < data_info->key_cols_num; i++) {
		key_cols_info[i].input_data_type = data_info->key_type[i];
		key_cols_info[i].col_data_info = data_info->key_data_info[i];
	}

	setup.agg_cols_num = data_info->agg_cols_num;
	setup.agg_cols_info = agg_cols_info;
	for (i = 0; i < data_info->agg_cols_num; i++) {
		agg_cols_info[i].col_alg_num = data_info->alg_num[i];
		agg_cols_info[i].col_data_info = data_info->agg_data_info[i];
		agg_cols_info[i].input_data_type = data_info->agg_input_type[i];
		for (j = 0; j < agg_cols_info[i].col_alg_num; j++) {
			agg_cols_info[i].output_data_types[j] = data_info->agg_output_type[i][j];
			agg_cols_info[i].output_col_algs[j] = data_info->agg_alg[i][j];
		}
	}

	setup.is_count_all = data_info->is_count_all;
	setup.count_all_data_type = data_info->count_all_type;
	setup.sched_param = 0;

	sess = wd_agg_alloc_sess(&setup);
	if (!sess) {
		printf("failed to alloc sess!\n");
		return (handle_t)0;
	}

	row_size = wd_agg_get_table_rowsize(sess);
	if (!row_size) {
		printf("failed to get row size!\n");
		goto free_sess;
	}
	ret = agg_alloc_table_addr(NULL, table, row_size);
	if (unlikely(ret)) {
		printf("failed to alloc table memory!\n");
		goto free_sess;
	}

	return sess;

free_sess:
	wd_agg_free_sess(sess);
	return (handle_t)0;
}

static void agg_free_col_addr(struct wd_dae_col_addr *cols, int num)
{
	int i;

	if (!cols)
		return;

	for (i = 0; i < num; i++) {
		if (cols[i].offset)
			free(cols[i].offset);
		free(cols[i].empty);
		free(cols[i].value);
	}

	free(cols);
}

static int agg_alloc_value_addr(struct wd_dae_col_addr *col, __u32 row_num,
				enum wd_dae_data_type type, __u16 data_info, int index)
{
	col[index].empty = aligned_alloc(128, row_num);
	if (unlikely(!col[index].empty))
		return -WD_ENOMEM;
	col[index].empty_size = row_num;

	switch (type) {
	case WD_DAE_DATE:
	case WD_DAE_INT:
		col[index].value_size = row_num << 2;
		break;
	case WD_DAE_LONG:
	case WD_DAE_SHORT_DECIMAL:
		col[index].value_size = row_num << 3;
		break;
	case WD_DAE_LONG_DECIMAL:
		col[index].value_size = row_num << 4;
		break;
	case WD_DAE_CHAR:
		col[index].value_size = data_info * row_num;
		break;
	case WD_DAE_VARCHAR:
		col[index].offset_size = (row_num + 1) << 2;
		col[index].offset = aligned_alloc(128, col[index].offset_size);
		if (unlikely(!col[index].offset))
			goto free_empty;
		col[index].value_size = row_num << 5;
		break;
	default:
		return -WD_EINVAL;
	}

	col[index].value = aligned_alloc(128, col[index].value_size);
	if (unlikely(!col[index].value))
		goto free_offset;

	return 0;

free_offset:
	if (col[index].offset) {
		free(col[index].offset);
		col[index].offset = NULL;
	}
free_empty:
	free(col[index].empty);
	col[index].empty = NULL;

	return -WD_ENOMEM;
}

static int agg_alloc_key_out_addr(struct agg_case_info *perf_data,
				  struct dae_pool *pool, __u32 row_num)
{
	struct wd_dae_col_addr *out_key_cols;
	int i, ret;

	out_key_cols = calloc(perf_data->key_cols_num, sizeof(struct wd_dae_col_addr));
	if (unlikely(!out_key_cols))
		return -WD_ENOMEM;

	for (i = 0; i < perf_data->key_cols_num; i++) {
		ret = agg_alloc_value_addr(out_key_cols, row_num, perf_data->key_type[i],
					 perf_data->key_data_info[i], i);
		if (unlikely(ret))
			goto free_key_cols;
	}

	pool->out_key_cols = out_key_cols;

	return 0;

free_key_cols:
	agg_free_col_addr(out_key_cols, i);
	return -WD_ENOMEM;
}

static int agg_alloc_agg_out_addr(struct agg_case_info *perf_data,
				  struct dae_pool *pool, __u32 output_num)
{
	struct wd_dae_col_addr *out_agg_cols;
	int ret, j, k, i = 0;

	out_agg_cols = calloc(perf_data->out_agg_cols_num, sizeof(struct wd_dae_col_addr));
	if (unlikely(!out_agg_cols))
		return -WD_ENOMEM;

	for (k = 0; k < perf_data->agg_cols_num; k++) {
		for (j = 0; j < perf_data->alg_num[k]; j++) {
			ret = agg_alloc_value_addr(out_agg_cols, output_num,
			perf_data->agg_output_type[k][j], perf_data->agg_data_info[k], i);
			if (unlikely(ret))
				goto free_agg_cols;
			i++;
		}
	}

	if (perf_data->is_count_all) {
		ret = agg_alloc_value_addr(out_agg_cols, output_num,
					WD_DAE_LONG, 0, i);
		if (unlikely(ret))
			goto free_agg_cols;
	}

	pool->out_agg_cols = out_agg_cols;

	return 0;
free_agg_cols:
	agg_free_col_addr(out_agg_cols, i);
	return -WD_ENOMEM;
}

static int agg_prepare_req(struct dae_pool *rehash_pool, struct wd_agg_req *rehash_req,
			   struct wd_agg_req *req)
{
	struct agg_case_info *perf_data = &agg_perf_data[g_usr_data.case_index];
	int ret;

	ret = agg_alloc_key_out_addr(perf_data, rehash_pool, g_usr_data.rehash_output_num);
	if (ret)
		return ret;

	ret = agg_alloc_agg_out_addr(perf_data, rehash_pool, g_usr_data.rehash_output_num);
	if (ret)
		goto free_out_key;

	rehash_req->out_agg_cols = rehash_pool->out_agg_cols;
	rehash_req->out_key_cols = rehash_pool->out_key_cols;
	rehash_req->out_row_count = g_usr_data.rehash_output_num;
	rehash_req->out_key_cols_num = perf_data->key_cols_num;
	rehash_req->out_agg_cols_num = perf_data->out_agg_cols_num;

	req->out_key_cols_num = perf_data->key_cols_num;
	req->out_agg_cols_num = perf_data->out_agg_cols_num;
	req->key_cols_num = perf_data->key_cols_num;
	req->agg_cols_num = perf_data->agg_cols_num;

	return 0;

free_out_key:
	agg_free_col_addr(rehash_pool->out_key_cols, 1);
	return ret;
}

static int agg_do_rehash(handle_t h_sess, struct wd_dae_hash_table *table,
			 struct wd_agg_req *rehash_req)
{
	struct wd_dae_hash_table new_table = {0};
	int ret;

	ret = agg_alloc_table_addr(table, &new_table, table->table_row_size);
	if (ret)
		return ret;

	ret = wd_agg_set_hash_table(h_sess, &new_table);
	if (ret) {
		printf("failed to set hash table!\n");
		goto free_table;
	}

	ret = wd_agg_rehash_sync(h_sess, rehash_req);
	if (ret) {
		printf("failed to do rehash!\n");
		goto free_table;
	}

	table->std_table_row_num = new_table.std_table_row_num;
	table->ext_table_row_num = new_table.std_table_row_num;
	agg_free_table_addr(table);
	table->std_table = new_table.std_table;
	table->ext_table = new_table.ext_table;

	return 0;

free_table:
	agg_free_table_addr(&new_table);
	return ret;
}

static void *agg_do_task_perf_test(void *arg)
{
	struct agg_case_info *perf_data = &agg_perf_data[g_usr_data.case_index];
	struct dae_thread_res *pdata = (struct dae_thread_res *)arg;
	struct dae_pool *pool = g_pool[pdata->td_id];
	struct wd_dae_col_addr out_key_cols[9];
	struct wd_dae_col_addr out_agg_cols[9];
	struct wd_dae_hash_table table = {0};
	struct wd_agg_req rehash_req = {0};
	struct wd_agg_req req = {0};
	struct dae_pool rehash_pool;
	struct timeval begin_time;
	struct timeval end_time;
	__u32 rehash_count = 0;
	__u64 total_row = 0;
	double time_used;
	handle_t h_sess;
	int ret, i = 0;

	ret = agg_prepare_req(&rehash_pool, &rehash_req, &req);
	if (ret)
		return NULL;

	memcpy(&out_agg_cols, rehash_pool.out_agg_cols,
		sizeof(struct wd_dae_col_addr) * perf_data->out_agg_cols_num);
	memcpy(&out_key_cols, rehash_pool.out_key_cols,
		sizeof(struct wd_dae_col_addr) * perf_data->key_cols_num);

	h_sess = agg_alloc_sess(&table);
	if (!h_sess)
		goto free_out_agg;
	gettimeofday(&begin_time, NULL);
	ret = wd_agg_set_hash_table(h_sess, &table);
	if (ret) {
		WD_ERR("failed to set hash table!\n");
		goto free_sess;
	}

	while (i < g_actual_req_num) {
		req.agg_cols = pool[i].agg_cols;
		req.key_cols = pool[i].key_cols;
		req.in_row_count = pool[i].row_num;
		req.real_in_row_count = 0;
		ret = wd_agg_add_input_sync(h_sess, &req);
		if (unlikely(ret)) {
			printf("failed to do agg input, ret = %d!\n", ret);
			goto free_sess;
		}

		if (req.state == WD_AGG_NEED_REHASH) {
			ret = agg_do_rehash(h_sess, &table, &rehash_req);
			if (unlikely(ret))
				goto free_sess;

			rehash_count++;
			memcpy(rehash_req.out_agg_cols, &out_agg_cols,
				sizeof(struct wd_dae_col_addr) * perf_data->out_agg_cols_num);
			memcpy(rehash_req.out_key_cols, &out_key_cols,
				sizeof(struct wd_dae_col_addr) * perf_data->key_cols_num);
			req.state = 0;
			continue;
		}
		if (unlikely(req.state)) {
			printf("failed to do agg input req->state = %d!\n", req.state);
			goto free_sess;
		}

		i++;
	}

	i = 0;
	req.out_row_count = g_usr_data.req_output_num;
	do {
		ret = agg_alloc_key_out_addr(perf_data, &pool[i], g_usr_data.req_output_num);
		if (unlikely(ret))
			break;
		ret = agg_alloc_agg_out_addr(perf_data, &pool[i], g_usr_data.req_output_num);
		if (unlikely(ret))
			break;
		req.out_agg_cols = pool[i].out_agg_cols;
		req.out_key_cols = pool[i].out_key_cols;
		ret = wd_agg_get_output_sync(h_sess, &req);
		if (unlikely(ret)) {
			printf("failed to do agg output!\n");
			goto free_sess;
		}

		if (req.state && req.state != 3) {
			printf("failed to do agg output req->state = %d!\n", req.state);
			goto free_sess;
		}
		total_row += req.real_out_row_count;
		if (req.output_done)
			break;
		i++;
	} while (true);
	gettimeofday(&end_time, NULL);
	time_used = (double)((end_time.tv_sec - begin_time.tv_sec) * S_TO_US_TIME +
			end_time.tv_usec - begin_time.tv_usec);
	WD_ERR("case %s thread %d start %lu s %lu us, end %lu s %lu us, used time %0.0lf us!\n",
		g_usr_data.case_name, pdata->td_id, begin_time.tv_sec, begin_time.tv_usec,
		end_time.tv_sec, end_time.tv_usec, time_used);

	printf("case %s thread %d output data %llu row num, rehash %u times!\n",
		g_usr_data.case_name, pdata->td_id, total_row, rehash_count);
	memcpy(&pdata->begin_time, &begin_time, sizeof(struct timeval));
	memcpy(&pdata->end_time, &end_time, sizeof(struct timeval));

free_sess:
	agg_free_sess(h_sess, &table);
free_out_agg:
	agg_free_col_addr(rehash_pool.out_agg_cols, 1);
	agg_free_col_addr(rehash_pool.out_key_cols, 1);
	return NULL;
}

static void agg_set_value_data(struct wd_dae_col_addr *col_addr, FILE *file,
				enum wd_dae_data_type type, __u32 row_idx, __u16 data_info)
{
	int *int_value, *offset;
	char output_buff[32];
	long *long_value;
	int vchar_len;
	__u8 *empty;
	char *ptr;

	empty = (__u8 *)col_addr->empty;
	fprintf(file, "%d,", empty[row_idx]);

	switch (type) {
	case WD_DAE_DATE:
	case WD_DAE_INT:
		int_value = (int *)col_addr->value;
		fprintf(file, "%d", int_value[row_idx]);
		break;
	case WD_DAE_LONG:
	case WD_DAE_SHORT_DECIMAL:
		long_value = (long *)col_addr->value;
		fprintf(file, "%ld", long_value[row_idx]);
		break;
	case WD_DAE_LONG_DECIMAL:
		long_value = (long *)((char *)col_addr->value + row_idx * 16);
		fprintf(file, "0x%032lx", *long_value);
		break;
	case WD_DAE_CHAR:
		ptr = (char *)col_addr->value + row_idx * data_info;
		memset(output_buff, '\0', 32);
		memcpy(output_buff, ptr, data_info);
		fprintf(file, "%s", output_buff);
	case WD_DAE_VARCHAR:
		offset = (int *)col_addr->offset;
		ptr = (char *)col_addr->value + offset[row_idx];
		vchar_len = offset[row_idx + 1] - offset[row_idx];
		memset(output_buff, '\0', 32);
		memcpy(output_buff, ptr, vchar_len);
		fprintf(file, "'''%s'''", output_buff);
//		fprintf(file,"%d", offset[row_idx]);
		break;
	default:
		break;
	}
}

enum wd_dae_data_type get_out_agg_type(struct agg_case_info *perf_data, int idx)
{
	int i, j, count = 0;

	for (i = 0; i < perf_data->agg_cols_num; i++) {
		for (j = 0; j < perf_data->alg_num[i]; j++) {
			if (count == idx)
				return perf_data->agg_output_type[i][j];
			count++;
		}
	}

	return WD_DAE_LONG;
}

static void agg_write_data(struct wd_agg_req *req, FILE *file)
{
	struct agg_case_info *perf_data = &agg_perf_data[g_usr_data.case_index];
	__u32 row_num = req->real_out_row_count;
	enum wd_dae_data_type type;
	int i, j;

	for (j = 0; j < row_num; j++) {
		for (i = 0; i < req->out_key_cols_num; i++) {
			agg_set_value_data(&req->out_key_cols[i], file, perf_data->key_type[i],
					    j, perf_data->key_data_info[i]);
			fprintf(file, ",");
		}

		for (i = 0; i < req->out_agg_cols_num; i++) {
			type = get_out_agg_type(perf_data, i);
			agg_set_value_data(&req->out_agg_cols[i], file, type, j, 0);
			if (i != (req->out_agg_cols_num - 1))
				fprintf(file, ",");
		}
		fprintf(file, "\n");
	}
}

static int agg_do_task_get_out(handle_t h_sess, struct dae_pool *pool, __u64 *total_row, __u32 idx)
{
	struct agg_case_info *perf_data = &agg_perf_data[g_usr_data.case_index];
	char file_path[64] = "/home/";
	struct wd_agg_req req = {0};
	int len, ret, i = 0;
	__u64 count = 0;
	char out[12];
	FILE *file;

	len = strlen(file_path);
	strcpy(file_path + len, g_usr_data.case_name);
	len = strlen(file_path);
	out[0] = '-';
	memcpy(out + 1, "out", strlen("out"));
	out[4] = idx + '0';
	memcpy(out + 5, ".txt", strlen(".txt"));
	out[9] = '\0';
	strcpy(file_path + len, out);
	if (!access(file_path, 0)) {
		printf("start clean %s!\n", file_path);
		if (truncate(file_path, 0) == -1) {
			printf("truncate failed\n");
			return -WD_EINVAL;
		}
	}

	file = fopen(file_path, "w");
	if (file == NULL) {
		printf("failed to open file %s\n", file_path);
		return -WD_EINVAL;
	}
	req.out_row_count = g_usr_data.req_output_num;
	req.out_key_cols_num = perf_data->key_cols_num;
	req.out_agg_cols_num = perf_data->out_agg_cols_num;
	do {
		req.out_agg_cols = pool[i].out_agg_cols;
		req.out_key_cols = pool[i].out_key_cols;
		ret = wd_agg_get_output_sync(h_sess, &req);
		if (ret) {
			printf("failed to do agg output!\n");
			return ret;
		}

		if (req.state == WD_AGG_SUM_OVERFLOW) {
			printf("failed to do agg output sum overflow!\n");
		} else if (req.state) {
			printf("failed to do agg output req->state = %d!\n", req.state);
			return -WD_EINVAL;
		}
		agg_write_data(&req, file);
		count += req.real_out_row_count;
		if (req.output_done)
			break;
		i++;
	} while (true);
	fclose(file);

	*total_row = count;

	return 0;
}

static void *agg_do_task_function_test(void *arg)
{
	struct agg_case_info *perf_data = &agg_perf_data[g_usr_data.case_index];
	struct dae_thread_res *pdata = (struct dae_thread_res *)arg;
	struct dae_pool *pool = g_pool[pdata->td_id];
	struct wd_dae_col_addr out_key_cols[9];
	struct wd_dae_col_addr out_agg_cols[9];
	struct wd_dae_hash_table table = {0};
	struct wd_agg_req rehash_req = {0};
	struct wd_agg_req req = {0};
	struct dae_pool rehash_pool;
	__u64 total_input_row = 0;
	__u64 total_output_row = 0;
	__u32 rehash_count = 0;
	handle_t h_sess;
	int ret, i = 0;

	ret = agg_prepare_req(&rehash_pool, &rehash_req, &req);
	if (ret)
		return NULL;

	memcpy(&out_agg_cols, rehash_pool.out_agg_cols,
		sizeof(struct wd_dae_col_addr) * perf_data->out_agg_cols_num);
	memcpy(&out_key_cols, rehash_pool.out_key_cols,
		sizeof(struct wd_dae_col_addr) * perf_data->key_cols_num);

	h_sess = agg_alloc_sess(&table);
	if (!h_sess)
		goto free_out_agg;

	ret = wd_agg_set_hash_table(h_sess, &table);
	if (ret) {
		printf("failed to set hash table!\n");
		goto free_sess;
	}

	while (i < g_actual_req_num) {
		req.agg_cols = pool[i].agg_cols;
		req.key_cols = pool[i].key_cols;
		req.in_row_count = pool[i].row_num;
		req.real_in_row_count = 0;
		ret = wd_agg_add_input_sync(h_sess, &req);
		if (ret) {
			printf("failed to do agg input, ret = %d!\n", ret);
			goto free_sess;
		}
		if (req.state == WD_AGG_NEED_REHASH) {
			ret = agg_do_rehash(h_sess, &table, &rehash_req);
			if (ret)
				goto free_sess;

			rehash_count++;
			memcpy(rehash_req.out_agg_cols, &out_agg_cols,
				sizeof(struct wd_dae_col_addr) * perf_data->out_agg_cols_num);
			memcpy(rehash_req.out_key_cols, &out_key_cols,
				sizeof(struct wd_dae_col_addr) * perf_data->key_cols_num);
			req.state = 0;
			continue;
		}

		if (req.state == WD_AGG_INVALID_VARCHAR) {
			printf("varchar overflow!\n");
			break;
		} else if (req.state == WD_AGG_SUM_OVERFLOW) {
			printf("failed to do agg input sum overflow!\n");
		} else if (req.state) {
			printf("failed to do agg input state = %d!\n", req.state);
			goto free_sess;
		}
		total_input_row += req.in_row_count;
		i++;
	}

	ret = agg_do_task_get_out(h_sess, pool, &total_output_row, pdata->td_id);
	if (ret) {
		printf("failed to get output %d!\n", ret);
		goto free_sess;
	}

	printf("%s input data num %llu output data %llu row num, rehash %u times!\n",
		g_usr_data.case_name, total_input_row, total_output_row, rehash_count);

free_sess:
	agg_free_sess(h_sess, &table);
free_out_agg:
	agg_free_col_addr(rehash_pool.out_agg_cols, 1);
	agg_free_col_addr(rehash_pool.out_key_cols, 1);
	return NULL;
}

static void start_tread_test(void)
{
	struct agg_case_info *perf_data = &agg_perf_data[g_usr_data.case_index];
	struct dae_thread_res threads_args[THREADS_NUM];
	pthread_t tdid[THREADS_NUM];
	struct timeval begin_time;
	bool time_set = false;
	struct timeval end_time;
	long time_used;
	double perf;
	int ret;
	__u32 i;

	for (i = 0; i < g_usr_data.thread_num; i++) {
		threads_args[i].td_id = i;
		if (g_usr_data.perf_test)
			ret = pthread_create(&tdid[i], NULL,
					agg_do_task_perf_test, &threads_args[i]);
		else
			ret = pthread_create(&tdid[i], NULL,
					agg_do_task_function_test, &threads_args[i]);
		if (ret) {
			printf("create agg thread fail, ret = %d!\n", ret);
			return;
		}
	}

	for (i = 0; i < g_usr_data.thread_num; i++) {
		ret = pthread_join(tdid[i], NULL);
		if (ret) {
			printf("join sync thread fail!\n");
			return;
		}
	}

	if (!g_usr_data.perf_test)
		return;

	memcpy(&begin_time, &threads_args[0].begin_time, sizeof(struct timeval));
	for (i = 0; i < g_usr_data.thread_num; i++) {
		if (threads_args[i].begin_time.tv_sec < begin_time.tv_sec) {
			memcpy(&begin_time, &threads_args[i].begin_time, sizeof(struct timeval));
			time_set = true;
			continue;
		}
	}

	for (i = 0; i < g_usr_data.thread_num; i++) {
		if (time_set)
			break;
		if (threads_args[i].begin_time.tv_usec < begin_time.tv_usec) {
			memcpy(&begin_time, &threads_args[i].begin_time, sizeof(struct timeval));
			continue;
		}
	}

	time_set = false;
	memcpy(&end_time, &threads_args[0].end_time, sizeof(struct timeval));
	for (i = 0; i < g_usr_data.thread_num; i++) {
		if (threads_args[i].end_time.tv_sec > end_time.tv_sec) {
			memcpy(&end_time, &threads_args[i].end_time, sizeof(struct timeval));
			time_set = true;
			continue;
		}
	}

	for (i = 0; i < g_usr_data.thread_num; i++) {
		if (time_set)
			break;
		if (threads_args[i].end_time.tv_usec > end_time.tv_usec) {
			memcpy(&end_time, &threads_args[i].end_time, sizeof(struct timeval));
			continue;
		}
	}

	time_used = (end_time.tv_sec - begin_time.tv_sec) * S_TO_US_TIME +
			end_time.tv_usec - begin_time.tv_usec;
	printf("case %s start %lu s %lu us, end %lu s %lu us, used time %ld us!\n",
		g_usr_data.case_name, begin_time.tv_sec, begin_time.tv_usec,
		end_time.tv_sec, end_time.tv_usec, time_used);

	perf = (double)perf_data->row_size * g_total_row / 1000 /
		time_used * g_usr_data.thread_num * 1.024;

	printf("case %s row size is %u perf is %lf GBps!\n",
		g_usr_data.case_name, perf_data->row_size, perf);
}

static int agg_alloc_key_in_addr(struct agg_case_info *perf_data, struct dae_pool *pool)
{
	struct wd_dae_col_addr *key_cols;
	int i, ret;

	key_cols = calloc(perf_data->key_cols_num, sizeof(struct wd_dae_col_addr));
	if (!key_cols)
		return -WD_ENOMEM;

	for (i = 0; i < perf_data->key_cols_num; i++) {
		ret = agg_alloc_value_addr(key_cols, g_usr_data.req_input_num,
					   perf_data->key_type[i], perf_data->key_data_info[i], i);
		if (ret)
			goto free_key_cols;

		key_cols[i].empty_size = 0;
		key_cols[i].value_size = 0;
		key_cols[i].offset_size = 4;
	}

	pool->key_cols = key_cols;

	return 0;

free_key_cols:
	agg_free_col_addr(key_cols, i);
	return -WD_ENOMEM;
}

static int agg_alloc_agg_in_addr(struct agg_case_info *perf_data, struct dae_pool *pool)
{
	struct wd_dae_col_addr *agg_cols;
	int i, ret;

	agg_cols = calloc(perf_data->agg_cols_num, sizeof(struct wd_dae_col_addr));
	if (!agg_cols)
		return -WD_ENOMEM;

	for (i = 0; i < perf_data->agg_cols_num; i++) {
		ret = agg_alloc_value_addr(agg_cols, g_usr_data.req_input_num,
					perf_data->agg_input_type[i],
					perf_data->agg_data_info[i], i);
		if (ret)
			goto free_agg_cols;

		agg_cols[i].value_size = 0;
		agg_cols[i].offset_size = 4;
		agg_cols[i].empty_size = 0;
	}

	pool->agg_cols = agg_cols;

	return 0;

free_agg_cols:
	agg_free_col_addr(agg_cols, i);
	return -WD_ENOMEM;
}

static void agg_uninit_req_mem(void)
{
	struct agg_case_info *perf_data = &agg_perf_data[g_usr_data.case_index];
	int i, j;

	if (!g_pool)
		return;

	for (j = 0; j < g_usr_data.thread_num; j++) {
		if (!g_pool[j])
			continue;
		for (i = 0; i < g_req_num; i++) {
			agg_free_col_addr(g_pool[j][i].key_cols, perf_data->key_cols_num);
			agg_free_col_addr(g_pool[j][i].out_key_cols, perf_data->key_cols_num);
			agg_free_col_addr(g_pool[j][i].agg_cols, perf_data->agg_cols_num);
			agg_free_col_addr(g_pool[j][i].out_agg_cols, perf_data->out_agg_cols_num);
		}
	}

	free(g_pool);
}

static int agg_init_req_mem(void)
{
	struct agg_case_info *perf_data = &agg_perf_data[g_usr_data.case_index];
	__u32 req_in_num, req_out_num, i, j;
	int ret;

	req_in_num = g_usr_data.all_num / g_usr_data.req_input_num;
	if (g_usr_data.all_num % g_usr_data.req_input_num)
		req_in_num++;

	req_out_num = g_usr_data.all_num / g_usr_data.req_output_num;
	if (g_usr_data.all_num % g_usr_data.req_output_num)
		req_out_num++;

	req_out_num += 2;
	g_req_num = req_in_num > req_out_num ? req_in_num : req_out_num;
	g_pool = calloc(g_usr_data.thread_num, sizeof(struct dae_pool *));
	if (!g_pool)
		return -WD_ENOMEM;

	for (j = 0; j < g_usr_data.thread_num; j++) {
		g_pool[j] = calloc(g_req_num, sizeof(struct dae_pool));
		if (!g_pool[j])
			goto free_pool;
		for (i = 0; i < g_req_num; i++) {
			if (!g_usr_data.perf_test) {
				ret = agg_alloc_agg_out_addr(perf_data, &g_pool[j][i],
							    g_usr_data.req_output_num);
				if (ret)
					goto free_pool;
				ret = agg_alloc_key_out_addr(perf_data, &g_pool[j][i],
							     g_usr_data.req_output_num);
				if (ret)
					goto free_pool;
			}
			ret = agg_alloc_agg_in_addr(perf_data, &g_pool[j][i]);
				if (ret)
					goto free_pool;
			ret = agg_alloc_key_in_addr(perf_data, &g_pool[j][i]);
			if (ret)
				goto free_pool;
		}
	}
	return 0;

free_pool:
	agg_uninit_req_mem();

	return -WD_ENOMEM;
}

static void agg_uninit_ctx(void)
{
	wd_agg_uninit();
}

static int agg_init_ctx(void)
{
	struct wd_ctx_params cparams = {0};
	struct wd_ctx_nums *ctx_set_num;
	int ret;

	ctx_set_num = calloc(1, sizeof(*ctx_set_num));
	if (!ctx_set_num) {
		printf("failed to alloc ctx_set_size!\n");
		return -WD_ENOMEM;
	}

	cparams.op_type_num = 1;
	cparams.ctx_set_num = ctx_set_num;
	cparams.bmp = numa_allocate_nodemask();
	if (!cparams.bmp) {
		printf("failed to create nodemask!\n");
		ret = -WD_ENOMEM;
		goto out_freectx;
	}

	numa_bitmask_setall(cparams.bmp);

	ctx_set_num->sync_ctx_num = g_usr_data.thread_num;

	ret = wd_agg_init("hashagg", 0, TASK_HW, &cparams);

	numa_free_nodemask(cparams.bmp);

out_freectx:
	free(ctx_set_num);
	return ret;
}

static void print_help(void)
{
	WD_INFO("NAME\n");
	WD_INFO("test agg performance,etc\n");
	WD_INFO("USAGE\n");
	WD_INFO("    numactl --cpubind=0  --membind=0,1 ./wd_dae_test xxxx\n");
	WD_INFO("        specify numa nodes for cpu and memory\n");
	WD_INFO("DESCRIPTION\n");
	WD_INFO("    [--std_num]:\n");
	WD_INFO("        standard hash table row num\n");
	WD_INFO("    [--ext_num]:\n");
	WD_INFO("        extend hash table row num\n");
	WD_INFO("    [--all_num]:\n");
	WD_INFO("        all data row num\n");
	WD_INFO("    [--input_num]:\n");
	WD_INFO("        each input req row num\n");
	WD_INFO("    [--output_num]:\n");
	WD_INFO("        each output req row num\n");
	WD_INFO("    [--case_name]:\n");
	WD_INFO("	test case name, like sql65-case1\n");
	WD_INFO("    [--perf_test]:\n");
	WD_INFO("	0: test function, 1: perf test\n");
	WD_INFO("    [--thread_num]:\n");
	WD_INFO("	thread number\n");
	WD_INFO("    [--rehash_rate]:\n");
	WD_INFO("	rehash memory rate\n");
	WD_INFO("    [--rehash_output_num]:\n");
	WD_INFO("	rehash output row num\n");
	WD_INFO("Example\n");
	WD_INFO("./wd_dae_test --all_num 100 --ext_num 1024 --case_name sql65-case1\n");
}

static int get_agg_case(const char *case_name)
{
	int case_size = ARRAY_SIZE(agg_case);
	int i, j;

	for (i = 0; i < case_size; i++) {
		for (j = 0; j < agg_case[i].case_num; j++) {
			if (strcmp(case_name, agg_case[i].case_name[j]) == 0)
				return agg_case[i].case_index;
		}
	}

	return -WD_EINVAL;
}

static void dump_usr_param(void)
{
	printf("[--std_num]:           %u\n", g_usr_data.std_num);
	printf("[--ext_num]:           %u\n", g_usr_data.ext_num);
	printf("[--all_num]:           %u\n", g_usr_data.all_num);
	printf("[--input_num]:         %u\n", g_usr_data.req_input_num);
	printf("[--output_num]:        %u\n", g_usr_data.req_output_num);
	printf("[--case_name]:         %s\n", g_usr_data.case_name);
	printf("[--perf_test]:         %u\n", g_usr_data.perf_test);
	printf("[--thread_num]:        %u\n", g_usr_data.thread_num);
	printf("[--rehash_rate]:       %u\n", g_usr_data.rehash_rate);
	printf("[--rehash_output_num]: %u\n", g_usr_data.rehash_output_num);
}

static int agg_check_usr_data(void)
{
	if (!g_usr_data.std_num)
		g_usr_data.std_num = HASH_TABLE_ROW_NUM;

	if (!g_usr_data.ext_num)
		g_usr_data.ext_num = HASH_TABLE_ROW_NUM;

	if (!g_usr_data.all_num)
		g_usr_data.all_num = DEFAULT_ROW_NUM;

	if (!g_usr_data.req_input_num)
		g_usr_data.req_input_num = DEFAULT_ROW_NUM;

	if (!g_usr_data.req_output_num)
		g_usr_data.req_output_num = DEFAULT_ROW_NUM;

	if (!g_usr_data.thread_num)
		g_usr_data.thread_num = 1;

	if (!g_usr_data.rehash_rate)
		g_usr_data.rehash_rate = 4;

	if (!g_usr_data.rehash_output_num)
		g_usr_data.rehash_output_num = DEFAULT_ROW_NUM;

	if (!strlen(g_usr_data.case_name)) {
		printf("case is null!\n");
		print_help();
		return -WD_EINVAL;
	}

	return 0;
}

int agg_cmd_parse(int argc, char *argv[])
{
	int option_index = 0;
	int c = 0, ret;

	static struct option long_options[] = {
		{"help",		no_argument,		0, 0},
		{"std_num",		required_argument,	0, 1},
		{"ext_num",		required_argument,	0, 2},
		{"all_num",		required_argument,	0, 3},
		{"input_num",		required_argument,	0, 4},
		{"output_num",		required_argument,	0, 5},
		{"case_name",		required_argument,	0, 6},
		{"perf_test",		required_argument,	0, 7},
		{"thread_num",		required_argument,	0, 8},
		{"rehash_rate",		required_argument,	0, 9},
		{"rehash_output_num",	required_argument,	0, 10},
		{0, 0, 0, 0}
	};

	while (1) {
		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 0:
			print_help();
			goto to_exit;
		case 1:
			g_usr_data.std_num = strtol(optarg, NULL, 0);
			if (!g_usr_data.std_num) {
				printf("invalid std num %u\n", g_usr_data.std_num);
				goto to_exit;
			}
			break;
		case 2:
			g_usr_data.ext_num = strtol(optarg, NULL, 0);
			if (!g_usr_data.ext_num) {
				printf("invalid ext num %u\n", g_usr_data.std_num);
				goto to_exit;
			}
			break;
		case 3:
			g_usr_data.all_num = strtol(optarg, NULL, 0);
			if (!g_usr_data.all_num) {
				printf("invalid all num %u\n", g_usr_data.std_num);
				goto to_exit;
			}
			break;
		case 4:
			g_usr_data.req_input_num = strtol(optarg, NULL, 0);
			printf("g_usr_data.req_input_num\n");
			if (!g_usr_data.req_input_num) {
				printf("invalid req_input_num %u\n", g_usr_data.req_input_num);
				goto to_exit;
			}
			break;
		case 5:
			g_usr_data.req_output_num = strtol(optarg, NULL, 0);
			if (!g_usr_data.req_output_num) {
				printf("invalid req_output_num %u\n", g_usr_data.req_output_num);
				goto to_exit;
			}
			break;
		case 6:
			ret = get_agg_case(optarg);
			if (ret < 0) {
				printf("invalid case_name %s\n", optarg);
				goto to_exit;
			}
			strcpy(g_usr_data.case_name, optarg);
			g_usr_data.case_index = ret;
			break;
		case 7:
			g_usr_data.perf_test = strtol(optarg, NULL, 0);
			break;
		case 8:
			g_usr_data.thread_num = strtol(optarg, NULL, 0);
			break;
		case 9:
			g_usr_data.rehash_rate = strtol(optarg, NULL, 0);
			break;
		case 10:
			g_usr_data.rehash_output_num = strtol(optarg, NULL, 0);
			break;
		default:
			printf("invalid: bad input parameter!\n");
			print_help();
			goto to_exit;
		}
	}

	ret = agg_check_usr_data();
	if (ret)
		goto to_exit;

	dump_usr_param();

	return 0;

to_exit:
	return -EINVAL;
}

int main(int argc, char **argv)
{
	int ret;

	ret = agg_cmd_parse(argc, argv);
	if (ret)
		return ret;

	ret = agg_init_ctx();
	if (ret)
		return ret;

	ret = agg_init_req_mem();
	if (ret)
		goto free_ctx;

	ret = agg_get_data_from_file();
	if (ret)
		goto free_req_mem;

	start_tread_test();

free_req_mem:
	agg_uninit_req_mem();
free_ctx:
	agg_uninit_ctx();
	return 0;
}
