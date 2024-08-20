/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#ifndef __WD_DAE_H
#define __WD_DAE_H

#include <dlfcn.h>
#include <stdbool.h>
#include <asm/types.h>
#include "wd.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * wd_dae_data_type - Data type of DAE
 */
enum wd_dae_data_type {
	WD_DAE_DATE,
	WD_DAE_INT,
	WD_DAE_LONG,
	WD_DAE_SHORT_DECIMAL,
	WD_DAE_LONG_DECIMAL,
	WD_DAE_CHAR,
	WD_DAE_VARCHAR,
	WD_DAE_DATA_TYPE_MAX,
};

/**
 * wd_dae_charset - Charset information of DAE
 */
struct wd_dae_charset {
	bool binary_format;
	bool space;
	bool subwoofer;
};

/**
 * wd_dae_col_addr - Column information of DAE.
 * @empty: 0 indicates that the data is valid, 1 indicate invalid.
 * @value: Indicates the value of the data.
 * @offset: Indicates the length of the string data, only for VARCHAR.
 * @empty_size: The value is equal to row_count * sizeof(__u8).
 * @value_size: The value is equal to row_count * sizeof(data_type).
 * @offset_size: The value is equal to (row_count + 1) * sizeof(__u32).
 */
struct wd_dae_col_addr {
	__u8 *empty;
	void *value;
	__u32 *offset;
	__u64 empty_size;
	__u64 value_size;
	__u64 offset_size;
};

/**
 * wd_dae_hash_table - Hash table information of DAE.
 * @std_table: Address of standard hash table.
 * @ext_table: Address of external hash table.
 * @std_table_row_num: Row number of standard hash table.
 * @ext_table_row_num: Row number of external hash table.
 * @table_row_size: Row size of hash table, user should get it
 * from wd_agg_get_table_rowsize.
 */
struct wd_dae_hash_table {
	void *std_table;
	void *ext_table;
	__u32 std_table_row_num;
	__u32 ext_table_row_num;
	__u32 table_row_size;
};

#ifdef __cplusplus
}
#endif

#endif /* __WD_DAE_H */
