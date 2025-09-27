// SPDX-License-Identifier: Apache-2.0
/* Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <asm/types.h>

#include "drv/hisi_comp_huf.h"
#include "wd_util.h"

#define MAX_HW_TAIL_CACHE_LEN		0x28
#define MIN_COMPLETE_STORE_LEN		0x20
#define DEFLATE_BFINAL_LEN		1
#define DEFLATE_BTYPE_LEN		2
#define BYTE_ALIGN_MASK			7
#define EMPTY_STORE_BLOCK_VAL		0xffff0000L
#define BLOCK_IS_COMPLETE		1
#define BLOCK_IS_INCOMPLETE		0
#define LEN_NLEN_CHECK(data)		(((data) & 0xffff) != (((data) >> 16) ^ 0xffff))

/* Constants related to the Huffman code table */
#define LIT_LEN_7BIT_THRESHOLD		7
#define LIT_LEN_8BIT_THRESHOLD		8
#define MAX_LIT_LEN_BITS		9
#define DIST_CODE_BITS			5
#define LEN_CODE_7BIT_MAX		0x17
#define LEN_CODE_7BIT_OFFSET		0x100
#define LIT_LEN_8BIT_LOW		0x30
#define LIT_LEN_8BIT_HIGH		0xBF
#define LIT_CODE_8BIT_OFFSET		0x30
#define LEN_CODE_8BIT_LOW		0xC0
#define LEN_CODE_8BIT_HIGH		0xC7
#define LEN_CODE_8BIT_BASE		0x118
#define LIT_LEN_9BIT_LOW		0x190
#define LIT_LEN_9BIT_HIGH		0x1FF
#define LIT_LEN_9BIT_BASE		0x90
/* Special code value */
#define END_OF_BLOCK_CODE		256
#define MIN_LEN_CODE			257
#define MAX_LEN_CODE			285
#define MAX_DIST_CODE			29

enum huffman_block_type {
	STORE_TYPE,
	FIX_TYPE,
	DYN_TYPE,
};

struct bit_reader {
	__u64 data;
	__u32 cur_pos;
	__u32 total_bits;
};

struct huffman_code {
	__u32 base;
	__u32 bits;
};

static struct huffman_code len_tab[] = {
	{3, 0}, {4, 0}, {5, 0}, {6, 0}, {7, 0}, {8, 0}, {9, 0}, {10, 0}, {11, 1},
	{13, 1}, {15, 2}, {19, 2}, {23, 3}, {27, 3}, {31, 4}, {35, 4}, {43, 5},
	{51, 5}, {59, 6}, {67, 6}, {83, 7}, {99, 7}, {115, 8}, {131, 8}, {163, 9},
	{195, 9}, {227, 10}, {258, 0}
};

static struct huffman_code dist_tab[] = {
	{1, 0}, {2, 0}, {3, 0}, {4, 0}, {5, 1}, {7, 1}, {9, 2}, {13, 2}, {17, 3},
	{25, 3}, {33, 4}, {49, 4}, {65, 5}, {97, 5}, {129, 6}, {193, 6}, {257, 7},
	{385, 7}, {513, 8}, {769, 8}, {1025, 9}, {1537, 9}, {2049, 10}, {3073, 10},
	{4097, 11}, {6145, 11}, {8193, 12}, {12289, 12}, {16385, 13}, {24577, 13}
};

static long read_bits(struct bit_reader *br, __u32 n)
{
	long ret;

	if (br->cur_pos + n > br->total_bits)
		return -WD_EINVAL;

	ret = (br->data >> br->cur_pos) & ((1UL << n) - 1UL);
	br->cur_pos += n;

	return ret;
}

static int check_store_huffman_block(struct bit_reader *br)
{
	__u32 pad, bit_len;
	unsigned long data;

	bit_len = br->total_bits - br->cur_pos;

	/* In store mode, data whose length is less than 32 bits must be incomplete */
	if (bit_len < MIN_COMPLETE_STORE_LEN)
		return BLOCK_IS_INCOMPLETE;

	/* go to a byte boundary */
	pad = bit_len & BYTE_ALIGN_MASK;
	bit_len -= pad;
	br->cur_pos += pad;

	/* check len and nlen */
	data = read_bits(br, bit_len);
	if (LEN_NLEN_CHECK(data))
		return -WD_EINVAL;

	if (data == EMPTY_STORE_BLOCK_VAL)
		return BLOCK_IS_COMPLETE;

	return BLOCK_IS_INCOMPLETE;
}

static int check_fix_huffman_block(struct bit_reader *br)
{
	long bits, bit, len_idx, dist_code, extra;
	unsigned long code, ubit;

	while (br->cur_pos < br->total_bits) {
		/* reads 7~9 bits to determine literal/length */
		code = 0;
		bits = 0;
		while (bits <= MAX_LIT_LEN_BITS) {
			bit = read_bits(br, 1);
			if (bit < 0)
				return BLOCK_IS_INCOMPLETE;

			ubit = bit;
			code = (code << 1) | ubit;
			bits++;

			/*
			 * Matching by bit in ascending order and convert code value to
			 * literal/length range value. The literal/length is determined
			 * based on the code value (256 indicates END_OF_BLOCK):
			 *  Range      Code        Type   Len
			 * 0-143   [0x30, 0xBF]   literal 8bit
			 * 144-255 [0x190, 0x1ff] literal 9bit
			 * 256-279 [0x0, 0x17]    length  7bit
			 * 280-287 [0xC0, 0xC7]   length  8bit
			 */
			if (bits == LIT_LEN_7BIT_THRESHOLD && code <= LEN_CODE_7BIT_MAX) {
				code += LEN_CODE_7BIT_OFFSET;
				break;
			} else if (bits == LIT_LEN_8BIT_THRESHOLD) {
				if (code >= LIT_LEN_8BIT_LOW && code <= LIT_LEN_8BIT_HIGH) {
					code -= LIT_CODE_8BIT_OFFSET;
					break;
				} else if (code >= LEN_CODE_8BIT_LOW &&
					   code <= LEN_CODE_8BIT_HIGH) {
					code = LEN_CODE_8BIT_BASE + (code - LEN_CODE_8BIT_LOW);
					break;
				}
			} else if (bits == MAX_LIT_LEN_BITS && code >= LIT_LEN_9BIT_LOW &&
				   code <= LIT_LEN_9BIT_HIGH) {
				code = LIT_LEN_9BIT_BASE + (code - LIT_LEN_9BIT_LOW);
				break;
			}
		}

		/* if the 9 bits cannot determin literal/length, an error occurs */
		if (bits > MAX_LIT_LEN_BITS)
			return -WD_EINVAL;

		/* end of a block */
		if (code == END_OF_BLOCK_CODE)
			return BLOCK_IS_COMPLETE;

		/* The literal encoding directly represents the byte content of the original data */
		if (code < END_OF_BLOCK_CODE)
			continue;

		if (code > MAX_LEN_CODE)
			return -WD_EINVAL;

		/*
		 * The length encoding needs to query the len_tab and dist_tab
		 * to determine the data length.
		 */
		len_idx = code - MIN_LEN_CODE;
		extra = read_bits(br, len_tab[len_idx].bits);
		if (extra < 0)
			return BLOCK_IS_INCOMPLETE;

		/* read 5 bits to determine the distance value */
		dist_code = read_bits(br, DIST_CODE_BITS);
		if (dist_code < 0)
			return BLOCK_IS_INCOMPLETE;
		else if (dist_code > MAX_DIST_CODE)
			return -WD_EINVAL;

		extra = read_bits(br, dist_tab[dist_code].bits);
		if (extra < 0)
			return BLOCK_IS_INCOMPLETE;
	}

	return BLOCK_IS_INCOMPLETE;
}

int check_bfinal_complete_block(void *addr, __u32 bit_len)
{
	struct bit_reader br = {0};
	long bfinal = 0;
	long btype;
	int ret;

	if (bit_len == 0 || bit_len >= MAX_HW_TAIL_CACHE_LEN)
		return BLOCK_IS_INCOMPLETE;

	br.total_bits = bit_len;
	br.data = *((__u64 *)addr);

	while (!bfinal && br.cur_pos < bit_len) {
		bfinal = read_bits(&br, DEFLATE_BFINAL_LEN);
		btype = read_bits(&br, DEFLATE_BTYPE_LEN);
		if (bfinal < 0 || btype < 0)
			return BLOCK_IS_INCOMPLETE;

		if (btype > DYN_TYPE)
			return -WD_EINVAL;

		/*
		 * Data in dynamic type must be incomplete when less than 5byte,
		 * the store type can have at most one complete block,
		 * the fix type needs to check the integrity of each block.
		 */
		if (btype == DYN_TYPE) {
			return BLOCK_IS_INCOMPLETE;
		} else if (btype == STORE_TYPE) {
			return check_store_huffman_block(&br);
		} else if (btype == FIX_TYPE) {
			ret = check_fix_huffman_block(&br);
			if (ret <= 0)
				return ret;
		}
	}

	/*
	 * The data seem to be incomplete if bfinal is 0 when
	 * the analyzed data is judged to be complete.
	 */
	if (!bfinal)
		return BLOCK_IS_INCOMPLETE;

	return BLOCK_IS_COMPLETE;
}
