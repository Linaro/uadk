// SPDX-License-Identifier: Apache-2.0
/* Copyright 2025 Huawei Technologies Co.,Ltd. All rights reserved. */

#include <asm/types.h>

#include "v1/drv/hisi_zip_huf.h"
#include "v1/wd_util.h"

#define HW_MAX_TAIL_CACHE_LEN		0x28
#define MIN_COMPLETE_STORE_LEN		0x20
#define DEFLATE_BFINAL_LEN		1
#define DEFLATE_BTYPE_LEN		2
#define BYTE_ALIGN_MASK			7
#define EMPTY_STORE_BLOCK_VAL		0xffff0000L
#define HF_BLOCK_IS_COMPLETE		1
#define HF_BLOCK_IS_INCOMPLETE		0
#define LEN_NLEN_CHECK(data)		((data & 0xffff) != ((data >> 16) ^ 0xffff))

/* Constants related to the Huffman code table */
#define LIT_LEN_7BITS_THRESHOLD		7
#define LIT_LEN_8BITS_THRESHOLD		8
#define MAX_LIT_BITS_LEN		9
#define DIST_CODE_BITS_LEN		5
#define LEN_CODE_7BITS_MAX_VAL		0x17
#define LEN_CODE_7BITS_OFFSET		0x100
#define LIT_LEN_8BITS_LOW		0x30
#define LIT_LEN_8BITS_HIGH		0xBF
#define LIT_CODE_8BITS_OFFSET		0x30
#define LEN_CODE_8BITS_LOW		0xC0
#define LEN_CODE_8BITS_HIGH		0xC7
#define LEN_CODE_8BITS_BASE		0x118
#define LIT_LEN_9BITS_LOW		0x190
#define LIT_LEN_9BITS_HIGH		0x1FF
#define LIT_LEN_9BITS_BASE		0x90
/* Special code value */
#define END_OF_BLOCK_CODE_VAL		256
#define MIN_LEN_CODE_VAL		257
#define MAX_LEN_CODE_VAL		285
#define MAX_DIST_CODE_VAL		29

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

struct huffman_table {
	__u32 base_val;
	__u32 bit_len;
};

static struct huffman_table huf_len_tab[] = {
	{3, 0}, {4, 0}, {5, 0}, {6, 0}, {7, 0}, {8, 0}, {9, 0}, {10, 0}, {11, 1},
	{13, 1}, {15, 2}, {19, 2}, {23, 3}, {27, 3}, {31, 4}, {35, 4}, {43, 5},
	{51, 5}, {59, 6}, {67, 6}, {83, 7}, {99, 7}, {115, 8}, {131, 8}, {163, 9},
	{195, 9}, {227, 10}, {258, 0}
};

static struct huffman_table huf_dist_tab[] = {
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

	ret = (br->data >> br->cur_pos) & ((1L << n) - 1L);
	br->cur_pos += n;

	return ret;
}

static int check_store_huffman_block(struct bit_reader *br)
{
	__u32 pad, bits;
	long data;

	bits = br->total_bits - br->cur_pos;

	/* In store mode, data whose length is less than 32 bits must be incomplete */
	if (bits < MIN_COMPLETE_STORE_LEN)
		return HF_BLOCK_IS_INCOMPLETE;

	/* go to a byte boundary */
	pad = bits & BYTE_ALIGN_MASK;
	bits -= pad;
	data = read_bits(br, pad);
	if (data < 0)
		return HF_BLOCK_IS_INCOMPLETE;

	data = read_bits(br, bits);
	if (data < 0)
		return HF_BLOCK_IS_INCOMPLETE;

	/* check len and nlen */
	if (LEN_NLEN_CHECK(data))
		return -WD_EINVAL;

	if (data == EMPTY_STORE_BLOCK_VAL)
		return HF_BLOCK_IS_COMPLETE;

	return HF_BLOCK_IS_INCOMPLETE;
}

static int check_fix_huffman_block(struct bit_reader *br)
{
	long bit, len_idx, dist_code, extra, code;
	__u32 bits;

	while (br->cur_pos < br->total_bits) {
		/* reads 7~9 bits to determine literal/length */
		code = 0;
		bits = 0;
		while (bits <= MAX_LIT_BITS_LEN) {
			bit = read_bits(br, 1);
			if (bit < 0)
				return HF_BLOCK_IS_INCOMPLETE;

			code = (code << 1) | bit;
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
			if (bits == LIT_LEN_7BITS_THRESHOLD && code <= LEN_CODE_7BITS_MAX_VAL) {
				code += LEN_CODE_7BITS_OFFSET;
				break;
			} else if (bits == LIT_LEN_8BITS_THRESHOLD) {
				if (code >= LIT_LEN_8BITS_LOW && code <= LIT_LEN_8BITS_HIGH) {
					code -= LIT_CODE_8BITS_OFFSET;
					break;
				} else if (code >= LEN_CODE_8BITS_LOW &&
					   code <= LEN_CODE_8BITS_HIGH) {
					code = LEN_CODE_8BITS_BASE + (code - LEN_CODE_8BITS_LOW);
					break;
				}
			} else if (bits == MAX_LIT_BITS_LEN && code >= LIT_LEN_9BITS_LOW &&
				   code <= LIT_LEN_9BITS_HIGH) {
				code = LIT_LEN_9BITS_BASE + (code - LIT_LEN_9BITS_LOW);
				break;
			}
		}

		/* if the 9 bits cannot determin literal/length, an error occurs */
		if (bits > MAX_LIT_BITS_LEN)
			return -WD_EINVAL;

		/* end of a block */
		if (code == END_OF_BLOCK_CODE_VAL)
			return HF_BLOCK_IS_COMPLETE;

		/* The literal encoding directly represents the byte content of the original data */
		if (code < END_OF_BLOCK_CODE_VAL)
			continue;

		if (code > MAX_LEN_CODE_VAL)
			return -WD_EINVAL;

		/*
		 * The length encoding needs to query the huf_len_tab and huf_dist_tab
		 * to determine the data length.
		 */
		len_idx = code - MIN_LEN_CODE_VAL;
		extra = read_bits(br, huf_len_tab[len_idx].bit_len);
		if (extra < 0)
			return HF_BLOCK_IS_INCOMPLETE;

		/* read 5 bits to determine the distance value */
		dist_code = read_bits(br, DIST_CODE_BITS_LEN);
		if (dist_code < 0)
			return HF_BLOCK_IS_INCOMPLETE;
		else if (dist_code > MAX_DIST_CODE_VAL)
			return -WD_EINVAL;

		extra = read_bits(br, huf_dist_tab[dist_code].bit_len);
		if (extra < 0)
			return HF_BLOCK_IS_INCOMPLETE;
	}

	return HF_BLOCK_IS_INCOMPLETE;
}

int check_huffman_block_integrity(void *data, __u32 bit_len)
{
	struct bit_reader br = {0};
	long bfinal = 0;
	long btype;
	int ret;

	if (bit_len == 0 || bit_len >= HW_MAX_TAIL_CACHE_LEN)
		return HF_BLOCK_IS_INCOMPLETE;

	br.total_bits = bit_len;
	br.data = *((__u64 *)data);

	while (!bfinal && br.cur_pos < bit_len) {
		bfinal = read_bits(&br, DEFLATE_BFINAL_LEN);
		btype = read_bits(&br, DEFLATE_BTYPE_LEN);
		if (bfinal < 0 || btype < 0)
			return HF_BLOCK_IS_INCOMPLETE;

		if (btype > DYN_TYPE)
			return -WD_EINVAL;

		/*
		 * Data in dynamic type must be incomplete when less than 5byte,
		 * the store type can have at most one complete block,
		 * the fix type needs to check the integrity of each block.
		 */
		if (btype == DYN_TYPE) {
			return HF_BLOCK_IS_INCOMPLETE;
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
		return HF_BLOCK_IS_INCOMPLETE;

	return HF_BLOCK_IS_COMPLETE;
}
