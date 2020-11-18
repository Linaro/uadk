/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file defines the dummy algo interface between the user and kernel space
 */

#ifndef __DUMMY_USR_IF_H
#define __DUMMY_USR_IF_H


/* Algorithm name */
#define AN_DUMMY_MEMCPY "memcopy"

#define AAN_AFLAGS		"aflags"
#define AAN_MAX_COPY_SIZE	"max_copy_size"

struct wd_dummy_cpy_param {
	int flags;
	int max_copy_size;
};

struct wd_dummy_cpy_msg {
	char *src_addr;
	char *tgt_addr;
	size_t size;
	void *ptr;
	__u32 ret;
};

#endif
