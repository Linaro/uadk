/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file defines the dummy hardware/driver interface between the user and
 * kernel space
 */

#ifndef __DUMMY_HW_USR_IF_H
#define __DUMMY_HW_USR_IF_H

#include <linux/types.h>

#define DUMMY_WD 		"dummy_wd"

#define Q_BDS 			16
#define DUMMY_HW_TAG_SZ 	8
#define DUMMY_HW_TAG 		"WDDUMMY"

/* mmio:	1 page (used for bd) (off=0)
 * dus:		2 page (no use yet, just for test) (off=1)
 * ss:		(off = 3)
 */
#define DUMMY_MMIO_START 0
#define DUMMY_DUS_START (PAGE_SIZE*1)
#define DUMMY_SS_START  (PAGE_SIZE*3)

/* the format of the device ring space, which is of drv */
#define ring_bd wd_dummy_cpy_msg

/* the format of the device io space, which is of drv */
struct dummy_hw_queue_reg {
	char hw_tag[DUMMY_HW_TAG_SZ];	/* should be "WDDUMMY\0" */
	struct ring_bd ring[Q_BDS];	/* in real hardware, this is good to be
					   in memory space, and will be fast
					   for communication. here we keep it
					   in io space just to make it simple
					   */
	__u32 ring_bd_num;		/* ring_bd_num, now it is Q_BDS until
					   we use a memory ring */
	__u32 head; 			/* assume int is atomical. it should be
					   fine as a dummy and test function.
					   head is for the writer(user) while
					   tail is for the reader(kernel).
					   head==tail means the queue is empty
					   */
	__u32 tail;
};

#define DUMMY_CMD_FLUSH		_IO('d', 0)

#endif
