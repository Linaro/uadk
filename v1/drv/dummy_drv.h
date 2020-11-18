/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __DUMMY_DRV_H__
#define __DUMMY_DRV_H__

#include "include/wd_dummy_usr_if.h"
#include "include/dummy_hw_usr_if.h"
#include "../wd.h"

#ifndef  DUMMY_ERR
#define DUMMY_ERR(format, args...) printf(format, ##args)
#endif

int dummy_set_queue_dio(struct wd_queue *q);
void dummy_unset_queue_dio(struct wd_queue *q);
int dummy_add_to_dio_q(struct wd_queue *q, void *req);
int dummy_get_from_dio_q(struct wd_queue *q, void **req);
void dummy_flush(struct wd_queue *q);
void *dummy_reserve_mem(struct wd_queue *q, size_t size);

#endif
