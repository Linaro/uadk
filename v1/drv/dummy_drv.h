/*
 * Copyright 2019 Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __DUMMY_DRV_H__
#define __DUMMY_DRV_H__

#include "internal/wd_dummy_usr_if.h"
#include "internal/dummy_hw_usr_if.h"
#include "../wd.h"

#ifndef  DUMMY_ERR
#define DUMMY_ERR(format, args...) printf(format, ##args)
#endif

int dummy_set_queue_dio(struct wd_queue *q);
void dummy_unset_queue_dio(struct wd_queue *q);
int dummy_add_to_dio_q(struct wd_queue *q, void **req, __u32 num);
int dummy_get_from_dio_q(struct wd_queue *q, void **req, __u32 num);
void dummy_flush(struct wd_queue *q);
void *dummy_reserve_mem(struct wd_queue *q, size_t size);

#endif
