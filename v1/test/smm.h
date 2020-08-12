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

#ifndef __SMM_H
#define __SMM_H

//#include <stddef.h>

extern int smm_init(void *pt_addr, size_t size, unsigned int align_mask);
extern void *smm_alloc(void *pt_addr, size_t size);
extern void smm_free(void *pt_addr, void *ptr);

#ifndef NDEBUG
extern void smm_dump(void *pt_addr);
extern int smm_get_freeblock_num(void *pt_addr);
#endif

#endif
