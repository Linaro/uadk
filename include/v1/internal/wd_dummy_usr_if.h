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

/*
 * This file defines the dummy algo interface between the user
 * and kernel space
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
