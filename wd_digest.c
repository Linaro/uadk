/* SPDX-License-Identifier: Apache-2.0 */
#include "hisi_sec.h"
#include "wd_digest.h"

handle_t wd_alg_digest_alloc_sess(struct wd_digest_sess_setup *setup,
				  wd_dev_mask_t *dev_mask)
{
	return 0;
}

void wd_alg_digest_free_sess(handle_t handle)
{
}

int wd_alg_do_digest(handle_t handle, struct wd_digest_arg *arg)
{
	return 0;
}

int wd_alg_set_digest_key(handle_t handle, __u8 *key, __u32 key_len)
{
	return 0;
}

int wd_alg_digest_poll(handle_t handle, __u32 count)
{
	return 0;
}
