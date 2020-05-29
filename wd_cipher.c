/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-License-Identifier: Apache-2.0 */
#include "hisi_sec.h"
#include "wd_cipher.h"

handle_t wd_alg_cipher_alloc_sess(char *alg_name, uint32_t mode,
				  wd_dev_mask_t *dev_mask)
{
	return 0;
}

void wd_alg_cipher_free_sess(handle_t handle)
{
}

int wd_alg_encrypt(handle_t handle, struct wd_cipher_arg *arg)
{
	return 0;
}

int wd_alg_decrypt(handle_t handle, struct wd_cipher_arg *arg)
{
	return 0;
}

int wd_alg_set_key(handle_t handle, __u8 *key, __u32 key_len)
{
	return 0;
}
