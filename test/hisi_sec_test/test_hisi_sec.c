// SPDX-License-Identifier: GPL-2.0+
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "test_hisi_sec.h"
#include "wd_cipher.h"

#define HW_CTX_SIZE (24 * 1024)
#define BUFF_SIZE 1024
#define IV_SIZE   256

static void hexdump(char *buff, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		printf("\\0x%02x", buff[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
	}
	printf("\n");
}

static int test_sec(int flag)
{
	struct cipher_testvec *tv = &aes_ecb_tv_template_128;
	struct wd_cipher_sess_setup setup;
	handle_t	handle;
	struct wd_cipher_arg arg;
	char algs[64];
	int cnt = 10;
	int ret = 0;

	/* config setup */
	setup.alg = WD_CIPHER_AES;
	setup.mode = WD_CIPHER_ECB;
	sprintf(algs, "cipher");
	setup.alg_name = algs;
	/* config arg */
	memset(&arg, 0, sizeof(struct wd_cipher_arg));
	arg.alg = WD_CIPHER_AES;
	arg.mode = WD_CIPHER_ECB;
	arg.op_type = WD_CIPHER_ENCRYPTION;

	arg.src  = malloc(BUFF_SIZE);
	if (!arg.src) {
		printf("arg src mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	memcpy(arg.src, tv->ptext, tv->len);
	arg.in_bytes = tv->len;

	arg.dst = malloc(BUFF_SIZE);
	if (!arg.dst) {
		printf("arg dst mem malloc failed!\n");
		ret = -1;
		goto out;
	}

	arg.iv = malloc(IV_SIZE);
	if (!arg.iv) {
		printf("arg iv mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	if (tv->iv)
		memcpy(arg.iv, tv->iv, strlen(tv->iv));
	
	handle = wd_alg_cipher_alloc_sess(&setup, NULL);
	if (!handle) {
		printf("wd alloc sess failed!\n");
		ret = -1;
		goto out;
	}
	
	/* set key */
	ret = wd_alg_set_key(handle, tv->key, tv->klen);
	if (ret) {
		printf("alg set key failed!\n");
		goto out;
	}
	while (cnt) {
		ret = wd_alg_encrypt(handle, &arg);
		cnt--;
		if (ret) {
			printf("fail to encrypt:%d\n", ret);
			goto out;
		}
	}
	
out:
	if (handle)
		wd_alg_cipher_free_sess(handle);

	if (arg.src)
		free(arg.src);
	if (arg.dst)
		free(arg.dst);
	if (arg.iv)
		free(arg.iv);
	if (arg.key)
		free(arg.key);

	return ret;

}

int main(int argc, char *argv[])
{
	printf("this is a hisi sec test.\n");
	int flag = 0;
	int ret;

	ret = test_sec(flag);

	if (!ret) {
		printf("test sec is successfull!\n");
	} else {
		printf("test sec is successfull!\n");
	}

	return 0;
}
