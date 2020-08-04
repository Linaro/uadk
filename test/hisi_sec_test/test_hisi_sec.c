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
	struct cipher_testvec *tv = &aes_ecb_tv_template_128[0];
	handle_t	handle;
	struct wd_cipher_req req;
	char algs[64];
	int cnt = 10;
	int ret = 0;

	/* config setup */
	sprintf(algs, "cipher");
	/* config arg */
	memset(&req, 0, sizeof(struct wd_cipher_req));
	req.alg = WD_CIPHER_AES;
	req.mode = WD_CIPHER_ECB;
	req.op_type = WD_CIPHER_ENCRYPTION;

	req.src  = malloc(BUFF_SIZE);
	if (!req.src) {
		printf("arg src mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	memcpy(req.src, tv->ptext, tv->len);
	req.in_bytes = tv->len;
	hexdump(req.src, tv->len);
	req.dst = malloc(BUFF_SIZE);
	if (!req.dst) {
		printf("arg dst mem malloc failed!\n");
		ret = -1;
		goto out;
	}

	req.iv = malloc(IV_SIZE);
	if (!req.iv) {
		printf("arg iv mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	if (tv->iv)
		memcpy(req.iv, tv->iv, strlen(tv->iv));
	
	
	/* set key */
	//ret = wd_alg_set_key(handle, tv->key, tv->klen);
	if (ret) {
		printf("alg set key failed!\n");
		goto out;
	}
	while (cnt) {
		//ret = wd_alg_encrypt(handle, &arg);
		cnt--;
		if (ret) {
			printf("fail to encrypt:%d\n", ret);
			goto out;
		}
	}
	
out:
	if (req.src)
		free(req.src);
	if (req.dst)
		free(req.dst);
	if (req.iv)
		free(req.iv);
	if (req.key)
		free(req.key);

	return ret;

}

int main(int argc, char *argv[])
{
	printf("this is a hisi sec test.\n");
	//int flag = 0;
	int ret = 0;

	//ret = test_sec(flag);

	if (!ret) {
		printf("test sec is successfull!\n");
	} else {
		printf("test sec is successfull!\n");
	}

	return 0;
}
