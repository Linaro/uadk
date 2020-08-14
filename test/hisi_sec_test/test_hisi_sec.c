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
#define HISI_DEV_NODE "/dev/hisi_sec-0"

#define SCHED_SINGLE "sched_single"
#define SCHED_NULL_CTX_SIZE	4

static struct wd_ctx_config g_ctx_cfg;
static struct wd_sched g_sched;

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

static handle_t sched_single_pick_next_ctx(struct wd_ctx_config *cfg,
		void *sched_ctx, struct wd_cipher_req *req, int numa_id)
{
	return g_ctx_cfg.ctxs[0].ctx;
}

static __u32 sched_single_poll_policy(struct wd_ctx_config *cfg)
{
	return 0;
}

static int init_sigle_ctx_config(int type, int mode, struct wd_sched *sched)
{
	int ret;

	memset(&g_ctx_cfg, 0, sizeof(struct wd_ctx_config));
	g_ctx_cfg.ctx_num = 1;
	g_ctx_cfg.ctxs = calloc(1, sizeof(struct wd_ctx));
	if (g_ctx_cfg.ctxs)
		return -ENOMEM;
	/* request ctx */
	g_ctx_cfg.ctxs[0].ctx = wd_request_ctx(HISI_DEV_NODE);
	if (!g_ctx_cfg.ctxs[0].ctx) {
		ret = -EINVAL;
		goto out;
	}
	g_ctx_cfg.ctxs[0].op_type = type;
	g_ctx_cfg.ctxs[0].ctx_mode = mode;

	sched->name = SCHED_SINGLE;
	sched->sched_ctx_size = SCHED_NULL_CTX_SIZE;
	sched->pick_next_ctx = sched_single_pick_next_ctx;
	sched->poll_policy = sched_single_poll_policy;
	/*cipher init*/
	wd_cipher_init(&g_ctx_cfg, sched);

	return 0;
out:
	free(g_ctx_cfg.ctxs);

	return ret;
}

static int test_sec_cipher_sync_once(void)
{
	struct cipher_testvec *tv = &aes_ecb_tv_template_128[0];
	handle_t	h_sess;
	struct wd_cipher_req req;
	char algs[64];
	int cnt = 10;
	int ret;

	/* config setup */
	sprintf(algs, "cipher");
	init_sigle_ctx_config(CTX_TYPE_ENCRYPT, CTX_MODE_SYNC, &g_sched);
	/* config arg */
	memset(&req, 0, sizeof(struct wd_cipher_req));
	req.alg = WD_CIPHER_AES;
	req.mode = WD_CIPHER_ECB;
	req.op_type = WD_CIPHER_ENCRYPTION;

	req.src  = malloc(BUFF_SIZE);
	if (!req.src) {
		printf("req src mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	memcpy(req.src, tv->ptext, tv->len);
	req.in_bytes = tv->len;
	hexdump(req.src, tv->len);
	req.dst = malloc(BUFF_SIZE);
	if (!req.dst) {
		printf("req dst mem malloc failed!\n");
		ret = -1;
		goto out;
	}

	req.iv = malloc(IV_SIZE);
	if (!req.iv) {
		printf("req iv mem malloc failed!\n");
		ret = -1;
		goto out;
	}
	if (tv->iv)
		memcpy(req.iv, tv->iv, strlen(tv->iv));
	h_sess = (handle_t)calloc(1, sizeof(struct wd_cipher_sess));
	if (!h_sess) {
		ret = -1;
		goto out;
	}
	
	/* set key */
	ret = wd_cipher_set_key(&req, (const __u8*)tv->key, tv->klen);
	if (ret) {
		printf("req set key failed!\n");
		goto out;
	}
	while (cnt) {
		ret = wd_do_cipher(h_sess, &req);
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
	int ret;

	ret = test_sec_cipher_sync_once();

	if (!ret) {
		printf("test sec is successfull!\n");
	} else {
		printf("test sec is successfull!\n");
	}

	return 0;
}
