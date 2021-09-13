/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#define __USE_GNU
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <semaphore.h>
#include <stdlib.h>

#include "../../wd.h"
#include "../../drv/hisi_qm_udrv.h"
#include "../../wd_bmm.h"
#include "../../wd_rsa.h"
#include "../../wd_dh.h"
#include "test_hisi_hpre.h"


#define BLK_NUM_TIMES(x,y)  ((y) * 100 / (x))
#define BLK_NUM_VALUE 87

struct thread_info
{
	struct wd_queue q;
	pthread_t thread_id;
	time_t p_time;
};


/***
函数功能：
      dh 业务
***/

#define BN_ULONG unsigned long
#define DH_GENERATOR_2 2
#define DH_GENERATOR_5 5
#define HPRE_TST_PRT printf

struct big_number {
	BN_ULONG *n;
	int latest;
	int size_d;
	int flag_neg;
	int flags;
};

/* stub structures */
struct rsa_st {
        int xxx;
};

struct dh_st {
        int xxx;
};

struct bn_gencb_st {
        int xxx;
};
typedef struct dh_st DH;
typedef struct big_number BIGNUM;
typedef struct bn_gencb_st BN_GENCB;
/*
struct hpre_queue_mempool {
        struct wd_queue *q;
        void *base;
        unsigned int *bitmap;
        unsigned int block_size;
        unsigned int block_num;
        unsigned int mem_size;
        unsigned int block_align_size;
        unsigned int free_num;
        unsigned int fail_times;
        unsigned long long index;
        sem_t   sem;
        int dev;
};
*/
static int key_bits = 2048;
static int openssl_check;

char* s2b(char* s) {
        int i;
        for(i = 0; i < 128; i++) {
		printf("%x ", s[i]);
        }
        printf("\n");
}

char* s2c(char* a, char* b) {
        int i;
        for(i = 0; i < 128; i++) {
        printf("%d %x %x\n", i, a[i], b[i]);
        if(a[i] != b[i])
        printf("error: No. %d failed\n", i);
        }
        printf("\n");
}
static int hpre_bn_format(void *buff, int len, int buf_len)
{
        int i = buf_len - 1;
        int j = 0;
        unsigned char *buf = buff;

        if (!buf || len <= 0) {
                HPRE_TST_PRT("%s params err!\n", __func__);
                return -1;
        }
        if (len == buf_len)
                return 0;

        if (len < buf_len)
                return  -1;

        for (j = len - 1; j >= 0; j--, i--) {
                if (i >= 0)
                        buf[j] = buf[i];
                else
                        buf[j] = 0;
        }
        return 0;
}

static int test_hpre_bin_to_crypto_bin(char *dst, char *src, int para_size)
{
        int i = 0, j = 0, cnt = 0;

        if (!dst || !src || para_size <= 0) {
                HPRE_TST_PRT("%s params err!\n", __func__);
                return -WD_EINVAL;
        }
        while (!src[j])
                j++;
        if (j == 0 && src == dst)
                return WD_SUCCESS;
        for (i = 0, cnt = j; i < para_size; j++, i++) {
                if (i < para_size - cnt)
                        dst[i] = src[j];
                else
                        dst[i] = 0;
        }

        return WD_SUCCESS;
}

int hpre_dh_test(void *c, struct hpre_queue_mempool *pool)
{
        DH *a = NULL, *b = NULL;
        int ret, generator = DH_GENERATOR_5;
        struct wcrypto_dh_op_data opdata_a;
        struct wcrypto_dh_op_data opdata_b;
        const BIGNUM *ap = NULL, *ag = NULL,
                        *apub_key = NULL, *apriv_key = NULL;
        const BIGNUM *bp = NULL, *bg = NULL,
                        *bpub_key = NULL, *bpriv_key = NULL;
        unsigned char *ap_bin = NULL, *ag_bin = NULL,
                        *apub_key_bin = NULL, *apriv_key_bin = NULL;
        unsigned char *bp_bin = NULL, *bg_bin = NULL,
                        *bpub_key_bin = NULL, *bpriv_key_bin = NULL;
        unsigned char *abuf = NULL;
        unsigned char *bbuf = NULL;
        struct wd_dtb g;
        __u32 gbytes;
        void *tag = NULL;
        int key_size, key_bits, i;

        if (!pool) {
                HPRE_TST_PRT("pool null!\n");
                return -1;
        }

        a = DH_new();
        b = DH_new();
        if (!a || !b) {
                HPRE_TST_PRT("New DH fail!\n");
                return -1;
        }
        if (wcrypto_dh_is_g2(c))
                generator = DH_GENERATOR_2;

        key_bits = wcrypto_dh_key_bits(c);
        key_size = key_bits >> 3;

        /* Alice generates DH parameters */
        ret = DH_generate_parameters_ex(a, key_bits, generator, NULL);
        if (!ret) {
                HPRE_TST_PRT("DH_generate_parameters_ex fail!\n");
                goto dh_err;
        }
        DH_get0_pqg(a, &ap, NULL, &ag);
        bp = BN_dup(ap);
        bg = BN_dup(ag);
        if (!bp || !bg) {
                HPRE_TST_PRT("bn dump fail!\n");
                ret = -1;
                goto dh_err;
        }
        /* Set the same parameters on Bob as Alice :) */
        DH_set0_pqg(b, (BIGNUM *)bp, NULL, (BIGNUM *)bg);
        if (!DH_generate_key(a)) {
                HPRE_TST_PRT("a DH_generate_key fail!\n");
                ret = -1;
                goto dh_err;
        }
        DH_get0_key(a, &apub_key, &apriv_key);
        ag_bin = wd_alloc_blk(pool);
        if (!ag_bin) {
                HPRE_TST_PRT("pool alloc ag_bin fail!\n");
                goto dh_err;
        }
        memset(ag_bin, 0, key_size * 2);
        apriv_key_bin = wd_alloc_blk(pool);
        if (!apriv_key_bin) {
                HPRE_TST_PRT("pool alloc apriv_key_bin fail!\n");
                goto dh_err;
        }
        memset(apriv_key_bin, 0, key_size * 2);

        /* The hpre_UM tells us key_addr contains xa and p,
         * their addr should be together
         */
        ap_bin= apriv_key_bin + key_size;

        gbytes = BN_bn2bin(ag, ag_bin);
        g.data = (char*)ag_bin;
        g.dsize = key_size;
        g.bsize = gbytes;
        opdata_a.pbytes = BN_bn2bin(ap, ap_bin);
        opdata_a.xbytes = BN_bn2bin(apriv_key, apriv_key_bin);
        ret = wcrypto_set_dh_g(c, &g);
        if (ret) {
                HPRE_TST_PRT("Alice wcrypto_set_dh_g fail!\n");
                goto dh_err;
        }
        opdata_a.x_p = apriv_key_bin;
        opdata_a.pri = wd_alloc_blk(pool);
        if (!opdata_a.pri) {
                HPRE_TST_PRT("pool alloc opdata_a.pri fail!\n");
                goto dh_err;
        }
        memset(opdata_a.pri, 0, key_size * 2);

        opdata_a.op_type = WCRYPTO_DH_PHASE1;

        /* Alice computes public key */
        ret = wcrypto_do_dh(c, &opdata_a, tag);
        if (ret) {
                HPRE_TST_PRT("a wcrypto_do_dh fail!\n");
                goto dh_err;
        }
        printf("a p1 =>\n");
        s2b(opdata_a.pri);

        if (openssl_check) {
                apub_key_bin = malloc(key_size);
                if (!apub_key_bin) {
                        HPRE_TST_PRT("malloc apub_key_bin fail!\n");
                        ret = -ENOMEM;
                        goto dh_err;
                }
                ret = BN_bn2bin(apub_key, apub_key_bin);
                if (!ret) {
                        HPRE_TST_PRT("apub_key bn 2 bin fail!\n");
                        goto dh_err;
                }
                ret = hpre_bn_format(apub_key_bin, key_size, key_size);
                if (ret) {
                        HPRE_TST_PRT("hpre_bn_format bpub_key bin fail!\n");
                        goto dh_err;
                }

                for (i = key_size - 1; apub_key_bin[i] == 0 && i >= 0; i--) {
                        ret = test_hpre_bin_to_crypto_bin(opdata_a.pri, opdata_a.pri, key_size);
                        if (ret) {
                                HPRE_TST_PRT("dh out share key format fail!\n");
                                goto dh_err;
                        }
                        ret = 0;
                        break;
                }

                if (memcmp(apub_key_bin, opdata_a.pri, key_size)) {
                        HPRE_TST_PRT("Alice HPRE DH key gen pub mismatch!\n");
                        ret = -EINVAL;
                        goto dh_err;
                }
        }
        if (!DH_generate_key(b)) {
                HPRE_TST_PRT("b DH_generate_key fail!\n");
                ret = -1;
                goto dh_err;
        }
        DH_get0_key(b, &bpub_key, &bpriv_key);
        bg_bin = wd_alloc_blk(pool);
        if (!bg_bin) {
                HPRE_TST_PRT("pool alloc bg_bin fail!\n");
                ret = -1;
                goto dh_err;
        }
        memset(bg_bin, 0, key_size * 2);

        bpriv_key_bin= wd_alloc_blk(pool);
        if (!bpriv_key_bin) {
                HPRE_TST_PRT("pool alloc bpriv_key_bin fail!\n");
                ret = -1;
                goto dh_err;
        }
        memset(bpriv_key_bin, 0, key_size * 2);
        bp_bin = bpriv_key_bin + key_size;
        gbytes = BN_bn2bin(bg, bg_bin);
        g.data = (char*)bg_bin;
        g.bsize = gbytes;
        g.dsize = key_size;
         printf("key bits: %d\n", key_bits);
        printf("key size: %d\n", key_size);

        ret = wcrypto_set_dh_g(c, &g);
        if (ret) {
                HPRE_TST_PRT("bob wcrypto_set_dh_g fail!\n");
                goto dh_err;
        }
        opdata_b.pbytes = BN_bn2bin(bp, bp_bin);
        opdata_b.xbytes = BN_bn2bin(bpriv_key, bpriv_key_bin);
        opdata_b.x_p = bpriv_key_bin;
        opdata_b.pri = wd_alloc_blk(pool);
        if (!opdata_b.pri) {
                HPRE_TST_PRT("pool alloc opdata_b.pri fail!\n");
                ret = -1;
                goto dh_err;
        }
        memset(opdata_b.pri, 0, key_size * 2);
        opdata_b.op_type = WCRYPTO_DH_PHASE1;

        /* Bob computes public key */
        ret = wcrypto_do_dh(c, &opdata_b, tag);
        if (ret) {
                HPRE_TST_PRT("b wcrypto_do_dh fail!\n");
                goto dh_err;
        }
        printf("b p1 =>\n");
        s2b(opdata_b.pri);
        if (openssl_check) {
                bpub_key_bin = malloc(key_size);
                if (!bpub_key_bin) {
                        HPRE_TST_PRT("malloc bpub_key_bin fail!\n");
                        ret = -1;
                        goto dh_err;
                }
                ret = BN_bn2bin(bpub_key, bpub_key_bin);
                if (!ret) {
                        HPRE_TST_PRT("bpub_key bn 2 bin fail!\n");
                        goto dh_err;
                }
                ret = hpre_bn_format(bpub_key_bin, key_size, key_size);
                if (ret) {
                        HPRE_TST_PRT("hpre_bn_format bpub_key bin fail!\n");
                        goto dh_err;
                }

                for (i = key_size - 1; bpub_key_bin[i] == 0 && i >= 0; i--) {
                        ret = test_hpre_bin_to_crypto_bin(opdata_b.pri, opdata_b.pri, key_size);
                        if (ret) {
                                HPRE_TST_PRT("dh out share key format fail!\n");
                                goto dh_err;
                        }
                        ret = 0;
                        break;
                }

                if (memcmp(bpub_key_bin, opdata_b.pri, key_size)) {
                        HPRE_TST_PRT("Bob HPRE DH key gen pub mismatch!\n");
                        ret = -EINVAL;
                        goto dh_err;
                }
        }
        /* Alice computes private key with OpenSSL */
        abuf = malloc(key_size);
        if (!abuf) {
                HPRE_TST_PRT("malloc abuf fail!\n");
                ret = -ENOMEM;
                goto dh_err;
        }
        memset(abuf, 0, key_size);
        if (openssl_check) {
                ret = DH_compute_key(abuf, bpub_key, a);
                if (!ret) {
                        HPRE_TST_PRT("DH_compute_key fail!\n");
                        ret = -1;
                        goto dh_err;
                }
        }

        /* Alice computes private key with HW accelerator */
        memset(ag_bin, 0, key_size * 2);
        memset(apriv_key_bin, 0, key_size * 2);
        ap_bin = apriv_key_bin + key_size;
        memset(opdata_a.pri, 0, key_size * 2);

        opdata_a.pvbytes = BN_bn2bin(bpub_key, ag_bin);
        opdata_a.pv = ag_bin;/* bob's public key here */
        opdata_a.pbytes = BN_bn2bin(ap, ap_bin);
        opdata_a.xbytes = BN_bn2bin(apriv_key, apriv_key_bin);
        opdata_a.x_p = apriv_key_bin;
        opdata_a.pri = wd_alloc_blk(pool);
        if (!opdata_a.pri) {
                HPRE_TST_PRT("pool alloc opdata_a.pri fail!\n");
                ret = -1;
                goto dh_err;
        }
        memset(opdata_a.pri, 0, key_size * 2);
        opdata_a.op_type = WCRYPTO_DH_PHASE2;

        /* Alice computes private key with HPRE */
        ret = wcrypto_do_dh(c, &opdata_a, tag);
        if (ret) {
                HPRE_TST_PRT("a wcrypto_do_dh fail!\n");
                goto dh_err;
        }
        //printf("a p2 =>\n");
        //s2b(opdata_a.pri);
        if (openssl_check) {
                ret = hpre_bn_format(abuf, key_size, key_size);
                if (ret) {
                        HPRE_TST_PRT("hpre_bn_format bpub_key bin fail!\n");
                        goto dh_err;
                }

                for (i = key_size - 1; abuf[i] == 0 && i >= 0; i--) {
                        ret = test_hpre_bin_to_crypto_bin(opdata_a.pri, opdata_a.pri, key_size);
                        if (ret) {
                                HPRE_TST_PRT("dh out share key format fail!\n");
                                goto dh_err;
                        }
                        ret = 0;
                        break;
                }

                if (memcmp(abuf, opdata_a.pri, key_size)) {
                        HPRE_TST_PRT("Alice HPRE DH gen privkey mismatch!\n");
                        ret = -EINVAL;
                        goto dh_err;
                }
        }
        /* Bob computes private key with OpenSSL */
        bbuf = malloc(key_size);
        if (!bbuf) {
                HPRE_TST_PRT("malloc abuf fail!\n");
                ret = -ENOMEM;
                goto dh_err;
        }
        memset(abuf, 0, key_size);
        if (openssl_check) {
                ret = DH_compute_key(bbuf, apub_key, b);
                if (!ret) {
                        HPRE_TST_PRT("DH_compute_key fail!\n");
                        ret = -1;
                        goto dh_err;
                }
        }

        /* Bob computes private key with HW accelerator */
        memset(bg_bin, 0, key_size * 2);
        memset(bpriv_key_bin, 0, key_size * 2);
        bp_bin = bpriv_key_bin + key_size;
        memset(opdata_b.pri, 0, key_size * 2);

        opdata_b.pvbytes = BN_bn2bin(apub_key, bg_bin);
        opdata_b.pv = bg_bin;/* bob's public key here */
        opdata_b.pbytes = BN_bn2bin(bp, bp_bin);
        opdata_b.xbytes = BN_bn2bin(bpriv_key, bpriv_key_bin);
        opdata_b.x_p = bpriv_key_bin;
        opdata_b.pri = wd_alloc_blk(pool);
        if (!opdata_b.pri) {
                HPRE_TST_PRT("pool alloc opdata_a.pri fail!\n");
                ret = -1;
                goto dh_err;
        }
        memset(opdata_b.pri, 0, key_size * 2);
        opdata_b.op_type = WCRYPTO_DH_PHASE2;

        /* Bob computes private key with HPRE */
        ret = wcrypto_do_dh(c, &opdata_b, tag);
        if (ret) {
                HPRE_TST_PRT("b wcrypto_do_dh fail!\n");
                goto dh_err;
        }
        //printf("b p2 =>\n");
        s2c(opdata_a.pri, opdata_b.pri);
        HPRE_TST_PRT("HPRE DH generate key sucessfully!\n");
        dh_err:
        DH_free(a);
        DH_free(b);
        if (ag_bin)
                wd_free_blk(pool, ag_bin);
        if (apriv_key_bin)
                wd_free_blk(pool, apriv_key_bin);
        if (opdata_a.pri)
                wd_free_blk(pool, opdata_a.pri);

        if (bg_bin)
                wd_free_blk(pool, bg_bin);
        if (bpriv_key_bin)
                wd_free_blk(pool, bpriv_key_bin);
        if (opdata_b.pri)
                wd_free_blk(pool, opdata_b.pri);

        if (apub_key_bin)
                free(apub_key_bin);
        if (bpub_key_bin)
                free(bpub_key_bin);
        if (abuf)
                free(abuf);
        return ret;
}
int do_dh(struct wd_queue *q)
{
	int ret;
		printf("\tinfo: init dh setup\n");
        struct wcrypto_dh_ctx_setup dh_setup;
        memset(&dh_setup, 0, sizeof(dh_setup));
        printf("\tinfo: assign dh setup\n");
        dh_setup.key_bits = 1024;
        dh_setup.br.alloc = (void *)wd_alloc_blk;
        dh_setup.br.free = (void *)wd_free_blk;
        dh_setup.br.iova_map = (void *)wd_blk_iova_map;
        dh_setup.br.iova_unmap = (void *)wd_blk_iova_unmap;

        printf("info: init pool\n");
        void *pool = NULL;
        printf("\tinfo: assign pool\n");
        printf("\tinfo: init wsetup\n");
        struct wd_blkpool_setup wsetup;
        memset(&wsetup, 0, sizeof(wsetup));
        printf("\tinfo: assign wsetup\n");
        wsetup.block_size = 2048 >> 2;
        wsetup.block_num = 1024;
        wsetup.align_size = 64;
        pool = wd_blkpool_create(q, &wsetup);
        unsigned int num = 0;
        sleep(1);
        if (wd_get_free_blk_num(pool, &num) == WD_SUCCESS)
                printf("pool num = %u\n", num);
        sleep(1);
        if (wd_blk_alloc_failures(pool, &num) == WD_SUCCESS)
                printf("pool fail num = %u\n", num);
        dh_setup.br.usr = pool;

        printf("info: create dh ctx\n");
        void *ctx = NULL;
        ctx = wcrypto_create_dh_ctx(q, &dh_setup);

 ret = hpre_dh_test(ctx, pool);

        printf("info: delete dh ctx\n");
        wcrypto_del_dh_ctx(ctx);

        printf("info: uninit pool\n");
        wd_blkpool_destroy(pool);

	return ret;
}


/***
函数功能：
      在指定设备上申请单个队列，并给队列预留指定大小的内存；
参数说明：
       dev         - 指定申请队列的设备
       alg_type  - 申请队列的算法类型
       m_size    - 队列预留内存大小
***/
int hpre_dev_queue_req(char *dev, char *alg_type, unsigned long m_size)
{
	void *addr;
	int ret = 0;
	struct wd_queue q;
	unsigned long memory_size;

	memset((void *)&q, 0, sizeof(q));
	q.capa.alg = alg_type;
	snprintf(q.dev_path, sizeof(q.dev_path), "%s", dev);
	printf("queue path:%s\n", q.dev_path);
	//申请队列
	ret = wd_request_queue(&q);
	if(ret)
	{
		printf("wd request queue fail!\n");
		return ret;
	}
	printf("wd request queue success,return:%d\n",ret);
	memory_size = m_size;
	//给队列预留内存
	addr = wd_reserve_memory(&q, memory_size);
	if(!addr)
	{
		wd_release_queue(&q);
		printf("wd reserve memory fail!\n");
		return 1;
	}
	printf("wd reserve memory success!\n");
	memset(addr, 0, memory_size);
	//释放队列，会释放所有资源，包括预留内存；
	wd_release_queue(&q);
	return 0;
}

/***

***/
int application_release_multiple_queue(char *dev, char *alg_type, unsigned int q_num)
{
	int i, ret = 0;
	struct wd_queue *q;

	q = malloc(q_num * sizeof(struct wd_queue));
        if (!q)
                return 1;
        memset((void *)q, 0, q_num * sizeof(struct wd_queue));

	for (i = 0; i < q_num; i++) {
		q[i].capa.alg = alg_type;
		snprintf(q[i].dev_path, sizeof(q[i].dev_path), "%s", dev);
		ret = wd_request_queue(&q[i]);
		if (ret) {
			printf("error: fail q => %d\n", i);
			return ret;
		}
		wd_get_node_id(&q[i]);
	}

	for (i = 0; i < q_num; i++) {
                wd_release_queue(&q[i]);
	}

	printf("application_release_multiple_queue test end!\n");
	return 0;
}

/***

***/
int hpre_dev_queue_share(char *dev, char * share_dev, char *alg_type, unsigned long m_size)
{
	void *addr=NULL;
	int ret = 0;
	struct wd_queue q;
	struct wd_queue target_q;
	unsigned long memory_size;

	memset((void *)&q, 0, sizeof(q));
	q.capa.alg = alg_type;
	snprintf(q.dev_path, sizeof(q.dev_path), "%s", dev);
	printf("queue path:%s\n", q.dev_path);

	ret = wd_request_queue(&q);
	if(ret)
	{
		printf("wd request queue fail!\n");
		return 1;
	}
	printf("wd request queue success!\n");
	memory_size = m_size;
	addr = wd_reserve_memory(&q, memory_size);
	if(!addr)
	{
		wd_release_queue(&q);
		printf("wd reserve memory fail!\n");
		return 1;
	}
	printf("wd reserve memory success!\n");
	memset(addr, 0, memory_size);

	memset((void *)&target_q, 0, sizeof(target_q));
	target_q.capa.alg = alg_type;
	snprintf(target_q.dev_path, sizeof(target_q.dev_path), "%s", share_dev);
	printf("target queue path:%s\n", target_q.dev_path);

	ret = wd_request_queue(&target_q);
	if(ret)
	{
		wd_release_queue(&q);
		printf("wd request target_q queue fail!\n");
		return 1;
	}
	printf("wd request target_q queue success!\n");
	//target_q队列共享q队列预留内存；
	ret = wd_share_reserved_memory(&q, &target_q);
	if(ret)
	{
		wd_release_queue(&q);
		wd_release_queue(&target_q);
		printf("wd target_q queue share reserved memory fail!\n");
		return 1;
	}
	printf("wd target_q queue share reserved memory success!\n");
	wd_release_queue(&target_q);
	wd_release_queue(&q);

	return 0;
}
/***

***/
int hpre_node_queue_share(char *dev, unsigned int node, unsigned int share_node, char *alg_type, unsigned long m_size)
{
	void *addr=NULL;
	int ret = 0;
	struct wd_queue q;
	struct wd_queue target_q;
	unsigned long memory_size;

	memset((void *)&q, 0, sizeof(q));
	q.capa.alg = alg_type;
	snprintf(q.dev_path, sizeof(q.dev_path), "%s", dev);
	printf("queue path:%s\n", q.dev_path);
	q.node_mask = node;

	ret = wd_request_queue(&q);
	if(ret)
	{
		printf("wd request queue fail!\n");
		return 1;
	}
	printf("wd request queue success!\n");
	memory_size = m_size;
	addr = wd_reserve_memory(&q, memory_size);
	if(!addr)
	{
		wd_release_queue(&q);
		printf("wd reserve memory fail!\n");
		return 1;
	}
	printf("wd reserve memory success!\n");
	memset(addr, 0, memory_size);

	memset((void *)&target_q, 0, sizeof(target_q));
	target_q.capa.alg = alg_type;
	target_q.node_mask = node;

	ret = wd_request_queue(&target_q);
	if(ret)
	{
		wd_release_queue(&q);
		printf("wd request target_q queue fail!\n");
		return 1;
	}
	printf("wd request target_q queue success!\n");
	//target_q队列共享q队列预留内存；
	ret = do_dh(&q);
	if(ret)
	{
		printf("do dh on q fail!\n");
		return 1;
	}
	ret = do_dh(&target_q);
	if(ret)
	{
		printf("do dh on target q fail!\n");
		return 1;
	}

	ret = wd_share_reserved_memory(&q, &target_q);

	if(ret)
	{
		wd_release_queue(&q);
		wd_release_queue(&target_q);
		printf("wd target_q queue share reserved memory fail!\n");
		return 1;
	}
	printf("wd target_q queue share reserved memory success!\n");
        ret = do_dh(&q);
	if(ret)
	{
		printf("do dh on share q fail!\n");
		return 1;
	}
	ret = do_dh(&target_q);
	if(ret)
	{
		printf("do dh on share target q fail!\n");
		return 1;
	}

	wd_release_queue(&target_q);
	wd_release_queue(&q);

	return 0;
}
/***

***/
int hpre_dev_queue_interact_share(char *dev, char * share_dev, char *alg_type, unsigned long m_size)
{
	void *addr=NULL;
	int ret = 0;
	struct wd_queue q;
	struct wd_queue target_q;
	unsigned long memory_size;

	memset((void *)&q, 0, sizeof(q));
	q.capa.alg = alg_type;
	snprintf(q.dev_path, sizeof(q.dev_path), "%s", dev);
	printf("queue path:%s\n", q.dev_path);

	ret = wd_request_queue(&q);
	if(ret)
	{
		printf("wd request queue fail!\n");
		return ret;
	}
	printf("wd request queue success!\n");
	memory_size = m_size;
	addr = wd_reserve_memory(&q, memory_size);
	if(!addr)
	{
		wd_release_queue(&q);
		printf("wd reserve memory fail!\n");
		return 1;
	}
	printf("wd reserve memory success!\n");
	memset(addr, 0, memory_size);

	memset((void *)&target_q, 0, sizeof(target_q));
	target_q.capa.alg = alg_type;
	snprintf(target_q.dev_path, sizeof(target_q.dev_path), "%s", share_dev);
	printf("target queue path:%s\n", target_q.dev_path);

	ret = wd_request_queue(&target_q);
	if(ret)
	{
		wd_release_queue(&q);
		printf("wd request target_q queue fail!\n");
		return 1;
	}
	printf("wd request target_q queue success!\n");
	addr = wd_reserve_memory(&target_q, memory_size);
	if(!addr)
	{
		wd_release_queue(&q);
		wd_release_queue(&target_q);
		printf("wd reserve memory fail!\n");
		return 1;
	}
	printf("wd reserve memory success!\n");
	memset(addr, 0, memory_size);

	//target_q
	ret = wd_share_reserved_memory(&q, &target_q);
	if(ret)
	{
		wd_release_queue(&q);
		wd_release_queue(&target_q);
		printf("wd target_q queue share reserved memory fail!\n");
		return 1;
	}
	printf("wd target_q queue share reserved memory success!\n");

	wd_release_queue(&target_q);
	wd_release_queue(&q);

	return 0;
}

/***

***/
int hpre_dev_queue_cross_proc_share(char *dev, char *alg_type, unsigned long m_size)
{
	void *addr=NULL;
	int ret = 0;
	pid_t pid;
	struct wd_queue q;
	struct wd_queue target_q;
	unsigned long memory_size=0;

	pid = fork();
	if(pid < 0)
	{
		printf("Creation process failed, pid:%d\n",pid);
		return 1;
	}
	else if(pid == 0)
	{
		printf("child process:%d\n", pid);
		memset((void *)&q, 0, sizeof(q));
		q.capa.alg = alg_type;
		snprintf(q.dev_path, sizeof(q.dev_path), "%s", dev);
		printf("queue path:%s\n", q.dev_path);

		ret = wd_request_queue(&q);
		if(ret)
		{
			printf("request queue fail!\n");
			exit(1);
		}
		printf("wd request queue success!\n");
		memory_size = m_size;
		addr = wd_reserve_memory(&q, memory_size);
		if(!addr)
		{
			wd_release_queue(&q);
			printf("queue reserve memory fail!\n");
			exit(2);
		}
		printf("queue reserve memory success!\n");
		memset(addr, 0, memory_size);
		exit(0);
	}
	printf("parent process:%d\n", pid);
	pid_t wpid;
	int status = -1;
	wpid = waitpid(pid, &status, WUNTRACED | WCONTINUED);
	if( wpid < 0)
	{
		printf("exited, status=%d\n", WEXITSTATUS(status));
		return(status);
	}

	memset((void *)&target_q, 0, sizeof(target_q));
	target_q.capa.alg = alg_type;
	snprintf(target_q.dev_path, sizeof(target_q.dev_path), "%s", dev);
	printf("target queue path:%s\n", target_q.dev_path);

	ret = wd_request_queue(&target_q);
	if(ret)
	{
		wd_release_queue(&q);
		printf("wd request target_q queue fail!\n");
		return 1;
	}
	printf("wd request target_q queue success!\n");
	ret = wd_share_reserved_memory(&q, &target_q);
	if(ret)
	{
		wd_release_queue(&target_q);
		wd_release_queue(&q);
		printf("wd target_q queue share reserved memory fail!\n");
		return 1;
	}
	printf("wd target_q queue share reserved memory success!\n");

	wd_release_queue(&target_q);
	wd_release_queue(&q);

	return 0;
}

/***

***/
void *create_queue(void *arg)
{
	int ret = 0;
	struct thread_info *tinfo = arg;
	ret = wd_request_queue(&tinfo ->q);
	if(ret)
	{
		printf("wd request queue fail!\n");
		return NULL;
	}
	printf("wd request queue success\n");

	sleep(tinfo ->p_time);
	return NULL;
}
/***

***/
int hpre_mult_thread_request_queue(char *dev, char *alg_type, int p_num, time_t p_time)
{
	int i = 0;
	void *ret = NULL;
	struct thread_info *tinfo;

	printf("pthread_num:%d, times:%ld\n", p_num, p_time);
	tinfo = calloc(p_num, sizeof(struct thread_info));
	if(NULL == tinfo)
	{
		printf("calloc fail...\n");
		return 1;
	}

	for(i = 0; i<p_num; i++)
	{
		tinfo[i].p_time=p_time;
		memset((void*)&tinfo[i].q, 0, sizeof(struct wd_queue));
		tinfo[i].q.capa.alg = alg_type;
		snprintf(tinfo[i].q.dev_path,sizeof(tinfo[i].q.dev_path),"%s",dev);
		printf("queue path:%s\n",tinfo[i].q.dev_path);

		if((pthread_create(&tinfo[i].thread_id,NULL,create_queue, (void *)&tinfo[i])) != 0)
		{
			free(tinfo);
			printf("create pthread fail.....\n");
			return 1;
		}
	}
	for(i = 0; i < p_num; i++)
	{
		if(pthread_join(tinfo[i].thread_id, &ret) != 0)
		{
			free(tinfo);
			printf("thread_id:%ld thread is not exit....\n", tinfo[i].thread_id);
			return 1;
		}
		printf("thread_id:%ld thread exit coid %d\n", tinfo[i].thread_id, *(int *)ret);
		wd_release_queue(&tinfo[i].q);
		free(ret);
	}

	free(tinfo);
	sleep(p_time);

	return 0;
}

int hpre_blkpool_operating(char *dev, unsigned int blk_sz, unsigned int blk_num, unsigned int align_sz)
{
        int ret = 0;
	 void *tmap = NULL;
        void *blk[65536];
        unsigned int i, blk_count = 0, end_count = 0, blk_fail_count = 0;
        struct wd_queue q;
        struct wd_blkpool_setup wsetup;
        struct wd_blkpool *pool;

        memset((void *)&q, 0, sizeof(q));
        q.capa.alg = "rsa";
        snprintf(q.dev_path, sizeof(q.dev_path), "%s", dev);
        printf("queue path:%s\n", q.dev_path);

        ret = wd_request_queue(&q);
        if(ret)
        {
                printf("wd request queue fail!\n");
                return ret;
        }
        printf("wd request queue success!\n");

        memset(&wsetup, 0, sizeof(wsetup));
        wsetup.block_size = blk_sz; //key_size;
        wsetup.block_num = blk_num;
        wsetup.align_size = align_sz;

        pool = wd_blkpool_create(&q, &wsetup);
        if (!pool)
        {
                printf("create ctx pool fail!\n");
                wd_release_queue(&q);
                return 1;
        }
        printf("create ctx pool success!\n");

        if (wd_get_free_blk_num(pool, &blk_count)  != WD_SUCCESS) {
                printf("wd_get_free_blk_num fail, blk count:%u\n", blk_count);
                ret = -WD_EINVAL;
                goto release_q;
        }
	 if (BLK_NUM_TIMES(blk_num, blk_count) < BLK_NUM_VALUE) {
	         printf("%u is 87% ;pwer than %u\n", blk_count, blk_num);
                ret = -WD_EINVAL;
                goto release_q;
        }

        for(i = 0; i < blk_count; i++)
        {
                blk[i] = wd_alloc_blk(pool);
                if(!blk[i])
                {
                        if (wd_blk_alloc_failures(pool, &blk_fail_count) != WD_SUCCESS) {
		                  printf("wd_blk_alloc_failures fail, blk_fail_count:%u\n", blk_fail_count);
                	   }
                        printf("create blk fail,blk_fail_count:%u\n", blk_fail_count);
                        ret = -WD_EINVAL;
                        goto release_q;
                }

                tmap = wd_blk_iova_map(pool, blk[i]);
		  if (!tmap) {
		  	  printf("wd_blk_iova_map blk fail\n");
                       ret = -WD_EINVAL;
                       goto release_q;
		  }
        }
        for(i = 0; i < blk_count; i++)
        {
                wd_free_blk(pool, blk[i]);
        }
	 if (wd_get_free_blk_num(pool, &end_count) != WD_SUCCESS) {
                printf("wd_get_free_blk_num fail, blk count:%u\n", end_count);
                ret = -WD_EINVAL;
                goto release_q;
        }
        if(blk_count != end_count)
        {
                printf("All memory blocks fail to release the memory pool, blk count:%u!\n", end_count);
                ret = -WD_EINVAL;
        }
	 printf("test hpre_blkpool_operating end!\n");

release_q:
        wd_blkpool_destroy(pool);
        wd_release_queue(&q);

        return ret;
}

/***
***/
int hpre_blkpool_alloc(char *dev)
{
        int ret = 0;
	 void *tmap = NULL;
        void *blk=NULL;
	 void *again_blk=NULL;
        unsigned int blk_count = 0, end_count = 0, blk_fail_count = 0;
        struct wd_queue q;
        struct wd_blkpool_setup wsetup;
        struct wd_blkpool *pool;

        memset((void *)&q, 0, sizeof(q));
        q.capa.alg = "rsa";
        snprintf(q.dev_path, sizeof(q.dev_path), "%s", dev);
        printf("queue path:%s\n", q.dev_path);

        ret = wd_request_queue(&q);
        if(ret)
        {
                printf("wd request queue fail!\n");
                return -WD_EINVAL;
        }
        printf("wd request queue success!\n");

        memset(&wsetup, 0, sizeof(wsetup));
        wsetup.block_size = 2048; //key_size;
        wsetup.block_num = 1;
        wsetup.align_size = 64;

        pool = wd_blkpool_create(&q, &wsetup);
        if (!pool)
        {
                printf("create ctx pool fail!\n");
                wd_release_queue(&q);
                return -WD_EINVAL;
        }
        printf("create ctx pool success!\n");

	 if (wd_get_free_blk_num(pool, &blk_count) != WD_SUCCESS) {
	         printf("wd_get_free_blk_num fail, blk_count:%u\n", blk_count);
		  ret = -WD_EINVAL;
                goto release_q;
        }
        blk = wd_alloc_blk(pool);
        if(!blk)
        {
                if (wd_blk_alloc_failures(pool, &blk_fail_count) != WD_SUCCESS) {
		          printf("wd_blk_alloc_failures fail, blk_fail_count:%u\n", blk_fail_count);
                }
                printf("alloc blk fail, blk_fail_count:%du\n", blk_fail_count);
                ret = -WD_EINVAL;
                goto release_q;
        }

        tmap = wd_blk_iova_map(pool, blk);
	 if (!tmap) {
	 	  printf("wd_blk_iova_map blk fail\n");
                ret = -WD_EINVAL;
                goto release_q;
	 }

        again_blk = wd_alloc_blk(pool);
        if(again_blk)
        {
                printf("again alloc blk fail\n");
                ret = -WD_EINVAL;
                goto release_q;
        }
        if (wd_blk_alloc_failures(pool, &blk_fail_count) != WD_SUCCESS) {
	         printf("Failed to get pool allocation errorblk_fail_count:%u\n",blk_fail_count);
		  ret = -WD_EINVAL;
                goto release_q;
        }
        printf("wd_blk_alloc_failures: %u\n", blk_count);

        wd_free_blk(pool, blk);
	 if (wd_get_free_blk_num(pool, &end_count) != WD_SUCCESS) {
	         printf("wd_get_free_blk_num fail\n");
		  ret = -WD_EINVAL;
                goto release_q;
        }
	 if (end_count != blk_count) {
	 	  printf("wd_free_blk fail\n");
		  ret = -WD_EINVAL;
	 }
	 printf("test hpre_blkpool_alloc end!\n");
release_q:
        wd_blkpool_destroy(pool);
        wd_release_queue(&q);

        return ret;
}

/***
***/
int hpre_blkpool_free(char *dev)
{
        int ret = 0;
        void *blk=NULL;
	 void *tmap=NULL;
        unsigned int blk_count = 0, end_count = 0, blk_fail_count = 0;
        struct wd_queue q;
        struct wd_blkpool_setup wsetup;
        struct wd_blkpool *pool;

        memset((void *)&q, 0, sizeof(q));
        q.capa.alg = "rsa";
        snprintf(q.dev_path, sizeof(q.dev_path), "%s", dev);
        printf("queue path:%s\n", q.dev_path);

        ret = wd_request_queue(&q);
        if(ret)
        {
                printf("wd request queue fail!\n");
                return ret;
        }
        printf("wd request queue success!\n");

        memset(&wsetup, 0, sizeof(wsetup));
        wsetup.block_size = 1024; //key_size;
        wsetup.block_num = 1;
        wsetup.align_size = 2;

        pool = wd_blkpool_create(&q, &wsetup);
        if (!pool)
        {
                printf("create ctx pool fail!\n");
                wd_release_queue(&q);
                return 1;
        }
		printf("create ctx pool success!\n");
        if (wd_get_free_blk_num(pool, &blk_count) != WD_SUCCESS) {
	         printf("wd_get_free_blk_num fail, blk_count:%u\n", blk_count);
		  ret = -WD_EINVAL;
                goto release_q;
        }

        blk = wd_alloc_blk(pool);
        if(!blk)
        {
                if (wd_blk_alloc_failures(pool, &blk_fail_count) != WD_SUCCESS) {
		          printf("wd_blk_alloc_failures fail, blk_fail_count:%u\n", blk_fail_count);
                }
                printf("alloc blk fail,blk_fail_count:%d\n", blk_fail_count);
                ret = -WD_EINVAL;
                goto release_q;
        }
        tmap = wd_blk_iova_map(pool, blk);
	 if (!tmap) {
	 	  printf("wd_blk_iova_map blk fail\n");
                ret = -WD_EINVAL;
                goto release_q;
	 }
	 wd_free_blk(pool, blk);
        if (wd_get_free_blk_num(pool, &end_count) != WD_SUCCESS) {
	         printf("wd_get_free_blk_num fail, end_count:%u\n", end_count);
		  ret = -WD_EINVAL;
                goto release_q;
	 }
        if(blk_count != end_count)
        {
                printf("Failed to free memory block, blk count:%u\n", end_count);
                ret = -WD_EINVAL;
                goto release_q;
        }
	 wd_free_blk(pool, blk);
	 if (wd_get_free_blk_num(pool, &end_count) != WD_SUCCESS) {
	         printf("wd_get_free_blk_num fail, blk_count:%u\n", end_count);
		  ret = -WD_EINVAL;
                goto release_q;
	 }
	 if(blk_count != end_count)
        {
                printf("Failed to free memory block, blk count:%u\n", end_count);
                ret = -WD_EINVAL;
        }
        printf("test hpre_blkpool_free end!\n");
release_q:

        wd_blkpool_destroy(pool);
        wd_release_queue(&q);

        return ret;
}

/***
***/
int hpre_blkpool_des(char *dev)
{
        int ret = 0;
        void *blk=NULL;
	 void *tmap=NULL;
        unsigned int blk_count = 0, end_count = 0, blk_fail_count = 0;
        struct wd_queue q;
        struct wd_blkpool_setup wsetup;
        struct wd_blkpool *pool;

        memset((void *)&q, 0, sizeof(q));
        q.capa.alg = "rsa";
        snprintf(q.dev_path, sizeof(q.dev_path), "%s", dev);
        printf("queue path:%s\n", q.dev_path);

        ret = wd_request_queue(&q);
        if(ret)
        {
                printf("wd request queue fail!\n");
                return ret;
        }
        printf("wd request queue success!\n");

        memset(&wsetup, 0, sizeof(wsetup));
        wsetup.block_size = 4096; //key_size;
        wsetup.block_num = 1;
        wsetup.align_size = 32;

        pool = wd_blkpool_create(&q, &wsetup);
        if (!pool)
        {
                printf("create ctx pool fail!\n");
                wd_release_queue(&q);
                return 1;
        }
		printf("create ctx pool success!\n");
	 if (wd_get_free_blk_num(pool, &blk_count) != WD_SUCCESS) {
	         printf("wd_get_free_blk_num fail, blk_count:%u\n", blk_count);
		  ret = -WD_EINVAL;
                goto release_q;
	 }
        blk = wd_alloc_blk(pool);
        if(!blk)
        {
                if (wd_blk_alloc_failures(pool, &blk_fail_count) != WD_SUCCESS) {
		          printf("wd_blk_alloc_failures fail, blk_fail_count:%u\n", blk_fail_count);
                }
                printf("create blk fail,blk_fail_count:%u\n", blk_fail_count);
                ret = -WD_EINVAL;
                goto release_q;
        }
        tmap = wd_blk_iova_map(pool, blk);
	 if (!tmap) {
	 	  printf("wd_blk_iova_map blk fail\n");
                ret = -WD_EINVAL;
                goto release_q;
	 }
        wd_blkpool_destroy(pool);
        wd_free_blk(pool, blk);
	 if (wd_get_free_blk_num(pool, &end_count) != WD_SUCCESS) {
        	  printf("wd_get_free_blk_num fail, blk_count:%u\n", end_count);
		  ret = -WD_EINVAL;
                goto release_q;
	 }
	 if(blk_count != end_count)
        {
                printf("Failed to free memory block, blk count:%u\n", end_count);
                ret = -WD_EINVAL;
        }
        printf("test hpre_blkpool_des end!\n");
release_q:

        wd_blkpool_destroy(pool);
        wd_release_queue(&q);

        return ret;
}

void *wd_alloc_free_test(void *blkpool)
{
        void *blk=NULL;
	 void *tmap=NULL;
        unsigned int i, blk_count = 0;
        struct wd_blkpool *pool = (struct wd_blkpool *)blkpool;

        if (wd_get_free_blk_num(pool, &blk_count) != WD_SUCCESS) {
	         printf("wd_get_free_blk_num fail, blk_count:%u\n", blk_count);
		  return NULL;
	 }
        for(i = 0; i < blk_count; i++)
        {
            blk = wd_alloc_blk(pool);
            if(!blk)
            {
                    if (wd_blk_alloc_failures(pool, &blk_count) != WD_SUCCESS) {
		              printf("wd_blk_alloc_failures fail, blk_count:%u\n", blk_count);
                    }
                    printf("create blk fail,blk_count:%u\n", blk_count);
                    return NULL;
            }
            tmap = wd_blk_iova_map(pool, blk);
	     if (!tmap) {
	             printf("wd_blk_iova_map blk fail\n");
                    return NULL;
	     }
            wd_free_blk(pool, blk);
        }
        //printf("test wd_alloc_free_test end!\n");

	 return NULL;
}


/***
***/
int hpre_blkpool_thread(char *dev, unsigned int blk_sz, unsigned int blk_num, unsigned int align_sz)
{
        int i, ret = 0;
        pthread_t pid[65535];
	 unsigned int blk_count = 0;
        struct wd_queue q;
	 struct wd_blkpool *pool = NULL;
        struct wd_blkpool_setup wsetup;

        memset((void *)&q, 0, sizeof(q));
        q.capa.alg = "rsa";
        snprintf(q.dev_path, sizeof(q.dev_path), "%s", dev);
        printf("queue path:%s\n", q.dev_path);

        ret = wd_request_queue(&q);
        if(ret)
        {
                printf("wd request queue fail!\n");
                return ret;
        }
        printf("wd request queue success!\n");

        memset(&wsetup, 0, sizeof(wsetup));
        wsetup.block_size = blk_sz; //key_size;
        wsetup.block_num = blk_num;
        wsetup.align_size = align_sz;

        pool = wd_blkpool_create(&q, &wsetup);
        if (!pool)
        {
                printf("%s(): create ctx pool fail!\n", __func__);
                wd_release_queue(&q);
                return 1;
        }
        for(i = 0; i < blk_num; i++)
        {
                ret = pthread_create(&pid[i], NULL, wd_alloc_free_test, (void *)pool);
	         if (ret != 0)
                {
		        printf("pid:%ld, can't create thread: %s\n", pid[i], strerror(ret));
                }
        }

        for(i = 0; i < blk_num; i++)
        {
		pthread_join(pid[i], NULL);
        }

        wd_get_free_blk_num(pool, &blk_count);
	 printf("blk count:%u.\n", blk_count);

        wd_blkpool_destroy(pool);
        wd_release_queue(&q);

        return 0;
}

int hpre_blkpool_create_des(char *dev, unsigned int blk_sz, unsigned int blk_num, unsigned int align_sz)
{
        int ret = 0;
        unsigned int blk_count = 0;
        struct wd_queue q;
        struct wd_blkpool_setup wsetup;
        struct wd_blkpool *pool;

        memset((void *)&q, 0, sizeof(q));
        q.capa.alg = "rsa";
        snprintf(q.dev_path, sizeof(q.dev_path), "%s", dev);
        printf("queue path:%s\n", q.dev_path);

        ret = wd_request_queue(&q);
        if(ret)
        {
                printf("wd request queue fail!\n");
                return ret;
        }
        printf("wd request queue success!\n");

        memset(&wsetup, 0, sizeof(wsetup));
        wsetup.block_size = blk_sz; //key_size;
        wsetup.block_num = blk_num;
        wsetup.align_size = align_sz;

        while(blk_count > blk_num)
        {
            pool = wd_blkpool_create(&q, &wsetup);
            if (!pool)
            {
                printf("%s(): create ctx pool fail!\n", __func__);
                wd_release_queue(&q);
                return 1;
            }
            printf("%s(): create ctx pool success!\n", __func__);

	     wd_get_free_blk_num(pool, &blk_count);
            if(blk_count !=  wsetup.block_num)
            {
                    printf("Memory block release failed, blk count:%u\n", blk_count);
                    wd_release_queue(&q);
                    return 1;
            }
	     wd_blkpool_destroy(pool);
            blk_count+=1;
        }
        wd_release_queue(&q);

        return 0;
}

int hpre_blkpool_interface_fault(void)
{
	 unsigned int blk_count = 0;
        void *blk =  NULL;
        struct wd_blkpool *pool = NULL;

        if (wd_get_free_blk_num(pool, &blk_count) == WD_SUCCESS) {
	         printf("wd_get_free_blk_num fail...\n");
		  return -WD_EINVAL;
	 }

        if (wd_blk_alloc_failures(pool , &blk_count) == WD_SUCCESS) {
                printf("wd_blk_alloc_failures fail...\n");
                return 1;
        }
        blk =  wd_blk_iova_map(pool, blk);
        if(NULL != blk)
        {
                printf("wd_blk_dma_map fail...\n");
                return 1;
        }
        blk = wd_alloc_blk(pool);
        if(NULL != blk)
        {
                printf("wd_alloc_blk...\n");
                return 1;
        }

        wd_free_blk(pool, blk);
        wd_blkpool_destroy(pool);

        return 0;
}

int hpre_node_mask(char *dev, unsigned int node, char *alg)
{
		int ret;

        struct wd_queue q;
        printf("info: init q %s\n", alg);

        printf("info: assign q\n");
        memset((void *)&q, 0, sizeof(q));
		printf("    | q alg => %s |\n", alg);
		q.capa.alg = alg;
		printf("    | q dev => %s |\n", dev);
	    snprintf(q.dev_path, sizeof(q.dev_path), "%s", dev);
		printf("    | q node => %d |\n", node);
		q.node_mask = node;

        printf("info: request q\n");
        ret = wd_request_queue(&q);
        if (ret) {
                printf("error: request q fail\n");
                return ret;
        }
        printf("info: check q\n");
	    static int t;
		t = wd_get_node_id(&q);
		printf("    | q node => %d |\n", t);
		t = wd_get_available_dev_num(alg);
		printf("    | q dev num => %d |\n", t);

        printf("info: release q\n");
        wd_release_queue(&q);
        return ret;
}

typedef struct thread_data{
    int threadid;
    char *dev;
    unsigned int node;
    char *alg;
}THDATA,*PTHDATA;

int hpre_node_mask_do(char *dev, unsigned int node, char *alg)
{
		int ret;

        struct wd_queue q;
        memset((void *)&q, 0, sizeof(q));
	q.capa.alg = alg;
	snprintf(q.dev_path, sizeof(q.dev_path), "%s", dev);
	q.node_mask = node;
        ret = wd_request_queue(&q);
        if (ret) {
                printf("error: request q fail\n");
                return ret;
        }
	wd_get_node_id(&q);
	wd_get_available_dev_num(alg);
        wd_release_queue(&q);
        return ret;
}
void *hpre_node_mask_thread(void *pthreadid)
{
		PTHDATA tid = (PTHDATA)pthreadid;

        printf("info: thread %d\n      dev %s\n      node %d\n      alg %s\n", tid->threadid, tid->dev, tid->node, tid->alg);
		hpre_node_mask_do(tid->dev, tid->node, tid->alg);
      //  return 0;
}

/***
argv[1] - 表示运行业务的类型
***/
int main(int arc, char *argv[])
{
	int ret = 0;
	int count = 0;
	int queue_num = 0;
	int pthread_num = 0;
	time_t p_time = 0;
	char dev[256]={0};
	char share_dev[256]={0};
	char algorithm_type[10]={0};
        unsigned int blk_size=0;
        unsigned int blk_num=0;
        unsigned int align_size=0;
	unsigned long memory_size=0;

	if(!strcmp(argv[1], "available-dev"))
	{
		/***
		argv[2] - 表示算法类型
		***/
		//查询算法的可用设备
		snprintf(algorithm_type, sizeof(algorithm_type), "%s", argv[2]);
		count = wd_get_available_dev_num(algorithm_type);
		printf("algorithm dev:%d\n",count);

		return count;
	}
	else if(!strcmp(argv[1], "queue-req"))
	{
		/***
		argv[2] - 表示算法类型
		argv[3] - 表示申请队列设备
		argv[4] - 表示申请队列的预留内存大小
		***/
		//申请单个队列，并给队列预留内存
		snprintf(algorithm_type, sizeof(algorithm_type), "%s", argv[2]);
		snprintf(dev, sizeof(dev), "%s", argv[3]);
		memory_size = strtoul(argv[4], NULL, 10);
		ret = hpre_dev_queue_req(dev, algorithm_type, memory_size);
		if(0 != ret)
		{
			return 1;
		}
	}
	else if(!strcmp(argv[1], "mult-queue"))
	{
		/***
		argv[2] - 表示算法类型
		argv[3] - 表示申请队列设
		argv[4] - 表示队列数量
		***/
		//申请多个队列
		snprintf(algorithm_type, sizeof(algorithm_type), "%s", argv[2]);
		snprintf(dev, sizeof(dev), "%s", argv[3]);
		queue_num = strtoul(argv[4], NULL, 10);
		ret = application_release_multiple_queue(dev, algorithm_type, queue_num);
		if(0 != ret)
		{
			return 1;
		}
	}
	else if(!strcmp(argv[1], "queue-share"))
	{
		/***
		argv[2] - 表示算法类型
		argv[3] - 表示申请队列设备
		argv[4] - 表示共享预留内存的设备
		argv[5] - 表示申请队列的预留内存大小
		***/
		//申请单个队列，预留内存，与其它队列共享预留内存
		snprintf(algorithm_type, sizeof(algorithm_type), "%s", argv[2]);
		snprintf(dev, sizeof(dev), "%s", argv[3]);
		snprintf(share_dev, sizeof(share_dev), "%s", argv[4]);
		memory_size = strtoul(argv[5], NULL, 10);

		ret = hpre_dev_queue_share(dev, share_dev, algorithm_type, memory_size);
		if(0 != ret)
		{
			return 1;
		}
	}
	else if(!strcmp(argv[1], "node-queue-share"))
	{
		/***
		argv[2] - 表示算法类型
		argv[3] - 表示申请队列设备
		argv[4] - 表示设备node
		argv[5] - 表示共享内存设备node
		argv[6] - 表示申请队列的预留内存大小
		***/
		//申请单个队列，预留内存，与其它队列共享预留内存
		snprintf(algorithm_type, sizeof(algorithm_type), "%s", argv[2]);
		snprintf(dev, sizeof(dev), "%s", argv[3]);
		unsigned int node=0;
        node = strtoul(argv[4], NULL, 16);
		unsigned int share_node=0;
        share_node = strtoul(argv[5], NULL, 16);
		memory_size = strtoul(argv[6], NULL, 10);

		ret = hpre_node_queue_share(dev, node, share_node, algorithm_type, memory_size);
		if(0 != ret)
		{
			return 1;
		}
	}
	else if(!strcmp(argv[1], "queue-interact-share"))
	{
		/***
		argv[2] - 表示算法类型
		argv[3] - 表示申请队列设备
		argv[4] - 表示共享预留内存的设备
		argv[5] - 表示申请队列的预留内存大小
		***/
		//队列预留内存后作为共享的目标队列
		snprintf(algorithm_type, sizeof(algorithm_type), "%s", argv[2]);
		snprintf(dev, sizeof(dev), "%s", argv[3]);
		snprintf(share_dev, sizeof(share_dev), "%s", argv[4]);
		memory_size = strtoul(argv[5], NULL, 10);

		ret = hpre_dev_queue_interact_share(dev, share_dev, algorithm_type, memory_size);
		if(0 != ret)
		{
			return 1;
		}
	}
	else if(!strcmp(argv[1], "queue-cross-proc-share"))
	{
		/***
		argv[2] - 表示算法类型
		argv[3] - 表示申请队列设备
		argv[4] - 表示申请队列的预留内存大小
		***/
		//跨进程进行队列共享
		snprintf(algorithm_type, sizeof(algorithm_type), "%s", argv[2]);
		snprintf(dev, sizeof(dev), "%s", argv[3]);
		memory_size = strtoul(argv[4], NULL, 10);
		ret = hpre_dev_queue_cross_proc_share(dev, algorithm_type, memory_size);
		if(0 != ret)
		{
			return 1;
		}
	}
	else if(!strcmp(argv[1], "mult-thread-queue"))
	{
		/***
		argv[2] - 表示算法类型
		argv[3] - 表示申请队列设备
		argv[4] - 线程数
		argv[5] - 线程睡眠时间
		***/
		//多线程申请多队列
		snprintf(algorithm_type, sizeof(algorithm_type), "%s", argv[2]);
		snprintf(dev, sizeof(dev), "%s", argv[3]);
		pthread_num = strtoul(argv[4], NULL, 10);
		p_time = strtoul(argv[5], NULL, 10);

		ret = hpre_mult_thread_request_queue(dev, algorithm_type, pthread_num, p_time);
		if(0 != ret)
		{
			return 1;
		}
	}
        else if(!strcmp(argv[1], "hpre-blk"))
        {
                /***
                argv[2] - 表示申请队列的设备
                argv[3] - 块内存大小
                argv[4] - 块内存个数
                argv[5] - 块内存对齐
                ***/

                //申请队列->创建内存池->申请内存块->映射内存块->释放内存块->注销内存池->释放队列
		snprintf(dev, sizeof(dev), "%s", argv[2]);
                blk_size = strtoul(argv[3], NULL, 10);
                blk_num = strtoul(argv[4], NULL, 10);
                align_size = strtoul(argv[5], NULL, 10);

                ret = hpre_blkpool_operating(dev, blk_size, blk_num, align_size);
                if(0 != ret)
                {
                         return 1;
                }
        }
        else if(!strcmp(argv[1], "hpre-blk-alloc"))
        {
                /***
                argv[2] - 表示申请队列的设备
                ***/
                //申请队列->创建内存池->申请内存块->再次申请内存块
                snprintf(dev, sizeof(dev), "%s", argv[2]);

                ret = hpre_blkpool_alloc(dev);
                if(0 != ret)
                {
                         return 1;
                }
        }
        else if(!strcmp(argv[1], "hpre-blk-free"))
        {
                /***
                argv[2] - 表示申请队列的设备
                ***/
                //申请队列->创建内存池->申请内存块->释放内存块->再次释放内存块
                snprintf(dev, sizeof(dev), "%s", argv[2]);

                ret = hpre_blkpool_free(dev);
                if(0 != ret)
                {
                         return 1;
                }
        }
        else if(!strcmp(argv[1], "hpre-blk-des"))
        {
                /***
                argv[2] - 表示申请队列的设备
                ***/
                //内存块未被释放，检查是否可以注销内存池
                snprintf(dev, sizeof(dev), "%s", argv[2]);

                ret = hpre_blkpool_des(dev);
                if(0 != ret)
                {
                         return 1;
                }
        }
        else if(!strcmp(argv[1], "hpre-blk-thread"))
        {
                /***
                argv[2] - 表示申请队列的设备
                argv[3] - 内存块大小
                argv[4] - 内存块个数
                argv[5] - 内存对齐
                ***/
                //创建内存池，多线程申请块内存并释放块内存
                snprintf(dev, sizeof(dev), "%s", argv[2]);
                blk_size = strtoul(argv[3], NULL, 10);
                blk_num = strtoul(argv[4], NULL, 10);
                align_size = strtoul(argv[5], NULL, 10);

                ret = hpre_blkpool_thread(dev, blk_size, blk_num, align_size);
                if(0 != ret)
                {
                         return 1;
                }
        }
        else if(!strcmp(argv[1], "hpre-blk-create-des"))
        {
                /***
                argv[2] - 表示申请队列的设备
                argv[3] - 内存块大小
                argv[4] - 内存块个数
                argv[5] - 内存对齐
                ***/
                //重复创建内存池和释放内存池
                snprintf(dev, sizeof(dev), "%s", argv[2]);
                blk_size = strtoul(argv[3], NULL, 10);
                blk_num = strtoul(argv[4], NULL, 10);
                align_size = strtoul(argv[5], NULL, 10);

                ret = hpre_blkpool_create_des(dev, blk_size, blk_num, align_size);
                if(0 != ret)
                {
                        return 1;
                }
        }
        else if(!strcmp(argv[1], "hpre-blk-interface-fault"))
        {
                //接口容错测试
                ret = hpre_blkpool_interface_fault();
                if(0 != ret)
                {
                        return 1;
                }
		}
        else if(!strcmp(argv[1], "hpre-node-mask"))
        {
                /***
                argv[2] - dev
                argv[3] - node
                argv[4] - alg
                blk_num = strtoul(argv[4], NULL, 10);
                align_size = strtoul(argv[5], NULL, 10);
                ***/
                snprintf(dev, sizeof(dev), "%s", argv[2]);
				unsigned int node=0;
                node = strtoul(argv[3], NULL, 10);
			    char alg[256]={0};
                snprintf(alg, sizeof(alg), "%s", argv[4]);

                ret = hpre_node_mask(dev, node, alg);
                if(0 != ret)
                {
                        return 1;
                }
        }

        else if(!strcmp(argv[1], "hpre-node-mask-thread"))
        {
                /***
                argv[2] - dev
                argv[3] - node
                argv[4] - alg
                argv[5] - thread
                blk_num = strtoul(argv[4], NULL, 10);
                align_size = strtoul(argv[5], NULL, 10);
                ***/
                snprintf(dev, sizeof(dev), "%s", argv[2]);
				unsigned int node=0;
                node = strtoul(argv[3], NULL, 10);
			    char alg[256]={0};
                snprintf(alg, sizeof(alg), "%s", argv[4]);
				unsigned int NUM_Threads=0;
                NUM_Threads = strtoul(argv[5], NULL, 10);
					pthread_t Pthread[NUM_Threads];
					THDATA index[NUM_Threads];
					static int i;
		static int cnt;
		while(1){
			usleep(1);
			for (i = 0; i < NUM_Threads; i++)
			{
				index[i].threadid = i;
				index[i].dev = dev;
				index[i].node = node;
				index[i].alg = alg;
				ret = pthread_create(&Pthread[i], NULL, hpre_node_mask_thread, (void *)&index[i]);
				if (0 != ret)
				{
					printf("error: creating failed!\n");
				}
			}
			if(cnt > 63)
			break;
			cnt++;

			//pthread_join(&Pthread[i], NULL);
		}
		pthread_exit(NULL);
	}
	return 0;
}

