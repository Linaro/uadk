#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#define __USE_GNU
#include <pthread.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include "../../wd.h"
#include "../../wd_sgl.h"
#include "sgl_test.h"

void *sgl_addr[4];

void sgl_alloc_and_get_test(void *addr);
void sgl_free_and_get_test(void *addr);
void func_test(void *pool, void *sgl);
void func_get_len(struct wd_sgl *sgl);

int main(int argc, char *argv[])
{
        int opt;
        __u16 sgl_num = 5;
        __u32 buf_num = 40;
	__u32 buf_size = 4096;
	__u8 sge_num_in_sgl = 4;
	__u8 buf_num_in_sgl = 3;
        __u32 align_size = 64;

        while ((opt = getopt(argc, argv, "a:b:c:d:e:f:")) != -1) {
		switch (opt) {
		case 'a':
                        sgl_num = atoi(optarg);
			break;
		case 'b':
                        buf_num = atoi(optarg);
			break;
		case 'c':
                        buf_size = atoi(optarg);
			break;
		case 'd':
                        sge_num_in_sgl = atoi(optarg);
			break;
		case 'e':
                        buf_num_in_sgl = atoi(optarg);
			break;
                case 'f':
                        align_size = atoi(optarg);
                        break;
                default:
			fprintf(stderr, "./sgl [-a sgl_num] [-b buf_num] [-c buf_size] [-d sge_num_in_sgl] [-e buf_num_in_sgl] [-f align_size]\n");
			return -1;
                }
        }
fprintf(stderr, "sgl_num = %hu, buf_num = %u, buf_size = %u.\nsge_num_in_sgl = %hhu, buf_num_in_sgl = %hhu, align_size = %u.\n\n",
        sgl_num, buf_num, buf_size, sge_num_in_sgl, buf_num_in_sgl, align_size);

        struct wd_queue *q;
        struct wd_sglpool_setup sp;
        __u32 free_sgl_num;
        void *sgl_pool;
        int ret;
#if 0
        pthread_t test_thrds[2];
        int loop = 1;
#endif

        q = calloc(1, sizeof(struct wd_queue));
	if (q == NULL) {
		ret = -ENOMEM;
		fprintf(stderr, "alloc q fail, ret =%d\n", ret);
		return -1;;
	}

	q->capa.alg = "zlib";
	q->capa.latency = 0;
	q->capa.throughput = 0;
        ret = wd_request_queue(q);
	if (ret) {
		fprintf(stderr, "wd_request_queue fail, ret =%d\n", ret);
		free(q);
	}

        sp.buf_size = buf_size;   // 128K
        sp.align_size = align_size;
        sp.sge_num_in_sgl = sge_num_in_sgl;
        sp.buf_num_in_sgl = buf_num_in_sgl;
        sp.sgl_num = sgl_num;
        sp.buf_num = buf_num;
        //sp.buf_num = sp.buf_num_in_sgl * sp.sgl_num + sp.sgl_num + 2;
        /* 创建sgl pool */
        sgl_pool = wd_sglpool_create(q, &sp);
        if (!sgl_pool) {
                printf("failed to create sgl pool.\n");
                wd_release_queue(q);
                free(q);
                return -1;
        }
        printf("sgl_pool = %p\n", sgl_pool);

        /* 获取sgl pool中空闲的sgl */
        ret = wd_get_free_sgl_num(sgl_pool, &free_sgl_num);
        if (ret)
                printf("test: failed to alloc sgl.\n");
        printf("free_sgl_num = %d\n", free_sgl_num);


        sgl_addr[0] = wd_alloc_sgl(sgl_pool, 4096);
        sgl_addr[1] = wd_alloc_sgl(sgl_pool, 4096);
        sgl_addr[2] = wd_alloc_sgl(sgl_pool, 4096);
        sgl_addr[3] = wd_alloc_sgl(sgl_pool, 4096);
        /* 合并sgl */
        ret = wd_sgl_merge(sgl_addr[0], sgl_addr[1]);
        if (ret)
                printf("test: wd_sgl_merge failed.\n");

        printf("after merge sgl_addr[0] and sgl_addr[1] ...\n");

#if 1
        func_test(sgl_pool, sgl_addr[0]);
        char a[5016] = { 0 };
        char b[10000] = { 0 };
        char c[50000] = { 0 };
        memset(a, 'f', sizeof(a));

#endif

        ret = wd_sgl_cp_from_pbuf(sgl_addr[2], 1000, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");
        printf("sgl_addr[2]:  coypy sz = %ld.\n", (ret == 0) ? sizeof(a) : ret);
        func_get_len(sgl_addr[2]);

        ret = wd_sgl_cp_from_pbuf(sgl_addr[3], 2000, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");
        printf("sgl_addr[3]:  coypy sz = %ld.\n", (ret == 0) ? sizeof(a) : ret);
        func_get_len(sgl_addr[3]);

        ret = wd_sgl_merge(sgl_addr[2], sgl_addr[3]);
        if (ret)
                printf("test: wd_sgl_merge failed.\n");

        printf("after merge sgl_addr[2] and sgl_addr[3]  ...\n");
        func_get_len(sgl_addr[3]);
        func_get_len(sgl_addr[2]);

        wd_free_sgl(sgl_pool, sgl_addr[2]);
        wd_free_sgl(sgl_pool, sgl_addr[3]);
        wd_free_sgl(sgl_pool, sgl_addr[2]);

printf("\n ......... wd_sgl_cp_from_pbuf start ........ \n");
        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 0, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");
        printf("1  coypy sz = %ld.\n", (ret == 0) ? sizeof(a) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 0, b, sizeof(b));
        if (ret < 0)
                printf("b coypy failed!\n");
        printf("2  coypy sz = %ld.\n", (ret == 0) ? sizeof(b) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 0, c, sizeof(c));
        if (ret < 0)
                printf("c coypy failed!\n");
        printf("3 coypy sz = %ld.\n", (ret == 0) ? sizeof(c) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

printf("\n ......... test  1 ........ \n");
#if 1
        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 2407, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");
        printf("1 coypy sz = %ld.\n", (ret == 0) ? sizeof(a) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 2407, b, sizeof(b));
        if (ret < 0)
                printf("b coypy failed!\n");
        printf("2 coypy sz = %ld.\n", (ret == 0) ? sizeof(b) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 2407, c, sizeof(c));
        if (ret < 0)
                printf("c coypy failed!\n");
        printf("3 coypy sz = %ld.\n", (ret == 0) ? sizeof(c) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

printf("\n ......... test  2 ........ \n");

         ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 4000, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");
        printf("1 coypy sz = %ld.\n", (ret == 0) ? sizeof(a) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 4000, b, sizeof(b));
        if (ret < 0)
                printf("b coypy failed!\n");
        printf("2 coypy sz = %ld.\n", (ret == 0) ? sizeof(b) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 4000, c, sizeof(c));
        if (ret < 0)
                printf("c coypy failed!\n");
        printf("3 coypy sz = %ld.\n", (ret == 0) ? sizeof(c) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

 printf("\n ......... test  3 ........ \n");

         ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 6000, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");
        printf("1 coypy sz = %ld.\n", (ret == 0) ? sizeof(a) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 6000, b, sizeof(b));
        if (ret < 0)
                printf("b coypy failed!\n");
        printf("2 coypy sz = %ld.\n", (ret == 0) ? sizeof(b) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 6000, c, sizeof(c));
        if (ret < 0)
                printf("c coypy failed!\n");
        printf("3 coypy sz = %ld.\n", (ret == 0) ? sizeof(c) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

printf("\n ......... test  4 ........ \n");

         ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 9000, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");
        printf("1 coypy sz = %ld.\n", (ret == 0) ? sizeof(a) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 9000, b, sizeof(b));
        if (ret < 0)
                printf("b coypy failed!\n");
        printf("2 coypy sz = %ld.\n", (ret == 0) ? sizeof(b) : ret);\
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 9000, c, sizeof(c));
        if (ret < 0)
                printf("c coypy failed!\n");
        printf("3 coypy sz = %ld.\n", (ret == 0) ? sizeof(c) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

printf("\n ......... test  5 ........ \n");

         ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 10000, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");
        printf("1 coypy sz = %ld.\n", (ret == 0) ? sizeof(a) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 10000, b, sizeof(b));
        if (ret < 0)
                printf("b coypy failed!\n");
        printf("2 coypy sz = %ld.\n", (ret == 0) ? sizeof(b) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);

        ret = wd_sgl_cp_from_pbuf(sgl_addr[0], 10000, c, sizeof(c));
        if (ret < 0)
                printf("c coypy failed!\n");
        printf("3 coypy sz = %ld.\n", (ret == 0) ? sizeof(c) : ret);
        func_get_len(sgl_addr[0]);
        func_get_len(sgl_addr[1]);
printf("\n ......... test end ........ \n");
#endif

#if 1
printf("\n ......... wd_sgl_cp_to_pbuf start ........ \n");
        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 0, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");

        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 0, b, sizeof(b));
        if (ret < 0)
                printf("b coypy failed!\n");

        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 0, c, sizeof(c));
        if (ret < 0)
                printf("c coypy failed!\n");

printf("\n ......... test  1 ........ \n");

        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 2407, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");

        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 2407, b, sizeof(b));
        if (ret < 0)
                printf("b coypy failed!\n");

        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 2407, c, sizeof(c));
        if (ret < 0)
                printf("c coypy failed!\n");

printf("\n ......... test  2 ........ \n");

         ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 4000, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");

        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 4000, b, sizeof(b));
        if (ret < 0)
                printf("b coypy failed!\n");

        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 4000, c, sizeof(c));
        if (ret < 0)
                printf("c coypy failed!\n");

 printf("\n ......... test  3 ........ \n");

         ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 6000, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");

        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 6000, b, sizeof(b));
        if (ret < 0)
                printf("b coypy failed!\n");

        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 6000, c, sizeof(c));
        if (ret < 0)
                printf("c coypy failed!\n");

printf("\n ......... test  4 ........ \n");

         ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 9000, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");

        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 9000, b, sizeof(b));
        if (ret < 0)
                printf("b coypy failed!\n");

        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 9000, c, sizeof(c));
        if (ret < 0)
                printf("c coypy failed!\n");

printf("\n ......... test  5 ........ \n");

         ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 10000, a, sizeof(a));
        if (ret < 0)
                printf("a coypy failed!\n");

        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 10000, b, sizeof(b));
        if (ret < 0)
                printf("b coypy failed!\n");

        ret = wd_sgl_cp_to_pbuf(sgl_addr[0], 10000, c, sizeof(c));
        if (ret < 0)
                printf("c coypy failed!\n");

printf("\n ......... test end ........ \n");
#endif

#if 0
        ret = pthread_create(&test_thrds[0], NULL, (void *)sgl_alloc_and_get_test, sgl_pool);
        if (ret) {
		printf("Create 1'th thread fail!\n");
		return ret;
	}

        ret = pthread_create(&test_thrds[1], NULL, (void *)sgl_free_and_get_test, sgl_pool);
        if (ret) {
		printf("Create 2'th thread fail!\n");
		return ret;
	}

        while (loop--)
                sleep(2);

        for (i = 0; i < 2; i++) {
		ret = pthread_join(test_thrds[i], NULL);
		if (ret) {
			printf("Join %dth thread fail!\n", i);
			return ret;
		}
	}
#endif
        wd_free_sgl(sgl_pool, sgl_addr[1]);
        wd_free_sgl(sgl_pool, sgl_addr[0]);
        wd_free_sgl(sgl_pool, sgl_addr[0]);

        func_test(sgl_pool, sgl_addr[0]);
        wd_sglpool_destroy(sgl_pool);
        wd_sglpool_destroy(sgl_pool);
        wd_release_queue(q);
	free(q);

        return 0;
}

void func_get_len(struct wd_sgl *sgl)
{
        __u32 dtsize;
        int ret, i;

        ret = wd_get_sgl_datalen(sgl, &dtsize);
        if (ret) {
                printf("wd_get_sgl_datalen failed!\n");
                return;
        }
        printf("wd_get_sgl_datalen ok: dtsize = %u!\n", dtsize);
        for (i = 1; i <= 3; i++) {
                ret = wd_get_sge_datalen(sgl, i, &dtsize);
                if (ret) {
                        printf("wd_get_sgl_datalen failed!\n");
                        return;
                }
                printf("    wd_get_sge_datalen ok: dtsize = %u!\n", dtsize);
        }
}

void sgl_alloc_and_get_test(void *pool)
{
        __u32 free_sgl_num = 0;
        int ret;

        /* 分配sgl */
        sgl_addr[0] = wd_alloc_sgl(pool, 10000);
        printf("%s, after alloc a sgl ...\n", __func__);

        /* 获取sgl pool中空闲的sgl */
        ret = wd_get_free_sgl_num(pool, &free_sgl_num);
        if (ret)
                printf("%s, test: failed to alloc sgl.\n", __func__);
        printf("%s, get free_sgl_num = %d\n", __func__, free_sgl_num);

        /* 分配sgl */
        sgl_addr[1] = wd_alloc_sgl(pool, 10000);
        printf("%s, after alloc a sgl ...\n", __func__);

        sgl_addr[2] = wd_alloc_sgl(pool, 10000);
        //sgl_addr[3] = wd_alloc_sgl(pool, 10000);
        func_test(pool, sgl_addr[0]);
}

void sgl_free_and_get_test(void *pool)
{
        __u32 free_sgl_num;
        int ret;

        ret = wd_get_free_sgl_num(pool, &free_sgl_num);
        if (ret)
                printf("test: failed to alloc sgl.\n");
        printf("%s, free_sgl_num = %d\n", __func__, free_sgl_num);

        if (sgl_addr[0] && sgl_addr[1]) {
                /* 合并sgl */
                ret = wd_sgl_merge(sgl_addr[0], sgl_addr[1]);
                if (ret)
                        printf("test: wd_sgl_merge failed.\n");

                printf("after merge 2 sgls ...\n");
                sleep(2);

                func_test(pool, sgl_addr[0]);
        }

        wd_free_sgl(pool, sgl_addr[0]);
        func_test(pool, sgl_addr[0]);

        //wd_free_sgl(pool, sgl_addr[0]);
        //wd_free_sgl(pool, sgl_addr[1]);
        wd_free_sgl(pool, sgl_addr[2]);
}

void func_test(void *pool, void *sgl)
{
        void *addr;
        __u32 sz;
        size_t mem_sz;
        __u32 free_num, num;
        int ret;

        printf("..........start .................\n");
        printf(".................................\n");
        addr = wd_get_last_sge_buf(sgl);
        printf("wd_get_last_sge_buf - sgl = %p\n", addr);

        addr = wd_get_first_sge_buf(sgl);
        printf("wd_get_first_sge_buf - sgl = %p\n", addr);

        ret = wd_get_sgl_sge_num(sgl);
        printf("wd_get_sgl_sge_num = %d\n",ret);

        ret = wd_get_sgl_buf_num(sgl);
        printf("wd_get_sgl_buf_num = %d\n", ret);

        addr = wd_get_sge_buf(sgl, 2);
        printf("wd_get_sge_buf - sgl_addr[1].buf = %p\n", addr);

        ret = wd_get_sgl_buf_sum(sgl);
        printf("wd_get_sgl_buf_sum = %d\n", ret);

        ret = wd_get_sgl_mem_size(sgl, &mem_sz);
        printf("wd_get_sgl_mem_size = %ld\n", mem_sz);

        ret = wd_get_free_sgl_num(pool, &free_num);
        if (ret)
                printf("wd_get_free_sgl_num err.");
        else
                printf("wd_get_free_sgl_num = %d\n", free_num);

        ret = wd_get_free_sgl_sge_num(sgl, &num);
        printf("wd_get_free_sgl_sge_num = %u\n", num);

        ret = wd_get_free_buf_num(pool, &free_num);
        printf("wd_get_free_buf_num = %d\n", free_num);

        __u32 dtsize;
        ret = wd_get_sgl_datalen(sgl, &dtsize);
        printf("wd_get_sgl_datalen = %d\n", dtsize);

        ret = wd_get_sge_datalen(sgl, 2, &dtsize);
        printf("wd_get_sge_datalen = %d\n", dtsize);

        ret = wd_get_sgl_bufsize(sgl, &sz);
        printf("wd_get_sgl_bufsize = %d\n", sz);

        printf(".................................\n");
        printf("..............end...................\n\n");
}
