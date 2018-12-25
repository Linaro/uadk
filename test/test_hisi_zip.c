// SPDX-License-Identifier: GPL-2.0+
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <getopt.h>
#include "../wd.h"
#include "../smm.h"
#include "../drv/hisi_qm_udrv.h"

/* statistic */
static int st_send = 0;
static int st_send_retries = 0;
static int st_recv = 0;
static int st_recv_retries = 0;

#define SYS_ERR_COND(cond, msg, ...) \
do { \
	if (cond) { \
		if (errno) \
			perror(msg); \
		else \
			fprintf(stderr, #cond); \
		fprintf(stderr, "\n" msg, ##__VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} \
} while (0)

#define ZLIB 0
#define GZIP 1

#if ENABLE_NOIOMMU
#define SS_REGION_SIZE (2*1024*1024)
#else
#define SS_REGION_SIZE (16*1024*1024)
#endif

#define ZLIB_HEADER "\x78\x9c"
#define ZLIB_HEADER_SZ 2

#define GZIP_HEADER "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03"
#define GZIP_HEADER_SZ 10

#define BLOCK_SIZE 512000

/*
 * Global init function for hizip. This is a single queue version, can be
 * extend to multi-queue in the future
 */
static struct wd_queue q;
static void *ss_region;
int hizip_init(int alg_type) {
	int ret;

	memset((void *)&q, 0, sizeof(q));
	if (alg_type == ZLIB)
		q.capa.alg = "zlib";
	else
		q.capa.alg = "gzip";

	ret = wd_request_queue(&q);
	if (ret)
		return ret;

#ifndef CONFIG_IOMMU_SVA
	ss_region = wd_reserve_memory(&q, SS_REGION_SIZE);
	if (!ss_region) {
		ret = -ENOMEM;
		goto out_with_queue;
	}

	ret = smm_init(ss_region, SS_REGION_SIZE, 0xFFF);
	if (ret)
		goto out_with_queue;
#endif

	return 0;

out_with_queue:
	wd_release_queue(&q);
	return ret;
}

void hizip_fini()
{
	wd_release_queue(&q);
	fprintf(stderr, "send %d retries: %d, recv %d retries: %d\n",
		st_send, st_send_retries, st_recv, st_recv_retries);
}

static inline void *hizip_malloc(size_t size)
{
#ifdef CONFIG_IOMMU_SVA
	return malloc(size);
#else
	return smm_alloc(ss_region, size);
#endif
}

static inline void hizip_free(void *ptr)
{
#ifdef CONFIG_IOMMU_SVA
	free(ptr);
#else
	smm_free(ss_region, ptr);
#endif
}

static void hizip_sync_req(__u64 in, __u64 out,
			   size_t ilen, size_t*olen, int dw9)
{
	struct hisi_qm_msg msg, *recv_msg;
	int ret;

	memset(&msg, 0, sizeof(msg)); /* todo: we don't need to copy so much */
	msg.input_date_length = ilen;
	msg.dw9 = dw9;
	msg.dest_avail_out = *olen;
	msg.source_addr_l = in & 0xffffffff;
	msg.source_addr_h = in >> 32;
	msg.dest_addr_l = out & 0xffffffff;
	msg.dest_addr_h = out >> 32;

	do {
		st_send++;
		ret = wd_send(&q, &msg);
		if (ret == -EBUSY) {
			usleep(1);
			st_send_retries++;
			continue;
		}
		SYS_ERR_COND(ret, "wd_send");
	} while (ret);

	do {
		st_recv++;
		ret = wd_recv(&q, (void **)&recv_msg);
		SYS_ERR_COND(ret == -EIO, "wd_recv");
		if (ret == -EAGAIN) {
			usleep(1);
			st_recv_retries++;
			continue;
		}
	} while (ret);

	*olen = recv_msg->produced;
}

void hizip_deflate(FILE *source, FILE *dest,  int type)
{
	__u64 in, out;
	void *a;
	int total_len, fd;
	size_t sz, ilen;
	struct stat s;

	fd = fileno(source);
	SYS_ERR_COND(fstat(fd, &s) < 0, "fstat");
	total_len = s.st_size;
	SYS_ERR_COND(!total_len, "input file length zero");

	a = hizip_malloc(BLOCK_SIZE * 2);
	SYS_ERR_COND(!a, "hizip_malloc!");
	in = (__u64)a;
	out = (__u64)a + BLOCK_SIZE;

	if (type == ZLIB) {
		SYS_ERR_COND(total_len > 16 * 1024 * 1024,
			     "total_len(%d) > 16MB)!", total_len);
		SYS_ERR_COND(total_len > BLOCK_SIZE,
			     "zip total_len(%d) > BLOCK_SIZE", total_len);

		sz = fread(a, 1, total_len, source);
		SYS_ERR_COND(sz != total_len, "read");

		sz = BLOCK_SIZE;
		hizip_sync_req(in, out, total_len, &sz, 2);
		fwrite(ZLIB_HEADER, 1, ZLIB_HEADER_SZ, dest);
		fwrite(a + BLOCK_SIZE, 1, sz, dest);
	} else {
		while (total_len) {
			ilen = total_len > BLOCK_SIZE ? BLOCK_SIZE : total_len;
			total_len -= ilen;

			sz = fread(a, 1, ilen, source);
			SYS_ERR_COND(sz != ilen, "read");

			sz = BLOCK_SIZE;
			hizip_sync_req(in, out, ilen, &sz, 3);
			fwrite(GZIP_HEADER, 1, GZIP_HEADER_SZ, dest);
			fwrite(a + BLOCK_SIZE, 1, sz, dest);
		}
	}

	fclose(dest);
	hizip_free(a);
}

int main(int argc, char *argv[])
{
	int alg_type = GZIP;
	int ret, opt;
	int show_help = 0;

	while ((opt = getopt(argc, argv, "zgh")) != -1) {
		switch (opt) {
		case 'z':
			alg_type = ZLIB;
			break;
		case 'g':
			alg_type = GZIP;
			break;
		default:
			show_help = 1;
			break;
               }
	}

	SYS_ERR_COND(show_help || optind > argc,
		     "test_hisi_zip -[g|z] < in > out");

	ret = hizip_init(alg_type);
	SYS_ERR_COND(ret, "hizip init fail\n");

	hizip_deflate(stdin, stdout, alg_type);

	hizip_fini();
	return EXIT_SUCCESS;
}
