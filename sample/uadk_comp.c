#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <math.h>
#include <sys/stat.h>

#include "wd_alg_common.h"
#include "wd_comp.h"
#include "wd_sched.h"
#include "wd_zlibwrapper.h"

#define SCHED_RR_NAME		"sched_rr"

#define CTX_SET_NUM		1
#define CTX_SET_SIZE		4
#define MAX_ALG_LEN		32
#define MAX_THREAD		1024

#define no_argument		0
#define required_argument	1
#define optional_argument	2

#define MAX_THREAD		1024

struct request_config {
	char algname[MAX_ALG_LEN];
	enum wd_comp_alg_type alg;
	enum wd_comp_level complv;
	enum wd_comp_op_type optype;
	enum wd_comp_winsz_type winsize;
	enum wd_ctx_mode request_mode;
	enum wd_buff_type buftype;
	struct wd_ctx_config ctx;
	struct wd_sched *sched;
	struct uacce_dev_list *list;
};

struct request_data {
	handle_t h_sess;
	struct wd_comp_req req;
};

struct acc_alg_item {
	char *name;
	int alg;
};

struct comp_sample_data {
	int size;
	char data[128];
};

static struct request_config config = {
	.complv = WD_COMP_L8,
	.optype = WD_DIR_COMPRESS,
	.winsize = WD_COMP_WS_8K,
	.request_mode = CTX_MODE_SYNC,
	.buftype = WD_FLAT_BUF,
};

static struct request_data data;

static pthread_t threads[MAX_THREAD];

static struct acc_alg_item alg_options[] = {
	{"zlib", WD_ZLIB},
	{"gzip", WD_GZIP},
	{"deflate", WD_DEFLATE},
	{"lz77_zstd", WD_LZ77_ZSTD},
	{"", WD_COMP_ALG_MAX}
};

static struct comp_sample_data sample_data = {
	.size = 20,
	.data = "Welcome to use uadk!",
};

static void cowfail(char *s)
{
	fprintf(stderr, ""
		"__________________________________\n\n"
		"%s"
		"\n----------------------------------\n"
		"\t        \\   ^__^\n"
		"\t         \\  (oo)\\_______\n"
		"\t            (__)\\       )\\\\\n"
		"\t                ||----w |\n"
		"\t                ||     ||\n"
		"\n", s);
}

static void *initthread(void *data)
{
	int ret;

	ret = wd_comp_init2("zlib", 0, TASK_HW);
	if (ret)
		fprintf(stderr, "%s: something is wrong, ret = %d!", __func__, ret);

	return NULL;
}

static int test_fork(void)
{
	int ret;

	pthread_create(&threads[0], NULL, initthread, NULL);

	sleep(2);
	ret = fork();
	if (ret == 0)
		ret = wd_comp_init2("zlib", 0, TASK_HW);
	else
		ret = pthread_join(threads[0], NULL);

	wd_comp_uninit2();

	return ret;
}

static int test_uadk_init2(void)
{
	struct wd_comp_sess_setup setup[2] = {0};
	struct sched_params param[2] = {0};
	struct wd_comp_req req[2] = {0};
	handle_t h_sess[2];
	void *src, *dst;
	int ret;

	ret = wd_comp_init2("zlib", 0, TASK_HW);
	if (ret)
		return ret;

	setup[0].alg_type = WD_ZLIB;
	setup[0].op_type = WD_DIR_COMPRESS;
	setup[0].comp_lv = 1;
	setup[0].win_sz = 1;
	param[0].type = WD_DIR_COMPRESS;
	setup[0].sched_param = &param[0];

	h_sess[0] = wd_comp_alloc_sess(&setup[0]);
	if (!h_sess[0]) {
		fprintf(stderr, "%s fail to alloc comp sess.\n", __func__);
		ret = -WD_EINVAL;
		goto out_uninit;
	}

	setup[1].alg_type = WD_ZLIB;
	setup[1].op_type = WD_DIR_DECOMPRESS;
	setup[1].comp_lv = 1;
	setup[1].win_sz = 1;
	param[1].type = WD_DIR_DECOMPRESS;
	setup[1].sched_param = &param[1];
	h_sess[1] = wd_comp_alloc_sess(&setup[1]);
	if (!h_sess[1]) {
		fprintf(stderr, "%s fail to alloc decomp sess.\n", __func__);
		ret = -WD_EINVAL;
		goto out_free_comp_sess;
	}

	src = calloc(1, sizeof(char) * 128);
	if (!src) {
		ret = -WD_ENOMEM;
		goto out_free_decomp_sess;
	}

	dst = calloc(1, sizeof(char) * 128);
	if (!dst) {
		ret = -WD_ENOMEM;
		goto out_free_src;
	}

	req[0].src = sample_data.data;
	req[0].src_len = sample_data.size;
	req[0].op_type = WD_DIR_COMPRESS;
	req[0].dst = dst;
	req[0].dst_len = 128;

	ret = wd_do_comp_sync(h_sess[0], &req[0]);
	if (ret)
		goto out_free_dst;

	req[1].src = dst;
	req[1].src_len = req[0].dst_len;
	req[1].op_type = WD_DIR_DECOMPRESS;
	req[1].dst = src;
	req[1].dst_len = 128;

	ret = wd_do_comp_sync(h_sess[1], &req[1]);

	ret = strcmp(sample_data.data, src);
	if (ret)
		fprintf(stderr, "decompress fail\n");
	else
		fprintf(stderr, "good\n");

out_free_dst:
	free(dst);
out_free_src:
	free(src);
out_free_decomp_sess:
	wd_comp_free_sess(h_sess[1]);
out_free_comp_sess:
	wd_comp_free_sess(h_sess[0]);
out_uninit:
	wd_comp_uninit2();
	return ret;
}

static int test_uadk_zlib_deflate(void *src, int src_len, void *dest, int dst_len)
{
	__u32 chunk = 128 * 1024;
	z_stream zstrm = {0};
	int ret, flush, have;

	ret = wd_comp_init2("zlib", 0, TASK_HW);
	if (ret) {
		fprintf(stderr, "%s fail to init wd_comp.\n", __func__);
		return ret;
	}

	ret = wd_deflate_init(&zstrm, 0, 15);
	if (ret) {
		fprintf(stderr, "%s fail to init deflate.\n", __func__);
		return ret;
	}

	zstrm.next_in = src;
	do {
		if (src_len > chunk) {
			zstrm.avail_in = chunk;
			src_len -= chunk;
		} else {
			zstrm.avail_in = src_len;
			src_len = 0;
		}

		flush = src_len ? Z_SYNC_FLUSH : Z_FINISH;

		/*
		 * Run wd_deflate() on input until output buffer not full,
		 * finish compression if all of source has been read in.
		 */
		do {
			zstrm.avail_out = chunk;
			zstrm.next_out = dest;
			ret = wd_deflate(&zstrm, flush);
			have = chunk - zstrm.avail_out;
			dest += have;
		} while (zstrm.avail_in > 0);

		/* done when last data in file processed */
	} while (flush != Z_FINISH);

	ret = ret == Z_STREAM_END ? zstrm.total_out : ret;

	(void)wd_deflate_end(&zstrm);

	return ret;
}

static int test_uadk_zlib_inflate(void *src, int src_len, void *dest, int dst_len)
{
	__u32 chunk = 128 * 1024;
	// __u32 chunk = 1024 * 1024 * 2;
	z_stream zstrm = {0};
	int ret, have;

	ret = wd_inflate_init(&zstrm, 15);
	if (ret) {
		fprintf(stderr, "%s fail to init inflate.\n", __func__);
		return ret;
	}

	zstrm.next_in = src;
	do {
		if (src_len > chunk) {
			zstrm.avail_in = chunk;
			src_len -= chunk;
		} else {
			zstrm.avail_in = src_len;
			src_len = 0;
		}
		/*
		 * Run wd_deflate() on input until output buffer not full,
		 * finish compression if all of source has been read in.
		 */
		do {
			zstrm.avail_out = chunk;
			zstrm.next_out = dest;
			ret = wd_inflate(&zstrm, Z_SYNC_FLUSH);
			have = chunk - zstrm.avail_out;
			dest += have;
		} while (zstrm.avail_in > 0);

		/* done when last data in file processed */
	} while (ret != Z_STREAM_END);

	ret = ret == Z_STREAM_END ? zstrm.total_out : ret;

	(void)wd_inflate_end(&zstrm);

	return ret;
}

static int test_uadk_zlib(void)
{
	void *src, *dst, *src2;
	FILE *source = stdin;
	FILE *dest = stdout;
	int ret, fd, sz;
	struct stat s;

	fd = fileno(source);
	ret = fstat(fd, &s);
	if (ret < 0) {
		fprintf(stderr, "%s fstat error!\n", __func__);
		return ret;
	}

	src = calloc(1, sizeof(char) * s.st_size);
	if (!src) {
		fprintf(stderr, "%s calloc error!\n", __func__);
		return -WD_ENOMEM;
	}

	src2 = calloc(1, sizeof(char) * s.st_size * 2);
	if (!src2) {
		fprintf(stderr, "%s calloc2 error!\n", __func__);
		ret = -WD_ENOMEM;
		goto free_src;
	}

	dst = calloc(1, sizeof(char) * s.st_size * 2);
	if (!dst) {
		fprintf(stderr, "%s calloc error!\n", __func__);
		ret = -WD_ENOMEM;
		goto free_src2;
	}

	sz = fread(src, 1, s.st_size, source);
	if (sz != s.st_size) {
		fprintf(stderr, "%s read file sz != file.size!\n", __func__);
		ret = -WD_EINVAL;
		goto free_dst;
	}

	ret = test_uadk_zlib_deflate(src, sz, dst, sz * 2);
	if (ret < 0) {
		fprintf(stderr, "%s do deflate fail ret %d\n", __func__, ret);
		goto free_dst;
	}

	ret = fwrite(dst, 1, ret, dest);
	if (ret < 0)
		fprintf(stderr, "%s file write fail ret %d\n", __func__, ret);

	ret = test_uadk_zlib_inflate(dst, ret, src2, sz * 2);
	if (ret < 0) {
		fprintf(stderr, "%s do inflate fail ret %d\n", __func__, ret);
		goto free_dst;
	}

	ret = memcmp(src, src2, sz);
	if (!ret)
		fprintf(stderr, "%s good!\n", __func__);

free_dst:
	free(dst);
free_src2:
	free(src2);
free_src:
	free(src);
	return ret;
}

static int test_func(int test_mode)
{
	int ret;

	switch (test_mode) {
	case 0:
		ret = test_fork();
		break;
	case 1:
		ret = test_uadk_init2();
		break;
	case 2:
		ret = test_uadk_zlib();
		break;
	default:
		ret = -WD_EINVAL;
		break;
	}

	return ret;
}

static struct uacce_dev_list* get_dev_list(char *alg_name)
{
	struct uacce_dev_list *list, *p, *head = NULL, *prev = NULL;
	int ctx_set_num = CTX_SET_NUM;
	int max_ctx_num;
	int i;

	for (i = 0; i < ARRAY_SIZE(alg_options); i++)
		if (!strcmp(alg_name, alg_options[i].name))
			config.alg = alg_options[i].alg;

	list = wd_get_accel_list(alg_name);
	if (!list)
		return NULL;

	p = list;
	/* Find one device matching the requested contexts. */
	while (p) {
		max_ctx_num = wd_get_avail_ctx(p->dev);
		/*
		 * Check whether there's enough contexts.
		 * There may be multiple taskes running together.
		 * The number of multiple taskes is specified in children.
		 */
		if (max_ctx_num < ctx_set_num * CTX_SET_SIZE) {
			if (!head)
				head = p;
			prev = p;
			p = p->next;
		} else
			break;
	}

	if (!p) {
		fprintf(stderr, "%s request too much contexts: %d.\n",
			__func__, ctx_set_num);
		goto out;
	}

	/* Adjust p to the head of list if p is in the middle. */
	if (p && (p != list)) {
		prev->next = p->next;
		p->next = head;
		return p;
	}

	return list;

out:
	wd_free_list_accels(list);
	return NULL;
}

static int lib_poll_func(__u32 pos, __u32 expect, __u32 *count)
{
	int ret;

	ret = wd_comp_poll_ctx(pos, expect, count);
	if (ret < 0)
		return ret;

	return 0;
}

static struct wd_sched *uadk_comp_sched_init(void)
{
	int ctx_set_num = CTX_SET_NUM;
	struct sched_params param;
	struct wd_sched *sched;
	int i, j, ret;

	sched = wd_sched_rr_alloc(SCHED_POLICY_RR, 2, 2, lib_poll_func);
	if (!sched) {
		fprintf(stderr, "%s fail to alloc sched.\n", __func__);
		return NULL;
	}
	sched->name = SCHED_RR_NAME;

	/*
	 * All contexts for 2 modes & 2 types.
	 * The test only uses one kind of contexts at the same time.
	 */
	for (i = 0; i < CTX_SET_SIZE; i++) {
		for (j = ctx_set_num * i; j < ctx_set_num * (i + 1); j++) {
			param.mode = i / 2;
			param.type = i % 2;
			param.numa_id = 0;
			param.begin = ctx_set_num * i;
			param.end = ctx_set_num * (i + 1) - 1;
			ret = wd_sched_rr_instance(sched, &param);
			if (ret < 0) {
				fprintf(stderr, "%s fail to fill sched region.\n",
					__func__);
				goto out_free_sched;
			}
		}
	}

	return sched;

out_free_sched:
	wd_sched_rr_release(sched);

	return NULL;
}

static int uadk_comp_ctx_init(void)
{
	struct wd_ctx_config *ctx = &config.ctx;
	int ctx_set_num = CTX_SET_NUM;
	struct wd_sched *sched;
	int i, j, ret;

	memset(ctx, 0, sizeof(struct wd_ctx_config));
	ctx->ctx_num = ctx_set_num * CTX_SET_SIZE;
	ctx->ctxs = calloc(ctx_set_num * CTX_SET_SIZE, sizeof(struct wd_ctx));
	if (!ctx->ctxs) {
		fprintf(stderr, "%s fail to allocate contexts.\n", __func__);
		return -WD_ENOMEM;
	}

	for (i = 0; i < CTX_SET_SIZE; i++) {
		for (j = ctx_set_num * i; j < ctx_set_num * (i + 1); j++) {
			ctx->ctxs[j].ctx = wd_request_ctx(config.list->dev);
			if (!ctx->ctxs[j].ctx) {
				fprintf(stderr, "%s fail to request context #%d.\n",
					__func__, i);
				ret = -WD_EINVAL;
				goto out_free_ctx;
			}
			ctx->ctxs[j].ctx_mode = i / 2;
			ctx->ctxs[j].op_type = i % 2;
		}
	}

	sched = uadk_comp_sched_init();
	if (!sched) {
		ret = -WD_EINVAL;
		goto out_free_ctx;
	}

	config.sched = sched;

	ret = wd_comp_init(ctx, sched);
	if (ret) {
		fprintf(stderr, "%s fail to init comp.\n", __func__);
		goto out_free_sched;
	}

	return 0;

out_free_sched:
	wd_sched_rr_release(sched);

out_free_ctx:
	for (i = 0; i < ctx->ctx_num; i++)
		if (ctx->ctxs[i].ctx)
			wd_release_ctx(ctx->ctxs[i].ctx);
	free(ctx->ctxs);

	return ret;
}

static void uadk_comp_ctx_uninit(void)
{
	struct wd_ctx_config *ctx = &config.ctx;
	int i;

	wd_comp_uninit();

	for (i = 0; i < ctx->ctx_num; i++)
		wd_release_ctx(ctx->ctxs[i].ctx);

	wd_free_list_accels(config.list);
	wd_sched_rr_release(config.sched);
}

static int uadk_comp_sess_init(void)
{
	struct wd_comp_sess_setup setup = {0};
	struct sched_params param = {0};
	handle_t h_sess;
	int ret = 0;

	setup.alg_type = config.alg;
	setup.op_type = config.optype;
	setup.comp_lv = config.complv;
	setup.win_sz = config.winsize;
	param.type = config.optype;
	setup.sched_param = &param;

	h_sess = wd_comp_alloc_sess(&setup);
	if (!h_sess) {
		fprintf(stderr, "%s fail to alloc comp sess.\n", __func__);
		ret = -WD_EINVAL;
		goto out_free_sess;
	}
	data.h_sess = h_sess;

	return 0;

out_free_sess:
	wd_comp_free_sess(data.h_sess);

	return ret;
}

static void uadk_comp_sess_uninit(void)
{
	wd_comp_free_sess(data.h_sess);
}

static int uadk_req_buf_init(struct wd_comp_req *req, FILE *source)
{
	int src_len = req->src_len;
	int dst_len = req->dst_len;
	void *src, *dst;
	int ret;

	src = malloc(src_len);
	if (!src) {
		fprintf(stderr, "%s fail to alloc src.\n", __func__);
		return -WD_ENOMEM;
	}

	dst = malloc(dst_len);
	if (!dst) {
		fprintf(stderr, "%s fail to alloc dst.\n", __func__);
		ret = -WD_ENOMEM;
		goto out_free_src;
	}

	ret = fread(src, 1, src_len, source);
	if (ret != src_len) {
		fprintf(stderr, "%s fail to read stdin.\n", __func__);
		ret = -WD_ENOMEM;
		goto out_free_dst;
	}

	req->src = src;
	req->dst = dst;

	return 0;

out_free_dst:
	free(dst);

out_free_src:
	free(src);

	return ret;
}

static void uadk_req_buf_uninit(void)
{
	free(data.req.src);
	free(data.req.dst);
}

static int uadk_comp_request_init(FILE *source)
{
	struct wd_comp_req *req;
	struct stat fs;
	int fd, ret;

	fd = fileno(source);
	ret = fstat(fd, &fs);
	if (ret < 0) {
		fprintf(stderr, "%s fstat error.\n", __func__);
		return ret;
	}

	req = &data.req;
	req->op_type = config.optype;
	req->data_fmt = WD_FLAT_BUF;
	req->src_len = fs.st_size;
	req->dst_len = fs.st_size * 4;

	return uadk_req_buf_init(req, source);
}

static void uadk_comp_request_uninit(void)
{
	uadk_req_buf_uninit();
}

static int uadk_do_comp(void)
{
	int ret;

	ret = wd_do_comp_sync2(data.h_sess, &data.req);
	if (ret < 0)
		fprintf(stderr, "%s fail to do comp sync(ret = %d).\n", __func__, ret);

	return ret;
}

static int uadk_comp_write_file(FILE *dest)
{
	int size;

	size = fwrite(data.req.dst, 1, data.req.dst_len, dest);
	if (size < 0)
		return size;

	return 0;
}

static int operation(FILE *source, FILE *dest)
{
	int ret;

	ret = uadk_comp_ctx_init();
	if (ret) {
		fprintf(stderr, "%s fail to init ctx! %d\n", __func__, ret);
		return ret;
	}

	ret = uadk_comp_sess_init();
	if (ret) {
		fprintf(stderr, "%s fail to init sess! %d\n", __func__, ret);
		goto out_ctx_uninit;
	}

	ret = uadk_comp_request_init(source);
	if (ret) {
		fprintf(stderr, "%s fail to init request! %d\n", __func__, ret);
		goto out_sess_uninit;
	}

	ret = uadk_do_comp();
	if (ret) {
		fprintf(stderr, "%s fail to do request! %d\n", __func__, ret);
		goto out_sess_uninit;
	}

	ret = uadk_comp_write_file(dest);
	if (ret)
		fprintf(stderr, "%s fail to write result! %d\n", __func__, ret);

	uadk_comp_request_uninit();

out_sess_uninit:
	uadk_comp_sess_uninit();

out_ctx_uninit:
	uadk_comp_ctx_uninit();

	return ret;
}

static void print_help(void)
{
	fprintf(stderr, ""
		"uadk_comp - a tool used to do compress/decompress\n\n"
		"Arguments:\n"
		"\t[--alg]:          "
		"The name of the algorithm (can find under .../uacce/<dev>/algorithms)\n"
		"\t[--optype]:       "
		"Use 0/1 stand for compression/decompression.\n"
		"\t[--winsize]:       "
		"The window size for compression(8K as default).\n"
		"\t[--complv]:       "
		"The compression level(8 as default).\n"
		"\t[--help]          "
		"Print Help (this message) and exit\n"
		"");
}

int main(int argc, char *argv[])
{
	int ret, c, test_mode;
	int option_index = 0;
	int help = 0;
	int test = 0;

	static struct option long_options[] = {
		{"help", no_argument, 0, 0},
		{"alg", required_argument, 0, 1},
		{"complv", required_argument, 0, 2},
		{"optype", required_argument, 0, 3},
		{"winsize", required_argument, 0, 4},
		{"fork", no_argument, 0, 5},
		{"init2", no_argument, 0, 6},
		{"zlib", no_argument, 0, 7},
		{0, 0, 0, 0}
	};

	while (!help) {
		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			help = 1;
			break;
		case 1:
			config.list = get_dev_list(optarg);
			if (!config.list) {
				help = 1;
				cowfail("Can't find your algorithm!\n");
			} else {
				strcpy(config.algname, optarg);
			}
			break;
		case 2:
			config.complv = strtol(optarg, NULL, 0);
			break;
		case 3:
			config.optype = strtol(optarg, NULL, 0);
			break;
		case 4:
			config.winsize = strtol(optarg, NULL, 0);
			break;
		case 5:
			test = 1;
			test_mode = 0;
			break;
		case 6:
			test = 1;
			test_mode = 1;
			break;
		case 7:
			test = 1;
			test_mode = 2;
			break;
		default:
			help = 1;
			cowfail("Bad input test parameter!\n");
			break;
		}
	}

	if (help) {
		print_help();
		exit(-1);
	}

	if (test == 1)
		ret = test_func(test_mode);
	else
		ret = operation(stdin, stdout);

	if (ret)
		cowfail("So sad for someting wrong!\n");

	return ret;
}
