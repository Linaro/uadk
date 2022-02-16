#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <math.h>
#include <sys/stat.h>

#include "wd_alg_common.h"
#include "wd_comp.h"
#include "wd_sched.h"

#define SCHED_RR_NAME		"sched_rr"

#define CTX_SET_NUM		1
#define CTX_SET_SIZE		4
#define MAX_ALG_LEN		32
#define MAX_THREAD		1024

#define no_argument		0
#define required_argument	1
#define optional_argument	2

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

static struct request_config config = {
	.complv = WD_COMP_L8,
	.optype = WD_DIR_COMPRESS,
	.winsize = WD_COMP_WS_8K,
	.request_mode = CTX_MODE_SYNC,
	.buftype = WD_FLAT_BUF,
};

static struct request_data data;

static struct acc_alg_item alg_options[] = {
	{"zlib", WD_ZLIB},
	{"gzip", WD_GZIP},
	{"deflate", WD_DEFLATE},
	{"lz77_zstd", WD_LZ77_ZSTD},
	{"", WD_COMP_ALG_MAX}
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
		printf("%s fail to alloc sched.\n", __func__);
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
		fprintf(stderr, "%s fail to init ctx!\n", __func__);
		return ret;
	}

	ret = uadk_comp_sess_init();
	if (ret) {
		fprintf(stderr, "%s fail to init sess!\n", __func__);
		goto out_ctx_uninit;
	}

	ret = uadk_comp_request_init(source);
	if (ret) {
		fprintf(stderr, "%s fail to init request!\n", __func__);
		goto out_sess_uninit;
	}

	ret = uadk_do_comp();
	if (ret) {
		fprintf(stderr, "%s fail to do request!\n", __func__);
		goto out_sess_uninit;
	}

	ret = uadk_comp_write_file(dest);
	if (ret)
		fprintf(stderr, "%s fail to write result!\n", __func__);

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
	int option_index = 0;
	int help = 0;
	int ret, c;

	static struct option long_options[] = {
		{"help", no_argument, 0, 0},
		{"alg", required_argument, 0, 1},
		{"complv", required_argument, 0, 2},
		{"optype", required_argument, 0, 3},
		{"winsize", required_argument, 0, 4},
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
				cowfail("Can't find your algorithm!\n");
				help = 1;
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
		default:
			help = 1;
			cowfail("bad input test parameter!\n");
			break;
		}
	}

	if (help) {
		print_help();
		exit(-1);
	}

	ret = operation(stdin, stdout);
	if (ret)
		cowfail("So sad for we do something wrong!\n");

	return ret;
}
