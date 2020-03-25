#include <signal.h>
#include <sys/mman.h>

#include "test_lib.h"
#include "drv/hisi_qm_udrv.h"

struct check_rand_ctx {
	int off;
	unsigned long global_off;
	__u32 last;
	unsigned short state[3];
};

#ifdef DEBUG_LOG
static void dbg_sqe(const char *head, struct hisi_zip_sqe *m)
{
	fprintf(stderr,
		"=== %s ===\n"
		"cons=0x%x prod=0x%x in=0x%x out=0x%x comp=0x%x\n"
		"lba=0x%08x 0x%08x\n"
		"dw3=0x%x dw7=0x%x dw8=0x%x dw9=0x%x dw10=0x%x dw12=0x%x\n"
		"priv=0x%x tag=0x%x\n"
		"ctx dw0=0x%x dw1=0x%x dw2=0x%x\n"
		"comp head addr=0x%08x 0x%08x\n"
		"source addr=0x%08x 0x%08x\n"
		"dest addr=0x%08x 0x%08x\n"
		"stream ctx addr=0x%08x 0x%08x\n"
		"cipher key1 addr=0x%08x 0x%08x\n"
		"cipher key2 addr=0x%08x 0x%08x\n"
		"isize=0x%x checksum=0x%x\n"
		"=== === === ===\n",

		head,
		m->consumed, m->produced, m->input_data_length,
		m->dest_avail_out, m->comp_data_length,
		m->lba_h, m->lba_l,
		m->dw3, m->dw7, m->dw8, m->dw9, m->dw10, m->dw12,
		m->priv_info, m->tag,
		m->ctx_dw0, m->ctx_dw1, m->ctx_dw2,
		m->comp_head_addr_h, m->comp_head_addr_l,
		m->source_addr_h, m->source_addr_l,
		m->dest_addr_h, m->dest_addr_l,
		m->stream_ctx_addr_h, m->stream_ctx_addr_l,
		m->cipher_key1_addr_h, m->cipher_key1_addr_l,
		m->cipher_key2_addr_h, m->cipher_key2_addr_l,
		m->isize, m->checksum
	       );
}
#else
#define dbg_sqe(...)
#endif

void *mmap_alloc(size_t len)
{
	void *p;
	long page_size = sysconf(_SC_PAGESIZE);

	if (len % page_size) {
		WD_ERR("unaligned allocation must use malloc\n");
		return NULL;
	}

	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
		 -1, 0);
	if (p == MAP_FAILED)
		WD_ERR("Failed to allocate %zu bytes\n", len);

	return p == MAP_FAILED ? NULL : p;
}

void hizip_test_default_init_cache(struct wd_scheduler *sched, int i,
				   void *priv)
{
	struct wd_msg *wd_msg = &sched->msgs[i];
	struct hizip_test_context *ctx = priv;
	struct hisi_zip_sqe *msg;

	msg = wd_msg->msg = &ctx->msgs[i];

	if (ctx->opts->alg_type == ZLIB)
		msg->dw9 = HW_ZLIB;
	else
		msg->dw9 = HW_GZIP;
	msg->dest_avail_out = sched->msg_data_size;

	/*
	 * This test doesn't use the data_in and data_out prepared by
	 * wd_sched_init. Instead we ask the zip device to directly work on our
	 * buffers to avoid a memcpy.
	 * TODO: don't alloc buffers
	 */

	if (!(ctx->flags & UACCE_DEV_SVA)) {
		void *data_in, *data_out;

		data_in = wd_get_pa_from_va(&sched->qs[0], wd_msg->data_in);
		data_out = wd_get_pa_from_va(&sched->qs[0], wd_msg->data_out);

		msg->source_addr_l = (__u64)data_in & 0xffffffff;
		msg->source_addr_h = (__u64)data_in >> 32;
		msg->dest_addr_l = (__u64)data_out & 0xffffffff;
		msg->dest_addr_h = (__u64)data_out >> 32;
	}
}

int hizip_test_default_input(struct wd_msg *msg, void *priv)
{
	size_t ilen;
	char *in_buf, *out_buf;
	struct hisi_zip_sqe *m = msg->msg;
	struct hizip_test_context *ctx = priv;
	struct test_options *opts = ctx->opts;

	ilen = ctx->total_len > opts->block_size ?
		opts->block_size : ctx->total_len;

	in_buf = ctx->in_buf;
	out_buf = ctx->out_buf;

	if (!(ctx->flags & UACCE_DEV_SVA)) {
		memcpy(msg->data_in, in_buf, ilen);
	} else {
		msg->data_in = in_buf;
		msg->data_out = out_buf;

		m->source_addr_l = (__u64)in_buf & 0xffffffff;
		m->source_addr_h = (__u64)in_buf >> 32;
		m->dest_addr_l = (__u64)out_buf & 0xffffffff;
		m->dest_addr_h = (__u64)out_buf >> 32;

		ctx->out_buf += ilen * EXPANSION_RATIO;
	}

	m->input_data_length = ilen;
	ctx->in_buf += ilen;
	ctx->total_len -= ilen;

	dbg_sqe("zip input", m);

	return 0;
}

int hizip_test_default_output(struct wd_msg *msg, void *priv)
{
	struct hizip_test_context *ctx = priv;
	struct hisi_zip_sqe *m = msg->msg;
	__u32 status = m->dw3 & 0xff;
	__u32 type = m->dw9 & 0xff;

	if (ctx->opts->faults & INJECT_SIG_WORK)
		kill(getpid(), SIGTERM);

	dbg_sqe("zip output", m);

	SYS_ERR_COND(status != 0 && status != 0x0d, "bad status (s=%d, t=%d)\n",
		     status, type);

	ctx->total_out += m->produced;
	return 0;
}

struct test_ops default_test_ops = {
	.init_cache = hizip_test_default_init_cache,
	.input = hizip_test_default_input,
	.output = hizip_test_default_output,
};

void hizip_prepare_random_input_data(struct hizip_test_context *ctx)
{
	__u32 seed = 0;
	unsigned short rand_state[3] = {(seed >> 16) & 0xffff, seed & 0xffff, 0x330e};

	unsigned long remain_size;
	__u32 block_size, size;
	char *in_buf;
	size_t i, j;

	/*
	 * TODO: change state for each buffer, to make sure there is no TLB
	 * aliasing. Can we store the seed into priv_info?
	 */
	//__u32 seed = ctx->state++;
	block_size = ctx->opts->block_size;
	remain_size = ctx->total_len;
	in_buf = ctx->in_buf;

	while (remain_size > 0) {
		if (remain_size > block_size)
			size = block_size;
		else
			size = remain_size;
		/*
		 * Prepare the input buffer with a reproducible sequence of
		 * numbers. nrand48() returns a pseudo-random number in the
		 * interval [0; 2^31). It's not really possible to compress a
		 * pseudo-random stream using deflate, since it can't find any
		 * string repetition. As a result the output size is bigger,
		 * with a ratio of 1.041.
		 */
		for (i = 0; i < size; i += 4) {
			__u64 n = nrand48(rand_state);

			for (j = 0; j < 4 && i + j < size; j++)
				in_buf[i + j] = (n >> (8 * j)) & 0xff;
		}

		in_buf += size;
		remain_size -= size;
	}
}

static int hizip_check_rand(unsigned char *buf, unsigned int size, void *opaque)
{
	int i;
	int *j;
	__u32 n;
	struct check_rand_ctx *rand_ctx = opaque;

	j = &rand_ctx->off;
	for (i = 0; i < size; i += 4) {
		if (*j) {
			/* Somthing left from a previous run */
			n = rand_ctx->last;
		} else {
			n = nrand48(rand_ctx->state);
			rand_ctx->last = n;
		}
		for (; *j < 4 && i + *j < size; (*j)++) {
			char expected = (n >> (8 * *j)) & 0xff;
			char actual = buf[i + *j];

			if (expected != actual) {
				WD_ERR("Invalid decompressed char at offset %lu: expected 0x%x != 0x%x\n",
				       rand_ctx->global_off + i + *j, expected,
				       actual);
				return -EINVAL;
			}
		}
		if (*j == 4)
			*j = 0;
	}
	rand_ctx->global_off += size;
	return 0;
}

int hizip_verify_random_output(char *out_buf, struct test_options *opts,
			       struct hizip_test_context *ctx)
{
	int ret;
	int seed = 0;
	off_t off = 0;
	size_t checked = 0;
	size_t total_checked = 0;
	struct check_rand_ctx rand_ctx = {
		.state = {(seed >> 16) & 0xffff, seed & 0xffff, 0x330e},
	};

	if (!opts->verify)
		return 0;

	do {
		ret = hizip_check_output(out_buf + off, ctx->total_out,
					 &checked, hizip_check_rand, &rand_ctx);
		if (ret) {
			WD_ERR("Check output failed with %d\n", ret);
			return ret;
		}
		total_checked += checked;
		off += opts->block_size * EXPANSION_RATIO;
	} while (!ret && total_checked < opts->total_len);

	if (rand_ctx.global_off != opts->total_len) {
		WD_ERR("Invalid output size %lu != %lu\n",
		       rand_ctx.global_off, opts->total_len);
		return -EINVAL;
	}
	return 0;
}

/*
 * Initialize the scheduler with the given options and operations.
 */
int hizip_test_init(struct wd_scheduler *sched, struct test_options *opts,
		    struct test_ops *ops, void *priv)
{
	int ret = -ENOMEM, i;
	char *alg;
	struct hisi_qm_priv *qm_priv;

	sched->q_num = opts->q_num;
	sched->ss_region_size = 0; /* let system make decision */
	sched->msg_cache_num = opts->req_cache_num;
	/* use twice the size of the input data, hope it is enough for output */
	sched->msg_data_size = opts->block_size * EXPANSION_RATIO;

	sched->priv = priv;
	sched->init_cache = ops->init_cache;
	sched->input = ops->input;
	sched->output = ops->output;

	sched->qs = calloc(opts->q_num, sizeof(*sched->qs));
	if (!sched->qs)
		return -ENOMEM;

	if (opts->alg_type == ZLIB)
		alg = "zlib";
	else
		alg = "gzip";

	for (i = 0; i < opts->q_num; i++) {
		sched->qs[i].capa.alg = alg;
		qm_priv = (struct hisi_qm_priv *)sched->qs[i].capa.priv;
		qm_priv->sqe_size = sizeof(struct hisi_zip_sqe);
		qm_priv->op_type = opts->op_type;
	}
	ret = wd_sched_init(sched);
	if (ret)
		goto err_with_qs;

	return 0;

err_with_qs:
	free(sched->qs);
	return ret;
}

int hizip_test_sched(struct wd_scheduler *sched, struct test_options *opts,
		     struct hizip_test_context *ctx)
{
	int ret = 0;

	while (ctx->total_len || !wd_sched_empty(sched)) {
		dbg("request loop: total_len=%d\n", ctx->total_len);
		ret = wd_sched_work(sched, ctx->total_len);
		if (ret < 0) {
			WD_ERR("wd_sched_work: %d\n", ret);
			break;
		}
	}

	return ret;
}

/*
 * Release the scheduler
 */
void hizip_test_fini(struct wd_scheduler *sched, struct test_options *opts)
{
	wd_sched_fini(sched);
	free(sched->qs);
}

int parse_common_option(const char opt, const char *optarg,
			struct test_options *opts)
{
	switch (opt) {
	case 'b':
		opts->block_size = strtol(optarg, NULL, 0);
		if (opts->block_size <= 0)
			return 1;
		break;
	case 'k':
		switch (optarg[0]) {
		case 'b':
			opts->faults |= INJECT_SIG_BIND;
			break;
		case 'w':
			opts->faults |= INJECT_SIG_WORK;
			break;
		default:
			SYS_ERR_COND(1, "invalid argument to -k: '%s'\n", optarg);
			break;
		}
		break;
	case 'c':
		opts->req_cache_num = strtol(optarg, NULL, 0);
		if (opts->req_cache_num <= 0)
			return 1;
		break;
	case 'n':
		opts->run_num = strtol(optarg, NULL, 0);
		SYS_ERR_COND(opts->run_num > MAX_RUNS,
			     "No more than %d runs supported\n", MAX_RUNS);
		if (opts->run_num <= 0)
			return 1;
		break;
	case 'q':
		opts->q_num = strtol(optarg, NULL, 0);
		if (opts->q_num <= 0)
			return 1;
		break;
	case 's':
		opts->total_len = strtol(optarg, NULL, 0);
		SYS_ERR_COND(opts->total_len <= 0, "invalid size '%s'\n",
			     optarg);
		break;
	case 'V':
		opts->verify = true;
		break;
	case 'v':
		opts->verbose = true;
		break;
	case 'z':
		opts->alg_type = ZLIB;
		break;
	default:
		return 1;
	}

	return 0;
}
