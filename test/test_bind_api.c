// SPDX-License-Identifier: GPL-2.0+
/*
 * Test the IOMMU SVA infrastructure of the Linux kernel.
 * - what happens when a process bound to a device is killed
 * - what happens on fork
 * - multiple threads binding to the same device
 */
#include <signal.h>
#include <sys/types.h>

#include "test_lib.h"

/*
 * I observed a worst case of 1.041x expansion with random data, but let's say 2
 * just in case. TODO: reduce this
 */
#define EXPANSION_RATIO	2

struct hizip_priv {
	struct test_options *opts;
	char *in_buf;
	char *out_buf;
	unsigned long total_len;
	struct hisi_zip_sqe *msgs;
};

static void hizip_wd_sched_init_cache(struct wd_scheduler *sched, int i)
{
	struct wd_msg *wd_msg = &sched->msgs[i];
	struct hisi_zip_sqe *msg;
	struct hizip_priv *priv = sched->priv;

	msg = wd_msg->msg = &priv->msgs[i];

	if (priv->opts->alg_type == ZLIB)
		msg->dw9 = HW_ZLIB;
	else
		msg->dw9 = HW_GZIP;
	msg->dest_avail_out = sched->msg_data_size * EXPANSION_RATIO;

	/*
	 * This test doesn't use the data_in and data_out prepared by
	 * wd_sched_init. Instead we ask the zip device to directly work on our
	 * buffers to avoid a memcpy.
	 * TODO: don't alloc buffers
	 */
}

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

static int hizip_wd_sched_input(struct wd_msg *msg, void *priv)
{
	size_t i, j, ilen;
	char *in_buf, *out_buf;
	struct hisi_zip_sqe *m = msg->msg;
	struct hizip_priv *hizip_priv = priv;
	struct test_options *opts = hizip_priv->opts;

	__u32 seed = 0;
	/*
	 * TODO: change state for each buffer, to make sure there is no TLB
	 * aliasing. Can we store the seed into priv_info?
	 */
	//__u32 seed = hizip_priv->state++;
	unsigned short rand_state[3] = {(seed >> 16) & 0xffff, seed & 0xffff, 0x330e};

	ilen = hizip_priv->total_len > opts->block_size ?
		opts->block_size : hizip_priv->total_len;

	in_buf = hizip_priv->in_buf;
	out_buf = hizip_priv->out_buf;

	/*
	 * Prepare the input buffer with a reproducible sequence of numbers.
	 * nrand48() returns a pseudo-random number in the interval [0; 2^31).
	 * It's not really possible to compress a pseudo-random stream using
	 * deflate, since it can't find any string repetition. As a result the
	 * output size is bigger, with a ratio of 1.041.
	 */
	for (i = 0; i < ilen; i += 4) {
		__u64 n = nrand48(rand_state);

		for (j = 0; j < 4 && i + j < ilen; j++)
			in_buf[i + j] = (n >> (8 * j)) & 0xff;
	}

	msg->data_in = in_buf;
	msg->data_out = out_buf;

	m->source_addr_l = (__u64)in_buf & 0xffffffff;
	m->source_addr_h = (__u64)in_buf >> 32;
	m->dest_addr_l = (__u64)out_buf & 0xffffffff;
	m->dest_addr_h = (__u64)out_buf >> 32;
	m->input_data_length = ilen;

	hizip_priv->in_buf += ilen;
	hizip_priv->out_buf += ilen * EXPANSION_RATIO;
	hizip_priv->total_len -= ilen;

	dbg_sqe("zip input", m);

	return 0;
}

struct check_rand_ctx {
	int off;
	unsigned long global_off;
	__u32 last;
	unsigned short state[3];
};

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
				WD_ERR("Invalid decompressed char at offet %lu: expected 0x%x != 0x%x\n",
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

static int hizip_wd_sched_output(struct wd_msg *msg, void *priv)
{
	struct hizip_priv *hizip_priv = priv;
	struct hisi_zip_sqe *m = msg->msg;
	__u32 status = m->dw3 & 0xff;
	__u32 type = m->dw9 & 0xff;
	int ret;

	__u32 seed = 0;
	struct check_rand_ctx rand_ctx = {
		.state = {(seed >> 16) & 0xffff, seed & 0xffff, 0x330e},
	};

	if (hizip_priv->opts->faults & INJECT_SIG_WORK)
		kill(0, SIGTERM);

	dbg_sqe("zip output", m);

	SYS_ERR_COND(status != 0 && status != 0x0d, "bad status (s=%d, t=%d)\n",
		     status, type);

	ret = hizip_check_output(msg->data_out, m->produced, hizip_check_rand,
				 &rand_ctx);
	if (ret)
		return ret;

	if (rand_ctx.global_off != m->consumed) {
		WD_ERR("Invalid output size %lu != %u\n", rand_ctx.global_off,
		       m->consumed);
		return -EINVAL;
	}

	return 0;
}

static struct test_ops test_ops = {
	.init_cache = hizip_wd_sched_init_cache,
	.input = hizip_wd_sched_input,
	.output = hizip_wd_sched_output,
};

static int run_test(struct test_options *opts)
{
	int flags;
	int ret = 0;
	void *in_buf, *out_buf;
	struct wd_scheduler sched = {0};
	struct hizip_priv hizip_priv = {0};

	hizip_priv.opts = opts;
	hizip_priv.msgs = calloc(opts->req_cache_num, sizeof(*hizip_priv.msgs));
	if (!hizip_priv.msgs)
		return -ENOMEM;

	hizip_priv.total_len = opts->total_len;

	in_buf = hizip_priv.in_buf = malloc(hizip_priv.total_len);
	if (!in_buf) {
		ret = -ENOMEM;
		goto out_with_msgs;
	}

	out_buf = hizip_priv.out_buf = malloc(hizip_priv.total_len * EXPANSION_RATIO);
	if (!out_buf) {
		ret = -ENOMEM;
		goto out_with_in_buf;
	}

	ret = hizip_test_init(&sched, opts, &test_ops, &hizip_priv);
	if (ret) {
		WD_ERR("hizip init fail with %d\n", ret);
		goto out_with_out_buf;
	}

	flags = sched.qs[0].dev_flags;
	if (!(flags & UACCE_DEV_SVA) || (flags & UACCE_DEV_NOIOMMU)) {
		ret = -ENODEV;
		WD_ERR("This test requires SVA to be supported\n");
		goto out_with_out_buf;
	}

	if (opts->faults & INJECT_SIG_BIND)
		kill(0, SIGTERM);

	while (hizip_priv.total_len || !wd_sched_empty(&sched)) {
		dbg("request loop: total_len=%d\n", hizip_priv.total_len);
		ret = wd_sched_work(&sched, hizip_priv.total_len);
		if (ret < 0) {
			WD_ERR("wd_sched_work: %d\n", ret);
			break;
		}
	}

	hizip_test_fini(&sched);
out_with_out_buf:
	free(out_buf);
out_with_in_buf:
	free(in_buf);
out_with_msgs:
	free(hizip_priv.msgs);
	return ret;
}

int main(int argc, char **argv)
{
	int opt;
	int show_help = 0;
	struct test_options opts = {
		.alg_type	= GZIP,
		.op_type	= DEFLATE,
		.req_cache_num	= 4,
		.q_num		= 1,
		.block_size	= 512000,
		.total_len	= opts.block_size * 10,
	};

	while ((opt = getopt(argc, argv, "hb:k:s:q:")) != -1) {
		switch (opt) {
		case 'b':
			opts.block_size = atoi(optarg);
			if (opts.block_size  <= 0)
				show_help = 1;
			break;
		case 'k':
			switch (optarg[0]) {
			case 'b':
				opts.faults |= INJECT_SIG_BIND;
				break;
			case 'w':
				opts.faults |= INJECT_SIG_WORK;
				break;
			default:
				SYS_ERR_COND(1, "invalid argument to -k: '%s'\n", optarg);
				break;
			}
			break;
		case 'q':
			opts.q_num = atoi(optarg);
			if (opts.q_num <= 0)
				show_help = 1;
			break;
		case 's':
			opts.total_len = atoi(optarg);
			SYS_ERR_COND(opts.total_len <= 0, "invalid size '%s'\n", optarg);
			break;
		default:
			show_help = 1;
			break;
		}
	}

	/*
	 * Align size to the next block. We allow non-power-of-two block sizes.
	 */
	opts.total_len = (opts.total_len + opts.block_size - 1) /
			 opts.block_size * opts.block_size;

	SYS_ERR_COND(show_help || optind > argc,
		     "test_bind_api [opts]\n"
		     "  -b <size>     block size\n"
		     "  -k <mode>     kill thread\n"
		     "                  'bind' kills the process after bind\n"
		     "                  'work' kills the process while the queue is working\n"
		     "  -q <num>      number of queues\n"
		     "  -s <size>     total size\n"
		    );

	return run_test(&opts);
}
