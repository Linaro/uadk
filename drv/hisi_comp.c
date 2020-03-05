/* SPDX-License-Identifier: Apache-2.0 */
#include "include/zip_usr_if.h"
#include "hisi_comp.h"
#include "hisi_qm_udrv.h"
#include "wd_sched.h"

#define BLOCK_SIZE	512000
#define CACHE_NUM	1	//4

#define ZLIB_HEADER	"\x78\x9c"
#define ZLIB_HEADER_SZ	2

/*
 * We use a extra field for gzip block length. So the fourth byte is \x04.
 * This is necessary because our software don't know the size of block when
 * using an hardware decompresser (It is known by hardware). This help our
 * decompresser to work and helpfully, compatible with gzip.
 */
#define GZIP_HEADER	"\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\x03"
#define GZIP_HEADER_SZ	10
#define GZIP_EXTRA_SZ	10
#define GZIP_TAIL_SZ	8

#define LOAD_SRC_TO_MSG(msg, src, idx, len)				\
	do {								\
		memcpy(msg, src + idx, len);				\
		idx += len;						\
	} while (0)

#define STORE_MSG_TO_DST(dst, idx, msg, len)				\
	do {								\
		memcpy(dst + idx, msg, len);				\
		idx += len;						\
	} while (0)

struct hisi_comp_sess {
	struct wd_ctx		ctx;
	struct wd_scheduler	sched;
};

struct hisi_sched {
	int	alg_type;
	int	op_type;
	int	dw9;
	int	total_len;
	struct hisi_zip_sqe	*msgs;
	struct wd_comp_arg	*arg;
	uint64_t	si;
	uint64_t	di;
	FILE	*sfile;
	FILE	*dfile;
};

static void hizip_init_cache(struct wd_scheduler *sched, int i)
{
	struct wd_msg	*wd_msg = &sched->msgs[i];
	struct hisi_zip_sqe	*msg;
	struct hisi_sched	*hpriv = sched->priv;

	msg = wd_msg->msg = &hpriv->msgs[i];
	msg->dw9 = hpriv->dw9;
	msg->dest_avail_out = sched->msg_data_size;
	msg->source_addr_l = (__u64)wd_msg->data_in & 0xffffffff;
	msg->source_addr_h = (__u64)wd_msg->data_in >> 32;
	msg->dest_addr_l = (__u64)wd_msg->data_out & 0xffffffff;
	msg->dest_addr_h = (__u64)wd_msg->data_out >> 32;
}

static int hizip_input(struct wd_msg *msg, void *priv)
{
	size_t	ilen, templen, real_len;
	struct hisi_zip_sqe	*m = msg->msg;
	struct hisi_sched	*hpriv = (struct hisi_sched *)priv;
	struct wd_comp_arg	*arg = hpriv->arg;

	ilen = arg->src_len > BLOCK_SIZE ? BLOCK_SIZE : arg->src_len;
	templen = ilen;
	arg->src_len -= ilen;
	if (hpriv->op_type == INFLATE) {
		if (hpriv->alg_type == ZLIB) {
			LOAD_SRC_TO_MSG(msg->data_in, arg->src,
					hpriv->si, ZLIB_HEADER_SZ);
			ilen -= ZLIB_HEADER_SZ;
		} else {
			LOAD_SRC_TO_MSG(msg->data_in, arg->src,
					hpriv->si, GZIP_HEADER_SZ);
			ilen -= GZIP_HEADER_SZ;
			if (*((char *)msg->data_in + 3) == 0x04) {
				LOAD_SRC_TO_MSG(msg->data_in, arg->src,
						hpriv->si, GZIP_EXTRA_SZ);
				memcpy(&ilen, msg->data_in + 6, 4);
				real_len = GZIP_HEADER_SZ + GZIP_EXTRA_SZ +
					   ilen;
				arg->src_len += templen - real_len;
			}
		}
	}

	LOAD_SRC_TO_MSG(msg->data_in, arg->src, hpriv->si, ilen);

	m->input_data_length = ilen;

	return 0;
}

static int hizip_output(struct wd_msg *msg, void *priv)
{
	struct hisi_zip_sqe *m = msg->msg;
	__u32 status = m->dw3 & 0xff;
	__u32 type = m->dw9 & 0xff;
	char gzip_extra[GZIP_EXTRA_SZ] = {0x08, 0x00, 0x48, 0x69, 0x04, 0x00,
					  0x00, 0x00, 0x00, 0x00};
	struct hisi_sched	*hpriv = (struct hisi_sched *)priv;

	if (status && (status != 0x0d)) {
		WD_ERR("bad status (s=%d, t=%d)\n", status, type);
		return -EFAULT;
	}
	if (hpriv->op_type == DEFLATE) {
		if (hpriv->alg_type == ZLIB) {
			STORE_MSG_TO_DST(hpriv->arg->dst, hpriv->di,
					 ZLIB_HEADER, ZLIB_HEADER_SZ);
		} else {
			STORE_MSG_TO_DST(hpriv->arg->dst, hpriv->di,
					 GZIP_HEADER, GZIP_HEADER_SZ);
			memcpy(gzip_extra + 6, &m->produced, 4);
			STORE_MSG_TO_DST(hpriv->arg->dst, hpriv->di,
					 gzip_extra, GZIP_EXTRA_SZ);
		}
	}
	STORE_MSG_TO_DST(hpriv->arg->dst, hpriv->di,
			 msg->data_out, m->produced);
	hpriv->arg->dst_len = hpriv->di;
	return 0;
}

int hisi_comp_init(struct wd_comp_sess *sess)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	struct hisi_sched	*sched_priv;
	int	ret = -EINVAL;

	priv = calloc(1, sizeof(struct hisi_comp_sess));
	if (!priv)
		return -ENOMEM;
	sess->priv = priv;
	sched = &priv->sched;
	sched->q_num = 1;
	sched->ss_region_size = 0; /* let system make decision */
	sched->msg_cache_num = CACHE_NUM;
	/* use double size of the input data */
	sched->msg_data_size = BLOCK_SIZE << 1;
	sched->init_cache = hizip_init_cache;
	sched->input = hizip_input;
	sched->output = hizip_output;
	sched->hw_alloc = hisi_qm_alloc_ctx;
	sched->hw_free = hisi_qm_free_ctx;
	sched->hw_send = hisi_qm_send;
	sched->hw_recv = hisi_qm_recv;

	sched->qs = malloc(sizeof(*sched->qs) * sched->q_num);
	if (!sched->qs)
		goto out;

	sched_priv = malloc(sizeof(struct hisi_sched));
	if (!sched_priv)
		goto out_priv;
	sched_priv->msgs = malloc(sizeof(struct hisi_zip_sqe) * CACHE_NUM);
	if (!sched_priv->msgs)
		goto out_msg;
	if (!strncmp(sess->alg_name, "zlib", strlen("zlib"))) {
		sched_priv->alg_type = ZLIB;
		sched_priv->dw9 = 2;
	} else {	// gzip
		sched_priv->alg_type = GZIP;
		sched_priv->dw9 = 3;
	}
	sched_priv->si = 0;
	sched_priv->di = 0;
	sched->priv = sched_priv;
	ret = wd_sched_init(sched, sess->node_path);
	if (ret)
		goto out_sched;
	return ret;
out_sched:
	free(sched_priv->msgs);
out_msg:
	free(sched_priv);
out_priv:
	free(sched->qs);
out:
	free(sess->priv);
	sess->priv = NULL;
	return ret;
}

void hisi_comp_exit(struct wd_comp_sess *sess)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	struct hisi_sched	*sched_priv;
	int	i;

	priv = (struct hisi_comp_sess *)sess->priv;
	sched = &priv->sched;
	for (i = 0; i < sched->q_num; i++) {
		wd_stop_ctx(&sched->qs[i]);
		sched->hw_free(&sched->qs[i]);
	}
	wd_sched_fini(sched);
	sched_priv = sched->priv;
	free(sched_priv->msgs);
	free(sched_priv);
	free(sched->qs);
	free(sess->priv);
	sess->priv = NULL;
}

int hisi_comp_deflate(struct wd_comp_sess *sess, struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	struct hisi_sched	*sched_priv;
	struct hisi_qm_capa	capa;
	struct hisi_qm_priv	*qm_priv;
	int	i, j, ret;

	priv = (struct hisi_comp_sess *)sess->priv;
	sched = &priv->sched;
	sched->data = &capa;
	sched_priv = sched->priv;
	if (sched_priv->alg_type == ZLIB)
		capa.alg = "zlib";
	else
		capa.alg = "gzip";

	qm_priv = (struct hisi_qm_priv *)&capa.priv;
	qm_priv->sqe_size = sizeof(struct hisi_zip_sqe);
	qm_priv->op_type = DEFLATE;
	for (i = 0; i < sched->q_num; i++) {
		ret = sched->hw_alloc(&sched->qs[i], sched->data);
		if (ret)
			goto out;
		ret = wd_start_ctx(&sched->qs[i]);
		if (ret)
			goto out_start;
	}
	sched_priv = (struct hisi_sched *)sched->priv;
	sched_priv->op_type = DEFLATE;
	sched_priv->arg = arg;
	arg->dst_len = 0;
	/* ZLIB engine can do only one time with buffer less than 16M */
	if (sched_priv->alg_type == ZLIB) {
		if (arg->src_len > BLOCK_SIZE) {
			WD_ERR("zlib total_len(%d) > BLOCK_SIZE(%d)\n",
				arg->src_len, BLOCK_SIZE);
			ret = -EINVAL;
			goto out_size;
		}
		if (BLOCK_SIZE > 16 << 20) {
			WD_ERR("BLOCK_SIZE(%d) > HW limitation (16MB)\n",
				arg->src_len);
			ret = -EINVAL;
			goto out_size;
		}
	}

	while (arg->src_len || !wd_sched_empty(sched)) {
		ret = wd_sched_work(sched, arg->src_len);
		if (ret < 0) {
			WD_ERR("fail to deflate by wd_sched (%d)\n", ret);
			goto out_size;
		}
		ret = 0;
	}
	return ret;
out_size:
	for (i = 0; i < sched->q_num; i++) {
		wd_stop_ctx(&sched->qs[i]);
		sched->hw_free(&sched->qs[i]);
	}
	return ret;
out_start:
	sched->hw_free(&sched->qs[i]);
out:
	for (j = i - 1; j >= 0; j--) {
		wd_stop_ctx(&sched->qs[j]);
		sched->hw_free(&sched->qs[j]);
	}
	return ret;
}

int hisi_comp_inflate(struct wd_comp_sess *sess, struct wd_comp_arg *arg)
{
	struct hisi_comp_sess	*priv;
	struct wd_scheduler	*sched;
	struct hisi_sched	*sched_priv;
	struct hisi_qm_capa	capa;
	struct hisi_qm_priv	*qm_priv;
	int	i, j, ret;

	priv = (struct hisi_comp_sess *)sess->priv;
	sched = &priv->sched;
	sched->data = &capa;
	sched_priv = sched->priv;
	if (sched_priv->alg_type == ZLIB)
		capa.alg = "zlib";
	else
		capa.alg = "gzip";
	qm_priv = (struct hisi_qm_priv *)&capa.priv;
	qm_priv->sqe_size = sizeof(struct hisi_zip_sqe);
	qm_priv->op_type = INFLATE;
	for (i = 0; i < sched->q_num; i++) {
		ret = sched->hw_alloc(&sched->qs[i], sched->data);
		if (ret)
			goto out;
		ret = wd_start_ctx(&sched->qs[i]);
		if (ret)
			goto out_start;
	}
	sched_priv = (struct hisi_sched *)sess->priv;
	sched_priv->op_type = INFLATE;
	sched_priv->arg = arg;
	/* ZLIB engine can do only one time with buffer less than 16M */
	if (sched_priv->alg_type == ZLIB) {
		if (arg->src_len > BLOCK_SIZE) {
			WD_ERR("zlib total_len(%d) > BLOCK_SIZE(%d)\n",
				arg->src_len, BLOCK_SIZE);
			ret = -EINVAL;
			goto out_size;
		}
		if (BLOCK_SIZE > 16 << 20) {
			WD_ERR("BLOCK_SIZE(%d) > HW limitation (16MB)\n",
				arg->src_len);
			ret = -EINVAL;
			goto out_size;
		}
	}

	while (arg->src_len || !wd_sched_empty(sched)) {
		ret = wd_sched_work(sched, arg->src_len);
		if (ret) {
			WD_ERR("fail to deflate by wd_sched (%d)\n", ret);
			goto out_size;
		}
	}
	return ret;
out_size:
	for (i = 0; i < sched->q_num; i++) {
		wd_stop_ctx(&sched->qs[i]);
		sched->hw_free(&sched->qs[i]);
	}
	return ret;
out_start:
	sched->hw_free(&sched->qs[i]);
out:
	for (j = i - 1; j >= 0; j--) {
		wd_stop_ctx(&sched->qs[j]);
		sched->hw_free(&sched->qs[j]);
	}
	return ret;
}

int hisi_comp_poll(struct wd_comp_sess *sess, struct wd_comp_arg *arg)
{
	return 0;
}
