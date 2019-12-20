#include "test_lib.h"
#include "drv/hisi_qm_udrv.h"

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

/*
 * Release the scheduler
 */
void hizip_test_fini(struct wd_scheduler *sched)
{
	wd_sched_fini(sched);
	free(sched->qs);
}

