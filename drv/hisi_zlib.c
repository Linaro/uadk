/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2023-2024 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2023-2024 Linaro ltd.
 */
#include <stdlib.h>
#include <stdio.h>
#include <zlib.h>

#include "drv/wd_comp_drv.h"

struct hisi_zlib_priv {
	int windowbits;
};

static int hisi_zlib_init(struct wd_alg_driver *drv, void *conf)
{
	struct hisi_zlib_priv *priv;

	priv = malloc(sizeof(struct hisi_zlib_priv));
	if (!priv)
		return -ENOMEM;

	if (strcmp(drv->alg_name, "zlib") == 0)
		priv->windowbits = 15;
	else if (strcmp(drv->alg_name, "deflate") == 0)
		priv->windowbits = -15;
	else if (strcmp(drv->alg_name, "gzip") == 0)
		priv->windowbits = 15 + 16;

	drv->priv = priv;

	return 0;
}
static void hisi_zlib_exit(struct wd_alg_driver *drv)
{
	struct hisi_zlib_priv *priv = (struct hisi_zlib_priv *)drv->priv;

	free(priv);
}

static int hisi_zlib_send(struct wd_alg_driver *drv, handle_t ctx, void *comp_msg)
{
	struct hisi_zlib_priv *priv = (struct hisi_zlib_priv *)drv->priv;
	struct wd_comp_msg *msg = comp_msg;
	z_stream strm;
	int ret;

	memset(&strm, 0, sizeof(z_stream));

	strm.next_in = msg->req.src;
	strm.avail_in = msg->req.src_len;
	strm.next_out = msg->req.dst;
	strm.avail_out = msg->req.dst_len;

	if (msg->req.op_type == WD_DIR_COMPRESS) {
		/* deflate */

		ret = deflateInit2(&strm, Z_BEST_SPEED, Z_DEFLATED, priv->windowbits,
				8, Z_DEFAULT_STRATEGY);
		if (ret != Z_OK) {
			printf("deflateInit2: %d\n", ret);
			return -EINVAL;
		}

		do {
			ret = deflate(&strm, Z_FINISH);
			if ((ret == Z_STREAM_ERROR) || (ret == Z_BUF_ERROR)) {
				printf("defalte error %d - %s\n", ret, strm.msg);
				ret = -ENOSR;
				break;
			} else if (!strm.avail_in) {
				if (ret != Z_STREAM_END)
					printf("deflate unexpected return: %d\n", ret);
				ret = 0;
				break;
			} else if (!strm.avail_out) {
				printf("deflate out of memory\n");
				ret = -ENOSPC;
				break;
			}
		} while (ret == Z_OK);

		deflateEnd(&strm);

	} else {
		/* inflate */

		/* Window size of 15, +32 for auto-decoding gzip/zlib */
		ret = inflateInit2(&strm, 15 + 32);
		if (ret != Z_OK) {
			printf("zlib inflateInit: %d\n", ret);
			return -EINVAL;
		}

		do {
			ret = inflate(&strm, Z_NO_FLUSH);
			if ((ret < 0) || (ret == Z_NEED_DICT)) {
				printf("zlib error %d - %s\n", ret, strm.msg);
				ret = -EINVAL;
				break;
			}
			if (!strm.avail_out) {
				if (!strm.avail_in || (ret == Z_STREAM_END)) {
					ret = 0;
					break;
				}
				printf("%s: avail_out is empty!\n", __func__);
				ret = -EINVAL;
				break;
			}
		} while (strm.avail_in && (ret != Z_STREAM_END));
		inflateEnd(&strm);
	}

	msg->produced = msg->req.dst_len - strm.avail_out;
	msg->in_cons = msg->req.src_len;

	return ret;
}
static int hisi_zlib_recv(struct wd_alg_driver *drv, handle_t ctx, void *msg)
{
	/*
	 * recv just return since cpu does not support async,
	 * once send func return, the operation is done
	 */
	return 0;
}

#define GEN_ZLIB_ALG_DRIVER(zlib_alg_name) \
{\
	.drv_name = "hisi_zlib",\
	.alg_name = zlib_alg_name,\
	.calc_type = UADK_ALG_SOFT,\
	.priority = 0,\
	.init = hisi_zlib_init,\
	.exit = hisi_zlib_exit,\
	.send = hisi_zlib_send,\
	.recv = hisi_zlib_recv,\
}

static struct wd_alg_driver zlib_alg_driver[] = {
	GEN_ZLIB_ALG_DRIVER("zlib"),
	GEN_ZLIB_ALG_DRIVER("gzip"),
	GEN_ZLIB_ALG_DRIVER("deflate"),
};

static void __attribute__((constructor)) hisi_zlib_probe(void)
{
	int alg_num = ARRAY_SIZE(zlib_alg_driver);
	int i, ret;

	for (i = 0; i < alg_num; i++) {
		ret = wd_alg_driver_register(&zlib_alg_driver[i]);
		if (ret)
			fprintf(stderr, "Error: register zlib %s failed!\n",
				zlib_alg_driver[i].alg_name);
	}
}

static void __attribute__((destructor)) hisi_zlib_remove(void)
{
	int alg_num = ARRAY_SIZE(zlib_alg_driver);
	int i;

	for (i = 0; i < alg_num; i++)
		wd_alg_driver_unregister(&zlib_alg_driver[i]);
}
