#include <zlib.h>
#include <stdlib.h>
#include "test_lib.h"

/*
 * Try to decompress a buffer using zLib's inflate(). Call compare_output with
 * the decompressed stream as argument
 *
 * Return 0 on success, or an error.
 */
int hizip_check_output(void *buf, size_t size, size_t *checked,
		       check_output_fn compare_output, void *opaque)
{
	int ret, ret2;
	unsigned char *out_buffer;
	const size_t out_buf_size = 0x100000;
	z_stream stream = {
		.next_in	= buf,
		.avail_in	= size,
	};

	out_buffer = calloc(1, out_buf_size);
	if (!out_buffer)
		return -ENOMEM;

	stream.next_out = out_buffer;
	stream.avail_out = out_buf_size;

	/* Pass -15 to skip parsing of header, since we have raw data. */
	ret = inflateInit2(&stream, -15);
	if (ret != Z_OK) {
		WD_ERR("zlib inflateInit: %d\n", ret);
		ret = -EINVAL;
		goto out_free_buf;
	}

	do {
		ret = inflate(&stream, Z_NO_FLUSH);
		if (ret < 0 || ret == Z_NEED_DICT) {
			WD_ERR("zlib error %d - %s\n", ret, stream.msg);
			ret = -ENOSR;
			break;
		}

		ret2 = compare_output(out_buffer, out_buf_size -
				      stream.avail_out, opaque);
		/* compare_output should print diagnostic messages. */
		if (ret2) {
			ret = Z_STREAM_ERROR;
			break;
		}

		if (!stream.avail_out) {
			stream.next_out = out_buffer;
			stream.avail_out = out_buf_size;
		}
	} while (ret != Z_STREAM_END);

	if (ret == Z_STREAM_END || ret == Z_OK) {
		*checked = stream.total_out;
		ret = 0;
	}

	inflateEnd(&stream);
out_free_buf:
	free(out_buffer);
	return ret;
}

int zlib_deflate(void *output, unsigned int out_size,
		 void *input, unsigned int in_size,
		 unsigned long *produced)
{
	int ret;
	z_stream stream = {
		.next_in	= input,
		.avail_in	= in_size,
		.next_out	= output,
		.avail_out	= out_size,
	};

	/* Pass -15 to output raw deflate data */
	ret = deflateInit2(&stream, Z_BEST_SPEED, Z_DEFLATED, -15, 9,
			   Z_DEFAULT_STRATEGY);
	if (ret != Z_OK) {
		WD_ERR("zlib deflateInit: %d\n", ret);
		return -EINVAL;
	}

	do {
		ret = deflate(&stream, Z_FINISH);
		if (ret == Z_STREAM_ERROR || ret == Z_BUF_ERROR) {
			WD_ERR("zlib error %d - %s\n", ret, stream.msg);
			ret = -ENOSR;
			break;
		} else if (!stream.avail_in) {
			if (ret != Z_STREAM_END)
				WD_ERR("unexpected deflate return value %d\n", ret);
			*produced = stream.total_out;
			ret = 0;
			break;
		} else if (!stream.avail_out) {
			WD_ERR("No more output available\n");
			ret = -ENOSPC;
			break;
		}
	} while (ret == Z_OK);

	deflateEnd(&stream);

	return ret;
}
