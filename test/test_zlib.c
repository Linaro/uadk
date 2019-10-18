#include <zlib.h>
#include <stdlib.h>
#include "test_lib.h"

/*
 * Try to decompress a buffer using zLib's inflate(). Call compare_output with
 * the decompressed stream as argument
 *
 * Return 0 on success, or an error.
 */
int hizip_check_output(void *buf, unsigned int size,
		       check_output_fn compare_output, void *opaque)
{
	int ret, ret2;
	unsigned char *out_buffer;
	size_t out_buf_size = 0x10000;
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
		ret = inflate(&stream, 0);

		if (ret == Z_OK || ret == Z_STREAM_END) {
			if (ret == Z_OK && stream.avail_out) {
				WD_ERR("stream.avail_out = %d, should be zero\n",
				       stream.avail_out);
				break;
			}

			ret2 = compare_output(out_buffer, out_buf_size -
					      stream.avail_out, opaque);

			/* compare_output should print diagnostic messages. */
			if (ret2) {
				ret = Z_STREAM_END;
				break;
			}

			if (!stream.avail_out) {
				stream.next_out = out_buffer;
				stream.avail_out = out_buf_size;
			}
		}
	} while (ret == Z_OK);

	if (ret != Z_OK && ret != Z_STREAM_END) {
		WD_ERR("zlib error %d - %s\n", ret, stream.msg);
	} else {
		ret = 0;
	}

	inflateEnd(&stream);
out_free_buf:
	free(out_buffer);
	return ret;
}
