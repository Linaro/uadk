#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "wd_comp.h"

#define PATHLEN		256

#define FLAG_ZLIB	(1 << 0)
#define FLAG_GZIP	(1 << 1)
#define FLAG_DECMPS	(1 << 2)
#define FLAG_STREAM	(1 << 3)

#define BUF_SIZE	(1 << 20)

static int test_compress(char *src, char *dst, int flag)
{
	handler_t		handle;
	struct wd_comp_arg	arg;
	struct stat		st;
	ssize_t	size;
	ssize_t in, out, file_len;
	int	mode;
	int	sfd, dfd, ret;
	char	algs[60];
	void	*tmp, *tmp2;

	if (!src || !dst)
		return -EINVAL;
	if (flag & FLAG_ZLIB)
		sprintf(algs, "zlib");
	else if (flag & FLAG_GZIP)
		sprintf(algs, "gzip");
	if (flag & FLAG_STREAM)
		mode = MODE_STREAM;
	else
		mode = 0;
	sfd = open(src, O_RDONLY);
	if (sfd < 0)
		return -EINVAL;
	dfd = open(dst, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (dfd < 0) {
		ret = -EINVAL;
		goto out;
	}
	memset(&arg, 0, sizeof(struct wd_comp_arg));
	fstat(sfd, &st);
	file_len = st.st_size;
	arg.src_len = BUF_SIZE;
	arg.src = malloc(sizeof(char) * BUF_SIZE);
	if (!arg.src) {
		printf("Fail to allocate src buffer with %d bytes.\n", arg.src_len);
		ret = -ENOMEM;
		goto out_src;
	}
	arg.dst_len = BUF_SIZE;	// for decompress
	arg.dst = malloc(sizeof(char) * arg.dst_len);
	if (!arg.dst) {
		printf("Fail to allocate dst buffer with %d bytes.\n", arg.dst_len);
		ret = -ENOMEM;
		goto out_dst;
	}
	tmp = arg.src;
	tmp2 = arg.dst;
	in = 0;
	out = 0;
	handle = wd_alg_comp_alloc_sess(algs, mode, NULL);
	while (1) {
		arg.flag = 0;
		arg.status = 0;
		if (in == file_len) {
			arg.flag |= FLAG_INPUT_FINISH;
			arg.src_len = 0;
		} else {
			arg.src = tmp;
			size = read(sfd, arg.src, BUF_SIZE);
			if (size < 0) {
				printf("fail to load data (%ld)\n", size);
				goto out_read;
			}
			if (in + size > file_len) {
				printf("invalid size:%ld, loaded bytes:%ld\n",
					size, in);
				goto out_read;
			} else if (in + size == file_len)
				arg.flag |= FLAG_INPUT_FINISH;
			arg.src_len = size;
			in += size;
		}
		arg.dst_len = BUF_SIZE;	// for decompress
		if (flag & FLAG_DECMPS) {
			ret = wd_alg_decompress(handle, &arg);
			if (ret < 0) {
				printf("fail to decompress (%d)\n", ret);
			}
		} else {
			arg.flag |= FLAG_DEFLATE;
			ret = wd_alg_compress(handle, &arg);
			if (ret < 0) {
				printf("fail to compress (%d)\n", ret);
			}
		}
		if (arg.status & STATUS_OUT_READY) {
			/* record */
			size = write(dfd, arg.dst - arg.dst_len, arg.dst_len);
			if (size < 0) {
				printf("fail to write data (%ld)\n", size);
				goto out_read;
			}
			out += size;
			arg.dst = tmp2;
		}
		/* load src with LARGE_BUF_SIZE */
		if (arg.status & STATUS_IN_PART_USE) {
			in -= arg.src_len;
			lseek(sfd, in, SEEK_SET);
		}
		if ((arg.flag & FLAG_INPUT_FINISH) &&
		    (arg.status & STATUS_IN_EMPTY) &&
		    (arg.status & STATUS_OUT_DRAINED))
			break;
	}
	wd_alg_comp_free_sess(handle);
	free(tmp2);
	free(tmp);
	close(dfd);
	close(sfd);
	return 0;
out_read:
	free(arg.dst);
out_dst:
	free(arg.src);
out_src:
	close(dfd);
out:
	close(sfd);
	return ret;
}

int main(int argc, char *argv[])
{
	int	fd, opt;
	int	flag = 0, flag_mask;
	char	src[PATHLEN+1], dst[PATHLEN+1];

	while ((opt = getopt(argc, argv, "i:o:hdgsz")) != -1) {
		switch (opt) {
		case 'i':
			snprintf(src, PATHLEN, "%s", optarg);
			break;
		case 'o':
			snprintf(dst, PATHLEN, "%s", optarg);
			break;
		case 'd':
			flag |= FLAG_DECMPS;
			break;
		case 'g':
			flag |= FLAG_GZIP;
			break;
		case 's':
			flag |= FLAG_STREAM;
			break;
		case 'z':
			flag |= FLAG_ZLIB;
			break;
		case 'h':
			printf("./test_comp -i <src> -o <dst> [-d] [-z] [-g]\n");
			break;
		default:
			fprintf(stderr, "Unrecognized option!\n");
			break;
		}
	}
	fd = open("/dev/hisi_zip-0", O_RDWR);
	if (fd < 0) {
		printf("failed to open dev node:%d\n", errno);
		return fd;
	}
	flag_mask = FLAG_GZIP | FLAG_ZLIB;
	if (!flag || ((flag & flag_mask) == flag_mask)) {
		printf("wrong flag setting:0x%x\n", flag);
		return -EINVAL;
	}

	test_compress(src, dst, flag);
	close(fd);
	return 0;
}
