#include "wd_comp.h"

#define TEST_WORD_LEN           64

int operation(int op_type, void *src, int src_sz, void *dst, int *dst_sz)
{
        struct wd_comp_sess_setup setup = {0};
        struct wd_comp_req req = {0};
        handle_t h_dfl;
        int ret;

        if (!src || !dst || !dst_sz || (*dst_sz <= 0))
                return -EINVAL;
        ret = wd_comp_env_init(NULL);
        if (ret < 0)
                goto out;

        setup.alg_type = WD_ZLIB;
        setup.win_sz = WD_COMP_WS_32K;
        setup.comp_lv = WD_COMP_L8;
        setup.op_type = op_type;
	h_dfl = wd_comp_alloc_sess(&setup);
        if (!h_dfl) {
                ret = -EINVAL;
                goto out_sess;
        }
        req.src = src;
        req.src_len = src_sz;
        req.dst = dst;
        req.dst_len = *dst_sz;
        req.op_type = op_type;
        req.data_fmt = WD_FLAT_BUF;
        do {
                ret = wd_do_comp_sync(h_dfl, &req);
        } while (ret == -WD_EBUSY);
        if (ret)
                goto out_comp;
        *dst_sz = req.dst_len;
        wd_comp_free_sess(h_dfl);
        wd_comp_env_uninit();
        return 0;
out_comp:
        wd_comp_free_sess(h_dfl);
out_sess:
        wd_comp_env_uninit();
out:
        return ret;
}

int main(void)
{
        char src[TEST_WORD_LEN] = {0}, dst[TEST_WORD_LEN] = {0};
        char tmp[TEST_WORD_LEN] = {0};
        int ret, src_sz, dst_sz, tmp_sz;

        strcpy(src, "go to test.");
        src_sz = strlen(src);
        dst_sz = tmp_sz = TEST_WORD_LEN;
        ret = operation(WD_DIR_COMPRESS, src, src_sz, tmp, &tmp_sz);
        if (ret < 0)
                goto out;
        ret = operation(WD_DIR_DECOMPRESS, tmp, tmp_sz, dst, &dst_sz);
        if (ret < 0)
                goto out;
        if ((src_sz == dst_sz) && !strcmp(src, dst))
                printf("Compression verified!\n");
        else {
                printf("Fail to verify the compression!\n");
                ret = -EFAULT;
                goto out;
        }
        return 0;
out:
        return ret;
}

