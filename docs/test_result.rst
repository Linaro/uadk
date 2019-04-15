Test results
============

v1-rc3:

    * ZIP, HPRE kernel crytpo self-test pass.
    * UACCE mode1, test_hisi_zip OK.
    * UACCE mode1, zlib OK
      (https://github.com/hisilicon/zlib.git zlib-wd-v1-rc3-hf-dev)
    * UACCE mode2, test_hisi_zip OK.
    * UACCE mode2, zlib OK
      (https://github.com/hisilicon/zlib.git zlib-wd-v1-rc3-hf-dev)
    * UACCE mode2, test_hisi_hpre OK.
    * UACCE mode2, openssl OK.
      (https://github.com/hisilicon/OpenSSL.git bobo-priv-openssl-warpdrive-eng)

  Known issues

    * Fail to register to UACCE for HPRE module in uacce_mode 2
    * Fail to run wd_test in openssl in multiple threads
