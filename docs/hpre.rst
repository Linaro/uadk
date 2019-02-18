Use HPRE
========

HPRE stands for High Performance RSA Engine. It is used with OpenSSL. So you
should compile it with OpenSSL.

Currently we have just tested it with OpenSSL source code. To use HPRE, please
compile openssl first. Here is an example to cross compile for aarch64 on
linux_x86_64::
        
        git clone https://github.com/openssl/openssl.git # or get from elsewhere
        cd $openssl
        ./Configure linux-aarch64 --cross-compile-prefix=aarch64-linux-gnu-
        cd $warpdrive
        ac_cv_func_malloc_0_nonnull=yes \
        ac_cv_func_realloc_0_nonnull=yes ./configure \
                --host aarch64-linux-gnu \
                --target aarch64-linux-gnu \
                --program-prefix aarch64-linux-gnu- \
                --with-openssl_dir=$openssl

This will build a test application in test/hisi_hpre_test.

Todo: build it as an openssl engine.
