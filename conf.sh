#!/bin/sh

#to build hpre
# git clone https://github.com/openssl/openssl.git
# cd openssl
# ./Configure linux-aarch64 --cross-compile-prefix=aarch64-linux-gnu-
# add the following configure to this project (assume it is in paralle dir):
# --with-openssl_dir=`pwd`/../openssl
#

ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes ./configure \
	--enable-perf=yes \
	--host aarch64-linux-gnu \
	--target aarch64-linux-gnu \
	--program-prefix aarch64-linux-gnu-
