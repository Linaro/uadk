#!/bin/sh

#to build hpre
# git clone https://github.com/openssl/openssl.git
# cd openssl
# ./Configure linux-aarch64 --cross-compile-prefix=aarch64-linux-gnu-
# add the following configure to this project (assume it is in paralle dir):
# --with-openssl_dir=`pwd`/../openssl
#

COMPILE_TYPE="--disable-static --enable-shared"

if [ $1 ]; then
	if [ $1 = "--static" ]; then
		echo "configure to static compile!"
		COMPILE_TYPE="--enable-static --disable-shared --with-static_drv"
	else
		echo "invalid paramter, --static is static compile, compile to shared lib by default"
	fi
fi

ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes ./configure \
	--enable-perf=yes \
	--host aarch64-linux-gnu \
	--target aarch64-linux-gnu \
	--program-prefix aarch64-linux-gnu- \
	$COMPILE_TYPE
