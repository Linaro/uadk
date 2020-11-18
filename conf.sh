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
	elif [ $1 = "--with-uadk_v1" ]; then
		echo "enable UADK v1!"
		UADK_VERSION="--with-uadk_v1"
	else
		echo "invalid paramter, --static is static compile, compile to shared lib by default"
	fi
fi

if [ $2 ]; then
	if [ $2 = "--with-uadk_v1" ]; then
		echo "enable UADK v1!"
		UADK_VERSION="--with-uadk_v1"
	fi
fi

ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes ./configure \
	--enable-perf=yes \
	--host aarch64-linux-gnu \
	--target aarch64-linux-gnu \
	--includedir=/usr/local/include/uadk \
	$COMPILE_TYPE \
	$UADK_VERSION
