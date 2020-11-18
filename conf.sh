#!/bin/bash

# Configure UADK to generate Makefile

# Build UADK into static library
COMPILE_TYPE="--disable-static --enable-shared"
# Build UADK v2 by default
UADK_VERSION=""

# These two parameters could be in arbitary sequence
if [[ $1 && $1 = "--static" ]] || [[ $2 && $2 = "--static" ]]; then
	echo "Configure to static compile!"
	COMPILE_TYPE="--enable-static --disable-shared --with-static_drv"
fi
if [[ $1 && $1 = "--with-uadk_v1" ]] || [[ $2 && $2 = "--with-uadk_v1" ]]; then
	UADK_VERSION="--with-uadk_v1"
fi


ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes ./configure \
	--enable-perf=yes \
	--host aarch64-linux-gnu \
	--target aarch64-linux-gnu \
	--includedir=/usr/local/include/uadk \
	$COMPILE_TYPE \
	$UADK_VERSION
