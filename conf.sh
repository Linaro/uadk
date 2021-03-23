#!/bin/bash

# Configure UADK to generate Makefile

# Build UADK into static library
COMPILE_TYPE="--disable-static --enable-shared"

# These two parameters could be in arbitary sequence
if [[ $1 && $1 = "--static" ]] || [[ $2 && $2 = "--static" ]]; then
	echo "Configure to static compile!"
	COMPILE_TYPE="--enable-static --disable-shared --with-static_drv"
fi


ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes ./configure \
	--enable-perf=yes \
	--host aarch64-linux-gnu \
	--target aarch64-linux-gnu \
	--includedir=/usr/local/include/uadk \
	$COMPILE_TYPE
