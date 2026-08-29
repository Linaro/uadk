#!/bin/bash

# Configure UADK to generate Makefile

# Build UADK into static library
COMPILE_TYPE="--disable-static --enable-shared"
DEBUG_TYPE=""

# These parameters could be in arbitary sequence
for arg in "$1" "$2" "$3"; do
	if [[ $arg = "--static" ]]; then
		echo "Configure to static compile!"
		COMPILE_TYPE="--enable-static --disable-shared --with-static_drv"
	elif [[ $arg = "--debug" ]]; then
		echo "Configure to debug compile (with symbols, no optimization)!"
		DEBUG_TYPE="--enable-debug=yes"
	fi
done

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes ./configure -v \
	--enable-perf=yes \
	--host aarch64-linux-gnu \
	--target aarch64-linux-gnu \
	--includedir=/usr/local/include/ \
	$COMPILE_TYPE \
	$DEBUG_TYPE
