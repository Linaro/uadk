ACLOCAL_AMFLAGS = -I m4 -I./include
AUTOMAKE_OPTIONS = foreign subdir-objects

# get UADK build time
BUILD_DATETIME := $(shell date -u +"%Y-%m-%d_%H:%M:%S")

AM_CFLAGS=-Wall -Werror -fno-strict-aliasing -I$(top_srcdir) -I$(top_srcdir)/benchmark/include \
			-pthread
AM_CFLAGS += -fPIC -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
-O2 -ftrapv -Wl,-z,now -Wl,-s

AM_CFLAGS += -DUADK_BUILD_DATETIME=\"$(BUILD_DATETIME)\"

#AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS=uadk_tool

uadk_tool_SOURCES=uadk_tool.c dfx/uadk_dfx.c dfx/uadk_dfx.h \
		benchmark/uadk_benchmark.c benchmark/uadk_benchmark.h \
		benchmark/sec_uadk_benchmark.c benchmark/sec_uadk_benchmark.h \
		benchmark/sec_wd_benchmark.c benchmark/sec_wd_benchmark.h \
		benchmark/hpre_uadk_benchmark.c benchmark/hpre_uadk_benchmark.h \
		benchmark/hpre_wd_benchmark.c hpre_wd_benchmark.h \
		benchmark/zip_uadk_benchmark.c benchmark/zip_uadk_benchmark.h \
		benchmark/zip_wd_benchmark.c benchmark/zip_wd_benchmark.h \
		benchmark/trng_wd_benchmark.c benchmark/trng_wd_benchmark.h \
		test/uadk_test.c test/uadk_test.h \
		test/test_sec.c test/test_sec.h test/sec_template_tv.h

if WD_STATIC_DRV
AM_CFLAGS+=-Bstatic
uadk_tool_LDADD=$(libwd_la_OBJECTS) \
			$(libwd_crypto_la_OBJECTS) \
			../.libs/libwd_comp.a \
			../.libs/libhisi_sec.a \
			../.libs/libhisi_hpre.a \
			../.libs/libhisi_zip.a \
			../.libs/libisa_ce.a \
			-ldl -lnuma
else
uadk_tool_LDADD=-L../.libs -l:libwd.so.2 -l:libwd_crypto.so.2 \
		-l:libwd_comp.so.2 -lnuma
endif

# For statistics
uadk_tool_LDADD+=-lm

if HAVE_ZLIB
uadk_tool_LDADD+=-lz
uadk_tool_CPPFLAGS=-DUSE_ZLIB
endif

if WITH_ZLIB_FSE_DIR
AM_CFLAGS += -DZLIB_FSE
uadk_tool_LDADD+= $(with_zlib_fse_dir)/libfse.a
endif

if HAVE_CRYPTO
uadk_tool_SOURCES+=benchmark/sec_soft_benchmark.c benchmark/sec_soft_benchmark.h \
		   test/comp_main.c test/comp_main.h test/comp_lib.c test/comp_lib.h
uadk_tool_LDADD+=$(libcrypto_LIBS)
endif
