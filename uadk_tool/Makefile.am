ACLOCAL_AMFLAGS = -I m4 -I./include
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CFLAGS=-Wall -fno-strict-aliasing -I$(top_srcdir) -I$(top_srcdir)/benchmark/include \
			-pthread

#AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS=uadk_tool

uadk_tool_SOURCES=uadk_tool.c dfx/uadk_dfx.c dfx/uadk_dfx.h \
		benchmark/uadk_benchmark.c benchmark/uadk_benchmark.h \
		benchmark/sec_uadk_benchmark.c benchmark/sec_uadk_benchmark.h \
		benchmark/sec_wd_benchmark.c benchmark/sec_wd_benchmark.h \
		benchmark/hpre_uadk_benchmark.c benchmark/hpre_uadk_benchmark.h \
		benchmark/hpre_wd_benchmark.c hpre_wd_benchmark.h \
		benchmark/zip_uadk_benchmark.c benchmark/zip_uadk_benchmark.h \
		benchmark/zip_wd_benchmark.c benchmark/zip_wd_benchmark.h

if WD_STATIC_DRV
AM_CFLAGS+=-Bstatic
uadk_tool_LDADD=$(libwd_la_OBJECTS) \
			$(libwd_crypto_la_OBJECTS) \
			../.libs/libwd_comp.a \
			../.libs/libhisi_sec.a \
			../.libs/libhisi_hpre.a \
			../.libs/libhisi_zip.a \
			-ldl -lnuma
else
uadk_tool_LDADD=-L../.libs -l:libwd.so.2 -l:libwd_crypto.so.2 \
		-l:libwd_comp.so.2 -lnuma
endif

uadk_tool_LDFLAGS=-Wl,-rpath,'/usr/local/lib'

if WITH_ZLIB_FSE_DIR
AM_CFLAGS += -DZLIB_FSE
uadk_tool_LDADD+= $(with_zlib_fse_dir)/libfse.a
endif

if WITH_OPENSSL_DIR
AM_CFLAGS+= -DWITH_OPENSSL_DIR -I$(with_openssl_dir)/include

uadk_tool_SOURCES+=benchmark/sec_soft_benchmark.c benchmark/sec_soft_benchmark.h

if WD_STATIC_DRV
uadk_tool_LDADD+= $(with_openssl_dir)/libcrypto.a
else
uadk_tool_LDADD+= $(with_openssl_dir)/libcrypto.so.1.1
endif

endif
