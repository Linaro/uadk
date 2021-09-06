ACLOCAL_AMFLAGS = -I m4 -I./include
AM_CFLAGS=-Wall -fno-strict-aliasing -I$(top_srcdir) -I$(top_srcdir)/include \
			-I$(top_srcdir)/uadk_benchmark/include -pthread

#AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS=uadk_benchmark

uadk_benchmark_SOURCES=uadk_benchmark.c \
			sec_uadk_benchmark.c sec_wd_benchmark.c sec_soft_benchmark.c

if WD_STATIC_DRV
AM_CFLAGS+=-Bstatic
uadk_benchmark_LDADD=$(libwd_la_OBJECTS) \
			$(libwd_crypto_la_OBJECTS) \
			../.libs/libhisi_sec.a \
			../.libs/libhisi_hpre.a \
			../.libs/libhisi_zip.a \
			include/libcrypto.so.1.1 -lnuma
else
uadk_benchmark_LDADD=-L../.libs -l:libwd.so.2 -l:libwd_crypto.so.2 \
			-L$(top_srcdir)/uadk_benchmark/include -l:libcrypto.so.1.1 -lnuma
endif
uadk_benchmark_LDFLAGS=-Wl,-rpath,'/usr/local/lib'
