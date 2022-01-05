ACLOCAL_AMFLAGS = -I m4 -I./include
AM_CFLAGS=-Wall -fno-strict-aliasing -I$(top_srcdir) -I$(top_srcdir)/include \
			-I$(top_srcdir)/uadk_tool/include -pthread

#AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS=uadk_tool

uadk_tool_SOURCES=uadk_tool.c uadk_dfx.c uadk_benchmark.c \
			sec_uadk_benchmark.c sec_wd_benchmark.c sec_soft_benchmark.c

if WD_STATIC_DRV
AM_CFLAGS+=-Bstatic
uadk_tool_LDADD=$(libwd_la_OBJECTS) \
			$(libwd_crypto_la_OBJECTS) \
			../.libs/libhisi_sec.a \
			../.libs/libhisi_hpre.a \
			../.libs/libhisi_zip.a \
			$(top_srcdir)/uadk_tool/include/libcrypto.a -ldl -lnuma
else
uadk_tool_LDADD=-L../.libs -l:libwd.so.2 -l:libwd_crypto.so.2 \
			-L$(top_srcdir)/uadk_tool/include -l:libcrypto.so.1.1 -lnuma
endif
uadk_tool_LDFLAGS=-Wl,-rpath,'/usr/local/lib'
