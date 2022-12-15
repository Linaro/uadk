AM_CFLAGS=-Wall -O0 -Werror -fno-strict-aliasing -I$(top_srcdir)/include -I$(top_srcdir)

bin_PROGRAMS=wd_mempool_test
wd_mempool_test_SOURCES=wd_mempool_test.c

if WD_STATIC_DRV
AM_CFLAGS+=-Bstatic
wd_mempool_test_LDADD=../.libs/libwd.a ../.libs/libwd_crypto.a \
			../.libs/libhisi_sec.a -lnuma -lpthread
else
wd_mempool_test_LDADD=-L../.libs -lwd -lwd_crypto -lnuma -lpthread
endif
wd_mempool_test_LDFLAGS=-Wl,-rpath,'/usr/local/lib'

SUBDIRS=. hisi_sec_test

if HAVE_CRYPTO
SUBDIRS += hisi_hpre_test

if HAVE_ZLIB
SUBDIRS += hisi_zip_test
endif

endif
