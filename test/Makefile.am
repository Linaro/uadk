AM_CFLAGS=-Wall -O0 -Werror -fno-strict-aliasing -I$(top_srcdir)/include -I$(top_srcdir)

bin_PROGRAMS=wd_mempool_test wd_dae_test
wd_mempool_test_SOURCES=wd_mempool_test.c
wd_dae_test_SOURCES=wd_dae_test.c

if WD_STATIC_DRV
AM_CFLAGS+=-Bstatic
wd_mempool_test_LDADD=../.libs/libwd.a ../.libs/libwd_crypto.a \
			../.libs/libhisi_sec.a -ldl -lnuma -lpthread
else
wd_mempool_test_LDADD=-L../.libs -lwd -ldl -lwd_crypto -lnuma -lpthread
endif
wd_mempool_test_LDFLAGS=-Wl,-rpath,'/usr/local/lib'

if WD_STATIC_DRV
wd_dae_test_LDADD=../.libs/libwd.a ../.libs/libwd_dae.a \
                        ../.libs/libhisi_dae.a -lnuma -lpthread -lm
else
wd_dae_test_LDADD=-L../.libs -lwd -lwd_dae -lnuma -lpthread
endif
wd_dae_test_LDFLAGS=-Wl,-rpath,'/usr/local/lib'

SUBDIRS = .
if HAVE_CRYPTO
SUBDIRS += hisi_hpre_test

endif
