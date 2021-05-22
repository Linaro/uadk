AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I$(top_srcdir)/include -I$(srcdir) -pthread

if WITH_OPENSSL_DIR
bin_PROGRAMS=test_hisi_sec

test_hisi_sec_SOURCES=test_hisi_sec.c test_hisi_sec.h

if WD_STATIC_DRV
test_hisi_sec_LDADD=../../../.libs/libwd.la $(with_openssl_dir)/libcrypto_wd.so
else
test_hisi_sec_LDADD=../../../.libs/libwd.so $(with_openssl_dir)/libcrypto_wd.so
endif

endif
