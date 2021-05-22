AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I$(top_srcdir)/include -I$(srcdir) -pthread

if WITH_OPENSSL_DIR
bin_PROGRAMS=test_hisi_sec_sgl

test_hisi_sec_sgl_SOURCES=test_hisi_sec_sgl.c test_hisi_sec_sgl.h

if WD_STATIC_DRV
test_hisi_sec_sgl_LDADD=../../../.libs/libwd.la $(with_openssl_dir)/libcrypto_wd.so
else
test_hisi_sec_sgl_LDADD=../../../.libs/libwd.so $(with_openssl_dir)/libcrypto_wd.so
endif

endif
