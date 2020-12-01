AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I$(top_srcdir)/include -I$(srcdir) -pthread

bin_PROGRAMS=test_hisi_sec_sgl

test_hisi_sec_sgl_SOURCES=test_hisi_sec_sgl.c test_hisi_sec_sgl.h

if WITH_OPENSSL_DIR
test_hisi_sec_sgl_LDADD=../../.libs/libwd.so $(with_openssl_dir)/libcrypto_wd.so
else
test_hisi_sec_sgl_LDADD=../../.libs/libwd.la
endif
