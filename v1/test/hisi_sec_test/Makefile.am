AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I$(top_srcdir)/include -I$(srcdir) -pthread

bin_PROGRAMS=test_hisi_sec

test_hisi_sec_SOURCES=test_hisi_sec.c test_hisi_sec.h

test_hisi_sec_LDADD=../../.libs/libwd.so $(with_openssl_dir)/libcrypto_wd.so