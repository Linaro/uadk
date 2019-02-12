AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../../include -ldl -pthread

bin_PROGRAMS=test_hisi_hpre

test_hisi_hpre_SOURCES=test_hisi_hpre.c test_hisi_hpre.h

test_hisi_hpre_LDADD=../../.libs/libwd.a $(with_openssl_dir)/libcrypto.a
