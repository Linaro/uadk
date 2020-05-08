AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../../include -pthread

bin_PROGRAMS=test_hisi_hpre hpre_test_tools

test_hisi_hpre_SOURCES=test_hisi_hpre.c test_hisi_hpre.h
hpre_test_tools_SOURCES=hpre_test_tools.c

test_hisi_hpre_LDADD=../../.libs/libwd.so $(with_openssl_dir)/libcrypto_wd.so
hpre_test_tools_LDADD=../../.libs/libwd.so $(with_openssl_dir)/libcrypto_wd.so
