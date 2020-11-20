AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../../include -pthread

if WITH_OPENSSL_DIR
bin_PROGRAMS=bmm_test

bmm_test_SOURCES=bmm_test.c bmm_test.h

bmm_test_LDADD=../../.libs/libwd.so $(with_openssl_dir)/libcrypto_wd.so
endif
