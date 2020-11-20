AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../include -I../ -I lib -pthread

bin_PROGRAMS=test_hisi_zip test_hisi_zlib wd_zip_test

test_hisi_zip_SOURCES=test_hisi_zip.c
test_hisi_zlib_SOURCES=test_hisi_zlib.c zip_alg.c
wd_zip_test_SOURCES=wd_zip_test.c zip_alg.c

test_hisi_zip_LDADD=../.libs/libwd.la
test_hisi_zlib_LDADD=../.libs/libwd.la
wd_zip_test_LDADD=../.libs/libwd.la -lz

SUBDIRS=. test_mm bmm_test

if WITH_OPENSSL_DIR
SUBDIRS+=hisi_hpre_test
endif
