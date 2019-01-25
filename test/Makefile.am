AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../include

bin_PROGRAMS=test_hisi_zip test_hisi_zlib test_dummy

test_hisi_zip_SOURCES=test_hisi_zip.c
test_hisi_zlib_SOURCES=test_hisi_zlib.c

test_hisi_zip_LDADD=../.libs/libwd.a
test_hisi_zlib_LDADD=../.libs/libwd.a

test_dummy_SOURCES=test_dummy.c

test_dummy_LDADD=../.libs/libwd.a

if WITH_OPENSSL_DIR
SUBDIRS=. hisi_hpre_test
endif
