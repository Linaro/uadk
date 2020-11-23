AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../include -I../ -I lib -pthread

bin_PROGRAMS=test_hisi_zip test_hisi_zlib test_dummy wd_zip_test

test_hisi_zip_SOURCES=test_hisi_zip.c
test_hisi_zip_LDFLAGS=-Wl,-rpath,'/usr/local/lib'
test_hisi_zip_LDADD=-L../.libs -l:libwd.so.1

test_hisi_zlib_SOURCES=test_hisi_zlib.c zip_alg.c
test_hisi_zlib_LDFLAGS=-Wl,-rpath,'/usr/local/lib'
test_hisi_zlib_LDADD=-L../.libs -l:libwd.so.1

wd_zip_test_SOURCES=wd_zip_test.c zip_alg.c
wd_zip_test_LDFLAGS=-Wl,-rpath,'/usr/local/lib'
wd_zip_test_LDADD=-L../.libs -l:libwd.so.1 -lz

test_dummy_SOURCES=test_dummy.c
test_dummy_LDFLAGS=-Wl,-rpath,'/usr/local/lib'
test_dummy_LDADD=-L../.libs -l:libwd.so.1

SUBDIRS=. test_mm
SUBDIRS+=bmm_test

if WITH_OPENSSL_DIR
SUBDIRS+=hisi_hpre_test
endif
