AM_CFLAGS=-Wall -fno-strict-aliasing -I../include

bin_PROGRAMS=test_hisi_zip test_hisi_zlib test_sva_perf test_sva_bind test_comp

test_hisi_zip_SOURCES=test_hisi_zip.c
test_hisi_zlib_SOURCES=test_hisi_zlib.c

test_sva_perf_SOURCES=test_sva_perf.c test_lib.c
test_sva_bind_SOURCES=test_sva_bind.c test_lib.c

test_hisi_zip_LDADD=../.libs/libwd.a
test_hisi_zlib_LDADD=../.libs/libwd.a
test_sva_perf_LDADD=../.libs/libwd.a
test_sva_bind_LDADD=../.libs/libwd.a

# For statistics
test_sva_perf_LDADD+=-lm

if HAVE_ZLIB
test_sva_perf_SOURCES+=test_zlib.c
test_sva_perf_LDADD+=-lz
test_sva_perf_CPPFLAGS=-DUSE_ZLIB
test_sva_bind_SOURCES+=test_zlib.c
test_sva_bind_LDADD+=-lz
test_sva_bind_CPPFLAGS=-DUSE_ZLIB
endif

test_comp_SOURCES=test_comp.c
test_comp_LDADD=../.libs/libwd.a

if WITH_OPENSSL_DIR
SUBDIRS=. hisi_hpre_test
endif
