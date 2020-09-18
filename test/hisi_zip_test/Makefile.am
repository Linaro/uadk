AM_CFLAGS=-Wall -fno-strict-aliasing -I../../include

bin_PROGRAMS=test_sva_perf

test_sva_perf_SOURCES=test_sva_perf.c test_lib.c ../sched_sample.c

test_sva_perf_LDADD=../../.libs/libwd.a ../../.libs/libwd_comp.a \
		    ../../.libs/libhisi_zip.a -lpthread

# For statistics
test_sva_perf_LDADD+=-lm

if HAVE_ZLIB
test_sva_perf_LDADD+=-lz
test_sva_perf_CPPFLAGS=-DUSE_ZLIB
endif
