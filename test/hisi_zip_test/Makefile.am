AM_CFLAGS=-Wall -fno-strict-aliasing -I../../include

bin_PROGRAMS=test_sva_perf

test_sva_perf_SOURCES=test_sva_perf.c sva_file_test.c test_lib.c ../sched_sample.c

if WD_STATIC_DRV
test_sva_perf_LDADD=../../.libs/libwd.a ../../.libs/libwd_comp.a \
		    ../../.libs/libhisi_zip.a -lpthread
else
test_sva_perf_LDADD=-L../../.libs -lwd -lhisi_zip -lwd_comp -lpthread
endif
test_sva_perf_LDFLAGS=-Wl,-rpath,'/usr/local/lib'

# For statistics
test_sva_perf_LDADD+=-lm

if HAVE_ZLIB
test_sva_perf_LDADD+=-lz
test_sva_perf_CPPFLAGS=-DUSE_ZLIB
endif
