AM_CFLAGS=-Wall -fno-strict-aliasing -I../../include

bin_PROGRAMS=zip_sva_perf

zip_sva_perf_SOURCES=test_sva_perf.c sva_file_test.c test_lib.c	\
			../sched_sample.c

if WD_STATIC_DRV
zip_sva_perf_LDADD=../../.libs/libwd.a ../../.libs/libwd_comp.a \
		    ../../.libs/libhisi_zip.a -lpthread
else
zip_sva_perf_LDADD=-L../../.libs -l:libwd.so.2 -l:libwd_comp.so.2 -lpthread
endif
zip_sva_perf_LDFLAGS=-Wl,-rpath,'/usr/local/lib'

# For statistics
zip_sva_perf_LDADD+=-lm

if HAVE_ZLIB
zip_sva_perf_LDADD+=-lz
zip_sva_perf_CPPFLAGS=-DUSE_ZLIB
endif
