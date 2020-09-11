AM_CFLAGS=-Wall -fno-strict-aliasing -I../../include

bin_PROGRAMS=test_sva_perf example zip_sva_test

test_sva_perf_SOURCES=test_sva_perf.c test_lib.c ../sched_sample.c

if WD_STATIC_DRV
test_sva_perf_LDADD=../../.libs/libwd.a ../../.libs/libwd_comp.a \
		    ../../.libs/libhisi_zip.a -lpthread
else
test_sva_perf_LDADD=-L../../.libs -lwd -lhisi_zip -lwd_comp -lpthread
endif

# For statistics
test_sva_perf_LDADD+=-lm

if HAVE_ZLIB
test_sva_perf_LDADD+=-lz
test_sva_perf_CPPFLAGS=-DUSE_ZLIB
endif

example_SOURCES = example.c
if WD_STATIC_DRV
example_LDADD = ../../.libs/libwd.a ../../.libs/libwd_comp.a \
		../../.libs/libhisi_zip.a -lpthread
else
example_LDADD =-L../../.libs -lwd -lwd_comp -lhisi_zip -lpthread
endif

zip_sva_test_SOURCES = zip_sva_test.c zip_wrap.c
if WD_STATIC_DRV
zip_sva_test_LDADD = ../../.libs/libwd.a ../../.libs/libwd_comp.a \
		../../.libs/libhisi_zip.a -lpthread
else
zip_sva_test_LDADD =-L../../.libs -lwd -lwd_comp -lhisi_zip -lpthread
endif
