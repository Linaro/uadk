AM_CFLAGS=-Wall -fno-strict-aliasing -I../../include

bin_PROGRAMS=test_sva_perf test_sva_bind example

test_sva_perf_SOURCES=test_sva_perf.c test_lib.c
test_sva_bind_SOURCES=test_sva_bind.c test_lib.c

if WD_STATIC_DRV
test_sva_perf_LDADD=../../.libs/libwd.a ../../.libs/libhisi_zip.a
test_sva_bind_LDADD=../../.libs/libwd.a ../../.libs/libhisi_zip.a
else
test_sva_perf_LDADD=-L../../.libs -lwd -lhisi_zip -lwd_comp
test_sva_bind_LDADD=-L../../.libs -lwd -lhisi_zip -lwd_comp
endif

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

test_comp_SOURCES=test_comp.c ../sched_sample.c
if WD_STATIC_DRV
test_comp_LDADD=../../.libs/libwd.a ../../.libs/libwd_comp.a \
		../../.libs/libhisi_zip.a
else
test_comp_LDADD=-L../../.libs -lwd -lwd_comp -lhisi_zip
endif

example_SOURCES = example.c
if WD_STATIC_DRV
example_LDADD = ../../.libs/libwd.a ../../.libs/libwd_comp.a \
		../../.libs/libhisi_zip.a -lpthread
else
example_LDADD =-L../../.libs -lwd -lwd_comp -lhisi_zip -lpthread
endif
