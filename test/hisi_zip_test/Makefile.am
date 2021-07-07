AM_CFLAGS=-Wall -Werror -fno-strict-aliasing -I../../include
AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS=zip_sva_perf

zip_sva_perf_SOURCES=test_sva_perf.c test_lib.c	testsuit.c

if WD_STATIC_DRV
zip_sva_perf_LDADD=../../.libs/libwd.a ../../.libs/libwd_comp.a \
		    ../../.libs/libhisi_zip.a -lpthread -lnuma -lcrypto
else
zip_sva_perf_LDADD=-L../../.libs -l:libwd.so.2 -l:libwd_comp.so.2 \
		   -lpthread -lcrypto
endif
zip_sva_perf_LDFLAGS=-Wl,-rpath,'/usr/local/lib'

# For statistics
zip_sva_perf_LDADD+=-lm

if HAVE_ZLIB
zip_sva_perf_LDADD+=-lz
zip_sva_perf_CPPFLAGS=-DUSE_ZLIB
endif
