AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I$(top_srcdir)/v1 -I$(srcdir)/v1/test -I$(top_srcdir) -pthread
AUTOMAKE_OPTIONS = subdir-objects
bin_PROGRAMS=test_hisi_zip test_hisi_zlib wd_zip_test test_hisi_zip_perf

test_hisi_zip_SOURCES=test_hisi_zip.c ../wd_sched.c
if WD_STATIC_DRV
test_hisi_zip_LDADD=../../../.libs/libwd.a
else
test_hisi_zip_LDADD=../../../.libs/libwd.so -lnuma
endif	# WD_STATIC_DRV

test_hisi_zlib_SOURCES=test_hisi_zlib.c zip_alg.c ../wd_sched.c ../smm.c
if WD_STATIC_DRV
test_hisi_zlib_LDADD=../../../.libs/libwd.a
else
test_hisi_zlib_LDADD=../../../.libs/libwd.so -lnuma
endif	# WD_STATIC_DRV

wd_zip_test_SOURCES=wd_zip_test.c zip_alg.c ../wd_sched.c ../smm.c
if WD_STATIC_DRV
wd_zip_test_LDADD=../../../.libs/libwd.a -lz
else
wd_zip_test_LDADD=../../../.libs/libwd.so -lz -lnuma
endif	# WD_STATIC_DRV

test_hisi_zip_perf_SOURCES=test_hisi_zip_perf.c zip_alg.c ../wd_sched.c ../smm.c
if WD_STATIC_DRV
test_hisi_zip_perf_LDADD=../../../.libs/libwd.a
else
test_hisi_zip_perf_LDADD=../../../.libs/libwd.so -lz -lnuma
endif	# WD_STATIC_DRV
