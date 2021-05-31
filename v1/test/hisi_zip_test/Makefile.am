AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../../ -I../ -pthread

bin_PROGRAMS=test_hisi_zip test_hisi_zlib wd_zip_test wd_zip_test_1630 test_hisi_zip_perf

test_hisi_zip_SOURCES=test_hisi_zip.c
if WD_STATIC_DRV
test_hisi_zip_LDADD=../../../.libs/libwd.a
else
test_hisi_zip_LDADD=-L../../../.libs -lwd
endif	# WD_STATIC_DRV

test_hisi_zlib_SOURCES=test_hisi_zlib.c zip_alg.c
if WD_STATIC_DRV
test_hisi_zlib_LDADD=../../../.libs/libwd.a
else
test_hisi_zlib_LDADD=-L../../../.libs -lwd
endif	# WD_STATIC_DRV

wd_zip_test_SOURCES=wd_zip_test.c zip_alg.c
if WD_STATIC_DRV
wd_zip_test_LDADD=../../../.libs/libwd.a -lz
else
wd_zip_test_LDADD=-L../../../.libs -lwd -lz
endif	# WD_STATIC_DRV

wd_zip_test_1630_SOURCES=wd_zip_test_1630.c
if WD_STATIC_DRV
wd_zip_test_1630_LDADD=../../../.libs/libwd.a -lz
else
wd_zip_test_1630_LDADD=-L../../../.libs -lwd -lz
endif	# WD_STATIC_DRV

test_hisi_zip_perf_SOURCES=test_hisi_zip_perf.c zip_alg.c
if WD_STATIC_DRV
test_hisi_zip_perf_LDADD=../../../.libs/libwd.a
else
test_hisi_zip_perf_LDADD=-L../../../.libs -lwd -lz
endif	# WD_STATIC_DRV
