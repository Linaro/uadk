AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../../ -I./ -pthread

bin_PROGRAMS=wd_zip_test_sgl sgl_test

wd_zip_test_sgl_SOURCES=wd_zip_test_sgl.c zip_alg_sgl.c zip_alg_sgl.h wd_sched_sgl.c wd_sched_sgl.h
sgl_test_SOURCES=sgl_test.c sgl_test.h

if WD_STATIC_DRV
wd_zip_test_sgl_LDADD=../../../.libs/libwd.a
sgl_test_LDADD=../../../.libs/libwd.a
else
wd_zip_test_sgl_LDADD=-L../../../.libs -lwd
sgl_test_LDADD=-L../../../.libs -lwd
endif
