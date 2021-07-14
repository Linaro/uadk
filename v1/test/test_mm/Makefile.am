AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../../include -I../../ -pthread

bin_PROGRAMS=test_wd_mem

test_wd_mem_SOURCES=test_wd_mem.c test_wd_mem.h

if WD_STATIC_DRV
test_wd_mem_LDADD=../../../.libs/libwd.la -ldl -lnuma
else
test_wd_mem_LDADD=../../../.libs/libwd.so -ldl -lnuma
endif
