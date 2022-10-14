AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I$(top_srcdir)/v1/include -pthread

if HAVE_CRYPTO
bin_PROGRAMS=bmm_test

bmm_test_SOURCES=bmm_test.c bmm_test.h

if WD_STATIC_DRV
bmm_test_LDADD=../../../.libs/libwd.la
else
bmm_test_LDADD=../../../.libs/libwd.so
endif
endif
