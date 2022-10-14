AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I$(top_srcdir) -I$(top_srcdir)/include -I$(srcdir) -pthread

if HAVE_CRYPTO
bin_PROGRAMS=test_hisi_sec_v1

test_hisi_sec_v1_SOURCES=test_hisi_sec.c test_hisi_sec.h

if WD_STATIC_DRV
test_hisi_sec_v1_LDADD=../../../.libs/libwd.la $(libcrypto_LIBS)
else
test_hisi_sec_v1_LDADD=../../../.libs/libwd.so $(libcrypto_LIBS)

endif

endif
