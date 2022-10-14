AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I$(top_srcdir) -I$(top_srcdir)/v1/internal -pthread

if HAVE_CRYPTO
bin_PROGRAMS=test_hisi_hpre_v1 hpre_test_tools_v1 test_hisi_hpre_times_v1

test_hisi_hpre_v1_SOURCES=test_hisi_hpre.c test_hisi_hpre.h
hpre_test_tools_v1_SOURCES=hpre_test_tools.c
test_hisi_hpre_times_v1_SOURCES=test_hisi_hpre_times.c test_hisi_hpre.h hpre_test_sample.h

if WD_STATIC_DRV
test_hisi_hpre_v1_LDADD=../../../.libs/libwd.la
hpre_test_tools_v1_LDADD=../../../.libs/libwd.la
test_hisi_hpre_times_v1_LDADD=../../../.libs/libwd.la
else
test_hisi_hpre_v1_LDADD=../../../.libs/libwd.so
hpre_test_tools_v1_LDADD=../../../.libs/libwd.so
test_hisi_hpre_times_v1_LDADD=../../../.libs/libwd.so
endif

test_hisi_hpre_v1_LDADD+=$(libcrypto_LIBS)
hpre_test_tools_v1_LDADD+=$(libcrypto_LIBS)
test_hisi_hpre_times_v1_LDADD+=$(libcrypto_LIBS)
endif
