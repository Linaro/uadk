AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I$(top_srcdir) -I$(top_srcdir)/v1/internal -pthread

if HAVE_CRYPTO
bin_PROGRAMS=test_hisi_hpre hpre_test_tools test_hisi_hpre_times

test_hisi_hpre_SOURCES=test_hisi_hpre.c test_hisi_hpre.h
hpre_test_tools_SOURCES=hpre_test_tools.c
test_hisi_hpre_times_SOURCES=test_hisi_hpre_times.c test_hisi_hpre.h hpre_test_sample.h

if WD_STATIC_DRV
test_hisi_hpre_LDADD=../../../.libs/libwd.la
hpre_test_tools_LDADD=../../../.libs/libwd.la
test_hisi_hpre_times_LDADD=../../../.libs/libwd.la
else
test_hisi_hpre_LDADD=../../../.libs/libwd.so
hpre_test_tools_LDADD=../../../.libs/libwd.so
test_hisi_hpre_times_LDADD=../../../.libs/libwd.so
endif

test_hisi_hpre_LDADD+=-lcrypto
hpre_test_tools_LDADD+=-lcrypto
test_hisi_hpre_times_LDADD+=-lcrypto
endif
