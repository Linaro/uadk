AM_CFLAGS=-Wall -Werror -O0 -fno-strict-aliasing -I$(top_srcdir)/include -I$(srcdir) -pthread

if HAVE_CRYPTO
bin_PROGRAMS=test_hisi_trngu_v1 test_hisi_trngk_v1 test_hisi_trngp_v1

test_hisi_trngu_v1_SOURCES=test_hisi_trngu.c
test_hisi_trngk_v1_SOURCES=test_hisi_trngk.c
test_hisi_trngp_v1_SOURCES=test_hisi_trngp.c

if WD_STATIC_DRV
test_hisi_trngu_v1_LDADD=../../../.libs/libwd.la
test_hisi_trngk_v1_LDADD=../../../.libs/libwd.la
test_hisi_trngp_v1_LDADD=../../../.libs/libwd.la
else
test_hisi_trngu_v1_LDADD=../../../.libs/libwd.so
test_hisi_trngk_v1_LDADD=../../../.libs/libwd.so
test_hisi_trngp_v1_LDADD=../../../.libs/libwd.so
endif

endif
