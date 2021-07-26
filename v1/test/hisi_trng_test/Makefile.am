AM_CFLAGS=-Wall -Werror -O0 -fno-strict-aliasing -I$(top_srcdir)/include -I$(srcdir) -pthread

if WITH_OPENSSL_DIR
bin_PROGRAMS=test_hisi_trngu test_hisi_trngk test_hisi_trngp

test_hisi_trngu_SOURCES=test_hisi_trngu.c
test_hisi_trngk_SOURCES=test_hisi_trngk.c
test_hisi_trngp_SOURCES=test_hisi_trngp.c

if WD_STATIC_DRV
test_hisi_trngu_LDADD=../../../.libs/libwd.la
test_hisi_trngk_LDADD=../../../.libs/libwd.la
test_hisi_trngp_LDADD=../../../.libs/libwd.la
else
test_hisi_trngu_LDADD=../../../.libs/libwd.so
test_hisi_trngk_LDADD=../../../.libs/libwd.so
test_hisi_trngp_LDADD=../../../.libs/libwd.so
endif

endif
