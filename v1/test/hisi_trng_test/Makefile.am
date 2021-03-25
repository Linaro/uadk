AM_CFLAGS=-Wall -Werror -O0 -fno-strict-aliasing -I$(top_srcdir)/include -I$(srcdir) -pthread

bin_PROGRAMS=test_hisi_trngu test_hisi_trngk test_hisi_trngp

test_hisi_trngu_SOURCES=test_hisi_trngu.c
test_hisi_trngk_SOURCES=test_hisi_trngk.c
test_hisi_trngp_SOURCES=test_hisi_trngp.c

test_hisi_trngu_LDADD=../../../.libs/libwd.la
test_hisi_trngk_LDADD=../../../.libs/libwd.la
test_hisi_trngp_LDADD=../../../.libs/libwd.la
