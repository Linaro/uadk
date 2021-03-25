AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../../internal -pthread

if WITH_OPENSSL_DIR
bin_PROGRAMS=test_hisi_hpre hpre_test_tools test_hisi_hpre_times

test_hisi_hpre_SOURCES=test_hisi_hpre.c test_hisi_hpre.h
hpre_test_tools_SOURCES=hpre_test_tools.c
test_hisi_hpre_times_SOURCES=test_hisi_hpre_times.c test_hisi_hpre.h hpre_test_sample.h

test_hisi_hpre_LDADD=../../../.libs/libwd.so $(with_openssl_dir)/libcrypto.so
hpre_test_tools_LDADD=../../../.libs/libwd.so $(with_openssl_dir)/libcrypto.so
test_hisi_hpre_times_LDADD=../../../.libs/libwd.so $(with_openssl_dir)/libcrypto.so
endif
