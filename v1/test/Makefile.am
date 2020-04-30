AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../internal -I../ -pthread

SUBDIRS=. test_mm bmm_test

if WITH_OPENSSL_DIR
SUBDIRS+=hisi_hpre_test
SUBDIRS+=hisi_trng_test
endif
