AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../../../include -I lib -pthread

SUBDIRS=. test_mm bmm_test

SUBDIRS+=hisi_zip_test
SUBDIRS+=hisi_zip_test_sgl
SUBDIRS+=hisi_sec_test_sgl

if WITH_OPENSSL_DIR
SUBDIRS+=hisi_hpre_test
SUBDIRS+=hisi_trng_test
SUBDIRS+=hisi_sec_test
endif
