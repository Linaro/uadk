AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I$(top_srcdir)/v1/internal -I$(top_srcdir)/v1 -I$(srcdir)lib -pthread

SUBDIRS=. test_mm bmm_test

if HAVE_ZLIB
SUBDIRS+=hisi_zip_test
endif

SUBDIRS+=hisi_zip_test_sgl
SUBDIRS+=hisi_trng_test

if HAVE_CRYPTO
SUBDIRS+=hisi_hpre_test
SUBDIRS+=hisi_sec_test
SUBDIRS+=hisi_sec_test_sgl
endif
