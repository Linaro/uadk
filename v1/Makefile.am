ACLOCAL_AMFLAGS = -I m4 -I./include
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CFLAGS=-Wall -O0 -fno-strict-aliasing

if WITH_LOG_FILE
AM_CFLAGS+=-DWITH_LOG_FILE=\"$(with_log_file)\"
endif

lib_LTLIBRARIES=libwd.la
libwd_la_SOURCES=wd.c wd_adapter.c wd.h wd_adapter.h \
	smm.c smm.h \
	bmm.c bmm.h \
	wd_sched.c wd_sched.h \
	wd_rsa.c wd_rsa.h \
	wd_dh.c wd_dh.h \
	wd_comp.c wd_comp.h \
	wd_cipher.c wd_cipher.h \
	wd_digest.c wd_digest.h \
	wd_util.c wd_util.h \
	wd_bmm.c wd_bmm.h \
	wd_ec.c wd_ec.h wd_ec_util.h \
	drv/dummy_drv.c drv/dummy_drv.h \
	drv/hisi_qm_udrv.c drv/hisi_qm_udrv.h \
	drv/hisi_zip_udrv.c drv/hisi_zip_udrv.h \
	drv/hisi_hpre_udrv.c drv/hisi_hpre_udrv.h \
	drv/hisi_rde_udrv.c drv/hisi_rde_udrv.h \
	drv/hisi_sec_udrv.c drv/hisi_sec_udrv.h
libwd_la_LDFLAGS=-version-info 1:0:0
SUBDIRS=. test

