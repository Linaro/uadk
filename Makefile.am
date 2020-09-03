ACLOCAL_AMFLAGS = -I m4 -I./include
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CFLAGS=-Wall -fno-strict-aliasing -I./include

if WITH_LOG_FILE
AM_CFLAGS+=-DWITH_LOG_FILE=\"$(with_log_file)\"
endif

if WD_STATIC_DRV
AM_CFLAGS+=-DWD_STATIC_DRV
endif

lib_LTLIBRARIES=libwd.la libwd_comp.la libhisi_zip.la libhisi_hpre.la \
		libwd_crypto.la libhisi_sec.la

libwd_la_SOURCES=wd.c wd.h bmm.c bmm.h smm.c smm.h

libwd_comp_la_SOURCES=wd_comp.c wd_comp.h wd_comp_drv.h
libwd_comp_la_LIBADD= $(libwd_la_OBJECTS) -ldl

libhisi_zip_la_SOURCES=drv/hisi_comp.c hisi_comp.h drv/hisi_qm_udrv.c \
		hisi_qm_udrv.h wd_comp_drv.h
libhisi_zip_la_LIBADD= -ldl

libwd_crypto_la_SOURCES=wd_cipher.c wd_cipher.h wd_cipher_drv.h \
			wd_rsa.c wd_rsa.h wd_hpre_drv.h \
			wd_digest.c wd_digest.h wd_digest_drv.h
libwd_crypto_la_LIBADD= $(libwd_la_OBJECTS) -ldl

libhisi_sec_la_SOURCES=drv/hisi_sec.c drv/hisi_qm_udrv.c \
		hisi_qm_udrv.h wd_cipher_drv.h
libhisi_sec_la_LIBADD= -ldl

libhisi_hpre_la_SOURCES=drv/hisi_hpre.c drv/hisi_qm_udrv.c \
		hisi_qm_udrv.h wd_hpre_drv.h
libhisi_hpre_la_LIBADD= -ldl
SUBDIRS=. test
