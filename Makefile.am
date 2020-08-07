ACLOCAL_AMFLAGS = -I m4 -I./include
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CFLAGS=-Wall -fno-strict-aliasing -I./include

if WITH_LOG_FILE
AM_CFLAGS+=-DWITH_LOG_FILE=\"$(with_log_file)\"
endif

if WD_STATIC_DRV
AM_CFLAGS+=-DWD_STATIC_DRV
endif

lib_LTLIBRARIES=libwd.la libwd_comp.la libhisi_zip.la libwd_cipher.la libhisi_sec.la

libwd_la_SOURCES=wd.c wd.h wd_sched.c wd_sched.h bmm.c bmm.h smm.c smm.h

libwd_comp_la_SOURCES=wd_comp.c wd_comp.h wd_comp_drv.h
libwd_comp_la_LIBADD= $(libwd_la_OBJECTS) -ldl

libhisi_zip_la_SOURCES=drv/hisi_comp.c hisi_comp.h drv/hisi_qm_udrv.c \
		hisi_qm_udrv.h wd_comp_drv.h wd_sched.c wd_sched.h smm.c smm.h
libhisi_zip_la_LIBADD= -ldl

libwd_cipher_la_SOURCES=wd_cipher.c wd_cipher.h \
		drv/hisi_sec.c hisi_sec.h drv/hisi_qm_udrv.c hisi_qm_udrv.h
libwd_cipher_la_LIBADD= $(libwd_la_OBJECTS) -ldl

libhisi_sec_la_SOURCES=drv/hisi_comp.c hisi_comp.h drv/hisi_qm_udrv.c \
		hisi_qm_udrv.h wd_sched.c wd_sched.h smm.c smm.h
libhisi_sec_la_LIBADD= -ldl
SUBDIRS=. test
