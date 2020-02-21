ACLOCAL_AMFLAGS = -I m4 -I./include
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CFLAGS=-Wall -fno-strict-aliasing

if WITH_LOG_FILE
AM_CFLAGS+=-DWITH_LOG_FILE=\"$(with_log_file)\"
endif

lib_LTLIBRARIES=libwd.la libhisi_qm.la
libwd_la_SOURCES=wd.c wd.h \
		 smm.c smm.h \
		 bmm.c bmm.h

libhisi_qm_la_SOURCES= drv/hisi_qm_udrv.c drv/hisi_qm_udrv.h

SUBDIRS=. test
