ACLOCAL_AMFLAGS = -I m4 -I./include
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CFLAGS=-Wall -fno-strict-aliasing -I./include

if WITH_LOG_FILE
AM_CFLAGS+=-DWITH_LOG_FILE=\"$(with_log_file)\"
endif

lib_LTLIBRARIES=libwd.la libhisi_qm.la libwd_comp.la
libwd_la_SOURCES=wd.c wd.h wd_sched.c wd_sched.h \
		bmm.c bmm.h smm.c smm.h

libhisi_qm_la_SOURCES=drv/hisi_qm_udrv.c drv/hisi_qm_udrv.h
libhisi_qm_la_LIBADD= $(libwd_la_OBJECTS)

libwd_comp_la_SOURCES=wd_comp.c wd_comp.h	\
		drv/hisi_comp.c drv/hisi_comp.h
libwd_comp_la_LIBADD= $(libwd_la_OBJECTS)

SUBDIRS=. test
