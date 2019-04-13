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
		 drv/dummy_drv.c drv/dummy_drv.h \
		 drv/hisi_qm_udrv.c drv/hisi_qm_udrv.h

SUBDIRS=. test
