ACLOCAL_AMFLAGS = -I m4 -I./include
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CFLAGS=-Wall -fno-strict-aliasing

if WITH_LOG_FILE
AM_CFLAGS+=-DWITH_LOG_FILE=\"$(with_log_file)\"
endif

#lib_LTLIBRARIES=libwd.la libwd_sched.la libsmm.la libhisi_qm.la libwd_comp.la
#libwd_la_SOURCES=wd.c wd.h bmm.c bmm.h

#libwd_sched_la_SOURCES=wd_sched.c wd_sched.h

#libsmm_la_SOURCES=smm.c smm.h

#libhisi_qm_la_SOURCES=drv/hisi_qm_udrv.c drv/hisi_qm_udrv.h

#libwd_comp_la_SOURCES=wd_comp.c wd_comp.h drv/hisi_comp.c
#libwd_comp_la_LIBADD=-lwd_sched

lib_LTLIBRARIES=libwd.la
libwd_la_SOURCES=wd.c wd.h wd_sched.c wd_sched.h bmm.c bmm.h smm.c smm.h \
		drv/hisi_qm_udrv.c drv/hisi_qm_udrv.h	\
		wd_comp.c wd_comp.h drv/hisi_comp.c

SUBDIRS=. test
