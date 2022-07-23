ACLOCAL_AMFLAGS = -I m4 -I./include
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CFLAGS=-Wall -Werror -fno-strict-aliasing -I$(top_srcdir)/include

if WITH_LOG_FILE
AM_CFLAGS+=-DWITH_LOG_FILE=\"$(with_log_file)\"
endif	# WITH_LOG_FILE

# libtool version is {current}:{revision}:{age} with -version-info
# libNAME.so.{x}.{y}.{z}
# But {current}:{revision}:{age} doesn't equal to {x}.{y}.{z}
# x = current - age
# y = age
# z = revision
#
# libtool version is {major}:{minor}:{revision} with -version-number
# libNAME.so.{x}.{y}.{z}
# x = major
# y = minor
# z = revision
MAJOR = 2
MINOR = 3
REVISION = 35
UADK_VERSION = -version-number ${MAJOR}:${MINOR}:${REVISION}

DAY = 11
MONTH = Jun
YEAR = 2022
AM_CFLAGS+= -DUADK_VERSION_NUMBER="\"UADK version: ${MAJOR}.${MINOR}.${REVISION}\""
AM_CFLAGS+= -DUADK_RELEASED_TIME="\"Released ${MONTH} ${DAY}, ${YEAR}\""

include_HEADERS = include/wd.h include/wd_cipher.h include/wd_aead.h \
		  include/wd_comp.h include/wd_dh.h include/wd_digest.h \
		  include/wd_rsa.h  include/uacce.h include/wd_alg_common.h \
		  include/wd_common.h include/wd_ecc.h include/wd_sched.h

nobase_include_HEADERS = v1/wd.h v1/wd_cipher.h v1/wd_aead.h v1/uacce.h v1/wd_dh.h \
			 v1/wd_digest.h v1/wd_rsa.h v1/wd_bmm.h

lib_LTLIBRARIES=libwd.la libwd_comp.la libwd_crypto.la libhisi_zip.la \
		libhisi_hpre.la libhisi_sec.la

libwd_la_SOURCES=wd.c wd_mempool.c wd.h		\
		 v1/wd.c v1/wd.h v1/wd_adapter.c v1/wd_adapter.h \
		 v1/wd_rng.c v1/wd_rng.h	\
		 v1/wd_rsa.c v1/wd_rsa.h	\
		 v1/wd_aead.c v1/wd_aead.h	\
		 v1/wd_dh.c v1/wd_dh.h		\
		 v1/wd_comp.c v1/wd_comp.h	\
		 v1/wd_cipher.c v1/wd_cipher.h	\
		 v1/wd_digest.c v1/wd_digest.h	\
		 v1/wd_util.c v1/wd_util.h	\
		 v1/wd_bmm.c v1/wd_bmm.h	\
		 v1/wd_ecc.c v1/wd_ecc.h	\
		 v1/wd_sgl.c v1/wd_sgl.h	\
		 v1/drv/dummy_drv.c v1/drv/dummy_drv.h \
		 v1/drv/hisi_qm_udrv.c v1/drv/hisi_qm_udrv.h \
		 v1/drv/hisi_zip_udrv.c v1/drv/hisi_zip_udrv.h \
		 v1/drv/hisi_hpre_udrv.c v1/drv/hisi_hpre_udrv.h \
		 v1/drv/hisi_sec_udrv.c v1/drv/hisi_sec_udrv.h \
		 v1/drv/hisi_rng_udrv.c v1/drv/hisi_rng_udrv.h

libwd_comp_la_SOURCES=wd_comp.c wd_comp.h wd_comp_drv.h wd_util.c wd_util.h \
		      wd_sched.c wd_sched.h

libhisi_zip_la_SOURCES=drv/hisi_comp.c hisi_comp.h drv/hisi_qm_udrv.c \
		hisi_qm_udrv.h wd_comp_drv.h

libwd_crypto_la_SOURCES=wd_cipher.c wd_cipher.h wd_cipher_drv.h \
			wd_aead.c wd_aead.h wd_aead_drv.h \
			wd_rsa.c wd_rsa.h wd_rsa_drv.h \
			wd_dh.c wd_dh.h wd_dh_drv.h \
			wd_ecc.c wd_ecc.h wd_ecc_drv.h \
			wd_digest.c wd_digest.h wd_digest_drv.h \
			wd_util.c wd_util.h \
			wd_sched.c wd_sched.h

libhisi_sec_la_SOURCES=drv/hisi_sec.c drv/hisi_qm_udrv.c \
		hisi_qm_udrv.h wd_cipher_drv.h wd_aead_drv.h

libhisi_hpre_la_SOURCES=drv/hisi_hpre.c drv/hisi_qm_udrv.c \
		hisi_qm_udrv.h wd_hpre_drv.h
if WD_STATIC_DRV
AM_CFLAGS += -DWD_STATIC_DRV
AM_CFLAGS += -DWD_NO_LOG

libwd_la_LIBADD = $(libwd_la_OBJECTS) -lnuma

libwd_comp_la_LIBADD = $(libwd_la_OBJECTS) -ldl
libwd_comp_la_DEPENDENCIES = libwd.la

libhisi_zip_la_LIBADD = -ldl

libwd_crypto_la_LIBADD = $(libwd_la_OBJECTS) -ldl -lnuma -lm
libwd_crypto_la_DEPENDENCIES = libwd.la

libhisi_sec_la_LIBADD = $(libwd_la_OBJECTS) $(libwd_crypto_la_OBJECTS)
libhisi_sec_la_DEPENDENCIES = libwd.la libwd_crypto.la

libhisi_hpre_la_LIBADD = $(libwd_la_OBJECTS) $(libwd_crypto_la_OBJECTS)
libhisi_hpre_la_DEPENDENCIES = libwd.la libwd_crypto.la
else
libwd_la_LDFLAGS=$(UADK_VERSION)
libwd_la_LIBADD= -lnuma

libwd_comp_la_LIBADD= -lwd -ldl
libwd_comp_la_LDFLAGS=$(UADK_VERSION)
libwd_comp_la_DEPENDENCIES= libwd.la

libhisi_zip_la_LIBADD= -ldl
libhisi_zip_la_LDFLAGS=$(UADK_VERSION)

libwd_crypto_la_LIBADD= -lwd -ldl -lnuma -lm
libwd_crypto_la_LDFLAGS=$(UADK_VERSION)
libwd_crypto_la_DEPENDENCIES= libwd.la

libhisi_sec_la_LIBADD= -lwd -lwd_crypto
libhisi_sec_la_LDFLAGS=$(UADK_VERSION)
libhisi_sec_la_DEPENDENCIES= libwd.la libwd_crypto.la

libhisi_hpre_la_LIBADD= -lwd -lwd_crypto
libhisi_hpre_la_LDFLAGS=$(UADK_VERSION)
libhisi_hpre_la_DEPENDENCIES= libwd.la libwd_crypto.la
endif	# WD_STATIC_DRV


SUBDIRS=. test v1/test uadk_tool sample
