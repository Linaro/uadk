ACLOCAL_AMFLAGS = -I m4 -I./include
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CFLAGS = -std=gnu11 -Wall -Werror -Wextra -Wno-unused-parameter -Wfloat-equal -I$(top_srcdir)/include
AM_CFLAGS += -g -O0 -fno-omit-frame-pointer -fPIC -fPIE -pie -fstack-protector-strong -ftrapv

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
REVISION = 22
UADK_VERSION = -version-number ${MAJOR}:${MINOR}:${REVISION}

DAY = 7
MONTH = Mar
YEAR = 2022
AM_CFLAGS+= -DUADK_VERSION_NUMBER="\"UADK version: ${MAJOR}.${MINOR}.${REVISION}\""
AM_CFLAGS+= -DUADK_RELEASED_TIME="\"Released ${MONTH} ${DAY}, ${YEAR}\""

include_HEADERS = include/wd.h include/wd_cipher.h include/wd_comp.h \
		  include/uacce.h include/wd_alg_common.h \
		  include/wd_sched.h include/wd_alg.h

lib_LTLIBRARIES=libwd.la libwd_comp.la libwd_crypto.la libhisi_zip.la \
		libisa_ce.la libisa_sve.la libhisi_sec.la

libwd_la_SOURCES=wd.c wd_mempool.c wd.h wd_alg.c wd_alg.h

libwd_comp_la_SOURCES=wd_comp.c wd_comp.h wd_comp_drv.h wd_util.c wd_util.h \
		      wd_sched.c wd_sched.h wd.c wd.h \
		      wd_zlibwrapper.c wd_zlibwrapper.h

libhisi_zip_la_SOURCES=drv/hisi_comp.c hisi_comp.h drv/hisi_qm_udrv.c \
		hisi_qm_udrv.h wd_comp_drv.h

libwd_crypto_la_SOURCES=wd_cipher.c wd_cipher.h wd_cipher_drv.h \
			wd_digest.c wd_digest.h wd_digest_drv.h \
			wd_util.c wd_util.h \
			wd_sched.c wd_sched.h \
			wd.c wd.h

libisa_ce_la_SOURCES=arm_arch_ce.h wd_cipher_drv.h drv/isa_ce_sm3.c \
		drv/isa_ce_sm3_armv8.S isa_ce_sm3.h \
		drv/isa_ce_sm4.c drv/isa_ce_sm4_armv8.S drv/isa_ce_sm4.h

libisa_sve_la_SOURCES=drv/hash_mb/hash_mb.c wd_digest_drv.h drv/hash_mb/hash_mb.h \
		drv/hash_mb/sm3_sve_common.S drv/hash_mb/sm3_mb_asimd_x1.S \
		drv/hash_mb/sm3_mb_asimd_x4.S drv/hash_mb/sm3_mb_sve.S \
		drv/hash_mb/md5_sve_common.S drv/hash_mb/md5_mb_asimd_x1.S \
		drv/hash_mb/md5_mb_asimd_x4.S drv/hash_mb/md5_mb_sve.S

libhisi_sec_la_SOURCES=drv/hisi_sec.c drv/hisi_qm_udrv.c \
		hisi_qm_udrv.h wd_cipher_drv.h \
		lib/crypto/aes.c lib/crypto/galois.c aes.h galois.h

if WD_STATIC_DRV
AM_CFLAGS += -DWD_STATIC_DRV
AM_CFLAGS += -DWD_NO_LOG

libwd_la_LIBADD = $(libwd_la_OBJECTS) -lnuma -lpthread

libwd_comp_la_LIBADD = $(libwd_la_OBJECTS) -ldl -lpthread -lnuma
libwd_comp_la_DEPENDENCIES = libwd.la

libhisi_zip_la_LIBADD = -ldl -lpthread

libwd_crypto_la_LIBADD = $(libwd_la_OBJECTS) -ldl -lnuma -lm -lpthread
libwd_crypto_la_DEPENDENCIES = libwd.la

libisa_ce_la_LIBADD = $(libwd_la_OBJECTS) $(libwd_crypto_la_OBJECTS)
libisa_ce_la_DEPENDENCIES = libwd.la libwd_crypto.la

libisa_sve_la_LIBADD = $(libwd_la_OBJECTS) $(libwd_crypto_la_OBJECTS)
libisa_sve_la_DEPENDENCIES = libwd.la libwd_crypto.la

libhisi_sec_la_LIBADD = $(libwd_la_OBJECTS) $(libwd_crypto_la_OBJECTS) $(libisa_ce_la_OBJECTS) $(libisa_sve_la_OBJECTS)
libhisi_sec_la_DEPENDENCIES = libwd.la libwd_crypto.la libisa_ce.la libisa_sve.la

else
UADK_WD_SYMBOL= -Wl,--version-script,$(top_srcdir)/libwd.map
UADK_CRYPTO_SYMBOL= -Wl,--version-script,$(top_srcdir)/libwd_crypto.map
#UADK_DAE_SYMBOL= -Wl,--version-script,$(top_srcdir)/libwd_dae.map
UADK_COMP_SYMBOL= -Wl,--version-script,$(top_srcdir)/libwd_comp.map
UADK_V1_SYMBOL= -Wl,--version-script,$(top_srcdir)/v1/libwd.map

libwd_la_LDFLAGS=$(UADK_VERSION) $(UADK_WD_SYMBOL) $(UADK_V1_SYMBOL)
libwd_la_LIBADD= -lnuma

libwd_comp_la_LIBADD= -lwd -ldl -lpthread -lnuma
libwd_comp_la_LDFLAGS=$(UADK_VERSION) $(UADK_COMP_SYMBOL)
libwd_comp_la_DEPENDENCIES= libwd.la

libwd_crypto_la_LIBADD= -lwd -ldl -lnuma -lm -lpthread
libwd_crypto_la_LDFLAGS=$(UADK_VERSION) $(UADK_CRYPTO_SYMBOL)
libwd_crypto_la_DEPENDENCIES= libwd.la

libhisi_zip_la_LIBADD= -lwd -ldl -lwd_comp
libhisi_zip_la_LDFLAGS=$(UADK_VERSION)
libhisi_zip_la_DEPENDENCIES= libwd.la libwd_comp.la

libisa_ce_la_LIBADD= -lwd -lwd_crypto
libisa_ce_la_LDFLAGS=$(UADK_VERSION)
libisa_ce_la_DEPENDENCIES= libwd.la libwd_crypto.la

libisa_sve_la_LIBADD= -lwd -lwd_crypto
libisa_sve_la_LDFLAGS=$(UADK_VERSION)
libisa_sve_la_DEPENDENCIES= libwd.la libwd_crypto.la

libhisi_sec_la_LIBADD= -lwd -lwd_crypto
libhisi_sec_la_LDFLAGS=$(UADK_VERSION)
libhisi_sec_la_DEPENDENCIES= libwd.la libwd_crypto.la

endif	# WD_STATIC_DRV

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lib/libwd_crypto.pc lib/libwd_comp.pc lib/libwd.pc

#SUBDIRS=. test v1/test uadk_tool sample
SUBDIRS=. uadk_tool