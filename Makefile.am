ACLOCAL_AMFLAGS = -I m4 -I./include
AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CFLAGS=-Wall -Werror -fno-strict-aliasing -I$(top_srcdir)/include
AM_CFLAGS+=-fPIC -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
	   -O2 -ftrapv -Wl,-z,relro,-z,now -Wl,-s
CLEANFILES =

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
MINOR = 7
REVISION = 0
UADK_VERSION = -version-number ${MAJOR}:${MINOR}:${REVISION}

DAY = 6
MONTH = June
YEAR = 2024
AM_CFLAGS+= -DUADK_VERSION_NUMBER="\"UADK version: ${MAJOR}.${MINOR}.${REVISION}\""
AM_CFLAGS+= -DUADK_RELEASED_TIME="\"Released ${MONTH} ${DAY}, ${YEAR}\""

pkginclude_HEADERS = include/wd.h include/wd_cipher.h include/wd_aead.h \
		  include/wd_comp.h include/wd_dh.h include/wd_digest.h \
		  include/wd_rsa.h  include/uacce.h include/wd_alg_common.h \
		  include/wd_ecc.h include/wd_sched.h include/wd_alg.h \
		  include/wd_zlibwrapper.h include/wd_dae.h include/wd_agg.h

nobase_pkginclude_HEADERS = v1/wd.h v1/wd_cipher.h v1/wd_aead.h v1/uacce.h v1/wd_dh.h \
			 v1/wd_digest.h v1/wd_rsa.h v1/wd_bmm.h

lib_LTLIBRARIES=libwd.la libwd_comp.la libwd_crypto.la libwd_dae.la

uadk_driversdir=$(libdir)/uadk
uadk_drivers_LTLIBRARIES=libhisi_sec.la libhisi_hpre.la libhisi_zip.la \
			 libisa_ce.la libisa_sve.la libhisi_dae.la

if HAVE_ZLIB
uadk_drivers_LTLIBRARIES+=libhisi_zlib.la
endif

libwd_la_SOURCES=wd.c wd_mempool.c wd.h	wd_alg.c wd_alg.h	\
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
		 v1/drv/hisi_qm_udrv.c v1/drv/hisi_qm_udrv.h \
		 v1/drv/hisi_zip_udrv.c v1/drv/hisi_zip_udrv.h \
		 v1/drv/hisi_hpre_udrv.c v1/drv/hisi_hpre_udrv.h \
		 v1/drv/hisi_sec_udrv.c v1/drv/hisi_sec_udrv.h \
		 v1/drv/hisi_rng_udrv.c v1/drv/hisi_rng_udrv.h \
		 adapter.c

libwd_dae_la_SOURCES=wd_dae.h wd_agg.h wd_agg_drv.h wd_agg.c \
		     wd_util.c wd_util.h wd_sched.c wd_sched.h wd.c wd.h

libwd_comp_la_SOURCES=wd_comp.c wd_comp.h wd_comp_drv.h wd_util.c wd_util.h \
		      wd_sched.c wd_sched.h wd.c wd.h wd_zlibwrapper.c

libhisi_zip_la_SOURCES=drv/hisi_comp.c hisi_comp.h drv/hisi_qm_udrv.c \
		hisi_qm_udrv.h wd_comp_drv.h

libhisi_zlib_la_SOURCES=drv/hisi_zlib.c

libwd_crypto_la_SOURCES=wd_cipher.c wd_cipher.h wd_cipher_drv.h \
			wd_aead.c wd_aead.h wd_aead_drv.h \
			wd_rsa.c wd_rsa.h wd_rsa_drv.h \
			wd_dh.c wd_dh.h wd_dh_drv.h \
			wd_ecc.c wd_ecc.h wd_ecc_drv.h \
			wd_digest.c wd_digest.h wd_digest_drv.h \
			wd_util.c wd_util.h \
			wd_sched.c wd_sched.h \
			wd.c wd.h

libhisi_sec_la_SOURCES=drv/hisi_sec.c drv/hisi_qm_udrv.c \
		lib/crypto/aes.c lib/crypto/galois.c \
		hisi_qm_udrv.h wd_cipher_drv.h wd_aead_drv.h aes.h galois.h

libhisi_hpre_la_SOURCES=drv/hisi_hpre.c drv/hisi_qm_udrv.c \
		hisi_qm_udrv.h

libisa_ce_la_SOURCES=arm_arch_ce.h drv/isa_ce_sm3.c drv/isa_ce_sm3_armv8.S isa_ce_sm3.h \
		drv/isa_ce_sm4.c drv/isa_ce_sm4_armv8.S drv/isa_ce_sm4.h

libisa_sve_la_SOURCES=drv/hash_mb/hash_mb.c wd_digest_drv.h drv/hash_mb/hash_mb.h \
		drv/hash_mb/sm3_sve_common.S drv/hash_mb/sm3_mb_asimd_x1.S \
		drv/hash_mb/sm3_mb_asimd_x4.S drv/hash_mb/sm3_mb_sve.S \
		drv/hash_mb/md5_sve_common.S drv/hash_mb/md5_mb_asimd_x1.S \
		drv/hash_mb/md5_mb_asimd_x4.S drv/hash_mb/md5_mb_sve.S

libhisi_dae_la_SOURCES=drv/hisi_dae.c drv/hisi_qm_udrv.c \
		hisi_qm_udrv.h

if WD_STATIC_DRV
AM_CFLAGS += -DWD_STATIC_DRV -fPIC
AM_CFLAGS += -DWD_NO_LOG

libwd_la_LIBADD = $(libwd_la_OBJECTS) -ldl -lnuma

libwd_comp_la_LIBADD = $(libwd_la_OBJECTS) -ldl -lnuma
libwd_comp_la_DEPENDENCIES = libwd.la

libhisi_zip_la_LIBADD = -ldl

libhisi_zlib_la_LIBADD = -ldl -lz

libwd_crypto_la_LIBADD = $(libwd_la_OBJECTS) -ldl -lnuma
libwd_crypto_la_DEPENDENCIES = libwd.la

libwd_dae_la_LIBADD = $(libwd_la_OBJECTS) -ldl -lnuma
libwd_dae_la_DEPENDENCIES = libwd.la

libhisi_sec_la_LIBADD = $(libwd_la_OBJECTS) $(libwd_crypto_la_OBJECTS)
libhisi_sec_la_DEPENDENCIES = libwd.la libwd_crypto.la

libhisi_hpre_la_LIBADD = $(libwd_la_OBJECTS) $(libwd_crypto_la_OBJECTS)
libhisi_hpre_la_DEPENDENCIES = libwd.la libwd_crypto.la

libisa_ce_la_LIBADD = $(libwd_la_OBJECTS) $(libwd_crypto_la_OBJECTS)
libisa_ce_la_DEPENDENCIES = libwd.la libwd_crypto.la

libisa_sve_la_LIBADD = $(libwd_la_OBJECTS) $(libwd_crypto_la_OBJECTS)
libisa_sve_la_DEPENDENCIES = libwd.la libwd_crypto.la

libhisi_dae_la_LIBADD = $(libwd_la_OBJECTS) $(libwd_dae_la_OBJECTS)
libhisi_dae_la_DEPENDENCIES = libwd.la libwd_dae.la

else
UADK_WD_SYMBOL= -Wl,--version-script,$(top_srcdir)/libwd.map
UADK_CRYPTO_SYMBOL= -Wl,--version-script,$(top_srcdir)/libwd_crypto.map
UADK_DAE_SYMBOL= -Wl,--version-script,$(top_srcdir)/libwd_dae.map
UADK_COMP_SYMBOL= -Wl,--version-script,$(top_srcdir)/libwd_comp.map
UADK_V1_SYMBOL= -Wl,--version-script,$(top_srcdir)/v1/libwd.map

libwd_la_LDFLAGS=$(UADK_VERSION) $(UADK_WD_SYMBOL) $(UADK_V1_SYMBOL)
libwd_la_LIBADD= -ldl -lnuma

libwd_comp_la_LIBADD= -lwd -ldl -lnuma
libwd_comp_la_LDFLAGS=$(UADK_VERSION) $(UADK_COMP_SYMBOL) -lpthread
libwd_comp_la_DEPENDENCIES= libwd.la

libwd_crypto_la_LIBADD= -lwd -ldl -lnuma
libwd_crypto_la_LDFLAGS=$(UADK_VERSION) $(UADK_CRYPTO_SYMBOL) -lpthread
libwd_crypto_la_DEPENDENCIES= libwd.la

libwd_dae_la_LIBADD= -lwd -ldl -lnuma
libwd_dae_la_LDFLAGS=$(UADK_VERSION) $(UADK_DAE_SYMBOL)
libwd_dae_la_DEPENDENCIES= libwd.la

libhisi_zip_la_LIBADD= -lwd -ldl -lwd_comp
libhisi_zip_la_LDFLAGS=$(UADK_VERSION)
libhisi_zip_la_DEPENDENCIES= libwd.la libwd_comp.la

libhisi_zlib_la_LIBADD= -ldl -lz
libhisi_zlib_la_LDFLAGS=$(UADK_VERSION)

libhisi_sec_la_LIBADD= -lwd -lwd_crypto
libhisi_sec_la_LDFLAGS=$(UADK_VERSION)
libhisi_sec_la_DEPENDENCIES= libwd.la libwd_crypto.la

libhisi_hpre_la_LIBADD= -lwd -lwd_crypto
libhisi_hpre_la_LDFLAGS=$(UADK_VERSION)
libhisi_hpre_la_DEPENDENCIES= libwd.la libwd_crypto.la

libisa_ce_la_LIBADD= -lwd -lwd_crypto
libisa_ce_la_LDFLAGS=$(UADK_VERSION)
libisa_ce_la_DEPENDENCIES= libwd.la libwd_crypto.la

libisa_sve_la_LIBADD= -lwd -lwd_crypto
libisa_sve_la_LDFLAGS=$(UADK_VERSION)
libisa_sve_la_DEPENDENCIES= libwd.la libwd_crypto.la

libhisi_dae_la_LIBADD= -lwd -lwd_dae
libhisi_dae_la_LDFLAGS=$(UADK_VERSION)
libhisi_dae_la_DEPENDENCIES= libwd.la libwd_dae.la

endif	# WD_STATIC_DRV

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lib/libwd_crypto.pc lib/libwd_comp.pc lib/libwd.pc
CLEANFILES += $(pkgconfig_DATA)

SUBDIRS=. test v1/test uadk_tool sample
