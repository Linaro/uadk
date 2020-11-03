CC		:= gcc
CFLAGS		:= -O2
DYNCFLAGS	:= $(CFLAGS) -shared -fPIC
STCCFLAGS	:= $(CFLAGS) -DWD_STATIC_DRV
INCLUDES	:= -I./include -I.
AR		:= ar
ARFLAGS		:= rv
LD		:= ld

RM		:= rm -f
LN		:= ln -sf
INSTALL		:= install
MAJOR		:= 0
MINOR		:= 0
REVISION	:= 0
VERSION		:= $(MAJOR).$(MINOR).$(REVISION)

SOURCE_DIR	:= . drv test test/hisi_hpre_test test/hisi_sec_test	\
		   test/hisi_zip_test
LIBDIR		:= /usr/local/lib
APPDIR		:= /usr/local/bin
INCDIR		:= /usr/local/include/uadk
DYNAPP		:= test_hisi_sec test_hisi_hpre zip_sva_perf
STCAPP		:= test_hisi_sec.static test_hisi_hpre.static		\
		   zip_sva_perf.static
TARGET_DYNLIB	:= libwd.so.$(VERSION) libwd_crypto.so.$(VERSION)	\
		   libwd_comp.so.$(VERSION) libhisi_sec.so.$(VERSION)	\
		   libhisi_hpre.so.$(VERSION) libhisi_zip.so.$(VERSION)
DYNLIB_MAJOR	:= libwd.so.$(MAJOR) libwd_crypto.so.$(MAJOR)		\
		   libwd_comp.so.$(MAJOR) libhisi_sec.so.$(MAJOR)	\
		   libhisi_hpre.so.$(MAJOR) libhisi_zip.so.$(MAJOR)
DYNLIB_SHORT	:= libwd.so libwd_crypto.so libwd_comp.so		\
		   libhisi_sec.so libhisi_hpre.so libhisi_zip.so
TARGET_STCLIB	:= libwd.a libwd_crypto.a libwd_comp.a libhisi_sec.a	\
		   libhisi_hpre.a libhisi_zip.a

HEADFILES	:= uacce.h wd_alg_common.h wd_cipher.h wd_comp.h	\
		   wd_dh.h wd_digest.h wd.h wd_rsa.h

SRCS		:= $(wildcard *.c)
STCOBJS		:= $(subst .c,.lo,$(SRCS))
DYNOBJS		:= $(subst .c,.o,$(SRCS))


TOPTARGETS	:= all clean install
SUBDIRS		:= drv test

$(TOPTARGETS): $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY:	$(TOPTARGETS) $(SUBDIRS)


all: $(DYNOBJS) $(STCOBJS) $(TARGET_DYNLIB) $(TARGET_STCLIB) $(DYNAPP)	\
     $(STCAPP)
libwd.so.$(VERSION): wd.o
	$(CC) $(DYNCFLAGS) -o $@ $?
	$(LN) libwd.so.$(VERSION) libwd.so

libwd_crypto.so.$(VERSION): wd_aead.o wd_cipher.o wd_digest.o wd_util.o	\
			    wd_rsa.o wd_dh.o
	$(CC) $(DYNCFLAGS) -o $@ $? -L. -lwd -lnuma -ldl
	$(LN) libwd_crypto.so.$(VERSION) libwd_crypto.so

libwd_comp.so.$(VERSION): wd_comp.o wd_util.o
	$(CC) $(DYNCFLAGS) -o $@ $? -L. -lwd -ldl
	$(LN) libwd_comp.so.$(VERSION) libwd_comp.so

libhisi_sec.so.$(VERSION): drv/hisi_sec.o drv/hisi_qm_udrv.o
	$(CC) $(DYNCFLAGS) -o $@ $? -L. -lwd -lwd_crypto
	$(LN) libhisi_sec.so.$(VERSION) libhisi_sec.so

libhisi_hpre.so.$(VERSION): drv/hisi_hpre.o drv/hisi_qm_udrv.o
	$(CC) $(DYNCFLAGS) -o $@ $? -L. -lwd -lwd_crypto
	$(LN) libhisi_hpre.so.$(VERSION) libhisi_hpre.so

libhisi_zip.so.$(VERSION): drv/hisi_comp.o drv/hisi_qm_udrv.o
	$(CC) $(DYNCFLAGS) -o $@ $? -L. -lwd
	$(LN) libhisi_zip.so.$(VERSION) libhisi_zip.so

test_hisi_sec: test/hisi_sec_test/test_hisi_sec.o test/sched_sample.o
	$(CC) -Wl,-rpath=/usr/local/lib -o $@ $^ -L. -lwd -lwd_crypto -lpthread

test_hisi_hpre: test/hisi_hpre_test/test_hisi_hpre.o test/sched_sample.o
	$(CC) -Wl,-rpath=/usr/local/lib -o $@ $^ -L. -lwd -lwd_crypto -lpthread

zip_sva_perf: test/hisi_zip_test/test_sva_perf.o test/sched_sample.o	\
	       test/hisi_zip_test/test_lib.o test/hisi_zip_test/sva_file_test.o
	$(CC) -Wl,-rpath=/usr/local/lib -o $@ $^ -L. -lwd -lwd_comp	\
		-lpthread -lm -lz

libwd.a: wd.lo
	$(AR) $(ARFLAGS) $@ $^

libwd_crypto.a: wd_aead.lo wd_cipher.lo wd_digest.lo wd_util.lo		\
		wd_rsa.lo wd_dh.lo
	$(AR) $(ARFLAGS) $@ $^

libwd_comp.a: wd_comp.lo wd_util.lo
	$(AR) $(ARFLAGS) $@ $^

libhisi_sec.a: drv/hisi_sec.lo drv/hisi_qm_udrv.lo
	$(AR) $(ARFLAGS) $@ $^

libhisi_hpre.a: drv/hisi_hpre.lo drv/hisi_qm_udrv.lo
	$(AR) $(ARFLAGS) $@ $^

libhisi_zip.a: drv/hisi_comp.lo drv/hisi_qm_udrv.lo
	$(AR) $(ARFLAGS) $@ $^

test_hisi_sec.static: test/hisi_sec_test/test_hisi_sec.lo test/sched_sample.lo
	$(CC) -o $@ $^ libwd.a libwd_crypto.a libhisi_sec.a -lnuma -lpthread

test_hisi_hpre.static: test/hisi_hpre_test/test_hisi_hpre.lo	\
		       test/sched_sample.lo
	$(CC) -o $@ $^ libwd.a libwd_crypto.a libhisi_hpre.a -lpthread

zip_sva_perf.static: test/hisi_zip_test/test_sva_perf.lo test/sched_sample.lo	\
		     test/hisi_zip_test/test_lib.lo				\
		     test/hisi_zip_test/sva_file_test.lo
	$(CC) -o $@ $^ libwd.a libwd_comp.a libhisi_zip.a -lpthread -lm -lz

%.o: %.c
	$(CC) $(INCLUDES) $(DYNCFLAGS) -c $< -o $@

%.lo: %.c
	$(CC) $(INCLUDES) $(STCCFLAGS) -c $< -o $@

#############################################################################
# clean
clean:
	$(RM) *.a *.o *.lo *.so *.so.*


#############################################################################
# install
install:
	$(INSTALL) -m 755 -t $(LIBDIR) $(TARGET_DYNLIB)
	$(INSTALL) -m 755 -t $(LIBDIR) $(TARGET_STCLIB)
	$(INSTALL) -m 755 -t $(APPDIR) $(DYNAPP)
	$(INSTALL) -m 755 -d $(INCDIR)
	for d in $(HEADFILES);					\
	do							\
		$(INSTALL) -m 755 -t $(INCDIR) include/$$d;	\
	done
	#PATH="$(PATH):/sbin" ldconfig -v -n $(LIBDIR)
	# Fail to use ldconfig. Use ln instead.
	export PATH="$(PATH):/sbin"
	$(LN) $(LIBDIR)/libwd.so.$(VERSION) $(LIBDIR)/libwd.so.$(MAJOR)
	$(LN) $(LIBDIR)/libwd.so.$(VERSION) $(LIBDIR)/libwd.so
	$(LN) $(LIBDIR)/libwd_comp.so.$(VERSION) $(LIBDIR)/libwd_comp.so.$(MAJOR)
	$(LN) $(LIBDIR)/libwd_comp.so.$(VERSION) $(LIBDIR)/libwd_comp.so
	$(LN) $(LIBDIR)/libwd_crypto.so.$(VERSION) $(LIBDIR)/libwd_crypto.so.$(MAJOR)
	$(LN) $(LIBDIR)/libwd_crypto.so.$(VERSION) $(LIBDIR)/libwd_crypto.so
	$(LN) $(LIBDIR)/libhisi_hpre.so.$(VERSION) $(LIBDIR)/libhisi_hpre.so.$(MAJOR)
	$(LN) $(LIBDIR)/libhisi_hpre.so.$(VERSION) $(LIBDIR)/libhisi_hpre.so
	$(LN) $(LIBDIR)/libhisi_sec.so.$(VERSION) $(LIBDIR)/libhisi_sec.so.$(MAJOR)
	$(LN) $(LIBDIR)/libhisi_sec.so.$(VERSION) $(LIBDIR)/libhisi_sec.so
	$(LN) $(LIBDIR)/libhisi_zip.so.$(VERSION) $(LIBDIR)/libhisi_zip.so.$(MAJOR)
	$(LN) $(LIBDIR)/libhisi_zip.so.$(VERSION) $(LIBDIR)/libhisi_zip.so
