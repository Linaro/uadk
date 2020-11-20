#!/bin/sh

if [ -r Makefile ]; then
	make distclean
fi

FILES="aclocal.m4 autom4te.cache compile config.guess config.h.in config.log \
       config.status config.sub configure cscope.out depcomp install-sh      \
       libsrc/Makefile libsrc/Makefile.in libtool ltmain.sh Makefile         \
       ar-lib m4 Makefile.in missing src/Makefile src/Makefile.in	     \
       test/Makefile test/Makefile.in test/hisi_hpre_test/Makefile.in	     \
       test/hisi_hpre_test/Makefile test/hisi_sec_test/Makefile              \
       test/hisi_sec_test/Makefile.in test/hisi_zip_test/Makefile            \
       test/hisi_zip_test/Makefile.in					     \
       v1/Makefile.in v1/Makefile.in v1/test/Makefile v1/test/Makefile.in    \
       v1/test/test_mm/Makefile v1/test/test_mm/Makefile.in		     \
       v1/test/bmm_test/Makefile v1/test/bmm_test/Makefile.in"

rm -vRf $FILES *~
