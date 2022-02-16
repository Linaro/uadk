ACLOCAL_AMFLAGS = -I m4 -I./include
AM_CFLAGS=-Wall -fno-strict-aliasing -I$(top_srcdir) -I$(top_srcdir)/include

bin_PROGRAMS=uadk_comp

uadk_comp_SOURCES=uadk_comp.c

if WD_STATIC_DRV
AM_CFLAGS+=-Bstatic
uadk_comp_LDADD=../.libs/libwd.a		\
		  ../.libs/libwd_comp.a		\
		  ../.libs/libhisi_zip.a -lpthread -lnuma
else
uadk_comp_LDADD=-L../.libs -l:libwd.so.2 -l:libwd_comp.so.2 -lpthread -lnuma
endif
uadk_comp_LDFLAGS=-Wl,-rpath,'/usr/local/lib'
