AM_CFLAGS=-Wall -fno-strict-aliasing -I$(top_srcdir)/include -pthread

bin_PROGRAMS=test_hisi_hpre

test_hisi_hpre_SOURCES=test_hisi_hpre.c test_hisi_hpre.h
	
if WD_STATIC_DRV
test_hisi_hpre_LDADD=../../.libs/libwd.a ../../.libs/libwd_crypto.a \
			../../.libs/libhisi_hpre.a -ldl -lnuma
else
test_hisi_hpre_LDADD=-L../../.libs -l:libwd.so.2 -l:libwd_crypto.so.2 \
			-lnuma
endif
test_hisi_hpre_LDFLAGS=-Wl,-rpath,'/usr/local/lib'
test_hisi_hpre_LDADD+= $(libcrypto_LIBS)
