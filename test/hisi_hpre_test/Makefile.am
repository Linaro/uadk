AM_CFLAGS=-w -O0 -fno-strict-aliasing -I../../include -pthread

bin_PROGRAMS=test_hisi_hpre

test_hisi_hpre_SOURCES=test_hisi_hpre.c test_hisi_hpre.h
	
if WD_STATIC_DRV
test_hisi_hpre_LDADD=../../.libs/libwd.a ../../.libs/libwd_crypto.a \
			../../.libs/libhisi_hpre.a -ldl
else
test_hisi_hpre_LDADD=-L../../.libs -lwd -lwd_crypto -lhisi_hpre
endif
test_hisi_hpre_LDFLAGS=-Wl,-rpath,'/usr/local/lib'
