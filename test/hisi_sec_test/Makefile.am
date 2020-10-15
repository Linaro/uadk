AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../../include -pthread

bin_PROGRAMS=test_hisi_sec

test_hisi_sec_SOURCES=test_hisi_sec.c ../sched_sample.c

if WD_STATIC_DRV
AM_CFLAGS+=-Bstatic
test_hisi_sec_LDADD=../../.libs/libwd.a ../../.libs/libwd_crypto.a \
			../../.libs/libhisi_sec.a -lnuma
else
test_hisi_sec_LDADD=-L../../.libs -lwd -lwd_crypto -lhisi_sec -lnuma
endif
test_hisi_sec_LDFLAGS=-Wl,-rpath,'/usr/local/lib'
