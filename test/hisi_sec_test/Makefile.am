AM_CFLAGS=-Wall -fno-strict-aliasing -I../../include -pthread

bin_PROGRAMS=test_hisi_sec

test_hisi_sec_SOURCES=test_hisi_sec.c ../sched_sample.c

if WD_STATIC_DRV
AM_CFLAGS+=-Bstatic
test_hisi_sec_LDADD=../../.libs/libwd.a ../../.libs/libwd_crypto.a \
			../../.libs/libhisi_sec.a -lnuma
else
test_hisi_sec_LDADD=-L../../.libs -l:libwd.so.2 -l:libwd_crypto.so.2 -lnuma
endif
test_hisi_sec_LDFLAGS=-Wl,-rpath,'/usr/local/lib'
