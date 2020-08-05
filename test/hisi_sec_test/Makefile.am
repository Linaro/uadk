AM_CFLAGS=-Wall -O0 -fno-strict-aliasing -I../../include -pthread

bin_PROGRAMS=test_hisi_sec

test_hisi_sec_SOURCES=test_hisi_sec.c test_hisi_sec.h ../../drv/hisi_qm_udrv.c \
		      ../../include/hisi_qm_udrv.h

test_hisi_sec_LDADD=../../.libs/libwd.a ../../.libs/libwd_cipher.a \
 -ldl
