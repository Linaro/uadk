CC		:= gcc
CFLAGS		:=
DYNCFLAGS	:= $(CFLAGS) -shared -fPIC
STCCFLAGS	:= $(CFLAGS) -DWD_STATIC_DRV
INCLUDES	:= -I../include -I. -I..

SRCS		:= $(wildcard *.c)
STCOBJS		:= $(subst .c,.lo,$(SRCS))
DYNOBJS		:= $(subst .c,.o,$(SRCS))

TOPTARGETS	:= all clean install
SUBDIRS		:= $(wildcard */.)

$(TOPTARGETS): $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY:	$(TOPTARGETS) $(SUBDIRS)

all: $(DYNOBJS) $(STCOBJS)
%.o: %.c
	$(CC) $(INCLUDES) $(DYNCFLAGS) -c $< -o $@

%.lo: %.c
	$(CC) $(INCLUDES) $(STCCFLAGS) -c $< -o $@

#############################################################################
# clean
clean:
	$(RM) *.a *.o *.lo *.so *.so.*
