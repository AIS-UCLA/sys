BINOWN= root

ifeq ($(shell uname -s),Linux)
	DESTDIR=/usr/
	BINDIR= local/bin
	MANDIR= share/man/
	else
	DESTDIR=/usr/local/
	BINDIR= bin
	MANDIR:=share/man/
endif

CFLAGS+= -W -Wextra -Wpedantic -Werror \
         -Wcast-qual -Wconversion -Wformat=2 -Wformat-security -Wnull-dereference -Wstack-protector \
         -Warray-bounds-pointer-arithmetic -Wconditional-uninitialized -Wcomma -Wpointer-arith -Widiomatic-parentheses \
         -Wunreachable-code-aggressive \
         -I/usr/local/include \
         -fstack-protector-strong -fPIE
LDFLAGS+=-L/usr/local/lib -lleveldb

all: reaper check

reaper.o: reaper.c config.h helpers.h
	$(CC) -c -o $@ reaper.c $(CFLAGS)

check.o: check.c config.h helpers.h
	$(CC) -c -o $@ check.c $(CFLAGS)

reaper: reaper.o
	$(CC) -o $@ $^ $(LDFLAGS) -lnvidia-ml

check: check.o
	$(CC) -o $@ $^ $(LDFLAGS)

install: reaper check
	install -o $(BINOWN) -m 755 check $(DESTDIR)$(BINDIR)/reaper-check
	install -o $(BINOWN) -m 744 -s reaper $(DESTDIR)sbin/reaper

clean:
	rm -f a.out *.core reaper check

.PHONY: all
