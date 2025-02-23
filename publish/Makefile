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
         -I/usr/local/include -I$(PLAN9)/include \
         -fstack-protector-strong -fPIE
LDFLAGS+=-L/usr/local/lib -L$(PLAN9)/lib

daemon.o: daemon.c config.h
	$(CC) -c -o $@ daemon.c $(CFLAGS)

daemon: daemon.o
	$(CC) -o $@ $^ $(LDFLAGS) -lssh2 -l9 -lbsd

install: daemon publish.sh
	install -o $(BINOWN) -m 755 publish.sh $(DESTDIR)$(BINDIR)/publish
	install -o $(BINOWN) -m 700 -s daemon $(DESTDIR)sbin/publish-daemon
ifeq ($(shell uname -s),Linux)
	install -o $(BINOWN) -m 644 publish.service /usr/lib/systemd/system/publish.service
endif

clean:
	rm -f a.out *.core publish-daemon publish-daemon.o

