SRCS=   pb.c
OBJS=   pb.o

PROG=   pb
MAN=    pb.1

BINOWN= root
BINMODE=0555
MANOWN= root
MANMODE=0644

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
         -std=c99 \
         -I/usr/local/include -I./hc \
         -fstack-protector-strong -fPIE
LIBS=    -lldap -llber
LDFLAGS+=-L/usr/local/lib


%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(PROG): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

install: $(PROG)
	install -o $(BINOWN) -m $(BINMODE) -s $(PROG) $(DESTDIR)$(BINDIR)/$(PROG)
	install -o $(MANOWN) -m $(MANMODE) $(MAN) $(DESTDIR)$(MANDIR)/man1/$(MAN)

clean:
	rm -f a.out *.core ${PROG} ${OBJS}

