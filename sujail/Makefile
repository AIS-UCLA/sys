SRCS=   sujail.c
OBJS=   sujail.o

PROG=   sujail
MAN=    sujail.1

BINOWN= root
BINMODE=4555
MANOWN= root
MANMODE=0644

DESTDIR=/usr/local/
BINDIR= sbin
MANDIR= share/man/

CFLAGS+= -W -Wextra -Wpedantic -Werror \
         -Wcast-qual -Wconversion -Wformat=2 -Wformat-security -Wnull-dereference -Wstack-protector \
         -Warray-bounds-pointer-arithmetic -Wconditional-uninitialized -Wcomma -Wpointer-arith -Widiomatic-parentheses \
         -Wunreachable-code-aggressive \
         -std=c99 \
         -fstack-protector-strong -fPIE
LIBS= -lutil


%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(PROG): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

install: $(PROG)
	install -o $(BINOWN) -m $(BINMODE) -s $(PROG) $(DESTDIR)$(BINDIR)/$(PROG)
	install -o $(MANOWN) -m $(MANMODE) $(MAN) $(DESTDIR)$(MANDIR)/man1/$(MAN)

clean:
	rm -f a.out *.core ${PROG} ${OBJS}

