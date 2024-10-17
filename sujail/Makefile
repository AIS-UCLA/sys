SRCS=   sujail.c
OBJS=   sujail.o

PROG=   sujail
MAN=    sujail.1 sujail.conf.5

BINOWN= root
BINMODE=4555

DESTDIR=/usr/local/
BINDIR= sbin

CFLAGS+= -W -Wextra -Wpedantic -Werror \
         -Wcast-qual -Wformat=2 -Wformat-security -Wnull-dereference -Wstack-protector \
         -std=c99 \
         -fstack-protector-strong  -fPIE 
LIBS= -lutil


%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(PROG): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

install: $(PROG)
	install -o $(BINOWN) -m $(BINMODE) -s $(PROG) $(DESTDIR)$(BINDIR)/$(PROG)

clean:
	rm -f a.out *.core ${PROG} ${OBJS}

