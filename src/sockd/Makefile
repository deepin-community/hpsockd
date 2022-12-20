
# (c) Copyright Hewlett-Packard Company 1997-2000
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

include ../Makefile.flags

CSRC=methods.c sockd.c util.c logging.c dns.c signal.c
MSRC=listen.c v4.c v5.c userpass.c v5command.c v5tcp.c v5udp.c
DSRC=sdc.c
LSRC=log2ascii.c
USRC=usage.c
OSRC=lexer.l gram.y
HSRC=logging.h sockd.h v4.h v5.h

OBJ=methods.o sockd.o signal.o util.o logging.o dns.o gram.tab.o lexer.o vers.o
MOBJ=listen.o v4.o v5.o userpass.o v5tcp.o v5udp.o v5command.o
DOBJ=sdc.o gram.tab.o lexer.o vers.o
LOBJ=log2ascii.o vers.o
UOBJ=usage.o vers.o

PROGRAMS=sockd sdc log2ascii usage

default: opt

debug: ../util/libutil.a
	${MAKE} `uname -s`.debug

opt: ../util/libutil.a
	${MAKE} `uname -s`

lint: ../util/libutil.a
	${MAKE} `uname -s`.lint

../util/libutil.a:
	@cd ../util; ${MAKE} `uname -s`

include ../Makefile.os

all: ${PROGRAMS}

sockd: ${OBJ} ${MOBJ}
	${CC} ${CFLAGS} -o $@ ${OBJ} ${MOBJ} ${CLFLAGS} ../util/libutil.a

lintx: ${OBJ} ${MOBJ}
	lint ${CFLAGS} ${CSRC} ${MSRC} lexer.c gram.tab.c

sdc: ${DOBJ}
	${CC} ${CFLAGS} -o $@ ${DOBJ} ../util/libutil.a

log2ascii: ${LOBJ}
	${CC} ${CFLAGS} -o $@ ${LOBJ} ../util/libutil.a

usage: ${UOBJ}
	${CC} ${CFLAGS} -o $@ ${UOBJ} ../util/libutil.a

gram.tab.c gram.tab.h: gram.y
	if [ -f /usr/bin/byacc ]; then		\
	    byacc -b gram -d -v gram.y;		\
	else					\
	    yacc -b gram -d -v gram.y;		\
	fi

lexer.c: lexer.l
	flex -p -s -t lexer.l > lexer.c
    
lexer.o: lexer.c gram.tab.h

vers.c: ../../debian/changelog
	sed -n '1,1s/.*(\(.*\)).*$$/char *socks_version="@(#)sockd version \1";/p' < $? > $@

clean:
	rm -f *.o gram.output gram.tab.c gram.tab.h lexer.c

clobber: clean
	rm -f ${PROGRAMS} vers.c

print:
	@pr -n $$(echo RCS/*,v | sed 's/RCS.\([^,]*\),v/\1/g')

fc:	
	@make debug
	rsync -ave ssh *.[chyl] sockd ftcona2.hp.com:socks5/
