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

SRC=btree.c inetdsec.c inet_ntoa.c
OBJ=btree.o inetdsec.o inet_ntoa.o

PROGRAMS=libutil.a

default debug:
	${MAKE} `uname -s`.debug

opt:
	${MAKE} `uname -s`

include ../Makefile.os

all: ${PROGRAMS}

libutil.a: ${OBJ}
	ar rv $@ $?
	ranlib $@

clean:
	rm -f *.o

clobber: clean
	rm -f ${PROGRAMS}

print:
	@pr -n $$(echo RCS/*,v | sed 's/RCS.\([^,]*\),v/\1/g')

#	@pr -n ${CSRC} ${OSRC} ${DSRC} ${MSRC} ${LSRC} ${USRC} ${HSRC}
