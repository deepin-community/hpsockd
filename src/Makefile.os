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

HP-UX:
	${MAKE} CFLAGS="${HPOPT} ${HPCFLAGS}" CLFLAGS="${HPCLFLAGS} ${HPCLOPTFLAGS}" all

HP-UX.debug:
	${MAKE} CFLAGS="${HPDEBUG} ${HPCFLAGS}" CLFLAGS="${HPCLFLAGS}" all

HP-UX.lint:
	${MAKE} CFLAGS="${HPDEBUG} ${HPCFLAGS}" CLFLAGS="${HPCLFLAGS}" lintx

HP-UX10:
	${MAKE} CFLAGS="${HPOPT} ${HP10CFLAGS}" CLFLAGS="${HP10CLFLAGS} ${HPCLOPTFLAGS}" all

HP-UX10.debug:
	${MAKE} CFLAGS="${HPDEBUG} ${HP10CFLAGS}" CLFLAGS="${HP10CLFLAGS}" all

HP-UX9:
	${MAKE} CFLAGS="${HPOPT} ${HP9CFLAGS}" CLFLAGS="${HP9CLFLAGS} ${HPCLOPTFLAGS}" all

HP-UX9.debug:
	${MAKE} CFLAGS="${HPDEBUG} ${HP9CFLAGS}" CLFLAGS="${HP9CLFLAGS}" all

Linux:
	${MAKE} CFLAGS="${LINUXOPT} ${LINUXCFLAGS}" CLFLAGS="${LINUXCLFLAGS}" all

Linux.debug:
	${MAKE} CFLAGS="${LINUXDEBUG} ${LINUXCFLAGS}" CLFLAGS="${LINUXCLFLAGS}" all

GNU/kFreeBSD: Linux

GNU/kFreeBSD.debug: Linux.debug

