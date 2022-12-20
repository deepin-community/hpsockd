
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

DIRS=util sockd

#CC=purify -cache-dir=/users/lamont/.purify-cache -follow-child-processes=yes cc
include Makefile.flags
ROOT=root
TEMPLATE=${ROOT}/opt/socks/newconfig/etc/opt/socks/sockd.conf.template

default opt:
	${MAKE} `uname -s`

debug:
	${MAKE} `uname -s`.debug

include Makefile.os

all clean clobber print:
	+for i in ${DIRS}; do (cd $$i && make $@); done

install: all
	umask 0222 && mkdir -p ${ROOT}/opt/socks/bin
	umask 0222 && mkdir -p ${ROOT}/opt/socks/sbin
	cp sockd/sockd ${ROOT}/opt/socks/sbin
	cp sockd/sdc ${ROOT}/opt/socks/bin
	cp sockd/usage ${ROOT}/opt/socks/bin
	cp sockd/log2ascii ${ROOT}/opt/socks/bin
	umask 0222 && mkdir -p ${ROOT}/sbin/init.d
	if [ -d ../Fshp-ux ]; then \
		cp ../Fshp-ux/sockd ${ROOT}/sbin/init.d/sockd; \
		chmod 544 ${ROOT}/sbin/init.d/sockd; \
		chown root:sys ${ROOT}/sbin/init.d/sockd; \
	fi
	umask 0222 && mkdir -p ${ROOT}/sbin/rc2.d ${ROOT}/sbin/rc1.d
	ln -sf /sbin/init.d/sockd ${ROOT}/sbin/rc2.d/S900sockd
	ln -sf /sbin/init.d/sockd ${ROOT}/sbin/rc1.d/K100sockd
	umask 0222 && mkdir -p ${ROOT}/opt/socks/doc
	cp ../doc/config.html ${ROOT}/opt/socks/doc
	cp ../doc/sdc.html ${ROOT}/opt/socks/doc
	cp ../doc/signals.html ${ROOT}/opt/socks/doc
	cp ../doc/rfc*.txt ${ROOT}/opt/socks/doc
	cp sockd/ChangeLog ${ROOT}/opt/socks/doc/Changelog
	chmod 444 ${ROOT}/opt/socks/doc/Changelog
	chown root:sys ${ROOT}/opt/socks/doc/Changelog
	umask 0222 && mkdir -p ${ROOT}/var/opt/socks
	umask 0222 && mkdir -p ${ROOT}/opt/socks/newconfig/etc/opt/socks
	cp sockd/sockd.conf.template ${TEMPLATE}
	chmod 444 ${TEMPLATE}
	chown root:sys ${TEMPLATE}


dist:
	mkdir -p ../dist/src ../dist/doc
	find . \( -name RCS -o -name test \) -prune -o -print | cpio -pdlmauxv ../dist/src
	cd ../doc && find . -name RCS -prune -o -print | cpio -pdlmauxv ../dist/doc

