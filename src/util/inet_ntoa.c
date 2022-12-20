#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/util/inet_ntoa.c,v 0.3 2000/12/08 20:49:44 lamont Exp $";
#endif

/*
(c) 1997-2000 Hewlett-Packard Company.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

/********************************************************************
 *
 * inetNtoa() returns a character string for the address given to it.
 * It needs to toggle between two buffers, because some routines call
 * it twice before using the results...
 *
 ********************************************************************/
char *inetNtor(register long addr)
{
#define ADDR_SLEN	16
#define NUM_ADDR	2
    static int which=0;
    static char str[NUM_ADDR][ADDR_SLEN];
    register unsigned int haddr=ntohl(addr);
    register int v=which;
    const char *fmt;

    which=(which+1)%NUM_ADDR;

    if (addr&0xff)
	fmt="%d.%d.%d.%d";
    else if (addr&0xffff)
	fmt="%d.%d.%d";
    else if (addr&0xffffff)
	fmt="%d.%d";
    else
	fmt="%d";
    snprintf(str[v],ADDR_SLEN,fmt,(haddr>>24&0xff),(haddr>>16&0xff),(haddr>>8&0xff),(haddr&0xff));
    return str[v];
#undef ADDR_SLEN
#undef NUM_ADDR
}
char *inetNtoa(register long addr)
{
#define ADDR_SLEN	16
#define NUM_ADDR	2
    static int which=0;
    static char str[NUM_ADDR][ADDR_SLEN];
    register unsigned int haddr=ntohl(addr);
    register int v=which;

    which=(which+1)%NUM_ADDR;
    snprintf(str[v],ADDR_SLEN,"%d.%d.%d.%d",(haddr>>24&255),(haddr>>16&255),(haddr>>8&255),(haddr&255));
    return str[v];
#undef ADDR_SLEN
#undef NUM_ADDR
}

