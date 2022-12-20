/* @(#)$Header: /var/cvs/hpsockd/src/sockd/v4.h,v 0.8 2000/12/08 20:47:24 lamont Exp $ */
/*
(c) Copyright Hewlett-Packard Company 1997-2000.

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

#ifndef V4_H_INCLUDED
#define V4_H_INCLUDED

#define SOCKS_CONNECT		1
#define SOCKS_BIND		2

#define SOCKS4_RESULT		90
#define SOCKS4_FAIL		91
#define SOCKS4_NO_IDENTD	92
#define SOCKS4_BAD_ID		93

typedef struct v4Head v4HeadType;

struct v4Head {
    u_int8_t	version;	/* == 4 */
    u_int8_t	cmd;
    u_int16_t	port;
    u_int32_t	destIP;
    char	user[4];	/* actually whatever it takes... */
};


inboundFunc newV4Client;

void v4DoConnect(fdInfoType *info,v4HeadType *req);
void v4DoBind(fdInfoType *info,v4HeadType *req);

#endif /* V4_H_INCLUDED */
