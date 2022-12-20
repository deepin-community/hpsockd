/* @(#)$Header: /var/cvs/hpsockd/src/sockd/v5.h,v 0.11 2000/12/08 20:47:24 lamont Exp $ */
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

#ifndef V5_H_INCLUDED
#define V5_H_INCLUDED

/* command definitions are in logging.h */

typedef struct v5Head v5HeadType;
typedef struct v5UdpHead v5UdpHeadType;

struct v5Head {
    u_int8_t	version;	/* == 5 */
    u_int8_t	cmd;
    u_int8_t	flags;
    u_int8_t	atyp;
    u_char	destAddr[4];	/* or longer, based on atyp */
    /* u_short	port;  immediately follows destAddr */
};

#define RQ_UDP_USE_CLIENT_PORT	1
#define	RQ_UDP_INTERFACE_DATA	4


struct v5UdpHead {
    u_int16_t	rsv;
    u_int8_t	frag;
    u_int8_t	atyp;
    u_char	destAddr[4];	/* or longer, based on atyp */
    /* u_short	port;  immediately follows destAddr */
};


inboundFunc newV5Client;

int v5DoConnect(fdInfoType *info);
int v5DoBind(fdInfoType *info);
int v5DoUdpAssociate(fdInfoType *info);

int v5PutSin(const struct sockaddr_in *sin, int sinLen, v5HeadType *reply);
int v5GetSin(const v5HeadType *req,struct sockaddr_in *sin,int sinLen);

int validate(fdInfoType *info,int flags,v5HeadType **req);	/* returns 0 for permit (OK), !=0 for deny. */
#define VL_NONE		0x0000			/* no flags */
#define VL_ISUDPREQ	0x0001			/* this is a udp request */

#endif /* V5_H_INCLUDED */
