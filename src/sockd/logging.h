/* @(#)$Header: /var/cvs/hpsockd/src/sockd/logging.h,v 0.19 2002/03/28 19:04:26 lamont Exp $ */

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

#ifndef LOGGING_H_INCLUDED
#define LOGGING_H_INCLUDED
typedef struct logHead logHeadType;
typedef struct logClose logCloseType;
typedef struct logRec logRecType;

struct logHead {
    u_short	size;
    u_short	type;
    time_t	time;
    int		id;
};

struct logRec {
    logHeadType		head;
    unsigned char	chars[256*3+256];	/* more than enough */
};

/*************************************************************
 * Open record is:
 * +-----+-----+----+-----+-----+-----+----+------+
 * |SATYP| SRC |ULEN| USER|DATYP|DEST |PORT|METHOD|
 * +-----+-----+----+-----+-----+-----+----+------+
 * |1    |2-255|1   |1-255|1    |2-255|2   |1     |
 * +-----+-----+----+-----+-----+-----+----+------+
 *************************************************************/

struct logClose {
    u_int32_t	toSrc,toDest,reason;
};

/*************************************************************
 * Client record is:
 * +------+-----+-----+----+-----+-----+-----+----+------+-----+-----+------+
 * |SECOND|SATYP| SRC |ULEN| USER|DATYP|DEST |PORT|METHOD|toSrc|toDst|reason|
 * +------+-----+-----+----+-----+-----+-----+----+------+-----+-----+------+
 * |4     |1    |2-255|1   |1-255|1    |2-255|2   |1     |4    |4    |4     |
 * +------+-----+-----+----+-----+-----+-----+----+------+-----+-----+------+
 *************************************************************/

#define SOCKS5_ANYACTION	0	/* used in validate */
#define SOCKS5_CONNECT		1
#define SOCKS5_BIND		2
#define SOCKS5_UDP_ASSOCIATE	3
#define SOCKS5_PING		0x80
#define SOCKS5_TRACEROUTE	0x81

#define LG_TYPE_CONNECT		SOCKS5_CONNECT
#define LG_TYPE_BIND		SOCKS5_BIND
#define LG_TYPE_UDPASSOC	SOCKS5_UDP_ASSOCIATE
#define LG_TYPE_PING		SOCKS5_PING
#define LG_TYPE_TRACEROUTE	SOCKS5_TRACEROUTE

#define LG_TYPE_CLOSE		1024
#define LG_TYPE_CLIENT		2048	/* + command */

/* connection close reasons */
/* SOCKS5_results below are valid */
#define LOG_CLOSE		1000
#define LOG_PROTOCOL_ERROR	1025
#define LOG_NOTSUPP		1026
#define LOG_TIMEOUT		1027
#define LOG_NOMETHOD		1028	/* couldn't find a good method */
#define LOG_OOB_DATA_NOT_SUPP	1029
#define LOG_OUT_OF_MEMORY	1030
#define LOG_TOO_MUCH_DATA	1031	/* Received excess data on UDP control socket. */
#define LOG_TOO_MUCH_TCP_DATA	1032	/* more data than we could handle - internal err */
#define LOG_SIGNAL		1100	/* thru 1199 */
#define LOG_ERRNO		2000

/* Logging levels */
#define LG_NONE		0
#define LG_STATS	2

#define SOCKS_V4	4
#define SOCKS_V5	5

#define ADDRLEN(a) (*(a)==ATYP_V4 ? 5 : *(a)==ATYP_V6 ? 17 : 2+*(a+1))
#define ATYP_V4		1
#define ATYP_DOMAIN	3
#define ATYP_V6		4

#define SOCKS5_TRY_AGAIN	-1	/* not part of RFC - bail out and try again later */
#define SOCKS5_OK		0	/* validate */
#define SOCKS5_GENFAIL		1	/* all over */
#define SOCKS5_DENIED		2	/* validate */
#define SOCKS5_NET_UNREACH	3	/* connect/bind */
#define SOCKS5_HOST_UNREACH	4	/* connect/bind */
#define SOCKS5_CONN_REFUSED	5	/* connect/bind */
#define SOCKS5_TTL_EXPIRED	6	/* not used */
#define SOCKS5_CMD_NOT_SUPP	7	/* newV5Client */
#define SOCKS5_ADDR_NOT_SUPP	8	/* validate */
#define SOCKS5_INVALID_ADDR	9	/* bind, udpAssoc - AVENTAIL draft */

/* logging.h */
void newLog(int sig);
#endif /* LOGGING_H_INCLUDED */
