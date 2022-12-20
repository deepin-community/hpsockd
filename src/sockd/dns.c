#include "sockd.h"
#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/dns.c,v 0.28 2001/12/29 06:12:33 lamont Exp $";
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

typedef struct dnsReq dnsReqType;
typedef struct dnsReply dnsReplyType;
sendFunc dnsWrite;

/*****************************************************************************
 *
 * The philosophy here is that one (or more) helper process(es) accept
 * requests on a port bound to 127.0.0.1, do the dns lookups, and then fire
 * the answer back to the guy who asked the question.  That sockd then
 * sanitizes the answer, and redoes the request processing, which
 * successfully hits the one entry cache in sockd, and things go from there.
 *
 * The basic flow is sockd -> dnsQuery -> sendto (return -1 -> SOCKS5_TRY_AGAIN)
 *	dnsHandler -> recvFrom -> gethostbyname -> sendto
 *	(sockd) mainLoop -> dnsRecv -> client->output -> dnsQuery(returns)
 *
 * At some point, we should consider doing reverse lookups, but for now we
 * just have room in the structure, but no code behind it.
 *****************************************************************************/
struct dnsReq {
    int			clientFd;
    int			type;
#define DNS_QUERY	1
#define DNS_IQUERY	2 
    union {
	char		name[256];
	struct {
	    int		type;
	    int		len;		/* actual length of addr */
	    char	addr[248];
	} addr;
    } req;
};
struct dnsReply {
    int			clientFd;
    long		bias;		/* &hostent when pointers were calculated */
    struct hostent	hostent;
};

void dnsHandler(int fd);
fdInfoType *dnsInfo;

/*****************************************************************************
 *
 * dnsGlobalInit() does the global initialization of the dns helper processes.
 * When it's done, dnsAddr holds the address of the helpers (who all listen
 * on the same address), and the helpers are all running.
 *
 *****************************************************************************/
struct sockaddr_in dnsAddr;
void dnsGlobalInit(void)
{
    register int	s;
    struct sockaddr_in	sin;
    int			sinLen;
    register int	i;
    register int	res;

    if (!config.daemon.numHelper)
	return;

    s=socket(AF_INET,SOCK_DGRAM,0);
    if (s<0) {
	syslog(LOG_ERR,"dns socket: %m");
	exit(2);
    }
    if (s>=maxFd) {
	syslog(LOG_ERR,"dns socket out of range");
	exit(2);
    }

    memset(&sin,0,sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port   = 0;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(s,(struct sockaddr*)&sin,sizeof(sin))<0) {
	perror("bind");
	exit(2);
    }

    sinLen=sizeof(dnsAddr);
    do {
	res=getsockname(s,&dnsAddr,&sinLen);
    } while (res<0 && errno==EINTR);

    for (i=config.daemon.numHelper; i>0; i--) {
	register int pid;
	do {
	    pid=fork();
	} while (pid<0 && errno==EINTR);

	if (pid==0) {
	    register int j;
	    for (j=0;daemonFd[j]>=0;j++) {
		close(daemonFd[j]);
	    }
	    free(daemonFd);
	    setupSignals(0);
	    setCommandLine("sockd --dnsHandler");

	    if (debug&DBG_DNS) {
		/* let the debugger come find us */
		volatile int debugSpin=0;
		while (!debugSpin);
	    }

	    dnsHandler(s);
	    return;
	} else if (pid<0) {
	    syslog(LOG_ERR,"fork(dnsHelper) failed: %m");
	    break;
	}
    }
    close(s);
}

/*****************************************************************************
 *
 * dnsServerInit() does the initialization of the sockd half of things, and
 * gets called once per server from setupDaemon().  After this point, we can
 * send queries to the dns helper.
 *
 *****************************************************************************/
void dnsServerInit(void)
{
    register int	s;
    struct sockaddr_in	sin;
    register fdInfoType	*info;
    register int	oldS=-1;

    if (!config.daemon.numHelper)
	return;

    if (dnsInfo) {
	oldS=dnsInfo->fd;
	forgetInfo(dnsInfo);
    }

    s=socket(AF_INET,SOCK_DGRAM,0);
    if (s<0) {
	syslog(LOG_ERR,"dns socket: %m");
	exit(2);
    }
    if (s>=maxFd) {
	syslog(LOG_ERR,"dns socket out of range");
	exit(2);
    }

    footprint(8,s,oldS,0);

    memset(&sin,0,sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port   = 0;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(s,(struct sockaddr*)&sin,sizeof(sin))<0) {
	perror("bind");
	exit(2);
    }

    if (connect(s,(struct sockaddr*)&dnsAddr,sizeof(dnsAddr))<0) {
	perror("connect");
	exit(2);
    }
    setNonBlocking(s);

    dnsInfo=info=fdInfo+s;
    memset(info,0,sizeof(*info));
    /* info->peer=NULL; */
    info->fd=s;
    info->flags=FD_IS_SPECIAL|FD_IS_UDP;
    info->UDP_RECVFROM=(recvFromFunc*)recvfrom, info->UDP_SENDTO=(sendToFunc*)sendto, info->excp=nullExcp;
    info->UDP_INBOUND=dnsInboundUdp;
    /* info->UDP_OUTPUT=NULL; */
    setSelect(s,SL_READ|SL_EXCP);
}
/*****************************************************************************
 *
 * adjust() is just a longwinded way of making sure that the pointers are
 * sane before we go for broke...  It adjusts the pointers to their rightful
 * values. Returns 0 for OK, -1 for failure (bogus value).
 *
 *****************************************************************************/
static int adjust(void*uptr,void *start,int len,void *newStart)
{
    register void **ptr=uptr;
    register long lptr=(long)*ptr;

    if (!*ptr) return 0;	/* Handle the NULL pointer */

    /* make sure it's inside the range */
    if (*ptr<start|| *ptr>(void*)((char*)start+len))
	return -1;
    
    lptr+=(long)newStart-(long)start;
    *ptr=(void*)lptr;
    return 0;
}
/* dnsSaveReply is the one entry cache for dns lookups. */
struct hostent *dnsSaveReply;

/*****************************************************************************
 *
 * dnsInboundUdp() is an inboundUdpFunc attached to the dns UDP request port
 *
 * Do a few sanity checks on the reply, adjust the pointers, and save it away.
 * Then we call peer->output (v5Request most likely) with no data, just to
 * tickle him into trying the request again.  He'll call dnsQuery(), which
 * will match dnsSaveReply, and he'll have his answer.  Ugly, but it keeps
 * things looking clean in the main code.
 *
 *****************************************************************************/
/* inboundUdpFunc */
/* ARGSUSED */
void dnsInboundUdp(fdInfoType *info,void *buf,int len,unsigned int flg, const void *vFrom, int fromLen)
{
    dnsReplyType		*reply=buf;
    register fdInfoType		*peer;
    register fdInfoType		*client;
    register int		clientFd=ntohl(reply->clientFd);
    register int		i;
    const struct sockaddr_in	*from=vFrom;


    /* Make sure that the packet arrived from dnsAddr */
    if (from->sin_port != dnsAddr.sin_port || from->sin_addr.s_addr != dnsAddr.sin_addr.s_addr) {
	syslog(LOG_ERR,"DNS reply from unexpected address: %s %d",inet_ntoa(from->sin_addr),ntohs(from->sin_port));
	return;
    }

    if (len==0) {
	if (!pendingTerm)
	    syslog(LOG_ERR,"Got end of file from DNS handler");
	dnsDestroy();
	unListen(1);	/* Don't take any more clients, since we can't handle ATYP_DOMAIN */
	return;
    }

    if (clientFd>=lowFd && clientFd<=maxFd) {
	peer=fdInfo+clientFd;
	client=peer->peer;
    } else {
bail:	syslog(LOG_ERR,"Bogus reply to dnsReply");
	return;
    }

    if (!client || client->fd<0) {
	syslog(LOG_WARNING,"Received DNS reply for closed connection");
	return;
    }

    if (adjust(&reply->hostent.h_name,(void*)reply->bias,len,&reply->hostent))
	goto bail;
    /* the h_addr_list pointer needs to be aligned. */
    if (adjust(&reply->hostent.h_addr_list,(void*)reply->bias,len,&reply->hostent) ||
	((long)reply->hostent.h_addr_list&(sizeof(void*)-1)))
	goto bail;
    if (reply->hostent.h_addr_list) {
	for (i=0;reply->hostent.h_addr_list[i]; i++) {
	    if (adjust(&reply->hostent.h_addr_list[i],(void*)reply->bias,len,&reply->hostent))
		goto bail;
	}
    }
    dnsSaveReply=&reply->hostent;
    setSelect(client->fd,SL_READ);	/* we shut him down earlier */
    if (!(client->flags&FD_IS_UDP)) {
	client->TCP_INBOUND(client,NULL,0,0);
    } else {
	client->UDP_INBOUND(client,NULL,0,0,NULL,0);
    }

    return;
}
/*****************************************************************************
 *
 * dnsQuery() does non-blocking dns resolution, the hard way.  Rather than
 * figure out packet formats and all that, we toss it over to a helper process
 * (or more), which do the lookup and fire the answer back at us.  This answer
 * gets cached and the caller is told to retry.  Consequently, if we have a
 * cached answer, then we just give them the answer.  If not, fire off the
 * question to the helper process.
 *
 *****************************************************************************/
struct hostent *dnsQuery(char *name, fdInfoType *peer)
{
    double dbuf[1024/sizeof(double)];
    dnsReqType *req=(dnsReqType*)dbuf;
    register struct hostent *hent=dnsSaveReply;

    if (!config.daemon.numHelper)
	return NULL;

    if (hent) {
	dnsSaveReply=NULL;
	if (hent->h_addr_list==NULL)
	    hent=NULL;
	return hent;
    }

    if (!dnsInfo)		/* No more DNS lookups */
	return NULL;

    req->clientFd=htonl(peer->fd);
    req->type=DNS_QUERY;
    if (strlen(name)>255)
	return NULL;
    strcpy(req->req.name,name);
    req->req.name[255]='\0';

    dnsWrite(dnsInfo->fd,req,sizeof(*req),0);
    return (struct hostent *)-1;
}
/*****************************************************************************
 *
 * dnsHandler() is just an infinite loop reading requests from his socket,
 * doing the lookup, and then returning the answer to the guy who asked.
 *
 *****************************************************************************/
void dnsHandler(int fd)
{
    double			sbuf[1024/sizeof(double)];
    double			dbuf[1024/sizeof(double)];
    register dnsReqType		*req=(dnsReqType*)sbuf;
    register dnsReplyType	*reply=(dnsReplyType*)dbuf;
    register char		*limit=(char*)dbuf+sizeof(dbuf);
    register struct hostent	*hent;
    struct sockaddr_in		from;
    int				fromLen;

    while (1) {
	register char	*next=(char*)(reply+1);
	register int	ret;
	do { 
	    fromLen=sizeof(from);
	    ret=recvfrom(fd,sbuf,sizeof(sbuf),0,&from,&fromLen);
	} while (ret<0 && errno==EINTR);

	if (ret<0)
	    break;

	if (ret != sizeof(*req)) {
	    syslog(LOG_ERR,"dnsHandler: bad size request (%d)");
	    continue;
	}

	memset(dbuf,0,sizeof(dbuf));
	reply->clientFd=req->clientFd;
	req->req.name[255]='\0';
	reply->bias=(long)&reply->hostent;
	reply->hostent.h_name=next; strcpy(next,req->req.name); next+=strlen(req->req.name)+1;
	hent=gethostbyname(req->req.name);
	if (hent) {
	    register int i,j;
	    for (i=0;hent->h_addr_list[i];i++);
	    reply->hostent.h_addr_list=(char**)((long)(next+(sizeof(char**)-1))&~(sizeof(char**)-1));

	    next=(char*)(reply->hostent.h_addr_list+i+1);
	    if (next+hent->h_length*i>limit) {
		i=(limit-next)/hent->h_length;
	    }
	    for (j=0;j<i;j++) {
		reply->hostent.h_addr_list[j]=next;
		memcpy(next,hent->h_addr_list[j],hent->h_length);
		next+=hent->h_length;
	    }
	    reply->hostent.h_addrtype=hent->h_addrtype;
	    reply->hostent.h_length=hent->h_length;
	} else {
	    reply->hostent.h_addr_list=(char**)NULL;
	}
	sendto(fd,dbuf,next-(char*)dbuf,0,&from,fromLen);
    }
    syslog(LOG_ERR,"dnsHandler dying: %m");
}

/*****************************************************************************
 *
 * dnsDestroy() is called from the top of destroyDaemon (in sockd) to get rid
 * of the connection to the dns helper.
 *
 *****************************************************************************/
void dnsDestroy(void)
{
    register int fd;
    if (!dnsInfo)
	return;
    fd=dnsInfo->fd;
    if (fd<0) {
	return;
    }
    closeConnection(dnsInfo,LOG_CLOSE,0);
    dnsInfo=NULL;
}

/* ARGSUSED */
ssize_t	dnsWrite(int fd, const void *buf,size_t count,unsigned int flg)
{
    return write(fd,buf,count);
}

