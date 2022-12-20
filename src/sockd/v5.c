#include "sockd.h"
#include "v5.h"
#include <arpa/inet.h>

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/v5.c,v 0.49 2001/08/23 17:25:27 lamont Exp $";
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


int noAuthInfo(methodInfoType *info,int version)
{
    if (version!=METHOD_VERSION)
	return -1;
    info->negotiate=simpleInbound;
#ifdef FULLMETHOD
    info->TCP_INBOUND=simpleInbound;
    info->TCP_OUTPUT=simpleOutput;
#endif
    return 0;
}

/* inboundFunc */
void newV5Client(fdInfoType *client,void *buf,int len,unsigned int flags)
{
    register methodInfoType	*method;
    u_char			reply[2];
    u_char			request[257];

    addToBuffer(client,&client->in,buf,len);
    if (client->in.dataLen<2 || client->in.dataLen<client->in.dataStart[1]+2) {
	return;	/* still don't have enough data */
    }

    getFromBuffer((char*)request,&client->in,client->in.dataStart[1]+2,0);
    method=findMatchingMethod(&client->sin,request);

    footprint(1,client->fd,method ? method->num : 255,client->sin.sin_addr.s_addr);

    reply[0]=SOCKS_V5;
    reply[1]=method ? method->num : 0xff;
    client->TCP_OUTPUT(client,(char*)&reply,2,0);

    if (client->fd<0) { /* TCP_OUTPUT met with resistance... */
	return;
    } else if (!method) {
	pendingClose(client,LOG_NOMETHOD);
	return;
    }

    client->conn->method=method;

    /* Copy the method startup information from method into client */
    client->TCP_INBOUND=method->negotiate;

    /* if we have data, go for it */
    if (client->in.dataLen) {
	client->TCP_INBOUND(client,NULL,0,flags);
    }

}
/* ARGSUSED */
int v5PutSin(const struct sockaddr_in *sin, int sinLen, v5HeadType *reply)
{
    reply->atyp=ATYP_V4;		/* in case of errors */
    switch (sin->sin_family) {
	default:
	    reply->cmd=SOCKS5_GENFAIL;
	    /* fall through */
	case AF_INET:
	    memcpy(reply->destAddr,&sin->sin_addr,4);
	    memcpy(reply->destAddr+4,&sin->sin_port,sizeof(sin->sin_port));
	    return 4+sizeof(sin->sin_port);
#ifdef AF_INET6
	case AF_INET6:
	    reply->atyp=ATYP_V6;
	    memcpy(reply->destAddr,&sin->sin_addr,16);
	    memcpy(reply->destAddr+16,&sin->sin_port,sizeof(sin->sin_port));
	    return 16+sizeof(sin->sin_port);
#endif
    }
}
int v5GetSin(const v5HeadType *req,struct sockaddr_in *sin,int sinLen)
{
    memset(sin,0,sinLen);
    switch (req->atyp) {
	case ATYP_V4:
	    sin->sin_family=AF_INET;
	    memcpy(&sin->sin_addr,req->destAddr,4);
	    memcpy(&sin->sin_port,req->destAddr+4,sizeof(short));
	    return SOCKS5_OK;
	case ATYP_V6:
#ifdef AF_INET6
	    if (sinLen<sizeof(struct sockaddr_in6))
		return SOCKS5_GENFAIL;
	    sin->sin_family=AF_INET6;
	    memcpy(&sin->sin_addr,req->destAddr,16);
	    memcpy(&sin->sin_port,req->destAddr+16,sizeof(short));
#endif
	    return SOCKS5_GENFAIL;
	case ATYP_DOMAIN:	/* fall thru */
	default:
	    return SOCKS5_GENFAIL;
    }
}
/* outputFunc */
int v5Request(fdInfoType *peer,void *buf,int len,unsigned int flags)
{
    v5HeadType			req;
    register int		ret;
    register fdInfoType		*client=peer->peer;
    register connInfoType	*conn=peer->conn;
    register int		size,asize;

#ifdef __lint
    size=flags;
#endif

    addToBuffer(peer,&peer->out,buf,len);

    if (!conn->req) {			/* If we got SOCKS5_TRY_AGAIN before then we already have client->req. */
	if (peer->out.dataLen < sizeof(req))
	    return 0;

	memcpy(&req,peer->out.dataStart,sizeof(req));

	/* see if we have enough data */
	switch(req.atyp) {
	    case ATYP_V4:	asize=4; break;
	    case ATYP_DOMAIN:	asize=req.destAddr[0]+1; break;
	    case ATYP_V6:	asize=16; break;
	}

	size=sizeof(req)+sizeof(u_short)-sizeof(req.destAddr)+asize;
	if (peer->out.dataLen < size)
	    return 0;

	conn->req=malloc(size);
	if (!conn->req) {
	    freeSomeMemory(&peer->out);
	    conn->req=malloc(size);
	    if (!conn->req) {
		pendingClose(client,LOG_OUT_OF_MEMORY);
		return;
	    }
	}
	getFromBuffer((char*)conn->req,&peer->out,size,0);
	logStartup(client);
    }

    ret=validate(client,VL_NONE,NULL);
    if (ret==SOCKS5_TRY_AGAIN)
	return 1;

    /* validate may have changed these. */
    setupTimeouts(conn,conn->timeOut);
    setSocketBuffer(peer->fd,conn->bufSize);
    setSocketBuffer(client->fd,conn->bufSize);

    if (ret==SOCKS5_OK) {
	peer->TCP_OUTPUT=simpleOutput;	/* we have the request now, don't need to come here any more */
	switch(conn->req->cmd) {
	    case SOCKS5_CONNECT:
		ret=v5DoConnect(client);
		break;
	    case SOCKS5_BIND:
		ret=v5DoBind(client);
		break;
	    case SOCKS5_UDP_ASSOCIATE:
		ret=v5DoUdpAssociate(client);
		break;
	    case SOCKS5_PING:
		ret=v5DoCommand(client,"PING");
		break;
	    case SOCKS5_TRACEROUTE:
		ret=v5DoCommand(client,"TRACEROUTE");
		break;
	    default:
		if (conn->req->cmd<128) {
		    syslog(LOG_ERR,"Bad v5 command %d from %s", conn->req->cmd,inet_ntoa(client->sin.sin_addr));
		    ret=SOCKS5_CMD_NOT_SUPP;
		} else {
		    char name[16];
		    sprintf(name,"COMMAND_%d",conn->req->cmd);
		    ret=v5DoCommand(client,name);
		}
		break;
	}
    }

    if (ret!=SOCKS5_OK) {
	v5HeadType reply;
	u_short port;

	memset(&reply,0,sizeof(reply));
	reply.version=SOCKS_V5;
	reply.cmd=ret;
	reply.atyp=ATYP_V4;
	port=htons(0);
	v5GetSin(conn->req,&peer->sin,sizeof(peer->sin));
	client->TCP_OUTPUT(client,(char*)&reply,sizeof(reply),0);
	client->TCP_OUTPUT(client,(char*)&port,sizeof(port),0);
	pendingClose(client,ret);
    }
    return 0;
}

int v5ErrnoToResult(int error)
{
    switch(error) {
	case 0:			return SOCKS5_OK;
	case EALREADY:
	case EINVAL:
	case ENETUNREACH:
	case ENETDOWN:
	case ENETRESET:		return SOCKS5_NET_UNREACH;
	case EHOSTUNREACH:
	case EHOSTDOWN:		return SOCKS5_HOST_UNREACH;
	case ECONNREFUSED:	return SOCKS5_CONN_REFUSED;
	case EADDRINUSE:	return SOCKS5_INVALID_ADDR;
	default:		return SOCKS5_GENFAIL;
    }
}
void v5WriteReply(fdInfoType *client, struct sockaddr_in *sin, int result, int flags)
{
    double		dbuf[304/sizeof(double)];
    v5HeadType		*reply=(v5HeadType*)dbuf;
    register		char *p=(char*)&reply->destAddr;

    memset(dbuf,0,sizeof(dbuf));
    reply->version=SOCKS_V5;
    reply->cmd=result;
    reply->flags=flags;
    p+=v5PutSin(sin,sizeof(*sin),reply);
    client->TCP_OUTPUT(client,(char*)dbuf,(p-(char*)dbuf),0);
}

/***************************************************************************
 * validate() verifies that the connection in question is OK.  0 means OK,
 * >0 is a socks return value, and you lose.
 ***************************************************************************/
int validate(fdInfoType *client, int flags, v5HeadType **iReq)
{
    register connInfoType	*conn=client->conn;
    register int		i;
    register clientInfoType	*cInfo;
    long			destIP;
    u_short			port;
    char			domain[256];
    struct hostent		*hent;
    register v5HeadType		*req=iReq ? *iReq : conn->req;
    register int		cmd;
    register int		checkDest;

    if (!(flags&VL_ISUDPREQ)) {
	if (req->version!=SOCKS_V5)
	    return SOCKS5_GENFAIL;
	cmd=req->cmd;
	checkDest=(cmd!=SOCKS5_UDP_ASSOCIATE);
    } else {
	if (((v5UdpHeadType*)req)->rsv)
	    return SOCKS5_GENFAIL;
	cmd=SOCKS5_UDP_ASSOCIATE;
	checkDest=1;
    }

    switch(req->atyp) {
	case ATYP_V4:
	    memcpy(&destIP,req->destAddr,sizeof(destIP));	
	    memcpy(&port,req+1,sizeof(port));
	    break;
	case ATYP_V6:
	    return SOCKS5_ADDR_NOT_SUPP;	/* XXX - no IPV6 support */
	case ATYP_DOMAIN:
	    memcpy(domain,req->destAddr+1,*req->destAddr);
	    domain[*req->destAddr]='\0';
	    memcpy(&port,req->destAddr+1+*req->destAddr,sizeof(port));
	    if ((hent=dnsQuery(domain,client->peer))==(struct hostent*)-1) {
		clrSelect(client->fd,SL_READ);
		return SOCKS5_TRY_AGAIN;
	    } else if (hent) {
		req=realloc(req,sizeof(*req)+sizeof(port)+hent->h_length-sizeof(req->destAddr));
		if (!req)
		    return SOCKS5_GENFAIL;
		if (!iReq)
		    conn->req=req;
		else
		    *iReq=req;
		switch(hent->h_addrtype) {
		    case AF_INET:	req->atyp=ATYP_V4; break;
#ifdef AF_INET6
		    case AF_INET6:	req->atyp=ATYP_V6; break;
#endif
		    default:	return SOCKS5_ADDR_NOT_SUPP;
		}
		memcpy(req->destAddr,hent->h_addr_list[0],hent->h_length);
		memcpy(req->destAddr+hent->h_length,&port,sizeof(port));
		return validate(client,flags,iReq ? iReq : NULL);		/* one more time... */
	    } else {
		return SOCKS5_HOST_UNREACH;
	    }
	    break;
    }

/* NEXT is used in ACTION_SKIP */
#define NEXT i--,cInfo++
    for (i=config.clients.num,cInfo=config.clients.list;i>0;NEXT) {
	register int checks;
	if (cInfo->request!=SOCKS5_ANYACTION && cInfo->request != cmd)
	    continue;
	
	checks=(cInfo->request==cmd);

	if (cInfo->src.num) {
	    register hostType *sInfo;
	    register int hit=0,j;
	    checks++;
	    for (sInfo=cInfo->src.list,j=cInfo->src.num; j>0; j--,sInfo++) {
		if (compareAddr(sInfo,client->sin.sin_addr.s_addr)) {
		    hit=1;break;
		}
	    }
	    if (!hit) continue;
	}
	if (cInfo->dest.num && checkDest) {
	    register hostType *dInfo;
	    register int hit=0,j;
	    register long dIP=destIP;
	    checks++;
	    for (dInfo=cInfo->dest.list,j=cInfo->dest.num; j>0; j--,dInfo++) {
		if (compareAddr(dInfo,dIP)) {
		hit=1;break;
		}
	    }
	    if (!hit) continue;
	}
	if (cInfo->port.num && checkDest) {
	    register portType *pInfo;
	    register int hit=0,j;
	    register u_short p=ntohs(port);
	    checks++;
	    for (pInfo=cInfo->port.list,j=cInfo->port.num; j>0; j--,pInfo++) {
		if (p >= ntohs(pInfo->low) && p <= ntohs(pInfo->high)) {
		    hit=1;break;
		}
	    }
	    if (!hit) continue;
	}
	if (cInfo->users.num) {
	    register char  **uInfo;
	    register int hit=0,j;
	    checks++;
	    if (conn->user) {
		for (uInfo=cInfo->users.list,j=cInfo->users.num; j>0; j--,uInfo++) {
		    if (strcmp(*uInfo,conn->user)==0) {
			hit=1;break;
		    }
		}
	    }
	    if (!hit) continue;
	}

	if (!checkDest && !checks)
	    continue;

	/* We have a winner!!! */
	conn->timeOut=(cInfo->timeOut) ? cInfo->timeOut : config.defaults.timeOut;
	if (cInfo->bufSize) conn->bufSize=cInfo->bufSize;
	if (cInfo->cmd) doCommand(cInfo->cmd,client);
	conn->ruleFlags = cInfo->flags;

	if (debug&DBG_VALIDATE) {
	    syslog(LOG_NOTICE,"validate(%d, %s:%s, %s:%d) --> %d, rule %d",
		cmd, inetNtoa(client->sin.sin_addr.s_addr),conn->user ? conn->user : "(NONE)",
		inetNtoa(destIP),port,
		cInfo->action,cInfo-config.clients.list);
	}
	switch (cInfo->action) {
	    case ACTION_PERMIT:
	    case ACTION_PERMIT_OK:
		return SOCKS5_OK;
	    case ACTION_DENY:
		return SOCKS5_DENIED;
	    case ACTION_SKIP:
		NEXT;
		continue;
	    default:
		syslog(LOG_ERR,"Unknown action %d found, denying",cInfo->action);
		return SOCKS5_DENIED;
	}
    }
#undef NEXT
    return SOCKS5_DENIED;	/* not found, you lose */
}
