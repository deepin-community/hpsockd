#include "sockd.h"
#include "v5.h"

#define RF_LOG_RECORDS_CLIENT	1
#define RF_LOG_RECORDS_PEER	2

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/v5udp.c,v 0.26 2001/11/14 22:25:50 lamont Exp $";
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


inboundFunc v5UdpCloseInbound;

/********************************************************************************
 *
 * How about those various fields in fdInfo, since we now have 4 fd's to play
 * with...  Here are the things of interest.
 *
 *		client		peer		udp			udpPeer
 * sin		client sin	last peer	client sin		--
 * req/user	valid		--		trashed by validate	--
 *
 ********************************************************************************/
int v5DoUdpAssociate(fdInfoType *client)
{
    register fdInfoType		*in,*out;
    register connInfoType	*conn=client->conn;
    register int		inFd,outFd,res;
    struct sockaddr_in		srcSin,dstSin,clientSin;
    register v5HeadType		*req=conn->req;
    register char		*m=NULL;
    register struct sockaddr_in *mSin=NULL;
    register u_char		replyFlags;

    client->TCP_INBOUND=v5UdpCloseInbound;	/* nuke it if we get more data */
    clrSelect(client->peer->fd,SL_ALL);
    footprint(4,client->fd,0,0);

    switch(conn->req->atyp) {
	u_int32_t src;
	ushort port;
	case ATYP_V4:
	    memcpy(&src,req->destAddr,4);
	    memcpy(&port,req->destAddr+4,sizeof(port));
	    memset(&dstSin,0,sizeof(dstSin));
	    dstSin.sin_family=AF_INET;
	    dstSin.sin_addr.s_addr=htonl(INADDR_ANY);	/* We don't get destinations until the reqest */
	    if (!src) {
		/* Fix the request to point at the client */
		memcpy(req->destAddr,&client->sin.sin_addr.s_addr,4);
		src=client->sin.sin_addr.s_addr;
	    } else if (src != client->sin.sin_addr.s_addr) {
		return SOCKS5_DENIED;
	    }
	    if ((req->flags&RQ_UDP_USE_CLIENT_PORT) && port>=IPPORT_RESERVED) {
		dstSin.sin_port=port;
		replyFlags=RQ_UDP_USE_CLIENT_PORT;
	    } else {
		dstSin.sin_port=0;
		replyFlags=0;
	    }
	    memset(&clientSin,0,sizeof(clientSin));
	    clientSin.sin_family=AF_INET;
	    clientSin.sin_addr.s_addr=src;
	    clientSin.sin_port=port;
	    break;
	default:
	    return SOCKS5_ADDR_NOT_SUPP;
    }

    memset(&srcSin,0,sizeof(srcSin));
    srcSin.sin_family=AF_INET;
    srcSin.sin_addr.s_addr=findRoute(client->sin.sin_addr.s_addr);
    srcSin.sin_port=0;

    inFd=createSocket(AF_INET,SOCK_DGRAM,0);
    if (inFd<0 && errno==EMFILE || inFd>=maxFd) {
	if (inFd>0)
	    close(inFd);
	if (spawnChild(conn)==0)
	    return SOCKS5_OK;	/* just let the child go home. */
	inFd=createSocket(AF_INET,SOCK_DGRAM,0);
    }

    if (inFd<0) {
	m="v5DoUdpAssoc inside socket failed: %m";
	goto bailout;
    }

    outFd=createSocket(AF_INET,SOCK_DGRAM,0);
    if (outFd<0 && errno==EMFILE || outFd>=maxFd) {
	if (outFd>0)
	    close(outFd);
	if (spawnChild(conn)==0) {
	    close(inFd);
	    return SOCKS5_OK;	/* just let the child go home. */
	}
	outFd=createSocket(AF_INET,SOCK_DGRAM,0);
    }

    if (outFd<0) {
	close(inFd);
	m="v5DoUdpAssoc outside socket failed: %m";
	goto bailout;
    }

    in=fdInfo+inFd, out=fdInfo+outFd;
    memset(in,0,sizeof(fdInfoType)); memset(out,0,sizeof(fdInfoType));
    conn->udp=in;
    in->conn=out->conn=conn;
    in->peer=out, out->peer=in;
    in->flags=FD_IS_CLIENT|FD_IS_UDP;
    out->flags=FD_IS_UDP;
    in->sin=clientSin,		memset(&out->sin,0,sizeof(out->sin));
    in->fd=inFd,		out->fd=outFd;

    setSocketBuffer(out->fd,conn->bufSize);
    setSocketBuffer(in->fd,conn->bufSize);

    in->UDP_RECVFROM=conn->method->recvFrom,	out->UDP_RECVFROM=(recvFromFunc*)recvfrom;
    in->UDP_SENDTO=conn->method->sendTo,    	out->UDP_SENDTO=(sendToFunc*)sendto;
    in->excp=nullExcp,				out->excp=nullExcp;
    in->UDP_INBOUND=conn->method->inboundUdp,	out->UDP_INBOUND=simpleInboundUdp;
    in->UDP_OUTPUT=conn->method->outputUdp,	out->UDP_OUTPUT=simpleOutputUdp;

    res=bind(inFd,(struct sockaddr*)&srcSin,sizeof(srcSin));

    if (res<0) {
	m="v5DoUdpAssoc inside bind([%s].%d) failed: %m";
	mSin=&srcSin;
	goto bailout;
    }

    res=bind(outFd,(struct sockaddr*)&dstSin,sizeof(dstSin));

    if (res<0) {
	m="v5DoUdpAssoc outside bind([%s].%d) failed: %m";
	mSin=&dstSin;
	goto bailout;
    } else {
	int len=sizeof(srcSin);
	res=getsockname(inFd,(struct sockaddr*)&srcSin,&len);
    } 
    
    if (res<0) {
	m="v5DoUdpAssoc inside getsockname failed: %m";
	goto bailout;
    }

    setSelect(in->fd,SL_READ|SL_EXCP);
    setSelect(out->fd,SL_READ|SL_EXCP);
    v5WriteReply(client,&srcSin,SOCKS5_OK,replyFlags);
    return SOCKS5_OK;

bailout:
    {
	register int ret=v5ErrnoToResult(errno);
	if (mSin)
	    syslog(LOG_ERR,m,inetNtoa(mSin->sin_addr.s_addr),ntohs(mSin->sin_port));
	else
	    syslog(LOG_ERR,m);
	return ret;
    }
}
void dumpUDPData(fdInfoType *info,const void *ubuf,unsigned int len, const char *tag)
{
    register int i,j;
    register const unsigned char *buf=ubuf;
    static const char chars[]="0123456789abcdef";
    static int num=0;
    char out[2048];
    register char *p;

    num++;
    while (len) {
	sprintf(out,"%2s-%05x%c ",tag, num, (i ? '-' : ':'));
	p=out+10;
	i=256;
	while (len>0 && --i) {
	    *p++=chars[*buf>>4];
	    *p++=chars[*buf&15];
	    ++buf;
	    if (i%4==0) *p++=' ';
	    --len;
	}
	*p=0;
	syslog(LOG_DEBUG,"%s",out);
    }
}
/***************************************************************************
 *
 * We shouldn't receive data on the control connection after the ASSOC
 * command.  If we do, just close the connection.
 *
 ***************************************************************************/
/* inboundFunc */
/* ARGSUSED */
void v5UdpCloseInbound(fdInfoType *info,void *buf,int len,unsigned int flags)
{
    pendingClose(info,LOG_TOO_MUCH_DATA);
}
/***************************************************************************
 *
 * v5InboundUdpReq takes a UDP request from the client and deals with it.
 *
 ***************************************************************************/
/* inboundUdpFunc */
/* ARGSUSED */
void v5InboundUdpReq(fdInfoType *info,void *buf,int len,unsigned int flags,const void *vfrom, int fromLen)
{
    register connInfoType *conn=info->conn;
    register const struct sockaddr_in *from;
    register v5UdpHeadType *req;	/* may not be aligned... */
    register int headLen;
    v5HeadType *validateReq;
    register int ret;
    int	vfBuf[256];
    struct sockaddr_in to;

    if (conn->ruleFlags&RF_LOG_RECORDS_CLIENT)
	dumpUDPData(info,buf,len,"IC");

    from=vfrom;
    if (!buf && info->in.bufStart && info->in.dataLen<=sizeof(vfBuf)) {
	buf=info->in.bufStart;
	len=info->in.bufSize;
	fromLen=info->in.dataLen;
	memcpy(vfBuf,info->in.dataStart,fromLen);
	from=(const struct sockaddr_in *)vfBuf;
	free(info->in.dataStart);
	info->in.bufStart=info->in.dataStart=NULL;
	info->in.bufSize=info->in.dataLen=0;
    }
    if (!buf) {
	syslog(LOG_ERR,"Entered v5InboundUdpReq with NULL buffer pointer");
	return;
    }

    req=buf;	/* may not be aligned... */
    headLen=sizeof(*req)+sizeof(u_short)+ADDRLEN(&req->atyp)-1-sizeof(req->destAddr);

    /* Verify that the source address matches the expected.  Log it and drop if bad */
    if (from->sin_family      != info->sin.sin_family ||
	from->sin_addr.s_addr != info->sin.sin_addr.s_addr ||
	(info->sin.sin_port && from->sin_port != info->sin.sin_port)) {
	syslog(LOG_ERR,"Received udp packet from [%s].%d, expected source was [%s].%d, dropped",
		inetNtoa(from->sin_addr.s_addr), from->sin_port,
		inetNtoa(info->sin.sin_addr.s_addr), info->sin.sin_port);
	return;
    }

    if (len < headLen) {
	syslog(LOG_WARNING,"Dropped short packet from [%s].%d",
		inetNtoa(from->sin_addr.s_addr), ntohs(from->sin_port));
	return;
    }

    if (req->rsv || req->frag)
	return;

    validateReq=malloc(headLen);
    if (!validateReq)			/* out of memory, just drop it.... */
	return;
    memcpy(validateReq,req,headLen);
    /* Split request into request header and data */

    /* XXX - check if this is the same destination as the last one... */
    ret=validate(info,VL_ISUDPREQ,&validateReq);
    if (ret==SOCKS5_TRY_AGAIN) {
	info->in.bufStart=buf;
	info->in.bufSize=len;
	info->in.dataStart=(void*)malloc(fromLen);
	memcpy(info->in.dataStart,vfrom,fromLen);
	info->in.dataLen=fromLen;
	return;
	/* dns will wake us up again when it's ready, and validate will be able to handle things */
    }
    /* BTW, validateReq may have changed in validate, so use that copy, not a local one... */
    if (v5GetSin(validateReq,&to,sizeof(to))!=SOCKS5_OK)
	    goto bail;

    if (ret==SOCKS5_OK) {
	/* Toss the data to the peer output routine. */
	info->peer->UDP_OUTPUT(info->peer,(caddr_t)buf+headLen,len-headLen,flags,(void*)&to,sizeof(to));
	if (info->fd>=0)
	    conn->client->peer->sin=to;
    } else {
	syslog(LOG_NOTICE,"Rejected packet from [%s].%d to [%s].%d, validate returned %d",
		inetNtoa(from->sin_addr.s_addr), ntohs(from->sin_port),
		inetNtoa(to.sin_addr.s_addr), ntohs(to.sin_port), ret);
    }
bail:
    free(validateReq);
}
/***************************************************************************
 *
 * v5OutputUdpReply sends a UDP datagram to the client.
 *
 ***************************************************************************/
/* outputUdpFunc */
void v5OutputUdpReply(fdInfoType *info,void *buf,int len,unsigned int flags,const void *from, int fromLen)
{
    double dbuf[65536/sizeof(double)];
    register v5UdpHeadType *head=(v5UdpHeadType*)dbuf;
    register char *c=(char*)dbuf+sizeof(v5UdpHeadType)-sizeof(head->destAddr);

    if (info->conn->ruleFlags&RF_LOG_RECORDS_CLIENT)
	dumpUDPData(info,buf,len,"OC");

    head->rsv=head->frag=0;
    c+=v5PutSin(from,fromLen,(v5HeadType*)head);
    if (head->rsv)		/* unsupported address family is the only thing that would do this... */
	return;			/* drop the packet */
    
    if (c+len > (char*)dbuf+sizeof(dbuf))		/* packet too long */
	return;
    memcpy(c,buf,len), c+=len;

    info->UDP_SENDTO(info->fd,dbuf,c-(char*)dbuf,flags,&info->sin,sizeof(struct sockaddr_in));
    updateTime(info,out,len,now);
}
/***************************************************************************
 *
 * simpleInboundUdp receives a UDP datagram from the peer.
 *
 ***************************************************************************/
void simpleInboundUdp(fdInfoType *info,void *buf,int len,unsigned int flags,const void *from, int fromLen)
{
    if (info->conn->ruleFlags&RF_LOG_RECORDS_PEER)
	dumpUDPData(info,buf,len,"IP");

    info->peer->UDP_OUTPUT(info->peer,buf,len,flags,from,fromLen);
}
/***************************************************************************
 *
 * simpleOutputUdp sends a UDP datagram to the peer.
 *
 ***************************************************************************/
void simpleOutputUdp(fdInfoType *info,void *buf,int len,unsigned int flags,const void *to, int toLen)
{
    if (info->conn->ruleFlags&RF_LOG_RECORDS_PEER)
	dumpUDPData(info,buf,len,"OP");

    (void)info->UDP_SENDTO(info->fd,buf,len,flags,to,toLen);
    updateTime(info,out,len,now);
}
