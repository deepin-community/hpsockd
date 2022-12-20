#include "sockd.h"
#include "v4.h"
#include "v5.h"		/* we convert requests for fdInfo */

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/v4.c,v 0.33 2000/12/08 20:47:24 lamont Exp $";
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


v5HeadType *makeV5Req(v4HeadType *req, dataBufType *buf);
sendFunc v4ConnectSendReply;
recvFunc v4BindRecv;

int v4Info(methodInfoType *info,int version)
{
    if (version!=METHOD_VERSION)
	return -1;
    info->negotiate=newV4Client;
#ifdef FULLMETHOD
    info->TCP_INBOUND=simpleInbound;
    info->TCP_OUTPUT=simpleOutput;
#endif
    return 0;
}

methodInfoType *v4Method;
/* inboundFunc */
void newV4Client(fdInfoType *client,void *buf,int len,unsigned int flags)
{
    register char		*p;
    register v4HeadType		*req;
    register int		l=ofs(v4HeadType,user);
    u_char			dest[5];
    register methodInfoType	*method;
    register fdInfoType		*peer=client->peer;
    register int		ret;
    register connInfoType	*conn=client->conn;

#ifdef __lint
    l=flags;
#endif

    addToBuffer(client,&client->in,buf,len);
    if (client->in.dataLen<=l)
	return;

    for (p=client->in.dataStart+l;l<client->in.dataLen && *p;l++,p++);
    if (l>=client->in.dataLen)
	return;

    /* We have a complete request */
    req=malloc(l+1);
    if (!req) {
	freeSomeMemory(&client->in);
	req=malloc(l+1);
    }

    if (req) {
	getFromBuffer((char*)req,&client->in,l+1,0);
	conn->req=makeV5Req(req,&client->in);
	conn->user=strdup(req->user);

	if (conn->req && v4Method) {
	    u_char methData[3]={SOCKS_V4,1,0};
	    methData[2]=v4Method->num;
	    method=findMatchingMethod(&client->sin,methData);
	} else {
	    method=NULL;
	}
    } else {
	method=NULL;
    }

    if (!method) {
	v4HeadType	reply;
	reply.version=SOCKS_V4;
	reply.cmd=SOCKS4_FAIL;
	client->TCP_OUTPUT(client,(char*)&reply,ofs(v4HeadType,user),0);
	pendingClose(client,LOG_NOMETHOD);
	goto leave;
    }
    conn->method=method;

    *dest=ATYP_V4; memcpy(dest+1,&req->destIP,4);

    logStartup(client);
    ret=validate(client,VL_NONE,NULL);
    if (ret!=SOCKS5_OK) {
	v4HeadType	reply;
	reply.version=SOCKS_V4;
	reply.cmd=SOCKS4_FAIL;
	v5GetSin(conn->req,&peer->sin,sizeof(peer->sin));
	client->TCP_OUTPUT(client,(char*)&reply,ofs(v4HeadType,user),0);
	pendingClose(client,ret);
	goto leave;
    }

    setupTimeouts(conn,conn->timeOut);
    setSocketBuffer(peer->fd,conn->bufSize);
    setSocketBuffer(client->fd,conn->bufSize);
    client->TCP_INBOUND=simpleInbound;
    client->TCP_OUTPUT=simpleOutput;

    switch(req->cmd) {
	case SOCKS_CONNECT:
	    v4DoConnect(client,req);
	    break;
	case SOCKS_BIND:
	    v4DoBind(client,req);
	    break;
	default:
	    syslog(LOG_ERR,"Bad v4 command %d from %s", req->cmd,inet_ntoa(client->sin.sin_addr));
	    pendingClose(client,LOG_PROTOCOL_ERROR);
	    goto leave;
    }
leave:
    if (req)
	free(req);
}
void v4DoConnect(fdInfoType *client,v4HeadType *req)
{
    struct sockaddr_in		sin;
    register fdInfoType		*peer=client->peer;
    register int		outFd=peer->fd;
    register int		res;

    clrSelect(client->fd,SL_READ);

    memset(&sin,0,sizeof(sin));
    sin.sin_family=AF_INET;
    sin.sin_addr.s_addr=req->destIP;
    sin.sin_port=req->port;

    peer->sin=sin;
    peer->TCP_INBOUND=simpleInbound;
    peer->TCP_OUTPUT =simpleOutput;

    setSelect(outFd,SL_READ|SL_EXCP);

    res=connect(outFd,(struct sockaddr*)&sin,sizeof(sin));

    if (res==0 || res<0 && errno==EINPROGRESS) {
	peer->TCP_SEND=v4ConnectSendReply;
	setSelect(outFd,SL_WRITE);
    } else {
	v4ConnectSendReply(outFd,(const void *)NULL,0,0);  /* just send it now */
    }
}
/* sendFunc */
/* ARGSUSED */
ssize_t	v4ConnectSendReply(int fd, const void *buf,size_t count,unsigned int flg)
{
    register fdInfoType	*peer=fdInfo+fd;
    register fdInfoType *client=peer->peer;
    register int	res;
    v4HeadType		reply;
    struct sockaddr_in	sin;
    int			sinlen=sizeof(sin);

    peer->TCP_SEND=(sendFunc*)send;
    peer->TCP_INBOUND=simpleInbound;

    res=connect(fd,(struct sockaddr*)&client->sin,sizeof(client->sin));

    memset((char*)&reply,0,sizeof(reply));
    memset(&sin,0,sizeof(sin));
#ifdef ONLY_GOOD_CLIENTS
    reply.version=SOCKS_V4;
#else
    reply.version=0;	/* Lots of idiot clients expect 0 instead of 4. */
#endif
    setSelect(client->fd,SL_READ);

    if (res==0 || errno==EISCONN) {
	reply.cmd=SOCKS4_RESULT;
	res=getsockname(fd,(struct sockaddr*)&sin,&sinlen);
	reply.port=sin.sin_port;
	reply.destIP=sin.sin_addr.s_addr;
    } else {
	reply.cmd=SOCKS4_FAIL;
    }
    client->TCP_OUTPUT(client,(char*)&reply,ofs(v4HeadType,user),0);
    if (reply.cmd==SOCKS4_FAIL) {
	pendingClose(client,LOG_ERRNO+errno);
    }
    return 0;
}

void v4DoBind(fdInfoType *client,v4HeadType *req)
{
    register fdInfoType *peer=client->peer;
    register int	outFd=peer->fd,res;
    struct sockaddr_in	sin;
    int			len=sizeof(sin);
    v4HeadType		reply;

    memset(&reply,0,sizeof(reply));
#ifdef ONLY_GOOD_CLIENTS
    reply.version=SOCKS_V4;
#else
    reply.version=0;	/* Lots of idiot clients expect 0 instead of 4. */
#endif
    reply.cmd=SOCKS4_RESULT;

    peer->TCP_INBOUND=simpleInbound;
    peer->TCP_OUTPUT =simpleOutput;
    setSelect(outFd,SL_READ|SL_EXCP);

    memset(&sin,0,sizeof(sin));
    sin.sin_family=AF_INET;
    sin.sin_addr.s_addr=findRoute(req->destIP);
    sin.sin_port=0;

    res=bind(outFd,(struct sockaddr*)&sin,sizeof(sin));

    if (res<0) {
	syslog(LOG_ERR,"v4DoBind bind failed: %m");
bDie:	reply.cmd=SOCKS4_FAIL;
	client->TCP_OUTPUT(client,(char*)&reply,ofs(v4HeadType,user),0);
	pendingClose(client,LOG_ERRNO+errno);
	return;
    }

    res=getsockname(outFd,(struct sockaddr*)&sin,&len);
    if (res<0) {
	syslog(LOG_ERR,"v4DoBind getsockname failed: %m");
	goto bDie;
    }

    v5GetSin(client->conn->req,&peer->sin,sizeof(peer->sin));	/* put the request address here for now. */

    reply.destIP=sin.sin_addr.s_addr;
    reply.port=sin.sin_port;
    client->TCP_OUTPUT(client,(char*)&reply,ofs(v4HeadType,user),0);

    if (client->fd<0)
	return;

    res=listen(outFd,1);

    peer->TCP_RECV=v4BindRecv;
    setSelect(outFd,SL_READ|SL_EXCP);
}
/* recvFunc */
/* ARGSUSED */
ssize_t v4BindRecv(int fd, void *buf,size_t count,unsigned int flags)
{
    struct sockaddr_in		sin;
    int				len=sizeof(sin);
    register int		newFd;
    register fdInfoType		*peer=fdInfo+fd;
    register fdInfoType		*client=peer->peer;
    register connInfoType	*conn=peer->conn;
    v4HeadType			reply;
    struct sockaddr_in		din;

    memset(&reply,0,sizeof(reply));
#ifdef ONLY_GOOD_CLIENTS
    reply.version=SOCKS_V4;
#else
    reply.version=0;	/* Lots of idiot clients expect 0 instead of 4. */
#endif
    reply.cmd=SOCKS4_RESULT;

    newFd=accept(fd,(struct sockaddr*)&sin,&len);

    if (newFd<0) {
	syslog(LOG_WARNING,"v4BindRecv accept failed: %m");
	return -1;
    }
    dup2(newFd,fd);
    close(newFd);

    setSocketBuffer(fd,conn->bufSize);
    setNonBlocking(fd);

    peer->sin=sin;
    peer->TCP_RECV=(recvFunc*)recv;

    v5GetSin(conn->req,&din,sizeof(din));	/* put the request address here for now. */
    if (ntohl(din.sin_addr.s_addr) != 0xffffffff && ntohl(din.sin_addr.s_addr) !=0 &&
		sin.sin_addr.s_addr != din.sin_addr.s_addr) {
	syslog(LOG_ERR,"v4BindRecv received connection from %s, expected connection from %s",
		inetNtoa(sin.sin_addr.s_addr), inetNtoa(din.sin_addr.s_addr));
	reply.cmd=SOCKS4_FAIL;
	client->TCP_OUTPUT(client,(char*)&reply,ofs(v4HeadType,user),0);
	errno=EACCES;
	return -1;
    }

    reply.port=sin.sin_port;
    reply.destIP=sin.sin_addr.s_addr;
    client->TCP_OUTPUT(client,(char*)&reply,ofs(v4HeadType,user),0);
    return -2;
}

v5HeadType *makeV5Req(v4HeadType *req, dataBufType *buf)
{
    register v5HeadType *v5;

    v5=malloc(sizeof(v5HeadType)+2);
    if (!v5) {
	freeSomeMemory(buf);
	v5=malloc(sizeof(v5HeadType)+2);
	if (!v5)
	    return NULL;
    }

    v5->version	= SOCKS_V5;
    v5->cmd	= req->cmd;
    v5->flags	= 0;
    v5->atyp	= ATYP_V4;
    memcpy(&v5->destAddr,&req->destIP,4);
    memcpy(v5+1,&req->port,sizeof(req->port));
    return v5;
}
