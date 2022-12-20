#include "sockd.h"
#include "v5.h"

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/v5tcp.c,v 0.24 2002/07/27 03:55:34 lamont Exp $";
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


/*************************************************************************
 * simpleInbound() is handed a buffer of unprocessed input data from recv(),
 * which it must completely consume, possibly into info->in.
 *************************************************************************/
void simpleInbound(fdInfoType *info,void *buf,int len,unsigned int flags)
{
    register fdInfoType *peer=info->peer;

    /* if there is no data queued, just toss it across. */
    if (!info->in.dataLen) {
	if (peer->TCP_OUTPUT(peer,buf,len,flags)>0) {
	    clrSelect(info->fd,SL_READ);
	}
    } else {
	/* We have data queued, and should handle it. */
	addToBuffer(info,&info->in,buf,len);
	if (peer->TCP_OUTPUT(peer,info->in.dataStart,info->in.dataLen,flags)>0) {
	    clrSelect(info->fd,SL_READ);
	}
	info->in.dataLen=0;
	bufFree(&info->in);
    }
}
/*************************************************************************
 * simpleOutput() is handed a buffer of unencapsulated data to be packed
 * and sent, which it must completely consume, possibly into info->out.
 * If data is queued in out (only because of a partial write to the
 * socket, then the write select flag must be set by output().  The
 * outer loop will then do the write() calls itself.
 * Returns 
 *   0 for all OK,
 *   1 if the inbound side should hold off sending more data
 *  -1 if there was an error (the inbound side is already shut down at
 *     that point.)
 *************************************************************************/
int simpleOutput(fdInfoType *info,void *ubuf,int len,unsigned int flags)
{
    register char *buf=ubuf;
    register int xfr;

    xfr=info->TCP_SEND(info->fd,buf,len,flags);

    if (xfr<0) {
	if (errno==EWOULDBLOCK) {
	    xfr=0;
	} else {
	    pendingClose(info,LOG_ERRNO+errno);
	    return -1;
	}
    } 
    updateTime(info,out,xfr,now);
    if (xfr != len) {
	addToBuffer(info,&info->out,buf+xfr,len-xfr);
	setSelect(info->fd,SL_WRITE);
	clrSelect(info->peer->fd,SL_READ);
	return 1;
    } else {
	if (info->peer->sin.sin_addr.s_addr) {
	    setSelect(info->peer->fd,SL_READ);
	}
	return 0;
    }
}
int v5DoConnect(fdInfoType *client)
{
    register fdInfoType		*peer=client->peer;
    register connInfoType	*conn=client->conn;
    register int		outFd=peer->fd,res;
    struct sockaddr_in		sin;
    register v5HeadType		*req=conn->req;
    register int ret;

    outFd=peer->fd;

    if ((ret=v5GetSin(req,&sin,sizeof(sin)))!= SOCKS5_OK)
	return ret;
    peer->sin=sin;
    peer->TCP_INBOUND=simpleInbound;
    peer->TCP_OUTPUT =simpleOutput;
    clrSelect(client->fd,SL_READ);

    res=connect(outFd,(struct sockaddr*)&sin,sizeof(sin));

    if (res==0 || res<0 && errno==EINPROGRESS) {
	peer->TCP_SEND=v5ConnectSendReply;
	setSelect(outFd,SL_WRITE);
	clrSelect(outFd,SL_READ);
    } else {
	v5ConnectSendReply(outFd,NULL,0,0);  /* just send it now */
    }
    return SOCKS5_OK;	/* so far, anyway.  (Or we already closed out the connection.) */
}
/* sendFunc */
/* ARGSUSED */
ssize_t	v5ConnectSendReply(int fd, const void *buf,size_t count,unsigned int flg)
{
    register fdInfoType	*peer=fdInfo+fd;
    register fdInfoType	*client=peer->peer;
    register int	res;
    struct sockaddr_in	sin;
    int			sinlen=sizeof(peer->sin);

    if (client->fd<0)
	return 0;

    peer->TCP_SEND=(sendFunc*)send;
    peer->TCP_INBOUND=simpleInbound;

    res=connect(fd,(struct sockaddr*)&client->sin,sizeof(client->sin));
    footprint(9,client->fd,errno,0);

    memset(&peer->sin,0,sizeof(peer->sin));

    if (res==0 || errno==EISCONN) {
	sinlen=sizeof(sin);
	res=getsockname(fd,(struct sockaddr*)&sin,&sinlen);

	sinlen=sizeof(peer->sin);
	res=getpeername(fd,(struct sockaddr*)&peer->sin,&sinlen);

	v5WriteReply(client,&sin,SOCKS5_OK,0);
	if (client->fd>=0) {
	    setSelect(client->fd,SL_READ);
	    setSelect(fd,SL_READ|SL_EXCP);
	}
    } else {
	v5WriteReply(client,&client->sin,v5ErrnoToResult(errno),0);
	if (client->fd>=0)
	    pendingClose(peer,LOG_ERRNO+errno);
    }
    return 0;
}

int v5DoBind(fdInfoType *client)
{
    register fdInfoType		*peer=client->peer;
    register connInfoType	*conn=client->conn;
    register int		outFd=peer->fd,res;
    struct sockaddr_in		sin;
    register v5HeadType		*req=conn->req;
    double			dbuf[304/sizeof(double)];

    outFd=peer->fd;

    switch(conn->req->atyp) {
	case ATYP_V4:
	    {
		u_int32_t dest;
		memcpy(&dest,req->destAddr,sizeof(dest));
		memset(&sin,0,sizeof(sin));
		sin.sin_family=AF_INET;
		sin.sin_addr.s_addr=findRoute(dest);
		memcpy(&sin.sin_port,req->destAddr+4,sizeof(sin.sin_port));
		if (ntohs(sin.sin_port)<IPPORT_RESERVED)
		    sin.sin_port=0;
	    }
	    break;
	default:
	    return SOCKS5_ADDR_NOT_SUPP;
    }

    res=bind(outFd,(struct sockaddr*)&sin,sizeof(sin));

    if (res<0) {
	syslog(LOG_ERR,"v5DoBind bind([%s].%d) failed: %m",inetNtoa(sin.sin_addr.s_addr),ntohs(sin.sin_port));
	return v5ErrnoToResult(errno);
    }

    {
	int len=sizeof(sin);
	res=getsockname(outFd,(struct sockaddr*)&sin,&len);
    }
    
    if (res<0) {
	syslog(LOG_ERR,"v5DoBind getsockname failed: %m");
	return v5ErrnoToResult(errno);
    }

    v5WriteReply(client,&sin,SOCKS5_OK,0);

    res=listen(outFd,1);

    peer->TCP_RECV=v5BindRecv;

    return SOCKS5_OK;	/* So far, anyway. */
}
/* recvFunc */
/* ARGSUSED */
ssize_t v5BindRecv(int fd, void *buf,size_t count,unsigned int flags)
{
    register fdInfoType		*peer=fdInfo+fd;
    register fdInfoType		*client=peer->peer;
    register connInfoType	*conn=peer->conn;
    int				sinlen=sizeof(peer->sin);
    register int		newFd;
    register int		result;

    newFd=accept(fd,(struct sockaddr*)&peer->sin,&sinlen);

    if (newFd>=0) {
	dup2(newFd,fd);
	close(newFd);

	setSocketBuffer(fd,conn->bufSize);
	setNonBlocking(fd);

	peer->TCP_RECV=(recvFunc*)recv;
	result=SOCKS5_GENFAIL;

	switch(peer->sin.sin_family) {
	    case AF_INET:
		if (memcmp(&conn->req->destAddr,&peer->sin.sin_addr,4)==0) {
		    result=SOCKS5_OK;
		} else {
		    unsigned int destAddr;
		    memcpy(&destAddr,conn->req->destAddr,sizeof(destAddr));
		    syslog(LOG_ERR,"v5BindRecv received connection from %s, expected connection from %s",
			    inetNtoa(peer->sin.sin_addr.s_addr), inetNtoa(destAddr));
		}
		break;
#ifdef AF_INET6
	    case AF_INET6:	if (memcmp(&conn->req->destAddr,&peer->sin.sin_addr,16)==0) result=SOCKS5_OK; break;
#endif
	    default:	result=SOCKS5_ADDR_NOT_SUPP; break;
	}
    } else {
	syslog(LOG_WARNING,"v5BindRecv accept failed: %m");
	result=v5ErrnoToResult(errno);
    }
    setSelect(fd,SL_READ|SL_EXCP);
    v5WriteReply(client,&peer->sin,result,0);
    return result==SOCKS5_OK ? -2 : -1;
}
