#include "sockd.h"

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/listen.c,v 0.51 2002/01/28 18:15:12 lamont Exp $";
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


void tryListenLock(void);
int		listenTries=10;
struct timeval	lastAccept;
int		avgClientTime;
float		avgClientWeight=0.99;

#define LISTEN_FAIL	-1
#define LISTEN_NOONE	-2
#define LISTEN_GOTONE	-3

/****************************************************************************
 *
 * listenRecv() is the recv function for the listen socket.  His job is to
 * accept new connections (since there are multiple listners, just getting
 * a read select doesn't mean you'll get a connection, so deal with EWOULDBLOCK)
 *
 * After accepting the new connection, we create a socket for the peer side
 * of things.  If we've hit the connection limit, then we fork and the child
 * gets all of the connections.
 * 
 ****************************************************************************/
/* returns -2 (all OK), or -1 (drop the connection) */
/* recvFunc */
/* ARGSUSED */
ssize_t	listenRecv1(int fd, void *buf,size_t count,unsigned int flags)
{
    struct sockaddr_in		sin;
    int				len=sizeof(sin);
    register int		newFd;
    register fdInfoType		*client,*peer;
    register int		peerFd=-1;
    register connInfoType	*conn;
    int val;
    struct timeval		myTime;

    if (avgClientTime<config.daemon.milliPerClient) {
	milliSleep(config.daemon.milliPerClient-avgClientTime);
    }
    errno=0;
    do {
	newFd=accept(fd,(struct sockaddr*)&sin,&len);

	if (newFd<0) {
	    if (errno==EWOULDBLOCK) return LISTEN_NOONE;
	    if (errno==EMFILE) {
		config.daemon.maxClient=negotInfo->numConn;
		syslog(LOG_WARNING,"Got EMFILE at %d connections", negotInfo->numConn);
		if (spawnChild(NULL)) {
		    continue;
		} else {
		    return LISTEN_NOONE;
		}
	    }
	    if (errno==ENOBUFS) {
		syslog(LOG_WARNING,"Got ENOBUFS on accept");
		if (debug&DBG_SANITY)
		    dumpFootprint(-1);
		return LISTEN_NOONE;
	    }
	    return LISTEN_FAIL;
	}
    } while (newFd<0);
    bumpHighLow(newFd);
    gettimeofday(&myTime,(struct timezone*)NULL);
    avgClientTime=(int)((float)avgClientTime*avgClientWeight+
			(1.0-avgClientWeight)*((myTime.tv_sec-lastAccept.tv_sec)*1000+
						(myTime.tv_usec-lastAccept.tv_usec)/1000));
    lastAccept=myTime;

    val=((config.daemon.flags&FL_NO_KEEPALIVE)==0);
    if (setsockopt(newFd,SOL_SOCKET,SO_KEEPALIVE,&val,sizeof(val))<0)
	syslog(LOG_NOTICE,"setsockopt(SO_KEEPALIVE) failed %m");
    val=1;
    if (setsockopt(newFd,SOL_SOCKET,SO_OOBINLINE,&val,sizeof(val))<0)
	syslog(LOG_NOTICE,"setsockopt(SO_OOBINLINE) failed %m");
    setNonBlocking(newFd);
    do {
	peerFd=createSocket(AF_INET,SOCK_STREAM,0);
	if (peerFd<0) {
	    if (errno==EMFILE) {
		config.daemon.maxClient=negotInfo->numConn;
		syslog(LOG_WARNING,"Got EMFILE at %d connections", negotInfo->numConn);
		if (spawnChild(NULL)) {
		    continue;
		} else {
		    close(newFd);
		    return LISTEN_NOONE;
		}
	    }
	    close(newFd);
	    return LISTEN_FAIL;
	}
    } while (peerFd<0);
    bumpHighLow(peerFd);

    if (newFd>=maxFd || peerFd>=maxFd) {
	config.daemon.maxClient=negotInfo->numConn;
	syslog(LOG_WARNING,"Got EMFILE at %d connections", negotInfo->numConn);
	if (spawnChild(NULL)) {
	    register int t1,t2;
	    t1=dup(newFd);  close(newFd);
	    t2=dup(peerFd); close(peerFd);
	    if (t1<0 || t2<0) {
		if (t1>=0) close(t1);
		if (t2>=0) close(t2);
		syslog(LOG_ERR,"Unable to recover from spawning child: %m");
		return LISTEN_FAIL;
	    }
	    newFd=t1;
	    peerFd=t2;
	    if (newFd>=maxFd || peerFd>=maxFd) {
		syslog(LOG_ERR,"Too many file descriptors");
		close(newFd);
		close(peerFd);
		unListen(1);
		return LISTEN_NOONE;
	    }
	} else {
	    close(newFd); close(peerFd);
	    return LISTEN_NOONE;
	}
    }

    if (config.daemon.inetdSecFile && DoInetdSec(config.daemon.service,&sin,config.daemon.inetdSecFile)<0) {
	syslog(LOG_ERR,"Connection denied (inetd.sec) for %s",inet_ntoa(sin.sin_addr));
	close(newFd);
	close(peerFd);
	return LISTEN_GOTONE;
    }

    /* Do we need another daemon? */
    if (negotInfo->numConn >= config.daemon.maxClient) {
	if(!spawnChild(NULL)) {
	    close(newFd); close(peerFd);
	    return LISTEN_NOONE;
	}
    }
    negotInfo->numConn++;

    footprint(2,newFd,peerFd,0);
    connSanity(2);

    client=fdInfo+newFd;
    peer=fdInfo+peerFd;

    /* We should never get here with freeConn==NULL */
    conn=freeConn;
    freeConn=(connInfoType*)conn->client;
    if (conn->flags&CO_IN_USE) {
	syslog(LOG_ERR,"structure insanity: connection in use");
	abort();
    }

    memset(client,0,sizeof(*client));
    memset(peer,0,sizeof(*peer));
    memset(conn,0,sizeof(*conn));
    client->fd=newFd, peer->fd=peerFd;
    client->conn=peer->conn=conn;
    client->sin=sin;
    conn->client=client;
    conn->flags|=CO_IN_USE;
    client->flags=FD_IS_CLIENT;

    peer->TCP_RECV=client->TCP_RECV=(recvFunc*)recv, peer->TCP_SEND=client->TCP_SEND=(sendFunc*)send;
    peer->excp=client->excp=nullExcp;
    conn->bufSize=config.defaults.bufSize;
    client->TCP_INBOUND=newClient,	client->TCP_OUTPUT=simpleOutput;
    peer->TCP_INBOUND=simpleInbound,	peer->TCP_OUTPUT=v5Request;
    setSelect(newFd,SL_READ|SL_EXCP);

    peer->peer=client, client->peer=peer;

    /* sets startTime, timeOut, and expire */
    setupTimeouts(conn, config.defaults.setupTimeOut ? config.defaults.setupTimeOut : config.defaults.timeOut);

    return LISTEN_GOTONE;
}
ssize_t	listenRecv(int fd, void *buf,size_t count,unsigned int flags)
{
    register int i;
    register ssize_t ret=LISTEN_GOTONE;
    for (i=listenTries; i>0 && ret==LISTEN_GOTONE; i--) {
	ret=listenRecv1(fd,buf,count,flags);
    }
}

/****************************************************************************
 *
 * newClient() is the initial inbound function for a client.  Once we get
 * enough data (one byte) to tell which protocol we're talking, we go to
 * the version specific new client code.  If we get a bogus version, just
 * drop the connection.
 *
 ****************************************************************************/

/* inboundFunc */
void newClient(fdInfoType *client,void *buf,int len,unsigned int flags)
{
    /* make sure we have enought data to proceed - buffer it */
    addToBuffer(client,&client->in,buf,len);

    if (client->in.dataLen<1)
     	return;	

    switch (*client->in.dataStart) {
	case SOCKS_V4:		/* V4 emulation */
	    client->TCP_INBOUND=newV4Client;
	    newV4Client(client,NULL,0,flags);
	    break;
	case SOCKS_V5:		/* V5 */
	    if (!(config.daemon.flags&FL_V4_ONLY)) {
		client->TCP_INBOUND=newV5Client;
		newV5Client(client,NULL,0,flags);
		break;
	    }
	    /* fall through */
	default:
	    syslog(LOG_WARNING,"Bad version %d from %s", *client->in.dataStart,inet_ntoa(client->sin.sin_addr));
	    pendingClose(client,LOG_PROTOCOL_ERROR);
	    break;
    }
}
/*****************************************************************************
 *
 * Now we get into the listen negotiation code.  Routines ending in Lock are
 * only called with the negotLock() held.
 *
 * checkPidLock() makes sure that the pid in the slot is still alive, and
 * assumes that the pid is non-zero.
 *
 *****************************************************************************/
void checkPidLock(int nSlot)
{
    register negotInfoType *nInfo=negot->slot+nSlot;
    register int ret;

    /* assumes negotLock() active. */
    ret=kill(nInfo->pid,0);
    if (ret<0) {
	syslog(LOG_WARNING,"Detected death of pid %d: %m",nInfo->pid);
	nInfo->pid=0;
	if (LI_ISSET(nSlot,negot->head.listeners)) {
	    LI_CLR(nSlot,negot->head.listeners);
	    negot->head.numListen--;
	}
    }
}
void doListenLock(void)
{
    register int i;
    /* Assumes that negotLock() is active */
    if (!LI_ISSET(negotSlot,negot->head.listeners)) {
	LI_SET(negotSlot,negot->head.listeners);
	negot->head.numListen++;
    }
    for (i=0;daemonFd[i]>=0; i++) {
	setSelect(daemonFd[i],SL_READ);
    }
}
void unListenLock(void)
{
    register int i;
    /* Assumes that negotLock() is active */
    if (LI_ISSET(negotSlot,negot->head.listeners)) {
	LI_CLR(negotSlot,negot->head.listeners);
	negot->head.numListen--;
    }
    for (i=0;daemonFd[i]>=0; i++) {
	clrSelect(daemonFd[i],SL_READ);
    }
}
void unListen(int forever)
{
#ifdef __hpux
    int *ap=&forever;
#endif
    if (negotInfo==&loserInfo)
	return;
    
    if (forever || (debug&DBG_UNLISTEN)) {
#ifdef __hpux
	syslog(LOG_NOTICE,"unListen(%d) from 0x%x",forever,ap[4]);
#else
	syslog(LOG_NOTICE,"unListen(%d)",forever);
#endif
    }

    negotLock();
    if (forever && (negotInfo->flags&NF_LOSER))	{		/* vacate the table entry */
	loserInfo=*negotInfo;
	negotInfo->pid=0;
	negotInfo=&loserInfo;
	negotUnlock();
	return;
    }

    unListenLock();
    if (forever) {
	char cmdLine[256];
	negotInfo->flags|=NF_LOSER;
	snprintf(cmdLine,sizeof(cmdLine),"%s --nolisten",config.daemon.name);
	setCommandLine(cmdLine);
    }
    negotUnlock();

    if (forever) {
	register int i;
	for (i=0;daemonFd[i]>=0; i++) {
	    close(daemonFd[i]);
	    fdInfo[daemonFd[i]].fd=-1;
	    daemonFd[i]=-1;
	}
	if (!negotInfo->numConn)
	    destroyDaemon();
    }
}

typedef struct sort sortType;
struct sort { u_short score; u_short idx; };

void tryListen(int lock)
{
    if (negotInfo->flags&NF_LOSER)
	return;

    if (!lock) negotLock();
    tryListenLock();
    if (!lock) negotUnlock();
    
}

void tryListenLock(void)
{
    register int betterListen=0;
    register negotInfoType *nInfo;
    register int numConn=negotInfo->numConn;
    register int minListen=config.daemon.minListen;
#ifdef USE_SIGNALS
    sortType sort[NEGOT_MAXSLOT+1];
    register int numDaemon=0;
#endif /* USE_SIGNALS */
    register int i;

    negotInfo->lastChecked=now;
    /* Handle the no brainer cases first:  not enough clients, or too many clients */
    if (numConn < config.daemon.minClient) {
	doListenLock();
	return;
    } else if (numConn >= config.daemon.maxClient) {
	unListenLock();
	return;
    } 

    /* figure out how many potential listeners there are, and set things up for the kinda-sort. */ 
    for (i=0,nInfo=negot->slot;i<NEGOT_MAXSLOT;i++,nInfo++) {
	/* This little gem makes the loop go a bit faster, since we only do the smash of system
	 * calls once every 5 seconds.  The down side is that if all the listeners just died, then
	 * we won't notice it for up to config.daemon.poll+5 seconds, at which time we will recover.
	 */
	if (nInfo->pid && nInfo->lastChecked+5<now) {
	    checkPidLock(i);
	    nInfo->lastChecked=now;
	}

	if (!nInfo->pid || (nInfo->flags&NF_LOSER))
	    continue;
#ifdef USE_SIGNALS
	sort[numDaemon].score=nInfo->numConn;
	sort[numDaemon].idx=i;
	numDaemon++;
#else	/* ! USE_SIGNALS */
	if (nInfo->numConn<numConn)
	    betterListen++;
#endif	/* ! USE_SIGNALS */
    }

#ifdef USE_SIGNALS
    /* if there are enough potential listners to have it make sense, do enough of a sort to determine
     * who should be listening.  Put ourselves in the right camp, and then wake up people in the wrong
     * camp, so that they can find their way back to the right side of the lens.
     */

    if (numDaemon>minListen) {
	register int a,z,i,j,k;

	/* lots of places below walk off the end of the world if we don't do this */
	sort[numDaemon].score=config.daemon.maxClient+99;
	sort[numDaemon].idx=-1;
	numDaemon++;

	a=i=0; z=j=numDaemon-1;
	do {
	    k=sort[i++].score;
	    while (i<j) {
		while (k >= sort[i].score) i++;
		while (k <  sort[j].score) j--;
		if (i<j) {
		    register sortType t=sort[i];
		    sort[i]=sort[j]; sort[j]=t;
		}
	    }
	    if (sort[a].score != sort[j].score) {
		register sortType t=sort[a];
		sort[a]=sort[j]; sort[j]=t;
	    } else {
		a=j;
	    }
	    if (j+1 > minListen)
		i=a,j=z=j-1;
	    else if (j+1 < minListen)
		a=i=j+1,j=z;
	} while (j+1!=minListen && a < minListen);

	k=sort[j++].score;
	while (k==sort[j].score) j++;

	/* at this point, j points to the first non-listner entry in the table. */
	if (numConn < sort[j].score)
	    doListenLock();
	else
	    unListenLock();

	for (i=0;i<numDaemon;i++) {
	    register int ret;
	    if (i < j && !LI_ISSET(i,negot->head.listeners) ||
		i >=j &&  LI_ISSET(i,negot->head.listeners)) {
		    ret=kill(negot->slot[sort[i].idx].pid,SIGWAKEUP);
		}
	}
    } else {
	doListenLock();
    }
#else /* ! USE_SIGNALS */
    if (betterListen<minListen)
	doListenLock();
    else
	unListenLock();

    /* Can't go having no one listen!! */
    if (!negot->head.numListen)
	doListenLock();
#endif /* ! USE_SIGNALS */
}
