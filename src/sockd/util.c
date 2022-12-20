#include "sockd.h"

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/util.c,v 0.75 2002/07/27 03:55:34 lamont Exp $";
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


#define FREE_IF_SET(x) { if (x) { free(x); (x)=NULL; } }
#define MUNMAP_IF_SET(x,s) { if (x) { munmap(x,s); (x)=NULL; } }

void bufFree(dataBufType *inf)
{
    if (inf->dataLen) {
	syslog(LOG_ERR,"Freeing buffer with %d byte(s) data", inf->dataLen);
    }
    MUNMAP_IF_SET(inf->bufStart,inf->bufSize);
    inf->bufStart=inf->dataStart=NULL;
    inf->bufSize=inf->dataLen=0;
}

/******************************************************************
 *
 * freeSomeMemory() will release a few buffers (and resize others)
 * in an attempt to recover from malloc returning a NULL.
 ******************************************************************/
void freeSomeMemory(dataBufType *buf)
{
    register fdInfoType *info;
    register int i;
    register long freed=0;
    register int thresh;

#define toss(x) { freed+=(x).bufSize; bufFree(&(x)); }

    /* First, toss any empty output buffers */
    for (i=lowFd,info=fdInfo+lowFd; i<=highFd; info++,i++) if (buf != &info->out) {
	if (info->out.bufStart && info->out.dataLen==0) {
	    toss(info->out);
	}
    }
    if (freed>=4096)
	goto done;
    
    /* Then toss any empty input buffers */
    for (i=lowFd,info=fdInfo+lowFd; i<=highFd; info++,i++) if (buf != &info->in) {
	if (info->in.bufStart && info->in.dataLen==0) {
	    toss(info->in);
	}
    }
    if (freed>=4096)
	goto done;

#undef toss

    /* If we didn't get any freed by now, bummer. */
    if (!freed) {
	abort();
    }
done:
    syslog(LOG_NOTICE,"freeSomeMemory freed %d bytes",freed);
}
/******************************************************************
 *
 * addToBuffer() and getFromBuffer() handle the task of adding data
 * to, and removing it from, a buffer (ala info->{in,out}).  Saying
 * peek to getFromBuffer will leave the data in the buffer.
 *
 ******************************************************************/
void addToBuffer(fdInfoType *info,dataBufType *inf,void *buf,int len)
{
    if (!inf->bufStart) {
	inf->bufSize=4096;
	inf->bufStart=mmap(NULL,len,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
	inf->dataStart=inf->bufStart;
	inf->dataLen=0;
	if (!inf->bufStart)
	    freeSomeMemory(inf);
	if (!inf->bufStart) {
	    pendingClose(info,LOG_OUT_OF_MEMORY);
	    return;
	}
    }

    if (inf->dataStart+inf->dataLen+len>inf->bufStart+inf->bufSize) {
	if (inf->dataStart != inf->bufStart) {
	    memmove(inf->bufStart,inf->dataStart,inf->dataLen);
	    inf->dataStart=inf->bufStart;
	} else {
	    syslog(LOG_ERR,
		"too much data in addToBuffer(fd=%d,datalen=%d,len=%d)",
			info->fd,inf->dataLen,len);
	    pendingClose(info,LOG_TOO_MUCH_TCP_DATA);
	    return;
	}
    }
    memcpy(inf->dataStart+inf->dataLen,buf,len);
    inf->dataLen+=len;
}

int getFromBuffer(void *buf,dataBufType *inf,int len,int peek)
{
    if (!inf->bufStart)
	return 0;
    if (inf->dataLen<len)
	len=inf->dataLen;

    memcpy(buf,inf->dataStart,len);
    if (!peek) {
	inf->dataStart+=len;
	inf->dataLen-=len;

	if (!inf->dataLen) {
	    inf->dataStart=inf->bufStart;
	}
    }
    return len;
}
/******************************************************************
 *
 * setupTimeouts() and setSocketBuffer() set the initial timeouts
 * and buffer sizes for a socket.
 *
 ******************************************************************/
void setupTimeouts(connInfoType *conn,int timeOut)
{
    if (!conn->startTime)
	conn->startTime=now;
    conn->timeOut=timeOut;
    conn->expire=timeOut ? timeOut+conn->startTime : 0;
}
void setSocketBuffer(int fd, int bufSize)
{
    int bval, blen=sizeof(bval);

    /* set send/recv buffer sizes */
    if (getsockopt(fd,SOL_SOCKET,SO_RCVBUF,&bval,&blen)==0 && bval<bufSize) {
	bval=bufSize;
	(void)setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&bval,blen);
    }
    if (getsockopt(fd,SOL_SOCKET,SO_SNDBUF,&bval,&blen)==0 && bval<bufSize) {
	bval=bufSize;
	(void)setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&bval,blen);
    }
}

/******************************************************************
 *
 * freePointers() is called from closeConnection(), once for each
 * half of a connection.  Any memory allocated for the connection
 * should be freed here.
 *
 ******************************************************************/
static void freePointers(fdInfoType *info)
{
    /* all that we leave is info->flags:  all malloc'ed regions are freed */

    bufFree(&info->in);
    bufFree(&info->out);
    shutdown(info->fd,SHUT_RDWR);
    close(info->fd);
    info->fd=-1;
    info->peer=NULL;
    info->conn=NULL;
}

extern int pendingCloses;
void pendingClose(fdInfoType *info,int why)
{
    register connInfoType *conn=info->conn;

    if (info->conn) {
	if (info->flags&FD_IS_LISTEN) {
	    syslog(LOG_WARNING,"pendingClose(listen socket,%d)",why);
#ifdef __hpux
	    dumpMap(0);
#endif
	    unListen(1);
	    return;
	}
	pendingCloses++;
	conn->flags|=CO_CLOSE_PENDING;
	conn->error=why;
    } else {
	closeConnection(info,why,1);
    }
}

/******************************************************************
 *
 * He's dead Jim.  Clean up the body, log the close record, and
 * handle any special beasties.
 *
 ******************************************************************/
void closeConnectionReal(fdInfoType *info,int why,int closeNow)
{
    register connInfoType *conn=info->conn;
    register fdInfoType *peer=info->peer;
    register fdInfoType *origInfo=info;

    if (debug&DBG_CLOSE) {
	syslog(LOG_DEBUG,"closeConnection(%d,%d,%d) fd=%d flags=x%x",info-fdInfo, why, closeNow, info->fd,info->flags);
    }

    if (info->fd<0)		/* we may have nuked him as part of his peer's closeConnection */
	return;

    footprint(3,info->fd,(int)info,(int)conn);
    
    if (info->flags&FD_IS_SPECIAL) {
	if (info==dnsInfo) {
	    dnsServerInit();
	} else {
	    info->flags|=FD_SHUTDOWN; clrSelect(info->fd,SL_ALL);
	    freePointers(info);
	    if (peer && peer->fd>=0) {
		peer->flags|=FD_SHUTDOWN; clrSelect(peer->fd,SL_ALL);
		freePointers(peer);
	    }
	}
	return;
    }

    if (info->flags&FD_IS_LISTEN) {
	syslog(LOG_WARNING,"closeConnection(listen socket,%d)",why);
#ifdef __hpux
	dumpMap(0);
#endif
	unListen(1);
	return;
    }

    /* Be the client. */
    info=conn->client;
    peer=info->peer;

    if (debug&DBG_CLOSE) {
	syslog(LOG_DEBUG," client=%d peer=%d udp=%d", conn->client-fdInfo, peer ? peer-fdInfo : -1,
	       conn->udp ? conn->udp-fdInfo : -1);
    }

    /* If there was a udp pair for this connection, nuke it too. */
    if (conn->udp) {
	register fdInfoType *udp,*udpPeer;
	udp=conn->udp, udpPeer=udp->peer;

	info->in.totalBytes+=udp->in.totalBytes;
	info->out.totalBytes+=udp->out.totalBytes;
	peer->in.totalBytes+=udpPeer->in.totalBytes;
	peer->out.totalBytes+=udpPeer->out.totalBytes;
	
	udp->flags|=FD_SHUTDOWN; clrSelect(udp->fd,SL_ALL);
	udpPeer->flags|=FD_SHUTDOWN; clrSelect(udpPeer->fd,SL_ALL);
	freePointers(udp);
	freePointers(udpPeer);
	conn->udp=NULL;
    }

    info->flags|=FD_SHUTDOWN; clrSelect(info->fd,SL_ALL);
    peer->flags|=FD_SHUTDOWN; clrSelect(peer->fd,SL_ALL);

    if (!closeNow && conn->req && (info->out.dataLen || peer->out.dataLen)) {
	if (info->out.dataLen) setSelect(info->fd,SL_WRITE);
	if (peer->out.dataLen) setSelect(peer->fd,SL_WRITE);
	return;
    }

    if (conn->pid) {
	kill(conn->pid,SIGKILL);
	conn->pid=0;
    }

    if (!info->conn) {
	syslog(LOG_ERR,"Null connection pointer origInfo=%x conn=%x info=%x",origInfo,conn,info);
#ifdef __hpux
	dumpMap(0);
#endif
	unListen(1);
	return;
    } else {
	logClose(info, why);
    }

    freePointers(info);
    freePointers(peer);
    FREE_IF_SET(conn->user);
    FREE_IF_SET(conn->req);

    conn->flags &= ~CO_IN_USE;
    conn->client=(fdInfoType*)freeConn;
    freeConn=conn;

    if (!--negotInfo->numConn && (negotInfo->flags&NF_LOSER))
	destroyDaemon();
    else {
	tryListen(0);
	while (fdInfo[highFd].fd == -1 && highFd>lowFd)
	    --highFd;
	while (fdInfo[lowFd].fd == -1 && highFd>lowFd)
	    ++lowFd;
    }
}
int insane_count=0;
void insane(int where)
{
    static int logged=0;
    if (!logged) {
	syslog(LOG_ERR, "insane internal structures: %d",where);
	dumpFootprint(where);
    }
    logged=1;
    insane_count++;
}
void connSanity(int call)
{
    register fdInfoType *info, *client;
    register connInfoType *conn;

    if (!(debug&DBG_SANITY))
	return;
    for (info=fdInfo; info<fdInfo+maxFd; info++)
	info->flags&=~FD_SANITY_HIT;
    for (conn=connInfo; conn<connInfo+config.daemon.maxClient; conn++)
	conn->flags&=~CO_SANITY_HIT;

    for (info=fdInfo; info<fdInfo+maxFd; info++) {
	conn=info->conn;
	if (info->fd<0 || !conn) continue;
	if (!(conn->flags&CO_IN_USE)) {
	    syslog(LOG_ERR,"using unused connection info=%x, conn=%x",info,conn);
	    insane(1);
	}
	info->flags |= FD_SANITY_HIT;
	if (info->peer->conn != conn || info->peer->peer != info)
	    insane(2);
	if (info->flags&FD_IS_CLIENT) {
	    if (info->flags&FD_IS_UDP) {
		if (conn->udp != info)
		    insane(3);
	    } else {
		if (conn->client != info)
		    insane(4);
	    }
	    if (conn->udp && conn->udp->conn != conn)
		insane(5);
	}
    }
    
    for (conn=freeConn; conn; conn=(connInfoType*)conn->client) {
	if (conn->flags&CO_IN_USE) {
	    syslog(LOG_ERR,"free conn(%x) in use",conn);
	    insane(6);
	}
	conn->flags |= CO_SANITY_HIT;
    }
    for (conn=connInfo; conn<connInfo+config.daemon.maxClient; conn++) {
	if ((conn->flags & (CO_SANITY_HIT|CO_IN_USE)) == 0) {
	    syslog(LOG_ERR,"lost conn(%x)",conn);
	    insane(7);
	}
	if (conn->flags&CO_IN_USE) {
	    if (conn->client->conn != conn || !(conn->client->flags&FD_SANITY_HIT)) {
		syslog(LOG_ERR,"badly broken connection %x",conn);
		insane(8);
	    }
	}
    }
}
void closeConnection(fdInfoType *info,int why,int closeNow)
{
    connSanity(0);
    closeConnectionReal(info,why,closeNow);
    connSanity(1);
}

int createSocket(int af, int type, int protocol)
{
    register int fd=socket(af,type,protocol);
    int val=((config.daemon.flags&FL_NO_KEEPALIVE)==0);

    if (fd<0)
	return fd;
    bumpHighLow(fd);
    setNonBlocking(fd);
    if (type==SOCK_STREAM) {
	if (setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&val,sizeof(val))<0)
	    syslog(LOG_NOTICE,"setsockopt(SO_KEEPALIVE) failed %m");
	val=1;
	if (setsockopt(fd,SOL_SOCKET,SO_OOBINLINE,&val,sizeof(val))<0)
	    syslog(LOG_NOTICE,"setsockopt(SO_OOBINLINE) failed %m");
    }
    return fd;
}

extern fd_set	readFds,writeFds,excpFds;
/***********************************************************************
 * setSelect(int fd,int which)
 * clrSelect(int fd,int which)
 *
 * Set select flags for mainLoop().
 ***********************************************************************/
void setSelect(int fd, int which)
{
    bumpHighLow(fd);

#if 0
    footprint(0xa,fd,which,0);
#endif
    if (which&SL_READ)  { FD_SET(fd,&readFds);  }
    if (which&SL_WRITE) { FD_SET(fd,&writeFds); }
    if (which&SL_EXCP)  { FD_SET(fd,&excpFds);  }
}
void clrSelect(int fd, int which)
{
#if 0
    footprint(0x1a,fd,which,0);
#endif
    if (which&SL_READ)  { FD_CLR(fd,&readFds);  }
    if (which&SL_WRITE) { FD_CLR(fd,&writeFds); }
    if (which&SL_EXCP)  { FD_CLR(fd,&excpFds);  }
}
/******************************************************************
 *
 * nullExcp is an exception handler for people who don't need
 * one.  Sometime down the road, we'll need to handle out of band
 * data.  As it sits, we just close the connection.
 *
 ******************************************************************/
void nullExcp(fdInfoType *info)
{
    syslog(LOG_NOTICE,"Exception on %d",info->fd);	/* XXX */
    pendingClose(info,LOG_OOB_DATA_NOT_SUPP);	/* XXX */
}
/******************************************************************
 *
 * setupDaemon() does all of the setup work for a newly hatched
 * daemon.  If possible, this daemon will compete for new
 * connections, just like his daddy and other relatives.  If he
 * can't get a slot in the negotiation table, then he is a loser.
 * (I know, that's really negative.  Bummer.)
 *
 ******************************************************************/
negotInfoType loserInfo;
void setupDaemon(int numConn)
{
    register int i;
    register negotInfoType *nInfo;
    register int loser=0;
    char cmdLine[256];

    setupSignals(1);
    negotInfo=NULL;	/* That one belongs to daddy. */

    negotLock();

    for (i=0,nInfo=negot->slot;i<NEGOT_MAXSLOT;nInfo++,i++) {
	if (nInfo->pid)
	    checkPidLock(i);
	if (!nInfo->pid) {
	    negotSlot=i;
	    negotInfo=nInfo;
	    break;
	}
    }

    if (!negotInfo) {
	loser=1;
	nInfo=negotInfo=&loserInfo;
	nInfo->flags|=NF_LOSER;
    }
    nInfo->pid=getpid();
    nInfo->flags=0;
    nInfo->numConn=numConn;
    nInfo->lastChecked=time(NULL);

    tryListen(1);

    negotUnlock();

    if (loser)  {
	unListen(1);
	if (!numConn)
	    destroyDaemon();
    } else {
	snprintf(cmdLine,sizeof(cmdLine),"%s --listen",config.daemon.name);
	setCommandLine(cmdLine);
	dnsServerInit();
    }
}

void forgetInfo(fdInfoType *info)
{
    if (info->in.bufStart) bufFree(&info->in);
    if (info->out.bufStart) bufFree(&info->out);
    info->conn=NULL;
    close(info->fd);
    clrSelect(info->fd,SL_ALL);
    info->fd=-1;
}
static void forgetConn(connInfoType *conn)
{
    fdInfoType *infos[5], *info;
    register int i=0;
    infos[i++]=conn->client;
    if (conn->client->peer)
	infos[i++]=conn->client->peer;
    if (conn->udp) {
	infos[i++]=conn->udp;
	if (conn->udp->peer)
	    infos[i++]=conn->udp->peer;
    }
    infos[i]=NULL;
    for (i=0;infos[i]; i++) {
	forgetInfo(infos[i]);
    }
    conn->startTime=0;
    conn->flags &= ~CO_IN_USE;
    conn->client=(fdInfoType*)freeConn;
    freeConn=conn;
}
/******************************************************************
 *
 * spawnChild() forks the daemon, and gives the child all of the
 * clients.  The parent is then free to continue on with his life.
 *
 ******************************************************************/
int spawnChild(connInfoType *conn)
{
    register int numConn=negotInfo->numConn;
    register int ret;
    register int fd;

    ret=fork();

    switch(ret) {
	register int i;
	register fdInfoType *info;
	case 0:	/* Child keeps all the active connections, except maybe 1 */
	    if ((debug&DBG_CHILD) && (debug&DBG_FOREGROUND)) {
		volatile int dbg_wait=0;
		while (!dbg_wait);
	    }
	    footprint(0x16,highFd,(int)conn,0);
	    if (conn) {
		forgetConn(conn);
		numConn--;
	    }
	    setupDaemon(numConn);
	    break;
	case -1:
	    syslog(LOG_ERR,"fork failed: %m");
	    return -1;
	default:
	    footprint(6,highFd,(int)conn,0);
	    connSanity(6);
	    for (i=lowFd,info=fdInfo+lowFd; i<=highFd; i++,info++) {
		if (info->fd!=-1) {
		    if (info->conn != conn && !(info->flags&FD_IS_LISTEN)) {
			forgetConn(info->conn);
		    } else {
			fd=i;
		    }
		}
	    }
	    highFd=fd;
	    negotInfo->numConn=conn ? 1 : 0;
    }
    return ret;
}
/******************************************************************
 *
 * We're dead, Jim.  Close the door and turn out the lights.
 *
 ******************************************************************/
static int inDestroy=0;
void destroyDaemon(void )
{
    dnsDestroy();
    if (!inDestroy && negotInfo->numConn) {
	inDestroy=1;
	terminate(0);
    }
    if (negotInfo!=&loserInfo) {
	unListen(1);
	negotLock();
	negotInfo->pid=0;
	negotUnlock();
    }
    exit(0);
}

/******************************************************************
 *
 * Here begins the negotiation routines.  On machines that support
 * memory mapped files, we use one of those.  Otherwise, we use
 * a shared memory segment.
 *
 * negotInit() is the guy who sets up the table initially, so that
 * everyone can play with it once we start launching daemon children.
 *
 ******************************************************************/
int negotFd;
void negotInit(void)
{
    char blank[NEGOT_SIZE];
    register int created=0;

    /* setup multi-daemon negotiation page */
    negotFd=open(config.daemon.negotFile,O_RDWR);
    if (negotFd<0) {
	if ((negotFd=open(config.daemon.negotFile,O_WRONLY|O_CREAT|O_EXCL,0644))>=0) {
	    memset(blank,0,sizeof(blank));
	    write(negotFd,blank,sizeof(blank));
	    close(negotFd);
	    negotFd=open(config.daemon.negotFile,O_RDWR);
	    created=1;
	}
	if (negotFd<0) {
	    syslog(LOG_ERR,"Unable to open negotiation file: %m");
	    exit(2);
	}
    }
#ifdef HAVE_MMAP
    negot=(negotPageType*)mmap((void*)NULL,NEGOT_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FILE,negotFd,0);
#define CHECK(negot) (negot)==(negotPageType*)0xffffffff || !(negot)
#define ERRSTR "Unable to mmap negotiation file: %m"
#else
    {
	int key;
	int shmId;
	key=ftok(config.daemon.name,ntohs(config.daemon.port));
	shmId=shmget(key,NEGOT_SIZE,IPC_CREAT|0644);
	if (shmId>=0) {
	    negot=(negotPageType*)shmat(shmId,NULL,0);
	} else {
	    negot=NULL;
	}
    }
#define CHECK(negot) !(negot)
#define ERRSTR "Unable to attach negotiation shared memory: %m"
#endif
    if (CHECK(negot)) {
	syslog(LOG_ERR,ERRSTR);
	exit(2);
    } else {
	register int i;
	if (created) {
	    memset((void*)negot,0,NEGOT_SIZE);
#ifdef HAVE_MSEM
	    msem_init(&negot->head.sema,MSEM_UNLOCKED);
#else
	    {
		struct semid_ds buf;
		int val=1;
		negot->head.semId=semget(ftok(config.daemon.name,ntohs(config.daemon.port)),1,IPC_CREAT|0600);
		semctl(negot->head.semId,0,SETVAL,val);
	    }
#endif
	    for (i=0;i<NEGOT_MAXSLOT;i++) {
		negot->slot[i].pid=0;
		negot->slot[i].numConn=0;
	    }
	}
    }
}
/******************************************************************
 *
 * negotLock() acquires exclusive access to the negotiation table.
 * This is useful for inserting yourself, or making sure that only
 * one daemon scans things at a time.  Note that updates to your
 * own slot's numConn are not protected by the semaphore.  Those
 * are read only for everyone else.
 *
 ******************************************************************/
void negotLock(void)
{
#ifdef HAVE_MSEM
    register int ret;
    ret=msem_lock(&negot->head.sema,0);
    if (ret<0) {
	syslog(LOG_ERR,"msem_lock: %m");
	exit(2);
    }
#else
    struct sembuf sops[1];
    register int res;

    sops[0].sem_num=0;
    sops[0].sem_op=-1;
    sops[0].sem_flg=0;
    res=semop(negot->head.semId,sops,1);
#endif
}
/******************************************************************
 *
 * negotUnlock() releases exclusive access to the negotiation table.
 * What we take, we must give back.
 *
 ******************************************************************/
void negotUnlock(void)
{
#ifdef HAVE_MSEM
    if (msem_unlock(&negot->head.sema,0)<0) {
	syslog(LOG_ERR,"msem_unlock: %m");
	exit(2);
    }
#else
    struct sembuf sops[1];
    register int res;

    sops[0].sem_num=0;
    sops[0].sem_op=1;
    sops[0].sem_flg=0;
    res=semop(negot->head.semId,sops,1);
#endif
}
/******************************************************************
 *
 * Compare a host entry to an address, and see if it's a hit.
 *
 ******************************************************************/
int compareAddr(hostType *host, u_int32_t IP)
{
    register int t=ntohl(IP&host->mask);

    switch(host->op) {
	case r_eq:	return t==ntohl(host->value);
	case r_ne:	return t!=ntohl(host->value);
	case r_lt:	return t< ntohl(host->value);
	case r_le:	return t<=ntohl(host->value);
	case r_gt:	return t> ntohl(host->value);
	case r_ge:	return t>=ntohl(host->value);
	default:	return 0;
    }
}
/******************************************************************
 *
 * At this point, we're down to the utilitiy routines again, so
 * there isn't much logic to the ordering of things...  Not that
 * there's that much order elsewhere, but I tried.
 *
 * findRoute takes a destination IP address and figures out what
 * the source IP address for the bind should be.
 *
 * XXX IPV6 - This needs to handle IP V6 addresses as well...
 *
 ******************************************************************/
u_int32_t findRoute(u_int32_t destIP)
{
    register routeInfoType *route=config.routes.list;
    register int i;

    for (i=config.routes.num;i>0;i--,route++) {
	if (compareAddr(&route->host,destIP))
	    return route->ip;
    }
    return INADDR_ANY;
}
/******************************************************************
 *
 * Get an environment variable for a connection.  We first look
 * in the method specific environment, and then move on to the
 * global environment.
 *
 ******************************************************************/
const char *getEnv(const fdInfoType *info,const char *name)
{
    register int len=strlen(name);
    register char **env;
    register int i;

    /* first look at the method specific environment */
    for (i=info->conn->method->env.num-1,env=info->conn->method->env.list;i>= 0; i--,env++) {
	if (strncmp(name,*env,len)==0 && env[0][len]=='=') {
	    return *env+len+1;
	}
    }
    /* then look at the global environment */
    for (i=config.env.num-1,env=config.env.list;i>= 0; i--,env++) {
	if (strncmp(name,*env,len)==0 && env[0][len]=='=') {
	    return *env+len+1;
	}
    }
    /* XXX - Maybe do a getenv()? */
    return NULL;
}

/******************************************************************
 * footprinting code.
 ******************************************************************/

#define FP_NUM 3000
int fp_num=FP_NUM;
struct fp {
    time_t time;
    unsigned short a,b;
    int c,d;
} fp[FP_NUM];
int fp_next=0;


void footprint(u_short a, u_short b, int c, int d)
{
    fp[fp_next].time=time(NULL);
    fp[fp_next].a=a;
    fp[fp_next].b=b;
    fp[fp_next].c=c;
    fp[fp_next].d=d;
    if (fp_next++ >= fp_num)
	fp_next=0;
}

void dumpFootprint(int where)
{
    register int fd;
    register char *base=config.log.dumpPrefix;
    register char *name;
    register int i;
    register fdInfoType *info;
    register connInfoType *conn;
    register FILE* f;

    if (!base) {
	syslog(LOG_ERR,"No dump file.");
	return;
    }

    name=malloc(strlen(base)+30);
    if (name==NULL) {
	freeSomeMemory(NULL);
	name=malloc(strlen(base)+30);
    }
    if (name==NULL) {
	syslog(LOG_ERR,"Out of memory in dumpFootprint");
	return;
    }
    sprintf(name,"%s.footprint.%d",base,negotInfo->pid);

    fd=open(name,O_WRONLY|O_CREAT|O_EXCL,0600);
    if (fd<0) {
	syslog(LOG_ERR,"Couldn't open %s for write",name);
	free(name);
	return;
    }
    f=fdopen(fd,"w");
    fprintf(f,"where=%d\n",where);

    i=fp_next ? fp_next-1 : fp_num-1;
    while (i!= fp_next) {
	if (fp[i].time)
	    fprintf(f,"%04x %4d 0x%08x 0x%08x %s", /* ctime has \n */
		 fp[i].a, fp[i].b, fp[i].c, fp[i].d, ctime(&fp[i].time));
	i= i ? i-1 : fp_num-1;
    }

    fprintf(f,"\nfdInfo:\n");
    fprintf(f,"  addr     peer     conn      fd     flags    IPaddr  port\n");
    fprintf(f,"======== ======== ======== ======== ======== ======== =====\n");
    for (info=fdInfo; info<fdInfo+maxFd; info++) {
	fprintf(f,"%08x %08x %08x %8d %08x %08x %5d\n",
		info,info->peer,info->conn,info->fd,info->flags,
		ntohl(info->sin.sin_addr.s_addr),ntohs(info->sin.sin_port));
    }
    fprintf(f,"\nconnInfo:\n");
    fprintf(f,"  addr    client    udp     flags    error\n");
    fprintf(f,"======== ======== ======== ======== ========\n");
    for (conn=connInfo; conn<connInfo+config.daemon.maxClient; conn++) {
	fprintf(f,"%08x %08x %08x %8x %08x\n",
		conn,conn->client,conn->udp,conn->flags,conn->error);
    }

    fclose(f);
    free(name);
}
/******************************************************************
 *
 * How do I set the command line?  Let me count the ways.
 *
 ******************************************************************/
#ifdef __hpux
#include <sys/pstat.h>
#define HAVE_PSTAT
#endif

void setCommandLine(char *s)
{
#ifdef HAVE_PSTAT /* [ */
    union pstun pst;
    pst.pst_command=s;
    pstat(PSTAT_SETCMD,pst,0,0,0);
    return;
#else /* ] ! HAVE_PSTAT [ */
    /* XXX - need non-PSTAT setCommandLine */
#endif /* ] ! HAVE_PSTAT */
}
