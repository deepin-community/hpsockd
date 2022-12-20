#include "sockd.h"
#include <sys/resource.h>
#include <net/if.h>
#include <sys/ioctl.h>

extern char *socks_version;

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/sockd.c,v 0.69 2003/08/29 16:02:30 lamont Exp $";
static char *copyright="@(#)Copyright Hewlett-Packard Company, 1997-2000.";
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


int main(int argc, char **argv);
void mainLoop(void);
void createListenSocket(void);

fd_set		readFds,writeFds,excpFds;
volatile int	highFd=0,lowFd=99999999;  /* Highest/lowest fd number in use */
int		maxFd;
int		*daemonFd;

fdInfoType	*fdInfo;
connInfoType	*connInfo;
connInfoType	*freeConn;
negotPageType	*negot;	/* negotiation page */
negotInfoType	*negotInfo;
volatile int		negotSlot;
configInfoType	config;
int		debug=DBG_SANITY;
static char	*configFile=CONFIG_FILE;
static char	syslogName[20];
time_t		now;
int		pendingCloses;	/* how many outstanding closes */

/************************************************************
 *
 * The outerblock takes care of parsing the one or two options,
 * and then sets everything up.  Almost everything comes from
 * the config file, so there aren't that many command line
 * options.
 *
 ************************************************************/
int main(int argc, char **argv)
{
    register int c;
    register int i;
    struct rlimit rp;

    /* we want core files */
    getrlimit(RLIMIT_CORE,&rp);
    rp.rlim_cur=0x7fffffff;
    rp.rlim_max=0x7fffffff;
    setrlimit(RLIMIT_CORE,&rp);

    while ((c=getopt(argc,argv,":c:d:l:vw:"))!=EOF) switch(c) {
	case 'c':	configFile=strdup(optarg); break;
	case 'd':	debug=strtol(optarg,(char**)NULL,0); break;
	case 'l':	listenTries=strtol(optarg,(char**)NULL,0); break;
	case 'v':	fprintf(stderr, "%s \n", socks_version+4); exit(0);
	case 'w':	avgClientWeight=(float)strtol(optarg,(char**)NULL,0)/100.0; break;
	case ':':
	case '?':
	default:	fprintf(stderr,"Usage: %s [ -c config ]\n",*argv); break;
    }

    readConfig(0);

    setgid(config.daemon.gid);
    setuid(config.daemon.uid);

    (void)openlog(syslogName,LOG_PID,config.log.facility);

    createListenSocket();
    negotInit();

    if (!(debug&DBG_FOREGROUND)) {
	register int ret=fork();
	if (ret<0) {
	    syslog(LOG_ERR,"fork: %m");
	    exit(1);
	} else if (ret) {
	    exit(0);	/* parent leaves, child does the work */
	}
	syslog(LOG_NOTICE,"Started on port %d (%s)",ntohs(config.daemon.port),socks_version+4);
	freopen("/dev/null","r",stdout);
	freopen("/dev/null","r+",stderr);
	if (debug&DBG_TRAIL)
	    freopen("debug_trail","a",stderr);
        setvbuf(stderr, (char *)NULL, _IONBF, 0);
	negot->head.processGroup=setsid();
	if (negot->head.processGroup<0) {
	    syslog(LOG_ERR,"Failed to get process group id: %m");
	    exit(2);
	}

	dnsGlobalInit();

	/* prefork daemons */
	for (i=config.daemon.preFork;i>1;i--) {
	    register pid_t pid=fork();
	    if (pid==-1) {
		syslog(LOG_WARNING,"preFork failed: %m");
		break;
	    } else if (pid==0) {
		sleep(i);	/* introduce some randomness */
		break;
	    }
	}
    } else {
	dnsGlobalInit();
    }

    setupDaemon(0);
    newLog(0);
    gettimeofday(&lastAccept,(struct timezone*)NULL);	/* make it something close... */

    /* go for broke */
    mainLoop();
    return 1;
}

/************************************************************
 *
 * This is the workhorse for the daemon.  Everything that means
 * anything causes a file descriptor to become ready for something.
 * The loop takes care of calculating the next timeout, making
 * sure that it polls for listening every config.daemon.poll
 * seconds.
 *
 * For read ready descriptors, we call info->recv, and if that
 * returns data, we call info->inbound.  Read select bits remain
 * on, unless the inbound func clears it.
 *
 * For write ready descriptors, we call info->send on the queued
 * data.  If we manage to write all of the data, and there is
 * a peer, we turn back on his read select bit.  Write select
 * bits are cleared if all the data is written.
 *
 * Any work scheduled by signal handlers is performed at the
 * top of the infinite while loop.
 *
 ************************************************************/
void mainLoop(void)
{
    register time_t	myNow;
    register time_t	nextExpire;
    register time_t	lastTryListen;

    myNow=now=time((time_t*)NULL);
    lastTryListen=myNow;
    nextExpire=myNow+config.daemon.poll;
    while (1) {
	register int	fd;
	fd_set r,w,e;
	struct timeval timeout;
	register int	num;
	register fdInfoType *info;
	register time_t	*exp;
	register int timeouts=0;	/* did something timeout (probably - the peer may save the day) */

	if (pendingSig) {
	    doSignals();
	}

	r=readFds, w=writeFds, e=writeFds;

	if (nextExpire<myNow)
	    nextExpire=myNow;
	timeout.tv_sec=nextExpire-myNow;
	timeout.tv_usec=0;

	if (debug&DBG_MAINLOOP)
	    fprintf(stderr,"selecting - timeout==%d\n",timeout.tv_sec);
	num=select(highFd+1,&r,&w,&e,(struct timeval *)&timeout);

	if (num<0) {
	    if (errno == EINTR) {
		continue;
	    } else {
		syslog(LOG_ALERT,"sockd died in select: %m");
		unListen(1);
		exit(1);
	    }
	}

	myNow=now=time((time_t*)NULL);
	if (lastTryListen+config.daemon.poll<=myNow) {
	    lastTryListen=myNow;
	    tryListen(0);
	}
	nextExpire=lastTryListen+config.daemon.poll;

	if (debug&DBG_MAINLOOP)
	    fprintf(stderr,"%d running num=%d\n",negotInfo->pid,num);
	for (fd=lowFd,info=fdInfo+lowFd;fd<=highFd;info++,fd++) {
	    if (info->fd<0) {
		if (fd==lowFd)
		    lowFd=fd;
		continue;
	    }
	    if (info->conn) {
		if (!FD_ISSET(fd,&e) && !FD_ISSET(fd,&w) && !FD_ISSET(fd,&r)) {
		    if (info->conn->expire) {
			if (info->conn->expire<=myNow) {
			    timeouts=1;
			} else if (info->conn->expire<nextExpire) {
			    nextExpire=info->conn->expire;
			}
		    }
		    continue;
		} else {
		    if (info->conn->timeOut) {
			info->conn->expire=myNow+info->conn->timeOut;
			if (info->conn->expire<nextExpire)
			    nextExpire=info->conn->expire;
		    }
		}
	    }
	    if (FD_ISSET(fd,&e)) {
		info->excp(info);
	    }
	    if (FD_ISSET(fd,&w)) {
		register int xfr;
		if (info->fd<0)
		    continue;
		if (debug&DBG_MAINLOOP)
		    footprint(5,fd,info->flags,0);
		clrSelect(fd,SL_WRITE);
		if (!(info->flags&FD_IS_UDP)) {
		    xfr=info->TCP_SEND(fd,info->out.dataStart,info->out.dataLen,0);
		    updateTime(info,out,xfr,myNow);
		    if (xfr>0) {
			info->out.dataLen-=xfr;
			if (!info->out.dataLen) {
			    bufFree(&info->out);
			} else {
			    info->out.dataStart+=xfr;
			    setSelect(fd,SL_WRITE);
			}
		    } else if (xfr<0) {
			pendingClose(info,LOG_ERRNO+errno);
			continue;
		    } 
		}
		if (info->peer && !info->out.dataLen) {
		    footprint(0xb,fd,0,0);
		    setSelect(info->peer->fd,SL_READ);
		}
	    }
	    if (FD_ISSET(fd,&r)) {
		register int xfr;
		char buf[65536];

#define TCPSIZE		1024
		if (info->fd<0)
		    continue;
		if (debug&DBG_MAINLOOP)
		    footprint(0x15,fd,info->flags,0);
		if (!(info->flags&FD_IS_UDP)) {
		    xfr=info->TCP_RECV(fd,buf,TCPSIZE,0);
		    updateTime(info,in,xfr,myNow);
		    if (xfr<0) {
			if (xfr==-1)
			    pendingClose(info,LOG_ERRNO+errno);
		    } else if (xfr) {
			info->TCP_INBOUND(info,buf,xfr,0);
			if (!info->in.dataLen) {
			    bufFree(&info->in);
			}
		    } else {
			pendingClose(info,LOG_CLOSE);
		    }
		} else {
		    struct sockaddr_in from;
		    int fromLen;
		    fromLen=sizeof(from);
		    xfr=info->UDP_RECVFROM(fd,buf,sizeof(buf),0,&from,&fromLen);
		    updateTime(info,in,xfr,myNow);
		    if (xfr<0) {
			if (xfr==-1)
			    pendingClose(info,LOG_ERRNO+errno);
		    } else {
			info->UDP_INBOUND(info,buf,xfr,0,&from,fromLen);
		    }
		}
	    }
	}
	if (timeouts) for (fd=lowFd,info=fdInfo+lowFd;fd<=highFd;info++,fd++) {
	    /* info->conn is set to NULL in closeConnection, so that's all we check */
	    if (info->conn && info->conn->expire && info->conn->expire<=myNow) {
		closeConnection(info,LOG_TIMEOUT,1);
	    }
	}

	if (pendingCloses) for (fd=lowFd,info=fdInfo+lowFd;fd<=highFd;info++,fd++) {
	    if (info->conn && (info->conn->flags&CO_CLOSE_PENDING)) {
		closeConnection(info,info->conn->error,info->conn->error==LOG_CLOSE ? 0 : 1);
	    }
	    pendingCloses=0;
	}
    }
}
longLType findListenInterfaces(void)
{
    struct ifconf		ifc;
    register struct ifreq	*ifreq;
    struct ifreq		myIfreq;
    char			buf[32768],*cplim;
    register int		i, fd=socket(AF_INET,SOCK_DGRAM,0);
    longLType			listenAddr;
    register void		*tmp;

    listenAddr.num=0;
    listenAddr.list=malloc(sizeof(*listenAddr.list));
    if (!listenAddr.list) {
nomem:	syslog(LOG_ERR,"Out of memory in findListenInterfaces");
	return listenAddr;
    }

    if (fd<0) {
	syslog(LOG_ERR,"socket failed in findListenInterfaces: %m");
	goto bailout;
    }

    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = buf;
    if (ioctl(fd,SIOCGIFCONF,&ifc)<0) {
	syslog(LOG_ERR,"SIOCGIFCONF failed: %m");
	goto bailout;
    }
    cplim=buf+ifc.ifc_len;
    for (i=0,ifreq=ifc.ifc_req;(char*)ifreq<cplim;i++,ifreq++) {
	memcpy(myIfreq.ifr_name,ifreq->ifr_name,sizeof(myIfreq.ifr_name));
	if (ioctl(fd,SIOCGIFFLAGS,&myIfreq)<0) {
	    syslog(LOG_WARNING,"SIOCGIFFLAGS failed on %s: %m",myIfreq.ifr_name);
	    continue;
	}
	if (myIfreq.ifr_flags&IFF_UP) {
	    register int j;
	    for (j=listenAddr.num-1;j>=0;j--) {
		if (listenAddr.list[j]==((struct sockaddr_in*)&ifreq->ifr_addr)->sin_addr.s_addr)
		    goto next_if;
	    }
	    tmp=realloc(listenAddr.list,(listenAddr.num+1)*sizeof(*listenAddr.list));
	    if (!tmp)
		goto nomem;
	    listenAddr.list=tmp;
	    listenAddr.list[listenAddr.num++]=((struct sockaddr_in*)&ifreq->ifr_addr)->sin_addr.s_addr;
	}
next_if: ;
    }
    close(fd);
bailout:
    if (!listenAddr.num)
	listenAddr.list[listenAddr.num++]=htonl(INADDR_ANY);

    return listenAddr;
}
/*********************************************************************
 *
 * Create the listen socket, and make it non-blocking (everything is
 * non-blocking).
 *
 *********************************************************************/
void createListenSocket(void)
{
    register int	s;
    long		sockopt;
    struct sockaddr_in	sin;
    register fdInfoType *info;
    register int	i;
    register int	numBound=0;
    longLType		addrs;
    int			tmp;

    memset(&sin,0,sizeof(sin));
    if (config.daemon.listenAddr.num) {
	addrs=config.daemon.listenAddr;
    } else {
	addrs=findListenInterfaces();
	if (!addrs.num) {
	    syslog(LOG_ERR,"Unable to find interfaces");
	    exit(2);
	}
    }

    daemonFd=malloc(sizeof(*daemonFd)*(addrs.num+1));
    if (!daemonFd) {
	syslog(LOG_ERR,"Out of memory in createListenSocket");
	fprintf(stderr,"Out of memory in createListenSocket");
	exit(2);
    }

    for (i=0; i<addrs.num; i++) {
	s=socket(AF_INET,SOCK_STREAM,0);
	if (s<0) {
	    syslog(LOG_ERR,"listen socket: %m");
	    exit(2);
	}
	if (s>=maxFd) {
	    syslog(LOG_ERR,"listen socket out of range");
	    exit(2);
	}
	sockopt=1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt))<0) {
	    perror("setsockopt(reuse)");
	    syslog(LOG_ERR,"Failed to setsockopt(reuseaddr): %m");
	    close(s);
	    continue;
	}
	sockopt=((config.daemon.flags&FL_NO_KEEPALIVE)==0);
	if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &sockopt, sizeof(sockopt))<0) {
	    perror("setsockopt(keepalive)");
	    syslog(LOG_ERR,"Failed to setsockopt(keepalive): %m");
	    close(s);
	    continue;
	}

	sin.sin_family = AF_INET;
	sin.sin_port   = config.daemon.port;
	sin.sin_addr.s_addr = addrs.list[i];
	if (bind(s,(struct sockaddr*)&sin,sizeof(sin))<0) {
	    perror("bind");
	    syslog(LOG_ERR,"Failed to bind to %s: %m",inet_ntoa(sin.sin_addr));
	    close(s);
	    continue;
	}

	if (listen(s,200)<0) {
	    perror("listen");
	    syslog(LOG_ERR,"Failed to listen on %s: %m",inet_ntoa(sin.sin_addr));
	    close(s);
	    continue;
	} 
	setNonBlocking(s);

	daemonFd[numBound]=s;
	info=fdInfo+s;
	memset(info,0,sizeof(*info));
	info->peer=NULL;
	info->fd=s;
	info->flags=FD_IS_LISTEN;
	info->TCP_RECV=listenRecv;
	setSelect(s,SL_READ|SL_EXCP);
	syslog(LOG_NOTICE,"listening on [%s].%d",inet_ntoa(sin.sin_addr),ntohs(config.daemon.port));
	numBound++;
    }
    daemonFd[numBound]=-1;

    if (!numBound) {
	syslog(LOG_ERR,"Failed to bind any listen sockets");
	exit(2);
    }
    if (!config.daemon.listenAddr.num) {
	free(addrs.list);
    }
}
/*********************************************************************
 *
 * (Re)read the configuration file and parse it.  If all goes well,
 * replace the current config (if any) with then new config.  chdir()
 * to the specified directory, set the umask, and bump the file limit
 * if needed (never reduce it).
 *
 *********************************************************************/
void readConfig(int sig)
{
    register int	newMaxFd;
    register int	oldMaxFd=maxFd;
    register int	oldMaxClient=config.daemon.maxClient;
    register int	newMaxClient;

    freopen(configFile,"r",stdin);

    if (!yyparse()) {
	if (sig)
	    freeConfig(&config);
	config=newConfig;
	strncpy(syslogName,config.daemon.name,sizeof(syslogName));
	syslogName[sizeof(syslogName)-1]='\0';
	chdir(config.daemon.directory);
	umask(config.daemon.umask);

	newMaxClient=config.daemon.maxClient;
	newMaxFd=newMaxClient*2+20+config.daemon.listenAddr.num;
	if (newMaxFd>maxFd) {
	    register fdInfoType		*oldFdInfo=fdInfo, *info;
	    register connInfoType	*oldConnInfo=connInfo, *conn;
	    register int		i;
	    struct rlimit rp;
	    maxFd=newMaxFd;
	    getrlimit(RLIMIT_NOFILE,&rp);
	    if (maxFd>rp.rlim_max) {
		maxFd=rp.rlim_max;
		newMaxClient=config.daemon.maxClient=(maxFd-20-config.daemon.listenAddr.num)/2;
		if (!sig) {
		    fprintf(stderr,"Too many clients - limited to %d\n",newMaxClient);
		} else {
		    syslog(LOG_ERR,"Too many clients - limited to %d",newMaxClient);
		}
	    }
	    rp.rlim_cur=maxFd;
	    setrlimit(RLIMIT_NOFILE,&rp);

	    if (fdInfo) {
		fdInfo=(fdInfoType*)realloc(fdInfo,maxFd*sizeof(fdInfoType));
		if (fdInfo)
		    memset(fdInfo+oldMaxFd,0,(maxFd-oldMaxFd)*sizeof(fdInfoType));
	    } else {
		fdInfo=(fdInfoType*)calloc(maxFd,sizeof(fdInfoType));
	    }

	    if (fdInfo) {
		for (i=maxFd,info=fdInfo+oldMaxFd;i>oldMaxFd;info++,i--) {
		    info->fd=-1;
		    info->TCP_RECV=(recvFunc*)recv, info->TCP_SEND=(sendFunc*)send, info->excp=nullExcp;
		}
	    } else {
		if (!sig) {
		    fprintf(stderr,"Could not allocate fdInfo memory - dying\n");
		} else {
		    syslog(LOG_ALERT,"Could not allocate fdInfo memory - dying");
		}
		exit(2);
	    }

	    if (connInfo) {
		connInfo=(connInfoType*)realloc(connInfo,newMaxClient*sizeof(connInfoType));
		if (connInfo)
		    memset(connInfo+oldMaxClient,0,(newMaxClient-oldMaxClient)*sizeof(connInfoType));
	    } else {
		connInfo=(connInfoType*)calloc(newMaxClient,sizeof(connInfoType));
	    }

	    if (!connInfo) {
		if (!sig) {
		    fprintf(stderr,"Could not allocate connInfo memory - dying\n");
		} else {
		    syslog(LOG_ALERT,"Could not allocate connInfo memory - dying");
		}
		exit(2);
	    }
#define adjustPtr(ptr,oldBase,newBase,typ) do {			\
    (ptr) = (typ)((long)(ptr)+(long)(newBase)-(long)(oldBase));	\
} while (0)

	    for (i=0,info=fdInfo; i<oldMaxFd; i++,info++) {
		if (info->conn)
		    adjustPtr(info->conn,oldConnInfo,connInfo,connInfoType *);
		if (info->peer)
		    adjustPtr(info->peer,oldFdInfo,fdInfo,fdInfoType *);
	    }
	    /* just rebuild the freeConn list, while fixing pointers in the
	     * ones that are in use.
	     */
	    freeConn=NULL;
	    for (i=newMaxClient-1,conn=connInfo+i;i>=0;i--,conn--) {
		if (conn->flags&CO_IN_USE) {
		    adjustPtr(conn->client,oldFdInfo,fdInfo,fdInfoType*);
		    if (conn->udp)
			adjustPtr(conn->udp,oldFdInfo,fdInfo,fdInfoType*);
		} else {
		    conn->client=(fdInfoType*)freeConn;
		    freeConn=conn;
		}

	    }
	    connSanity(9);
#undef adjustPtr
	}
	v4Method=findMethod(&config,"v4");
	if (sig)
	    syslog(LOG_NOTICE,"Configuration file read");
    } else {
	if (sig) {
	    syslog(LOG_ERR,"configuration file %s failed to parse\n",configFile);
	    freeConfig(&newConfig);
	} else {
	    fprintf(stderr,"configuration file %s failed to parse.  See syslog output.\n",configFile);
	    exit(1);
	}
    }
}
