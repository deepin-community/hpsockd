/* @(#)$Header: /var/cvs/hpsockd/src/sockd/sockd.h,v 0.67 2002/03/28 19:04:26 lamont Exp $ */
#ifndef SOCKD_H_INCLUDED
#define SOCKD_H_INCLUDED

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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <db_185.h>
#include <time.h>
#include <syslog.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#ifndef SIGEMT
#define SIGEMT SIGFPE
#endif
#include <errno.h>
#include "paths.h"
#include "inet_ntoa.h"

#ifdef HAVE_MMAP
#include <sys/mman.h>
#ifndef MAP_FILE
#define MAP_FILE 0
#endif
#endif

#ifndef SUPPORT_IP6
#undef AF_INET6
#endif

#ifdef MSEM_UNLOCKED
#define HAVE_MSEM
#else
#include <sys/sem.h>
#endif

#ifdef __hpux
#define setuid(x) setresuid((x),(x),(x))
#define setgid(x) setresgid((x),(x),(x))
#endif

#ifdef USE_SIGNALS
#define SIGWAKEUP	SIGWINCH
#endif

typedef struct dataBuf dataBufType;
typedef struct fdInfo fdInfoType;
typedef struct connInfo connInfoType;
typedef struct sockdLog sockdLogType;
typedef volatile struct negotPage negotPageType;
typedef volatile struct negotInfo negotInfoType;
typedef volatile struct negotHead negotHeadType;
typedef struct timeOutHead timeOutHeadType;
typedef struct daemonInfo daemonInfoType;
typedef struct logInfo logInfoType;
typedef struct defaultInfo defaultInfoType ;
typedef struct configInfo configInfoType;
typedef struct clientInfo clientInfoType;
typedef enum relop { r_eq, r_ne, r_lt, r_le, r_gt, r_ge } relopType;
typedef struct host hostType;
typedef struct routeInfo routeInfoType;
typedef struct port portType;
typedef struct methodInfo methodInfoType;
typedef struct clientMethodInfo clientMethodInfoType;
typedef struct intMethInfo intMethInfoType;


typedef void (inboundFunc)(fdInfoType *info,void *buf,int len,unsigned int flags);
typedef int (outputFunc)(fdInfoType *info,void *buf,int len,unsigned int flags);
typedef ssize_t	(recvFunc)(int fd, void *buf,size_t count,unsigned int flg);
typedef ssize_t	(sendFunc)(int fd, const void *buf,size_t count,unsigned int flg);

typedef void (inboundUdpFunc)(fdInfoType *info,void *buf,int len,unsigned int flags,const void *from, int fromLen);
typedef void (outputUdpFunc)(fdInfoType *info,void *buf,int len,unsigned int flags,const void *to, int toLen);
typedef ssize_t	(recvFromFunc)(int fd, void *buf,size_t count,unsigned int flg,void *from, int *fromLen);
typedef ssize_t	(sendToFunc)(int fd, const void *buf,size_t count,unsigned int flg,const void *to, int toLen);

typedef void (excpFunc)(fdInfoType *info);
typedef int (infoFunc)(methodInfoType* info,int version);


#define listType(stru,typdef,type) typedef struct stru { int num; type *list; } typdef;

listType(longList,longLType,long)
listType(hostList,hostLType,hostType)
listType(portList,portLType,portType)
listType(strList, strLType,char *)
listType(clInList,clInLType,clientInfoType)
listType(rtInList,rtInLType,routeInfoType)
listType(cmInList,cmInLType,clientMethodInfoType)
listType(mInfList,mInfLType,methodInfoType)
listType(mInPList,mInPLType,methodInfoType *)

#define ofs(tp,field) (int)(&(((tp*)0)->field))

#define bumpHighLow(fd) do {						\
	if (fd>highFd) highFd=fd; if (fd<lowFd) lowFd=fd;		\
} while (0)

#define setNonBlocking(fd) do { \
	register int __flags=fcntl((fd),F_GETFL)|O_NDELAY;		\
	if (fcntl((fd),F_SETFL,__flags)) { perror("fcntl(F_SETFL)"); }	\
} while (0)

#define updateTime(who,which,len,when) do {				\
    if ((len)>0) (who)->which.totalBytes += (len);			\
    if ((who)->conn && (who)->conn->expire)				\
	(who)->conn->expire = (when)+(who)->conn->timeOut;		\
} while (0)

#define milliSleep(mSec) do {						\
    int i=(mSec);							\
    struct timeval tv; tv.tv_sec=i/1000; tv.tv_usec=(i%1000)*1000;		\
    select(0,NULL,NULL,NULL,&tv);					\
} while (0)

struct dataBuf {
    char	*bufStart,	/* first byte of buffer */
		*dataStart;	/* first valid data byte */
    int		dataLen,	/* number of valid data bytes */
		bufSize;	/* size of buffer */
    long	totalBytes;	/* total bytes (encapsulated) through */
};

struct connInfo {
    fdInfoType		*client;	/* TCP connection controlling a UDP port, if any, */
					/* When on free list, this is the ptr to next */
    fdInfoType		*udp;		/* UDP half of UDP associate connections */
    struct v5Head	*req;		/* v5 formated request, freed at close */
    char		*user;		/* authenticated user name, freed at close */
    time_t		startTime;	/* startup time for this socket */
    pid_t		pid;		/* pid to kill (if any) */
    int			timeOut;	/* inactivity timeout, in seconds */
    time_t		expire;		/* When do we expire? */
    int			bufSize;	/* based on client rule, from validation */
    int			logId;		/* set by logStartup */
    methodInfoType	*method;	/* Used to log method number in startup */
    int			flags;
#define CO_CLOSE_PENDING	0x00000001
#define CO_IN_USE		0x00000002
#define CO_SANITY_HIT		0x00010000
    int			ruleFlags;	/* flags from rule, method specific */
    int			error;
};

struct fdInfo {
    fdInfoType		*peer;		/* Who are we talking to? */
    connInfoType	*conn;		/* Connection global information */
    volatile int	fd;		/* our socket */
    int			flags;
#define FD_IS_LISTEN	0x00000001	/* This is the listen socket	*/
#define FD_IS_UDP	0x00000002	/* UDP (not TCP) socket		*/
#define FD_SHUTDOWN	0x00000004	/* flushing wrt data for close	*/
#define FD_IS_CLIENT	0x00000008	/* This is the client half of the link */
#define FD_IS_SPECIAL	0x00000010	/* it's wierd.. */
#define FD_SANITY_HIT	0x00010000	/* used in sanity check. */

    struct sockaddr_in	sin;		/* who is on the other end of this socket */
    union {
	struct { 
	    inboundFunc		*inbound;
	/* inbound() is handed a buffer of unprocessed input data from recv(),
	 * which it must completely consume, possibly into in.
	 */
	    outputFunc		*output;
	/* output() is handed a buffer of unencapsulated data to be packed
	 * and sent, which it must completely consume, possibly into out.
	 * If data is queued in out (only because of a partial write to the
	 * socket, then the write select flag must be set by output().  The
	 * outer loop will then do the write() calls itself.
	 */
	    recvFunc		*recv;
	    sendFunc		*send;
	} fdiTcp;
	struct {
	    inboundUdpFunc	*inboundUdp;
	/* inbound() is handed a buffer of unprocessed input data from recv(),
	 * which it must completely consume, possibly into in.
	 */
	    outputUdpFunc	*outputUdp;
	/* output() is handed a buffer of unencapsulated data to be packed
	 * and sent, which it must completely consume, possibly into out.
	 * If data is queued in out (only because of a partial write to the
	 * socket, then the write select flag must be set by output().  The
	 * outer loop will then do the write() calls itself.
	 */
	    recvFromFunc	*recvFrom;
	    sendToFunc		*sendTo;
	} fdiUdp;
    } uFuncs;
    excpFunc		*excp;
    dataBufType		in;		/* unprocessed inbound data */
    dataBufType		out;		/* unsent, processed outbound data */
};
#define TCP_INBOUND	uFuncs.fdiTcp.inbound
#define TCP_OUTPUT	uFuncs.fdiTcp.output
#define TCP_RECV	uFuncs.fdiTcp.recv
#define TCP_SEND	uFuncs.fdiTcp.send
#define UDP_INBOUND	uFuncs.fdiUdp.inboundUdp
#define UDP_OUTPUT	uFuncs.fdiUdp.outputUdp
#define UDP_RECVFROM	uFuncs.fdiUdp.recvFrom
#define UDP_SENDTO	uFuncs.fdiUdp.sendTo

struct negotInfo {
    pid_t	pid;
    int		numConn;
    int		flags;
#define NF_LOSER	1	/* can never be the listener - not set in negot page.*/
    time_t	lastChecked;
};

#define NEGOT_SIZE	4096
#define LI_BITSPERINT	(sizeof(int)*8)
#define LI_SET(slot,listn) (listn[(slot)/LI_BITSPERINT]|=(1<<(slot%LI_BITSPERINT)))
#define LI_CLR(slot,listn) (listn[(slot)/LI_BITSPERINT]&=~(1<<(slot%LI_BITSPERINT)))
#define LI_ISSET(slot,listn) (listn[(slot)/LI_BITSPERINT]&(1<<(slot%LI_BITSPERINT)))

struct negotHead {
#ifdef HAVE_MSEM
    msemaphore	sema;
#else
    int		semId;
#endif
    pid_t	processGroup;
    int		numListen;		/* how many listening */
    int		listeners[(NEGOT_SIZE+sizeof(negotInfoType)-1)/sizeof(negotInfoType)/LI_BITSPERINT];
};

#define NEGOT_MAXSLOT ((NEGOT_SIZE-sizeof(negotHeadType))/sizeof(negotInfoType))
struct negotPage {
    negotHeadType	head;
    negotInfoType	slot[NEGOT_MAXSLOT];
};

struct timeOutHead {
    fdInfoType	*first,*last;
};

struct daemonInfo {
    int		minListen,maxListen;
    int		minClient,maxClient;
    int		preFork;
    int		numHelper;
    uid_t	uid;
    gid_t	gid;
    longLType	listenAddr;
    char	*service;	/* name of service */
    int		port;		/* network byte order */
    int		umask;
    char	*directory;	/* chdir here before working */
    char	*name;		/* name for syslog */
    char	*negotFile;
    char	*inetdSecFile;
    int		poll;
    int		flags;
    int		milliPerClient; /* Average distance in time between accepts */
};

#define FL_NO_KEEPALIVE	0x0001	/* Don't do keepalives */
#define FL_V4_ONLY	0x8000

struct logInfo {
    int		level;		/* how verbose are we */
    int		facility;
    char	*logFile;	/* name of log file */
    char	*dumpPrefix;
};

struct defaultInfo {
    int		bufSize;
    int		timeOut;
    int		setupTimeOut;
};

struct host {
    relopType	op;
    long	value,mask;	/* value&mask == addr&mask --> hit */
};

struct routeInfo {
    hostType	host;
    long	ip;
};

struct port {
    u_short	low,high;	/* low<=port<=high --> hit */
};


#define METHOD_VERSION	0
struct methodInfo {
    char		*name;
    u_char		num;
    char		*libName;
    infoFunc		*info;
    strLType		env;		/* method specific environment variables */ 
    int			flags;		/* user specified flags for method.  These are left completely to the method. */

			/* The following are filled in by the info routine (if version==METHOD_VERSION).
			 * Initially, info->inbound=negotiate, and info->output=simpleOutput.  Once method negotiation
			 * is complete, the inbound and output functions must be changed to point to the encapsulation
			 * versions of the routines.  If you have no method specific negotiation, just set negotiate
			 * to the inbound function.
			 *
			 * Likewise, the UdpAssoc routine will change things to point to the UDP versions if that's
			 * where we go.
			 */
    inboundFunc		*negotiate;
    inboundUdpFunc	*inboundUdp;
    outputUdpFunc	*outputUdp;
    recvFromFunc	*recvFrom;
    sendToFunc		*sendTo;

#ifdef FULLMETHOD
    /* These are currently unused, since the method negotiation is responsible for changing them. */
    inboundFunc		*inbound;
    outputFunc		*output;
    recvFunc		*recv;		/* defaults to recv() */
    sendFunc		*send;		/* defaults to send() */
    excpFunc		*excp;		/* defaults to nullExcp() */
#endif
};

struct intMethInfo {
    char	*name;
    infoFunc	*info;
};

struct clientMethodInfo {
    hostLType		src;		/* for these sources */
    mInPLType		methods;
};

#define ACTION_PERMIT		1
#define ACTION_PERMIT_OK	2
#define ACTION_DENY		3
#define ACTION_SKIP		4	/* skip the next rule */

struct clientInfo {
    int		action;
    int		request;	/* one of SOCKS5_CONNECT and friends */
    strLType	users;
    hostLType	src,dest;
    portLType	port;
    char	*cmd;
    int		timeOut;
    int		bufSize;
    int		flags;
};

struct configInfo {
    daemonInfoType		daemon;
    logInfoType			log;
    defaultInfoType		defaults;
    rtInLType			routes;
    clInLType			clients;
    mInfLType			methods;
    cmInLType			cliMeth;
    strLType			env;		/* global environment */
};

#include "logging.h"
/* dns.c */
extern fdInfoType *dnsInfo;
void dnsGlobalInit(void);
void dnsServerInit(void);
inboundUdpFunc dnsInboundUdp;
struct hostent *dnsQuery(char *name, fdInfoType *client);
void dnsDestroy(void);

/* gram.y */
void defaultConfig(void);
extern configInfoType newConfig, config;
void freeConfig(configInfoType *cfg);
int strToFacility(char *name);
char *facilityToStr(int facil);
methodInfoType *findMethod(configInfoType *cfg,char *name);

/* internal.c */
extern intMethInfoType intMethods[];
int loadMethInfo(methodInfoType *mInfo);

/* lexer.l */
char *timeToStr(int time);
char *expandString(const char *us);

/* listen.c */
extern int listenTries;
extern struct timeval lastAccept;
extern int avgClientTime;
extern float avgClientWeight;
recvFunc listenRecv;
inboundFunc newClient;
void tryListen(int lock);
void unListen(int forever);
void checkPidLock(int nSlot);

/* logging.c */
void logStartup(fdInfoType *info);
void logClose(fdInfoType *info, u_int32_t reason);
logRecType *makeLogRec(fdInfoType *info, u_int32_t reason);

/* methods.c */
int loadMethInfo(methodInfoType *mInfo);
methodInfoType *findMatchingMethod(struct sockaddr_in *sin,u_char *methData);

/* signal.c */
void doSignals(void);
#ifdef __hpux
void markSignal(int sig, int code, struct sigcontext *scp);
#else
void markSignal(int sig);
#endif
extern volatile int		pendingSig;

/* sockd.c */
extern configInfoType		config;
extern pid_t			processGroup;
extern fdInfoType		*fdInfo;
extern connInfoType		*freeConn;
extern connInfoType		*connInfo;
extern int			maxConn;
extern int			maxFd;
extern volatile int		highFd,lowFd;
extern int			*daemonFd;
extern negotPageType		*negot;	/* negotiation page */
extern volatile int		negotSlot;
extern negotInfoType		*negotInfo;
extern int			debug;
extern volatile int		pendingTerm;	/* term signal is pending */
extern time_t			now;		/* time at select loop start. */
#define DBG_FOREGROUND		1
#define DBG_MAINLOOP		2
#define DBG_CLOSE		0x10
#define DBG_CHILD		0x40
#define DBG_DNS			0x80
#define DBG_TRAIL		0x100
#define DBG_UNLISTEN		0x200
#define DBG_VALIDATE		0x400
#define DBG_SANITY		0x800
extern int			logFd;
void nullExcp(fdInfoType *info);
void dumpConfig(int sig);
void terminate(int sig);
void readConfig(int sig);
void setupSignals(int daemon);

/* util.c */
void freeSomeMemory(dataBufType *buf);
extern negotInfoType loserInfo;	/* negotInfo structure for non-listeners */
void bufFree(dataBufType *inf);
void addToBuffer(fdInfoType *info,dataBufType *inf,void *buf,int len);
int getFromBuffer(void *buf,dataBufType *inf,int len,int peek);
void setupTimeouts(connInfoType *conn,int timeout);
void setSocketBuffer(int fd, int bufSize);
void pendingClose(fdInfoType *info,int why);
void connSanity(int call);
void closeConnection(fdInfoType *info,int why,int closeNow);
int createSocket(int af, int type, int protocol);
void setSelect(int fd,int which);
void clrSelect(int fd,int which);
#define SL_READ 1
#define SL_WRITE 2
#define SL_EXCP 4
#define SL_ALL (SL_READ|SL_WRITE|SL_EXCP)
void setupDaemon(int numConn);
void forgetInfo(fdInfoType *info);
int spawnChild(connInfoType *conn);
void destroyDaemon(void);
void negotLock(void);
void negotUnlock(void);
int compareAddr(hostType *host, u_int32_t IP);
u_int32_t findRoute(u_int32_t destIP);
void addTimeOut(fdInfoType *info);
void reQueueTimeOut(fdInfoType *info);
const char *getEnv(const fdInfoType *info,const char *name);
u_int32_t inetAddr(const char *s);
void footprint(u_short a, u_short b, int c, int d);
void dumpFootprint(int where);
void setCommandLine(char *s);

/* v4.c */
inboundFunc newV4Client;
infoFunc v4Info;
extern methodInfoType *v4Method;	/* for v4 emulation */

/* v5.c */
inboundFunc newV5Client;
infoFunc noAuthInfo;
outputFunc v5Request;
void v5WriteReply(fdInfoType *client, struct sockaddr_in *sin, int result, int flags);

/* v5command.c */
void doCommand(const char *cmd,fdInfoType *info);	/* fork and execute a command */
void doCommand2(const char *cmd,fdInfoType *client);
int v5DoCommand(fdInfoType *client,const char *name);

/* v5tcp.c */
inboundFunc simpleInbound;
outputFunc simpleOutput;
sendFunc v5ConnectSendReply;
recvFunc v5BindRecv;
int v5DoConnect(fdInfoType *client);
int v5DoBind(fdInfoType *client);

/* v5udp.c */
inboundUdpFunc simpleInboundUdp;
outputUdpFunc simpleOutputUdp;
int v5DoUdpAssociate(fdInfoType *client);
inboundUdpFunc v5InboundUdpReq;		/* UDP request from client */
outputUdpFunc v5OutputUdpReply;		/* UDP reply to client */

/* userpass.c */
infoFunc userPassInfo;

#endif /* SOCKD_H_INCLUDED */
