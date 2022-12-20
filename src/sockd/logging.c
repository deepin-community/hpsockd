#include "sockd.h"
#include "v5.h"

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/logging.c,v 0.26 2001/03/02 01:34:54 lamont Exp $";
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


static u_short nextId=1;
static pid_t	myPid;

#define ADDRLEN(a) (*(a)==ATYP_V4 ? 5 : *(a)==ATYP_V6 ? 17 : 2+*(a+1))

int	logFd=-1;
time_t lastLogOpen=0;

/* ARGSUSED */
void newLog(int sig)
{
    myPid=getpid();
    if (!config.log.level)
	return;

    if (logFd>=0) {
	close(logFd);
    }
    logFd=open(config.log.logFile,O_WRONLY|O_APPEND);
    if (logFd<0) {
	logFd=open(config.log.logFile,O_WRONLY|O_APPEND|O_CREAT|O_EXCL,0644);
	close(logFd);
	logFd=open(config.log.logFile,O_WRONLY|O_APPEND);
    }
    if (logFd<0) {
	syslog(LOG_ERR,"Unable to open log file %s: %m.  Turning off logging.",config.log.logFile);
	config.log.level=0;
	return;
    }
    lastLogOpen=time((time_t*)NULL);
}
void logStartup(fdInfoType *info)
{
    register connInfoType *conn=info->conn;

    if (config.log.level < LG_STATS)
	return;

    if (!conn->startTime)
	conn->startTime=now;
    if (!conn->logId)
	conn->logId=htonl(((myPid<<16)|((nextId++)&0xffff)));
    return;
}

logRecType *makeLogRec(fdInfoType *info, u_int32_t reason)
{
    register int i;
    register connInfoType *conn=info->conn;
    register fdInfoType *udp=conn->udp;
    register int id=conn->logId;
    static logRecType rec;
    register char *p=(char*)rec.chars;
    v5HeadType *req=conn->req;
    register struct sockaddr_in *srcSin=&info->sin, *destSin=&info->peer->sin;
    u_int32_t tmp;

    if (req==NULL && conn->error != LOG_NOMETHOD) {
	syslog(LOG_CRIT,"makeLogRec got null request pointer.  Info=%08x flags=%08x pid=%d",info,info->flags,conn->pid);	/* XXX */
	return NULL;
    }
    rec.head.type=LG_TYPE_CLIENT+req->cmd;
    rec.head.time=htonl(now);
    rec.head.id=htonl(id);

    tmp=htonl(now-conn->startTime); memcpy(p,&tmp,sizeof(tmp)); p+=sizeof(tmp);

    switch(srcSin->sin_family) {
	case AF_INET:	*p=ATYP_V4; memcpy(p+1,&srcSin->sin_addr,4); p+=5; break;
#ifdef AF_INET6
	case AF_INET6:	*p=ATYP_V6; memcpy(p+1,&srcSin->sin_addr,16); p+=17; break;
#endif
	default:
	    syslog(LOG_WARNING,"got source address family %d in makeLogRec",srcSin->sin_family);
	    return NULL;	/* Beats me what it is... */
    }

    if (conn->user) {
	i=strlen(conn->user)&0xff; *p++=i; memcpy(p,conn->user,i); p+=i;	/* name limited to 255 octets */
    } else {
	*p++=0;
    }

    switch(destSin->sin_family) {
	register u_char *c;
	default:
	    c=(u_char*)&destSin->sin_addr;
	    if (destSin->sin_family || destSin->sin_port || c[0] || c[1] || c[2] || c[3]) {
		syslog(LOG_WARNING,"got destination address family %d in makeLogRec",destSin->sin_family);
		/* Beats me what it is, lets pretend it's v4... */
	    }
	    /* fall through */
	case AF_INET:	*p=ATYP_V4; memcpy(p+1,&destSin->sin_addr,4); p+=5; break;
#ifdef AF_INET6
	case AF_INET6:	*p=ATYP_V6; memcpy(p+1,&destSin->sin_addr,16); p+=17; break;
#endif
    }
    memcpy(p,&destSin->sin_port,sizeof(u_short)); p+=sizeof(u_short);

    *p++=conn->method->num;
    tmp=htonl(info->out.totalBytes + (udp ? udp->out.totalBytes : 0));
	memcpy(p,&tmp,sizeof(tmp)), p+=sizeof(tmp);
    tmp=htonl(info->peer->out.totalBytes + (udp ? udp->peer->out.totalBytes : 0));
	memcpy(p,&tmp,sizeof(tmp)), p+=sizeof(tmp);
    tmp=htonl(reason); memcpy(p,&tmp,sizeof(tmp)), p+=sizeof(tmp);
    tmp=p-(char*)&rec;
    rec.head.size=htons(tmp);

    return &rec;
}
void logClose(fdInfoType *info, u_int32_t reason)
{
    register logRecType *rec;
    register int i,ret;
    register connInfoType *conn=info->conn;

    now=time((time_t*)NULL);

    if (conn==NULL) {
	syslog(LOG_ERR,"Null connection pointer in logClose");
#ifdef __hpux
	dumpMap(0);
#endif
	return;
    }

    if (config.log.level < LG_STATS || !conn->logId)
	return;

    /* Horrible kludge to allow the log file to move out from under us without needing a signal.
     * This is because only the current process group gets signaled by sdc.  With this kludge,
     * we'll start writing to the new log file withine 60 seconds of it getting created...
     */
    if (lastLogOpen+60 < now) {
	i=open(config.log.logFile,O_WRONLY|O_APPEND);
	if (i>=0) {
	    ret=dup2(i,logFd);
	    if (ret>=0) {
		(void)close(i);
	    } else {
		(void)close(logFd);
		logFd=i;
	    }
	}
	lastLogOpen=now;
    }

    rec=makeLogRec(info,reason);

    conn->logId=0;

    ret=write(logFd,rec,ntohs(rec->head.size));
    if (ret<0) {
	syslog(LOG_ERR,"Error on logfile write: %m");
    } else if (ret != ntohs(rec->head.size)) {
	syslog(LOG_ERR,"Out of disk space on log file write");
    }
}
