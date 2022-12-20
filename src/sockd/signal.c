#include "sockd.h"

#ifdef __hpux
#include <sys/syscall.h>
#endif

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/signal.c,v 0.32 2002/01/10 04:37:20 lamont Exp $";
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


sigset_t	pendingSignals;
volatile int	pendingSig=0;
volatile int	pendingTerm;

static char *makeMask(register long mask)
{
    static char	buf[20];
    register	int i;

    if ((((mask&mask-1)^mask)-1|mask) == 0xffffffff) {
	for (i=0;mask;mask&=mask-1,i++ );
	sprintf(buf,"%d",i);
	return buf;
    } else {
	return inetNtoa(mask);
    }
}
static char *relopToStr(relopType op)
{
    switch(op) {
	case r_eq:	return "";
	case r_ne:	return "!";
	case r_lt:	return "<";
	case r_le:	return "<=";
	case r_gt:	return ">";
	case r_ge:	return ">=";
	default:	return "bad_op";
    }
}
static char *hostToStr(hostType *host)
{
    static char result[sizeof("255.255.255.255")*2+8];

    if (host->mask==-1) {
	snprintf(result,sizeof(result),"%s%s",relopToStr(host->op),inetNtoa(host->value));
    } else if (host->mask) {
	snprintf(result,sizeof(result),"%s%s/%s",relopToStr(host->op),inetNtor(host->value), makeMask(host->mask));
    } else {
	snprintf(result,sizeof(result),"default");
    }
    return result;
}
/*********************************************************************
 *
 * Dump information on every client we have (request and totals to
 * date).  This is the result of a signal.
 *
 *********************************************************************/
/* ARGSUSED */
void dumpClients(int sig)
{
    register int fd;
    register char *base=config.log.dumpPrefix;
    register char *name;
    register int i;
    register fdInfoType *info;

    now=time((time_t*)NULL);	/* used in makeLogRec, make it current */

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
	syslog(LOG_ERR,"Out of memory in dumpClients");
	return;
    }
    sprintf(name,"%s.client.%d",base,negotInfo->pid);

    unlink(name);
    fd=open(name,O_WRONLY|O_CREAT|O_EXCL,0600);
    if (fd<0) {
	syslog(LOG_ERR,"Couldn't open %s for write",name);
	free(name);
	return;
    }

    for (i=lowFd,info=fdInfo+lowFd; i<=highFd; i++,info++) {
	if ((info->flags&FD_IS_CLIENT) && !(info->flags&FD_IS_UDP) && info->fd>=0) {
	    register int ret;
	    register logRecType *rec;
	    rec=makeLogRec(info,0);
	    if (rec) do {
		ret=write(fd,rec,ntohs(rec->head.size));
	    } while (ret<0 && errno==EINTR);
	}
    }
    close(fd);
    free(name);
    if (debug&DBG_SANITY)
	dumpFootprint(-1);
}
/******************************************************************
 *
 * dumpConfig() writes out the config file in a format that is
 * parseable, should the user decide to use that file next time.
 * Accordingly, it's rather long...
 *
 ******************************************************************/
/* ARGSUSED */
void dumpConfig(int sig)
{
    register int fd;
    register FILE *f;
    register char *base=config.log.dumpPrefix;
    register char *name;
    time_t	curTime;
    register int i;

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
	syslog(LOG_ERR,"Out of memory in dumpConfig()");
	return;
    }
    sprintf(name,"%s.conf.%d",base,negotInfo->pid);

    unlink(name);
    fd=open(name,O_WRONLY|O_CREAT|O_EXCL,0600);
    if (fd<0) {
	syslog(LOG_ERR,"Couldn't open %s for write",name);
	free(name);
	return;
    }
    free(name);

    f=fdopen(fd,"w");
    curTime=time((time_t*)NULL);
    fprintf(f,"# dumped on %s\n\n",ctime(&curTime));
    fprintf(f,"daemon {\n");
    fprintf(f,"\tname\t\t\"%s\";\n",config.daemon.name);
    fprintf(f,"\tdirectory\t\"%s\";\n",config.daemon.directory);
    fprintf(f,"\tumask\t\t0o%03o;\n",config.daemon.umask);
    if (config.daemon.listenAddr.num) {
	register int j;
	fprintf(f,"\tlisten-address\t{ ");
	for (j=0;j<config.daemon.listenAddr.num;j++) {
	    fprintf(f,"%s; ",inetNtoa(config.daemon.listenAddr.list[j]));
	}
	fprintf(f,"};\n");
    }
    fprintf(f,"\tnegotiate-file\t\"%s\";\n",config.daemon.negotFile);
    if (config.daemon.inetdSecFile) {
	fprintf(f,"\tinetdsec-file\t\"%s\";\n",config.daemon.inetdSecFile);
    } else {
	fprintf(f,"\tinetdsec-file\tnone;\n");
    }
    fprintf(f,"\tlisten\t\t{%d,%d};\n",config.daemon.minListen,config.daemon.maxListen);
    fprintf(f,"\tclient\t\t{%d,%d};\n",config.daemon.minClient,config.daemon.maxClient);
    fprintf(f,"\tpre-fork\t%d;\n",config.daemon.preFork);
    fprintf(f,"\tservice\t\t\"%s\";\n",config.daemon.service);
    fprintf(f,"\tport\t\t%d;\n",ntohs(config.daemon.port));
    fprintf(f,"\tpoll\t\t%s;\n",timeToStr(config.daemon.poll));
    fprintf(f,"\tuser\t\t%d;\n",config.daemon.uid);
    fprintf(f,"\tgroup\t\t%d;\n",config.daemon.gid);
    fprintf(f,"\tdns-helper\t%d;\n",config.daemon.numHelper);
    if (config.daemon.milliPerClient) {
	fprintf(f,"\tclients-per-min\t%d;\t# milli-per-client %d avg %d\n",
		60000/config.daemon.milliPerClient,
		config.daemon.milliPerClient, avgClientTime);
    } else {
	fprintf(f,"\t#clients-per-min\t>60000 # milli-per-client 0 avg %d\n",
		avgClientTime);
    }
    if (config.daemon.flags) {
	fprintf(f,"\tflags\t\t{ ");
	if (config.daemon.flags&FL_V4_ONLY)
	    fprintf(f,"v4-only; ");
	fprintf(f,"};\n");
    }
    fprintf(f,"};\n\n");
    
    if (config.env.num) {
	fprintf(f,"env {\n");
	for (i=0;i<config.env.num; i++) {
	    register char *c=config.env.list[i];
	    fprintf(f,"\t");
	    do { putc(*c,f); } while (*c++!='=');
	    c=expandString(c);
	    fprintf(f,"\"%s\";\n",c);
	    free(c);
	}
	fprintf(f,"};\n\n");
    }

    fprintf(f,"logging {\n");
    fprintf(f,"\tfacility\t\"%s\";\n",facilityToStr(config.log.facility));
    fprintf(f,"\tlevel\t\t%d;\n",config.log.level);
    if (config.log.dumpPrefix)
	fprintf(f,"\tdump-prefix\t\"%s\";\n",config.log.dumpPrefix);
    else
	fprintf(f,"\tdump-prefix\tnone;\n");
    if (config.log.logFile)
	fprintf(f,"\tusage-log\t\"%s\";\n",config.log.logFile);
    else
	fprintf(f,"\tusage-log\tnone;\n");
    fprintf(f,"};\n\n");

    fprintf(f,"default {\n");
    fprintf(f,"\ttimeout\t\t%s;\n",timeToStr(config.defaults.timeOut));
    fprintf(f,"\tsetup-timeout\t%s;\n",timeToStr(config.defaults.setupTimeOut));
    fprintf(f,"\tbufsize\t\t%d;\n};\n\n",config.defaults.bufSize);

    fprintf(f,"route {\n");
    for (i=0;i<config.routes.num;i++) {
	fprintf(f,"\t{ %s %s };\n",hostToStr(&config.routes.list[i].host),inetNtoa(config.routes.list[i].ip));
    }
    fprintf(f,"};\n\n");

    fprintf(f,"method-list {\n");
    for (i=0;i<config.methods.num; i++) {
	fprintf(f,"\t{ number %3d; name \"%s\"; ",config.methods.list[i].num,config.methods.list[i].name);
	if (config.methods.list[i].libName)
	    fprintf(f,"library \"%s\";",config.methods.list[i].libName);
	else
	    fprintf(f,"internal;");
	if (config.methods.list[i].env.num) {
	    register int j;
	    fprintf(f,"\n\t\tenv {\n");
	    for (j=0;j<config.methods.list[i].env.num; j++) {
		register char *c=config.methods.list[i].env.list[j];
		fprintf(f,"\t\t");
		do { putc(*c,f); } while (*c++!='=');
		c=expandString(c);
		fprintf(f,"\"%s\";\n",c);
		free(c);
	    }
	    fprintf(f,"\t\t};");
	}
	fprintf(f," };\n");
    }
    fprintf(f,"};\n\n");

    fprintf(f,"client-method {\n");
    for (i=0;i<config.cliMeth.num; i++) {
	register int j;
	fprintf(f,"\t{ src { ");
	for (j=0;j<config.cliMeth.list[i].src.num;j++) {
	    fprintf(f,"%s; ",hostToStr(&config.cliMeth.list[i].src.list[j]));
	}
	fprintf(f,"};\n\t  method { ");
	for (j=0;j<config.cliMeth.list[i].methods.num;j++) {
	    fprintf(f,"\"%s\"; ",config.cliMeth.list[i].methods.list[j]->name);
	}
	fprintf(f,"};\n\t};\n");
    }
    fprintf(f,"};\n\n");

    fprintf(f,"client {\n");
    for (i=0;i<config.clients.num; i++) {
	register int j;
	register char *c,*d;
	char c2[sizeof("unknown-")+10],d2[sizeof(" unknown-")+10];
	switch(config.clients.list[i].action) {
	    case ACTION_PERMIT:		c="permit"; break;
	    case ACTION_PERMIT_OK:	c="permit!"; break;
	    case ACTION_DENY:		c="deny"; break;
	    case ACTION_SKIP:		c="skip"; break;
	    default:			c=c2; sprintf(c,"unknown-%d",config.clients.list[i].action); break;
	}
	switch(config.clients.list[i].request) {
	    case SOCKS5_ANYACTION:	d=""; break;
	    case SOCKS5_CONNECT:	d=" connect"; break;
	    case SOCKS5_BIND:		d=" bind"; break;
	    case SOCKS5_UDP_ASSOCIATE:	d=" udp-associate"; break;
	    case SOCKS5_PING:		d=" ping"; break;
	    case SOCKS5_TRACEROUTE:	d=" traceroute"; break;
	    default:			d=d2; sprintf(d," unknown-%d",config.clients.list[i].request); break;
	}
	fprintf(f,"\t%s%s {\n",c,d);
	if (config.clients.list[i].users.num) {
	    fprintf(f,"\t\tuser { ");
	    for (j=0;j<config.clients.list[i].users.num;j++) {
		fprintf(f,"\"%s\"; ",config.clients.list[i].users.list[j]);
	    }
	    fprintf(f,"};\n");
	}
	if (config.clients.list[i].src.num) {
	    fprintf(f,"\t\tsrc { ");
	    for (j=0;j<config.clients.list[i].src.num;j++) {
		fprintf(f,"%s; ",hostToStr(&config.clients.list[i].src.list[j]));
	    }
	    fprintf(f,"};\n");
	}
	if (config.clients.list[i].dest.num) {
	    fprintf(f,"\t\tdest { ");
	    for (j=0;j<config.clients.list[i].dest.num;j++) {
		fprintf(f,"%s; ",hostToStr(&config.clients.list[i].dest.list[j]));
	    }
	    fprintf(f,"};\n");
	}
	if (config.clients.list[i].port.num) {
	    fprintf(f,"\t\tport { ");
	    for (j=0;j<config.clients.list[i].port.num;j++) {
		if (config.clients.list[i].port.list[j].low==config.clients.list[i].port.list[j].high) {
		    fprintf(f,"%d; ",config.clients.list[i].port.list[j].low);
		} else {
		    fprintf(f,"%d-%d; ",config.clients.list[i].port.list[j].low,config.clients.list[i].port.list[j].high);
		}
	    }
	    fprintf(f,"};\n");
	}
	if (config.clients.list[i].cmd) {
	    register char *s=expandString(config.clients.list[i].cmd);
	    fprintf(f,"\t\tcmd \"%s\";\n",s);
	    free(s);
	}
	if (config.clients.list[i].timeOut)
	    fprintf(f,"\t\ttimeout %s;\n",timeToStr(config.clients.list[i].timeOut));
	if (config.clients.list[i].bufSize)
	    fprintf(f,"\t\tbufsize %d;\n",config.clients.list[i].bufSize);
	fprintf(f,"\t};\n");
    }
    fprintf(f,"};\n\n");

    fflush(f);
    fclose(f);
}
#ifdef __hpux
#pragma _HP_SECONDARY_DEF mymemorymap _memorymap
/* ARGSUSED */
void mymemorymap(int a)
{
    return;
}
/*********************************************************************
 *
 * Dump memory map information and generate a copy of core.
 * This is the result of a signal (SIGSYS).
 *
 *********************************************************************/
/* ARGSUSED */
void dumpMap(int sig)
{
    register int fd;
    time_t timeVal;
    register char *base=config.log.dumpPrefix;
    register char *name;
    register pid_t pid = negotInfo->pid;

    if (!base) {
	syslog(LOG_ERR,"No dump file.");
	return;
    }

    if (fork()) return;

    name=malloc(strlen(base)+30);
    if (name) {
	sprintf(name,"%s.memmap.%d",base,pid);
    } else {
	syslog(LOG_ERR,"Out of memory in dumpMap() - using %s for filename",base);
	name=base;
    }

    unlink(name);
    fd=open(name,O_WRONLY|O_CREAT|O_EXCL,0600);
    if (fd<0) {
	syslog(LOG_ERR,"Couldn't open %s for write",name);
	return;
    }

    fflush(stdout);
    dup2(fd,1);
    dup2(fd,2);
    time(&timeVal);
    printf("%s\n", ctime(&timeVal));
    _memorymap(1);
    printf("End of dump\n");
    U_STACK_TRACE();
    abort();
}
#endif

/*********************************************************************
 *
 * End it all.  Close every connection, and then destroy the daemon.
 * (clean everything up and exit.)
 *
 *********************************************************************/
void terminate(int sig)
{
    register int i;
    register fdInfoType *info;

    syslog(LOG_WARNING,"terminating on signal %d",sig);
    for (i=lowFd,info=fdInfo+lowFd; i<=highFd; i++,info++) {
	if (info->fd>=0 && (info->flags&FD_IS_CLIENT))
	    closeConnection(info,LOG_SIGNAL+sig,1);
    }
    destroyDaemon();
}
void dnsTerminate(int sig)
{
    syslog(LOG_WARNING,"dns helper terminating on signal %d",sig);
    exit(0);
}
/*********************************************************************
 *
 * Setup all signals for the deamon.  We catch just about everything
 * that we can, and ignore most of them.  The ones we do catch just
 * set a flag in pendingSignals, so that mainLoop() can schedule them
 * at a safe and reasonable time.
 *
 *********************************************************************/
typedef void (sigactFunc)(int);
void setupSignals(int daemon)
{
    register int ret,i;
    struct sigaction act;

    memset(&act,0,sizeof(act));
    sigfillset(&act.sa_mask);
    sigdelset(&act.sa_mask,SIGTRAP);

    act.sa_handler=SIG_IGN;

    /* first, just ignore everything */

    for (i=1;i<NSIG; i++) {
	switch (i) {
	    case SIGABRT:
	    case SIGSEGV:
	    case SIGBUS:
	    case SIGFPE:
	    case SIGTRAP:
	    case SIGTERM:
	    case SIGKILL:
	    case SIGSTOP:
#ifdef SIGRESERVE
	    case SIGRESERVE:
#endif
#ifdef SIGDIL
	    case SIGDIL:
#endif
		break;
	    default:
		ret=sigaction(i,&act,(struct sigaction*)NULL);
		if (ret<0 && errno != EINVAL)
		    syslog(LOG_ERR,"sigaction(%d) failed: %m",i);
		break;
	}
    }

    /* Helper is done here */
    if (!daemon) {
	act.sa_handler=dnsTerminate;
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGEMT,&act,(struct sigaction*)NULL)<0)
	    syslog(LOG_ERR,"sigaction(SIGEMT) failed: %m");
	return;
    }

    /* Daemon needs to catch these signals. */
    act.sa_handler=markSignal;
    act.sa_flags = SA_RESTART;
    if (sigaction(SIGHUP,&act,(struct sigaction*)NULL)<0)
	syslog(LOG_ERR,"sigaction(SIGHUP) failed: %m");
    if (sigaction(SIGINT,&act,(struct sigaction*)NULL)<0)
	syslog(LOG_ERR,"sigaction(SIGINT) failed: %m");
    if (sigaction(SIGEMT,&act,(struct sigaction*)NULL)<0)
	syslog(LOG_ERR,"sigaction(SIGEMT) failed: %m");
    if (sigaction(SIGTERM,&act,(struct sigaction*)NULL)<0)
	syslog(LOG_ERR,"sigaction(SIGTERM) failed: %m");
    if (sigaction(SIGUSR1,&act,(struct sigaction*)NULL)<0)
	syslog(LOG_ERR,"sigaction(SIGUSR1) failed: %m");
    if (sigaction(SIGUSR2,&act,(struct sigaction*)NULL)<0)
	syslog(LOG_ERR,"sigaction(SIGUSR2) failed: %m");
#ifdef USE_SIGNALS
    if (sigaction(SIGWINCH,&act,(struct sigaction*)NULL)<0)
	syslog(LOG_ERR,"sigaction(SIGWINCH) failed: %m");
#endif
#ifdef __hpux
    if (sigaction(SIGSYS,&act,(struct sigaction*)NULL)<0)
	syslog(LOG_ERR,"sigaction(SIGSYS) failed: %m");
#endif

}
/*********************************************************************
 *
 * Our grand and illustrious signal handler.  Just remember that we
 * have work to do, and mainLoop() will call doSignals() when it
 * feels like it.
 *
 *********************************************************************/
#ifdef __hpux
void markSignal(int sig, int code, struct sigcontext *scp)
#else
void markSignal(int sig)
#endif
{
    pendingSig++;
    sigaddset(&pendingSignals,sig);
    if (sig==SIGTERM)
	pendingTerm=1;
#ifdef __hpux
    if (scp && scp->sc_syscall==SYS_select) {
	scp->sc_syscall_action=SIG_RETURN;
    }
#endif
}
/*********************************************************************
 *
 * For each signal we care about, if we got one, call the handler.
 * At some point, we may have enough to make a switch statement make
 * sense.  Order counts here:  if they send two of one signal, we're
 * allowed to only do it once, but we're not allowed to loose track
 * of any:  check it, clear it, and call the handler.
 *
 *********************************************************************/
void doSignals(void)
{
    pendingSig=0;	/* if we're not going to call them all, then remember to do it later. */

    /* XXX - probably should block signals, since there is a small window in sigdelset where we could lose one */

#define callit(sig,handler) { if (sigismember(&pendingSignals,(sig)))	\
				{ footprint(7,(sig),0,0);		\
				  sigdelset(&pendingSignals,(sig));	\
				  handler ((sig)); } }
#ifdef __hpux
    callit(SIGSYS,dumpMap)
#endif
    callit(SIGUSR1,dumpClients)
    callit(SIGUSR2,dumpConfig)	/* in gram.y	*/
    callit(SIGHUP,readConfig)	/* in sockd.c	*/
    callit(SIGINT,newLog)	/* in logging.c	*/
    callit(SIGEMT,unListen)	/* in listen.c	*/
    callit(SIGTERM,terminate)
#undef callit
}
