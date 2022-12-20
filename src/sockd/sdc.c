#include "sockd.h"

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/sdc.c,v 0.28 2002/01/08 08:13:19 lamont Exp $";
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

#ifndef SOCKD_PATH
#define SOCKD_PATH "/opt/socks/sbin/sockd"
#endif

fdInfoType	*fdInfo;
time_t		*expire;
negotPageType	*negot;	/* negotiation page */
negotInfoType	*negotInfo;
volatile int	negotSlot;
configInfoType	config;
int		debug=0;
static char	*configFile=CONFIG_FILE;
static char	syslogName[20];

void doClients(void);
int main(int argc,char **argv)
{
    register int c;
    register int negotFd;
    register int i;
    register int wait=-1;
    register char *name=*argv;
    register pid_t pGroup=0;
    register int signal;

    while ((c=getopt(argc,argv,"c:d:p:"))!=EOF) switch(c) {
	case 'c':	configFile=strdup(optarg); break;
	case 'd':	debug=strtol(optarg,(char**)NULL,0); break;
	case 'p':	pGroup=strtol(optarg,(char**)NULL,0); break;
	case ':':	break;
	case '?':	break;
	default:	break;
    }

    argc-=optind, argv+=optind;

    freopen(configFile,"r",stdin);

    if (yyparse()) {
	perror("yyparse");
	goto usage;
    }
    config=newConfig;

    chdir(config.daemon.directory);

    /* setup multi-daemon negotiation page */
    negotFd=open(config.daemon.negotFile,O_RDONLY);
    if (negotFd<0) {
	perror("negot open()");
	exit(1);
    }
#ifdef HAVE_MMAP
    negot=(negotPageType*)mmap((void*)NULL,NEGOT_SIZE,PROT_READ,MAP_SHARED|MAP_FILE,negotFd,0);
#else
    {
	int key;
	int shmId;
	void *negotTmp;
	key=ftok(config.daemon.name,ntohs(config.daemon.port));
	shmId=shmget(key,NEGOT_SIZE,0444);
	negotTmp=(shmId>=0)? (negotPageType*)shmat(shmId,NULL,0) : NULL;
	if (negotTmp) {
	    negot=malloc(NEGOT_SIZE);
	    if (negot==NULL) {
		syslog(LOG_ERR,"Out of memory");
		exit(1);
	    }
	    memcpy(negot,negotTmp,NEGOT_SIZE);
	    shmdt(negotTmp);
	}
    }
#endif
    if (negot==(negotPageType*)0xffffffff || !negot) {
	perror("negot mmap()");
	exit(1);
    }

    if (!pGroup)
	pGroup=-negot->head.processGroup;

    signal=0;
    if (strcmp(*argv,"status")==0) {
	register int wait=0;
	if (argc>1)
	    wait=strtol(argv[1],NULL,10);
	doStatus(wait);
	return 0;
    } else if (strcmp(*argv,"reload")==0) {
	signal=SIGHUP;
    } else if (strcmp(*argv,"newlog")==0) {
	signal=SIGINT;
    } else if (strcmp(*argv,"dumpconfig")==0 || strcmp(*argv,"config")==0) {
	signal=SIGUSR2;
    } else if (strcmp(*argv,"dumpclient")==0 || strcmp(*argv,"client")==0) {
	signal=SIGUSR1;
	doClients();
    } else if (strcmp(*argv,"stop")==0) {
	signal=SIGTERM;
    } else if (strcmp(*argv,"start")==0) {
        register char *c=strrchr(SOCKD_PATH,'/')+1;
	execl(SOCKD_PATH,c,(char*)NULL);
	perror("exec failed");
    } else if (strcmp(*argv,"unlisten")==0) {
	signal=SIGEMT;
    } else if (strcmp(*argv,"restart")==0) {
	register int ret=kill(pGroup,SIGEMT);
        register char *c=strrchr(SOCKD_PATH,'/')+1;
	if (ret<0) {
	    perror("failed to deliver signal");
	    return 1;
	}
	sleep(2);
	execl(SOCKD_PATH,c,(char*)NULL);
	perror("exec failed");
    } else {
usage:
	fprintf(stderr,
	    "usage: %s [-c config] status [interval]|reload|newlog|dumpconfig|dumpclient|unlisten|stop|start|restart\n",
	    name);
	return 2;
    }
    if (signal) {
	register int ret=kill(pGroup,signal);
	if (ret<0) {
	    perror("failed to deliver signal");
	    return 1;
	}
    }
    return 0;
}
const char *printFlags(int flags)
{
    static char buf[12];
    if (flags==NF_LOSER) {
	return "nolisten";
    } else if (!flags) {
	return "";
    } else {
	snprintf(buf,sizeof(buf),"0x%08x",flags);
	return buf;
    }
}
doStatus(int wait)
{
    register int i;
    register int highSlot=NEGOT_MAXSLOT;
    register int highListen;
    register negotInfoType *nInfo;

    for (nInfo=negot->slot+highSlot-1;!nInfo->pid && highSlot>0;highSlot--,nInfo--);
    for (highListen=highSlot,nInfo=negot->slot+highListen-1;
	 ((nInfo->flags&NF_LOSER) || !nInfo->pid) && highListen>0;
	 highListen--,nInfo--);

    do {
	printf("process group=%d\n",negot->head.processGroup);
	printf("listeners: %d  (min=%d max=%d)\n",negot->head.numListen,config.daemon.minListen,
		    config.daemon.maxListen);
	for (i=0;i<sizeof(negot->head.listeners)/sizeof(negot->head.listeners[0]);i++) {
	    printf("0x%08x ",negot->head.listeners[i]);
	    if ((i+1)*sizeof(negot->head.listeners[0])*8 >= highSlot)
		break;
	}
	putchar('\n');

	for (i=0,nInfo=negot->slot;i<highSlot;nInfo++,i++) if (nInfo->pid) {
	    printf("%3d: %5d %5d %10s %s",i,nInfo->pid,nInfo->numConn,printFlags(nInfo->flags),ctime(&nInfo->lastChecked));
	}
	if (!negot->head.numListen)	/* all gone, time to leave... */
	    wait=0;
    } while (wait>0 && sleep(wait)==0);
    return 0;
}
void doClients(void)
{
    sleep(1);	/* give them some time to complete */
    /* XXX - fork/exec log2ascii on each dump file */
}
int loadMethInfo(methodInfoType *mInfo) { return 0; }	/* keep gram.y happy */
void freeSomeMemory(dataBufType *buf) { fprintf(stderr,"out of memory!!??\n"); exit(1); }
