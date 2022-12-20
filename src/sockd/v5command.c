#include "sockd.h"
#include "v5.h"

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/v5command.c,v 0.13 2002/12/17 05:21:22 lamont Exp $";
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


outputFunc commandOutput;

int v5DoCommand(fdInfoType *client,const char *name)
{
    register pid_t		pid;
    register int		i;
    v5HeadType			reply;
    u_short			port;
    register const char		*cmd=getEnv(client,name);
    int				pipeFd[2];
    register connInfoType	*conn=client->conn;

    if (!cmd)
	return SOCKS5_CMD_NOT_SUPP;

    close(client->peer->fd);
    do {
    	i=pipe(pipeFd);
    } while (i<0 && errno==EINTR);

    if (i<0)
	return SOCKS5_GENFAIL;

    do { 
	pid=fork();
    } while (pid<0 && errno==EINTR);

    switch (pid) {
	case -1:
	    close(pipeFd[0]);
	    close(pipeFd[1]);
	    return SOCKS5_GENFAIL;
	case 0:		
	    setpgrp();
	    close(pipeFd[0]);
	    break;
	default:
	    conn->pid=-pid;
	    setSelect(client->peer->fd,SL_READ|SL_EXCP);
	    if (pipeFd[0] != client->peer->fd) {
		dup2(pipeFd[0],client->peer->fd);
		close(pipeFd[0]);
	    }
	    if (pipeFd[1] != client->peer->fd) close(pipeFd[1]);
	    client->peer->TCP_RECV=(recvFunc*)read;
	    client->peer->TCP_SEND=(sendFunc*)write;
	    client->peer->TCP_OUTPUT=commandOutput;
	    v5GetSin(conn->req,&client->peer->sin,sizeof(client->peer->sin));
	    return SOCKS5_OK;
    }

    if (debug&DBG_CHILD) {
	volatile int dbg_wait=0;
	while (!dbg_wait);
    }

    memset(&reply,0,sizeof(reply));
    reply.version=SOCKS_V5;
    reply.cmd=SOCKS5_OK;
    reply.atyp=ATYP_V4;
    port=htons(0);
    client->TCP_OUTPUT(client,(char*)&reply,sizeof(reply),0);
    client->TCP_OUTPUT(client,(char*)&port,sizeof(port),0);

    for (i=lowFd; i<=highFd; i++) {
	if (i!=pipeFd[1])
	    close(i);
    }
    dup2(pipeFd[1],1), dup2(pipeFd[1],2), close(pipeFd[1]);
    freopen("/dev/null","r",stdin);
    doCommand2(cmd,client);
    _exit(0);
    return SOCKS5_OK;	/* this is to keep lint happy... */
}

int commandOutput(fdInfoType *peer,void *buf, int len, unsigned int flags)
{
    register char *p;
    register int i;

#if 0 /* [ */
    /* The client doesn't have stdin open anyway, so don't bother him. */
    for (p=buf,i=len;i>0;p++,i--) {
	switch(*p) {
	    case 'c'&0x1f:
		kill(peer->conn->pid,SIGINT);
		break;
	    case 'v'&0x1f:
		if (i<2) break;
		i--,p++;
		/* fall thru */
	    default:
		simpleOutput(peer,p,1,flags);
		break;
	}
    }
#else
    kill(peer->conn->pid,SIGINT);
#endif /* ] 0 */
    return 0;
}

void doCommand(const char *cmd,fdInfoType *client)
{
    register int pid;

    if (!(debug&DBG_FOREGROUND)) {
	do {
	    pid=fork();
	    } while (pid<0 && errno==EINTR);

	if (pid < 0) {
	    syslog(LOG_ERR,"doCommand: fork failed %m");
	    return;
	} else if (pid) {
	    return;
	}
    }
    /* The child gets here - it's OK to block again... */
    doCommand2(cmd,client);
}
void doCommand2(const char *sCmd,fdInfoType *client)
{
    register connInfoType	*conn=client->conn;
    register char		*cmdStart,*cmd,*c;
    register const char		*srcCmd=sCmd,*shell;
    register int		left;
    register int		size;
    u_short			portNum;
    
    c=(char*)&conn->req->atyp;
    c+=ADDRLEN(c); memcpy(&portNum,c,sizeof(u_short));

    cmdStart=cmd=malloc(left=size=2048);
    if (!cmdStart) {
	syslog(LOG_ERR,"doCommand: malloc failed");
	exit(1);
    }

    /* walk through the command string, building up our command.  Then launch the puppy.  */

    do {
	register int len,need;
	register char *srcName=NULL,*destName=NULL,*servName=NULL;
	register char *escape=NULL;
	char escapeBuf[256];
	register int warned=0;

	c=strchr(srcCmd,'%');
	len= (c) ? (c-srcCmd) : strlen(srcCmd);

	if (c) switch(c[1]) {
	    struct hostent *hp;
	    struct servent *sp;
	    case 'A':	/* source name */
		if (!srcName) {
		    hp=gethostbyaddr((const char *)&client->sin.sin_addr, sizeof(struct in_addr),client->sin.sin_family);
		    if (hp) {
			srcName=strdup(hp->h_name);
		    } else {
			goto source_addr;
		    }
		}
		if (strlen(srcName)>255)
		    srcName[255]='\0';
		escape=srcName;
		break;

	    case 'a':	/* source IP */
source_addr:	escape=inet_ntoa(client->sin.sin_addr);
		break;
	    case 'c':	/* command */
		switch(conn->req->cmd) {
		    case SOCKS5_CONNECT:	escape="connect"; break;
		    case SOCKS5_BIND:		escape="bind"; break;
		    case SOCKS5_UDP_ASSOCIATE:	escape="udp_assoc"; break;
		    case SOCKS5_PING:		escape="ping"; break;
		    case SOCKS5_TRACEROUTE:	escape="traceroute"; break;
		    default:			escape=escapeBuf; sprintf(escapeBuf,"%d",conn->req->cmd); break;
		}
		break;
	    case 'p':	/* sockd's pid */
		escape=escapeBuf;
		sprintf(escapeBuf,"%d", getpid());
		break;
	    case 'S':	/* service name */
		if (!servName) {
		    sp=getservbyport(portNum,(client->flags&FD_IS_UDP) ? "udp" : "tcp");
		    if (sp) {
			servName=strdup(sp->s_name);
		    } else {
			sprintf(escapeBuf,"%d",ntohs(portNum));
			servName=strdup(escapeBuf);
		    }
		}
		escape=servName;
		break;
	    case 's':	/* service num */
		escape=escapeBuf;
		sprintf(escapeBuf,"%d",ntohs(portNum));
		break;
	    case 'u':	/* user name */
		escape=conn->user ? conn->user : "(NONE)";
		break;
	    case 'Z':	/* destination name */
		if (!destName) {
		    switch(conn->req->atyp) {
			case ATYP_V4:
			    hp=gethostbyaddr((const char *)&conn->req->destAddr, sizeof(conn->req->destAddr),AF_INET);
			    break;
			case ATYP_V6:
			default:
			    hp=NULL;
			    break;
		    }
		    if (hp) {
			destName=strdup(hp->h_name);
		    } else {
			goto dest_addr;
		    }
		}
		if (strlen(destName)>255)
		    destName[255]='\0';
		escape=destName;
		break;

	    case 'z':	/* destination IP */
dest_addr:	switch(conn->req->atyp) {
		    case ATYP_V4:
			escape=inet_ntoa(*(struct in_addr*)&conn->req->destAddr);
			break;
		    case ATYP_V6:
			escape="V6 address";
			break;
		    default:
			escape="Unknown address type";
			break;
		}
		break;
	    default:
		escape=escapeBuf;
		escapeBuf[0]=*c, escapeBuf[1]=c[1], escapeBuf[2]='\0';
		break;
	}
	need=len+strlen(escape);
	while (need+40>left) {	/* some slop for next time through */
	    register int pos=cmd-cmdStart;
#define BUMP_AMOUNT 500
	    left+=BUMP_AMOUNT;
	    cmdStart=realloc(cmdStart,(size+=BUMP_AMOUNT));
	    if (!cmdStart) {
		syslog(LOG_ERR,"doCommand: realloc failed");
		exit(1);
	    }
	    cmd=cmdStart+pos;
#undef  BUMP_AMOUNT
	}
	strncpy(cmd,srcCmd,len), srcCmd+=len+2, cmd+=len;
	if (escape) {
	    register char *p;
	    for (p=escape; *p; p++)
		if (strchr("{}[]%^;$#!`~&*()\"'<>|\\/=",*p) || *p<=' ') {
		    if (!warned) {
			syslog(LOG_WARNING,"Possible shell escape in %s",escape);
			warned=1;
		    }
		    *p='_';
		}
	    strcpy(cmd,escape), cmd+=strlen(escape);
	}
    } while (c);

    shell=getEnv(client,"SHELL");
    if (!shell) shell="/bin/sh";
    if (!(debug&DBG_FOREGROUND)) {
	execl(shell,"sh","-c",cmdStart,(char*)NULL);
	syslog(LOG_ERR,"exec failed (%m) %s -c %s",shell,cmdStart);
    } else {
	system(cmdStart);
	free(cmdStart);
    }
}
