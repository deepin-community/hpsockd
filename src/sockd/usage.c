
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

#ifndef __lint
static char sccsid[]="@(#)$Header: /var/cvs/hpsockd/src/sockd/usage.c,v 0.15 2003/01/19 14:05:56 lamont Exp $";
static char *copyright="@(#)Copyright Hewlett-Packard Company, 1997-2000.";
#endif

#include <unistd.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <db.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include "btree.h"
#include <assert.h>
#include "logging.h"

#define STRCASEEQ(a, b)	(strcasecmp(a, b) == 0)
#define STREQ(a, b)	(strcmp(a, b) == 0)
#define Max(a,b)	((a)<(b) ? (b) : (a))

#define NEW(x)	((x*)malloc(sizeof(x)))
#define CNEW(n,x)	((x*)calloc((n),sizeof(x)))

#ifdef NO_LONG_LONG
typedef struct {
	long	h;
	long	l;
} llType;
#define ADD(res,p1,p2) ((res).h=(p1).h+(p2).h,((res).l=(p1).l+(p2).l)>=1000000000 ? (res).h++,(res).l-=1000000000 : 0)
#define ADDL(res,p1,p2) ((res).h=(p1).h,((res).l=(p1).l+(p2))>=1000000000 ? (res).h++,(res).l-=1000000000 : 0)
#define ZERO(res)	((res).h=(res).l=0)
#else	/* !NO_LONG_LONG */
typedef long long llType;
#define ADD(res,p1,p2) ((res)=(p1)+(p2))
#define ADDL(res,p1,p2) ((res)=(p1)+(p2))
#define ZERO(res)	((res)=0)
#endif	/* !NO_LONG_LONG */

typedef struct Conn ConnType;
typedef enum { protoTcp,protoUdp} protoType;
typedef enum { bindCmd=LG_TYPE_BIND,connectCmd=LG_TYPE_CONNECT,udpAssocCmd=LG_TYPE_UDPASSOC } typeType;
#ifndef __lint
char *typeName[] = { "Bind","Cnct","UdpAssoc" };
char *protoName[] = { "TCP", "UDP" };
#endif

#define MAXCHASH	64
#define CKEY(id) ((id)%MAXCHASH)

typedef struct {
	u_char		*dest;
	unsigned short	port;
	protoType	proto;
} DkeyType;
typedef struct {
	DkeyType	*key;
	llType		recvd;
	llType		sent;
	long		count;
} DdataType;

typedef struct {
	u_char		*src;
	char		*user;
} SkeyType;
typedef struct {
	SkeyType	*key;
	llType		recvd;
	llType		sent;
	long		count;
} SdataType;

struct Conn {
	ConnType	*link;
	logHeadType	head;
	SdataType	*src;
	DdataType	*dst;
} *Chash[MAXCHASH];

void *Droot=NULL,*Sroot=NULL;

long debug=0;
#define DBG_INPUT	0x1000
#define DBG_DUMP	0x2000
#define DBG_SVALID	0x10000
#define DBG_DVALID	0x20000

int show_source;
int show_dest;
int verbose;

unsigned int host;	/* one host only */

int main (int argc, char **argv);
int process_file (FILE *in);
void lostConn(ConnType *conn);
ConnType *findConn(long id);
void freeConn(ConnType *conn);
SdataType *addSrc(u_char *src,char *srcusr);
DdataType *addDst(u_char *dst,unsigned short dstport, protoType proto);
void outputStats(void);
int Sprint(void *key, void *data,btw_t which,void*info);
int Dprint(void *key, void *data,btw_t which,void*info);
int Scmp(void *uk1, void *uk2);
int Dcmp(void *uk1, void *uk2);
char *address(u_char *addr);

const char *lltos(llType ll)
{
	static char	buf[80];
	static char	which=1;
	register char	*c,*c1;
	register long	a,b,l;
#ifndef NO_LONG_LONG
	register llType	aa;
#endif

	which^=1;
	c1=c=buf+which*40;

#ifdef NO_LONG_LONG
	while (ll.l >= 1000000000) {
		ll.l -= 1000000000;
		ll.h++;
	}
	l=ll.l;
	a=ll.h;
	b=0;
#else	/* !NO_LONG_LONG */
	aa=ll/1000000000;
	b=aa/1000000000;	/* 10^18 and up */
	a=aa%1000000000;	/* 10^17..10^9 */
	l=ll%1000000000;	/* 10^8..10^0 */
#endif	/* !NO_LONG_LONG */

	*c='\0';
	if (b)
		sprintf(c,"%d",b);
	if (a||b)
		sprintf(c+strlen(c),b?"%09d":"%d",a);
	sprintf(c+strlen(c),(a||b)?"%09d":"%d",l);

	return c1;
}

const char *ntoa(unsigned long ip)
{
	struct in_addr ia;
	ia.s_addr=ip;
	return inet_ntoa(ia);
}

int main(int argc, char **argv)
{
	int		c;
	char		*myname;
	FILE		*in;
	extern char	*optarg;
	extern int	optind;
	int		status=0;

	myname=strrchr(argv[0],'/');
	if (myname==NULL) myname=argv[0]; else myname++;

	while ((c=getopt(argc,argv,"D:sdvn:h:")) != EOF) switch (c) {
		case 'D':	debug=strtol(optarg,(char**)NULL,0); break;
		case 's':	show_source=1; break;
		case 'd':	show_dest=1; break;
		case 'v':	verbose++; break;
		case 'h':	host=inet_addr(optarg); break;
		case ':':
		case '?':
			fprintf(stderr, 
			   "Usage: %s [-sdvv] [-n name] [-h host] [file...]\n",
				myname);
			exit(1);
	}

	if (!show_source && !show_dest)
		show_source++;
	
	if (optind==argc) {
		if (process_file(stdin)<0)
			status=2;
	} else for (;optind<argc; optind++) {
		if (STREQ(argv[optind],"-"))
			in=stdin;
		else if ((in=fopen(argv[optind],"r"))==NULL) {
			perror("fopen(in)");
			status=1;
			continue;
		}
		if (process_file(in)<0)
			status=2;
		if (in != stdin)
			(void)fclose(in);
	}
	outputStats();
	if (debug & DBG_DUMP) {
		if (show_source) btdump(Sroot);
		if (show_dest) btdump(Droot);
	}

	return status;
}
#pragma HP_ALIGN NOPADDING PUSH
typedef union { int i; unsigned int ui; unsigned short us; } crunchType;
#pragma HP_ALIGN POP

int Read(int fd, void *ubuf, int size)
{
    register int ret=0,r;
    register char *buf=ubuf;

    do {
	r=read(fd,buf,size);
	if (r<0) 
	    return r;
	else if (!r)
	    return ret;
	else
	    size-=r, buf+=r, ret+=r;
    } while (size);
    return ret;
}

int process_file (FILE *in)
{
	double		dbuf[1024/sizeof(double)];
	char		*buf=(char*)dbuf;
	logHeadType	logHead;
	register int	inFd=fileno(in);
	register int	ret;

	while (ret=Read(inFd,&logHead,sizeof(logHead))) {
	    register long id=logHead.id;
	    if (ret<0) {
		perror("read");
		return -1;
	    } else if (ret != sizeof(logHead)) {
		fprintf(stderr,"short read");
		return -1;
	    }
	    buf=(char*)dbuf;
	    ret=Read(inFd,buf,logHead.size-sizeof(logHead));
	    if (ret<0) {
		perror("closeRead");
		return -1;
	    } else if (ret != logHead.size-sizeof(logHead)) {
		fprintf(stderr,"short read");
		return -1;
	    }
	    if (logHead.type >= LG_TYPE_CLIENT && logHead.type < LG_TYPE_CLIENT+256) {
		register u_char *src,*utmp,*dest,*p;
		register u_short dstport;
		char user[256];
		register SdataType *srcData;
		register DdataType *dstData;
		register unsigned int toSrc, toDest;

		logHead.type-=LG_TYPE_CLIENT;

		src=(void*)(buf+sizeof(unsigned int));			/* skip elapsed time */
		utmp=src+ADDRLEN(src);
		dest=utmp+*utmp+1;

		if (host) { 
		    if (*src==ATYP_V4 && *dest==ATYP_V4) {
			if (memcmp(src+1,&host,sizeof(host))!=0 &&
			    memcmp(dest+1,&host,sizeof(host))!=0)
			    continue;					/* next record */
		    }
		}
		p=dest+ADDRLEN(dest);
		dstport=((crunchType*)p)->us; p+=sizeof(short)+1;	/* skip method */
		toSrc=((crunchType*)p)->ui; p+=sizeof(unsigned int);
		toDest=((crunchType*)p)->ui; p+=sizeof(unsigned int);
		user[*utmp]='\0';
		memcpy(user,utmp+1,*utmp);

		srcData=addSrc(src,user);
		srcData->count++;
		dstData=addDst(dest,dstport,(logHead.type==LG_TYPE_UDPASSOC) ? protoUdp : protoTcp);
		dstData->count++;

		ADDL(srcData->recvd,srcData->recvd,toDest);
		ADDL(dstData->sent,dstData->sent,toDest);
		ADDL(dstData->recvd,dstData->recvd,toSrc);
		ADDL(srcData->sent,srcData->sent,toSrc);
	    } else switch(logHead.type) {
		case LG_TYPE_CONNECT:
		case LG_TYPE_BIND:
		case LG_TYPE_UDPASSOC:		/* Not in the old files, but hey, why not. */
		case LG_TYPE_PING:		/* Not in the old files, but hey, why not. */
		case LG_TYPE_TRACEROUTE:	/* Not in the old files, but hey, why not. */
		    {
			register u_char *src,*utmp,*dest;
			register u_short dstport;
			register ConnType *conn;
			char user[256];

			src=(void*)buf;
			utmp=src+ADDRLEN(src);
			dest=utmp+*utmp+1;
			dstport=((crunchType*)(dest+ADDRLEN(dest)))->us;
			user[*utmp]='\0';
			memcpy(user,utmp+1,*utmp);
			if ((conn=findConn(id)) != NULL) {
			    lostConn(conn);
			    freeConn(conn);
			}
			conn=NEW(ConnType);
			conn->head=logHead;
			conn->src=addSrc(src,user);
			conn->src->count++;
			conn->dst=addDst(dest,dstport,(logHead.type==LG_TYPE_UDPASSOC) ? protoUdp : protoTcp);
			conn->dst->count++;
			conn->link=Chash[CKEY(id)];
			Chash[CKEY(id)]=conn;
		    }
		    break;

		case LG_TYPE_CLOSE:
		    {
			register ConnType	*conn;
			register SdataType	*src;
			register DdataType	*dst;
			register logCloseType	*logClose=(logCloseType*)dbuf;

			if ((conn=findConn(id))==NULL) {
			    static u_char unkHost[]={ ATYP_DOMAIN,9,'.','u','n','k','n','o','w','n','.' };
			    static char *unkUser="\010|unknown";
			    fprintf(stderr,"Orphan close 0x%08x\n",id);
			    src=addSrc(unkHost,unkUser);
			    dst=addDst(unkHost,0,protoTcp);
			} else {
			    src=conn->src;
			    dst=conn->dst;
			}
			ADDL(src->recvd,src->recvd,logClose->toDest);
			ADDL(dst->sent,dst->sent,logClose->toDest);
			ADDL(dst->recvd,dst->recvd,logClose->toSrc);
			ADDL(src->sent,src->sent,logClose->toSrc);
			if (conn) {
			    freeConn(conn);
			}
		    }
		    break;

		default:
		    fprintf(stderr,"Unknown log record type %d\n",logHead.type);
		    continue;
	    }

	}
	return 0;
}
void lostConn(ConnType *conn)
{
    fprintf(stderr,"Lost connection 0x%08x\n",conn->head.id);
    /* XXX - finish lostConn */
}
ConnType *findConn(long id)
{
	register ConnType *conn=Chash[CKEY(id)];
	while (conn && (conn->head.id != id))
		conn=conn->link;
	return conn;
}
void freeConn(ConnType *conn)
{
	register long key=CKEY(conn->head.id);
	register ConnType *prev=Chash[key];
	if (prev==conn) {
		Chash[key]=conn->link;
	} else {
		while (prev && prev->link != conn)
			prev=prev->link;
		if (!prev) {
			fprintf(stderr,"Freeing free connection\n");
			return;
		}
		prev->link=conn->link;
	}
	free(conn);
}
#if 0
void freeSrc(SdataType *src)
{
	register int key=SKEY(src->key->ip);
	register SdataType *prev=S_hash[key];
	if (prev==src) {
		S_hash[key]=src->link;
	} else {
		while (prev && prev->link != src)
			prev=prev->link;
		if (!prev) {
			fprintf(stderr,"Freeing free source\n");
			return;
		}
		prev->link=src->link;
	}
	free(src->key->src);
	free(src->key->user);
	free(src);
}
void freeDst(DdataType *dst)
{
	register int key=DKEY(dst->key->ip);
	register DdataType *prev=D_hash[key];
	if (prev==dst) {
		D_hash[key]=dst->link;
	} else {
		while (prev && prev->link != dst)
			prev=prev->link;
		if (!prev) {
			fprintf(stderr,"Freeing free destination\n");
			return;
		}
		prev->link=dst->link;
	}
	free(dst->key->dest);
	free(dst);
}
#endif
SdataType *addSrc(unsigned char *src,char *user)
{
	register SkeyType *key=NEW(SkeyType);
	register SdataType *data=CNEW(1,SdataType),*ret;

	key->src=malloc(ADDRLEN(src)); memcpy(key->src,src,ADDRLEN(src));
	key->user=strdup(user);
	data->key=key;
	ret=(SdataType *)btsearch(&Sroot,key,data,Scmp,BT_INS);
	if (ret != data) {
		assert(memcmp(key->src,ret->key->src,ADDRLEN(src))==0 &&
			strcmp(key->user,ret->key->user)==0);
		free(key->src);
		free(key->user);
		free(key);
		free(data);
	}
	if (debug&DBG_SVALID)
		assert(btvalidate(Sroot,Scmp)==0);
	return ret;
}
DdataType *addDst(u_char *dst,unsigned short dstport,protoType proto)
{
	register DkeyType *key=NEW(DkeyType);
	register DdataType *data=CNEW(1,DdataType),*ret;

	key->dest=malloc(ADDRLEN(dst)); memcpy(key->dest,dst,ADDRLEN(dst));
	key->port=dstport;
	key->proto=proto;
	data->key=key;
	ret=(DdataType *)btsearch(&Droot,key,data,Dcmp,BT_INS);
	if (ret != data) {
		assert(memcmp(key->dest,ret->key->dest,ADDRLEN(dst))==0 && key->port==ret->key->port &&
			key->proto==ret->key->proto);
		free(key->dest);
		free(key);
		free(data);
	}
	if (debug&DBG_DVALID)
		assert(btvalidate(Droot,Dcmp)==0);
	return ret;
}
void outputStats(void)
{
	register int i;

	/* any outstanding connections? */
	for (i=0; i< MAXCHASH;i++) {
		register ConnType *conn=Chash[i];
		while (conn != NULL) {
			register ConnType *save=conn->link;
			lostConn(conn);
			freeConn(conn);
			conn=save;
		}
	}
	/* now do the source data */

	if (show_source)
		btwalk(Sroot,Sprint,NULL);

	if (show_dest)
		btwalk(Droot,Dprint,NULL);
}
static llType	gin,gout;
static long	gcnt;
static llType	tin,tout;
static long	tcnt;
int Sprint(void *ukey, void *udata,btw_t which,void*info)
{
    register SkeyType *key=(SkeyType*)ukey;
    register SdataType *data=(SdataType*)udata;
    static SkeyType *lastkey=NULL;

    if (which == bt_first) {
	ZERO(tin);
	ZERO(tout);
	tcnt=0;
	ZERO(gin);
	ZERO(gout);
	gcnt=0;
	return 0;
    }
    if (which == bt_last || lastkey != NULL && memcmp(lastkey->src,key->src,ADDRLEN(key->src))!=0) {
	if (verbose)
	    printf("ST:%s:%s:%s:%d\n",address(lastkey->src),lltos(tout),lltos(tin),tcnt);
	ADD(gin,gin,tin);
	ADD(gout,gout,tout);
	gcnt+=tcnt;
	ZERO(tin);
	ZERO(tout);
	tcnt=0;
    }
    if (which == bt_last) {
	printf("SG:%s:%s:%d\n", lltos(gout), lltos(gin),gcnt);
	return 0;
    }

    if (verbose > 1) {
	printf("SD:%s:%s:%s:%s:%d\n",address(key->src),key->user,
		lltos(data->sent),lltos(data->recvd),data->count);
    }
    ADD(tin,tin,data->recvd);
    ADD(tout,tout,data->sent);
    tcnt+=data->count;
    lastkey=key;
    return 0;
}
int Scmp(void *uk1, void *uk2)
{
    register SkeyType *k1=(SkeyType*)uk1,*k2=(SkeyType*)uk2;
    register int i;

    if (i=memcmp(k1->src,k2->src,ADDRLEN(k1->src)))
	return i;
    else
	return (i=*k1->user-*k2->user)?i:strcmp(k1->user+1,k2->user+1);
}
int Dprint(void *ukey, void *udata,btw_t which,void*info)
{
    register DkeyType *key=(DkeyType*)ukey;
    register DdataType *data=(DdataType*)udata;
    static DkeyType *lastkey=NULL;

    if (which == bt_first) {
	ZERO(tin);
	ZERO(tout);
	tcnt=0;
	ZERO(gin);
	ZERO(gout);
	gcnt=0;
	return 0;
    }
    if (which == bt_last || lastkey != NULL && memcmp(lastkey->dest,key->dest,ADDRLEN(key->dest))!=0) {
	if (verbose)
	    printf("DT:%s:%s:%s:%d\n",address(lastkey->dest),lltos(tout),lltos(tin),tcnt);
	ADD(gin,gin,tin);
	ADD(gout,gout,tout);
	gcnt+=tcnt;
	ZERO(tin);
	ZERO(tout);
	tcnt=0;
    }
    if (which == bt_last) {
	printf("DG:%s:%s:%d\n", lltos(gout), lltos(gin),gcnt);
	return 0;
    }

    if (verbose > 1) {
	printf("DD:%s:%d:%s:%s:%s:%d\n",address(key->dest),key->port,protoName[key->proto],
		lltos(data->sent),lltos(data->recvd),data->count);
    }
    ADD(tin,tin,data->recvd);
    ADD(tout,tout,data->sent);
    tcnt+=data->count;
    lastkey=key;
    return 0;
}
int Dcmp(void *uk1, void *uk2)
{
    register DkeyType *k1=(DkeyType*)uk1,*k2=(DkeyType*)uk2;
    register int i;

    if (i=memcmp(k1->dest,k2->dest,ADDRLEN(k1->dest)))
	return i;
    else
	return (i=k1->port-k2->port) ? i : k1->proto-k2->proto;
}
char *address(u_char *addr)
{
    static char buf[256];
    struct in_addr in;
    switch(*addr) {
	case ATYP_V4:
	    memcpy(&in,addr+1,4);
	    return inet_ntoa(in);
	case ATYP_V6:
	    sprintf(buf,"v6 addr");	/* XXX */
	    break;
	case ATYP_DOMAIN:
	    addr++;
	    buf[*addr]='\0';
	    memcpy(buf,addr+1,*addr);
	    break;
	default:
	    sprintf(buf,"unknown_address_type %d",*addr);
	    break;
    };
    return buf;
}
