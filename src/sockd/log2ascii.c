#include "sockd.h"

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/log2ascii.c,v 0.16 2001/03/02 01:34:53 lamont Exp $";
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


char *typeToStr(int type);
int dumpAddr(char *c);
int dumpString(char *c);

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

void process_file(int fd);
int sourceOnly;
int follow;
main(int argc,char **argv)
{
    extern char		*optarg;
    extern int		optind;
    char		*myname=argv[0];
    register int	c;

    while ((c=getopt(argc,argv,":fs")) != EOF) switch (c) {
	case 'f':	follow=1; break;
	case 's':	sourceOnly=1; break;
	case ':':
	case '?':
		fprintf(stderr, "Usage: %s [file...]\n", myname);
		exit(1);
    }

    if (follow && optind != argc-1) {
	fprintf(stderr,"Expected exactly one file name with -f.\n");
	exit(1);
    }

    if (optind==argc) {
	    process_file(fileno(stdin));
    } else for (;optind<argc; optind++) {
	    register int in;
	    if (strcmp(argv[optind],"-")==0)
		in=fileno(stdin);
	    else if ((in=open(argv[optind],O_RDONLY,0))<0) {
		perror("open(in)");
		continue;
	    }
	    if (follow)
		lseek(in,0,SEEK_END);
	    process_file(in);
	    if (in != fileno(stdin))
		(void)close(in);
    }
    return 0;
}
#define CACHE_SIZE 256
int cache[CACHE_SIZE];
#define HASH(c) ((c[0]^c[1]^c[2]^c[3])&(CACHE_SIZE-1))
void process_file(int fd)
{
    register int	f=fd;
    logHeadType		head;
    u_short		port;
    union {
	char		chars[65536];
	unsigned char	uchars[65536];
	logCloseType	close;
    } rec;
    register int	done;

    do {
	register int l=Read(f,&head,sizeof(head));
	if (l<0) {
	    perror("read");
	    return;
	}
	done=(!follow && !l);
	if (!l) {
	    if (follow)
		sleep(1);
	    continue;
	}

	if (!sourceOnly) {
	    register char *s;
	    head.time=ntohl(head.time);
	    s=ctime(&head.time);
	    s[19]='\0';
	    printf("%s %08x %s:",s+4,ntohl(head.id),typeToStr(head.type));
	}
	if (head.size>sizeof(head))
	    Read(f,&rec,ntohs(head.size)-sizeof(head));
	if (head.size<=sizeof(head))
	    continue;
	if (head.type >= LG_TYPE_CLIENT && head.type < LG_TYPE_CLIENT+256) {
	    int tmp;
	    time_t time;
	    register int i=0;
	    if (!sourceOnly) {
		memcpy(&tmp,rec.chars+i,sizeof(tmp)), i+=sizeof(tmp); printf("%u:", ntohl(tmp));	/* delta seconds*/
		i+=dumpAddr(rec.chars+i);								/* src		*/
		i+=dumpString(rec.chars+i);								/* user		*/
		i+=dumpAddr(rec.chars+i);								/* dest		*/
		memcpy(&port,rec.chars+i,sizeof(port)), i+=sizeof(port); printf("%u:",ntohs(port));	/* port		*/
		printf("%u:",rec.uchars[i++]);								/* method	*/
		memcpy(&tmp,rec.chars+i,sizeof(tmp)), i+=sizeof(tmp); printf("%u:",ntohl(tmp));		/* to src	*/
		memcpy(&tmp,rec.chars+i,sizeof(tmp)), i+=sizeof(tmp); printf("%u:",ntohl(tmp));		/* to dest	*/
		memcpy(&tmp,rec.chars+i,sizeof(tmp)), i+=sizeof(tmp); printf("%u\n",ntohl(tmp));	/* reason	*/
	    } else {
		i+=sizeof(tmp);						/* point at source address */
		if (rec.chars[i]==ATYP_V4) {
		    register char *p=(char*)&tmp;
		    memcpy(&tmp,rec.chars+i,sizeof(tmp));
		    if (cache[HASH(p)]==tmp)
			continue;
		    cache[HASH(p)]=tmp;
		}
		(void)dumpAddr(rec.chars+i);
		/* XXX - assumes that reason is the last field in the record...  */
		memcpy(&tmp,rec.chars+head.size-sizeof(tmp)-sizeof(head),sizeof(tmp));
		printf("%u\n",ntohl(tmp));	/* reason	*/
	    }
	} else switch(head.type) {
	    register int i;
	    case LG_TYPE_CONNECT:
	    case LG_TYPE_BIND:
	    case LG_TYPE_UDPASSOC:
	    case LG_TYPE_PING:
	    case LG_TYPE_TRACEROUTE:
		i=dumpAddr(rec.chars);
		i+=dumpString(rec.chars+i);
		i+=dumpAddr(rec.chars+i);
		memcpy(&port,rec.chars+i,sizeof(port)), i+=sizeof(port);
		printf("%d",ntohs(port));
		if (i<ntohs(head.size))
		    printf(":%d\n",rec.chars[i]);
		else
		    putchar('\n');
		break;
		
	    case LG_TYPE_CLOSE:
		printf("%d:%d:%d\n",ntohl(rec.close.toSrc),ntohl(rec.close.toDest),ntohl(rec.close.reason));
		break;

	    default:
		printf("\n");
		break;
	}
    } while (!done);
}
char *typeToStr(int type)
{
    static char buf[1024];
    if (type>= LG_TYPE_CLIENT && type < LG_TYPE_CLIENT+256) {
	snprintf(buf,sizeof(buf),"Client(%s)",typeToStr(type-LG_TYPE_CLIENT));
	return buf;
    } else switch(type) {
	case LG_TYPE_CONNECT:		return "Cnct";
	case LG_TYPE_BIND:		return "Bind";
	case LG_TYPE_UDPASSOC:		return "Assoc";
	case LG_TYPE_PING:		return "Ping";
	case LG_TYPE_TRACEROUTE:	return "Traceroute";
	case LG_TYPE_CLOSE:		return "Close";
	default:			return "UNKNOWN";
    }
}
int dumpAddr(char *c)
{
    struct sockaddr_in sin;

    switch(*c) {
	case ATYP_V4:
	    memcpy(&sin.sin_addr,c+1,4);
	    printf("%s:",inet_ntoa(sin.sin_addr));
	    return 5;
	case ATYP_V6:
	    printf("IPV6 address:");
	    return 17;
	case ATYP_DOMAIN:
	    return dumpString(c+1)+1;
    }
}
int dumpString(char *c)
{
    char name[256];
    memcpy(name,c+1,*c);
    name[*c]='\0';
    printf("%s:",name);
    return *c+1;
}
