hex		0x([A-Fa-f0-9])+
dec		([1-9][0-9]*|0)
oct		0o([0-7])+
num		({hex}|{dec}|{oct})
ip4		({num}\.){3}{num}
ipprefix	({num}\.){1,2}{num}

%{
#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/lexer.l,v 0.34 2002/01/10 18:54:45 lamont Exp $";
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
#include "sockd.h"
#include "gram.tab.h"
#define yylex zzlex
static char * dequoteEnv(char *s);
int getSpecial(char **str);
int tonum(char *s,int len,int base);

%}
%option noyywrap

/* No is for rules that are turned off right now.  We may turn them on later... */
%x Str No
%%

[ \t\n]+	;
\#.*\n		;

daemon		{ return T_DAEMON; }
directory	{ return T_DIRECTORY; }
umask		{ return T_UMASK; }
service		{ return T_SERVICE; }
listen-address	{ return T_LISTENADDR; }
listen-addr	{ return T_LISTENADDR; }
user		{ return T_USER; }
group		{ return T_GROUP; }
pre-fork	{ return T_PREFORK; }
dns-helper	{ return T_NUMHELPER; }
listen		{ return T_LISTEN; }
client		{ return T_CLIENT; }
name		{ return T_NAME; }
negotiate-file	{ return T_NEGOTFILE; }
inetdsec-file	{ return T_INETDSEC; }
none		{ return T_NONE; }
poll		{ return T_POLL; }
env		{ return T_ENV; }
clients-per-min { return T_CLIENT_PER_MIN; }

flags		{ return T_FLAGS; }
v4-only		{ yylval.iVal=FL_V4_ONLY; return I_FLAG; }
no-keepalive	{ yylval.iVal=FL_NO_KEEPALIVE; return I_FLAG; }

logging		{ return T_LOGGING; }
level		{ return T_LEVEL; }
facility	{ return T_FACIL; }
usage-log	{ return T_LOGFILE; }
dump-prefix	{ return T_DUMPPREFIX; }
debug		{ return T_DEBUG; }

default		{ return T_DEFAULT; }
timeout		{ return T_TIMEOUT; }
setup-timeout	{ return T_SETUPTIMEOUT; }
bufsize		{ return T_BUFSIZE; }

route		{ return T_ROUTE; }
host		{ return T_HOST; }

method-list	{ return T_METHODLIST; }
library		{ return T_LIB; }
number		{ return T_NUMBER; }
internal	{ return T_INTERNAL; }

client-method	{ return T_CLIENTMETH; }
method		{ return T_METHOD; }

permit		{ yylval.iVal=ACTION_PERMIT; return I_ACTION; }
permit!		{ yylval.iVal=ACTION_PERMIT_OK; return I_ACTION; }
deny		{ yylval.iVal=ACTION_DENY; return I_ACTION; }
skip		{ yylval.iVal=ACTION_SKIP; return I_ACTION; }

connect		{ yylval.iVal=SOCKS5_CONNECT; return I_REQ; }
bind		{ yylval.iVal=SOCKS5_BIND; return I_REQ; }
udp-associate	{ yylval.iVal=SOCKS5_UDP_ASSOCIATE; return I_REQ; }
ping		{ yylval.iVal=SOCKS5_PING; return I_REQ; }
traceroute	{ yylval.iVal=SOCKS5_TRACEROUTE; return I_REQ; }

src		{ return T_SRC; }
dest		{ return T_DEST; }
port		{ return T_PORT; }
cmd		{ return T_CMD; }

\=\=?		{ yylval.opVal=r_eq; return E_RELOP; };
\!\=?|\<\>	{ yylval.opVal=r_ne; return E_RELOP; };
<No>\>		{ yylval.opVal=r_gt; return E_RELOP; };
<No>\>\=	{ yylval.opVal=r_ge; return E_RELOP; };
<No>\<		{ yylval.opVal=r_lt; return E_RELOP; };
<No>\<\=	{ yylval.opVal=r_le; return E_RELOP; };

\{		{ return START; }
[-}|/;,]	{ return yytext[0]; }

{ip4}		{ yylval.iVal=inetAddr(yytext); return I_IP4;}
{ipprefix}	{ yylval.iVal=inetAddr(yytext); return I_IPPREFIX;}
({dec}[wdhms])+	{ yylval.iVal=strToTime(yytext); return I_TIME; }
{dec}		{ yylval.iVal=strtol(yytext,(char**)NULL,10); return I_NUM; }
{hex}		{ yylval.iVal=strtol(yytext+2,(char**)NULL,16); return I_NUM; }
{oct}		{ yylval.iVal=strtol(yytext+2,(char**)NULL,8); return I_NUM; }

\"[^\"\\]*\"		{ register char *c=strdup(yytext+1); c[yyleng-2]='\0'; yylval.sVal=c; return S_STR; }

\"			{ BEGIN Str; yymore(); break; }
<Str>[^\\]*\\.		{ yymore(); break; }

<Str>\n			{ return T_BADTOKEN; }

<Str>[^\\\n]*\"		{
			    char *c;
			    register char *d=malloc(yyleng);
			    register int j;
			    BEGIN INITIAL;
			    if (!d) {
				syslog(LOG_WARNING,"Out of memory in lexer.");
				return T_BADTOKEN;
			    }
			    for (j=0,c=yytext+1;c<yytext+yyleng-1;j++,c++) {
				if (*c=='\\')
				    d[j]=getSpecial(&c);
				else
				    d[j]=*c;
			    }
			    d[j]='\0';
			    yylval.sVal=d;
			    return S_COMPLEXSTR;
			}

[A-Za-z0-9_]+=[^ ;]*	{ yylval.sVal=strdup(yytext); return S_ENV; }
[A-Za-z0-9_]+=\"[^"]*\"	{ yylval.sVal=dequoteEnv(yytext); return S_ENV; }
[A-Za-z0-9_]+=\'[^']*\'	{ yylval.sVal=dequoteEnv(yytext); return S_ENV; }
[A-Za-z0-9_]+=\/[^/]*\/	{ yylval.sVal=dequoteEnv(yytext); return S_ENV; }
[A-Za-z0-9_]+=\:[^:]*\:	{ yylval.sVal=dequoteEnv(yytext); return S_ENV; }

[A-Za-z][-A-Za-z0-9_]*	{ fprintf(stderr,"GOT %s\n",yytext);    return T_BADTOKEN; }
<*>.|\n			{ fprintf(stderr,"GOT %c\n",yytext[0]); return yytext[0]; }
%%

static char * dequoteEnv(char *s)
{
    register char *c;
    register int i;
    s=strdup(s);
    c=strchr(s,'=')+1;
    memmove(c,c+1,i=(strlen(c)-2));
    c[i]='\0';
    return s;
}

int strToTime(char *in)
{
    char *p=in;
    register int ret=0;
    register int i;

    while (1) { 
	i=strtol(p,&p,10);
	switch(*p++) {
	case 'w':	ret+=i*7*86400; break; 	/* weeks */
	case 'd':	ret+=i*86400;	break; 	/* days */
	case 'h':	ret+=i*3600; 	break;	/* hours */
	case 'm':	ret+=i*60; 	break;	/* minutes */
	case 's':	ret+=i; 	break;	/* seconds */
	case '\0':	return ret;
	}
    }
}

char *timeToStr(int time)
{
    static char retBuf[100];
    register int retLen;
    register int oTime=time;

    *retBuf='\0'; retLen=0;
    if (time>=7*86400) {
	retLen+=snprintf(retBuf+retLen,sizeof(retBuf)-retLen,"%dw",time/(7*86400));
	time%=(7*86400);
    }
    if (time>=86400) {
	retLen+=snprintf(retBuf+retLen,sizeof(retBuf)-retLen,"%dd",time/86400);
	time%=86400;
    }
    if (time>=3600) {
	retLen+=snprintf(retBuf+retLen,sizeof(retBuf)-retLen,"%dh",time/3600);
	time%=3600;
    }
    if (time>=60) {
	retLen+=snprintf(retBuf+retLen,sizeof(retBuf)-retLen,"%dm",time/60);
	time%=60;
    }
    if (!oTime || time) {
	retLen+=snprintf(retBuf+retLen,sizeof(retBuf)-retLen,"%ds",time);
    }
    return retBuf;
}


int tonum(char *s,int len,int base)
{
	int n=0;
	for (; len > 0; len--,s++)
	{
		n *= base;
		if (*s >= '0' && *s <= '9') n += (*s - '0');
		else if (*s >= 'A' && *s <= 'F') n += (*s - 'A'+10);
		else if (*s >= 'a' && *s <= 'f') n += (*s - 'a'+10);
	}
	return(n);
}
int getSpecial(char **str)
{
	char *c=*str;
	char d;

	switch(*++c) {
	case 'a':	d='\a'; break;
	case 'b':	d='\b'; break;
	case 'f':	d='\f'; break;
	case 'n':	d='\n'; break;
	case 'r':	d='\r'; break;
	case 't':	d='\t'; break;
	case 'v':	d='\v'; break;
	case 'x':	
		if (strchr("0123456789abcdefABCDEF",c[2]) != NULL)
			d=tonum((c+=2)-1,2,16);
		else
			d=tonum(++c,1,16);
		break;
	case '\'':
	case '\"':
	case '\\':
	case '\?':	d=*c; break;
	default:
		if (*c>='0'&&*c<='7')
			if (c[1]>='0'&&c[1]<='7')
				if (c[2]>='0'&&c[2]<='7')
					d=tonum((c+=2)-2,3,8);
				else
					d=tonum((c+=1)-1,2,8);
		    	else
				d=*c-'0';
		else {
			d='\\';
			(void)fprintf(stderr,"bad \\ ignored\n");
		}
	}
	*str=c;
	return d;
}

static char hexChars[16]="0123456789abcdef";

char *expandString(const char *us)
{
    register const unsigned char *s=(const unsigned char *)us;
    register char *ret;
    register unsigned char *d;
    register char *str=malloc(strlen(us)*4+4);

    if (str==NULL) {
	syslog(LOG_ERR,"Out of memory in expandString()");
	return strdup("??");
    }
    d=(unsigned char *)str;

    for (;*s;s++) {
	switch (*s) {
	    case '\a':	*d++='\\', *d++='a'; break;
	    case '\b':	*d++='\\', *d++='b'; break;
	    case '\f':	*d++='\\', *d++='f'; break;
	    case '\n':	*d++='\\', *d++='n'; break;
	    case '\r':	*d++='\\', *d++='r'; break;
	    case '\t':	*d++='\\', *d++='t'; break;
	    case '\v':	*d++='\\', *d++='v'; break;
	    case '\"':	*d++='\\', *d++='\"'; break;
	    case '\'':	*d++='\\', *d++='\''; break;
	    case '\?':	*d++='\\', *d++='\?'; break;
	    case '\\':	*d++='\\', *d++='\\'; break;
	    default:
		if (*s>=0x20 && *s<0x7f) {
		    *d++=*s;
		} else {
		    *d++='\\', *d++='x', *d++=hexChars[*s/16], *d++=hexChars[*s%16];
		}
		break;
	}
    }
    *d++='\0';
    return str;
}
u_int32_t inetAddr(const char *s)
{
    register int       i;
    const char         *p;
    union {
	u_int32_t       i;
	u_char          c[4];
    } v;

    /* this handles partial IP's (into the top of the word), while the official one is, umm, broken. */
    for (v.i=0, p=s,i=0;i<4;i++,p++) {
	if (*p=='0' && p[1]=='x') v.c[i]=strtol(p+2,(char**)&p,16);
	else if (*p=='0' && p[1]=='o') v.c[i]=strtol(p+2,(char**)&p,8);
	else v.c[i]=strtol(p,(char**)&p,10);
	if (!p || !*p)
	    break;
    }
    return v.i;
}
