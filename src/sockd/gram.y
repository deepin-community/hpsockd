%{
#include "sockd.h"
#include <grp.h>
#include <sys/param.h>
#include <net/if.h>
#include <sys/ioctl.h>
#define YYDEBUG 1
void dumpTokens(void);

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/gram.y,v 0.51 2002/01/08 08:13:18 lamont Exp $";
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

configInfoType	newConfig;
static int cleanupConfig(void);
methodInfoType *findMethod(configInfoType *cfg,char *name);
static clientInfoType clInfo;
static methodInfoType methElem;
static clientMethodInfoType clientMethElem;
static hostLType makeHostSpec(relopType op, long mask, longLType list);

static int goodEq, goodSrc;	/* found a good equal compare in src statement for a client */

#define NEWLIST(l,i)	{ (l).list=malloc(sizeof(i)), (l).num=1; \
	if ((l).list==NULL) { syslog(LOG_ERR,"Out of memory in parser"); YYABORT; } \
	(l).list[0]=(i); }
#define ADDTOLIST(l,i)	{ (l).list=realloc((l).list,++(l).num*sizeof(i)); \
	if ((l).list==NULL) { syslog(LOG_ERR,"Out of memory in parser"); YYABORT; } \
	(l).list[(l).num-1]=(i); }
#define APPENDTOLIST(l,m)	{ (l).list=realloc((l).list,((l).num+(m).num)*sizeof(*(m).list)); \
	if ((l).list==NULL) { syslog(LOG_ERR,"Out of memory in parser"); YYABORT; } \
	memcpy((l).list+((l).num),(m).list,(m).num*sizeof(*(m).list)); (l).num += (m).num; \
	free((m).list); (m).list=NULL; }

#ifdef __hpux
#define DEFAULT_GID	-2
#else
#define DEFAULT_GID	65534
#endif

%}
%union {
    int 				iVal;
    char				*sVal;
    strLType				uStr;
    hostLType				hStr;
    longLType				iStr;
    portLType				pStr;
    portType				pVal;
    hostType				hVal;
    relopType				opVal;
    clientInfoType			clInf;
    clInLType				clStr;
    routeInfoType			rInf;
    rtInLType				rStr;
    methodInfoType			mInf;
    mInfLType				mStr;
    clientMethodInfoType		cmInf;
    cmInLType				cmStr;
    methodInfoType			*mPtr;
    mInPLType				mPStr;
    struct { int num1, num2; }		nPair;
}

%type   <iStr>	hostaddr
%type   <iStr>	rangeaddr
%type   <iStr>	ifaddr
%type   <iStr>	hostToken
%type	<iStr>	hostaddrs
%type	<uStr>	users
%type	<pVal>	port
%type	<iVal>	portNum
%type	<pStr>	portlist
%type	<hStr>	hostSpec
%type	<hStr>	hostlist
%type   <clInf> clientInfo
%type   <clStr> clients
%type	<rStr>  routeElem
%type	<rStr>	routeInfo
%type	<mInf>	method_elem
%type	<mStr>	methods
%type	<cmInf>	cliMethElem
%type	<cmStr>	cliMeths
%type	<mPStr>	methList
%type	<mPtr>	methodElem
%type	<nPair>	numPair
%type	<iVal>	numSemi
%type	<sVal>	strSemi
%type	<sVal>	strOrNone
%type	<sVal>	compStrOrNone
%type	<uStr>	envList
%type	<uStr>	env
%type	<sVal>	envSemi
%type	<opVal>	relop

%token		T_BADTOKEN
%token		T_DAEMON
%token		T_LISTENADDR
%token		T_SERVICE
%token		T_USER
%token		T_GROUP
%token		T_PREFORK
%token		T_NUMHELPER
%token		T_LISTEN
%token		T_CLIENT
%token		T_CLIENT_PER_MIN
%token		T_NAME
%token		T_DIRECTORY
%token		T_UMASK
%token		T_NEGOTFILE
%token		T_INETDSEC
%token		T_NONE
%token		T_POLL
%token		T_ENV

%token		T_FLAGS

%token		T_LOGGING
%token		T_LEVEL
%token		T_FACIL
%token		T_DUMPPREFIX
%token		T_LOGFILE
%token		T_DEBUG

%token		T_DEFAULT
%token		T_TIMEOUT
%token		T_SETUPTIMEOUT
%token		T_BUFSIZE

%token		T_ROUTE
%token		T_HOST

%token		T_METHOD
%token		T_METHODLIST
%token		T_LIB
%token		T_NUMBER
%token		T_CLIENTMETH

%token	<iVal>	I_ACTION
%token	<iVal>	I_REQ
%token		T_SRC
%token		T_DEST
%token		T_PORT
%token		T_CMD

%token		T_INTERNAL
%token	<sVal>	S_STR		/* strdup() */
%token	<sVal>	S_COMPLEXSTR	/* strdup() */
%token	<sVal>	S_ENV		/* strdup() */
%token	<iVal>	I_IP4
%token	<iVal>	I_IPPREFIX
%token	<iVal>	I_NUM
%token	<iVal>	I_TIME
%token	<iVal>	I_FLAG
%type	<iVal>	timeOrNumSemi
%token	<opVal>	E_RELOP

%token		START		/* { */

%start config
/* { */
%%

config:				{ defaultConfig(); }
		    conf	{ if (cleanupConfig()==0) YYACCEPT; else YYABORT;}
		;

conf:		cfent
		| conf cfent
		;
    
cfent:		T_DAEMON START dI End 
		| env					{ newConfig.env=$1; }
		| T_LOGGING START logI End
		| T_DEFAULT START defI End
		| T_ROUTE START routeInfo End		{ newConfig.routes=$3; }
		| T_CLIENT START clients End		{ newConfig.clients=$3; }
		| T_METHODLIST START methods End	{ newConfig.methods=$3; }
		| T_CLIENTMETH START cliMeths End	{ newConfig.cliMeth=$3; }
		;

dI:			/* make it recurse */
		| dI T_LISTENADDR START hostaddrs End	{ newConfig.daemon.listenAddr=$4; }
		| dI T_SERVICE strSemi			{ struct servent *sp=getservbyname($3,"tcp");
							  if (!sp) {
								syslog(LOG_ERR,"No such service %s",$3);
								YYABORT;
							  }
							  if (newConfig.daemon.service)
							    free(newConfig.daemon.service);
							  newConfig.daemon.service=$3;
							  if (newConfig.daemon.port == -1)
							      newConfig.daemon.port=sp->s_port;
							}
		| dI T_PORT numSemi			{ if (!newConfig.daemon.service) {
							    register struct servent *sp=getservbyport(htons($3),"tcp");
							    if (!sp) {
								syslog(LOG_WARNING,"No service on %d, using 'socks'",$3);
								newConfig.daemon.service=strdup("socks");
							    } else {
								newConfig.daemon.service=strdup(sp->s_name);
							    }
							  }
							  newConfig.daemon.port=htons($3); 
							}
		| dI T_NAME strSemi			{ newConfig.daemon.name=$3; }
		| dI T_DIRECTORY strSemi		{ newConfig.daemon.directory=$3; }
		| dI T_UMASK numSemi			{ newConfig.daemon.umask=$3; }
		| dI T_NEGOTFILE strSemi		{ newConfig.daemon.negotFile=$3; }
		| dI T_PREFORK numSemi			{ newConfig.daemon.preFork=$3; }
		| dI T_NUMHELPER numSemi		{ newConfig.daemon.numHelper=$3; }
		| dI T_LISTEN numPair			{ if ($3.num1 < 1) {
							    syslog(LOG_WARNING,"Number of listeners set to 1");
							    $3.num1=1;
							  }
							  newConfig.daemon.minListen=$3.num1; 
							  if ($3.num2 > NEGOT_MAXSLOT) {
							    $3.num2=NEGOT_MAXSLOT;
							    syslog(LOG_WARNING,"Listners limited to %d\n",$3.num2);
							  }
							  newConfig.daemon.maxListen=$3.num2;
							}
		| dI T_CLIENT numPair	     		{ newConfig.daemon.minClient=$3.num1;
							  newConfig.daemon.maxClient=$3.num2;
							}
		| dI T_CLIENT_PER_MIN numSemi		{ newConfig.daemon.milliPerClient=60000/$3; }
		| dI T_USER userInfo
		| dI T_GROUP groupInfo
		| dI T_INETDSEC strOrNone		{ newConfig.daemon.inetdSecFile=$3; }
		| dI T_POLL timeOrNumSemi		{ newConfig.daemon.poll=$3; }
		| dI T_FLAGS START dF End

dF:			/* make it  recursive */
		| dF I_FLAG ';'				{ newConfig.daemon.flags|=$2; }
		;

env:	    	T_ENV START envList End			{ $$=$3; }
		;

envList:	envSemi					{ NEWLIST($$,$1); }
		| envList envSemi			{ ADDTOLIST($$,$2); }
		;

numPair:	START I_NUM ',' I_NUM End		{ $$.num1=$2; $$.num2=$4; }
		;

userInfo:	strSemi 				{ struct passwd *pw=getpwnam($1);
							  if (!pw) {
								syslog(LOG_ERR,"No such user %s",$1);
								YYABORT;
							  }
							  newConfig.daemon.uid=pw->pw_uid;
							  if (newConfig.daemon.gid == DEFAULT_GID )
							      newConfig.daemon.gid=pw->pw_gid;
							  free($1);
							}
		| numSemi 				{ newConfig.daemon.uid=$1; }
		;

groupInfo:	strSemi					{ struct group *gr=getgrnam($1);
							  if (!gr) {
								syslog(LOG_ERR,"No such group %s",$1);
								YYABORT;
							  }
							  newConfig.daemon.gid=gr->gr_gid;
							  free($1);
							}
		| numSemi				{ newConfig.daemon.gid=$1; }
		;

logI:				/* make it recurse */
		| logI T_FACIL strSemi			{ newConfig.log.facility=strToFacility($3); free($3); }
		| logI T_LEVEL numSemi			{ newConfig.log.level=$3; }
		| logI T_LOGFILE strOrNone		{ newConfig.log.logFile=$3; }
		| logI T_DUMPPREFIX strOrNone		{ newConfig.log.dumpPrefix=$3; }
		| logI T_DEBUG numSemi			{ debug=$3; }
		;
    
defI:			/* make it recurse */
		| defI T_TIMEOUT timeOrNumSemi		{ newConfig.defaults.timeOut=$3; }
		| defI T_SETUPTIMEOUT timeOrNumSemi	{ newConfig.defaults.setupTimeOut=$3; }
		| defI T_BUFSIZE numSemi		{ newConfig.defaults.bufSize=$3; }
		;

timeOrNumSemi:	numSemi
		| I_TIME ';'
		;

routeInfo:	routeElem				
		| routeInfo routeElem			{ APPENDTOLIST($$,$2); }
		;
		
routeElem:	START hostSpec ifaddr End		{ routeInfoType t; register int i;
							  t.ip=$3.list[0];
							  if ($3.num>1)
							    syslog(LOG_WARNING,
								    "More than one address for interface, using %s",
								    inetNtoa(t.ip));
							  t.host=$2.list[0]; NEWLIST($$,t);
							  for (i=1;i<$2.num; i++) {
							    t.host=$2.list[i];
							    ADDTOLIST($$,t);
							  }
							  free($2.list); free($3.list);
							}
		;

clients:	clientInfo				{ NEWLIST($$,$1); }
		| clients clientInfo			{ ADDTOLIST($$,$2); }
		;
		
clientInfo:	I_ACTION				{ memset(&clInfo,0,sizeof(clInfo)); clInfo.action=$1; goodSrc=0; }
		    request
		    START cliDefs End			{ $$=clInfo;
							  if (clInfo.action==ACTION_PERMIT && !goodSrc) {
							    syslog(LOG_ERR,"Lacking good source specification on permit line");
							    YYABORT;
							  }
							}
		;
request:			/* optional */
		| I_REQ					{ clInfo.request=$1; }
		| I_NUM					{ clInfo.request=$1; }
		;

cliDefs:			/* make it recursive */
		| cliDefs T_USER START users End	{ clInfo.users=$4; }
		| cliDefs T_SRC				{ goodEq=0; }
		    START hostlist End			{ clInfo.src=$5; goodSrc=goodEq; }
		| cliDefs T_DEST START hostlist End	{ clInfo.dest=$4; }
		| cliDefs T_PORT START portlist End	{ clInfo.port=$4; }
		| cliDefs T_CMD compStrOrNone		{ clInfo.cmd=$3; }
		| cliDefs T_TIMEOUT timeOrNumSemi	{ clInfo.timeOut=$3; }
		| cliDefs T_BUFSIZE numSemi		{ clInfo.bufSize=$3; }
		| cliDefs T_FLAGS numSemi 		{ clInfo.flags|=$3; }
		;

users:		strSemi					{ NEWLIST($$,$1); }
		| users strSemi				{ ADDTOLIST($$,$2); }
		;

hostlist:	hostSpec ';'				{ goodEq+=($1.list->op==r_eq && $1.list->mask); $$=$1; }
		| hostlist hostSpec ';'			{ goodEq+=($2.list->op==r_eq && $2.list->mask); APPENDTOLIST($$,$2); }
		;
		
hostSpec:	relop hostaddr				{ $$=makeHostSpec($1,-1,$2); if (!$$.list) YYABORT; }
		| relop rangeaddr '/' I_IP4 		{ $$=makeHostSpec($1,$4,$2); if (!$$.list) YYABORT; }
		| relop rangeaddr '/' I_NUM 		{ $$=makeHostSpec($1,$4?htonl(-(1<<(32-$4))):0,$2); if (!$$.list) YYABORT; }
		| T_DEFAULT				{ hostType t; t.op=r_eq; t.mask=t.value=0; NEWLIST($$,t);}
		;

relop:							{ $$= r_eq; }
		| E_RELOP
		;

hostaddrs:	ifaddr ';'
		| hostaddrs ifaddr ';'			{ APPENDTOLIST($$,$2); }
		;

ifaddr:		I_IP4					{ NEWLIST($$,$1); }
		| hostToken
		| S_STR					{ struct ifreq ifr;
							  register int localFd=socket(AF_INET,SOCK_DGRAM,0);
							  strncpy(ifr.ifr_name,$1,sizeof(ifr.ifr_name));
							  if (ioctl(localFd,SIOCGIFADDR,&ifr)==0) {
							      NEWLIST($$,((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr);
							  } else {
							      struct hostent *hp; 
							      register int i;
							      if ((hp=gethostbyname($1))==NULL) {
								    syslog(LOG_ERR,"No such interface or host");
								    YYABORT;
							      }
							      NEWLIST($$,*(int*)hp->h_addr_list[0]);
							      for (i=1; hp->h_addr_list[i]; i++)
								    ADDTOLIST($$,*(int*)hp->h_addr_list[i]);
							  }
							  free($1);
							  close(localFd);
							}
		;
		
rangeaddr:	hostaddr				{ $$=$1; }
		| I_NUM					{ NEWLIST($$,htonl($1<<24)); }
		| I_IPPREFIX				{ NEWLIST($$,$1); }
		;

hostaddr:	I_IP4					{ NEWLIST($$,$1); }
		| hostToken				{ $$=$1; }
		| S_STR					{ struct hostent *hp; 
							  register int i;
							  if ((hp=gethostbyname($1))==NULL) {
								syslog(LOG_ERR,"No such host");
								YYABORT;
							  }
							  NEWLIST($$,*(int*)hp->h_addr_list[0]);
							  for (i=1; hp->h_addr_list[i]; i++)
								ADDTOLIST($$,*(int*)hp->h_addr_list[i]);
							  free($1);
							}
		; 

hostToken:	T_HOST					{ struct hostent *hp;
							  char tmp[MAXPATHLEN];
							  register int i;
							  gethostname(tmp,sizeof(tmp));
							  if ((hp=gethostbyname(tmp))==NULL) {
								syslog(LOG_ERR,"No such host");
								YYABORT;
							  }
							  NEWLIST($$,*(int*)hp->h_addr_list[0]);
							  for (i=1; hp->h_addr_list[i]; i++)
								ADDTOLIST($$,*(int*)hp->h_addr_list[i]);
							}
		;


portlist:	port ';'				{ NEWLIST($$,$1); }
		| portlist port ';'			{ ADDTOLIST($$,$2); }
		;

port:		portNum 				{ $$.low=$1, $$.high=$1; }
		| portNum '-' portNum 			{ $$.low=$1, $$.high=$3; }
		;

portNum:	I_NUM					{ $$ = htons($1); }
		| S_STR					{ struct servent *sp=getservbyname($1,"tcp");
							  if (!sp) {
								syslog(LOG_ERR,"No such service %s",$1);
								YYABORT;
							  }
							  $$=sp->s_port;
							  free($1);
							}
		;

methods:	method_elem				{ NEWLIST($$,$1); }
		| methods method_elem			{ ADDTOLIST($$,$2); }
		;

method_elem:	START					{ memset(&methElem,0,sizeof(methElem)); }
		    methodComps End			{ $$=methElem;
							  if (loadMethInfo(&$$)) {
							    syslog(LOG_ERR,"Failed to load method %s\n",$$.name);
							    YYABORT;
							  }
							}
		;

methodComps:			/* make it recursable */	
		| methodComps T_NAME strSemi		{ methElem.name=$3; }
		| methodComps T_LIB strSemi		{ methElem.libName=$3; }
		| methodComps T_INTERNAL ';'		{ methElem.libName=NULL; }
		| methodComps T_NUMBER numSemi		{ if ($3<0 || $3>254) {
							    syslog(LOG_ERR,"Bad method number %d",$3);
							    YYABORT;
							  } else {
							    methElem.num=$3;
							  }
							}
		| methodComps T_FLAGS numSemi		{ methElem.flags=$3; }
		| methodComps env			{ methElem.env=$2; }
		;

cliMeths:	cliMethElem				{ NEWLIST($$,$1); }
		| cliMeths cliMethElem			{ ADDTOLIST($$,$2); } 
		;

cliMethElem:	START					{ memset(&clientMethElem,0,sizeof(clientMethElem)); }
		    cMComps End				{ $$=clientMethElem; }
		;

cMComps:			/* make it recursable */
		| cMComps T_SRC START hostlist End	{ clientMethElem.src=$4; }
		| cMComps T_METHOD START methList End	{ clientMethElem.methods=$4; }
		;

methList:	methodElem				{ NEWLIST($$,$1); }
		| methList methodElem			{ ADDTOLIST($$,$2); }
		;

methodElem:	strSemi					{ if (($$=findMethod(&newConfig,$1))==NULL) { YYABORT; } free($1); }
		;

numSemi:	I_NUM ';'
		;

envSemi:	S_ENV ';'
		;

strSemi:	S_STR ';'
		;

compStrOrNone:	strOrNone
		| S_COMPLEXSTR ';'
		;

strOrNone:	strSemi
		| T_NONE ';'				{ $$=NULL; }
		;

End:		'}' ';'
		| ';' '}' ';'		/* Allow an extra semicolon before the brace. */
		;

%%
/* } */
/******************************************************************
 *
 * defaultConfig() and cleanupConfig() conspire to fill in any
 * default values not specified in the config file.  defaultConfig()
 * is called at the start of things, and cleanupConfig() is called
 * just before yyparse() returns.  Accordingly, defaultConfig()
 * initializes all of the non-string values (after zeroing the
 * entire structure, and cleanupConfig sets any string values that
 * need to be, along with doing sanity checks, and possibly causing
 * the parsing of the config file to fail.
 *
 ******************************************************************/
void defaultConfig(void)
{
    memset(&newConfig,0,sizeof(newConfig));
    newConfig.daemon.uid=-2;
    newConfig.daemon.gid=DEFAULT_GID;
    newConfig.daemon.port=-1;		/* This will change if not specified */
    newConfig.daemon.minListen=1;
    newConfig.daemon.maxListen=NEGOT_MAXSLOT;
    newConfig.daemon.minClient=1;
    newConfig.daemon.maxClient=200;
    newConfig.daemon.poll=60;		/* one minute */
    newConfig.daemon.numHelper=1;
    newConfig.daemon.umask=002;

    newConfig.log.level=LG_STATS;
    newConfig.log.facility=LOG_DAEMON;

    newConfig.defaults.bufSize=32768;
    newConfig.defaults.timeOut=2*60*60;	/* default timeout */
    newConfig.defaults.setupTimeOut=15*60;

    newConfig.routes.num=0;
    newConfig.clients.num=0;
}
static int cleanupConfig(void)
{
    register int ret=0;

    if (!newConfig.routes.num) {
	syslog(LOG_ERR,"No routes in config file.");
	ret=1;
    }

    if (!newConfig.clients.num) {
	syslog(LOG_ERR,"No clients in config file.");
	ret=1;
    }

    if (!newConfig.daemon.name)
	newConfig.daemon.name=strdup("sockd");
    
    if (!newConfig.daemon.directory)
	newConfig.daemon.directory=strdup("/var/opt/socks");

    if (!newConfig.daemon.negotFile) {
	syslog(LOG_ERR,"No negotiate-file specified.");
	ret=1;
    }
    if (!newConfig.daemon.service) {
	struct servent *sp=getservbyname("socks","tcp");
	newConfig.daemon.service=strdup("socks");
	if (!sp) {
	    syslog(LOG_WARNING,"No such service socks, using 1080");
	    newConfig.daemon.port=htons(1080);
	} else {
	    newConfig.daemon.port=sp->s_port;
	}
    }
    if (newConfig.daemon.preFork > newConfig.daemon.maxListen) {
	syslog(LOG_WARNING,"Stupid pre-fork %d, chopping to %d", newConfig.daemon.preFork, newConfig.daemon.maxListen);
	newConfig.daemon.preFork = newConfig.daemon.maxListen;
    }
    if (!newConfig.log.logFile && newConfig.log.level) {
	syslog(LOG_WARNING,"No log file given, log level set to 0");
	newConfig.log.level=0;
    }

    if (newConfig.daemon.flags&FL_V4_ONLY)
	newConfig.daemon.numHelper=0;

    return ret;
}

/******************************************************************
 *
 * freeConfig() is responsible for making sure that rereading the
 * config file does not result in memory leaking out onto the
 * floor.  If there was anything malloc'ed (or strdup'ed) during
 * reading the config file, then we free it here.
 *
 ******************************************************************/
void freeConfig(configInfoType *cfg)
{
    register int i;

    free(cfg->daemon.listenAddr.list);
    free(cfg->daemon.name);
    free(cfg->daemon.directory);
    free(cfg->daemon.service);
    free(cfg->daemon.negotFile);
    if (cfg->daemon.inetdSecFile)
	free(cfg->daemon.inetdSecFile);
    if (cfg->log.logFile)
	free(cfg->log.logFile);
    if (cfg->log.dumpPrefix)
	free(cfg->log.dumpPrefix);
    if (cfg->routes.num) {
	free(cfg->routes.list);
	cfg->routes.list=NULL;
	cfg->routes.num=0;
    }
    if (cfg->env.num) {
	register int j;
	for (j=cfg->env.num-1;j>=0;j--)
	    free(cfg->env.list[j]);
	free(cfg->env.list);
	cfg->env.list=NULL;
    }
    if (cfg->methods.num) {
#if 0
	/* we have to leak the method data, since there may be references
	 * to it from fdInfo[]...  One small leak per config file reload.
	 */
	for (i=cfg->methods.num-1;i>=0;i--) {
	    free(cfg->methods[i].name);
	    if (cfg->methods[i].libName)
		free(cfg->methods[i].libName);
	    cfg->methods[i].name=cfg->methods[i].libName=NULL;
	    if (cfg->methods[i].env.num) {
		register int j;
		for (j=cfg->methods[i].env.num-1;j>=0;j--)
		    free(cfg->methods[i].env.list[j]);
		free(cfg->methods[i].env.list);
		cfg->methods[i].env.list=NULL;
	    }
	}
	free(cfg->methods.list);
#endif 
	cfg->methods.list=NULL;
    }
    if (cfg->cliMeth.num) {
	for(i=cfg->cliMeth.num-1;i>=0;i--) {
	    register int j;
	    free(cfg->cliMeth.list[i].src.list);
	    cfg->cliMeth.list[i].src.list=NULL;
	    if (cfg->cliMeth.list[i].methods.num) {
		free(cfg->cliMeth.list[i].methods.list);
		cfg->cliMeth.list[i].methods.list=NULL;
	    }
	}
	free(cfg->cliMeth.list);
	cfg->cliMeth.list=NULL;
    }
    if (cfg->clients.num) {
	for (i=cfg->clients.num-1;i>=0;i--) {
	    register int j;
	    if (cfg->clients.list[i].users.num) {
		for (j=cfg->clients.list[i].users.num-1;j>=0;j--)
		    free(cfg->clients.list[i].users.list[j]);
		free(cfg->clients.list[i].users.list);
		cfg->clients.list[i].users.list=NULL;
	    }
	    if (cfg->clients.list[i].src.num) {
		free(cfg->clients.list[i].src.list);
		cfg->clients.list[i].src.list=NULL;
	    }
	    if (cfg->clients.list[i].dest.num) {
		free(cfg->clients.list[i].dest.list);
		cfg->clients.list[i].dest.list=NULL;
	    }
	    if (cfg->clients.list[i].port.num) {
		free(cfg->clients.list[i].port.list);
		cfg->clients.list[i].port.list=NULL;
	    }
	    if (cfg->clients.list[i].cmd)
		free(cfg->clients.list[i].cmd);
	}
	free(cfg->clients.list);
	cfg->clients.list=NULL;
	cfg->clients.num=0;
    }
}

/******************************************************************
 *
 * strToFacility() takes the user specified name and turns it into
 * something that we can use.  facilityToStr() reverses the process.
 *
 ******************************************************************/
int strToFacility(char *name)
{
    if (strcmp(name,"daemon")==0)	{ return LOG_DAEMON; }
    else if (strcmp(name,"local0")==0)	{ return LOG_LOCAL0; }
    else if (strcmp(name,"local1")==0)	{ return LOG_LOCAL1; }
    else if (strcmp(name,"local2")==0)	{ return LOG_LOCAL2; }
    else if (strcmp(name,"local3")==0)	{ return LOG_LOCAL3; }
    else if (strcmp(name,"local4")==0)	{ return LOG_LOCAL4; }
    else if (strcmp(name,"local5")==0)	{ return LOG_LOCAL5; }
    else if (strcmp(name,"local6")==0)	{ return LOG_LOCAL6; }
    else if (strcmp(name,"local7")==0)	{ return LOG_LOCAL7; }
    else if (strcmp(name,"kern")==0)	{ return LOG_KERN; }
    else if (strcmp(name,"user")==0)	{ return LOG_USER; }
    else if (strcmp(name,"mail")==0)	{ return LOG_MAIL; }
    else if (strcmp(name,"auth")==0)	{ return LOG_AUTH; }
    else if (strcmp(name,"syslog")==0)	{ return LOG_SYSLOG; }
    else if (strcmp(name,"lpr")==0)	{ return LOG_LPR; }
    else {
	syslog(LOG_WARNING,"Unknown facility %s, using daemon",name);
	return LOG_DAEMON;
    }
    
}
char* facilityToStr(int facil)
{
    if (facil==LOG_DAEMON) { return "daemon"; }
    else if (facil==LOG_LOCAL0) { return "local0"; }
    else if (facil==LOG_LOCAL1) { return "local1"; }
    else if (facil==LOG_LOCAL2) { return "local2"; }
    else if (facil==LOG_LOCAL3) { return "local3"; }
    else if (facil==LOG_LOCAL4) { return "local4"; }
    else if (facil==LOG_LOCAL5) { return "local5"; }
    else if (facil==LOG_LOCAL6) { return "local6"; }
    else if (facil==LOG_LOCAL7) { return "local7"; }
    else if (facil==LOG_KERN) { return "kern"; }
    else if (facil==LOG_USER) { return "user"; }
    else if (facil==LOG_MAIL) { return "mail"; }
    else if (facil==LOG_AUTH) { return "auth"; }
    else if (facil==LOG_SYSLOG) { return "syslog"; }
    else if (facil==LOG_LPR) { return "lpr"; }
    else { return "unknown"; }
}

/******************************************************************
 *
 * Not much of an error handler, but, hey, it's what we have.
 *
 ******************************************************************/
yyerror(char *s)
{
    fprintf(stderr,"%s\nLast tokens were:\n",s);
    dumpTokens();
    syslog(LOG_ERR,"%s\n",s);
}
/******************************************************************
 *
 * findMethod() takes a method by name and tracks it down.
 * config file does not result in memory leaking out onto the
 * floor.  If there was anything malloc'ed (or strdup'ed) during
 * reading the config file, then we free it here.
 *
 ******************************************************************/
methodInfoType *findMethod(configInfoType *cfg,char *name)
{
    methodInfoType *m=cfg->methods.list;
    register int i=cfg->methods.num;
    for (;i>0;i--,m++) {
	if (strcmp(name,m->name)==0)
	    return m;
    }
    syslog(LOG_ERR,"Could not find method %s",name);
    return NULL;
}

extern int zzlex(void);
#define MAX_TOKEN_HIST 30
int tokenHistory[MAX_TOKEN_HIST];
int tokenValues[MAX_TOKEN_HIST];
int tokenHistNext;
int tokenHistWrapped;
int yylex(void)
{
    register int token=zzlex();

    tokenValues[tokenHistNext]=yylval.iVal;
    tokenHistory[tokenHistNext++]=token;
    if (tokenHistNext>=MAX_TOKEN_HIST) {
	tokenHistNext=0;
	tokenHistWrapped=1;
    }
    return token;
}
void dumpTokens(void)
{
    register int i= tokenHistWrapped ? tokenHistNext : 0;
    do {
	if (tokenHistory[i]==START) {
	    fprintf(stderr,"{ ");
	} else if (tokenHistory[i]<256) {
	    if (tokenHistory[i]=='{')
		fprintf(stderr,"LBRACE!!");
	    else
		putc(tokenHistory[i],stderr);
	} else {
	    switch (*(yyname[tokenHistory[i]])) {
		case '\'':
		    putc(yyname[tokenHistory[i]][1],stderr);
		    break;
		case 'E':
		    fprintf(stderr," enum(%u)",tokenValues[i]);
		    break;
		case 'I':
		    fprintf(stderr," %u",tokenValues[i]);
		    break;
		case 'T':
		    putc('\n',stderr);
		    /* fall through */
		default:
		    fprintf(stderr,"%s ",yyname[tokenHistory[i]]);
		    break;
	    }
	}
	if (++i>=MAX_TOKEN_HIST)
	    i=0;
    } while (i!=tokenHistNext);

    putc('\n',stderr);
}
static hostLType makeHostSpec(relopType op, long mask, longLType list)
{
    hostLType ret;
    register hostType *p;
    register long *s;
    register int i;

    ret.num=list.num;
    ret.list=malloc(sizeof(hostType)*list.num);

    if (ret.list==NULL) {
	syslog(LOG_ERR,"Out of memory in parser");
	return ret;
    }

    for (i=0,p=ret.list,s=list.list;i<list.num;i++,p++,s++) {
	p->op=op, p->mask=mask, p->value=(*s&mask);
    }
    free(list.list);
    return ret;
}
