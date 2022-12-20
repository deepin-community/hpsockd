#include "sockd.h"
#include "v5.h"

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/userpass.c,v 0.16 2001/05/14 14:31:21 lamont Exp $";
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

#define USERPASS_VERSION 1

inboundFunc v5UserPassNegotiate;
static DB *userDB=NULL;

int userPassInfo(methodInfoType *info,int version)
{
    if (version!=METHOD_VERSION)
	return -1;
    info->negotiate=v5UserPassNegotiate;
#if FULLMETHOD
    info->TCP_INBOUND=simpleInbound;
    info->TCP_OUTPUT=simpleOutput;
#endif
    return 0;
}

/*************************************************************
 * +----+------+----------+------+----------+
 * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 * +----+------+----------+------+----------+
 * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 * +----+------+----------+------+----------+
 *************************************************************/

int v5UserPassInit(fdInfoType *client, unsigned int flags)
{
    register const char *name=getEnv(client,"USERPASSDB_PATH");
    if (!name)
	name=USERPASSDB_PATH;
    userDB=dbopen(name,O_RDONLY,0600,DB_HASH,NULL);
    if (!userDB) {
	syslog(LOG_ERR,"userpass: Unable to open database %s: %m",name);
	return -1;
    }
    return 0;
}

int v5UserPassAuth(fdInfoType *client, char *user,const char *pass, unsigned int flags)
{
    int ret=SOCKS5_DENIED;
    DBT key,data;
    register int dbRes;
    key.data = user;
    key.size = strlen(user);
    dbRes=userDB->get(userDB,&key,&data,0);

    if(dbRes<0) {
	syslog(LOG_ERR,"userpass: db error on get: %m");
    } else if (dbRes>0) {
	syslog(LOG_WARNING,"userpass: %s not known",user);
    } else if (data.size==strlen(pass) && memcmp(data.data,pass,data.size)==0) {
	ret=0;
    } else {
	syslog(LOG_WARNING,"userpass: Bad password for user %s",user);
    }
    return ret;
}
/* inboundFunc */
/* ARGSUSED */
void v5UserPassNegotiate(fdInfoType *client,void *buf,int len,unsigned int flags)
{
    register int        l;                   
    register int        present;                              
    register char       *user;
    register char       *pass;
    register int        ret=SOCKS5_DENIED;
    u_char		req[256+256+4];                       
    u_char		reply[2];

    addToBuffer(client,&client->in,buf,len);               

    if (!userDB) {
	v5UserPassInit(client, flags);
    }
    present=client->in.dataLen;
    
    if (present<3 || present<(l=3+client->in.dataStart[1]) ||
		present<(l=l+client->in.dataStart[l-1]))
        return;

    client->TCP_INBOUND=simpleInbound;
    getFromBuffer(&req,&client->in,l,0);
    req[l]='\0';

    user=(char*)req+2;
    pass=user+user[-1]+1;
    pass[pass[-1]]='\0';
    pass[-1]='\0';
    client->conn->user=strdup(user);

    if (*req==USERPASS_VERSION) {
	ret=v5UserPassAuth(client,user,pass,flags);
    } 

Bailout:
    reply[0]=USERPASS_VERSION;
    reply[1]=ret;

    client->TCP_OUTPUT(client,(void*)&reply,sizeof(reply),0);
    if (ret) {
	pendingClose(client,ret);
    }
}
