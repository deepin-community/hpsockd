#include "sockd.h"

#ifndef __lint
static char *vers="@(#)$Header: /var/cvs/hpsockd/src/sockd/methods.c,v 0.13 2000/12/08 20:47:24 lamont Exp $";
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


#ifdef HAVE_SHL_LOAD
#include "dl.h"
#elif defined(HAVE_DLOPEN)
#include <dlfcn.h>
#endif

intMethInfoType intMethods[]= {
	{ "v4",		v4Info },
	{ "noAuth",	noAuthInfo},
	{ "userPass",	userPassInfo},
	{ NULL,		NULL}
};

int loadMethInfo(methodInfoType *mInfo)
{
    register intMethInfoType *meth=intMethods;
    register char *name=mInfo->name;

    mInfo->info=NULL;

#ifdef FULLMETHOD
    mInfo->recv=recv; mInfo->send=send; mInfo->excp=nullExcp;
#endif
    mInfo->inboundUdp=v5InboundUdpReq, mInfo->outputUdp=v5OutputUdpReply;
    mInfo->recvFrom=(recvFromFunc*)recvfrom, mInfo->sendTo=(sendToFunc*)sendto;

    if (mInfo->libName) {
	register char *infoName;
#ifdef HAVE_SHL_LOAD
	shl_t handle=shl_load(mInfo->libName,BIND_IMMEDIATE,0);
#elif defined(HAVE_DLOPEN)
	void *handle=dlopen(mInfo->libName,RTLD_NOW);
#else
	void *handle;
	return -1;
#endif

	if (!handle)
	    return -1;
	
	infoName=malloc(strlen(name)+5);
	if (infoName==NULL) {
	    syslog(LOG_ERR,"Out of memory in loadMethInfo");
	    return -1;
	}
	sprintf(infoName,"%sInfo",name);

#ifdef HAVE_SHL_LOAD
	if (shl_findsym(&handle,infoName,TYPE_PROCEDURE,&mInfo->info)<0) {
#elif defined(HAVE_DLOPEN)
	if (!(mInfo->info=(infoFunc*)dlsym(handle,infoName))) {
#else
	{
#endif
	    free(infoName);
	    return -1;
	}
	free(infoName);
    } else {
	while (meth->name) {
	    if (strcmp(meth->name,name)==0) {
		mInfo->info=meth->info;
		break;
	    }
	    meth++;
	}
	if (!mInfo->info)
	    return -1;
    }
    return mInfo->info(mInfo,METHOD_VERSION);
}
/********************************************************************************************
 * Find the method that we will agree to use for this client.  Once we find a source that
 * matches the client, we run through that method list until we find one that is included
 * in methData (from the client).  If we don't find anything, we leave.
 *
 * The v4 code passes in a version of SOCKS_V4, 1 method, "v4".
 *******************************************************************************************/
methodInfoType *findMatchingMethod(struct sockaddr_in *sin,u_char *methData)
{
    register int i,j,k,l;

    for (i=0;i<config.cliMeth.num;i++) {
	for (j=0;j<config.cliMeth.list[i].src.num;j++) {
	    if (compareAddr(config.cliMeth.list[i].src.list+j,sin->sin_addr.s_addr)) {
		/* Find the first method that is in methData */
		for (k=0;k<config.cliMeth.list[i].methods.num;k++) {
		    register int num=config.cliMeth.list[i].methods.list[k]->num;
		    for (l=0;l<methData[1];l++) {
			if (methData[l+2]==num) {
			    return config.cliMeth.list[i].methods.list[k];
			}
		    }
		}
		/* At this point, we have a source description that matches, but could not find a
		 * method we liked.  Nuke him.
		 */
		return NULL;
	    }
	}
    }
    return NULL;
}
