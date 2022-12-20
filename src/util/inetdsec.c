
#if !defined(__lint)
static char *RCSid = "@(#)$Header: /var/cvs/hpsockd/src/util/inetdsec.c,v 0.5 2000/12/08 20:49:44 lamont Exp $";
#endif

/*
(c) Copyright 1988, 1997-2000, Hewlett-Packard Company.

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
/*
 * header files
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>

typedef unsigned char byte;

int DoInetdSec(char *,struct sockaddr_in,char *);

static caddr_t attachline(void);
static int internet_parse(caddr_t, byte *, caddr_t);
static caddr_t nextline(int);
static int readsecfile(caddr_t);

#define TRUE 1
#define FALSE 0
#define SIZLINE 8192

static int readsec = 0;		/* If 0, security file has not been read yet */
struct stat lastread;		/* Last modification time when file last read */

struct secinfo {
     int allowed;
     char *list;
} safe;

FILE *securep;

 /*                                                                      */
 /* Secure returns: -1 for a remote host that failed the security check  */
 /*		-2  stat call on security file failed		*/
 /*		1 when there is no security file to check		*/
 /*		and 0 when the remote host passed the security check.*/
int DoInetdSec(char *service, struct sockaddr_in from, char *security_file)
{
	struct stat	lastmod; /* last modification time for security */
				/* file right now.	*/
	char	*p, *addrpointer;
	long	netaddr;
	int 	parsed;
	struct	hostent	*hostname;
	struct	netent	*netname;
	char buf[BUFSIZ];
	char *lastp;

	if (stat(security_file, &lastmod) == -1) {
		if (errno == ENOENT)
			return 1;

		return -2;
	}

	if (!readsec || lastmod.st_mtime != lastread.st_mtime) {
		readsec = TRUE;

		securep = fopen(security_file, "r");

		if (securep == NULL)
			return -2;

		if (!readsecfile(service)) {
			fclose(securep);
			(void)stat(security_file, &lastread);
			return 0;	/* entry not found, allowed */
		}

		fclose(securep);
		(void)stat(security_file, &lastread);
	}

	if (safe.list==NULL)
	    return 0;	/* entry not found, allowed */

	/* find correct address to match remote host address */

	addrpointer = inet_ntoa(from.sin_addr);
#ifdef MSDOS
	hostname = gethostbyaddr((struct in_addr far *)&from.sin_addr,
				 sizeof(struct in_addr), from.sin_family); 
#else
	hostname = gethostbyaddr((const char *)&from.sin_addr,
				 sizeof(struct in_addr), from.sin_family); 
#endif /*MSDOS*/
	netaddr = inet_netof(from.sin_addr);
	netname = getnetbyaddr(netaddr, AF_INET);
	(void)strcpy(buf, safe.list);
	lastp = &buf[strlen(buf)];
	p = strtok(buf, " \t");

	while (p != NULL) {
		/* if list member matches address, hostname or */
		/* netname of the remote host, the remote host */
		/* is allowed.				*/
		if (!strcmp(p, addrpointer) ||
		    (hostname != NULL && !strcasecmp(p, hostname->h_name)) || 
		    (netname != NULL && !strcasecmp(p, netname->n_name))) {
			if (safe.allowed)			
				return 0;
			else
				return -1;
		}

		/* Check for ranges and wild card characters */

		parsed = internet_parse(p, (byte *)&from.sin_addr, service);

		if (parsed == 1) {
			if (safe.allowed)
				return 0;
			else
				return -1;
		}

		/* if the list member doesn't match anything, get  */
		/* next list member.				*/
		/* strtok() is used in internet_parse() which causes */
		/* problems because it overwrites the state we had so */
		/* we need to specify the buffer again. */
		p = &p[strlen(p)];

		if (p == lastp)
			break;

		p = strtok(&p[1], " \t");
	} /* end of while */

	/* if the service was found but the host we are looking */
	/* for is not in list, then if it was a list of allowed */
	/* hosts the host is not allowed, and if it was a list  */
	/* of hosts not allowed, the host is allowed.	*/

	if (safe.allowed)
		return -1;		/* bad host  */

	return 0;
} /* end of DoInetdSec */

/*** Internet_parse written Feb., 1986 by Cristina Mahon and Darren Smith    **/

/*** routine to take a string, which represents an entry in the 	**/
/*** security file, and a pointer to an address in Internet format (i.e four **/
/*** bytes), and return an indication of whether the address matches the     **/
/*** string, where the string can have wild cards and ranges  		**/

/*** returns a -1 in case of config error, a zero if it doesn't match        **/
/*** and a 1 if it succeeds. 						**/

static internet_parse(char *string,byte *addr,char *service)
{
	int i;

	/***** low, high, num, and addr are defined as unsigned chars to get **/
	/***** the proper conversion, otherwise the byte vallues in chars ***/
	/***** are converted to integers, which screws up the signs. **/

	byte low, high;
	byte num;
	char *cp;
	char store[100];  /*** internet specifies 60 chars, + some ***/
	char *list[4];

	/*** If this is not an address: for example hostname or netname */
	/*** return with no match.					*/

	if ( strspn(string,"0123456789-*.") != strlen(string) )
		return(0);

	/** save string before we destroy it! */
	strncpy(store,string,sizeof(store));

	cp = strtok(store,".\0");
	for (i=0;i<4;i++) {
		list[i]=cp;
		cp = strtok(NULL,".\0");
		if ( cp == NULL || *cp == '\0')
			cp = "*";
	}

	for (i=0;i<4; i++) {

		/*** check for wild card.  Only if it is exactly the **/
		/*** string "*" will it match. ***/

		if ( strcmp(list[i],"*") == 0 )
			continue;

		/*** if it still contains a wild card, make it an error **/


		if ( strchr(list[i],'*') != NULL )
		{
			return(-1);
		}

		/*** check for a string with a range of numbers.  **/
		/*** no error checking for blanks, etc. **/

		if ( (cp = strchr(list[i],'-')) != NULL ) {
			if( cp == list[i] ) /** no first number **/
			{
				return(-1);
			}

			*cp = (char)NULL;
			cp++ ;

			if ( *cp == '\0' ) /** no second number **/
			{
				return(-1);
			}

			/** get the two numbers **/
			low  = (byte)atoi(list[i]);
			high = (byte)atoi(cp);

			/*** this is a hack.  We needed to pick out the **/
			/*** four bytes in the in_addr structure and compare **/
			/*** them one at a time.  Since in_addr is not a **/
			/*** array, we kludged it to look like an array **/
			/*** of chars, which will be converted to integers **/
			/*** by C when it does the actual comparison. SIGH **/
			if( low <= addr[i] && addr[i] <= high )
				continue;
			else
				if ( high < low )
				{
					return(-1);
				}
				else
					return(0);

		} /*** end of if strchr(string,'-') **/

		/**** check for the number exactly ***/

		num = (byte)atoi(list[i]);
		if ( num == addr[i] )
			continue;
		else
			return(0);

	} /***** end of for i = 0 to 3 ***/

	/*** if made it this far, it succeeded ***/

	return(1);

} /*** end of internet_parse ***/

/* read the security file and fill the security structure with information */

static int readsecfile(char *service)
{
	char	*cp, *saveline;
	int 	lensafe;	/* size of the list of hosts */

	safe.allowed = FALSE;
	if (safe.list) free(safe.list);
	safe.list = NULL;

	while (TRUE) {
		if ((saveline = attachline()) == NULL)
			break;

		/* find service name */

		if ((cp = strtok(saveline," \t\n")) == NULL) {
			free(saveline);
			continue;
		}

		if (!strcmp(service, cp))
			break;
		else
			free(saveline);
	} /* while */

	if (saveline == NULL)
		return 0;

	if ((cp = strtok(NULL," \t\n")) == NULL) {
		free(saveline);
		return 1;
	}

	if (!strcasecmp(cp, "allow"))
		safe.allowed = TRUE;
	else if (!strcasecmp(cp, "deny"))
		safe.allowed = FALSE;
	else {
		free(saveline);
		return 1;
	}

	while (*cp != '\0')
		cp++;

	cp++;

	while ((*cp == ' ')|| (*cp == '\t'))
		cp++;

	if ((*cp == '\n') || (*cp == '\0')) {
		free(saveline);
		return 1;
	}

	safe.list = strdup(cp);
	free(saveline);
	lensafe = strlen(safe.list);

	if (safe.list[lensafe - 1] == '\n')
		safe.list[lensafe - 1] = '\0';

	return 1;
} /* readsecfile */

static char * attachline(void)
{
	char *p, *cp, *saveline;
	int len, newlen, i;

	/* get the next line ignoring blank lines */
	if ((p = nextline(1)) == NULL)
		return (char *)NULL;

	while (*p == ' ' || *p == '\t')
		p++;		/* skip any initial blanks */
	saveline = strdup(p);
	cp = saveline;
	while (*cp != '\n')
	{
		if (*cp == '\\')
		{
			*cp = ' ';
			cp++;
			if (*cp == '\n')
			{
				len = cp - saveline;
			/* get the next line taking into account blank lines */
				p = nextline(0);
				newlen = strlen(p);
				cp = saveline =(caddr_t)realloc(saveline,len+1+newlen+1);
				for (i=1; i<=len; i++)
					cp++;
				strcpy(cp,p);
				if (*p == '\n')
					return(saveline);
			}
		}
		cp++;
	}
	return(saveline);

} /* end of attachline */


char *inetd_line=NULL;
/* Get next line of the configuration file */

static char * nextline(int ignoreblklines)
{
	char *cp;
	
	if (inetd_line==NULL)
		inetd_line=(char*)malloc(SIZLINE+1);

	while (TRUE)
	{
		if ((cp = fgets(inetd_line,SIZLINE, securep)) == NULL)
			return (char *)NULL;

		/* ignore blank lines unless we are attaching to previous */
		/* line in which case it should not be ignored */
		if ((*cp == '\n') && (ignoreblklines))
			continue; 		/* skip blank lines */
		if ((*cp == '#') && (ignoreblklines))
			continue;		/* skip comment lines */
		if (strlen(cp) == strspn(cp, " \t\f\r\n"))
			continue;		/* skip blank lines */
		return(inetd_line);
	}
} /* end of nextline */
