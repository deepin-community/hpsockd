#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "btree.h"

#ifndef __lint
static char  rev[] = "@(#) btree.c  $Header: /var/cvs/hpsockd/src/util/btree.c,v 0.3 2000/12/08 20:49:44 lamont Exp $";
#endif

/*
(c) 1993-2000 Hewlett-Packard Company.

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

typedef struct node node_t;
typedef struct elem elem_t;
struct elem {
	void	*key;
	union	{
		node_t	*child;	/* pointer to next layer */
		void	*data;	/* pointer to data */
	} p;
};

#ifndef E_PER_N
#define E_PER_N	64
#endif
typedef enum { n_leaf,n_interior } ntype_t;
struct node {
/*+00*/	node_t	*left,*right;
/*+08*/	node_t	*parent;
/*+0c*/	short	nel;
/*+0e*/	ntype_t n_type;
/*+10*/	elem_t	e[E_PER_N];
};

#define CMP int (*cmp)(void *k1,void *k2)
static int find_ix P_((node_t *pn,void* key, CMP, int *rv));
static node_t *put_entry P_((node_t **root,node_t *pn,int ix, void *key,
	void *data, CMP));
static node_t *search P_((node_t **root,node_t *pn,void *key, void *data,
	CMP,int flags,void **user_ret));

#define SEQ_SWITCHOVER 2

#ifdef BT_PROTOTYPES
static int find_ix(node_t *pn,void* key, CMP,int *rv)
#else
static int find_ix(node_t *pn,void* key, CMP,rv)
node_t *pn;
void* key;
int (*cmp)();
int *rv;
#endif
{
	register int rval=-1;
	register int l,h,chk;

/* find_ix searches the node whose address is passed as the pn parameter
 * to determine where to place the new 'key'
 * 
 * cmp returns are modeled after strcmp; <0 if key1 < key2, etc.
 * 
 * find_ix returns the index of the largest entry in the 'e' array
 * which is <= the supplied key,  or -1 if the node is empty or if
 * the input key is less than the lowest entry in the node.
 * The idea is that the new key would be added after the index'd
 * entry whose index we return.
 */

	if (pn->nel==0 || (rval=cmp(key,pn->e[0].key))<=0) {
		if (rv!=NULL) *rv=rval;
		return (rval==0) ? 0 : -1;
	}
	
	l=0;
	h=pn->nel;
	while (h-l > SEQ_SWITCHOVER) {
		chk=l+(h-l)/2;
		if ((rval=cmp(key,pn->e[chk].key))<0)
			h=chk;
		else if (rval==0) {
			if (rv!=NULL) *rv=rval;
			return chk;
		} else
			l=chk;
	}
	while (h>l+1 && (rval=cmp(key,pn->e[h-1].key))<=0) {
		h--;
		if (rval==0) {
			if (rv!=NULL) *rv=rval;
			return h;
		}
	}
	if (rv!=NULL) *rv=rval;
	return h-1;
}

static void fix_keys (node_t *pn,void *okey,CMP)
{
	register int nix;
	register node_t *n=pn->parent;
	register void *nkey=pn->e[0].key;

	if (pn->nel==0)
		return;

	while (n != NULL) {
		nix=find_ix(n,okey,cmp,NULL);
		n->e[nix].key=nkey;
		if (nix != 0)
			n=NULL;
		else
			n=n->parent;
	}
}

#ifdef BT_PROTOTYPES
static node_t *put_entry(node_t **root,node_t *pn,int ix, void *key,
	void *data, CMP)
#else
static node_t *put_entry(root,pn,ix, key, data,cmp)
node_t **root;
node_t *pn;
int ix;
void *key;
void *data;
int (*cmp)();
#endif
{
	register node_t *newNode;
	/* insert the key/data pair into the node after the ix'th spot */

	/* If the new entry will fit in the current node, add it */
	if (pn->nel<E_PER_N) {
		if (pn->nel-ix-1>0)
			(void)memmove(pn->e+ix+2,pn->e+ix+1,
				(pn->nel-ix-1)*sizeof(elem_t));
		pn->e[ix+1].key=key;
		pn->e[ix+1].p.data=data;
		pn->nel++;

		/* if this is a new lowest entry, follow the parent chain
		 * up, fixing their keys. */
		if (ix==-1)
			fix_keys(pn,pn->e[1].key,cmp);
		return NULL;
	}
	/* No room in this node, see if there's room in the siblings. */
	if (pn->right != NULL && pn->right->nel < E_PER_N) {
		newNode=pn->right;
		(void)memmove(newNode->e+1,newNode->e,newNode->nel*sizeof(elem_t));
		newNode->nel++;
		if (ix==E_PER_N-1) {
			newNode->e[0].key=key;
			newNode->e[0].p.data=data;
			if (newNode->n_type == n_interior)
				newNode->e[0].p.child->parent=newNode;
			fix_keys(newNode,newNode->e[1].key,cmp);
			return NULL;
		} else {
			newNode->e[0].key=pn->e[E_PER_N-1].key;
			newNode->e[0].p.data=pn->e[E_PER_N-1].p.data;
			pn->nel--;
			fix_keys(newNode,newNode->e[1].key,cmp);
			if (newNode->n_type == n_interior)
				newNode->e[0].p.child->parent=newNode;
			/* this time we'll have room. */
			return put_entry(root,pn,ix,key,data,cmp);
		}
	}
	/* How about the left sibling */
	if (pn->left != NULL && pn->left->nel < E_PER_N) {
		newNode=pn->left;
		newNode->e[newNode->nel].key=pn->e[0].key;
		newNode->e[newNode->nel].p.data=pn->e[0].p.data;
		if (newNode->n_type == n_interior)
			newNode->e[newNode->nel].p.child->parent=newNode;
		newNode->nel++;
		if (ix>0)
			(void)memmove(pn->e,pn->e+1,ix*sizeof(elem_t));
		pn->e[ix].key=key;
		pn->e[ix].p.data=data;
		fix_keys(pn,newNode->e[newNode->nel-1].key,cmp);
		return NULL;
	}

	/* Split the node, which may involve more splitting... */
	newNode=(node_t*)calloc(1,sizeof(node_t));
	assert(newNode!=NULL);
	newNode->parent=pn->parent;
	newNode->left=pn;
	newNode->right=pn->right;
	if (pn->right != NULL)
		pn->right->left=newNode;
	pn->right=newNode;
	newNode->n_type=pn->n_type;
	newNode->nel=E_PER_N/2;
	pn->nel-=newNode->nel;
	(void)memcpy(newNode->e,pn->e+pn->nel,newNode->nel*sizeof(elem_t));
	if (newNode->n_type == n_interior) {
		register int i;
		for (i=0;i<newNode->nel;i++) 
			newNode->e[i].p.child->parent=newNode;
	}

	if (ix >= pn->nel) {
		ix-=pn->nel;
		if (newNode->nel-ix-1>0)
			(void)memmove(newNode->e+ix+2,newNode->e+ix+1,
				(newNode->nel-ix-1)*sizeof(elem_t));
		newNode->e[ix+1].key=key;
		newNode->e[ix+1].p.data=data;
		newNode->nel++;
		if (newNode->n_type== n_interior)
			newNode->e[ix+1].p.child->parent=newNode;
	} else {
		if (pn->nel-ix-1>0)
			(void)memmove(pn->e+ix+2,pn->e+ix+1,
				(pn->nel-ix-1)*sizeof(elem_t));
		pn->e[ix+1].key=key;
		pn->e[ix+1].p.data=data;
		pn->nel++;

		/* if this is a new lowest entry, follow the parent chain
		 * up, fixing their keys. */
		if (ix==-1)
			fix_keys(pn,pn->e[1].key,cmp);
	}
	/* if we just split the root, then make a new one. */
	if (pn == *root) {
		*root=(node_t*)calloc(1,sizeof(node_t));
		assert(*root!=NULL);
		(*root)->nel		= 2;
		(*root)->n_type		= n_interior;
		(*root)->e[0].key	= pn->e[0].key;
		(*root)->e[0].p.child	= pn;
		(*root)->e[1].key	= newNode->e[0].key;
		(*root)->e[1].p.child	= newNode;
		pn->parent=newNode->parent	= *root;
	}

	/* return newNode, so the caller can insert that in the parent. */
	return newNode;
}

#ifdef BT_PROTOTYPES
static node_t *search(node_t **root,node_t *pn,void *key, void *data,
	CMP, int flags, void **user_ret)
#else
static node_t *search(root,pn, key, data, cmp, flags, user_ret)
node_t **root;
node_t *pn;
void *key;
void *data,**user_ret;
int (*cmp)();
int flags;
#endif
{
	int rval;
	register int ix=find_ix(pn,key,cmp,&rval);

	if (pn->n_type==n_interior) {
		register nix=ix;
		register node_t *n;
		if (nix==-1) nix=0;
		if ((n=search(root,pn->e[nix].p.child,key,data,cmp,
					flags,user_ret)) != NULL) {
			nix=find_ix(pn,n->e[0].key,cmp,NULL);
			return put_entry(root,pn,nix,n->e[0].key,
					 (void*)n,cmp);
		}
		return NULL;
	} else {
		register node_t *n=NULL,*nn=pn;
		register void *okey0=(pn->nel ? pn->e[0].key : key);
		if (user_ret != NULL)
			*user_ret=NULL;

		if (rval != 0) { 	/* couldn't find the beast */
			if ((flags & BT_INS)) {
				n=put_entry(root,pn,ix,key,data,cmp);

		/* if we shifted one entry to the left sibling, then
		   the e[0].key will have changed; otherwise, our entry
		   is the one after ix. */

				if (ix < 0 || pn->e[0].key == okey0)
					ix++;
			}
			else if (!(flags&BT_CLOSE))
				return NULL;
		}

		if (flags&BT_INS) {
			/* if we're outside the bounds of the node, then we must
			   have split */
			if (ix >= pn->nel) {
				nn=pn->right;
				ix=ix-pn->nel;
			}

			/* was this a previously deleted key? */
			if (nn->e[ix].p.data == NULL)
				nn->e[ix].p.data=data;
		}
		
		if (user_ret != NULL)
			*user_ret = nn->e[ix].p.data;

		if ((flags & BT_DEL)) {
			/* XXX - just mark it deleted for now */
			nn->e[ix].p.data=NULL;
		}
		return n;
	}
}

#ifdef BT_PROTOTYPES
void *btsearch(void **uroot,void *key,void *data, CMP, int flags)
#else
void *btsearch(uroot,key,data,cmp,flags)
void **uroot;
void *key,*data;
int (*cmp)();
int flags;
#endif
{
	node_t **root=(node_t**)uroot;
	void *user_ret;
	if (*root == NULL) {
		register node_t *node;
		node=*root=(node_t*)calloc(1,sizeof(node_t));
		assert(node!=NULL);
		node->n_type=n_leaf;
		node->nel=0;
	}
	(void)search(root,*root,key,data,cmp,flags,&user_ret);
	return user_ret;
}
#ifdef BT_PROTOTYPES
int btdelete(void **uroot,void *key,CMP)
#else
int btdelete(uroot,key,cmp)
void **uroot;
void *key;
int (*cmp)();
#endif
{
	node_t **root=(node_t**)uroot;
	if (*root == NULL)
		return -1;
	search(root,*root,key,NULL,cmp,BT_DEL,NULL);
	return 0;
}
#ifdef BT_PROTOTYPES
int btwalk(void *upn,
	   int(*act)(void *key,void *data,btw_t which,void *info),void *info)
#else
int btwalk(upn,act,info)
void *upn;
int(*act)();
void *info;
#endif
{
	register node_t *pn=(node_t*)upn;
	register int i;
	register int ret;

	if (pn==NULL)
		return 1;
	while (pn->n_type == n_interior) {
		pn=pn->e[0].p.child;
	}
	ret=(*act)(NULL,NULL,bt_first,info);
	if (ret!=0) return ret;
	while (pn != NULL) {
		for (i=0;i<pn->nel;i++) {
		    if (pn->e[i].p.data != NULL) {
			ret=(*act)(pn->e[i].key,pn->e[i].p.data,bt_data,info);
			if (ret!=0) return ret;
		    }
		}
		pn=pn->right;
	}
	return (*act)(NULL,NULL,bt_last,info);
}
#ifdef BT_PROTOTYPES
static void destroy (void *upn,int(*act)(void *key,void*data))
#else
static void destroy(upn,act)
void *upn;
int(*act)();
#endif
{
	register node_t *pn=(node_t*)upn;
	register int i;

	if (pn->n_type == n_interior) {
		destroy(pn->e[0].p.child,act);
	}
	while (pn != NULL) {
		for (i=0;i<pn->nel;i++) {
			if (pn->n_type==n_leaf) {
				if (act!=NULL)
					(*act)(pn->e[i].key,pn->e[i].p.data);
			} else {
				/* key is user data */
				free(pn->e[i].p.child);
			}
		}
		pn=pn->right;
	}
}
#ifdef BT_PROTOTYPES
void btdestroy (void **uroot,int(*act)(void *key,void*data))
#else
void btdestroy(uroot,act)
void **uroot;
int(*act)();
#endif
{
	register node_t **root=(node_t**)uroot;
	register int i;

	if (root==NULL||*root==NULL)
		return;
	if ((*root)->n_type == n_interior) {
		destroy((*root)->e[0].p.child,act);
	}
	for (i=0;i<(*root)->nel;i++) {
		if ((*root)->n_type==n_leaf) {
			if (act!=NULL)
				(*act)((*root)->e[i].key,(*root)->e[i].p.data);
		} else {
			/* key is user data */
			free((*root)->e[i].p.child);
		}
	}
	free(*root);
	*root=NULL;
}

#define Fprintf	(void)fprintf

#ifdef BT_PROTOTYPES
int btvalidate(void*upn,CMP)
#else
int btvalidate(upn,cmp)
void *upn;
int(*cmp)();
#endif
{
	register node_t *pn=(node_t*)upn;
	register int i;
	register int errs=0;
#define ERR(s,n) ( Fprintf(stderr,s,pn,n),errs++ )

	if (pn->nel==0) {
		ERR("Empty node at %x\n",0);
		return errs;
	}
	if (pn->right !=NULL &&
	    (*cmp)(pn->e[pn->nel-1].key,pn->right->e[0].key)>=0)
		ERR("Key out of order/dup in %x[%d]\n",pn->nel-1);
	for (i=0;i<pn->nel-1;i++) {
		if ((*cmp)(pn->e[i].key,pn->e[i+1].key)>=0)
			ERR("Key out of order/dup in %x[%d]\n",i);
	}
	
	if (pn->n_type == n_interior) {
	    if (pn->left != NULL) {
	        if (pn->e[0].p.child->left != 
		    pn->left->e[pn->left->nel-1].p.child)
			ERR("bad left pointer in %x[0]\n",0);
	    }
	    if (pn->right != NULL) {
	        if (pn->e[pn->nel-1].p.child->right !=
				pn->right->e[0].p.child)
			ERR("bad right pointer in %x[%d]\n",pn->nel-1);
	    }
	    for (i=0;i<pn->nel;i++) {
		if (pn->e[i].key != pn->e[i].p.child->e[0].key)
			ERR("bad key in %x[%d]\n",i);
		if (i>0) {
		    if (pn->e[i].p.child->left != pn->e[i-1].p.child)
			ERR("bad left pointer in %x[%d]\n",i);
		}
		if (i<pn->nel-1) {
		    if (pn->e[i].p.child->right != pn->e[i+1].p.child)
			ERR("bad right pointer in %x[%d]\n",i);
		    if ((*cmp)(pn->e[i].key,pn->e[i+1].key)>=0)
			ERR("Key out of order/dup key in %x[%d]\n",i);
		}
		if (pn->e[i].p.child->parent != pn)
			ERR("bad parent pointer in %x[%d]\n",i);
		errs+=btvalidate(pn->e[i].p.child,cmp);
	    }
	}
	return errs;
}

#ifdef BT_PROTOTYPES
void btdump(void *upn)
#else
void btdump(upn)
void *upn;
#endif
{
	static int lev=0;
	register int i;
	char indent[300];
	register node_t *pn=(node_t*)upn;

	for (i=0;i<lev*2;i++) indent[i]=' ';
	indent[lev*2]='\0';

	lev++;
	Fprintf(stderr,"%s%2d: %08x (l=%08x r=%08x p=%08x) %s nel=%d\n",
		indent,lev,
		pn,pn->left,pn->right,pn->parent,
		pn->n_type == n_leaf ? "leaf" : "intr", pn->nel);
	for (i=0;i<pn->nel;i++) {
		Fprintf(stderr,"%s    %08x[%d] %08x %08x\n",indent,
			pn,i,pn->e[i].key, pn->e[i].p.data);
		if (pn->n_type == n_interior)
			btdump(pn->e[i].p.child);
	}
	lev--;
}
#ifdef __cplusplus
}
#endif
