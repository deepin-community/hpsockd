#ifdef __cplusplus
extern "C" {
#endif

/*
(c) Copyright Hewlett-Packard Company 1993-2000.

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

#ifndef BTREE_H
#define BTREE_H
#if defined(__STDC__) && (__STDC__ != 0)
#define BT_PROTOTYPES
#define P_(x) x
#else  /* ! ANSI C */
#undef BT_PROTOTYPES
#define P_(x) ()
#endif /* ! ANSI C */

/* flags for btsearch */
#define BT_INS	1	/* insert the key/data if not found */
#define BT_DEL	2	/* delete the key if found - used by bt delete */
#define BT_CLOSE 4	/* return closest (lower or equal) entry */
typedef enum { bt_first, bt_data, bt_last } btw_t;

void* btsearch P_((void **root,void *key,void *data,
		int(*cmp)(void *k1,void *k2), int flags));
int btdelete P_((void **root,void *key,int(*cmp)(void *n1,void *n2)));
int btwalk P_((void *root,int(*act)(void *key,void *data,btw_t which,void *info),void *info));
int btvalidate P_((void*pn, int(*cmp)(void *k1,void *k2)));
void btdump P_((void *pn));
void btdestroy P_((void **root,int(*act)(void *key,void*data)));
#endif /*  BTREE_H */
#ifdef __cplusplus
}
#endif
