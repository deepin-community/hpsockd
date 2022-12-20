/* USERPASSDB_PATH is the path to the user/pass database, built with
 * makepass hash userpass < userpass
 */

/*
(c) Copyright Hewlett-Packard Company 1997-2000.

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

#define USERPASSDB_PATH	"/etc/opt/socks/userpass.db"

#ifndef CONFIG_FILE
/* The default config file. */
#define CONFIG_FILE	"/etc/opt/socks/sockd.conf"
#endif
