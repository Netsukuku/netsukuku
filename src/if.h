/* This file is part of Netsukuku
 * (c) Copyright 2004 Andrea Lo Pumo aka AlpT <alpt@freaknet.org>
 *
 * This source code is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published 
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * Please refer to the GNU Public License for more details.
 *
 * You should have received a copy of the GNU Public License along with
 * this source code; if not, write to:
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef IF_H
#define IF_H

#include <net/if.h>
#include "inet.h"

#define MAX_INTERFACES		16	/* The maximum number of network 
					   interfaces, which can be used 
					   by Netsukuku */

typedef struct {
	char		dev_name[IFNAMSIZ];	/* If name */
	int		dev_idx;		/* If index */
} interface;

/* from linux/ipv6.h */
struct in6_ifreq {
	struct in6_addr ifr6_addr;
	uint32_t        ifr6_prefixlen;
	int             ifr6_ifindex;
};


int ifs_get_pos(interface *ifs, int ifs_n, interface *dev);
interface *ifs_find_idx(interface *ifs, int ifs_n, int dev_idx);
int ifs_find_devname(interface *ifs, int ifs_n, char *dev_name);
void ifs_del(interface *ifs, int *ifs_n, int if_pos);
void ifs_del_byname(interface *ifs, int *ifs_n, char *dev_name);
void ifs_del_all_name(interface *ifs, int *ifs_n, char *dev_name);
const char *get_dev(int *dev_idx);
int set_dev_up(char *dev);
int set_dev_down(char *dev);
int set_flags(char *dev, u_int flags, u_int mask);
int set_all_ifs(interface *ifs, int ifs_n, int (*set_func)(char *dev));
int if_init_all(char *ifs_name[MAX_INTERFACES], int ifs_n, interface *new_ifs, int *new_ifs_n);
void if_close_all(void);
int set_all_dev_ip(inet_prefix ip, interface *ifs, int ifs_n);
int set_dev_ip(inet_prefix ip, char *dev);
int get_dev_ip(inet_prefix *ip, int family, char *dev);
int ip_addr_flush(int family, char *dev, int scope);
int ip_addr_flush_all_ifs(interface *ifs, int ifs_n, int family, int scope);

#endif /*IF_H*/
