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

#ifndef KRNL_ROUTE_H
#define KRNL_ROUTE_H

#include "if.h"

#define RTPROT_NETSUKUKU	15

struct nexthop 
{
	inet_prefix gw;
	char *dev;
	u_char hops;
};

struct rt_request {
	struct nlmsghdr 	nh;
	struct rtmsg 		rt;
	char   			buf[1024];
};


#define ROUTE_CMD_VARS	 int type, int scope, inet_prefix *src, inet_prefix *to, \
			 struct nexthop *nhops, char *dev, u_char table

int route_add(ROUTE_CMD_VARS);
int route_del(ROUTE_CMD_VARS);
int route_replace(ROUTE_CMD_VARS);
int route_change(ROUTE_CMD_VARS);
int route_append(ROUTE_CMD_VARS);
int route_get_exact_prefix_dst(inet_prefix, inet_prefix *, char *);
int route_flush_cache(int family);
int route_ip_forward(int family, int enable);
int route_rp_filter(int family, char *dev, int enable);
int route_rp_filter_all_dev(int family, interface *ifs, int ifs_n, int enable);

#endif /*KRNL_ROUTE_H*/
