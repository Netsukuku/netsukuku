/* This file is part of Netsukuku
 * (c) Copyright 2005 Andrea Lo Pumo aka AlpT <alpt@freaknet.org>
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

#ifndef IPTUNNEL_H
#define IPTUNNEL_H

#include "if.h"

#define DEFAULT_TUNL_PREFIX	"tunl"
#define DEFAULT_TUNL_NUMBER	0	/* The permanent tunl0 device */
#define DEFAULT_TUNL_IF		"tunl0"
#define NTK_TUNL_PREFIX		"ntk_tunl"

/* Usage: printf(TUNL_STRING, TUNL_NUMBER("tunl", x)); */
#define TUNL_STRING		"%s%d"
#define TUNL_N(prefix, x)	prefix, x

#define MAX_TUNNEL_IFS		24	/* it must be >= MAX_MULTIPATH_ROUTES,
					   since in igs.c we are using a tunnel 
					   for each nexthop inet-gw */

/*
 * * Globals * *
 */

interface tunnel_ifs[MAX_TUNNEL_IFS];


/* 
 * Functions declaration
 */


int tunnel_add(inet_prefix *remote, inet_prefix *local, char *dev,
		char *tunl_prefix, int tunl_number);
int tunnel_change(inet_prefix *remote, inet_prefix *local, char *dev,
		char *tunl_prefix, int tunl_number);
int tunnel_del(inet_prefix *remote, inet_prefix *local, char *dev,
		char *tunl_prefix, int tunl_number);

int tun_add_tunl(interface *ifs, char *tunl_prefix, u_char tunl_number);
int tun_del_tunl(interface *ifs, char *tunl_prefix, u_char tunl_number);
void init_tunnels_ifs(void);
int set_tunnel_ip(char *tunl_prefix, int tunl_number, inet_prefix *tunl_ip);
int first_free_tunnel_if(void);
int do_get(char *dev);
int add_tunnel_if(inet_prefix *remote, inet_prefix *local, char *dev,
		char *tunl_prefix, int tunl_number, inet_prefix *tunl_ip);
int del_tunnel_if(inet_prefix *remote, inet_prefix *local, char *dev,
		char *tunl_prefix, int tunl_number);
void del_all_tunnel_ifs(inet_prefix *remote, inet_prefix *local, char *dev, 
		char *tunl_prefix);
#endif /* IPTUNNEL_H */
