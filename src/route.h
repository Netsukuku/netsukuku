/* This file is part of Netsukuku system
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

#ifndef ROUTE_H
#define ROUTE_H

#include "gmap.h"
#include "bmap.h"
#include "if.h"

#define MAX_MULTIPATH_ROUTES		24	/* The maximum number of 
						   nexthops used to create a 
						   single multipath route. */

/* 
 * get_gw_gnode_recurse() uses this array to decide the number of forks per
 * level. The number of forks for the level `x' is located at
 * sub_gw_links[GET_LEVELS(my_family) - x - 1].  
 * `x' must be < GET_LEVELS(my_family).
 * For example, at level 3, in ipv4, it will fork in 4 gateway gnodes, then,
 * descending in each gw gnodes (in the lower level) it will fork in other 3
 * gw gnodes. Continuing it will reach the level 1, and there it will choose 2
 * gw gnodes for each forked gw gnode of the higher level. The total number of
 * gateways choosen will be MAX_MULTIPATH_ROUTES, which is 4*3*2.
 * For the ipv6 it's the same thing, but from the level 11 there will be no
 * more forks.
 */
const static int sub_gw_links[MAX_LEVELS] = { 4, 3, 2, 1, 1, 1, 1, 1, 
					  1, 1, 1, 1, 1, 1, 1, 1 };

/* * * Functions declaration * * */
void **get_gw_gnode(map_node *, map_gnode **, map_bnode **, 
		u_int *, map_gnode *, u_char, u_char, int);
int get_gw_ips(map_node *, map_gnode **, map_bnode **, u_int *, 
		quadro_group *, map_gnode *, u_char, u_char, 
		inet_prefix *, map_node **, int);
struct nexthop *rt_build_nexthop_gw(map_node *node, map_gnode *gnode, int level,
		int maxhops);
void rt_update_node(inet_prefix *dst_ip, void *dst_node, quadro_group *dst_quadg, 
		      void *void_gw, interface **, u_char level);
void rt_rnodes_update(int check_update_flag);
void rt_full_update(int check_update_flag);

int rt_get_default_gw(inet_prefix *gw, char *dev_name);
int rt_add_gw(char *dev, inet_prefix to, inet_prefix gw, u_char table);
int rt_del_gw(char *dev, inet_prefix to, inet_prefix gw, u_char table);
int rt_change_gw(char *dev, inet_prefix to, inet_prefix gw, u_char table);
int rt_replace_gw(char *dev, inet_prefix to, inet_prefix gw, u_char table);
int rt_replace_def_gw(char *dev, inet_prefix gw, u_char table);
int rt_delete_def_gw(u_char);

int rt_del_loopback_net(void);
int rt_append_subnet_src(inet_prefix *src, char *dev);

#endif /*ROUTE_H*/
