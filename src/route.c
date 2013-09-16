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
 *
 * --
 * route.c:
 * Routing table management code.
 */

#include "includes.h"

#include "common.h"
#include "libnetlink.h"
#include "inet.h"
#include "krnl_route.h"
#include "request.h"
#include "endianness.h"
#include "pkts.h"
#include "bmap.h"
#include "qspn.h"
#include "radar.h"
#include "netsukuku.h"
#include "route.h"

int get_gw_gnode_recurse(map_node *, map_gnode **, map_bnode **, u_int *,
		map_gnode *, map_gnode *, map_node *, u_char, u_char, 
		void **, int, int);

/*
 * get_gw_bnode_recurse: this function is part of get_gw_gnode_recurse(). 
 * The explanation of it's way of working is inside the get_gw_gnode() 
 * function.
 */
int get_gw_bnode_recurse(map_node *int_map, map_gnode **ext_map,
		map_bnode **bnode_map, u_int *bmap_nodes, map_gnode *find_gnode,
		map_gnode *gnode_gw, map_node *node_gw, u_char gnode_level,
		u_char gw_level, void **gateways, int gateways_nmembs, int single_gw)
{
	map_gnode *gnode=0;
	map_node *node, *root_node;
	ext_rnode_cache *erc;
	int i, bpos;

	i=gnode_level;

	if(i == gw_level) {
		/* Gateway found */
		gateways[0]=(void *)node_gw;
		return 0;
	} else if(!i)
		return -1;

	/* Find the bnode which borders on the `node_gw' gnode */
	bpos=map_find_bnode_rnode(bnode_map[i-1], bmap_nodes[i-1], (void *)node_gw);
	if(bpos == -1) {
		/*debug(DBG_INSANE, "get_gw: l=%d, node_gw=%x not found in bmap lvl %d", 
				i, node_gw, i-1);*/
		return -1;
	}

	if(!(i-1))
		node=node_from_pos(bnode_map[i-1][bpos].bnode_ptr, int_map);
	else {
		gnode=gnode_from_pos(bnode_map[i-1][bpos].bnode_ptr, 
				ext_map[_EL(i-1)]);
		node=&gnode->g;

		/* If we are a bnode and the `gnode', the found bnode, is us,
		 * let's check if we have `gnode_gw' in our external rnode
		 * cache. If we have, the gw has been found */
		qspn_set_map_vars(i-1, 0, &root_node, 0, 0);
		if(me.cur_node->flags & MAP_BNODE && 
				gnode == (map_gnode *)root_node) {
			/* debug(DBG_INSANE, "get_gw: bmap searching ernode for gnode 0x%x",node_gw); */

			erc=erc_find_gnode(me.cur_erc, gnode_gw, i);
			if(erc) {
				gateways[0]=(void *)erc->e;
				return 0;
			}
		}
	}
	
	/* debug(DBG_INSANE, "get_gw: bmap found = %x", node); */

	/* Descend in the lower level */
	if((--i) >= gw_level) 
		return get_gw_gnode_recurse(int_map, ext_map, bnode_map, bmap_nodes,
				find_gnode, gnode, node, i, gw_level, 
				gateways, gateways_nmembs, single_gw);
	return -1;
}


/*
 * get_gw_gnode_recurse: recursive part of the get_gw_gnode function (see
 * below).
 * `gateways' is the array of pointers. which point to the found gateway
 * nodes.
 * `gateways_nmembs' is the number of members of the `gateways' array.
 */
int get_gw_gnode_recurse(map_node *int_map, map_gnode **ext_map,
		map_bnode **bnode_map, u_int *bmap_nodes, map_gnode *find_gnode,
		map_gnode *gnode, map_node *node, u_char gnode_level, 
		u_char gw_level, void **gateways, int gateways_nmembs, 
		int single_gw)
{
	map_gnode *gnode_gw=0;
	map_node  *node_gw;
	int i, pos, routes, sub_routes, e, ret;

	/*debug(DBG_INSANE, "get_gw: find_gnode=%x", find_gnode);*/
	i=gnode_level; 

	if(node->flags & MAP_RNODE) {
		/*
		 * If `node' is an our rnode, then the gateway to reach it is
		 * itself, so we set the `gnode_gw' to `node' in order to find
		 * in the lower level a bnode which borders on `node'
		 */
		gnode_gw=(void *)node;
		node_gw=(map_node *)gnode_gw;
		/*debug(DBG_INSANE, "get_gw: l=%d, node & MAP_RNODE. node_gw=node=%x",
				i, node);*/
	} else if (node->flags & MAP_ME) {
		/* 
		 * If `node' is an our gnode. we reset the gnode_gw to
		 * `find_gnode', in this way, in the lower level we'll find a
		 * bnode which borders on `find_gnode'. 
		 */
		gnode_gw=(void *)find_gnode;
		node_gw=(map_node *)gnode_gw;
		/*debug(DBG_INSANE, "get_gw: l=%d, node & MAP_ME. find_gnode: %x",
				i, find_gnode);*/
	} else {
		
		if(!node->links || (i && !gnode))
			/* That's no good */
			return -1;

		if(single_gw) {
			/* only one route is needed, do not fork */
			routes=1;
			sub_routes=1;
		} else {
			/* `routes': how many different links we must consider */
			routes = sub_gw_links[FAMILY_LVLS - i - 1];
			routes = routes > node->links ? node->links : routes;

			/* How many routes there are in each of the `routes'# links */
			sub_routes = gateways_nmembs/routes;

		}
		
		int old_pos[routes];
		memset(old_pos, -1, sizeof(int)*routes);
		
		ret=0;
		for(e=0; e < routes; e++) {
			
			/* Choose a random link, which was not chosen before */
			while(find_int((pos=rand_range(0, node->links-1)), old_pos, routes));
			old_pos[e]=pos;
			
			if(!i) {
				node_gw=(void *)node->r_node[pos].r_node;
			} else {
				gnode_gw=(map_gnode *)gnode->g.r_node[pos].r_node;
				node_gw=(void *)gnode_gw;
			}
			
			if(node_gw->flags & MAP_RNODE)
				find_gnode=(map_gnode *)node_gw;
			/*debug(DBG_INSANE, "get_gw: l=%d, e %d node_gw=rnode[%d].r_node=%x,"
					" find_gnode=%x", i, e, pos, node_gw, find_gnode);*/

			ret+=get_gw_bnode_recurse(int_map, ext_map, bnode_map, bmap_nodes, 
					find_gnode, gnode_gw, node_gw, i, gw_level, 
					&gateways[e*sub_routes], sub_routes, single_gw);
		}
		return ret;
	}

	return get_gw_bnode_recurse(int_map, ext_map, bnode_map, bmap_nodes, 
			find_gnode, gnode_gw, node_gw, i, gw_level, gateways,
			gateways_nmembs, single_gw);
}


/* 
 * get_gw_gnode: It finds the MAX_MULTIPATH_ROUTES best gateway present in the 
 * map of level `gw_level'. These gateways are the nodes to be used as gateway 
 * to reach, from the `gw_level' level,  the `find_gnode' gnode at the
 * `gnode_level' level. 
 * If not a single gateway is found, NULL is returned, otherwise an  array of 
 * pointers to the gateway nodes is returned, the array has
 * MAX_MULTIPATH_ROUTES+1 nmembs. Some member of the array can be NULL, ignore
 * them. Remember to xfree the array of pointers!
 * If `single_gw' is not 0, only one gateway will be returned.
 */
void **get_gw_gnode(map_node *int_map, map_gnode **ext_map,
		map_bnode **bnode_map, u_int *bmap_nodes, 
		map_gnode *find_gnode, u_char gnode_level, 
		u_char gw_level, int single_gw) 
{
	map_gnode *gnode;
	map_node *node;
	void **gateways=0;
	int ret;
	
	if(!gnode_level || gw_level > gnode_level)
		goto error;

	gateways=xzalloc(sizeof(void *) * MAX_MULTIPATH_ROUTES+1);

	/* 
	 * In order to find the gateway at level `gw_level', which will be
	 * used to reach the `find_gnode' gnode at level `gnode_level',
	 * firstly we find the gnode, at level `gnode_level' that can be used
	 * as a gateway to reach `find_gnode', then we go down of one level
	 * and we search the gateway that can be used to reach the border node 
	 * which borders to the previously found gateway. The same procedure
	 * is done until we arrive at the desired `gw_level' level.
	 *
	 * Sadly this procedure can give us only one route to reach the
	 * `find_gnode' gnode, in fact, there can be, at each level, multiple
	 * gateways to reach the same gnode (or bnode). For this reason, at
	 * each level, we must first fork at each found gateway and then we
	 * can descend in the lower level. In this way each forked child will
	 * try to find the gateway to reach the bnode which borders on the
	 * parent gateway.
	 * Each found gateway, which belongs to the `gw_level' is added to the
	 * `gateways' array, but here comes another problem: if in each level
	 * we find the maximum number of available gateways, there will be a
	 * total of MAX_MULTIPATH_ROUTES^(gnode_level-gw_level) routes.
	 * We can return only MAX_MULTIPATH_ROUTES routes, so we restrict the
	 * number of forks per level. Each level has its forks number, which
	 * is already stored in the `sub_gw_links' array. (For more info on
	 * that array, read route.h).
	 * That's all.
	 *
	 * To implement all that mess we use three functions, in this way:
	 *
	 * get_gw_gnode() is only the starting function. It sets
	 * gnode=find_gnode and launches get_gw_gnode_recurse(gnode), which 
	 * finds the gateway to reach the given `gnode'. It then forks for
	 * each gateway found and launches get_gw_bnode_recurse(gateway) which
	 * searches, in the lower level, the bnode which borders on `gateway'. 
	 * Then get_gw_bnode_recurse() sets gnode to the found gateway and 
	 * launches again get_gw_gnode(gnode). The loop continues until the
	 * `gw_level' is reached.
	 *
	 * Wow, that was a long explanation ;)
	 */
	gnode=find_gnode;
	node=&gnode->g;

	/* The gateway to reach me is myself. */
	if(node->flags & MAP_ME) {
		gateways[0]=(void *)node;
		return gateways;
	}

	ret=get_gw_gnode_recurse(int_map, ext_map, bnode_map, bmap_nodes, 
			find_gnode, gnode, node, gnode_level, gw_level, 
			gateways, MAX_MULTIPATH_ROUTES, single_gw);

	if(ret < 0)
		goto error;
	
	return gateways;

error:
	if(gateways)
		xfree(gateways);
	return 0;
}



/*
 * get_gw_ips: It's a wrapper to get_gw_gnode() that converts the found
 * gateways to IPs. 
 * `gw_ip' is the array of inet_prefix structs where the converted IPs will be
 * stored. It must have MAX_MULTIPATH_ROUTES members.
 * If `single_gw' is not null, only the best gateway will be converted and it
 * is assumed that `gw_ip' has only 1 member.
 * The number of IPs stored in `gw_ip' is returned.
 * The pointer to the gateways node pointers are copied in the `gw_gnodes'
 * array, (if not null), which must have at least MAX_MULTIPATH_ROUTES members.
 * On error -1 is returned.
 */
int get_gw_ips(map_node *int_map, map_gnode **ext_map,
		map_bnode **bnode_map, u_int *bmap_nodes, 
		quadro_group *cur_quadg,
		map_gnode *find_gnode, u_char gnode_level, 
		u_char gw_level, inet_prefix *gw_ip, map_node **gw_nodes,
		int single_gw)
{
	ext_rnode *e_rnode=0;
	map_node **gw_node=0;
	int i, e, gw_ip_members;

	gw_ip_members=single_gw ? 1 : MAX_MULTIPATH_ROUTES;
	setzero(gw_ip, sizeof(inet_prefix)*gw_ip_members);

	gw_node=(map_node **)get_gw_gnode(int_map, ext_map, bnode_map, bmap_nodes,
			find_gnode, gnode_level, gw_level, single_gw);

	if(!gw_node)
		return -1;

	for(i=0, e=0; i<MAX_MULTIPATH_ROUTES; i++) {

		if(!gw_node[i])
			continue;

		if(gw_node[i]->flags & MAP_ERNODE) {
			e_rnode=(ext_rnode *)gw_node[i];
			inet_copy(&gw_ip[e], &e_rnode->quadg.ipstart[gw_level]);
		} else
			maptoip((u_int)int_map, (u_int)gw_node[i], cur_quadg->ipstart[1], 
					&gw_ip[e]);

		if(gw_nodes)
			gw_nodes[e]=gw_node[i];

		e++;
	}

	xfree(gw_node);
	return e ? e : -1;
}

/*
 * find_rnode_dev_and_retry
 *
 * Searches with rnl_get_dev() the rnode_list which points to `node'. 
 * If it is not found it waits the next radar_scan. If it is not found again 
 * NULL is returned, otherwise the devices list of the related rnode_list 
 * struct is returned.
 */
interface **find_rnode_dev_and_retry(map_node *node)
{
	int retries;
	interface **devs=0;
	
	for(retries=0; !(devs=rnl_get_dev(rlist, node)) && !retries; retries++)
		radar_wait_new_scan();
	return devs;
}

/*
 * rt_build_nexthop_gw: returns an array of nexthop structs, which has a 
 * maximum of `maxhops' members. The nexthop are all gateway which can be used
 * to reach `node' or `gnode'.
 * The array is xmallocateed.
 * On error NULL is returned.
 */
struct nexthop *rt_build_nexthop_gw(map_node *node, map_gnode *gnode, int level,
		int maxhops)
{
	map_node *tmp_node;
	struct nexthop *nh=0;
	interface **devs;
	int n, i, ips, routes;
	
	if(!level) {
		nh=xmalloc(sizeof(struct nexthop)*(node->links+1));
		setzero(nh, sizeof(struct nexthop)*(node->links+1));

		for(i=0, n=0; i<node->links; i++) {
			tmp_node=(map_node *)node->r_node[i].r_node;
			
			maptoip((u_int)me.int_map, (u_int)tmp_node,
					me.cur_quadg.ipstart[1], &nh[n].gw);
			inet_htonl(nh[n].gw.data, nh[n].gw.family);
			
			if(!(devs=find_rnode_dev_and_retry(tmp_node)))
				continue;
			nh[n].dev=devs[0]->dev_name;

			nh[n].hops=node->links-i;	/* multipath weigth */
			n++;

			if(maxhops && n >= maxhops)
				break;
		}
		nh[n].dev=0;
	} else if(level) {
		inet_prefix gnode_gws[MAX_MULTIPATH_ROUTES];
		map_node *gw_nodes[MAX_MULTIPATH_ROUTES];
		
		routes=get_gw_ips(me.int_map, me.ext_map, me.bnode_map,
			     me.bmap_nodes, &me.cur_quadg,
			     gnode, level, 0, gnode_gws, gw_nodes, 0);
		if(routes < 0)
			goto finish;

		nh=xmalloc(sizeof(struct nexthop)*(routes+1));
		setzero(nh, sizeof(struct nexthop)*(routes+1));

		for(ips=0, n=0; ips < routes; ips++) {
			inet_copy(&nh[n].gw, &gnode_gws[ips]);
			inet_htonl(nh[n].gw.data, nh[n].gw.family);
			
			if(!(devs=find_rnode_dev_and_retry(gw_nodes[ips])))
				continue;
			nh[n].dev=devs[0]->dev_name;
			
			nh[n].hops=routes-ips; 	/* multipath weigth */
			n++;

			if(maxhops && n >= maxhops)
				break;
		}
		
		nh[n].dev=0;
	}
finish:
	return nh;
}

struct nexthop *rt_build_nexthop_voidgw(void *void_gw, interface **oifs)
{
	map_node *gw_node=0;
	ext_rnode *e_rnode=0;
	struct nexthop *nh;
	int dev_n, i;

	if(void_gw)
		gw_node=(map_node *)void_gw;

	if(!oifs && !(oifs=find_rnode_dev_and_retry(gw_node)))
		/* It wasn't found any suitable dev */
		return 0;
	
	for(dev_n=0; oifs[dev_n]; dev_n++);
	
	nh=xmalloc(sizeof(struct nexthop)*(dev_n+1));
	setzero(nh, sizeof(struct nexthop)*(dev_n+1));

	if(gw_node->flags & MAP_ERNODE) {
		e_rnode=(ext_rnode *)gw_node;
		inet_copy(&nh[0].gw, &e_rnode->quadg.ipstart[0]);
	} else 
		maptoip((u_int)me.int_map, (u_int)gw_node, 
				me.cur_quadg.ipstart[1], &nh[0].gw);
	inet_htonl(nh[0].gw.data, nh[0].gw.family);
	nh[0].dev=oifs[0]->dev_name;
	nh[0].hops=1;

	for(i=1; i<dev_n; i++) {
		memcpy(&nh[i], &nh[0], sizeof(struct nexthop));
		nh[i].dev=oifs[i]->dev_name;
		nh[i].hops=1;
	}
	nh[i].dev=0;

	return nh;
}

/* 
 * rt_update_node
 *
 * It adds/replaces or removes a route from the kernel's
 * table, if the node's flag is found, respectively, to be set to 
 * MAP_UPDATE or set to MAP_VOID. When a route is deleted only the destination
 * arguments are required (i.e `void_gw', `oif' are not needed).
 * 
 * The destination of the route can be given with `dst_ip', `dst_node' or
 * `dst_quadg'.
 * 
 * If `dst_ip' is not null, the given inet_prefix struct is used, it's also 
 * used the `dst_node' to retrieve the flags.
 * If the destination of the route is a node which belongs to the level 0, the
 * same node must be passed in the `dst_node' argument. 
 * 
 * If `level' is > 0 and `dst_quadg' is not null, then it updates the gnode
 * which is inside the `dst_quadg' struct: dst_quadg->gnode[_EL(level)]. The 
 * quadro_group struct must be complete and refer to the groups of the 
 * given gnode. 
 * 
 * If `level' is > 0 and `dst_quadg' is null, it's assumed that the gnode is passed
 * in `dst_node' and that the quadro_group for that gnode is me.cur_quadg.
 * 
 * If `void_gw' is not null, it is used as the only gw to reach the destination 
 * node, otherwise the gw will be calculated.
 * `oifs', if not null, will be used in conjuction with `void_gw' as the output
 * interfaces to be used in the route. `oifs' is an array of pointers of
 * maximum MAX_INTERFACES# members.
 */
void rt_update_node(inet_prefix *dst_ip, void *dst_node, quadro_group *dst_quadg, 
		      void *void_gw, interface **oifs, u_char level)
{
	map_node *node=0;
	map_gnode *gnode=0;
	struct nexthop *nh=0;
	inet_prefix to;
	int node_pos=0, route_scope=0;

#ifdef DEBUG		
#define MAX_GW_IP_STR_SIZE (MAX_MULTIPATH_ROUTES*((INET6_ADDRSTRLEN+1)+IFNAMSIZ)+1)
	int n;
	char *to_ip=0, gw_ip[MAX_GW_IP_STR_SIZE]="";
#else
	const char *to_ip=0;
#endif

	node=(map_node *)dst_node;
	gnode=(map_gnode *)dst_node;

	/* 
	 * Deduce the destination's ip 
	 */
	if(dst_ip)
		inet_copy(&to, dst_ip);
	else if(level) {
		if(!dst_quadg) {
			dst_quadg=&me.cur_quadg;
			node_pos=pos_from_gnode(gnode, me.ext_map[_EL(level)]);
		} else {
			gnode=dst_quadg->gnode[_EL(level)];
			node_pos=dst_quadg->gid[level];
		}
		node=&gnode->g;
		gnodetoip(dst_quadg, node_pos, level, &to);
	} else {
		node_pos=pos_from_node(node, me.int_map);
		maptoip((u_int)me.int_map, (u_int)node, me.cur_quadg.ipstart[1], &to);
	}
#ifdef DEBUG		
	to_ip=xstrdup(inet_to_str(to));
#else
	to_ip=inet_to_str(to); 
#endif
	inet_htonl(to.data, to.family);

	if(node->flags & MAP_VOID)
		/* We have only to delete the route, skip to do_update */
		goto do_update;
		
	/* 
	 * If `node' it's a rnode of level 0, do nothing! It is already 
	 * directly connected to me. (If void_gw is not null, skip this check).
	 */
	if(node->flags & MAP_RNODE && !level && !void_gw)
		goto finish;
	
	/* Dumb you, we don't need the route to reach ourself */
	if(node->flags & MAP_ME)
		goto finish;

	/*
	 * Now, get the gateway to reach the destination.
	 */
	if(void_gw)
		nh=rt_build_nexthop_voidgw(void_gw, oifs);
	else
		nh=rt_build_nexthop_gw(node, gnode, level, MAX_MULTIPATH_ROUTES);
	if(!nh) {
		debug(DBG_NORMAL, "Cannot get the gateway for "
				"the (g)node: %d of level: %d, ip:"
				"%s", node_pos, level, to_ip);
		goto finish;
	}

do_update:
#ifdef DEBUG
	for(n=0; nh && nh[n].dev; n++){ 
		strcat(gw_ip, inet_to_str(nh[n].gw));
		strcat(gw_ip, ":");
		strcat(gw_ip, nh[n].dev);
		if(nh[n+1].dev)
			strcat(gw_ip, ",");
	}
	if(node->flags & MAP_VOID)
		strcpy(gw_ip, "deleted");
	debug(DBG_INSANE, "rt_update_node: to "PURPLE("%s/%d") " via " RED("%s"),
			to_ip, to.bits, gw_ip);
		
#endif
	if(node->flags & MAP_RNODE && !level)
		/* The dst node is a node directly linked to us */
		route_scope = RT_SCOPE_LINK;

	if(node->flags & MAP_VOID) {
		/* Ok, let's delete it */
		if(route_del(RTN_UNICAST, 0, 0, &to, 0, 0, 0))
			error("WARNING: Cannot delete the route entry for the"
					"%snode %d lvl %d!", !level ? " " : " g",
					node_pos, level);
	} else if(route_replace(0, route_scope, 0, &to, nh, 0, 0))
			error("WARNING: Cannot update the route entry for the"
					"%snode %d lvl %d",!level ? " " : " g",
					node_pos, level);
finish:
#ifdef DEBUG
	if(to_ip)
		xfree(to_ip);
#endif
	if(nh)
		xfree(nh);
}

/* 
 * rt_rnodes_update
 * 
 * It updates all the node which are rnodes of the root_node
 * of all the maps. If `check_update_flag' is non zero, the rnode will be
 * updated only if it has the MAP_UPDATE flag set.
 */
void rt_rnodes_update(int check_update_flag)
{
	u_short i, level;
	ext_rnode *e_rnode;
	map_node *root_node, *node, *rnode;
	map_gnode *gnode;
	interface **out_devs;
	
	/* Internal map */
	root_node=me.cur_node;
	for(i=0; i < root_node->links; i++) {
		rnode=(map_node *)root_node->r_node[i].r_node;
		out_devs=rnl_get_dev(rlist, rnode);

		if(check_update_flag && !(rnode->flags & MAP_UPDATE))
			/* nothing to do for this rnode */
			continue;

		if(rnode->flags & MAP_ERNODE) {
			e_rnode=(ext_rnode *)rnode;
			
			rt_update_node(&e_rnode->quadg.ipstart[0], rnode, 0,
					me.cur_node, out_devs, /*level*/0);
			rnode->flags&=~MAP_UPDATE;

			for(level=1; level < e_rnode->quadg.levels; level++) {
				if(!(gnode = e_rnode->quadg.gnode[_EL(level)]))
					continue;

				node = &gnode->g;
				rt_update_node(0, 0, &e_rnode->quadg,
						rnode, out_devs, level);
				node->flags&=~MAP_UPDATE;
			}
		} else {
			rt_update_node(0, rnode, 0, me.cur_node, out_devs, /*level*/0); 
			rnode->flags&=~MAP_UPDATE;
		}
	}

	/*
	 * Shall we activate it?
	 * route_flush_cache(my_family); 
	 */
}

/* 
 * rt_full_update
 * 
 * It updates _ALL_ the possible routes it can get from _ALL_ the maps. 
 * If `check_update_flag' is not 0, it will update only the routes of the 
 * nodes with the MAP_UPDATE flag set. Note that the MAP_VOID nodes aren't
 * considered.
 */
void rt_full_update(int check_update_flag)
{
	u_short i, l;

	/* Update ext_maps */
	for(l=me.cur_quadg.levels-1; l>=1; l--)
		for(i=0; i<MAXGROUPNODE; i++) {
			if(me.ext_map[_EL(l)][i].g.flags & MAP_VOID || 
				me.ext_map[_EL(l)][i].flags & GMAP_VOID ||
				me.ext_map[_EL(l)][i].g.flags & MAP_ME)
				continue;

			if(check_update_flag && 
				!(me.ext_map[_EL(l)][i].g.flags & MAP_UPDATE))
				continue;

			rt_update_node(0, &me.ext_map[_EL(l)][i].g, 0, 0, 0, l);
			me.ext_map[_EL(l)][i].g.flags&=~MAP_UPDATE;
		}

	/* Update int_map */
	for(i=0, l=0; i<MAXGROUPNODE; i++) {
		if(me.int_map[i].flags & MAP_VOID || me.int_map[i].flags & MAP_ME)
			continue;

		if(check_update_flag && !((me.int_map[i].flags & MAP_UPDATE)))
			continue;

		rt_update_node(0, &me.int_map[i], 0, 0, 0, l);
		me.int_map[i].flags&=~MAP_UPDATE;
	}

	route_flush_cache(my_family);
}

/*
 * rt_get_default_gw
 * 
 * It stores in `gw' the IP address of the current default gw, and in 
 * `dev_name' its utilised net interface. If the default gw doesn't exist
 * `gw' and `dev_name' are set to 0.
 * If an error occurred a number < 0 is returned.
 * `dev_name' must be of IFNAMSIZ# bytes.
 */
int rt_get_default_gw(inet_prefix *gw, char *dev_name)
{
	inet_prefix default_gw;

	inet_setip_anyaddr(&default_gw, my_family);
	default_gw.len=default_gw.bits=0;
	return route_get_exact_prefix_dst(default_gw, gw, dev_name);
}

int rt_exec_gw(char *dev, inet_prefix to, inet_prefix gw, 
		int (*route_function)(ROUTE_CMD_VARS), u_char table)
{
	struct nexthop nh[2], *neho;

	if(to.len)
		inet_htonl(to.data, to.family);

	if(gw.len) {
		setzero(nh, sizeof(struct nexthop)*2);	
		inet_copy(&nh[0].gw, &gw);
		inet_htonl(nh[0].gw.data, nh[0].gw.family);
		nh[0].dev=dev;
		nh[1].dev=0;
		neho=nh;
	} else
		neho=0;

	return route_function(0, 0, 0, &to, neho, dev, table);
}

int rt_add_gw(char *dev, inet_prefix to, inet_prefix gw, u_char table)
{
	return rt_exec_gw(dev, to, gw, route_add, table);
}

int rt_del_gw(char *dev, inet_prefix to, inet_prefix gw, u_char table)
{
	return rt_exec_gw(dev, to, gw, route_del, table);
}

int rt_change_gw(char *dev, inet_prefix to, inet_prefix gw, u_char table)
{
	return rt_exec_gw(dev, to, gw, route_change, table);
}

int rt_replace_gw(char *dev, inet_prefix to, inet_prefix gw, u_char table)
{
	return rt_exec_gw(dev, to, gw, route_replace, table);
}

int rt_replace_def_gw(char *dev, inet_prefix gw, u_char table)
{
	inet_prefix to;

	if(inet_setip_anyaddr(&to, my_family)) {
		error("rt_replace_def_gw(): Cannot use INADRR_ANY for the %d "
				"family", to.family);
		return -1;
	}
	to.len=to.bits=0;

	return rt_replace_gw(dev, to, gw, table);
}

int rt_delete_def_gw(u_char table)
{
	inet_prefix to;

	if(inet_setip_anyaddr(&to, my_family)) {
		error("rt_delete_def_gw(): Cannot use INADRR_ANY for the %d "
				"family", to.family);
		return -1;
	}
	to.len=to.bits=0;

	return route_del(0, 0, 0, &to, 0, 0, table);
}

/* 
 * rt_del_loopback_net:
 * We remove the loopback net, leaving only the 127.0.0.1 ip for loopback.
 *  ip route del local 127.0.0.0/8  proto kernel  scope host src 127.0.0.1
 *  ip route del broadcast 127.255.255.255  proto kernel scope link  src 127.0.0.1
 *  ip route del broadcast 127.0.0.0  proto kernel  scope link src 127.0.0.1
 */
int rt_del_loopback_net(void)
{
	inet_prefix to;
	char lo_dev[]="lo";
	u_int idata[MAX_IP_INT];

	setzero(idata, MAX_IP_SZ);
	if(my_family!=AF_INET) 
		return 0;

	/*
	 * ip route del broadcast 127.0.0.0  proto kernel  scope link      \
	 * src 127.0.0.1
	 */
	idata[0]=LOOPBACK_NET;
	inet_setip(&to, idata, my_family);
	route_del(RTN_BROADCAST, 0, 0, &to, 0, 0, RT_TABLE_LOCAL);

	/*
	 * ip route del local 127.0.0.0/8  proto kernel  scope host 	   \
	 * src 127.0.0.1
	 */
	to.bits=8;
	route_del(RTN_LOCAL, 0, 0, &to, 0, lo_dev, RT_TABLE_LOCAL);

	/* 
	 * ip route del broadcast 127.255.255.255  proto kernel scope link \
	 * src 127.0.0.1 
	 */
	idata[0]=LOOPBACK_BCAST;
	inet_setip(&to, idata, my_family);
	route_del(RTN_BROADCAST, 0, 0, &to, 0, lo_dev, RT_TABLE_LOCAL);

	return 0;
}

/*
 * rt_append_subnet_src:
 * it appends the subnet relative to a `src' IP and its device in the routing
 * table, f.e. when you do "ifconfig eth0 10.2.3.1 up" the kernel
 * automatically adds this route:
 * 10.0.0.0/8 dev eth0  proto kernel  scope link  src 10.2.3.1
 * In this case `src'="10.2.3.1"  and `dev'="eth0"
 */
int rt_append_subnet_src(inet_prefix *src, char *dev)
{
	inet_prefix to, src_htonl;

	if(src->family == AF_INET6)
		fatal(ERROR_MSG "Family not supported", ERROR_POS);
	
	inet_copy(&src_htonl, src);
	inet_htonl(src_htonl.data, src->family);

	setzero(&to, sizeof(inet_prefix));
	to.family=src->family;
	to.len=src->len;
	if(((NTK_PRIVATE_B(src_htonl.data[0])) ||
			(NTK_PRIVATE_C(src_htonl.data[0])))) {
		to.bits=16;
		to.data[0]=htonl((src->data[0] & 0xffff0000));
	} else {
		to.bits=8;
		to.data[0]=htonl((src->data[0] & 0xff000000));
	}

	return route_append(0, RT_SCOPE_LINK, &src_htonl, &to, 0, dev, 0);
}
