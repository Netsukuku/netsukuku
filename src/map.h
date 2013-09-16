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

#ifndef MAP_H
#define MAP_H

#include "inet.h"

/* Generic map defines */
#define MAXGROUPNODE_BITS	8	/* 2^MAXGROUPNODE_BITS == MAXGROUPNODE */
#define MAXGROUPNODE		(1<<MAXGROUPNODE_BITS)
#define MAXROUTES	 	20

#define MAXLINKS		MAXROUTES

/*** flags ***/
#define MAP_ME		1		/*The root_node, in other words, me ;)*/
#define MAP_VOID	(1<<1)		/*It indicates a non existent node*/
#define MAP_HNODE	(1<<2)		/*Hooking node. The node is currently 
					  hooking*/
#define MAP_BNODE	(1<<3)		/*The node is a border_node. If this 
					  flag is set to a root_node, this means 
					  that we are a bnode at the root_node's 
					  level*/
#define MAP_ERNODE	(1<<4)		/*It is an External Rnode*/
#define MAP_GNODE	(1<<5)		/*It is a gnode*/
#define MAP_RNODE	(1<<6)		/*If a node has this set, it is one of the rnodes*/
#define MAP_UPDATE	(1<<7)		/*If it is set, the corresponding route 
					  in the krnl will be updated*/
#define QSPN_CLOSED	(1<<8)		/*This flag is set only to the rnodes, 
					  it puts a link in a QSPN_CLOSED state*/
#define QSPN_OPENED	(1<<9)		/*It puts a link in a QSPN_OPEN state*/
#define QSPN_OLD	(1<<10)		/*If a node isn't updated by the current
					  qspn_round it is marked with QSPN_ROUND.
					  If in the next qspn_round the same node 
					  isn't updated it is removed from the map.*/
#define QSPN_STARTER	(1<<11)		/*The root node is marked with this flag
					  if it is a qspn_starter*/
#define QSPN_OPENER	(1<<12)		/*If the root_node sent a new qspn_open
					  it is a qspn_opener*/
#define MAP_IGW		(1<<13)		/*This node is an Internet gateway*/


/*\ 			    
 * 			    *** Map notes ***
 *
 * The map is an array of MAXGROUPNODE map_node structs. It is a generic map 
 * and it is used to keep the qspn_map, the internal map and the external map.
 * The position in the map of each struct corresponds to its relative ip.
 * For example, if the map goes from 192.128.1.0 to 192.128.3.0, the map will
 * have 512 structs, the first one will correspond to 192.168.1.0, the 50th to
 * 192.168.1.50 and so on.
 * Note: because MAXGROUPNODE is 256, we can use an u_char for the index of the
 * array.
 *
\*/

/* map_rnode is what map_node.r_node points to. (read struct map_node below) */
typedef struct
{
	int	 	*r_node;	/*It's the pointer to the struct of the
					  r_node in the map*/
	u_int		trtt;		
	/*
	 * node <-> root_node total rtt: The rtt to reach the root_node 
	 * starting from the node which uses this rnode (in millisec). 
	 * Cuz I've explained it in such a bad way I make an example:
	 * map_node node_A; From node_A "node_A.links"th routes to the root_node
	 * start. So I have "node_A.links"th node_A.r_node[s], each of them is a
	 * different route to reach the root_node. 
	 * With the node_A.r_node[route_number_to_follow].trtt I can get the rtt 
	 * needed to reach the root_node starting from the node_A using the 
	 * route_number_to_follow. Gotcha? I hope so.
	 * Note: The trtt is mainly used to sort the routes
	 */
}map_rnode;

/* Note: This int_info is used for the pack of a map_rnode struct (see 
 * get_rnode_block()). 
 * Since the r_node pointer, in the pack, is an integer, we add it in the
 * int_info as a normal 32bit int. */
INT_INFO map_rnode_iinfo  = { 2, 
			      { INT_TYPE_32BIT, INT_TYPE_32BIT },
			      { 0, sizeof(int) },
			      { 1, 1 }
			    };
#define MAP_RNODE_PACK_SZ	(sizeof(int *)+sizeof(u_int))

/*
 * 		****) The qspn int_map (****
 *
 * - map_node.r_node points to the r_node of the root_node to be used as 
 *   gateway to reach map_node. So map_node.r_node stores only the gateway 
 *   needed to reach map_node from the root_node.
 *   The only execption is the root_node itself. The root_node's 
 *   map_node.r_node keeps all its rnodes as a normal (non qspn) map would.
 *
 * The only exception is the root_node. Its rnodes have a different meaning: 
 * they are its effective rnodes, so each map_node.r_node points to the node 
 * which is the real rnode of the root_node.
 * The root_node at level 0 may have also rnode of a different gnode 
 * (it is a border node).
 * To store these external rnodes in root_node.r_node[x], the 
 * root_node.r_node[x].r_node will point to the relative ext_rnode struct 
 * (see gmap.h) and the MAP_GNODE | MAP_ERNODE flags will be set in 
 * root_node.r_node[x].flags.
 * The rnodes of the root_node of 0 level are updated by the radar(), 
 * instead the root_nodes of greater levels are updated by the qspn.
 */
typedef struct
{
	u_short 	flags;
	u_int		brdcast;	 /*Pkt_id of the last brdcast_pkt sent by this node*/
	u_short		links;		 /*Number of r_nodes*/
	map_rnode	*r_node;	 /*These structs will be kept in ascending
					   order considering their rnode_t.rtt*/
}map_node;

/* Note: This int_info is used for the pack of a map_rnode struct (see
 * pack_map()) */
INT_INFO map_node_iinfo = { 3, 
			    { INT_TYPE_16BIT, INT_TYPE_32BIT, INT_TYPE_16BIT },
			    { 0, sizeof(short), sizeof(short)+sizeof(int) },
			    { 1, 1, 1 }
			  };

#define MAP_NODE_PACK_SZ	(sizeof(u_short)*2 + sizeof(u_int))

#define MAXRNODEBLOCK		(MAXLINKS * MAXGROUPNODE * sizeof(map_rnode))
#define MAXRNODEBLOCK_PACK_SZ	(MAXLINKS * MAXGROUPNODE * MAP_RNODE_PACK_SZ)
#define INTMAP_END(mapstart)	((sizeof(map_node)*MAXGROUPNODE)+(mapstart))

/*This block is used to send/save the int_map and the bnode_map*/
struct int_map_hdr
{
	u_char root_node;
	size_t int_map_sz;
	size_t rblock_sz;
}_PACKED_;
INT_INFO int_map_hdr_iinfo = { 2, 
			       { INT_TYPE_32BIT, INT_TYPE_32BIT }, 
			       { sizeof(char), sizeof(char)+sizeof(size_t) },
			       { 1, 1 }
			     };

/*
 * The int_map_block is:
 * 	struct int_map_hdr hdr;
 * 	char map_node[int_map_sz];
 * 	char map_rnode[rblock_sz];
 */
#define INT_MAP_BLOCK_SZ(int_map_sz, rblock_sz) (sizeof(struct int_map_hdr)+(int_map_sz)+(rblock_sz))


/* 
 * * * Functions' declaration * * *
 */

/*conversion functions*/
int pos_from_node(map_node *node, map_node *map);
map_node *node_from_pos(int pos, map_node *map);
void postoip(u_int map_pos, inet_prefix ipstart, inet_prefix *ret);
void maptoip(u_int mapstart, u_int mapoff, inet_prefix ipstart, inet_prefix *ret);
int iptomap(u_int mapstart, inet_prefix ip, inet_prefix ipstart, map_node **ret);

map_node *init_map(size_t len);
void free_map(map_node *map, size_t count);
void map_node_del(map_node *node);
void reset_int_map(map_node *map, int maxgroupnode);

map_rnode *rnode_insert(map_rnode *buf, size_t pos, map_rnode *new);
map_rnode *map_rnode_insert(map_node *node, size_t pos, map_rnode *new);
map_rnode *rnode_add(map_node *node, map_rnode *new);
void rnode_swap(map_rnode *one, map_rnode *two);
void rnode_del(map_node *node, size_t pos);
void rnode_destroy(map_node *node);
int rnode_find(map_node *node, void *n);

int rnode_trtt_compar(const void *a, const void *b);
void rnode_trtt_order(map_node *node);
void map_routes_order(map_node *map);

u_int get_route_trtt(map_node *node, u_short route);
void rnode_set_trtt(map_node *node);
void rnode_recurse_trtt(map_rnode *rnode, int route, struct timeval *trtt);
void node_recurse_trtt(map_node *node);
void map_set_trtt(map_node *map);
map_node *get_gw_node(map_node *node, u_short route);

int merge_maps(map_node *base, map_node *new, map_node *base_root, map_node *new_root);
int mod_rnode_addr(map_rnode *node, int *map_start, int *new_start);
int get_rnode_block(int *map, map_node *node, map_rnode *rblock, int rstart);
map_rnode *map_get_rblock(map_node *map, int *addr_map, int maxgroupnode, int *count);
int store_rnode_block(int *map, map_node *node, map_rnode *rblock, int rstart);
int map_store_rblock(map_node *map, int *addr_map, int maxgroupnode, map_rnode *rblock);

int verify_int_map_hdr(struct int_map_hdr *imap_hdr, int maxgroupnode, int maxrnodeblock);
void pack_map_node(map_node *node, char *pack);
void unpack_map_node(map_node *node, char *pack);
char *pack_map(map_node *map, int *addr_map, int maxgroupnode, map_node *root_node, size_t *pack_sz);
map_node *unpack_map(char *pack, int *addr_map, map_node **new_root, int maxgroupnode, int maxrnodeblock);
int save_map(map_node *map, map_node *root_node, char *file);
map_node *load_map(char *file, map_node **new_root);

#endif /*MAP_H*/
