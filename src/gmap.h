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

#ifndef GMAP_H
#define GMAP_H

#include "llist.c"
#include "map.h"

/* * * Groupnode stuff * * */
#define GMAP_ME		MAP_ME		/*1*/
#define GMAP_VOID	MAP_VOID	/*(1<<1)*/
#define GMAP_HGNODE	(1<<2)		/*Hooked Gnode. We already hooked at 
					  this gnode */
#define GMAP_FULL	(1<<3)		/*The gnode is full!! aaahh, run away!*/

/* This is the holy external_map. Each struct corresponds to a groupnode. 
 * This groupnode cointains MAXGROUPNODE nodes if we are at level 1 or 
 * MAXGROUPNODE groups. The map is equal to the int_map, in fact, a map_node
 * is embedded in a map_gnode. 
 * This int_map uses the QSPN_MAP_STYLEII (see qspn.h). */
typedef struct
{
	/* 
	 * The gnode_map starts here. Note that it is a normal map. (See map.h). 
	 * It is here, at the top of the struct to allow to manipulate a map_gnode
	 * as a map_node with the help of the magic cast. The cast is heavily 
	 * used in qspn.c
	 */
	map_node	g;
	
	u_char 		flags;
	u_char		seeds;	/*The number of active static nodes connected to this
				  gnode minus one (the root_node is not counted).
				  If seeds == MAXGROUPNODE-1, the gnode is full ^_^*/
	u_int		gcount;	/*The total number of nodes which are inside this 
				  gnode*/
} map_gnode;

INT_INFO map_gnode_iinfo = { 1, 
			     { INT_TYPE_32BIT }, 
			     { MAP_NODE_PACK_SZ+sizeof(u_char)*2 }, 
			     { 1 }
			   };
#define MAP_GNODE_PACK_SZ	(MAP_NODE_PACK_SZ+sizeof(u_char)*2+sizeof(int))


/*
 * 			* * * Levels notes * * *
 * 			
 * These are the levels of the external_map. Note that the 0 level is never used 
 * for the ext_map because it corresponds to the internal map. Btw the 0 level is 
 * counted so the number of LEVELS includes it too. 
 * But we have to add another extra level: the last exiled level. It is also never 
 * used but it is vital, cause, its gnode 0 includes the entire Netsukuku, the other
 * gnodes aren't used, it is a mere symbol. We call it the unity level.
 *
 * All the structs/arrays related to the external map, and the ext_map itself, don't
 * use the EXTRA_LEVELS, thus, they lack of the zero level. To retrieve the position 
 * in the array from the level the _EL macro must be used. In other words: 
 * because the arrays goes from 0 to n-1 we refer to the levels as the arrays,
 * so the level 1 is the level 0, the level 2 is the level 1, and so on.
 * These arrays/structs are: quadg.gnode, rblock, ext_map, qspn_gnode_count.
 */
#define ZERO_LEVEL	1
#define UNITY_LEVEL	1
#define EXTRA_LEVELS	(ZERO_LEVEL + UNITY_LEVEL)
/* To use the right level. */
#define _EL(level)    ((level)-1)
/* And to restore it. */
#define _NL(level)    ((level)+1)

/* 
 * Using MAXGROUPNODE = 2^8; IPV4_LEVELS = 3; ips = 2^32;
 * 	ips/(MAXGROUPNODE^IPV4_LEVELS) == 256;
 * If we use IPV4_LEVELS = 3, we almost cover all the ips, but the division gives
 * 256. So there are only 256 groups in the last level (3), in fact:
 *      ips/(256 * (MAXGROUPNODE^3)) == 1
 * And to include them we use the unity level, thus IPV4_LEVELS is equal to 3+1.
 * This means that the unity level is the one which has only one group node which includes
 * the entire network.
 * Sadly we cannot use all this ips, because there are the banned classes (MULTICAST,
 * ZERONET), the kernel will sput on us.
 * 
 * For the ipv6 we have IPV6_LEVELS = 16, ips = 2^128; so:
 *      ips/(MAXGROUPNODE^16) == 1
 */
#define IPV4_LEVELS		(2+EXTRA_LEVELS)

#define IPV6_LEVELS		(14+EXTRA_LEVELS)

#define MAX_LEVELS		IPV6_LEVELS
#ifdef DEBUG
#define GET_LEVELS(family)						\
({ 									\
	if((family) != AF_INET && (family) != AF_INET6)			\
		fatal("GET_LEVELS: family not specified!");		\
	(family) == AF_INET ? IPV4_LEVELS : IPV6_LEVELS;		\
 })
#else
#define GET_LEVELS(family) ({ (family)==AF_INET ? IPV4_LEVELS : IPV6_LEVELS; })
#endif

#define FAMILY_LVLS		(GET_LEVELS(my_family))

/* NODES_PER_LEVEL: returns the maximum number of nodes which can reside in
 * a gnode of the `lvl'th level */
#define NODES_PER_LEVEL(lvl)	((1<<(MAXGROUPNODE_BITS*(lvl))))

/* Struct used to keep all the quadro_group ids of a node. (The node is part of this
 * quadro groups) */
typedef struct {
	u_char      levels;		 /*How many levels we have*/
	int         gid[MAX_LEVELS];	 /*Group ids. Each element is the gid of the quadrogroup in the 
					   relative level. (ex: gid[n] is the gid of the quadropgroup a 
					   the n-th level)*/
	map_gnode  *gnode[MAX_LEVELS-ZERO_LEVEL]; /*Each element is a pointer to the relative
						    gnode in the ext_map.*/
	inet_prefix ipstart[MAX_LEVELS]; /*The ipstart of each quadg.gid in their respective levels*/
}quadro_group;

/* Note: this is the int_info of the a packed quadro_group struct, which
 * hasnt't the `map_gnode *gnode' pointers. The ipstart structs must be also
 * packed with pack_inet_prefix() */
INT_INFO quadro_group_iinfo = { 1, 
				{ INT_TYPE_32BIT },
				{ sizeof(u_char) },
				{ MAX_LEVELS }
			      };
#define QUADRO_GROUP_PACK_SZ (sizeof(u_char) + sizeof(int)*MAX_LEVELS +     \
				+ INET_PREFIX_PACK_SZ * MAX_LEVELS)

/*These are the flags passed to iptoquadg()*/
#define QUADG_IPSTART 1
#define QUADG_GID     (1<<1)
#define QUADG_GNODE   (1<<2)

/* This block is used to send the ext_map */
struct ext_map_hdr
{
	char   quadg[QUADRO_GROUP_PACK_SZ];  /* The packed me.cur_quadg */

	size_t ext_map_sz; 		/*It's the sum of all the gmaps_sz.
					  The size of a single map is:
					  (ext_map_sz/(MAP_GNODE_PACK_SZ*
					  (quadg.levels-EXTRA_LEVELS)); */
	size_t rblock_sz[MAX_LEVELS];	/*The size of the rblock of each gmap*/
	size_t total_rblock_sz;		/*The sum of all rblock_sz*/
}_PACKED_;

/* Note: You have to consider the quadro_group struct when convert between
 * endianness */
INT_INFO ext_map_hdr_iinfo = { 3, 
			       { INT_TYPE_32BIT, INT_TYPE_32BIT, INT_TYPE_32BIT },
			       { QUADRO_GROUP_PACK_SZ, 
				   QUADRO_GROUP_PACK_SZ+sizeof(size_t),
				   QUADRO_GROUP_PACK_SZ+(sizeof(size_t)*(MAX_LEVELS+1)) },
			       { 1, MAX_LEVELS, 1 }
			     };
	
/* The ext_map_block is:
 * 	struct ext_map_hdr hdr;
 * 	char ext_map[ext_map_sz];
 * 	char rnode_blocks[total_rblock_sz];
 */
#define EXT_MAP_BLOCK_SZ(ext_map_sz, rblock_sz) (sizeof(struct ext_map_hdr)+(ext_map_sz)+(rblock_sz))

/* 
 * This struct is used by the root_node to describe all the rnodes which
 * doesn't belongs to our same gnode.
 */
typedef struct {
	map_node	node;
	quadro_group 	quadg;	/* quadg.gnode[level] may be set to 0
				 * if that gnode doesn't belong to the
				 * same upper level of me.cur_quadg:
				 * quadg.gid[level+1] != me.cur_quadg.gid[level+1]
				 */
}ext_rnode;

/*This cache keeps the list of all the ext_rnode used.*/
struct ext_rnode_cache {
	LLIST_HDR	(struct ext_rnode_cache);

	ext_rnode	*e;		/*The pointer to the ext_rnode struct*/
	int		rnode_pos;	/*The ext_rnode position in the 
					  array of rnodes of the root_node */
};
typedef struct ext_rnode_cache ext_rnode_cache;

/* * * Functions' declaration * * */
inline int get_groups(int family, int lvl);
int is_group_invalid(int *gids, int gid, int lvl, int family);

int  pos_from_gnode(map_gnode *gnode, map_gnode *map);
map_gnode * gnode_from_pos(int pos, map_gnode *map);
void rnodetoip(u_int mapstart, u_int maprnode, inet_prefix ipstart, inet_prefix *ret);
const char *rnode_to_ipstr(u_int mapstart, u_int maprnode, inet_prefix ipstart);
int iptogid(inet_prefix *ip, int level);
void iptogids(inet_prefix *ip, int *gid, int levels);
void gidtoipstart(int *gid, u_char total_levels, u_char levels, int family, 
		inet_prefix *ip);
void iptoquadg(inet_prefix ip, map_gnode **ext_map, quadro_group *qg, char flags);

void quadg_setflags(quadro_group *qg, char flags);
void quadg_free(quadro_group *qg);
void quadg_destroy(quadro_group *qg);
void gnode_inc_seeds(quadro_group *qg, int level);
void gnode_dec_seeds(quadro_group *qg, int level);
void pack_quadro_group(quadro_group *qg, char *pack);
void unpack_quadro_group(quadro_group *qg, char *pack);

int free_gids(quadro_group *qg, int level, map_gnode **ext_map,	map_node *int_map);
int void_gids(quadro_group *qg, int level, map_gnode **ext_map,	map_node *int_map);

int random_ip(inet_prefix *ipstart, int final_level, int final_gid, 
		int total_levels, map_gnode **ext_map, int only_free_gnode, 
		inet_prefix *new_ip, int my_family);
void gnodetoip(quadro_group *quadg, int gnodeid, u_char level, inet_prefix *ip);
int gids_cmp(int *gids_a, int *gids_b, int lvl, int max_lvl);
int quadg_gids_cmp(quadro_group a, quadro_group b, int lvl);
int ip_gids_cmp(inet_prefix a, inet_prefix b, int lvl);
ext_rnode_cache *erc_find(ext_rnode_cache *erc, ext_rnode *e_rnode);
void e_rnode_del(ext_rnode_cache **erc_head, u_int *counter, ext_rnode_cache *erc);
void e_rnode_add(ext_rnode_cache **erc, ext_rnode *e_rnode, int rnode_pos, u_int *counter);
ext_rnode_cache *e_rnode_init(u_int *counter);
void e_rnode_free(ext_rnode_cache **erc, u_int *counter);
ext_rnode_cache *e_rnode_find(ext_rnode_cache *erc, quadro_group *qg, int level);
void erc_update_rnodepos(ext_rnode_cache *erc, map_node *root_node, int old_rnode_pos);
void erc_reorder_rnodepos(ext_rnode_cache **erc, u_int *erc_counter, map_node *root_node);
ext_rnode_cache *erc_find_gnode(ext_rnode_cache *erc, map_gnode *gnode, u_char level);

map_gnode *init_gmap(int groups);
void reset_gmap(map_gnode *gmap, int groups);
map_gnode **init_extmap(u_char levels, int groups);
void free_extmap(map_gnode **ext_map, u_char levels, int groups);
void reset_extmap(map_gnode **ext_map, u_char levels, int groups);

int  g_rnode_find(map_gnode *gnode, map_gnode *n);
int  extmap_find_level(map_gnode **ext_map, map_gnode *gnode, u_char max_level);
void gmap_node_del(map_gnode *gnode);

int merge_ext_maps(map_gnode **base, map_gnode **new, quadro_group base_root,
		quadro_group new_root);

int verify_ext_map_hdr(struct ext_map_hdr *emap_hdr, quadro_group *quadg);
void free_extmap_rblock(map_rnode **rblock, u_char levels);
void pack_map_gnode(map_gnode *gnode, char *pack);
void unpack_map_gnode(map_gnode *gnode, char *pack);
char *pack_extmap(map_gnode **ext_map, int maxgroupnode, quadro_group *quadg, size_t *pack_sz);
map_gnode **unpack_extmap(char *package, quadro_group *quadg);
int save_extmap(map_gnode **ext_map, int maxgroupnode, quadro_group *quadg, char *file);
map_gnode **load_extmap(char *file, quadro_group *quadg);

#endif /*GMAP_H*/
