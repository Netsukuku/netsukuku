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
 * bmap.c:
 * Border node map code.
 */

#include "includes.h"

#include "common.h"
#include "inet.h"
#include "endianness.h"
#include "map.h"
#include "gmap.h"
#include "bmap.h"

void bmap_levels_init(u_char levels, map_bnode ***bmap, u_int **bmap_nodes)
{
	*bmap=xmalloc(sizeof(map_bnode *) * levels);
	*bmap_nodes=(u_int *)xmalloc(sizeof(u_int) * levels);

	setzero(*bmap, sizeof(map_bnode *) * levels);
	bmap_counter_reset(levels, *bmap_nodes);
}

void bmap_levels_free(map_bnode **bmap, u_int *bmap_nodes)
{
	xfree(bmap);
	xfree(bmap_nodes);
}

void bmap_counter_init(u_char levels, u_int **bnodes_closed, u_int **bnodes_opened)
{
	*bnodes_closed=(u_int *)xmalloc(sizeof(u_int) * levels);
	*bnodes_opened=(u_int *)xmalloc(sizeof(u_int) * levels);
	
	bmap_counter_reset(levels, *bnodes_closed);
	bmap_counter_reset(levels, *bnodes_opened);
}

void bmap_counter_free(u_int *bnodes_closed, u_int *bnodes_opened)
{
	xfree(bnodes_closed);
	xfree(bnodes_opened);
}

void bmap_counter_reset(u_char levels, u_int *counter)
{
	setzero(counter, sizeof(u_int) * levels);
}

/* 
 * map_add_bnode: It adds a new bnode in the `bmap' and then returns its position
 * in the bmap. It also increments the `*bmap_nodes' counter. The bnode_ptr is set
 * to `bnode' and the links to `links'.
 * Note that the `bmap' argument must be an adress of a pointer.
 */
int map_add_bnode(map_bnode **bmap, u_int *bmap_nodes, u_int bnode, u_int links)
{
	map_bnode *bnode_map;
	u_int bm;
	
	bm=*bmap_nodes; 
	(*bmap_nodes)++;
	if(!bm)
		*bmap=xmalloc(sizeof(map_bnode));
	else
		*bmap=xrealloc(*bmap, sizeof(map_bnode) * *bmap_nodes);

	bnode_map=*bmap;
	setzero(bnode_map, sizeof(map_bnode));
	bnode_map[bm].bnode_ptr=bnode;
	bnode_map[bm].links=links;
	return bm;
}

/* 
 * map_bnode_del: It deletes the `bnode' in the `bmap' which has `bmap_nodes'.
 * It returns the newly rescaled `bmap'.
 * It returns 0 if the `bmap' doesn't exist anymore.*/
map_bnode *map_bnode_del(map_bnode *bmap, u_int *bmap_nodes,  map_bnode *bnode)
{
	map_node_del((map_node *)bnode);
	
	if( ((char *)bnode-(char *)bmap)/sizeof(map_bnode) != (*bmap_nodes)-1 )
		memcpy(bnode, &bmap[*bmap_nodes-1], sizeof(map_bnode));

	(*bmap_nodes)--;
	if(*bmap_nodes)
		return xrealloc(bmap, (*bmap_nodes) * sizeof(map_bnode));
	else {
		*bmap_nodes=0;
		xfree(bmap);
		return 0;
	}
}

/*
 * bmap_del_rnode_by_level: it is pretty specific, it deletes all the rnodes
 * of `bnode' which point to a gnode located in a level not equal to `level'.
 * The number of rnode deleted is returned.
 * `total_levels' must be equal to the maximum levels 
 * available (use FAMILY_LVLS).
 */
int bmap_del_rnode_by_level(map_bnode *bnode, int level, map_gnode **ext_map,
		int total_levels)
{ 
	map_gnode *gn;
	int i, ret=0, lvl;
	
	
	for(i=0; i < bnode->links; i++) {
		gn=(map_gnode *)bnode->r_node[i].r_node;
		lvl=extmap_find_level(ext_map, gn, total_levels);

		if(lvl != level) {
			rnode_del(bnode, i);
			ret++;
		}
	}

	return ret;
}

/* 
 * map_find_bnode: Find the given `node' (in the pos_from_node() format) in the
 * given map_bnode `bmap'.
 */
int map_find_bnode(map_bnode *bmap, int bmap_nodes, int node)
{
	int e;

	for(e=0; e<bmap_nodes; e++)
		if(bmap[e].bnode_ptr == node)
			return e;
	
	return -1;
}

/* 
 * map_find_bnode_rnode: Find the first bnode in the `bmap' which has a rnode
 * which points to `n'. If it is found the pos of the bnode in the `bmap' is
 * returned, otherwise -1 is the return value. 
 */
int map_find_bnode_rnode(map_bnode *bmap, int bmap_nodes, void *n)
{
	int e;

	for(e=0; e<bmap_nodes; e++)
		if(rnode_find((map_node *)&bmap[e], (map_node *)n) != -1)
			return e;

	return -1;
}

/*
 * map_count_bnode_rnode: counts how many bnode which have a rnode which
 * points to `n' there are in `bmap'.
 */
int map_count_bnode_rnode(map_bnode *bmap, int bmap_nodes, void *n)
{
	int e, i;

	for(i=0, e=0; i<bmap_nodes; i++)
		if(rnode_find((map_node *)&bmap[i], (map_node *)n) != -1)
			e++;

	return e;
}

/*
 * bmaps_count_bnode_rnode: applies map_count_bnode_rnode() to each level of
 * `bmap' and returns the sum of the results.
 * `levels' are the total levels of `bmap'.
 */
int bmaps_count_bnode_rnode(map_bnode **bmap, int *bmap_nodes, int levels, void *n)
{
	int i, e;

	for(i=0, e=0; i<levels; i++)
		e+=map_count_bnode_rnode(bmap[i], bmap_nodes[i], n);

	return e;
}

/*
 * map_del_bnode_rnode: deletes all the rnodes of the bnode, present in `bmap',
 * which points to `n' and deletes the bnodes remained empty.
 * `bmap' is the address of the pointer to the bmap.
 * It returns the number of rnodes deleted.
 */
int map_del_bnode_rnode(map_bnode **bmap, int *bmap_nodes, void *n)
{
	map_bnode *bm;
	int e, p, ret=0;

	bm=*bmap;
	for(e=0; e < *bmap_nodes; e++) {
		if((p=rnode_find((map_node *)&bm[e], (map_node *)n)) != -1) {
			rnode_del(&bm[e], p);

			if(!bm[e].links) {
				*bmap=map_bnode_del(*bmap,(u_int*)bmap_nodes, &bm[e]);
				bm=*bmap;
			}
			ret++;
		}
	}

	return ret;
}

/*
 * bmaps_del_bnode_rnode: applies map_del_bnode_rnode() to each level of
 * `bmap'.
 * `levels' are the total levels of `bmap'.
 * It returns the total number of rnodes deleted
 */
int bmaps_del_bnode_rnode(map_bnode **bmap, int *bmap_nodes, int levels, void *n)
{
	int i, e;

	for(i=0, e=0; i<levels; i++)
		e+=map_del_bnode_rnode(&bmap[i], &bmap_nodes[i], n);

	return e;
}

/*
 * map_set_bnode_flag: sets the `flags' to all the `bmap_nodes'# present in
 * `bmap'.
 */
void map_set_bnode_flag(map_bnode *bmap, int bmap_nodes, int flags)
{
	int e;
	for(e=0; e<bmap_nodes; e++)
		bmap[e].flags|=flags;
}

/*
 * bmaps_set_bnode_flag: sets the `flags' to all the bnodes present in the
 * `levels'#  `bmap'.
 */
void bmaps_set_bnode_flag(map_bnode **bmap, int *bmap_nodes, int levels, int flags)
{
	int i;		
	
	for(i=0; i<levels; i++)
		map_set_bnode_flag(bmap[i], bmap_nodes[i], flags);
}

/* 
 * pack_all_bmaps: It creates the block of all the `bmaps' which have
 * `bmap_nodes' nodes. `ext_map' and `quadg' are the structs referring
 * to the external map. In `pack_sz' is stored the size of the block.
 * The address pointing to the block is returned otherwise 0 is given.
 * The package will be in network order.
 */
char *
pack_all_bmaps(map_bnode **bmaps,  u_int *bmap_nodes, map_gnode **ext_map,
		quadro_group quadg, size_t *pack_sz)
{
	struct bnode_maps_hdr bmaps_hdr;
	size_t sz, tmp_sz[BMAP_LEVELS(quadg.levels)];
	char *pack[BMAP_LEVELS(quadg.levels)], *final_pack, *buf;
	u_char level;

	*pack_sz=0;

	for(level=0; level < BMAP_LEVELS(quadg.levels); level++) {
		pack[level]=pack_map((map_node *)bmaps[level], (int *)ext_map[_EL(level+1)], 
				bmap_nodes[level], 0, &sz);
		tmp_sz[level]=sz;
		(*pack_sz)+=sz;
	}

	bmaps_hdr.levels=BMAP_LEVELS(quadg.levels);
	bmaps_hdr.bmaps_block_sz=*pack_sz;
	(*pack_sz)+=sizeof(struct bnode_maps_hdr);
	
	final_pack=xmalloc((*pack_sz));
	memcpy(final_pack, &bmaps_hdr, sizeof(struct bnode_maps_hdr));
	ints_host_to_network(final_pack, bnode_maps_hdr_iinfo);
	
	buf=final_pack+sizeof(struct bnode_maps_hdr);
	for(level=0; level < BMAP_LEVELS(quadg.levels); level++) {
		memcpy(buf, pack[level], tmp_sz[level]);
		buf+=tmp_sz[level];
		xfree(pack[level]);
	}

	return final_pack;
}

/*
 * unpack_all_bmaps: Given a block `pack' of size `pack_sz' containing `levels'
 * it unpacks each bnode map it finds in it. 
 * `ext_map' is the external map used by the new bmaps.  
 * In `bmap_nodes' unpack_all_bmaps stores the address of the newly xmallocated 
 * array of u_int. Each bmap_nodes[x] contains the number of nodes of the bmap 
 * of level x.  
 * `maxbnodes' is the maximum number of nodes each bmap can contain,
 * while `maxbnode_rnodeblock' is the maximum number of rnodes each node can
 * contain.
 * On error 0 is returned.
 * Note: `pack' will be modified during the unpacking.
 */ 
map_bnode **
unpack_all_bmaps(char *pack, u_char max_levels, map_gnode **ext_map, 
		u_int **bmap_nodes, int maxbnodes, int maxbnode_rnodeblock)
{
	struct bnode_maps_hdr *bmaps_hdr;
	struct bnode_map_hdr *bmap_hdr;
	map_bnode **bmap, *unpacked_bmap;
	size_t bblock_sz, pack_sz;
	int i,e=0;
	char *bblock, *buf;
	u_char levels;
	
	bmaps_hdr=(struct bnode_maps_hdr *)pack;
	ints_network_to_host(bmaps_hdr, bnode_maps_hdr_iinfo);

	levels=bmaps_hdr->levels;
	pack_sz=bmaps_hdr->bmaps_block_sz;
	
	if(levels > max_levels || pack_sz < sizeof(struct bnode_maps_hdr))
		return 0;

	bmap_levels_init(levels, &bmap, bmap_nodes);

	buf=pack+sizeof(struct bnode_maps_hdr);
	for(i=0; i<levels; i++) {
		bmap_hdr=(struct bnode_map_hdr *)buf;
		if(!bmap_hdr->bnode_map_sz) {
			buf+=sizeof(struct bnode_map_hdr);
			continue;
		}
		
		/*Extracting the map...*/
		bblock=(char *)bmap_hdr;
		unpacked_bmap=unpack_map(bblock, (int *)ext_map[_EL(i+1)], 0,	
				maxbnodes, maxbnode_rnodeblock);
		if(!unpacked_bmap) {
			error("Cannot unpack the bnode_map at level %d ! Skipping...", i);
			e++;
			continue;
		}

		(*bmap_nodes)[i]=bmap_hdr->bnode_map_sz/MAP_BNODE_PACK_SZ;
		bblock_sz=INT_MAP_BLOCK_SZ(bmap_hdr->bnode_map_sz, bmap_hdr->rblock_sz);

		bmap[i]=unpacked_bmap;

		buf+=bblock_sz;
	}
	
	if(e == levels)
		/* Not a single map was restored */
		return 0;

	return bmap;
}

/* * *  save/load bnode_map * * */

/* 
 * save_bmap: It saves the bnode maps `bmaps' in `file'. The each `bmaps[x]' has
 * `bmap_nodes[x]' nodes. `ext_map' is the pointer to the external map the bmap is
 * referring to.
 */
int save_bmap(map_bnode **bmaps, u_int *bmap_nodes, map_gnode **ext_map, 
		quadro_group quadg, char *file)
{
	FILE *fd;
	char *pack;
	size_t pack_sz;
	
	
	pack=pack_all_bmaps(bmaps, bmap_nodes, ext_map, quadg, &pack_sz);
	if(!pack_sz || !pack)
		return 0;

	if((fd=fopen(file, "w"))==NULL) {
		error("Cannot save the bnode_map in %s: %s", file, strerror(errno));
		return -1;
	}
	fwrite(pack, pack_sz, 1, fd);

	xfree(pack);
	fclose(fd);
	return 0;
}

/*
 * load_bmap: It loads all the bnode maps from `file' and returns the address
 * of the array of pointer to the loaded bmaps. `ext_map' is the external maps
 * the bmap shall refer to. In `bmap_nodes' the address of the u_int array, used
 * to count the nodes in each bmaps, is stored. On error 0 is returned.
 */
map_bnode **load_bmap(char *file, map_gnode **ext_map, u_char max_levels, u_int **bmap_nodes)
{
	map_bnode **bmap=0;
	FILE *fd;
	struct bnode_maps_hdr bmaps_hdr;
	size_t pack_sz;
	u_char levels;
	char *pack=0;
	
	if((fd=fopen(file, "r"))==NULL) {
		error("Cannot load the bmap from %s: %s", file, strerror(errno));
		return 0;
	}
	
	if(!fread(&bmaps_hdr, sizeof(struct bnode_maps_hdr), 1, fd))
		goto finish;
		
	ints_network_to_host(&bmaps_hdr, bnode_maps_hdr_iinfo);
	levels=bmaps_hdr.levels;
	pack_sz=bmaps_hdr.bmaps_block_sz;
	if(levels > max_levels || pack_sz < sizeof(struct bnode_maps_hdr))
		goto finish;

	/* Extracting the map... */
	rewind(fd);
	pack=xmalloc(pack_sz);
	if(!fread(pack, pack_sz, 1, fd))
		goto finish;
	
	bmap=unpack_all_bmaps(pack, max_levels, ext_map, bmap_nodes, 
			MAXGROUPNODE, MAXBNODE_RNODEBLOCK);
	
finish:
	fclose(fd);
	if(pack)
		xfree(pack);
	if(!bmap)
		error("Malformed bmap file. Cannot load the bnode maps.");
	return bmap;
}
