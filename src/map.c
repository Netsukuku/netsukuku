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
 * Internal map code.
 */

#include "includes.h"

#include "ipv6-gmp.h"
#include "map.h"
#include "common.h"

extern int errno;

/*
 * pos_from_node: Position from node: It returns the position of the `node'
 * in the `map'.
 */
int pos_from_node(map_node *node, map_node *map)
{
	return ((char *)node-(char *)map)/sizeof(map_node);
}

/*
 * Node from position: it returns the node pointer calculated by the given 
 * `pos' in the map.
 */
map_node *node_from_pos(int pos, map_node *map)
{
	return (map_node *)((pos*sizeof(map_node))+(char *)map);
}

/* 
 * Position (of a struct in the map) to ip: Converts the node position 
 * `map_pos' to its relative ip.
 */
void postoip(u_int map_pos, inet_prefix ipstart, inet_prefix *ret) 
{
	ret->family=ipstart.family;
	if(ipstart.family==AF_INET) {
		ret->data[0]=map_pos + ipstart.data[0];
		ret->len=4;
	} else {
		ret->len=16;
		inet_copy_ipdata_raw(ret->data, &ipstart);
		sum_int(map_pos, ret->data);
	}
	ret->bits=ret->len*8;
}

/* 
 * Map (address) to ip: Converts an address of a struct in the map to the
 * corresponding ip.
 */
void maptoip(u_int mapstart, u_int mapoff, inet_prefix ipstart, inet_prefix *ret)
{
	int map_pos=pos_from_node((map_node *)mapoff, (map_node *)mapstart);
	postoip(map_pos, ipstart, ret);
}

/*
 * iptomap: Converts an ip to an address of a struct in the map and stores it
 * int `*ret'.
 */
int iptomap(u_int mapstart, inet_prefix ip, inet_prefix ipstart, map_node **ret)
{
	if(ip.family==AF_INET)
		*ret=(map_node *)(((ip.data[0]-ipstart.data[0])*sizeof(map_node))+mapstart);
	else {
		uint32_t h_ip[MAX_IP_INT], h_ipstart[MAX_IP_INT];

		memcpy(h_ip, ip.data, MAX_IP_SZ);
		memcpy(h_ipstart, ipstart.data, MAX_IP_SZ);

		/* h_ipstart=h_ip - h_ipstart */
		sub_128(h_ip, h_ipstart);
		/* The result is always < MAXGROUPNODE, so we can take for grant that
		 * we have only one u_int*/
		*ret=(map_node *)(h_ipstart[0]*sizeof(map_node)+mapstart);
	}

	if(*ret > (map_node *)INTMAP_END(mapstart) || *ret < (map_node *)mapstart)
		/*Ok, this is an extern ip to our gnode.*/
		return 1;

	return 0;
}

map_node *init_map(size_t len)
{
	int i;
	map_node *map;
	if(!len)
		len=sizeof(map_node)*MAXGROUPNODE;
	
	map=(map_node *)xmalloc(len);
	setzero(map, len);
	for(i=0; i<MAXGROUPNODE; i++)
		map[i].flags|=MAP_VOID;
	
	return map;
}

void free_map(map_node *map, size_t count)
{
	int i, len;

	if(!count)
		count=MAXGROUPNODE;
	len=sizeof(map_node)*count;
	
	for(i=0; i<count; i++) {
		if(map[i].links) {
			if(map[i].r_node)
				xfree(map[i].r_node);
		}
	}
	
	setzero(map, len);
	xfree(map);
}


map_rnode *rnode_insert(map_rnode *buf, size_t pos, map_rnode *new)
{
	map_rnode *ptr=buf+pos;
	
	memcpy(ptr, new, sizeof(map_rnode));
	return ptr;
}

map_rnode *map_rnode_insert(map_node *node, size_t pos, map_rnode *new)
{
	if(pos >= node->links)
		fatal("Error in %s: %d: Cannot insert map_rnode in %u position."
				" It goes beyond the buffer\n", ERROR_POS, pos);
	
	return rnode_insert(node->r_node, pos, new);
}
			
map_rnode *rnode_add(map_node *node, map_rnode *new)
{
	node->links++;
	if(node->links == 1)
		node->r_node=xmalloc(sizeof(map_rnode));
	else
		node->r_node=xrealloc(node->r_node, node->links*sizeof(map_rnode));
	return map_rnode_insert(node, node->links-1, new);
}

void rnode_swap(map_rnode *one, map_rnode *two)
{
	map_rnode tmp;
	
	memcpy(&tmp, one, sizeof(map_rnode));
	memcpy(one, two, sizeof(map_rnode));
	memcpy(two, &tmp, sizeof(map_rnode));
}

void rnode_del(map_node *node, size_t pos)
{
	if(pos >= node->links || node->links <= 0)
		fatal("Error in %s: %d: Cannot delete Map_rnode in %u position."
				" It goes beyond the buffer\n",ERROR_POS, pos);
	if(pos!=node->links-1)
		rnode_swap((map_rnode *)&node->r_node[pos], 
				(map_rnode *)&node->r_node[(node->links-1)]);
					
	node->links--;
	if(!node->links) {
		xfree(node->r_node);
		node->r_node=0;
	} else
		node->r_node=xrealloc(node->r_node, node->links*sizeof(map_rnode));
}

/* 
 * rnode_destroy
 *
 * Wipe out all the rnodes YEAHAHA ^_- 
 */
void rnode_destroy(map_node *node)
{
	if(node->r_node && node->links)
		xfree(node->r_node);
	node->r_node=0;
	node->links=0;
}

/*
 * rnode_find
 *
 * It searches in the `node' a rnode which points to the node `n'.
 * It then returns the position of that rnode.
 * If the rnode is not found it returns -1;
 */
int rnode_find(map_node *node, void *n)
{
	int e;
	for(e=0; e < node->links; e++)
		if(node->r_node[e].r_node == n)
			return e;
	return -1;
}


/*
 * map_node_del: It deletes a `node' from the `map'. Really it frees its rnodes
 * and set the node's flags to MAP_VOID.
 */
void map_node_del(map_node *node)
{
	rnode_destroy(node);
	setzero(node, sizeof(map_node));
	node->flags|=MAP_VOID;
}

void reset_int_map(map_node *map, int maxgroupnode)
{
	int i;
	
	if(!maxgroupnode)
		maxgroupnode=MAXGROUPNODE;
	
	for(i=0; i<maxgroupnode; i++)
		map_node_del(&map[i]);
}

/*
 * rnode_trtt_compar: It's used by rnode_trtt_order
 */
int rnode_trtt_compar(const void *a, const void *b) 
{
	map_rnode *rnode_a=(map_rnode *)a, *rnode_b=(map_rnode *)b;
	
	if (rnode_a->trtt > rnode_b->trtt)
		return 1;
	else if(rnode_a->trtt == rnode_b->trtt)
		return 0;
	else 
		return -1;
}

/* 
 * rnode_trtt_order
 *
 * It qsorts the rnodes of a map_node comparing their trtt. 
 * It is used by map_routes_order.
 */
void rnode_trtt_order(map_node *node)
{
	qsort(node->r_node, node->links, sizeof(map_rnode), rnode_trtt_compar);
}

/* 
 * map_routes_order
 *
 * It orders all the r_node of each node using their trtt.
 */
void map_routes_order(map_node *map)
{
	int i;
	for(i=0; i<MAXGROUPNODE; i++)
		rnode_trtt_order(&map[i]);
}

/* 
 * get_route_trtt
 *
 * It returns the total round trip time (trtt) of `node' (in millisec) for the
 * `route'th route.
 */
u_int get_route_trtt(map_node *node, u_short route)
{
	if(route >= node->links || node->flags & MAP_VOID || node->links <= 0)
		return -1;

	if(node->flags & MAP_ME)
		return 0;

	return node->r_node[route].trtt;
}

/*
 * merge_maps: 
 *
 * Given two maps it merges them selecting only the best routes.
 * In `base' map there will be the resulting map. The `new' map is the
 * second map. `base_root' points to the root_node present in the `base' map.
 * `new_root' points to the root_node of the `new' map.
 * It's assumed that `new_root' is a rnode of `base_root'.
 * Note that the `new' map is modified during the merging!
 */
int merge_maps(map_node *base, map_node *new, map_node *base_root, map_node *new_root)
{
	int i, e, x, count=0, base_root_pos, ngpos;
	u_int base_trtt, new_trtt;
	map_node *new_root_in_base, *node_gw;
	
	base_root_pos=pos_from_node(base_root, base);
	new_root_in_base=&base[pos_from_node(new_root, new)];
		
	for(i=0; i<MAXGROUPNODE; i++) {
		if(base[i].flags & MAP_ME || new[i].flags & MAP_ME ||
				new[i].flags & MAP_VOID)
			continue;
		
		for(e=0; e<new[i].links; e++) {
			/* 
			 * We set in node_gw the gw that must be used to reach
			 * the new[i] node, with the new_root_node as the 
			 * starting point; `node_gw' is a rnode of new_root_node.
			 */
			node_gw=(map_node *)new[i].r_node[e].r_node; 
			
			ngpos=pos_from_node(node_gw, new);
			if(ngpos == base_root_pos)
				/* We skip, cause the new_map it's using the 
				 * base_root node (me) as gw to reach new[i]. 
				 */
				continue;

			/* 
			 * Now we change the r_nodes pointers of the new map to
			 * let them point to the base map's nodes. 
			 */
			if(new[i].flags & MAP_RNODE) {
				/* 
				 * new[i] is a rnode of new_root node, so we
				 * reach it trough new_root.
				 */
				new[i].r_node[e].r_node=(int *)new_root_in_base;

			} else if(base[ngpos].flags & MAP_VOID || 
					!base[ngpos].links) {
				/*
				 * In the `base' map, `node_gw' is VOID.
				 * We must use the new_root node as gw because
				 * it is one of our rnode.
				 */
				new[i].r_node[e].r_node=(int *)new_root_in_base;
			} else {
				/* 
				 * In this case the node_gw is already known in
				 * the base map, so we change it to the gw used
				 * to reach itself in the base map.
				 */
				new[i].r_node[e].r_node=base[ngpos].r_node[0].r_node;
			}
			
			/*
			 * new[i] has more routes than base[i]. Add them in
			 * base[i].
			 */
			if(e >= base[i].links) {
				rnode_add(&base[i], &new[i].r_node[e]);
				rnode_trtt_order(&base[i]);
				base[i].flags|=MAP_UPDATE;
				count++;
				
				continue;
			}
		
			/* 
			 * If the worst route in base[i] is better than the best
			 * route in new[i], let's go ahead.
			 */
			base_trtt = get_route_trtt(&base[i], base[i].links-1);
			new_trtt  = get_route_trtt(&new[i], e);
			if(base_trtt < new_trtt)
				continue;
		
			/* 
			 * Compare the each route of base[i] with
			 * new[i].r_node[e]. The first route of base[i] which
			 * is found to be worse than new[i].r_node[e] is
			 * deleted and replaced with new[i].r_node[e] itself.
			 */
			for(x=0; x<base[i].links; x++) {
				base_trtt = get_route_trtt(&base[i], x);
				new_trtt  = get_route_trtt(&new[i], e);
				if(base_trtt > new_trtt) {
					map_rnode_insert(&base[i], x, &new[i].r_node[e]);
					base[i].flags|=MAP_UPDATE;
					count++;
					break;
				}
			}
		}
		
		if(base[i].links)
			base[i].flags&=~MAP_VOID;
		else
			map_node_del(&base[i]);
	}

	return count;
}

/* 
 * mod_rnode_addr
 *
 * Modify_rnode_address
 */
int mod_rnode_addr(map_rnode *rnode, int *map_start, int *new_start)
{
	rnode->r_node = (int *)(((char *)rnode->r_node - (char *)map_start) + (char *)new_start);
	return 0;
}

/* 
 * get_rnode_block
 *
 * It packs all the rnode structs of a node. The node->r_node pointer of the
 * map_rnode struct is changed to point to the position of the node in the map,
 * instead of the address. get_rnode_block returns the number 
 * of rnode structs packed.
 * Note that the packed structs will be in network order.
 */
int get_rnode_block(int *map, map_node *node, map_rnode *rblock, int rstart)
{
	int e;
	char *p;

	for(e=0; e<node->links; e++) {
		p=(char *)&rblock[e+rstart];
		
		memcpy(p, &node->r_node[e].r_node, sizeof(int *));
		p+=sizeof(int *);

		memcpy(p, &node->r_node[e].trtt, sizeof(u_int));
		p+=sizeof(u_int);
		
		mod_rnode_addr(&rblock[e+rstart], map, 0);

		ints_host_to_network(&rblock[e+rstart], map_rnode_iinfo);
	}

	return e;
}

/* 
 * map_get_rblock
 *
 * It uses get_rnode_block to pack all the int_map's rnode.
 * `maxgroupnode' is the number of nodes present in the map.
 * `map' is the actual int_map, while `addr_map' is the address used by get_rnode_block
 * to change the rnodes' pointers (read get_rnode_block).
 * It returns a pointer to the start of the rnode block and stores in `count'
 * the number of rnode structs packed.
 * On error NULL is returned.
 */
map_rnode *map_get_rblock(map_node *map, int *addr_map, int maxgroupnode, int *count)
{
	int i, c=0, tot=0;
 	map_rnode *rblock;
	*count=0;
	
	for(i=0; i<maxgroupnode; i++)
		tot+=map[i].links;
	if(!tot)
		return 0;
	rblock=(map_rnode *)xmalloc(MAP_RNODE_PACK_SZ*tot);

	for(i=0; i<maxgroupnode; i++)
		c+=get_rnode_block((int *)addr_map, &map[i], rblock, c);

	*count=c;	
	return rblock;
}


/* 
 * store_rnode_block: Given a correct `node' it restores in it all the r_node structs
 * contained in the rnode_block. It returns the number of rnode structs restored.
 * Note that `rblock' will be modified during the restoration.
 */
int store_rnode_block(int *map, map_node *node, map_rnode *rblock, int rstart) 
{
	int i;
	char *p;

	if(!node->links)
		return 0;

	node->r_node=xmalloc(MAP_RNODE_PACK_SZ*node->links);
	for(i=0; i<node->links; i++) {
		p=(char *)&rblock[i+rstart];

		ints_network_to_host(p, map_rnode_iinfo);
	
		memcpy(&node->r_node[i].r_node, p, sizeof(int *));
		p+=sizeof(int *);

		memcpy(&node->r_node[i].trtt, p, sizeof(u_int));
		p+=sizeof(u_int);

		mod_rnode_addr(&node->r_node[i], 0, map);
	}
	
	return i;
}

/* 
 * map_store_rblock: Given a correct int_map with `maxgroupnode' nodes,
 * it restores all the r_node structs in the `map' from the `rblock' 
 * using store_rnode_block. `addr_map' is the address used to change 
 * the rnodes' pointers (read store_rnode_block).
 */
int map_store_rblock(map_node *map, int *addr_map, int maxgroupnode, map_rnode *rblock)
{
	int i, c=0;
	
	for(i=0; i<maxgroupnode; i++)
		c+=store_rnode_block(addr_map, &map[i], rblock, c);
	return c;
}

/*
 * verify_int_map_hdr: verifies the validity of an int_map_hdr struct.
 * If `imap_hdr' is invalid 1 will be returned.
 */
int verify_int_map_hdr(struct int_map_hdr *imap_hdr, int maxgroupnode, int maxrnodeblock)
{
	/* No map to care about */
	if(!imap_hdr->int_map_sz)
		return 0;

	if(imap_hdr->rblock_sz > maxrnodeblock || 
			imap_hdr->int_map_sz > maxgroupnode*MAP_NODE_PACK_SZ)
		return 1;
	
	return 0;
}

/*
 * pack_map_node: it packs the `node' struct and stores it in `pack'. 
 * The packed struct will be in network order 
 */
void pack_map_node(map_node *node, char *pack)
{
	char *buf;

	buf=pack;

	memcpy(buf, &node->flags, sizeof(u_short));
	buf+=sizeof(u_short);

	memcpy(buf, &node->brdcast, sizeof(u_int));
	buf+=sizeof(u_int);

	memcpy(buf, &node->links, sizeof(u_short));
	buf+=sizeof(u_short);
	
	ints_host_to_network(pack, map_node_iinfo);
}

/*
 * unpack_map_node: it unpacks `pack', which contains a packed map_node struct.
 * The restored map_node struct will be written in `node'.
 * Note that `pack' will be modified during the restoration.
 */
void unpack_map_node(map_node *node, char *pack)
{
	char *buf;

	ints_network_to_host(pack, map_node_iinfo);

	buf=pack;

	memcpy(&node->flags, buf, sizeof(u_short));
	buf+=sizeof(u_short);

	memcpy(&node->brdcast, buf, sizeof(u_int));
	buf+=sizeof(u_int);

	memcpy(&node->links, buf, sizeof(u_short));
	buf+=sizeof(u_short);

	node->r_node=0;
}

/* 
 * pack_map: It returns a pack of the int/bmap_map `map', which has 
 * `maxgroupnode' nodes ready to be saved or sent. In `pack_sz' it
 * stores the size of the package. For info on `addr_map' please
 * read get_map_rblock().
 * The pack will be in network order.
 */
char *pack_map(map_node *map, int *addr_map, int maxgroupnode, 
		map_node *root_node, size_t *pack_sz)
{
	struct int_map_hdr imap_hdr;
	map_rnode *rblock=0;
	int count, i;
	char *package, *p;

	if(!addr_map)
		addr_map=(int *)map;
	
	setzero(&imap_hdr, sizeof(struct int_map_hdr));
	if(map) {
		/*rblock packing*/
		rblock=map_get_rblock(map, addr_map, maxgroupnode, &count);
		/*Header creation*/
		imap_hdr.root_node=root_node ? pos_from_node(root_node, map) : 0;
		imap_hdr.rblock_sz=count*MAP_RNODE_PACK_SZ;
		imap_hdr.int_map_sz=maxgroupnode*MAP_NODE_PACK_SZ;
	} 
	
	/*Package creation*/
	*pack_sz=INT_MAP_BLOCK_SZ(imap_hdr.int_map_sz, imap_hdr.rblock_sz);
	package=xmalloc(*pack_sz);
	memcpy(package, &imap_hdr, sizeof(struct int_map_hdr));
	ints_host_to_network(package, int_map_hdr_iinfo);
	
	p=package;
	if(imap_hdr.int_map_sz) {
		/* Pack the map_node strucs of the `map' */

		p+=sizeof(struct int_map_hdr);

		for(i=0; i<maxgroupnode; i++) {
			pack_map_node(&map[i], p);
			p+=MAP_NODE_PACK_SZ;
		}
	}
	
	if(imap_hdr.rblock_sz) {
		memcpy(p, rblock, imap_hdr.rblock_sz);
		xfree(rblock);
	}

	return package;	
}

/* 
 * unpack_map: Given a valid int/bmap_map package (packed with pack_intmap), it 
 * allocates a brand new int_map and restores in it the map and the rnodes.
 * It puts in `*new_root' the pointer to the root_node in the loaded map.
 * For info on `addr_map' please read map_store_rblock().
 * On success the a pointer to the new int_map is retuned, otherwise 0 will be
 * the fatal value.
 * Note: `pack' will be modified during the unpacking.
 */
map_node *unpack_map(char *pack, int *addr_map, map_node **new_root, 
		     int maxgroupnode, int maxrnodeblock)
{
	map_node *map;
	struct int_map_hdr *imap_hdr=(struct int_map_hdr *)pack;
	map_rnode *rblock;
	int err, nodes, i;
	char *p;

	ints_network_to_host(imap_hdr, int_map_hdr_iinfo);
	
	if(verify_int_map_hdr(imap_hdr, maxgroupnode, maxrnodeblock)) {
		error("Malformed int/bmap_map_hdr. Aborting unpack_map().");
		return 0;
	}
		
	/*Extracting the map...*/
	p=pack+sizeof(struct int_map_hdr);
	map=init_map(0);
	
	if(!imap_hdr->int_map_sz)
		return map;

	/* Restore in `map' the packed map_node struct */
	nodes=imap_hdr->int_map_sz/MAP_NODE_PACK_SZ;
	for(i=0; i<nodes; i++) {
		unpack_map_node(&map[i], p);
		p+=MAP_NODE_PACK_SZ;
	}

	/*Restoring the rnodes...*/
	if(imap_hdr->rblock_sz) {
		/*Extracting the rnodes block and merging it to the map*/
		rblock=(map_rnode *)p;
		if(!addr_map)
			addr_map=(int *)map;
		err=map_store_rblock(map, addr_map, nodes, rblock);
		if(err!=imap_hdr->rblock_sz/MAP_RNODE_PACK_SZ) {
			error("An error occurred while storing the rnodes block in the int/bnode_map");
			free_map(map, 0);
			return 0;
		}
	}

	if(new_root) {
		map[imap_hdr->root_node].flags|=MAP_ME;
		*new_root=&map[imap_hdr->root_node];
	}
	
	return map;
}


/* 
 * * * save/load int_map * * *
 */

int save_map(map_node *map, map_node *root_node, char *file)
{
	FILE *fd;
	size_t pack_sz;
	char *pack;

	/*Pack!*/
	pack=pack_map(map, 0, MAXGROUPNODE, root_node, &pack_sz);
	if(!pack_sz || !pack)
		return 0;
	
	if((fd=fopen(file, "w"))==NULL) {
		error("Cannot save the int_map in %s: %s", file, strerror(errno));
		return -1;
	}

	/*Write!*/
	fwrite(pack, pack_sz, 1, fd);
	
	xfree(pack);
	fclose(fd);
	return 0;
}

/* 
 * load_map: It loads the internal_map from `file'.
 * It returns the start of the map and if `new_root' is not NULL, it
 * puts in `*new_root' the pointer to the root_node in the loaded map.
 * On error it returns NULL. 
 */
map_node *load_map(char *file, map_node **new_root)
{
	map_node *map=0;
	FILE *fd;
	struct int_map_hdr imap_hdr;
	char *pack=0;
	size_t pack_sz;
	
	if((fd=fopen(file, "r"))==NULL) {
		error("Cannot load the map from %s: %s", file, strerror(errno));
		return 0;
	}

	if(!fread(&imap_hdr, sizeof(struct int_map_hdr), 1, fd))
		goto finish;

	ints_network_to_host(&imap_hdr, int_map_hdr_iinfo);
	
	if(!imap_hdr.int_map_sz)
		goto finish;

	if(verify_int_map_hdr(&imap_hdr, MAXGROUPNODE, MAXRNODEBLOCK_PACK_SZ))
		goto finish;
		
	rewind(fd);
	pack_sz=INT_MAP_BLOCK_SZ(imap_hdr.int_map_sz, imap_hdr.rblock_sz);
	pack=xmalloc(pack_sz);
	if(!fread(pack, pack_sz, 1, fd))
		goto finish;

	map=unpack_map(pack, 0, new_root, MAXGROUPNODE, MAXRNODEBLOCK_PACK_SZ);

finish:
	if(pack)
		xfree(pack);
	fclose(fd);
	if(!map)
		error("Malformed map file. Aborting load_map().");
	return map;
}
