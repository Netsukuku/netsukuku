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
 * qspn-empiric:
 * This is the living proof of the QSPN algorithm.
 * The qspn-empiric simulates an entire network and runs on it the QSPN,
 * but it doesn't simulate the qspn with levels.
 * Then when all is done it collects the generated data and makes some 
 * statistics, in this way it's possible to watch the effect of a QSPN 
 * explosion in a network. 
 * The qspn-empiric can be also used to solve graph without using djkstra 
 * hehehe.
 * ah,..  yes it uses threads... a lot of them... ^_^ I want a cluster!
 * -
 * time to explain how this thing happens to work:
 * If a map filename to load is not given as argv[1] gen_rnd_map is used 
 * to create a new random map of MAXGROUPNODE nodes.
 * Then we choose a random node to be the QSPN_STARTER.
 * Now, instead of simulating the nodes we simulate the packets! Each pkt
 * is a thread. When a new thread/pkt is created it sleeps for the rtt there
 * is between the "from" node and the "to" node.
 * Now we have only to wait.
 * enjoy the trip.
 */


#include "includes.h"

#include "common.h"
#include "inet.h"
#include "endianness.h"
#include "qspn-empiric.h"


/*
 * 	* 	* Map functions *	*	*
 */
/*
 * pos_from_node: Position from node: It returns the position of the `node'
 * in the `map'.
 */
int pos_from_node(map_node *node, map_node *map)
{
	return ((char *)node-(char *)map)/sizeof(map_node);
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

/*rnode_rtt_compar: It's used by rnode_rtt_order*/
int rnode_rtt_compar(const void *a, const void *b) 
{
	map_rnode *rnode_a=(map_rnode *)a, *rnode_b=(map_rnode *)b;

	if(MILLISEC(rnode_a->rtt) > MILLISEC(rnode_b->rtt))
		return 1;
	else if(MILLISEC(rnode_a->rtt) == MILLISEC(rnode_b->rtt))
		return 0;
	else
		return -1;
}

/*rnode_rtt_order: It qsort the rnodes of a map_node comparing their rtt
 */
void rnode_rtt_order(map_node *node)
{
	qsort(node->r_node, node->links, sizeof(map_rnode), rnode_rtt_compar);
}


/* 
 * mod_rnode_addr: Modify_rnode_address 
 */
int mod_rnode_addr(map_rnode *rnode, int *map_start, int *new_start)
{
	rnode->r_node = (int *)(((char *)rnode->r_node - (char *)map_start) + (char *)new_start);
	return 0;
}

/* 
 * get_rnode_block: It packs all the rnode structs of a node. The node->r_node
 * pointer of the map_rnode struct is changed to point to the position of the 
 * node in the map, instead of the address. get_rnode_block returns the number 
 * of rnode structs packed.
 * Note that the packed structs will be in network order.
 */
int get_rnode_block(int *map, map_node *node, map_rnode *rblock, int rstart)
{
	int e;
	char *p;

	for(e=0; e<node->links; e++) {
		p=(char *)&rblock[e+rstart];
	
		memcpy(p, &node->r_node[e].flags, sizeof(u_short));
		p+=sizeof(u_short);

		memcpy(p, &node->r_node[e].r_node, sizeof(int *));
		p+=sizeof(int *);

		memcpy(p, &node->r_node[e].rtt, sizeof(struct timeval));
		p+=sizeof(struct timeval);

		memcpy(p, &node->r_node[e].trtt, sizeof(struct timeval));
		p+=sizeof(struct timeval);
		
		mod_rnode_addr(&rblock[e+rstart], map, 0);

		ints_host_to_network(&rblock[e+rstart], map_rnode_iinfo);
	}

	return e;
}

/* 
 * map_get_rblock: It uses get_rnode_block to pack all the int_map's rnode.
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

		memcpy(&node->r_node[i].flags, p, sizeof(u_short));
		p+=sizeof(u_short);

		memcpy(&node->r_node[i].r_node, p, sizeof(int *));
		p+=sizeof(int *);

		memcpy(&node->r_node[i].rtt, p, sizeof(struct timeval));
		p+=sizeof(struct timeval);

		memcpy(&node->r_node[i].trtt, p, sizeof(struct timeval));
		p+=sizeof(struct timeval);

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

int verify_int_map_hdr(struct int_map_hdr *imap_hdr, int maxgroupnode, int maxrnodeblock)
{
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

	memcpy(buf, &node->flags, sizeof(u_int));
	buf+=sizeof(u_int);

	memcpy(buf, &node->brdcast, sizeof(u_int)*MAXGROUPNODE);
	buf+=sizeof(u_int)*MAXGROUPNODE;

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

	memcpy(&node->flags, buf, sizeof(u_int));
	buf+=sizeof(u_int);

	memcpy(&node->brdcast, buf, sizeof(u_int)*MAXGROUPNODE);
	buf+=sizeof(u_int)*MAXGROUPNODE;

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
			pack_map_node(&map[i], 	p);
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


/*
 * ******* End of map functions *********
 */


/* thread_joint creates a thread in JOINED STATE or in DETACHED STATE*/
void thread_joint(int joint, void * (*start_routine)(void *), void *nopt)
{	
	pthread_t thread;
	total_threads++;
	if(joint && !disable_joint) {
		fprintf(stderr, "%u: Joining the thread...", pthread_self());
		pthread_create(&thread, NULL, start_routine, (void *)nopt);
		fprintf(stderr, " %u\n", thread);
		pthread_join(thread, NULL);	
	} else {
		pthread_create(&thread, NULL, start_routine, (void *)nopt);
		pthread_detach(thread);
	}
}

/* wait_threads: it waits until the total number of threads doesn't change anymore*/
void wait_threads(void) {
	int tt=0;
	while(total_threads != tt) {
		tt=total_threads;
		sleep(5);
	}
}

/* gen_rnd_map: Generate Random Map.
 * It creates the start_node in the map. 
 * (If back_link >= 0) It then adds the back_link node (with rtt equal to back_link_rtt) 
 * in the start_node's rnodes and adds other random rnodes (with random rtt).
 * If the added new rnode doesn't exist yet in the map it calls recusively itself giving 
 * the rnode as the "start_node" argument, the start_node as back_link and the rnode's rtt
 * as back_link_rtt. Else if the new rnode exists, it adds the start_node in the rnode's rnodes.
 * Automagically it terminates.
 */
void gen_rnd_map(int start_node, int back_link, int back_link_rtt) 
{
	int i=start_node, r=0, e, b=0, rnode_rnd, ms_rnd;
	map_rnode rtmp;

	if(i > MAXGROUPNODE)
		i=rand_range(0, MAXGROUPNODE-1);

	if(back_link>=0 && back_link<MAXGROUPNODE)
		b=1;
	
	if(int_map[i].flags & MAP_HNODE)
		return;
	
	r=rand_range(0, MAXLINKS);
	int_map[i].flags|=MAP_HNODE;
	int_map[i].flags&=~MAP_VOID;
	if(b) {
		r++;
		setzero(&rtmp, sizeof(map_rnode));
		rtmp.r_node=(u_int *)&int_map[back_link];
		rtmp.rtt.tv_usec=back_link_rtt;
		//printf("Node %d -> Adding rnode %d (back link)\n", i, back_link);
		rnode_add(&int_map[i], &rtmp);
		b=0;
	}
	/*printf("Creating %d links for the node %d\n",  r, i);*/
	for(e=0; e<r; e++) { /*It's e<r and not e<=r because we've already added the back_link rnode at r position*/
		setzero(&rtmp, sizeof(map_rnode));
random_node:
		/*Are we adding ourself or an already addded node in our rnodes?*/
		while((rnode_rnd=(rand_range(0, MAXGROUPNODE-1)))== i);
		for(b=0; b<int_map[i].links; b++)
			if((map_node *)&int_map[rnode_rnd] == (map_node *)int_map[i].r_node[b].r_node) {
				//printf("goto random_node;\n");
				goto random_node;
			}

		/*the building of the new rnode is here*/
		rtmp.r_node=(u_int *)&int_map[rnode_rnd];
		ms_rnd=rand_range(0, (MAXRTT*1000));
		rtmp.rtt.tv_usec=ms_rnd*1000;
		//printf("Node %d -> Adding rnode %d\n", i, rnode_rnd);
		rnode_add(&int_map[i], &rtmp);

		/*Does exist the node "rnode_rnd" added as rnode?*/
		if(int_map[rnode_rnd].flags & MAP_VOID)	{
			/*No, let's create it*/
			gen_rnd_map(rnode_rnd, i, rtmp.rtt.tv_usec);
		} else {
			/*It does, let's check if it has a link to me*/
			int c=0;
			for(b=0; b<int_map[rnode_rnd].links; b++)
				if((map_node *)int_map[rnode_rnd].r_node[b].r_node == &int_map[i]) {
					c=1;
					break;
				}
			if(!c) {
				/*We create the back link from rnode_rnd to me (i)*/
				setzero(&rtmp, sizeof(map_rnode));
				rtmp.r_node=(u_int *)&int_map[i];
				rtmp.rtt.tv_usec=ms_rnd*1000;
				//printf("Node %d -> Adding rnode %d (front link)\n", rnode_rnd,i);
				rnode_add(&int_map[rnode_rnd], &rtmp);
			}
		}
	}
}

/*init the qspn queue*/
void init_q_queue(map_node *map)
{
	int i;

	for(i=0; i<MAXGROUPNODE; i++) {
		if(map[i].links) {
			qspn_q[i]=xmalloc(sizeof(struct qspn_queue)*map[i].links);
			setzero(qspn_q[i], sizeof(struct qspn_queue));
		}
	}
}

void free_q_queue(map_node *map)
{
	int i, e, x;
	for(i=0; i<MAXGROUPNODE; i++) {
		xfree(qspn_q[i]);
	}
}

/* store_tracer_pkt: It stores the tracer_pkt received in the 
 * packets' db (used to collect stats after) and it adds our 
 * entry in the new tracer_pkt that will be sent
 */
int store_tracer_pkt(struct q_opt *qopt)
{
	int x, pkt, to=qopt->q.to;

	pthread_mutex_lock(&mutex[to]);	
	pkt=pkt_dbc[to];
	pkt_dbc[to]++;
	pthread_mutex_unlock(&mutex[to]);	

	if(!pkt)
		pkt_db[to]=xmalloc(sizeof(struct q_opt *));
	else
		pkt_db[to]=xrealloc(pkt_db[to], sizeof(struct q_opt *)*pkt_dbc[to]);

	pkt_db[to][pkt]=xmalloc(sizeof(struct q_pkt));
	setzero(pkt_db[to][pkt], sizeof(struct q_pkt));
	pkt_db[to][pkt]->q_id=qopt->q.q_id;
	pkt_db[to][pkt]->q_sub_id=qopt->q.q_sub_id;
	pkt_db[to][pkt]->from=qopt->q.from;
	pkt_db[to][pkt]->routes=qopt->q.routes+1;
	if(pkt_db[to][pkt]->routes) {
		pkt_db[to][pkt]->tracer=xmalloc(sizeof(short)*pkt_db[to][pkt]->routes);
		for(x=0; x<qopt->q.routes; x++)
			pkt_db[to][pkt]->tracer[x]=qopt->q.tracer[x];
		/*Let's add our entry in the tracer pkt*/
		pkt_db[to][pkt]->tracer[pkt_db[to][pkt]->routes-1]=to;
	}
	pkt_db[to][pkt]->op=qopt->q.op;
	pkt_db[to][pkt]->broadcast=qopt->q.broadcast;

	return pkt;
}

/*Ok, I see... The qspn_backpro is a completely lame thing!*/
void *send_qspn_backpro(void *argv)
{
	struct q_opt *qopt=(struct q_opt *)argv, *nopt;
	int x, dst, pkt, to=qopt->q.to;

	usleep(qopt->sleep);
	fprintf(stderr, "%u: qspn_backpro from %d to %d\n", pthread_self(), qopt->q.from, to);

	/*Now we store the received pkt in our pkt_db*/
	pkt=store_tracer_pkt(qopt);	

	/*We've arrived... finally*/
	if(int_map[to].flags & QSPN_STARTER) {
		fprintf(stderr, "%u: qspn_backpro: We've arrived... finally\n", pthread_self());
		return;
	}

	for(x=0; x<int_map[to].links; x++) {
		if((map_node *)int_map[to].r_node[x].r_node == &int_map[qopt->q.from]) 
			continue;

		if(int_map[to].r_node[x].flags & QSPN_CLOSED) {
			dst=((void *)int_map[to].r_node[x].r_node - (void *)int_map)/sizeof(map_node);

			gbl_stat.total_pkts++;
			node_stat[to].total_pkts++;

			nopt=xmalloc(sizeof(struct q_opt));
			setzero(nopt, sizeof(struct q_opt));
			nopt->sleep=int_map[to].r_node[x].rtt.tv_usec;
			nopt->q.to=dst;
			nopt->q.from=to;
			nopt->q.routes=pkt_db[to][pkt]->routes;
			nopt->q.tracer=pkt_db[to][pkt]->tracer;
			nopt->q.broadcast=pkt_db[to][pkt]->broadcast;
			nopt->join=qopt->join;

			gbl_stat.qspn_backpro++;
			node_stat[to].qspn_backpro++;
			nopt->q.op=OP_BACKPRO;
			thread_joint(qopt->join, send_qspn_backpro, (void *)nopt);
		}
	}
	xfree(qopt);
	total_threads--;
	pthread_exit(NULL);
}

void *send_qspn_reply(void *argv)
{
	struct q_opt *qopt=(struct q_opt *)argv, *nopt;
	int x, dst, pkt, to=qopt->q.to;

	usleep(qopt->sleep);
	fprintf(stderr, "%u: qspn_reply from %d to %d\n", pthread_self(), qopt->q.from, to);

	/*Let's store the tracer_pkt first*/
	pkt=store_tracer_pkt(qopt);	

	/*Bad old broadcast pkt*/
	if(qopt->q.broadcast <= int_map[to].brdcast[qopt->q.from]) {
		fprintf(stderr, "%u: DROPPED old brdcast: q.broadcast: %d, qopt->q.from broadcast: %d\n", pthread_self(), qopt->q.broadcast, int_map[to].brdcast[qopt->q.from]);
		return;
	} else
		int_map[to].brdcast[qopt->q.from]=qopt->q.broadcast;

	/*Let's keep broadcasting*/
	for(x=0; x<int_map[to].links; x++) {	
		if((map_node *)int_map[to].r_node[x].r_node == &int_map[qopt->q.from]) 
			continue;

		dst=((void *)int_map[to].r_node[x].r_node - (void *)int_map)/sizeof(map_node);

		gbl_stat.total_pkts++;
		node_stat[to].total_pkts++;

		nopt=xmalloc(sizeof(struct q_opt));
		setzero(nopt, sizeof(struct q_opt));
		nopt->sleep=int_map[to].r_node[x].rtt.tv_usec;
		nopt->q.to=dst;
		nopt->q.from=to;
		nopt->q.routes=pkt_db[to][pkt]->routes;
		nopt->q.tracer=pkt_db[to][pkt]->tracer;
		nopt->q.broadcast=pkt_db[to][pkt]->broadcast;
		nopt->join=qopt->join;

		
		gbl_stat.qspn_replies++;
		node_stat[to].qspn_replies++;
		nopt->q.op=OP_REPLY;
		thread_joint(qopt->join, send_qspn_reply, (void *)nopt);
	}
	xfree(qopt);
	total_threads--;
	pthread_exit(NULL);
}

/*Holy Disagio, I wrote this piece of code without seeing actually it, I don't
 * know what it will generate... where am I?
 */
void *send_qspn_open(void *argv)
{
	struct q_opt *qopt=(struct q_opt *)argv, *nopt;
	int x, i=0, dst, pkt, to=qopt->q.to;
	int re, sub_id=qopt->q.q_sub_id;

	usleep(qopt->sleep);
	fprintf(stderr, "%u: qspn_open from %d to %d [subid: %d]\n", pthread_self(), qopt->q.from, to, sub_id);
	
	pkt=store_tracer_pkt(qopt);	

	if(to == sub_id) {
		fprintf(stderr, "%u: qspn_open: We received a qspn_open, but we are the OPENER!!\n", pthread_self());
		return;
	}

	for(x=0; x<int_map[to].links; x++) {
		if((map_node *)int_map[to].r_node[x].r_node == &int_map[qopt->q.from]) {
			qspn_q[to][x].flags[sub_id]|=QSPN_OPENED;
			fprintf(stderr, "%u: node:%d->rnode %d  opened\n", pthread_self(), to, x);
		}
		
		if(!(qspn_q[to][x].flags[sub_id] & QSPN_OPENED))
			i++;
	}
	/*Shall we stop our insane run?*/
	if(!i) {
		/*Yai! We've finished the reopening of heaven*/
		fprintf(stderr, "%u: Yai! We've finished the reopening of heaven\n", pthread_self());
		return;
	}

	for(x=0; x<int_map[to].links; x++) {	
		if((map_node *)int_map[to].r_node[x].r_node == &int_map[qopt->q.from]) 
			continue;

		if(qspn_q[to][x].flags[sub_id] & QSPN_OPENED)
			continue;

		dst=((void *)int_map[to].r_node[x].r_node - (void *)int_map)/sizeof(map_node);
		gbl_stat.total_pkts++;
		node_stat[to].total_pkts++;

		nopt=xmalloc(sizeof(struct q_opt));
		setzero(nopt, sizeof(struct q_opt));
		nopt->q.q_id=qopt->q.q_id;
		nopt->q.q_sub_id=sub_id;
		nopt->q.from=to;
		nopt->q.to=dst;
		nopt->q.routes=pkt_db[to][pkt]->routes;
		nopt->q.tracer=pkt_db[to][pkt]->tracer;
		nopt->sleep=int_map[to].r_node[x].rtt.tv_usec;
		nopt->q.broadcast=pkt_db[to][pkt]->broadcast;
		if(x == int_map[to].links-1)
			qopt->join=1;
		nopt->join=qopt->join;

		gbl_stat.qspn_replies++;
		node_stat[to].qspn_replies++;
		nopt->q.op=OP_OPEN;
		thread_joint(qopt->join, send_qspn_open, (void *)nopt);
	}
	xfree(qopt);
	total_threads--;
	pthread_exit(NULL);
}

void *send_qspn_pkt(void *argv)
{
	struct q_opt *qopt=(struct q_opt *)argv, *nopt;
	int x, i=0, dst, pkt, to=qopt->q.to;

	usleep(qopt->sleep);
	fprintf(stderr, "%u: qspn_pkt from %d to %d\n", pthread_self(), qopt->q.from, to);
	
	pkt=store_tracer_pkt(qopt);	
	
	if(qopt->q.routes > 1 && (int_map[to].flags & QSPN_STARTER)) {
		fprintf(stderr, "%u: qspn_pkt: We received a qspn_pkt, but we are the QSPN_STARTER!!\n", pthread_self());
		return;
	}
	
	for(x=0; x<int_map[to].links; x++) {
		if((map_node *)int_map[to].r_node[x].r_node == &int_map[qopt->q.from]) {
			int_map[to].r_node[x].flags|=QSPN_CLOSED;
			/*fprintf(stderr, "%u: node:%d->rnode %d closed\n", pthread_self(), to, x);*/
		}
		if(!(int_map[to].r_node[x].flags & QSPN_CLOSED))
			i++;
	}

#ifdef Q_OPEN
	if(!i && !(int_map[to].flags & QSPN_OPENER) && !(int_map[to].flags & QSPN_STARTER)) {
		/*W00t I'm an extreme node!*/
		fprintf(stderr, "%u: W00t I'm an extreme node!\n", pthread_self());
		int_map[to].flags|=QSPN_OPENER;
		for(x=0; x<int_map[to].links; x++) {	
			/*if(int_map[to].r_node[x].flags & QSPN_SENT) 
				continue;
			*/

			dst=((void *)int_map[to].r_node[x].r_node - (void *)int_map)/sizeof(map_node);
			gbl_stat.total_pkts++;
			node_stat[to].total_pkts++;

			nopt=xmalloc(sizeof(struct q_opt));
			setzero(nopt, sizeof(struct q_opt));
			nopt->sleep=int_map[to].r_node[x].rtt.tv_usec;
			nopt->q.q_id=pkt_db[to][pkt]->q_id;
			nopt->q.q_sub_id=to;
			nopt->q.to=dst;
			nopt->q.from=to;
			if((map_node *)int_map[to].r_node[x].r_node == &int_map[qopt->q.from]) {
				nopt->q.tracer=xmalloc(sizeof(short));
				nopt->q.tracer[0]=nopt->q.from;
				nopt->q.routes=1;
			} else {
				nopt->q.routes=pkt_db[to][pkt]->routes;
				nopt->q.tracer=pkt_db[to][pkt]->tracer;
			}
			nopt->q.op=OP_OPEN;
			nopt->q.broadcast=pkt_db[to][pkt]->broadcast;
			nopt->join=qopt->join;

			gbl_stat.qspn_replies++;
			node_stat[to].qspn_replies++;
			fprintf(stderr, "%u: Sending a qspn_open to %d\n", pthread_self(), dst);
			thread_joint(qopt->join, send_qspn_open, (void *)nopt);
			xfree(qopt);
			return;
		}
	}
#else	/*Q_OPEN not defined*/
	/*Shall we send a QSPN_REPLY?*/
	if(!i && !(int_map[to].flags & QSPN_OPENER) && !(int_map[to].flags & QSPN_STARTER)) {
		/*W00t I'm an extreme node!*/
		fprintf(stderr, "%u: W00t I'm an extreme node!\n", pthread_self());
		
		int_map[to].flags|=QSPN_OPENER;
		for(x=0; x<int_map[to].links; x++) {	
			if((map_node *)int_map[to].r_node[x].r_node == &int_map[qopt->q.from]) 
				continue;

			/*We've to clear the closed link
			int_map[to].r_node[x].flags&=~QSPN_CLOSED;
			*/

			dst=((void *)int_map[to].r_node[x].r_node - (void *)int_map)/sizeof(map_node);
			gbl_stat.total_pkts++;
			node_stat[to].total_pkts++;

			nopt=xmalloc(sizeof(struct q_opt));
			setzero(nopt, sizeof(struct q_opt));
			nopt->sleep=int_map[to].r_node[x].rtt.tv_usec;
			nopt->q.to=dst;
			nopt->q.from=to;
			nopt->q.routes=pkt_db[to][pkt]->routes;
			nopt->q.tracer=pkt_db[to][pkt]->tracer;
			nopt->q.op=OP_REPLY;
			int_map[to].broadcast[to]++;
			nopt->q.broadcast=int_map[to].broadcast[to];
			nopt->join=qopt->join;

			gbl_stat.qspn_replies++;
			node_stat[to].qspn_replies++;
			fprintf(stderr, "%u: Sending a qspn_reply to %d\n", pthread_self(), dst);
			thread_joint(qopt->join, send_qspn_reply, (void *)nopt);
			xfree(qopt);
			return;
		}
	}
#endif /*Q_OPEN*/

	for(x=0; x<int_map[to].links; x++) {	
		if((map_node *)int_map[to].r_node[x].r_node == &int_map[qopt->q.from]) 
			continue;
#ifndef Q_BACKPRO
		if(int_map[to].r_node[x].flags & QSPN_CLOSED)
			continue;
#endif

		dst=((void *)int_map[to].r_node[x].r_node - (void *)int_map)/sizeof(map_node);
		gbl_stat.total_pkts++;
		node_stat[to].total_pkts++;

		nopt=xmalloc(sizeof(struct q_opt));
		setzero(nopt, sizeof(struct q_opt));
		nopt->q.from=to;
		nopt->q.to=dst;
		nopt->q.routes=pkt_db[to][pkt]->routes;
		nopt->q.tracer=pkt_db[to][pkt]->tracer;
		nopt->sleep=int_map[to].r_node[x].rtt.tv_usec;
		nopt->q.broadcast=pkt_db[to][pkt]->broadcast;
		nopt->join=qopt->join;

		if(int_map[to].r_node[x].flags & QSPN_CLOSED && !(int_map[to].r_node[x].flags & QSPN_BACKPRO)) {
#ifdef Q_BACKPRO
			gbl_stat.qspn_backpro++;
			node_stat[to].qspn_backpro++;
			nopt->q.op=OP_BACKPRO;
			int_map[to].r_node[x].flags|=QSPN_BACKPRO;
			thread_joint(qopt->join, send_qspn_backpro, (void *)nopt);
#else
			0;
#endif	/*Q_BACKPRO*/
		} else if(!(int_map[to].r_node[x].flags & QSPN_CLOSED)){
			gbl_stat.qspn_requests++;
			node_stat[to].qspn_requests++;
			nopt->q.op=OP_REQUEST;
			//int_map[to].r_node[x].flags|=QSPN_SENT;
			thread_joint(qopt->join, send_qspn_pkt, (void *)nopt);
		}
	}
	xfree(qopt);
	total_threads--;
	pthread_exit(NULL);
}

/*collect_data: it calculates how many routes we have for each node*/
void collect_data(void)
{
	int i, x, e;

	fprintf(stderr, "Collecting the data!\n");
	for(i=0; i<MAXGROUPNODE; i++)
		for(e=0; e<pkt_dbc[i]; e++)
			for(x=0; x<pkt_db[i][e]->routes; x++) {
				rt_stat[i][pkt_db[i][e]->tracer[x]]++;
				if(rt_stat[i][pkt_db[i][e]->tracer[x]]++==1)
					rt_total[i]++;
			}
}

/*show_temp_stat: Every 5 seconds it shows how is it going*/
void *show_temp_stat(void *null)
{
	FILE *fd=stdout;
	while(1) {
		sleep(5);
		fprintf(fd, "Total_threads: %d\n", total_threads);		
		fprintf(fd, "Gbl_stat{\n\ttotal_pkts: %d\n\tqspn_requests: %d"
				"\n\tqspn_replies: %d\n\tqspn_backpro: %d }\n\n",
				gbl_stat.total_pkts, gbl_stat.qspn_requests,
				gbl_stat.qspn_replies, gbl_stat.qspn_backpro);
	}
}

/*print_map: Print the map in human readable form in the "map_file"*/
int print_map(map_node *map, char *map_file)
{
	int x,e, node;
	FILE *fd;

	fd=fopen(map_file, "w");
	fprintf(fd,"--- map ---\n");
	for(x=0; x<MAXGROUPNODE; x++) {
		fprintf(fd, "Node %d\n",x);
		for(e=0; e<map[x].links; e++) {
			node=((void *)map[x].r_node[e].r_node - (void *)map)/sizeof(map_node);
			fprintf(fd, "        -> %d\n", node);
		}

		fprintf(fd, "--\n");
	}
	fclose(fd);
	return 0;
}

/*lgl_print_map saves the map in the lgl format. 
 * (LGL is a nice program to generate images of graphs)*/
int lgl_print_map(map_node *map, char *lgl_mapfile)
{
	int x,e,i, c=0, d, node;
	FILE *lgl;
	
	lgl=fopen(lgl_mapfile, "w");

	for(x=0; x<MAXGROUPNODE; x++) {
		fprintf(lgl, "# %d\n", x);
		for(e=0; e<map[x].links; e++) {
			c=0;
			for(i=0; i<x; i++)
				if(&map[i] == (map_node *)map[x].r_node[e].r_node) {
					for(d=0; d<map[i].links; d++)
						if((map_node *)map[i].r_node[d].r_node == &map[x]) {
							c=1;
							break;
						}
					if(c)
						break;
				}
			if(!c) {
				node=((void *)map[x].r_node[e].r_node - (void *)map)/sizeof(map_node);
				fprintf(lgl, "%d %d\n",node, map[x].r_node[e].rtt.tv_usec);
			}
		}
	}
	fclose(lgl);
	return 0;
}

/*print_data: Prints the accumulated data and statistics in "file"*/
void print_data(char *file)
{
	int i, x, e, null, maxgroupnode;
	FILE *fd;

	fprintf(stderr, "Saving the d4ta\n");
	fd=fopen((file), "w");

	fprintf(fd, "---- Test dump n. 6 ----\n");

	for(i=0, null=0; i<MAXGROUPNODE; i++)
		if(!int_map[i].links)
			null++;
	maxgroupnode=MAXGROUPNODE-null;
	for(i=0; i<MAXGROUPNODE; i++)
		if(rt_total[i]<maxgroupnode && int_map[i].links) 
			fprintf(fd,"*WARNING* The node %d has only %d/%d routes *WARNING*\n", i, rt_total[i], maxgroupnode);

	fprintf(fd, "- Gbl_stat{\n\ttotal_pkts: %d\n\tqspn_requests: %d"
			"\n\tqspn_replies: %d\n\tqspn_backpro: %d }, QSPN finished in :%d seconds\n",
			gbl_stat.total_pkts, gbl_stat.qspn_requests,
			gbl_stat.qspn_replies, gbl_stat.qspn_backpro, time_stat);

	fprintf(fd, "- Total routes: \n");
	for(i=0; i<MAXGROUPNODE; i++) {	
		fprintf(fd, "Node: %d { ", i);
		for(x=0; x<MAXGROUPNODE; x++) {
			if(!int_map[x].links)
				fprintf(fd, "(%d)NULL ", x);
			else
				fprintf(fd, "(%d)%d ", x,rt_stat[i][x]);

			if(!x%20 && x)
				fprintf(fd, "\n           ");
		}
		fprintf(fd, "}\n");
	}

	fprintf(fd, "\n--\n\n");
	fprintf(fd, "- Node single stats: \n");

	for(i=0; i<MAXGROUPNODE; i++)
		fprintf(fd, "%d_stat{\n\ttotal_pkts: %d\n\tqspn_requests: %d\n\t"
				"qspn_replies: %d\n\tqspn_backpro: %d }\n", i,
				node_stat[i].total_pkts, node_stat[i].qspn_requests,
				node_stat[i].qspn_replies, node_stat[i].qspn_backpro);

	fprintf(fd, "- Pkts dump: \n");
	for(i=0; i<MAXGROUPNODE; i++) {
		for(x=0; x<pkt_dbc[i]; x++) {
			fprintf(fd, "(%d) { op: %d, from: %d, broadcast: %d, ",
					i, pkt_db[i][x]->op, pkt_db[i][x]->from,
					pkt_db[i][x]->broadcast);
			fprintf(fd, "tracer: ");
			for(e=0; e<pkt_db[i][x]->routes; e++) {
				fprintf(fd, "%d -> ",pkt_db[i][x]->tracer[e]);
				if(!x%16 && x)
					fprintf(fd, "\n");
			}
			fprintf(fd, "}\n");
		}
	}
	fclose(fd);
}

void clear_all(void)
{
	fprintf(stderr, "Clearing all the dirty\n");
	setzero(&gbl_stat, sizeof(struct qstat));
	setzero(&node_stat, sizeof(struct qstat)*MAXGROUPNODE);
	setzero(&pkt_db, sizeof(struct q_pkt)*MAXGROUPNODE);
	setzero(&pkt_dbc, sizeof(int)*MAXGROUPNODE);
	setzero(&rt_stat, sizeof(short)*MAXGROUPNODE*MAXGROUPNODE);
	setzero(&rt_total, sizeof(short)*MAXGROUPNODE);
}

int main(int argc, char **argv)
{
	struct q_opt *nopt;
	int i, r, e, x, qspn_id;
	time_t start, end;

	log_init(argv[0], 1, 1);
	clear_all();

#ifndef QSPN_EMPIRIC
	fatal("QSPN_EMPIRIC is not enabled! Aborting.");
#endif
	
	for(i=0; i<MAXGROUPNODE; i++) 
		pthread_mutex_init(&mutex[i], NULL);

	if(argc>1) {
		if(!(int_map=load_map(argv[1], 0))) {
			printf("Error! Cannot load the map\n");
			exit(1);
		}
		printf("Map loaded. Printing it... \n");
		print_map(int_map, "QSPN-map.load");
		lgl_print_map(int_map, "QSPN-map.lgl.load");
	} else {
		int_map=init_map(sizeof(map_node)*MAXGROUPNODE);
		printf("Generating a random map...\n");
		srandom(time(0));
		i=rand_range(0, MAXGROUPNODE-1);
		gen_rnd_map(i, -1, 0);
		for(x=0; x<MAXGROUPNODE; x++)
			rnode_rtt_order(&int_map[x]);
		printf("Map generated. Printing it... \n");
		print_map(int_map, "QSPN-map");
		lgl_print_map(int_map, "QSPN-map.lgl");
		int_map[i].flags|=MAP_ME;
		printf("Saving the map to QSPN-map.raw\n");
		save_map(int_map, &int_map[i], "QSPN-map.raw");
	}
	printf("Initialization of qspn_queue\n");
	init_q_queue(int_map);
	
	printf("Running the first test...\n");
	thread_joint(0, show_temp_stat, NULL);
#ifdef NO_JOINT
	disable_joint=1;
#endif
	if(argc > 2)
		r=atoi(argv[2]);
	else
		r=rand_range(0, MAXGROUPNODE-1);
	printf("Starting the QSPN spreading from node %d\n", r);
	int_map[r].flags|=QSPN_STARTER;
	qspn_id=random();
	start=time(0);
	for(x=0; x<int_map[r].links; x++) {
		gbl_stat.total_pkts++;
		node_stat[r].total_pkts++;

		nopt=xmalloc(sizeof(struct q_opt));
		setzero(nopt, sizeof(struct q_opt));
		nopt->q.q_id=qspn_id;
		nopt->q.from=r;
		nopt->q.to=((void *)int_map[r].r_node[x].r_node - (void *)int_map)/sizeof(map_node);
		nopt->q.tracer=xmalloc(sizeof(short));
		nopt->q.tracer[0]=nopt->q.from;
		nopt->q.routes=1;
		nopt->sleep=int_map[r].r_node[x].rtt.tv_usec;
		nopt->q.broadcast=0;
		nopt->join=0;

		gbl_stat.qspn_requests++;
		node_stat[r].qspn_requests++;
		nopt->q.op=OP_REQUEST;
		if(x == int_map[r].links-1)
			nopt->join=1; 
		
		thread_joint(nopt->join, send_qspn_pkt, (void *)nopt);
	}
#ifdef NO_JOINT
	wait_threads();
#endif
	end=time(0);
	time_stat=end-start;
	int_map[r].flags&=~QSPN_STARTER;
		
	printf("Saving the data to QSPN1...\n");
	collect_data();
	print_data("QSPN1");
	for(x=0; x<MAXGROUPNODE; x++) {
		for(e=0; e<pkt_dbc[x]; e++) {
			xfree(pkt_db[x][e]->tracer);
			xfree(pkt_db[x][e]);
		}
		xfree(pkt_db[x]);
	}
	free_q_queue(int_map); 		/*WARNING* To be used when the int_map it's of no more use*/
	clear_all();
	
	printf("All done yeah\n");
	fprintf(stderr, "All done yeah\n");
	exit(0);
}
