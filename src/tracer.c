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

#include "includes.h"

#include "common.h"
#include "request.h"
#include "pkts.h"
#include "bmap.h"
#include "radar.h"
#include "route.h"
#include "radar.h"
#include "rehook.h"
#include "tracer.h"
#include "qspn.h"
#include "igs.h"
#include "netsukuku.h"

char *tracer_pack_pkt(brdcast_hdr *bcast_hdr, tracer_hdr *trcr_hdr, tracer_chunk *tracer, 
		      char *bblocks, size_t bblocks_sz, int new_bblocks);

/* 
 * ip_to_rfrom: If `rip_quadg' is null, it converts the `rip' ip in a 
 * quadro_group that is stored in `new_quadg' (if it is not null), otherwise it
 * uses `rip_quadg' itself.
 * The flags passed to iptoquadg are orred whith `quadg_flags'. 
 * The rnode position of the root_node of level 0 which corresponds to 
 * the given ip is returned, if it isn't found -1 is returned.
 */
int ip_to_rfrom(inet_prefix rip, quadro_group *rip_quadg,
		quadro_group *new_quadg, char quadg_flags)
{
	quadro_group qdg, *quadg;
	map_node *from;
	ext_rnode_cache *erc;
	int ret, external_node=0;

	quadg=&qdg;

	if(rip_quadg) {
		quadg=rip_quadg;
	} else {
		quadg_flags|=QUADG_GID|QUADG_GNODE;		
		iptoquadg(rip, me.ext_map, quadg, quadg_flags);
		if(new_quadg)
			memcpy(new_quadg, quadg, sizeof(quadro_group));
	}
	
	if(quadg_gids_cmp(me.cur_quadg, *quadg, 1))
		external_node=1;
	
	if(!external_node) {
		iptomap((u_int)me.int_map, rip, me.cur_quadg.ipstart[1], &from);
		ret=rnode_find(me.cur_node, from);
	} else {
		erc=e_rnode_find(me.cur_erc, quadg, 0);
		ret = !erc ? -1 : erc->rnode_pos;
	}
	
	return ret;
}

/* 
 * tracer_verify_pkt: It checks the validity of `tracer': The last entry
 * in the tracer must be a node present in our r_nodes.
 * Instead of using iptoquadg it uses `rip_quadg' if it isn't null.
 */
int tracer_verify_pkt(tracer_chunk *tracer, u_short hops, inet_prefix rip, 
		quadro_group *rip_quadg, int level)
{
	quadro_group qdg, *quadg;
	map_node *from, *real_from, *real_gfrom;
	int retries=0, ret;

	from=real_from=real_gfrom=0;
	quadg=&qdg;

	if(!rip_quadg)
		iptoquadg(rip, me.ext_map, quadg, QUADG_GID|QUADG_GNODE);
	else 
		quadg=rip_quadg;
	
	if(!quadg_gids_cmp(*quadg, me.cur_quadg, level))
		return 0;

	/* 
	 * Now, let's check if we are part of the bcast_hdr->g_node of 
	 * bcast_hdr->level. If not let's  drop it! Why the hell this pkt is 
	 * here?
	 */
	if(quadg_gids_cmp(*quadg, me.cur_quadg, level+1)) {
		debug(DBG_INSANE, "%s:%d", ERROR_POS);
		return -1;
	}
	
	/*
	 * `from' has to be absolutely one of our rnodes
	 */
	
	if(!level) {
		iptomap((u_int)me.int_map, rip, me.cur_quadg.ipstart[1], &real_from);
		from = node_from_pos(tracer[hops-1].node, me.int_map);
	} else {
		real_gfrom = &quadg->gnode[_EL(level)]->g;
		from = node_from_pos(quadg->gid[0], me.int_map);
	}
	
	/* Look for the `from' node in the int_map. */
	if((real_from && real_from == from) || from) {
		/* Is `from' in our rnodes? */
		for(retries=0; 
			(ret=rnode_find(me.cur_node, from)) == -1 && !retries; 
				retries++)
			radar_wait_new_scan();
		if(ret != -1)
			return 0;
	}

	/* `from' is a gnode, look in the ext_map */
	if(level) {
		/* Look in ext_map */
		from=(map_node *)gnode_from_pos(tracer[hops-1].node,
				me.ext_map[_EL(level)]);
		if(!from || (real_gfrom && real_gfrom != from)) {
			debug(DBG_INSANE, "%s:%d", ERROR_POS);
			return -1;
		}

		ret=g_rnode_find(me.cur_quadg.gnode[_EL(level)], (map_gnode *)from);
		if(ret == -1) {
			debug(DBG_INSANE, "%s:%d gnode: %d, level: %d", 
					ERROR_POS, tracer[hops-1].node, level);
			return -1;
		}
	}

	return 0;
}

/* 
 * tracer_add_entry: Append our entry `node' to the tracer pkt `tracer' wich has 
 * `hops'. It returns the modified tracer pkt in a newly mallocated struct and
 * it increments the `*hops'.
 * If `tracer' is null it will return the new tracer_pkt.
 * On errors it returns NULL.
 */
tracer_chunk *
tracer_add_entry(void *void_map, void *void_node, tracer_chunk *tracer, 
		u_int *hops, u_char level)
{
	tracer_chunk *t;
	map_node *from;
	map_rnode *rfrom=0;
	map_node  *map, *node;
	map_gnode **ext_map, *gnode;
	int pos, new_entry_pos, last_entry_node, nhops;

	map=(map_node *)void_map;
	node=(map_node *)void_node;
	ext_map=(map_gnode **)void_map;
	gnode=(map_gnode *)void_node;

	(*hops)++;
	nhops=*hops;
	new_entry_pos=nhops-1;
	t=xzalloc(sizeof(tracer_chunk) * nhops);
	
	if(tracer || nhops > 1) {
		/* 
		 * In the tracer_pkt there are already some chunks, we copy 
		 * them in the new pkt.
		 */
		memcpy(t, tracer, sizeof(tracer_chunk) * (nhops-1));


		/* 
		 * We add, in the new entry, the rtt there is from me to the 
		 * node of the the last entry of the old tracer pkt.
		 */

		last_entry_node=tracer[nhops-2].node;
		if(!level) {
			from=node_from_pos(last_entry_node, map);
			
			/* check if `from' is in our rnodes */
			if((pos=rnode_find(me.cur_node, from)) == -1) {
				debug(DBG_INSANE, "%s:%d lvl: %d last_entry_node: %d",
						ERROR_POS, level, last_entry_node);
				return 0;
			}
			
			rfrom=&me.cur_node->r_node[pos];
		} else {
			from=(map_node*)gnode_from_pos(last_entry_node, 
					ext_map[_EL(level)]);
			
			/* check if `from' is in our rnodes */
			if((pos=g_rnode_find(me.cur_quadg.gnode[_EL(level)], 
							(map_gnode *)from) == -1)) {
				debug(DBG_INSANE, "%s:%d lvl: %d last_entry_node: %d",
						ERROR_POS, level, last_entry_node);
				return 0;
			}

			rfrom=&me.cur_quadg.gnode[_EL(level)]->g.r_node[pos];
		}
		t[new_entry_pos].rtt=rfrom->trtt;
	}

	/* Fill the new entry in the tracer_pkt */
	if(!level) {
		t[new_entry_pos].gcount = 1;
		t[new_entry_pos].node=pos_from_node(node, map);
	} else {
		t[new_entry_pos].gcount = qspn_gnode_count[_EL(level)];
		t[new_entry_pos].node=pos_from_gnode(gnode, ext_map[_EL(level)]);
	}

	return t;
}

/* 
 * tracer_add_rtt: Increments the rtt of the `hop'th `tracer' chunk by adding
 * the rtt of the rnode who is in the `rpos' postion in me.cur_node->r_node.
 * It returns the new rtt value on success.
 */
int tracer_add_rtt(int rpos, tracer_chunk *tracer, u_short hop)
{
	tracer[hop].rtt+=me.cur_node->r_node[rpos].trtt;
	return tracer[hop].rtt;
}

/* 
 * tracer_get_trtt: It stores in `trtt' the total round trip time needed to
 * reach the `tracer[0].node' from the me.cur_node.
 * me.cur_node->r_node[`from_rnode_pos'] is the rnode who forwarded us the pkt. 
 * If it succeeds 0 is returned.
 */
int tracer_get_trtt(int from_rnode_pos, tracer_hdr *trcr_hdr,
		tracer_chunk *tracer, u_int *trtt)
{
	int hops, i;
	u_int trtt_ms=0;
	
	*trtt=0;

	hops = trcr_hdr->hops;
	if(!hops)
		return -1;
	
	/* Add the rtt of me -> from */
	trtt_ms+=me.cur_node->r_node[from_rnode_pos].trtt;

	for(i=hops-1; i >= 0; i--)
		trtt_ms+=tracer[i].rtt;

	*trtt=trtt_ms;

	return 0;
}

/*
 * tracer_update_gcount: it updates `gcount_counter' by adding the sum of 
 * gcounts present in `tracer'.
 * It then updates the map_gnode.gcount counter of the gnodes present in the 
 * `ext_map' of the `level'th level.
 * It ignores all the tracer chunks < `first_hop'.
 */
void tracer_update_gcount(tracer_hdr *trcr_hdr, tracer_chunk *tracer,
		int first_hop, u_int *gcount_counter, 
		map_node *int_map, map_gnode **ext_map, int level)
{
	map_node *node=0;
	map_gnode *gnode;
	u_int hops;
	int i;
	
	hops = trcr_hdr->hops;
	if(!hops || first_hop >= hops || first_hop < 0)
		return;

	for(i=first_hop; i>=0; i--) {
		if(level) {
			gnode=gnode_from_pos(tracer[i].node, ext_map[_EL(level)]);
			qspn_dec_gcount(gcount_counter, level+1, gnode->gcount);
			gnode->gcount=tracer[i].gcount;
		} else
			node = node_from_pos(tracer[i].node, int_map);

		if(level || (!level && node->flags & MAP_VOID))
			qspn_inc_gcount(gcount_counter, level+1, tracer[i].gcount);
	}
}

/* 
 * tracer_build_bentry: It builds the bnode_block to be added in the bnode's 
 * entry in the tracer pkt. It stores in `bnodechunk' the pointer to the 
 * first bnode_chunk and returns a pointer to the bnode_hdr.
 * `bnode_hdr' and `bnode_chunk' are on the same block of allocated memory.
 * The number of bnode_chunks is stored in `bnode_links'.
 * On errors it returns a NULL pointer.
 */
bnode_hdr *tracer_build_bentry(void *void_map, void *void_node, 
		quadro_group *node_quadg, bnode_chunk **bnodechunk,
		int *bnode_links, u_char level)
{
	map_node  *int_map, *node;
	map_gnode **ext_map, *gnode;
	map_gnode *gn;
	bnode_hdr *bhdr;
	bnode_chunk *bchunk;
	int i, bm, node_pos;
	size_t bblock_sz;
	u_char lvl;
	char *bblock;
	u_char *bnode_gid;

	int_map=(map_node *)void_map;
	node=(map_node *)void_node;
	ext_map=(map_gnode **)void_map;
	gnode=(map_gnode *)void_node;
	
	if(level == me.cur_quadg.levels-1)
		goto error;

	if(!level)
		node_pos=pos_from_node(node, int_map);
	else
		node_pos=pos_from_gnode(gnode, ext_map[_EL(level)]);
	
	bm=map_find_bnode(me.bnode_map[level], me.bmap_nodes[level], node_pos);
	if(bm==-1)
		goto error;

	/*This will never happen, but we know the universe is fucking bastard*/
	if(!me.bnode_map[level][bm].links)
		goto error;

	bblock_sz = BNODEBLOCK_SZ(level+1, me.bnode_map[level][bm].links);
	bblock=xzalloc(bblock_sz);

	bhdr=(bnode_hdr *)bblock;
	bhdr->bnode_levels=level+1;

	bnode_gid=(u_char *)(bblock + sizeof(bnode_hdr));
	bchunk=(bnode_chunk *)(bnode_gid + sizeof(u_char)*bhdr->bnode_levels);
	
	for(i=0; i<bhdr->bnode_levels; i++)
		bnode_gid[i] = node_quadg->gid[i];
	
	/* Fill the bnode chunks */
	for(i=0; i < me.bnode_map[level][bm].links; i++) {
		gn=(map_gnode *)me.bnode_map[level][bm].r_node[i].r_node;
		lvl=extmap_find_level(me.ext_map, gn, me.cur_quadg.levels);
	
		if(lvl != level+1)
			continue;

		bchunk[i].gnode=pos_from_gnode(gn, me.ext_map[_EL(lvl)]);
		bchunk[i].level=lvl;
		bchunk[i].rtt=me.bnode_map[level][bm].r_node[i].trtt;
		
		bhdr->links++;
		
		debug(DBG_INSANE, "tracer_build_bentry: lvl %d bchunk[%d].gnode:"
				" %d", level, i, bchunk[i].gnode);
	}

	if(!bhdr->links) {
		xfree(bblock);
		goto error;
	}	
	
	/* Reduce the size of the bblock to its effective size. Initially we 
	 * allocated it considering all the `me.bnode_map[level][bm].links' 
	 * links, but if bhdr->links is lesser than 
	 * me.bnode_map[level][bm].links that means they are not all added in
	 * the chunks.
	 */
	if(bhdr->links < me.bnode_map[level][bm].links) {
		bblock_sz = BNODEBLOCK_SZ(bhdr->bnode_levels, bhdr->links);
		bblock = xrealloc(bblock, bblock_sz);
		bhdr=(bnode_hdr *)bblock;
		bchunk=(bnode_chunk *)(bblock + BNODE_HDR_SZ(bhdr->bnode_levels));
	}

	*bnode_links=bhdr->links;
	*bnodechunk=bchunk;
	return bhdr;
error:
	*bnode_links=0;
	*bnodechunk=0;
	return 0;
}

/* 
 * tracer_pkt_build: 
 * It builds a tracer_pkt and stores it in `pkt'.
 * 
 * If `trcr_hdr' or `tracer' are null, it will build a brand new tracer_pkt, 
 * otherwise it will append in the `tracer' the new entry. 
 * Tracer_pkt_build will append also the old bblock: 
 * `old_bblocks' is the number of bblocks, 
 * `old_bblock_buf' is the block of the old bblock and it is `old_bblock_sz' big. 
 * If `old_bblocks' is 0 or `old_bblock_buf' and `old_bblock_sz' are null
 * they are ignored.
 * 
 * The `pkt.hdr.op' is set to `rq', `pkt.hdr.id' to `rq_id' and the 
 * `bcast_hdr.sub_id' to `bcast_sub_id'.
 * 
 * The packet shall be sent with flood_pkt_send.
 * It returns -1 on errors. 
 */
int tracer_pkt_build(u_char rq,   	     int rq_id, 	     int bcast_sub_id,
		     int gnode_id,	     u_char gnode_level,
		     brdcast_hdr *bcast_hdr, tracer_hdr *trcr_hdr,   tracer_chunk *tracer,  
		     u_short old_bblocks,    char *old_bblock_buf,   size_t old_bblock_sz,  
		     PACKET *pkt)
{
	brdcast_hdr bh;
	tracer_hdr th;
	
	tracer_chunk *new_tracer=0;
	bnode_hdr    *new_bhdr=0;
	bnode_chunk  *new_bchunk=0;
	map_node *root_node, *upper_root_node=0;
	char *igw_pack=0;
	void *void_map, *void_node, *p;
	size_t new_bblock_sz=0, total_bblock_sz=0, igw_pack_sz=0;
	u_int hops=0;
	int new_bblock_links=0, new_bblocks=0, tot_new_bblocks=0, tot_bblocks=0;

	if(!trcr_hdr || !tracer || !bcast_hdr) {
		/* Brand new tracer packet */
		bcast_hdr=&bh;
		setzero(bcast_hdr, sizeof(brdcast_hdr));
		
		bcast_hdr->gttl=MAXGROUPNODE-1;
		bcast_hdr->level=gnode_level+1;
		bcast_hdr->g_node=gnode_id; 
		
		trcr_hdr=&th;
		setzero(trcr_hdr, sizeof(tracer_hdr));
	} 
	
	hops=trcr_hdr->hops;

	setzero(pkt, sizeof(PACKET));
	pkt->hdr.op=rq;
	pkt->hdr.id=rq_id;
	pkt->hdr.flags|=BCAST_PKT;
	bcast_hdr->flags|=BCAST_TRACER_PKT;
	
	if(!gnode_level) {
		void_map=(void *)me.int_map;
		root_node=me.cur_node;
		void_node=(void *)root_node;
	} else {
		void_map=(void *)me.ext_map;
		root_node=&me.cur_quadg.gnode[_EL(gnode_level)]->g;
		void_node=(void *)root_node;
	}
	
	if(gnode_level < me.cur_quadg.levels)
		upper_root_node=&me.cur_quadg.gnode[_EL(gnode_level+1)]->g;


	/* 
	 * Time to append our entry in the tracer_pkt 
	 */
	new_tracer=tracer_add_entry(void_map, void_node, tracer, &hops, 
			gnode_level); 
	if(!new_tracer) {
		debug(DBG_NOISE, "tracer_pkt_build: Cannot add the new"
				" entry in the tracer_pkt");
		return -1;
	}
	if(rq == QSPN_OPEN && !trcr_hdr->first_qspn_open_chunk)
		trcr_hdr->first_qspn_open_chunk=hops;

	/* If we are a bnode we have to append the bnode_block too. */
	if(me.cur_node->flags & MAP_BNODE &&
			gnode_level < me.cur_quadg.levels-1 &&
			upper_root_node->flags & MAP_BNODE) {

		new_bhdr=tracer_build_bentry(void_map, void_node,&me.cur_quadg,
				&new_bchunk, &new_bblock_links, gnode_level);
		if(new_bhdr) {
			tot_new_bblocks=1;
			new_bblock_sz=BNODEBLOCK_SZ(new_bhdr->bnode_levels,
					new_bblock_links);

			bcast_hdr->flags|=BCAST_TRACER_BBLOCK;
			trcr_hdr->flags|=TRCR_BBLOCK;
		}
	}

	if(restricted_mode &&
		((!gnode_level && server_opt.share_internet && me.inet_connected) || 
			(gnode_level && me.igws_counter[gnode_level-1]))) {
		
		igw_pack=igw_build_bentry(gnode_level, &igw_pack_sz, &new_bblocks);

		/* Append the igw_pack after the new bblock */
		if(igw_pack) {
			total_bblock_sz = new_bblock_sz + igw_pack_sz;
			new_bhdr=xrealloc(new_bhdr, total_bblock_sz);

			tot_new_bblocks += new_bblocks;
			
			bcast_hdr->flags|=BCAST_TRACER_BBLOCK;
			trcr_hdr->flags|=TRCR_IGW;

			p=(char *)new_bhdr + new_bblock_sz;
			memcpy(p, igw_pack, igw_pack_sz);
		}
		
		new_bblock_sz+=igw_pack_sz;
	}
	
	/*
	 * If in the old tracer_pkt is present a bblock, we append it after the 
	 * new entry.
	 */
	if(old_bblocks && old_bblock_buf && old_bblock_sz) {
		total_bblock_sz = new_bblock_sz + old_bblock_sz;
		new_bhdr=xrealloc(new_bhdr, total_bblock_sz);
	
		p=(char *)new_bhdr + new_bblock_sz;
		memcpy(p, old_bblock_buf, old_bblock_sz);
		
		bcast_hdr->flags|=BCAST_TRACER_BBLOCK;
		
		new_bblock_sz+=old_bblock_sz;
	}

	tot_bblocks=tot_new_bblocks+old_bblocks;
	
	/* 
	 * Here we are really building the pkt, packing all the stuff into a
	 * single bullet.
	 */
	trcr_hdr->hops=hops;
	bcast_hdr->sub_id=bcast_sub_id;
	bcast_hdr->sz=TRACERPKT_SZ(hops)+new_bblock_sz;
	pkt->hdr.sz=BRDCAST_SZ(bcast_hdr->sz);
	pkt_addcompress(pkt);
	pkt_addtimeout(pkt, TRACER_RQ_TIMEOUT, 0, 1);
	pkt_addnonblock(pkt);
	
	pkt->msg=tracer_pack_pkt(bcast_hdr, trcr_hdr, new_tracer,
			(char *)new_bhdr, new_bblock_sz, tot_bblocks);
	
	/* Yea, finished */
	if(new_tracer)
		xfree(new_tracer);	
	if(new_bhdr)
		xfree(new_bhdr);
	return 0;
}

/* 
 * tracer_pack_pkt: it packs the tracer packet.
 * 
 * If `new_bblocks' isn't zero, the first `new_bblocks'# bblocks contained in
 * `bblocks' are converted to network order.
 */
char *tracer_pack_pkt(brdcast_hdr *bcast_hdr, tracer_hdr *trcr_hdr, tracer_chunk *tracer, 
		      char *bblocks, size_t bblocks_sz, int new_bblocks)
{
	bnode_hdr *bhdr;
	bnode_chunk *bchunk;
	size_t pkt_sz;
	char *msg, *buf;
	int i, e;

	pkt_sz=BRDCAST_SZ(TRACERPKT_SZ(trcr_hdr->hops) + bblocks_sz);
	
	buf=msg=xzalloc(pkt_sz);

	/* add broadcast header */
	memcpy(buf, bcast_hdr, sizeof(brdcast_hdr));
	ints_host_to_network(buf, brdcast_hdr_iinfo);
	buf+=sizeof(brdcast_hdr);
	
	/* add the tracer header */
	memcpy(buf, trcr_hdr, sizeof(tracer_hdr));
	ints_host_to_network(buf, tracer_hdr_iinfo);
	buf+=sizeof(tracer_hdr);

	/* add the tracer chunks and convert them to network order */
	for(i=0; i<trcr_hdr->hops; i++) {
		memcpy(buf, &tracer[i], sizeof(tracer_chunk));
		ints_host_to_network(buf, tracer_chunk_iinfo);
		
		buf+=sizeof(tracer_chunk);
	}

	/* add the bnode blocks */
	if(bblocks_sz && bblocks) {
		/* copy the whole block */
		memcpy(buf, bblocks, bblocks_sz);
	
		/* and convert it to network order */
		for(e=0; e<new_bblocks; e++) {
			bhdr=(bnode_hdr *)buf;
			bchunk=(bnode_chunk *)((char *)buf+sizeof(bnode_hdr)+
					sizeof(u_char)*bhdr->bnode_levels);

			for(i=0; i<bhdr->links; i++)
				ints_host_to_network(&bchunk[i], bnode_chunk_iinfo);

			buf+=BNODEBLOCK_SZ(bhdr->bnode_levels, bhdr->links);
			ints_host_to_network(bhdr, bnode_hdr_iinfo);
		}
	}

	return msg;
}

/* 
 * tracer_unpack_pkt: Given a packet `rpkt' it scomposes the rpkt.msg in 
 * `new_bcast_hdr', `new_tracer_hdr', `new_tracer', 'new_bhdr', and 
 * `new_block_sz'.
 * If the `new_rip_quadg' pointer is not null, the quadro_group of the 
 * `rpk.from' ip is stored in it.
 * It returns 0 if the packet is valid, otherwise -1 is returned.
 * Note that rpkt.msg will be modified during the unpacking.
 */
int tracer_unpack_pkt(PACKET rpkt, brdcast_hdr **new_bcast_hdr, 
		      tracer_hdr **new_tracer_hdr, tracer_chunk **new_tracer, 
		      bnode_hdr **new_bhdr, size_t *new_bblock_sz,
		      quadro_group *new_rip_quadg, int *real_from_rpos)
{
	brdcast_hdr *bcast_hdr;
	tracer_hdr  *trcr_hdr;
	tracer_chunk *tracer;
	bnode_hdr    *bhdr=0;
	quadro_group rip_quadg;
	size_t bblock_sz=0, tracer_sz=0;
	int level, i;

	bcast_hdr=BRDCAST_HDR_PTR(rpkt.msg);
	ints_network_to_host(bcast_hdr, brdcast_hdr_iinfo);
	
	trcr_hdr=TRACER_HDR_PTR(rpkt.msg);
	ints_network_to_host(trcr_hdr, tracer_hdr_iinfo);
	
	tracer=TRACER_CHUNK_PTR(rpkt.msg);

	*new_bcast_hdr=0;
	*new_tracer_hdr=0;
	*new_tracer=0;
	*new_bhdr=0;
	*new_bblock_sz=0;
	*real_from_rpos=0;

	tracer_sz=BRDCAST_SZ(TRACERPKT_SZ(trcr_hdr->hops));
	if(tracer_sz > rpkt.hdr.sz || !trcr_hdr->hops || 
			trcr_hdr->hops > MAXGROUPNODE) {
		debug(DBG_INSANE, "%s:%d messed tracer pkt: %d, %d, %d", 
				ERROR_POS, tracer_sz, rpkt.hdr.sz, 
				trcr_hdr->hops);
		return -1;
	}

	if(rpkt.hdr.op == QSPN_CLOSE)
		/* It can be non-zero only if it is a QSPN_OPEN */
		trcr_hdr->first_qspn_open_chunk=0;
	
	/* Convert the tracer chunks to host order */
	for(i=0; i<trcr_hdr->hops; i++)
		ints_network_to_host(&tracer[i], tracer_chunk_iinfo);
	
	if(rpkt.hdr.sz > tracer_sz) {
		/* There is also a bnode block in the tracer pkt */

		bblock_sz=rpkt.hdr.sz-tracer_sz;
		bhdr=(bnode_hdr *)(rpkt.msg+tracer_sz);
		if((!(trcr_hdr->flags & TRCR_BBLOCK) && !(trcr_hdr->flags & TRCR_IGW)) ||
				!(bcast_hdr->flags & BCAST_TRACER_BBLOCK)) {
			debug(DBG_INSANE, ERROR_MSG "trcr_flags: %d flags: %d", 
					ERROR_POS, trcr_hdr->flags, 
					bcast_hdr->flags);
			return -1;
		}
	}

	if((level=bcast_hdr->level) > 0)
		level--;
	if(!(rpkt.hdr.flags & BCAST_PKT) || !(bcast_hdr->flags & BCAST_TRACER_PKT) || 
			level > FAMILY_LVLS) {
		debug(DBG_INSANE, "%s:%d", ERROR_POS);
			return -1;
	}

	/* Convert the ip in quadro_group */
	iptoquadg(rpkt.from, me.ext_map, &rip_quadg, QUADG_GID|QUADG_GNODE);
	memcpy(new_rip_quadg, &rip_quadg, sizeof(quadro_group));

	if(tracer_verify_pkt(tracer, trcr_hdr->hops, rpkt.from, &rip_quadg, level))
		return -1;
	
	*real_from_rpos=ip_to_rfrom(rpkt.from, &rip_quadg, 0, 0);
	if(*real_from_rpos < 0) {
		debug(DBG_INSANE, "%s:%d", ERROR_POS);
		return -1;
	}

	
	*new_bcast_hdr=bcast_hdr;
	*new_tracer_hdr=trcr_hdr;
	*new_tracer=tracer;
	*new_bhdr=bhdr;
	*new_bblock_sz=bblock_sz;
	return 0;
}

/* 
 * tracer_split_bblock: It searches from bnode_block_start to 
 * bnode_block_start+bblock_sz for bnode blocks.
 * It puts the address of the found bblock_hdr in the `bbl_hdr' (bnode block list)
 * and the address pointing to the start of the bnode_chunk in the `bbl'. The 
 * total size of all the valid bblocks considered is stored in `*bblock_found_sz'.
 * It then returns the number of bblocks found. 
 * 
 * During the splitting the bblock is modified 'cause it is converted in host
 * order.
 * Remember to xfree bbl_hdr and bbl after using tracer_split_bblock too. 
 * On error zero is returned.
 */
u_short tracer_split_bblock(void *bnode_block_start, size_t bblock_sz, bnode_hdr ***bbl_hdr, 
		        bnode_chunk ****bbl, size_t *bblock_found_sz)
{
	bnode_hdr 	*bblock_hdr;
	bnode_chunk 	*bblock;
	bnode_hdr 	**bblist_hdr=0;
	bnode_chunk 	***bblist=0;
	u_char 		*bnode_gid;
	size_t 		bsz=0;
	int loop,e,p,x=0;
		
	*bblock_found_sz=0;
	if(!bblock_sz)
		return 0;

	for(loop=0; loop <= 1; loop++) {
		/*
		 * The second `for' below acts in different ways for different
		 * values of `loop'.
		 * When `loop' == 0 it just counts how many valid bblocks there 
		 * are, then it allocs the right amount of memory for
		 * `bblist_hdr' and `bblist'.
		 * When `loop' == 1 it fills the `bblist_hdr' and `bblist'
		 * arrays.
		 *
		 * If we use just one loop we are forced to xrealloc
		 * `bblist_hdr' and `bblist' many times, because we don't know
		 * how many bblocks thereare. The malloc operation are slow,
		 * therefore to use only one xmalloc we prefer to count first.
		 */

		for(e=0, x=0; e < bblock_sz; ) {
			bblock_hdr=(void *)((char *)bnode_block_start + e);
			if(!loop)
				ints_network_to_host(bblock_hdr, bnode_hdr_iinfo);

			bnode_gid = (u_char *)bblock_hdr+sizeof(bnode_hdr);
			bblock    = (bnode_chunk *)((char *)bnode_gid +
					(bblock_hdr->bnode_levels*sizeof(u_char)));

			if(bblock_hdr->links <= 0 || bblock_hdr->links >= MAXGROUPNODE) {
				e+=BNODEBLOCK_SZ(bblock_hdr->bnode_levels, 0);
				continue;
			}

			bsz=BNODEBLOCK_SZ(bblock_hdr->bnode_levels, bblock_hdr->links);

			/*Are we going far away the end of the buffer?*/
			if(bblock_sz-e < bsz)
				break;

			if(loop) {
				bblist_hdr[x]=bblock_hdr;
				bblist[x]=xmalloc(sizeof(bnode_chunk *) * bblock_hdr->links);
				for(p=0; p<bblock_hdr->links; p++) {
					bblist[x][p]=&bblock[p];
					ints_network_to_host(&bblock[p], bnode_chunk_iinfo); 
				}
			}

			if(!loop)
				(*bblock_found_sz)+=bsz;
			
			x++;
			e+=bsz;
		}

		if(!loop) {
			if(!x)
				return 0;

			bblist_hdr=xmalloc(sizeof(bnode_hdr *) * x);
			bblist=xmalloc(sizeof(bnode_chunk *) * x);
		}
	}

	*bbl_hdr=bblist_hdr;
	*bbl=bblist;
	return x;
}

/*
 * tracer_store_bblock: stores in the bnode map the chunks of the bblock
 * starting at `bnode_block_start'.
 * In `*bblocks_found' it stores the number of bblocks considered and stores in
 * `bblocks_found_block' these bblocks. The `bblocks_found_block' remains in 
 * host order.
 * Remember to xfree(bblocks_found_block);
 * On error -1 is returned.
 */
int tracer_store_bblock(u_char level, tracer_hdr *trcr_hdr, tracer_chunk *tracer,
		     void *bnode_block_start, size_t bblock_sz, 
		     u_short *bblocks_found,  char **bblocks_found_block,
		     size_t *bblock_found_sz)
{
	map_node *node;
	map_gnode *gnode;
	void *void_node;
	
	bnode_hdr 	**bblist_hdr=0;
	bnode_chunk 	***bblist=0;
	map_rnode rn;
	int i, e, o, f, p, bm, igws_found=0;
	u_short bb;
	size_t found_block_sz, bsz, x;
	char *found_block;
	u_char *bnode_gid, bnode, blevel;

	/*
	 * Split the block
	 */
	bb=tracer_split_bblock(bnode_block_start, bblock_sz, &bblist_hdr,
			&bblist, &found_block_sz);
	*bblocks_found = bb;
	if(!bb) {
		/* The bblock was malformed -_- */
		debug(DBG_NORMAL, ERROR_MSG "malformed bnode block", ERROR_POS);
		*bblock_found_sz = 0;
		*bblocks_found_block = 0;
		return -1;
	} 
		
	/*
	 * Store the received bnode blocks 
	 */

	igws_found=x=0;
	*bblocks_found_block=found_block=xmalloc(found_block_sz);
	for(i=0; i<bb; i++) {

		bnode_gid=(u_char *)bblist_hdr[i] + sizeof(bnode_hdr);

		/* We update only the bmaps which are at
		 * levels where our gnodes are in common with
		 * those of the bnode, which sent us this
		 * bblock */
		for(o=level, f=0; o >= 0; o--)
			if(bnode_gid[o] != me.cur_quadg.gid[o]) {
				f=1;
				break;
			}
		if(!f) { 
			/*
			 * bnode_gid is equal to me.cur_quadg.gid, so this 
			 * bnode block was sent by ourself, skip it. 
			 */

			debug(DBG_NORMAL, ERROR_MSG "skipping the %d bnode,"
					"it was built by us!", ERROR_POS, i);
			goto discard_bblock;
		}

		/*
		 * Check if this bblock is an IGW. If it is, store it in
		 * me.igws
		 */
		if(bblist[i][0]->level >= FAMILY_LVLS+1) {
			if(restricted_mode && 
				(igws_found < MAX_IGW_PER_QSPN_CHUNK &&
					trcr_hdr->flags & TRCR_IGW)) {

				if(server_opt.use_shared_inet)
					igw_store_bblock(bblist_hdr[i],
							 bblist[i][0], level);
				igws_found++;
				
				goto skip_bmap;
			} else {
				debug(DBG_NOISE, ERROR_MSG "Malforded bblock entry", 
						ERROR_POS);
				goto discard_bblock;
			}
		}
	
		if(!(trcr_hdr->flags & TRCR_BBLOCK)) {
			debug(DBG_NOISE, ERROR_MSG "Malforded bblock entry", ERROR_POS);
			goto discard_bblock;
		}

		for(blevel=o; blevel < bblist_hdr[i]->bnode_levels; blevel++) {
			bnode=bnode_gid[blevel];

			if(!blevel) {
				node=node_from_pos(bnode, me.int_map);
				node->flags|=MAP_BNODE;
				node->flags&=~QSPN_OLD;
				void_node=(void *)node;
			} else {
				gnode=gnode_from_pos(bnode, me.ext_map[_EL(blevel)]);
				gnode->g.flags|=MAP_BNODE;
				gnode->g.flags&=~QSPN_OLD;
				void_node=(void *)&gnode->g;
			}

			/* Let's check if we have this bnode in the bmap, if not let's 
			 * add it */
			bm=map_find_bnode(me.bnode_map[blevel], me.bmap_nodes[blevel], 
					bnode);
			if(bm==-1)
				bm=map_add_bnode(&me.bnode_map[blevel], 
						&me.bmap_nodes[blevel],
						bnode,  0);

			/* This bnode has the BMAP_UPDATE
			 * flag set, thus this is the first
			 * time we update him during this new
			 * qspn_round and for this reason
			 * delete all its rnodes */
			if(me.bnode_map[blevel][bm].flags & BMAP_UPDATE) {
				rnode_destroy(&me.bnode_map[blevel][bm]);
				me.bnode_map[blevel][bm].flags&=~BMAP_UPDATE;
			}

			/* Store the rnodes of the bnode */
			for(e=0; e < bblist_hdr[i]->links; e++) {
				setzero(&rn, sizeof(map_rnode));
				debug(DBG_INSANE, "Bnode %d new link %d: gid %d lvl %d", 
						bnode, e, bblist[i][e]->gnode,
						bblist[i][e]->level);

				gnode=gnode_from_pos(bblist[i][e]->gnode, 
						me.ext_map[_EL(bblist[i][e]->level)]);
				gnode->g.flags&=~QSPN_OLD;

				rn.r_node=(int *)gnode;
				rn.trtt=bblist[i][e]->rtt;

				if((p=rnode_find(&me.bnode_map[blevel][bm], gnode)) > 0) {
					/* Overwrite the current rnode */
					map_rnode_insert(&me.bnode_map[blevel][bm],p,&rn);
				} else
					/* Add a new rnode */
					rnode_add(&me.bnode_map[blevel][bm], &rn);
			}
		}
skip_bmap:
		/* Copy the found bblock in `bblocks_found_block' and converts
		 * it in network order */
		bsz=BNODEBLOCK_SZ(bblist_hdr[i]->bnode_levels, bblist_hdr[i]->links);
		memcpy(found_block+x, bblist_hdr[i], bsz);
		x+=bsz;
discard_bblock:
		xfree(bblist[i]);
	}

	*bblock_found_sz=x;

	xfree(bblist_hdr);
	xfree(bblist);

	return 0;
}

/*
 * tracer_check_node_collision: if a collision is detected between me and the
 * (g)node `node', new_rehook shall be called and 1 returned.
 * `tr_node' is the gid of `node'.
 */
int tracer_check_node_collision(tracer_hdr *trcr, int hop, map_node *node, 
		int tr_node, int tr_gcount, int level)
{
	map_gnode *gnode;
	int probable_collision=0;
	u_int gcount;
	map_node *root_node;

	gnode=(map_gnode *)node;
	if(!level) {
		gcount=0;
		root_node=me.cur_node;
	} else {
		gcount=tr_gcount;
		root_node=&me.cur_quadg.gnode[_EL(level)]->g;
	}

	if(node == root_node && 
		(
		   (
		    trcr->first_qspn_open_chunk && 
		    !(
			  (trcr->first_qspn_open_chunk-1 == hop && 
				  (root_node->flags & QSPN_OPENER)) || 
			  (hop < trcr->first_qspn_open_chunk-1)
		     )
		   ) ||
		   (
		    !trcr->first_qspn_open_chunk && 
		    !(!hop && (root_node->flags & QSPN_STARTER))
		   )
		)
	  )
		probable_collision=1;

	if(probable_collision) {
		loginfo("%s collision detected! Checking rehook status...", 
				!level ? "node" : "gnode");
		debug(DBG_NORMAL,"collision info: i: %d, starter %d opener %d",
				hop, me.cur_node->flags & QSPN_STARTER,
				me.cur_node->flags & QSPN_OPENER);
		new_rehook(gnode, tr_node, level, gcount);

		return 1;
	}

	return 0;
}

/* 
 * tracer_store_pkt: This is the main function used to keep the int/ext_map's
 * karma in peace.
 * It updates the internal or external map with the given tracer pkt.
 *
 * `rip' is the rnode ip. It is the last node who forwarded the tracer pkt to
 * us. `rip_quadg' is a quadro_group struct related to it.
 *
 * `trcr_hdr' is the header of the tracer pkt, while `tracer' points at the
 * start of its body.
 * 
 * The bnode blocks (if any) are unpacked and used to update the data of the
 * bordering gnodes. Read the tracer_store_bblock() description (above) to 
 * know the meaning of the other arguments.
 */
int tracer_store_pkt(inet_prefix rip, quadro_group *rip_quadg, u_char level, 
		     tracer_hdr *trcr_hdr,    tracer_chunk *tracer,
		     void *bnode_block_start, size_t bblock_sz, 
		     u_short *bblocks_found,  char **bblocks_found_block, 
		     size_t *bblock_found_sz)
{
	map_node *from, *node, *root_node;
	map_gnode *gfrom, *gnode=0;
	map_rnode rnn;
			
	int i, e, x, f, diff, from_rnode_pos, skip_rfrom;
	int gfrom_rnode_pos, from_tpos;
	u_int hops, trtt_ms=0;


	hops = trcr_hdr->hops;
	/* Nothing to store */
	if(hops <= 0)
		return 0;
	
	from_tpos = hops-1;
	if(!level) {
	 	from   	       = node_from_pos(tracer[from_tpos].node, me.int_map);
		root_node      = me.cur_node;
	} else {
		gfrom	       = gnode_from_pos(tracer[from_tpos].node, me.ext_map[_EL(level)]);
		from	       = &gfrom->g;
		root_node      = &me.cur_quadg.gnode[_EL(level)]->g;
	}
	from_rnode_pos = rnode_find(root_node, from);

	/* It's alive, keep it young */
	from->flags&=~QSPN_OLD;
	
	if(bblock_sz && level != me.cur_quadg.levels-1) {
		/* Well, well, we have to take care of bnode blocks, split the
		 * bblock. */
		tracer_store_bblock(level, trcr_hdr, tracer, bnode_block_start,
				bblock_sz, bblocks_found, bblocks_found_block,
				bblock_found_sz);
	}
	
	/* 
	 * * Store the qspn routes to reach all the nodes of the tracer pkt *
	 */
	
	skip_rfrom=0;
	node=root_node;
	if(!level) {
		/* We skip the node at hops-1 which it is the `from' node. The radar() 
		 * takes care of him. */
		skip_rfrom = 1;
	} else if(from == root_node) {
		/* If tracer[hops-1].node is our gnode then we can skip it */
		skip_rfrom = 1;
		from_tpos  = hops-2;
		from_rnode_pos=ip_to_rfrom(rip, rip_quadg, 0, 0);

		if(hops > 1) {
			map_rnode rnn;
			
			/* 
			 * hops-2 is an rnode of hops-1, which is our gnode,
			 * so we update the `gfrom' and `from' vars and let
			 * them point to hops-2.
			 */
			gfrom=gnode_from_pos(tracer[hops-2].node,
					me.ext_map[_EL(level)]);
			from = &gfrom->g;
			from->flags|=MAP_GNODE | MAP_RNODE;

			gfrom_rnode_pos=rnode_find(root_node, gfrom);
			if(gfrom_rnode_pos == -1) {
				gfrom_rnode_pos=root_node->links;
				
				/*
				 * Add an rnode in the root_node which point to
				 * `gfrom', because it is our new (g)rnode.
				 */
				setzero(&rnn, sizeof(map_rnode));
				rnn.r_node=(int *)gfrom;
				rnode_add(root_node, &rnn);
			}
			root_node->r_node[gfrom_rnode_pos].trtt=tracer[hops-2].rtt;
		}

		/* we are using the real from, so the root node is the one
		 * at level 0 */
		node=me.cur_node;
	} else if(me.cur_node->flags & MAP_BNODE) {
		/* If we are a bnode which borders on the `from' [g]node, then we
		 * can skip it. */
		i=map_find_bnode_rnode(me.bnode_map[level-1], me.bmap_nodes[level-1], from);
		if(i != -1)
			skip_rfrom = 1;
	}

	if(from_tpos >= 0) { /* Is there a rnode in the tracer ? */

		/* Update `qspn_gnode_count' */
		tracer_update_gcount(trcr_hdr, tracer, from_tpos, 
				qspn_gnode_count, me.int_map, me.ext_map, level);

		/* Let's see if we have to rehook */
		new_rehook((map_gnode *)from, tracer[from_tpos].node, level,
				tracer[from_tpos].gcount);
	}

	/* We add in the total rtt the first rtt which is me -> from */
	trtt_ms=node->r_node[from_rnode_pos].trtt;

	/* If we are skipping the rfrom, remember to sum its rtt */
	if(skip_rfrom)
		trtt_ms+=tracer[hops-1].rtt;

	for(i=(hops-skip_rfrom)-1; i >= 0; i--) {
		if(i)
			trtt_ms+=tracer[i].rtt;

		if(!level)
			node=node_from_pos(tracer[i].node, me.int_map);
		else {
			gnode=gnode_from_pos(tracer[i].node, me.ext_map[_EL(level)]);
			node=&gnode->g;

			if(tracer[i].gcount == NODES_PER_LEVEL(level))
				/* The gnode is full */
				gnode->g.flags|=GMAP_FULL;
		}
		
		if(tracer_check_node_collision(trcr_hdr, i, node, tracer[i].node, 
					tracer[i].gcount, level))
			break;
				
		node->flags&=~QSPN_OLD;
			
		if(node->flags & MAP_VOID) { 
			/* Ehi, we hadn't this node in the map. Add it. */
			node->flags&=~MAP_VOID;
			node->flags|=MAP_UPDATE;
			if(level)
				gnode->flags&=~GMAP_VOID;
	
			gnode_inc_seeds(&me.cur_quadg, level);
			debug(DBG_INSANE, "TRCR_STORE: node %d added", tracer[i].node);
		}
		
		/* update the rtt of the node */
		for(e=0,f=0; e < node->links; e++) {
			if(node->r_node[e].r_node == (int *)from) {
				diff=abs(node->r_node[e].trtt - trtt_ms);
				if(diff >= RTT_DELTA) {
					node->r_node[e].trtt = trtt_ms;
					node->flags|=MAP_UPDATE;
				}
				f=1;
				break;
			}
		}
		if(!f) { 
			/*If the `node' doesn't have `from' in his r_nodes... let's add it*/
			setzero(&rnn, sizeof(map_rnode));

			rnn.r_node=(int *)from;
			rnn.trtt=trtt_ms;
			
			rnode_add(node, &rnn);
			node->flags|=MAP_UPDATE;
		}

		/* ok, now the kernel needs a refresh of the routing table */
		if(node->flags & MAP_UPDATE) {
			rnode_trtt_order(node);
			
			if(node->links > MAXROUTES) { 
				/* 
				 * If we have too many routes we purge the worst
				 * ones.
				 */
				for(x=MAXROUTES; x < node->links; x++)
					rnode_del(node, x);
			}
			
			debug(DBG_INSANE, "TRCR_STORE: krnl_update node %d", tracer[i].node);
			rt_update_node(0, node, 0, 0, 0, level);
			node->flags&=~MAP_UPDATE;
		}
	}
	return 0;
}


/* 
 * flood_pkt_send: This functions is used to propagate packets, in a broadcast
 * manner, in a entire gnode of a specified level.
 * It sends the `pkt' to all the nodes excluding the excluded nodes. It knows 
 * if a node is excluded by calling the `is_node_excluded' function. The 
 * second argument to this function is the node who sent the pkt and it must be
 * always excluded. The third argument is the position of the node being processed
 * in the r_node array of me.cur_node. The other arguments are described in
 * tracer.h.
 * If `is_node_excluded' returns a non 0 value, the node is considered as excluded.
 * The `from_rpos' argument is the node who sent the `pkt'.
 * It returns the number of pkts sent or -1 on errors. Note that the total pkt sent
 * should be == me.cur_node->links-the_excluded_nodes.
 * Note that `level', `sub_id', and `from_rpos' are vars used only by
 * is_node_excluded() (see tracer.h).
 */
int flood_pkt_send(int(*is_node_excluded)(TRACER_PKT_EXCLUDE_VARS), u_char level,
		int sub_id, int from_rpos, PACKET pkt)
{
	ext_rnode *e_rnode;
	map_node *dst_node, *node;

	ssize_t err;
	const char *ntop;
	int i, e=0;

	/*
	 * Forward the pkt to all our r_nodes (excluding the excluded;)
	 */
	for(i=0; i < me.cur_node->links; i++) {
		node=(map_node *)me.cur_node->r_node[i].r_node;
		if(node->flags & MAP_ERNODE) {
			e_rnode=(ext_rnode *)node;
			dst_node=(map_node *)e_rnode->quadg.gnode[_EL(level-1)];
		} else {
			e_rnode=0;
			dst_node=node;
		}

		if(!dst_node)
			continue;
		if(is_node_excluded(e_rnode, dst_node, from_rpos, i, level, sub_id))
			continue;

		/* Get the socket associated to the rnode  */
		if(rnl_fill_rq(node, &pkt) < 0)
			continue;
		if(server_opt.dbg_lvl)
			debug(DBG_INSANE, "flood_pkt_send(0x%x): %s to %s"
					" lvl %d", pkt.hdr.id, 
					rq_to_str(pkt.hdr.op),
					inet_to_str(pkt.to), level-1);
				
		/* Let's send the pkt */
		err=rnl_send_rq(node, &pkt, 0, pkt.hdr.op, pkt.hdr.id, 
				0, 0, 0);
		if(err==-1) {
			ntop=inet_to_str(pkt.to);
			error(ERROR_MSG "Cannot send the %s request"
					" with id: %d to %s", 
			      ERROR_FUNC, rq_to_str(pkt.hdr.op),
					  pkt.hdr.id, ntop);
		} else
			e++;
	}
		
	pkt_free(&pkt, 0);
	return e;
}

/* * * 	Exclude functions * * *
 * These exclude function are used in conjunction with flood_pkt_send. 
 * They return 1 if the node has to be excluded, otherwise 0.
 */

/*
 * exclude_glevel: Exclude `node' if it doesn't belong to the gid (`excl_gid') of 
 * the level (`excl_level') specified.
 */
int exclude_glevel(TRACER_PKT_EXCLUDE_VARS)
{
	/* If `node' is null we can exclude it, because it isn't a gnode
	 * of ours levels */
	if(!node)
		return 1;
	
	/* Ehi, if the node isn't even an external rnode, we don't exclude it. */
	if(!(node->flags & MAP_ERNODE))
		return 0;

	/* Reach the sky */
	if(excl_level == me.cur_quadg.levels)
		return 0;
	
	return quadg_gids_cmp(e_rnode->quadg, me.cur_quadg, excl_level);
}

/* Exclude the `from' node */
int exclude_from(TRACER_PKT_EXCLUDE_VARS)
{
	if(pos == from_rpos)
		return 1;
	return 0;
}

/* Exclude all the nodes, except the from node */
int exclude_all_but_notfrom(TRACER_PKT_EXCLUDE_VARS)
{
	if(!exclude_from(TRACER_PKT_EXCLUDE_VARS_NAME))
		return 1;
	return 0;
}

int exclude_from_and_glevel(TRACER_PKT_EXCLUDE_VARS)
{
	if(exclude_glevel(TRACER_PKT_EXCLUDE_VARS_NAME) || 
			exclude_from(TRACER_PKT_EXCLUDE_VARS_NAME))
		return 1;
	return 0;
}


/* 
 * tracer_pkt_recv: It receive a TRACER_PKT or a TRACER_PKT_CONNECT, analyzes 
 * the received pkt, adds the new entry in it and forward the pkt to all 
 * the r_nodes.
 */
int tracer_pkt_recv(PACKET rpkt)
{
	PACKET pkt;
	brdcast_hdr  *bcast_hdr;
	tracer_hdr   *trcr_hdr;
	tracer_chunk *tracer;
	bnode_hdr    *bhdr=0;
	map_node *from, *tracer_starter, *root_node;
	map_gnode *gfrom;
	quadro_group rip_quadg;
	
	int(*exclude_function)(TRACER_PKT_EXCLUDE_VARS);
	int ret_err, gid, real_from_rpos;
	u_int hops;
	size_t bblock_sz=0, old_bblock_sz;
	u_short old_bblocks_found=0;
	u_char level, orig_lvl;
	const char *ntop=0;
	char *old_bblock=0;
	void *void_map;

	ret_err=tracer_unpack_pkt(rpkt, &bcast_hdr, &trcr_hdr, &tracer, 
			&bhdr, &bblock_sz, &rip_quadg, &real_from_rpos);
	if(ret_err) {
		ntop=inet_to_str(rpkt.from);
		debug(DBG_NOISE, "tracer_pkt_recv(): The %s sent an invalid "
				 "tracer_pkt here.", ntop);
		return -1;
	}

	hops=trcr_hdr->hops;
	gid=bcast_hdr->g_node;
	level=orig_lvl=bcast_hdr->level;
	if(!level || level == 1) {
		level=0;
		root_node      = me.cur_node;
		from	       = node_from_pos(tracer[hops-1].node, me.int_map);
		tracer_starter = node_from_pos(tracer[0].node, me.int_map);
		void_map=me.int_map;
	} else {
		level--;
		root_node      = &me.cur_quadg.gnode[_EL(level)]->g;
		gfrom	       = gnode_from_pos(tracer[hops-1].node, me.ext_map[_EL(level)]);
		from	       = &gfrom->g;
		tracer_starter = (map_node *)gnode_from_pos(tracer[0].node, me.ext_map[_EL(level)]);
		void_map       = me.ext_map;
	}

	if(server_opt.dbg_lvl) {
		ntop=inet_to_str(rpkt.from);
		debug(DBG_NOISE, "Tracer_pkt(0x%x, lvl %d) received from %s", 
				rpkt.hdr.id, level, ntop);
	}

	/*
	 * This is the check for the broadcast id. If it is <= tracer_starter->brdcast
	 * the pkt is an old broadcast that still dance around.
	 */
	if(rpkt.hdr.id <= tracer_starter->brdcast) {
		debug(DBG_NOISE, "tracer_pkt_recv(): Received from %s an old "
				"tracer_pkt broadcast: 0x%x, cur: 0x%x", ntop,
				rpkt.hdr.id, tracer_starter->brdcast);
		return -1;
	} else
		tracer_starter->brdcast=rpkt.hdr.id;


	/* 
	 * Time to update our map
	 */
	if(rpkt.hdr.op == TRACER_PKT) { /*This check is made because tracer_pkt_recv 
					 handles also TRACER_PKT_CONNECT pkts*/
		
		ret_err=tracer_store_pkt(rpkt.from, &rip_quadg, level,
				trcr_hdr, tracer, (void *)bhdr,
				bblock_sz, &old_bblocks_found, &old_bblock,
				&old_bblock_sz);
		if(ret_err) {
			ntop=inet_to_str(rpkt.from);
			debug(DBG_NORMAL, "tracer_pkt_recv(): Cannot store the"
					" tracer_pkt received from %s", ntop);
		}
	}


	/* 
	 * Drop the pkt if it is bound to the contigual qspn starters and we
	 * aren't a qspn_starter
	 */
	if(bcast_hdr->flags & BCAST_TRACER_STARTERS  && 
			!(root_node->flags & QSPN_STARTER))
		return 0;
	
	/*The forge of the packet.*/
	if((!level || ((me.cur_node->flags & MAP_BNODE) && 
					(root_node->flags & MAP_BNODE))) &&
			from != root_node) {
		tracer_pkt_build(rpkt.hdr.op, rpkt.hdr.id, bcast_hdr->sub_id,  /*IDs*/
				 gid,         level,			    
				 bcast_hdr,   trcr_hdr, tracer, 	       /*Received tracer_pkt*/
				 old_bblocks_found, old_bblock, old_bblock_sz, /*bnode_block*/
				 &pkt);					       /*Where the pkt is built*/
	} else {
		/* Increment the rtt of the last gnode chunk */
		ret_err=tracer_add_rtt(real_from_rpos, tracer, hops-1);
		if(ret_err < 0)
			debug(DBG_NOISE, "tracer_add_rtt(0x%x) hop %d failed",
					rpkt.hdr.id, hops-1);
		pkt_copy(&pkt, &rpkt);
		pkt_clear(&pkt);
	}
	

	/*... forward the tracer_pkt to our r_nodes*/
	exclude_function=exclude_from_and_glevel;
	flood_pkt_send(exclude_function, orig_lvl, real_from_rpos,
			real_from_rpos, pkt);

	if(old_bblock)
		xfree(old_bblock);
	return 0;
}

/* 
 * tracer_pkt_start: It sends only a normal tracer_pkt. This is useful after 
 * the hook, to let all the other nodes know we are alive and to give them 
 * the right route.
 */
int tracer_pkt_start(u_char level)
{
	PACKET pkt;
	int root_node_pos;
	
	if(tracer_pkt_start_mutex)
		return 0;
	else
		tracer_pkt_start_mutex=1;

	if(!level || level == 1) {
		level=0;
		root_node_pos=pos_from_node(me.cur_node, me.int_map);
	} else
		root_node_pos=pos_from_gnode(me.cur_quadg.gnode[_EL(level)], 
				me.ext_map[_EL(level)]);

	me.cur_node->brdcast++;
	tracer_pkt_build(TRACER_PKT, me.cur_node->brdcast, root_node_pos,/*IDs*/
			 me.cur_quadg.gid[level+1],	   level,	 /*GnodeID and level*/
			 0,          0,                    0, 		 /*Received tracer_pkt*/
			 0,          0,                    0, 		 /*bnode_block*/
			 &pkt);						 /*Where the pkt is built*/
	/*Diffuse the packet in all the universe!*/
	debug(DBG_INSANE, "Tracer_pkt 0x%x starting.", pkt.hdr.id);
	flood_pkt_send(exclude_from_and_glevel, level+1, -1, -1, pkt);
	tracer_pkt_start_mutex=0;
	return 0;
}
