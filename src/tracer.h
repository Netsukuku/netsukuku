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

#ifndef TRACER_H
#define TRACER_H

#include "pkts.h"
#include "bmap.h"


#define TRACER_RQ_TIMEOUT	16	/* seconds */

/*
 * Tracer_hdr flags
 */

#define TRCR_BBLOCK		1	/* In this tracer_pkt there are 
					   encapsulated bblocks */
#define TRCR_IGW		(1<<1)	/* Internet Gateways are encapsulated
					   in the pkt */

/*
 * *  Tracer packet. It is encapsulated in a broadcast pkt  *
 */
typedef struct
{
	u_char		flags;
	u_short		hops;
	u_short		first_qspn_open_chunk;
}_PACKED_ tracer_hdr;
INT_INFO tracer_hdr_iinfo = { 2,
			      { INT_TYPE_16BIT, INT_TYPE_16BIT }, 
			      { sizeof(u_char), sizeof(u_char)+sizeof(u_short) },
			      { 1, 1 }
			    };
typedef struct
{
	u_char		node;
	u_int		rtt;	/* The rtt to reach the `node' of the previous
				   chunk from the node of the current `one'. 
				   (in milliseconds) */
	u_int		gcount; /* how many nodes there are in the `node' 
				   gnode */
}_PACKED_ tracer_chunk;
INT_INFO tracer_chunk_iinfo = { 2, 
				{ INT_TYPE_32BIT, INT_TYPE_32BIT }, 
				{ sizeof(char), sizeof(char)+sizeof(u_int) }, 
				{ 1, 1 } 
			      };
#define TRACERPKT_SZ(hops) 	(sizeof(tracer_hdr)+(sizeof(tracer_chunk)*(hops)))
#define TRACER_HDR_PTR(msg) 	((tracer_hdr *)(((char *)BRDCAST_HDR_PTR((msg)))+sizeof(brdcast_hdr)))
#define TRACER_CHUNK_PTR(msg)	((tracer_chunk *)(((char *)TRACER_HDR_PTR(msg))+sizeof(tracer_hdr)))

int tracer_pkt_start_mutex;

/*Functions definition. Damn I hate to use functions with a lot of args. It isn't elegant*/
int ip_to_rfrom(inet_prefix rip, quadro_group *rip_quadg,
		quadro_group *new_quadg, char quadg_flags);
tracer_chunk *tracer_add_entry(void *void_map, void *void_node,
		tracer_chunk *tracer, u_int *hops, u_char level);
int tracer_add_rtt(int rpos, tracer_chunk *tracer, u_short hop);
u_short tracer_split_bblock(void *, size_t, bnode_hdr ***, bnode_chunk ****, size_t *);
int tracer_get_trtt(int from_rnode_pos, tracer_hdr *trcr_hdr,
		tracer_chunk *tracer, u_int *trtt);
int tracer_store_pkt(inet_prefix, quadro_group *, u_char, tracer_hdr *, 
		tracer_chunk *, void *, size_t, u_short *,  char **, size_t *);
int tracer_unpack_pkt(PACKET, brdcast_hdr **, tracer_hdr **, tracer_chunk **, 
		bnode_hdr **, size_t *, quadro_group *, int *);
int tracer_pkt_build(u_char, int, int, int, u_char, brdcast_hdr *, tracer_hdr *,
		     tracer_chunk *, u_short, char *, size_t, PACKET *);

/*
 * TRACER_PKT_EXCLUDE_VARS:
 * `e_rnode':   if the dst is an external rnode, the relative one is passed.
 * `node':      the destination node/gnode we are sending the pkt to.
 * `from_rpos': the position in the root_node's rnodes of the node from 
 *              which the pkt was sent to us.
 * `pos' :      the position of the `node' in the root_node's rnodes.
 * `level':     The level where there is the gnode the pkt is restricted to.
 * `sub_id':    If the pkt is a qspn_open, it is the qspn open sub_id of 
 * 		the pkt.
 */
#define TRACER_PKT_EXCLUDE_VARS		ext_rnode *e_rnode, map_node *node,    \
					int from_rpos, int pos,		       \
					u_char excl_level, int sub_id
#define TRACER_PKT_EXCLUDE_VARS_NAME	e_rnode, node, from_rpos, pos, 	       \
					excl_level, sub_id
int flood_pkt_send(int(*is_node_excluded)(TRACER_PKT_EXCLUDE_VARS), u_char level,
		int sub_id, int from_rpos, PACKET pkt);
int exclude_from(TRACER_PKT_EXCLUDE_VARS);
int exclude_glevel(TRACER_PKT_EXCLUDE_VARS);
int exclude_all_but_notfrom(TRACER_PKT_EXCLUDE_VARS);
int exclude_from_and_glevel(TRACER_PKT_EXCLUDE_VARS);

int tracer_pkt_recv(PACKET rpkt);
int tracer_pkt_start(u_char level);

#endif /*TRACER_H*/
