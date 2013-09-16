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
 *  
 * hook.c:
 * This is code which handles the hooking of a new node in netsukuku, or the
 * creation of a new gnode.
 */

#include "includes.h"

#include "common.h"
#include "libnetlink.h"
#include "ll_map.h"
#include "inet.h"
#include "if.h"
#include "krnl_route.h"
#include "iptunnel.h"
#include "endianness.h"
#include "bmap.h"
#include "route.h"
#include "request.h"
#include "pkts.h"
#include "tracer.h"
#include "qspn.h"
#include "hook.h"
#include "rehook.h"
#include "radar.h"
#include "netsukuku.h"
#include "common.h"

int free_the_tmp_cur_node;
int we_are_rehooking; 		/* 1 if it is true */

void hook_reset(void);

/*
 * hook_fill_rq
 *
 * It's just a wrapper to rnl_fill_rq().
 */
int hook_fill_rq(map_node *dst_rnode, PACKET *pkt, u_char rq)
{
	if(rnl_fill_rq(dst_rnode, pkt) < 0)
		return -1;

	if(server_opt.dbg_lvl) {
		const char *ntop;
		ntop=inet_to_str(pkt->to);
		debug(DBG_INSANE, "Quest %s to %s", rq_to_str(rq), ntop);
	}

	return 0;
}


/*
 * verify_free_nodes_hdr: verifies the validity of the `fn_hdr'
 * free_nodes_hdr. `to' is the ip of the node which sent the 
 * put_free_nodes reply.
 * If the header is valid 0 is returned.
 */
int verify_free_nodes_hdr(inet_prefix *to, struct free_nodes_hdr *fn_hdr)
{
	quadro_group qg_a, qg_b;
	inet_prefix ipstart;

	if(fn_hdr->max_levels > FAMILY_LVLS || !fn_hdr->level)
		return 1;
	
	if(fn_hdr->level >= fn_hdr->max_levels)
		return 1;

	/* If fn_hdr->ipstart != `to' there is an error */
	inet_setip(&ipstart, (u_int *)fn_hdr->ipstart, my_family);
	iptoquadg(ipstart, me.ext_map, &qg_a, QUADG_GID);
	iptoquadg(*to, me.ext_map, &qg_b, QUADG_GID);
	if(quadg_gids_cmp(qg_a, qg_b, fn_hdr->level))
		return 1;

	if(fn_hdr->nodes <= 0 || fn_hdr->nodes == (MAXGROUPNODE-1))
		return 1;

	return 0;
}

/*\
 *   *  *  put/get free_nodes  *  *
\*/

/* 
 * get_free_nodes
 *
 * It send the GET_FREE_NODES request, used to retrieve the free_nodes pkt 
 * (see hook.h), to rnode `dst_rnode'.
 * `fn_hdr' is the header of the received free_nodes packet.
 * `nodes' must be an u_char array with at least MAXGROUPNODES members. All the
 * members that go from `free_nodes[0]' to `free_nodes[fn_hdr.nodes]' will be
 * filled with the gids of the received free nodes.
 * -1 is returned if `to' said its quadro_group is full or if a generic error
 * occurred. In this case it is advised to ask to get the free_nodes list from
 * another rnode.
 * If -2 is returned, the whole Netsukuku net is full, so desist to retry, or
 * drop down your neighbors.
 */
int get_free_nodes(map_node *dst_rnode, 
		   struct free_nodes_hdr *fn_hdr, u_char *nodes)
{
	PACKET pkt, rpkt;
	ssize_t err;
	int ret=0, e, i;
	char *buf=0;
	
	setzero(&pkt, sizeof(PACKET));
	setzero(&rpkt, sizeof(PACKET));
	
	hook_fill_rq(dst_rnode, &pkt, GET_FREE_NODES) < 0 && _return (-1);
	pkt_addtimeout(&pkt, HOOK_RQ_TIMEOUT, 1, 0);
	
	err=rnl_send_rq(dst_rnode, &pkt, 0, GET_FREE_NODES, 0, PUT_FREE_NODES,
			1, &rpkt);
	if(err < 0) {
		if(rpkt.hdr.sz && (u_char)(*rpkt.msg) == E_NTK_FULL)
			ERROR_FINISH(ret, -2, finish);
		ERROR_FINISH(ret, -1, finish);
	}

	ints_network_to_host(rpkt.msg, free_nodes_hdr_iinfo);
	memcpy(fn_hdr, rpkt.msg, sizeof(struct free_nodes_hdr));

	if(verify_free_nodes_hdr(&pkt.to, fn_hdr)) {
		error("Malformed PUT_FREE_NODES request hdr from %s", 
				inet_to_str(pkt.to));
		ERROR_FINISH(ret, -1, finish);
	}
	
	fn_hdr->nodes++;
	
	buf=rpkt.msg+sizeof(struct free_nodes_hdr);

	for(i=0, e=0; i<MAXGROUPNODE; i++) {
		if(TEST_BIT(buf, i)) {
			nodes[e]=i;
			e++;
		}
	}

	debug(DBG_NORMAL, "Received %d free %s", fn_hdr->nodes, 
			fn_hdr->level == 1 ? "nodes" : "gnodes");
finish:
	pkt_free(&pkt, 0);
	pkt_free(&rpkt,0);
	return ret;
}

/* 
 * put_free_nodes: It sends a free_nodes pkt to rq_pkt.from. To see what's a
 * free_nodes pkt go in hook.h.
 */
int put_free_nodes(PACKET rq_pkt)
{	
	struct fn_pkt {
		struct free_nodes_hdr fn_hdr;
		u_char free_nodes[MAXGROUPNODE>>3];
	}_PACKED_ fn_pkt;

	PACKET pkt;
	int ret=0, i, e=0, links;
	ssize_t err, pkt_sz;
	u_char level, err_reply;
	const char *ntop;
	char *p=0; 
	
	ntop=inet_to_str(rq_pkt.from);
	
	setzero(&pkt, sizeof(PACKET));
	pkt_addto(&pkt, &rq_pkt.from);
	pkt_addport(&pkt, ntk_tcp_port);
	pkt_addsk(&pkt, my_family, rq_pkt.sk, rq_pkt.sk_type);
	pkt_add_dev(&pkt, rq_pkt.dev, 1);
	pkt_addcompress(&pkt);

	/* We search in each level a gnode which is not full. */
	for(level=1, e=0; level < me.cur_quadg.levels; level++) {
		if(!(me.cur_quadg.gnode[_EL(level)]->flags & GMAP_FULL)) {
			e=1;
			break;
		}
	}
	if(!e) {
		if(me.ext_map[_EL(me.cur_quadg.levels)][0].flags & GMAP_FULL)
			/* <<Netsukuku is completely full, sry>> */
			err_reply=E_NTK_FULL;
		else
			/* Our Quadro Group is full, bye */
			err_reply=E_QGROUP_FULL;
			
		pkt_fill_hdr(&pkt.hdr, HOOK_PKT, rq_pkt.hdr.id, PUT_FREE_NODES, 0);
		err=pkt_err(pkt, err_reply, 1);
		goto finish;
	}

	/* Ok, we've found one, so let's roll the pkt */
	setzero(&fn_pkt, sizeof(fn_pkt));

	/*
	 * Fill the reply packet
	 */
	fn_pkt.fn_hdr.max_levels=me.cur_quadg.levels;
	inet_copy_ipdata(fn_pkt.fn_hdr.ipstart, &me.cur_quadg.ipstart[level]);
	fn_pkt.fn_hdr.level=level;
	fn_pkt.fn_hdr.gid=me.cur_quadg.gid[level];

	/*
	 * Update the hook_join_rate and stores give the stores in
	 * `fn_pkt.fn_hdr.join_rate' the join_rate destined to `rq_pkt.from'
	 */
	links=me.cur_node->links-rnodes_rehooked-1;
	if(hook_join_rate >= links && links > 0)
		fn_pkt.fn_hdr.join_rate = hook_join_rate/links;
	else if(hook_join_rate > 0)
		fn_pkt.fn_hdr.join_rate = 1;
	else
		fn_pkt.fn_hdr.join_rate = 0;
	hook_join_rate -= fn_pkt.fn_hdr.join_rate;
	hook_join_rate = hook_join_rate < 0 ? 0 : hook_join_rate;
	rnodes_rehooked++;
	
	/*
	 * Creates the list of the free nodes, which belongs to the gnode. If 
	 * the gnode level is 1 it scans the int_map to find all the MAP_VOID 
	 * nodes, otherwise it scans the gnode map at level-1 searching for 
	 * GMAP_VOID gnodes.
	 */
	e=0;
	if(level == 1) {
		for(i=0; i<MAXGROUPNODE; i++)
			if(me.int_map[i].flags & MAP_VOID) {
				SET_BIT(fn_pkt.free_nodes, i);
				e++;
			}
	} else {
		for(i=0; i<MAXGROUPNODE; i++)
			if(me.ext_map[_EL(level-1)][i].flags & GMAP_VOID ||
					me.ext_map[_EL(level-1)][i].g.flags & MAP_VOID) {
				SET_BIT(fn_pkt.free_nodes, i);
				e++;
			}
	}
	fn_pkt.fn_hdr.nodes=(u_char)e-1;
	
	/* Go pkt, go! Follow your instinct */
	pkt_sz=FREE_NODES_SZ((fn_pkt.fn_hdr.nodes+1));
	pkt_fill_hdr(&pkt.hdr, HOOK_PKT, rq_pkt.hdr.id, PUT_FREE_NODES, pkt_sz);
	pkt.msg=xzalloc(pkt_sz);
	
	p=pkt.msg;
	memcpy(p, &fn_pkt, sizeof(fn_pkt));
	ints_host_to_network(p, free_nodes_hdr_iinfo);
	
	debug(DBG_INSANE, "Reply %s to %s", re_to_str(pkt.hdr.op), ntop);
	err=pkt_send(&pkt);
	
finish:	
	if(err < 0) {
		error("put_free_nodes(): Cannot send the PUT_FREE_NODES reply to %s.", ntop);
		ret=-1;
	}
	pkt_free(&pkt, 0);
	return ret;
}


/*\
 *   *  * put/get qspn_round *  *
\*/

/* 
 * get_qspn_round: It send the GET_QSPN_ROUND request, used to retrieve the 
 * qspn ids and and qspn times. (see hook.h).
 */
int get_qspn_round(map_node *dst_rnode, struct timeval to_rtt, 
		struct timeval *qtime, int *qspn_id, int *qspn_gcount)
{
	PACKET pkt, rpkt;
	struct timeval cur_t;
	ssize_t err;
	int ret=0, level;
	char *buf=0;
	u_char max_levels;
	int_info qr_pkt_iinfo;
	
	setzero(&pkt, sizeof(PACKET));
	setzero(&rpkt, sizeof(PACKET));
	
	hook_fill_rq(dst_rnode, &pkt, GET_QSPN_ROUND) < 0 && _return (-1);
	pkt_addtimeout(&pkt, HOOK_RQ_TIMEOUT, 1, 0);

	err=rnl_send_rq(dst_rnode, &pkt, 0, GET_QSPN_ROUND, 0, PUT_QSPN_ROUND, 
			1, &rpkt);
	if(err < 0)
		ERROR_FINISH(ret, -1, finish);

	buf=rpkt.msg;
	bufget(&max_levels, sizeof(u_char));
	if(QSPN_ROUND_PKT_SZ(max_levels) != rpkt.hdr.sz ||
			max_levels > FAMILY_LVLS) {
		error("Malformed PUT_QSPN_ROUND request hdr from %s",
				inet_to_str(pkt.to));
		ERROR_FINISH(ret, -1, finish);
	}
	
	/* Convert the pkt from network to host order */
	int_info_copy(&qr_pkt_iinfo, &qspn_round_pkt_iinfo);
	qr_pkt_iinfo.int_offset[1] = me.cur_quadg.levels*sizeof(int)+sizeof(char);
	qr_pkt_iinfo.int_offset[2] = qr_pkt_iinfo.int_offset[1] + sizeof(struct timeval)*max_levels;
	qr_pkt_iinfo.int_nmemb[0]  = max_levels;
	qr_pkt_iinfo.int_nmemb[1]  = max_levels*2;
	ints_network_to_host(rpkt.msg, qr_pkt_iinfo);

	/* Restoring the qspn_id and the qspn_round time */
	bufget(qspn_id, max_levels*sizeof(int));
	bufget(qtime, max_levels*sizeof(struct timeval));
	
	gettimeofday(&cur_t, 0);
	for(level=0; level < max_levels; level++) {
		timeradd(&to_rtt, &qtime[level], &qtime[level]);
		timersub(&cur_t, &qtime[level], &qtime[level]);
	}

	/* Extracting the qspn_gnode_count */
	bufget(qspn_gcount, sizeof(u_int)*GCOUNT_LEVELS);

finish:
	pkt_free(&pkt, 0);
	pkt_free(&rpkt,0);
	return ret;
}

/* 
 * put_qspn_round
 *
 * It sends the current qspn times and ids to rq_pkt.from. 
 */
int put_qspn_round(PACKET rq_pkt)
{	
        /*
	 * We cannot use this elegant struct because gcc is bugged, -_.
	 * http://gcc.gnu.org/bugzilla/show_bug.cgi?id=27945
	 *
	 * We have to wait some years, then when gcc4 will be obsolete (and
	 * the bug will be solved), we'll activate it.
	 *
         * struct qspn_round_pkt {
         *         u_char          max_levels;
         *         int32_t         qspn_id[me.cur_quadg.levels];
         *         struct timeval _PACKED_ qtime[me.cur_quadg.levels];
         *         u_int           gcount[GCOUNT_LEVELS];
         * }_PACKED_ qr_pkt;
         */
	char qr_pkt[QSPN_ROUND_PKT_SZ(me.cur_quadg.levels)];
	int_info qr_pkt_iinfo;

	PACKET pkt;
	struct timeval cur_t, *tptr;
	int ret=0;
	ssize_t err, pkt_sz;
	u_char level;
	const char *ntop;
	u_char max_levels;
	char *buf=0;

	ntop=inet_to_str(rq_pkt.from);
	
	setzero(&pkt, sizeof(PACKET));
	pkt_addto(&pkt, &rq_pkt.from);
	pkt_addport(&pkt, ntk_tcp_port);
	pkt_addsk(&pkt, my_family, rq_pkt.sk, rq_pkt.sk_type);
	pkt_add_dev(&pkt, rq_pkt.dev, 1);
	pkt_addcompress(&pkt);

	/* We fill the qspn_id and the qspn round time */
	buf=qr_pkt;
	max_levels=me.cur_quadg.levels;
	bufput(&max_levels, sizeof(u_char));
	bufput(me.cur_qspn_id, sizeof(int)*max_levels);
	
	gettimeofday(&cur_t, 0);
	for(level=0; level < max_levels; level++) {
		update_qspn_time(level, 0);
		tptr=(struct timeval *)buf;
		timersub(&cur_t, &me.cur_qspn_time[level], tptr);
		buf+=sizeof(struct timeval);
	}

	/* copy in the pkt the qspn_gnode_count */
	bufput(qspn_gnode_count, sizeof(qspn_gnode_count));

	/* Convert the pkt from host to network order */
	int_info_copy(&qr_pkt_iinfo, &qspn_round_pkt_iinfo);
	qr_pkt_iinfo.int_offset[1] = me.cur_quadg.levels*sizeof(int)+sizeof(char);
	qr_pkt_iinfo.int_offset[2] = qr_pkt_iinfo.int_offset[1] + 
						sizeof(struct timeval)*max_levels;
	qr_pkt_iinfo.int_nmemb[0]  = me.cur_quadg.levels;
	qr_pkt_iinfo.int_nmemb[1]  = me.cur_quadg.levels*2;
	ints_host_to_network(qr_pkt, qr_pkt_iinfo);
	
	/* fill the pkt header */
	pkt_sz=sizeof(qr_pkt);
	pkt_fill_hdr(&pkt.hdr, HOOK_PKT, rq_pkt.hdr.id, PUT_QSPN_ROUND, pkt_sz);
	pkt.msg=xzalloc(pkt_sz);
	
	/* Go pkt, go! Follow your instinct */
	debug(DBG_INSANE, "Reply %s to %s", re_to_str(pkt.hdr.op), ntop);
	memcpy(pkt.msg, &qr_pkt, sizeof(qr_pkt));
	err=pkt_send(&pkt);
	
	if(err < 0) {
		error("put_qspn_round(): Cannot send the PUT_QSPN_ROUND reply to %s.", ntop);
		ret=-1;
	}
	pkt_free(&pkt, 0);
	return ret;
}


/*\ 
 *   *  *  put/get ext_map  *  *
\*/

int put_ext_map(PACKET rq_pkt)
{
	PACKET pkt;
	const char *ntop; 
	int ret=0;
	ssize_t err;
	size_t pkt_sz=0;
	
	ntop=inet_to_str(rq_pkt.from);
	
	setzero(&pkt, sizeof(PACKET));
	pkt_addsk(&pkt, my_family, rq_pkt.sk, rq_pkt.sk_type);
	pkt_addcompress(&pkt);

	pkt.msg=pack_extmap(me.ext_map, MAXGROUPNODE, &me.cur_quadg, &pkt_sz);
	pkt.hdr.sz=pkt_sz;
	debug(DBG_INSANE, "Reply %s to %s", re_to_str(PUT_EXT_MAP), ntop);
	err=send_rq(&pkt, 0, PUT_EXT_MAP, rq_pkt.hdr.id, 0, 0, 0);
	if(err < 0) {
		error("put_ext_maps(): Cannot send the PUT_EXT_MAP reply to %s.", ntop);
		ERROR_FINISH(ret, -1, finish);
	}

finish:
	pkt_free(&pkt, 0);
	return ret;
}

/* 
 * get_ext_map: It sends the GET_EXT_MAP request to retrieve the
 * dst_node's ext_map.
 */
map_gnode **get_ext_map(map_node *dst_rnode, quadro_group *new_quadg)
{
	PACKET pkt, rpkt;
	char *pack;
	int err;
	map_gnode **ext_map=0, **ret=0;

	setzero(&pkt, sizeof(PACKET));
	setzero(&rpkt, sizeof(PACKET));

	hook_fill_rq(dst_rnode, &pkt, GET_EXT_MAP) < 0 && _return (0);
	pkt_addtimeout(&pkt, HOOK_RQ_TIMEOUT, 1, 0);

	err=rnl_send_rq(dst_rnode, &pkt, 0, GET_EXT_MAP, 0, PUT_EXT_MAP, 1,
			&rpkt);
	if(err < 0) {
		ret=0;
		goto finish;
	}
	
	pack=rpkt.msg;
	ret=ext_map=unpack_extmap(pack, new_quadg);
	if(!ext_map)
		error("get_ext_map: Malformed ext_map. Cannot unpack the ext_map.");
finish:
	pkt_free(&pkt, 0);
	pkt_free(&rpkt, 0);
	return ret;
}

/*\
 *   *  *  put/get int_map  *  *
\*/

int put_int_map(PACKET rq_pkt)
{
	PACKET pkt;
	map_node *map=me.int_map;
	const char *ntop; 
	int ret=0;
	ssize_t err;
	size_t pkt_sz=0;
	
	ntop=inet_to_str(rq_pkt.from);
	
	setzero(&pkt, sizeof(PACKET));
	pkt_addto(&pkt, &rq_pkt.from);
	pkt_addsk(&pkt, my_family, rq_pkt.sk, rq_pkt.sk_type);
	pkt_add_dev(&pkt, rq_pkt.dev, 1);
	pkt_addcompress(&pkt);

	pkt.msg=pack_map(map, 0, MAXGROUPNODE, me.cur_node, &pkt_sz);
	pkt.hdr.sz=pkt_sz;
	debug(DBG_INSANE, "Reply %s to %s", re_to_str(PUT_INT_MAP), ntop);
	err=send_rq(&pkt, 0, PUT_INT_MAP, rq_pkt.hdr.id, 0, 0, 0);
	if(err < 0) {
		error("put_int_map(): Cannot send the PUT_INT_MAP reply to %s.", ntop);
		ERROR_FINISH(ret, -1, finish);
	}
finish:
	pkt_free(&pkt, 0);
	return ret;
}

/* 
 * get_int_map: It sends the GET_INT_MAP request to retrieve the 
 * dst_node's int_map. 
 */
map_node *get_int_map(map_node *dst_rnode, map_node **new_root)
{
	PACKET pkt, rpkt;
	map_node *int_map, *ret=0;
	int err;
	char *pack;
	
	setzero(&pkt, sizeof(PACKET));
	setzero(&rpkt, sizeof(PACKET));
	
	hook_fill_rq(dst_rnode, &pkt, GET_INT_MAP) < 0 && _return (0);
	pkt_addtimeout(&pkt, HOOK_RQ_TIMEOUT, 1, 0);

	err=rnl_send_rq(dst_rnode, &pkt, 0, GET_INT_MAP, 0, PUT_INT_MAP, 1, 
			&rpkt);
	if(err < 0) {
		ret=0;
		goto finish;
	}
	
	pack=rpkt.msg;
	ret=int_map=unpack_map(pack, 0, new_root, MAXGROUPNODE, 
			MAXRNODEBLOCK_PACK_SZ);
	if(!int_map)
		error("get_int_map(): Malformed int_map. Cannot load it");
	
	/*Finished, yeah*/
finish:
	pkt_free(&pkt, 0);
	pkt_free(&rpkt, 0);
	return ret;
}

/*\
 *   *  *  put/get bnode_map  *  *
\*/

int put_bnode_map(PACKET rq_pkt)
{
	PACKET pkt;
	map_bnode **bmaps=me.bnode_map;
	const char *ntop; 
	int ret=0;
	ssize_t err;
	size_t pack_sz=0;
	
	ntop=inet_to_str(rq_pkt.from);

	setzero(&pkt, sizeof(PACKET));
	pkt_addto(&pkt, &rq_pkt.from);
	pkt_addsk(&pkt, my_family, rq_pkt.sk, rq_pkt.sk_type);
	pkt_add_dev(&pkt, rq_pkt.dev, 1);
	pkt_addcompress(&pkt);

	pkt.msg=pack_all_bmaps(bmaps, me.bmap_nodes, me.ext_map, me.cur_quadg, &pack_sz);
	pkt.hdr.sz=pack_sz;

	debug(DBG_INSANE, "Reply %s to %s", re_to_str(PUT_BNODE_MAP), ntop);
	err=send_rq(&pkt, 0, PUT_BNODE_MAP, rq_pkt.hdr.id, 0, 0, 0);
	if(err < 0) {
		error("put_bnode_maps(): Cannot send the PUT_BNODE_MAP reply to %s.", ntop);
		ERROR_FINISH(ret, -1, finish);
	}

finish:
	pkt_free(&pkt, 0);
	return ret;
}

/* 
 * get_bnode_map: It sends the GET_BNODE_MAP request to retrieve the 
 * dst_node's bnode_map. 
 */
map_bnode **get_bnode_map(map_node *dst_rnode, u_int **bmap_nodes)
{
	PACKET pkt, rpkt;
	int err;
	map_bnode **bnode_map, **ret=0;
	char *pack;
	
	setzero(&pkt, sizeof(PACKET));
	setzero(&rpkt, sizeof(PACKET));
	
	hook_fill_rq(dst_rnode, &pkt, GET_BNODE_MAP) < 0 && _return (0);
	pkt_addtimeout(&pkt, HOOK_RQ_TIMEOUT, 1, 0);

	err=rnl_send_rq(dst_rnode, &pkt, 0, GET_BNODE_MAP, 0, PUT_BNODE_MAP, 
			1, &rpkt);
	if(err < 0) {
		ret=0;
		goto finish;
	}
	
	/* Extracting the map... */
	pack=rpkt.msg;
	ret=bnode_map=unpack_all_bmaps(pack, FAMILY_LVLS, me.ext_map, bmap_nodes, 
			MAXGROUPNODE, MAXBNODE_RNODEBLOCK);
	if(!bnode_map)
		error("get_bnode_map(): Malformed bnode_map. Cannot load it");

finish:
	pkt_free(&pkt, 0);
	pkt_free(&rpkt, 0);
	return ret;
}


/*\
 *   *  *  put/get internet gateways list  *  *
\*/

int put_internet_gws(PACKET rq_pkt)
{
	PACKET pkt;
	const char *ntop; 
	int ret=0;
	ssize_t err;
	size_t pack_sz=0;
	
	ntop=inet_to_str(rq_pkt.from);

	setzero(&pkt, sizeof(PACKET));
	pkt_addto(&pkt, &rq_pkt.from);
	pkt_addsk(&pkt, my_family, rq_pkt.sk, rq_pkt.sk_type);
	pkt_add_dev(&pkt, rq_pkt.dev, 1);
	pkt_addcompress(&pkt);

	pkt.msg=pack_igws(me.igws, me.igws_counter, me.cur_quadg.levels, 
			(int*)&pack_sz);
	pkt.hdr.sz=pack_sz;

	debug(DBG_INSANE, "Reply %s to %s", re_to_str(PUT_INTERNET_GWS), ntop);
	err=send_rq(&pkt, 0, PUT_INTERNET_GWS, rq_pkt.hdr.id, 0, 0, 0);
	if(err < 0) {
		error("put_internet_gws(): Cannot send the PUT_INTERNET_GWS "
				"reply to %s.", ntop);
		ERROR_FINISH(ret, -1, finish);
	}

finish:
	pkt_free(&pkt, 0);
	return ret;
}

/* 
 * get_internet_gws: It sends the GET_INTERNET_GWS request to retrieve the 
 * Internet Gateways list from `to'.
 */
inet_gw **get_internet_gws(map_node *dst_rnode, int **igws_counter)
{
	PACKET pkt, rpkt;
	int err, ret=0;
	inet_gw **igws=0;
	char *pack;
	
	setzero(&pkt, sizeof(PACKET));
	setzero(&rpkt, sizeof(PACKET));

	hook_fill_rq(dst_rnode, &pkt, GET_INTERNET_GWS) < 0 && _return (0);
	pkt_addtimeout(&pkt, HOOK_RQ_TIMEOUT, 1, 0);

	err=rnl_send_rq(dst_rnode, &pkt, 0, GET_INTERNET_GWS, 0, 
			PUT_INTERNET_GWS, 1, &rpkt);
	if(err < 0)
		ERROR_FINISH(ret, 0, finish);
	
	/* Extracting the list... */
	pack=rpkt.msg;
	ret=unpack_igws(pack, rpkt.hdr.sz, me.int_map, me.ext_map, FAMILY_LVLS,
			&igws, igws_counter);
	if(ret < 0) {
		error("get_internet_gws(): Malformed internet_gws. Cannot load it");
		igws=0;
	}

finish:
	pkt_free(&pkt, 0);
	pkt_free(&rpkt, 0);
	return igws;
}


/* 
 * hook_set_all_ips
 *
 * Sets the same `ip' to all the devices.
 */
void hook_set_all_ips(inet_prefix ip, interface *ifs, int ifs_n)
{
	const char *ntop;
	ntop=inet_to_str(ip);
	
	loginfo("Setting the %s ip to all the interfaces", ntop);

	if(my_family == AF_INET) {
		/* Down & Up: reset the configurations of all the interfaces */
		set_all_ifs(ifs, ifs_n, set_dev_down);
		set_all_ifs(ifs, ifs_n, set_dev_up);
	} else {
		ip_addr_flush_all_ifs(ifs, ifs_n, my_family, RT_SCOPE_UNIVERSE);
		ip_addr_flush_all_ifs(ifs, ifs_n, my_family, RT_SCOPE_SITE);
	}

	if(set_all_dev_ip(ip, ifs, ifs_n) < 0)
		fatal("Cannot set the %s ip to all the interfaces", ntop);
	if(restricted_mode && (server_opt.use_shared_inet || 
				server_opt.share_internet)) {
		set_dev_down(DEFAULT_TUNL_IF);
		set_dev_up(DEFAULT_TUNL_IF);
		if(set_dev_ip(ip, DEFAULT_TUNL_IF) < 0)
			fatal("Cannot assign an IP to the default tunnel");
	}
}

/*
 * create_gnodes
 *
 * This function is used to create a new gnode (or more) when we are the first
 * node in the area or when all the other gnodes are full. 
 * Our ip will be set to `ip'. If `ip' is NULL, a random ip is chosen. 
 * create_gnodes() sets also all the vital variables for the new gnode/gnodes
 * like me.cur_quadg, me.cur_ip, etc...
 * `final_level' is the highest level where we create the gnode, all the other
 * gnodes we create are in the sub-levels of `final_level'. 
 */
int create_gnodes(inet_prefix *ip, int final_level)
{
	int i;

	if(!ip) {
		random_ip(0, 0, 0, FAMILY_LVLS, me.ext_map, 0, &me.cur_ip, 
				my_family);
	} else
		inet_copy(&me.cur_ip, ip);

	if(restricted_mode)
		inet_setip_localaddr(&me.cur_ip, my_family, restricted_class);

	if(!final_level)
		final_level=FAMILY_LVLS;
	
	/* 
	 * We remove all the traces of the old gnodes in the ext_map to add the
	 * new ones.
	 */
	if(!(me.cur_node->flags & MAP_HNODE))
		for(i=1; i<final_level; i++) {
			me.cur_quadg.gnode[_EL(i)]->flags &= ~GMAP_ME;
			me.cur_quadg.gnode[_EL(i)]->g.flags &= ~MAP_ME & ~MAP_GNODE;
		}

	/* Now, we update the ext_map with the new gnodes */
	me.cur_quadg.levels=FAMILY_LVLS;
	reset_extmap(me.ext_map, me.cur_quadg.levels, 0);
	iptoquadg(me.cur_ip, me.ext_map, &me.cur_quadg, QUADG_GID|QUADG_GNODE|QUADG_IPSTART);

	/* Set the new flags */
	for(i=1; i<final_level; i++) {
		me.cur_quadg.gnode[_EL(i)]->flags &= ~GMAP_VOID;
		me.cur_quadg.gnode[_EL(i)]->flags |=  GMAP_ME;
		me.cur_quadg.gnode[_EL(i)]->g.flags&=~ MAP_VOID;
		me.cur_quadg.gnode[_EL(i)]->g.flags |= MAP_ME | MAP_GNODE;

		/* Increment the gnode seeds counter */
		gnode_inc_seeds(&me.cur_quadg, i);
	}

	/* Reset the `qspn_gnode_count' counter */
	qspn_reset_gcount(qspn_gnode_count, final_level, 1);

	/* Tidying up the internal map */
	if(free_the_tmp_cur_node) {
		xfree(me.cur_node);
		free_the_tmp_cur_node=0;
	}
	reset_int_map(me.int_map, 0);
	me.cur_node = &me.int_map[me.cur_quadg.gid[0]];
	me.cur_node->flags &= ~MAP_VOID;
	me.cur_node->flags |= MAP_ME;

	return 0;
}

/*
 * create_new_qgroup
 * 
 * this is just a wrapper to create_gnodes(). It creates completely
 * random gnodes in all the levels.
 */
void create_new_qgroup(int hook_level)
{
	const char *ntop;

	if(we_are_rehooking)
		create_gnodes(&rk_gnode_ip, hook_level+1);
	else
		create_gnodes(0, FAMILY_LVLS);
	ntop=inet_to_str(me.cur_ip);

	hook_set_all_ips(me.cur_ip, me.cur_ifs, me.cur_ifs_n);

	loginfo("Now we are in a brand new gnode. The ip %s is now"
			" used.", ntop);
}

/*
 * update_join_rate
 * 
 * it updates the `hook_join_rate' according to `gnode_count', which has the
 * gnode count of `hook_gnode' and to `fn_hdr', which is the free_nodes_hdr 
 * received from `hook_gnode'.
 * `old_gcount' is the gnode_count we had before the start of the rehook.
 * If a new_gnode has to be created 1 is returned, (and hook_join_rate will be
 * 0), otherwise 0 is the returned value.
 * If we aren't rehooking or if it isn't necessary to consider the join_rate,
 * -1 is returned.
 */
int update_join_rate(map_gnode *hook_gnode, int hook_level, 
		u_int *old_gcount, u_int *gnode_count, 
		struct free_nodes_hdr *fn_hdr)
{
	u_int free_nodes, total_bnodes;
	int new_gnode=0, i;

	if(!hook_level || !hook_gnode || !we_are_rehooking)
		return -1;

	/*
	 * `free_nodes' is the number of VOID nodes present at the
	 * `hook_level' in `hook_gnode', and it is the difference
	 * between the maximum number of nodes in that level and the
	 * actual number of nodes in it (gnode_count).
	 */
	free_nodes = NODES_PER_LEVEL(hook_level) - gnode_count[_EL(hook_level)];

	if(old_gcount[_EL(hook_level)] <= free_nodes)
		return -1;
	
	debug(DBG_SOFT, "update_join_rate: free_nodes %d, fn_hdr->join_rate %d",
			free_nodes, fn_hdr->join_rate);

	/* There aren't free nodes in `hook_gnode', so skip this function */
	if(free_nodes <= 0) {
		new_gnode=1;
		goto finish;
	}
		
	if(map_find_bnode_rnode(me.bnode_map[hook_level-1], me.bmap_nodes[hook_level-1],
				hook_gnode) >= 0) {
		/* We border on `hook_gnode' so we initialize
		 * `hook_join_rate' for this new re-hook session,
		 * later we'll hook at `hook_gnode'. */

		hook_join_rate = free_nodes;

		for(i=hook_level-1; i >= 0; i--) {

			/* `total_bnodes' = how many bnodes border to
			 * `hook_gnode' in level `i'th */
			total_bnodes = map_count_bnode_rnode(me.bnode_map[i], me.bmap_nodes[i],
					hook_gnode);

			total_bnodes = total_bnodes ? total_bnodes : 1;
			hook_join_rate /= total_bnodes;
		}
		new_gnode=0;
	} else if(fn_hdr->join_rate) {
		/* The join_rate we got from our rnode is > 0, so
		 * we hook at `hook_gnode'. */
		hook_join_rate = fn_hdr->join_rate;
		new_gnode=0;
	} else
		new_gnode=1;

	if(!new_gnode) {
		/* Don't count us in the join_rate, 'cause we are rehooking */
		hook_join_rate--;
		hook_join_rate = hook_join_rate < 0 ? 0 : hook_join_rate;
	}


	debug(DBG_NOISE, "update_join_rate: new join_rate %u, new_gnode %d",
			hook_join_rate, new_gnode);

finish:
	return new_gnode;
}

/* 
 * hook_init
 *
 * inits the hook.c code. Call this function only once, at the start of the
 * daemon.
 */
int hook_init(void)
{
	/* register the hook's ops in the pkt_op_table */
	add_pkt_op(GET_FREE_NODES, SKT_TCP, ntk_tcp_port, put_free_nodes);
	add_pkt_op(PUT_FREE_NODES, SKT_TCP, ntk_tcp_port, 0);
	add_pkt_op(GET_QSPN_ROUND, SKT_TCP, ntk_tcp_port, put_qspn_round);
	add_pkt_op(PUT_QSPN_ROUND, SKT_TCP, ntk_tcp_port, 0);
	add_pkt_op(GET_INT_MAP, SKT_TCP, ntk_tcp_port, put_int_map);
	add_pkt_op(PUT_INT_MAP, SKT_TCP, ntk_tcp_port, 0);
	add_pkt_op(GET_EXT_MAP, SKT_TCP, ntk_tcp_port, put_ext_map);
	add_pkt_op(PUT_EXT_MAP, SKT_TCP, ntk_tcp_port, 0);
	add_pkt_op(GET_BNODE_MAP, SKT_TCP, ntk_tcp_port, put_bnode_map);
	add_pkt_op(PUT_BNODE_MAP, SKT_TCP, ntk_tcp_port, 0);
	add_pkt_op(GET_INTERNET_GWS, SKT_TCP, ntk_tcp_port, put_internet_gws);
	add_pkt_op(PUT_INTERNET_GWS, SKT_TCP, ntk_tcp_port, 0);

	total_hooks=0;
	we_are_rehooking=0;
	free_the_tmp_cur_node=0;

	hook_reset();

	debug(DBG_NORMAL, "Activating ip_forward and disabling rp_filter");
	route_ip_forward(my_family, 1);
	route_rp_filter_all_dev(my_family, me.cur_ifs, me.cur_ifs_n, 0);
	if(restricted_mode && (server_opt.share_internet || 
				server_opt.share_internet))
		route_rp_filter(my_family, DEFAULT_TUNL_IF, 0);

	
	return 0;
}

/*
 * hook_reset: resets all the variables needed to hook. This function is
 * called at the beginning of netsukuku_hook().
 */
void hook_reset(void)
{
	u_int idata[MAX_IP_INT];

	/* We use a fake root_node for a while */
	if(free_the_tmp_cur_node)
		xfree(me.cur_node);
	free_the_tmp_cur_node=1;
	me.cur_node=xzalloc(sizeof(map_node));
	me.cur_node->flags|=MAP_HNODE;

	rnodes_rehooked=hook_join_rate=0;
	
	/*
	 * Do not reply to any request while we are hooking, except the radar
	 * ECHO_ME, ECHO_REPLY, and all the replies.
	 */
	op_filter_reset(OP_FILTER_DROP);
	op_filter_reset_re(OP_FILTER_ALLOW);
	op_filter_clr(ECHO_ME);
	op_filter_clr(ECHO_REPLY);
	
	/*
	 * We set the dev ip to HOOKING_IP+random_number to begin our 
	 * transaction. 
	 */
	setzero(idata, MAX_IP_SZ);
	if(my_family==AF_INET) {
		idata[0]=restricted_class == RESTRICTED_10 ? HOOKING_IP_10 : HOOKING_IP_172;
	} else
		idata[0]=HOOKING_IPV6;
	
	if(my_family == AF_INET6)
		idata[0]+=rand_range(0, MAXGROUPNODE-2);
	else
		idata[0]+=rand_range(0, MAXGROUPNODE-2);

	inet_setip_raw(&me.cur_ip, idata, my_family);
	iptoquadg(me.cur_ip, me.ext_map, &me.cur_quadg,	
			QUADG_GID|QUADG_GNODE|QUADG_IPSTART);
	
	hook_set_all_ips(me.cur_ip, me.cur_ifs, me.cur_ifs_n);
}


/*
 * hook_first_radar_scan: launches the first scan to know what rnodes we have
 * around us.
 * If a new gnode has to be created, 1 is returned.
 */
int hook_first_radar_scan(map_gnode *hook_gnode, int hook_level, quadro_group *old_quadg)
{
	int total_hooking_nodes, i; 
	
	/*
	 * If we are rehooking to `hook_gnode' tell the radar to ignore all
	 * the other rnodes, which don't belong to it.
	 */
	if(hook_gnode && we_are_rehooking) {
		int gid[NMEMB(old_quadg->gid)];

		memcpy(gid, old_quadg->gid, sizeof(old_quadg->gid));
		gid[hook_level]=pos_from_gnode(hook_gnode, me.ext_map[_EL(hook_level)]);
		new_rnode_allowed(&alwd_rnodes, &alwd_rnodes_counter, 
				gid, hook_level, FAMILY_LVLS);
	}

	/*
	 * If we are in restricted mode, ignore the restricted nodes which
	 * belong to our opposite restricted class. So, if we are 10.0.0.1
	 * ignore 172.x.x.x, and viceversa. This happens only in ipv4.
	 */
	if(restricted_mode && my_family == AF_INET) {
		int gid[IPV4_LEVELS]={0,0,0,0};
		
		if(restricted_class == RESTRICTED_10)
			gid[3]=10;
		else
			gid[3]=172;
		new_rnode_allowed(&alwd_rnodes, &alwd_rnodes_counter,
				gid, 3, FAMILY_LVLS);
	}

	/* 
	 * We do our first scans to know what we've around us. The rnodes are 
	 * kept in me.cur_node->r_nodes.
	 * The fastest one is in me.cur_node->r_nodes[0].
	 *
	 * If after MAX_FIRST_RADAR_SCANS# tries we haven't found any rnodes
	 * we start as a new gnode.
	 */
	
	for(i=0; i<MAX_FIRST_RADAR_SCANS; i++) {
		me.cur_node->flags|=MAP_HNODE;

		loginfo("Launching radar_scan %d of %d", i+1, MAX_FIRST_RADAR_SCANS);
		
		if(radar_scan(0))
			fatal("%s:%d: Scan of the area failed. Cannot continue.", 
					ERROR_POS);
		total_hooking_nodes=count_hooking_nodes();

		if(!me.cur_node->links || 
				( me.cur_node->links==total_hooking_nodes 
				  && !hook_retry )) {
			/* 
			 * If we have 0 nodes around us, we are alone, so we create a
			 * new gnode.
			 * If all the nodes around us are hooking and we started hooking
			 * before them, we create the new gnode.
			 */
			if(!me.cur_node->links) {
				/* 
				 * We haven't found any rnodes. Let's retry the
				 * radar_scan if i+1<MAX_FIRST_RADAR_SCANS
				 */
				if(i+1 < MAX_FIRST_RADAR_SCANS)
					goto hook_retry_scan;

				loginfo("No nodes found! This is a black zone. "
						"Creating a new_gnode.");
			} else
				loginfo("There are %d nodes around, which are hooking"
						" like us, but we came first so we have "
						"to create the new gnode", 
						total_hooking_nodes);
			create_new_qgroup(hook_level);

			return 1;
		} else if(hook_retry) {
			/* 
			 * There are only hooking nodes, but we started the hooking
			 * after them, so we wait until some of them create the new
			 * gnode.
			 */
			loginfo("I've seen %d hooking nodes around us, and one of them "
					"is becoming a new gnode.\n"
					"  We wait, then we'll restart the hook.", 
					total_hooking_nodes);

			usleep(rand_range(0, 1024)); /* ++entropy, thx to katolaz :) */
			sleep(MAX_RADAR_WAIT);
			i--;
		} else 
			break;

hook_retry_scan:
		reset_radar();
		rnode_destroy(me.cur_node);
		setzero(me.cur_node, sizeof(map_node));
		me.cur_node->flags|=MAP_HNODE;
		qspn_b_del_all_dead_rnodes();
	}

	loginfo("We have %d nodes around us. (%d are hooking)", 
			me.cur_node->links, total_hooking_nodes);

	return 0;
}


/*
 * hook_get_free_nodes
 * 
 * gets the free_nodes list and the qson_round info from our nearest rnode.
 * In `fn_hdr', `fnodes', `gnode_ipstart' and `new_gcount' there will be stored the relative
 * value.
 * If a new gnode has to be created 1 is returned.
 */
int hook_get_free_nodes(int hook_level, struct free_nodes_hdr *fn_hdr, 
		u_char *fnodes, inet_prefix *gnode_ipstart, u_int *new_gcount,
		struct rnode_list **ret_rnl)
{
	struct radar_queue *rq=0;
	struct rnode_list *rnl=rlist;
	int e=0, err;
	
	/* 
	 * Now we choose the nearest rnode we found and we send it the 
	 * GET_FREE_NODES request.
	 */
	list_for(rnl) {
		if(rnl->node->flags & MAP_HNODE)
			continue;

		err=get_free_nodes(rnl->node, fn_hdr, fnodes);
		if(err == -2)
			fatal("Netsukuku is full! Bring down some nodes and retry");
		else if(err == -1)
			continue;

		/* Extract the ipstart of the gnode */
		inet_setip(gnode_ipstart, (u_int *)fn_hdr->ipstart, my_family);

		/* Get the qspn round info */
		rq=find_node_radar_q(rnl->node);
		if(!get_qspn_round(rnl->node, rq->final_rtt, me.cur_qspn_time,
					me.cur_qspn_id,
					(int*)new_gcount)) {
			e=1;
			break;
		}
	}

	*ret_rnl=rnl;

	if(!e) {
		loginfo("It seems all the quadro_groups in this area are full "
				"or are not cooperating.\n  "
				"We are going to create a new gnode");
		
		create_new_qgroup(hook_level);
		return 1;
	}
	
	return 0;
}

/*
 * hook_choose_new_ip
 * 
 * after reading the received `fn_hdr', it decides our new IP and if we have to
 * create a new gnode it returns 1.
 */
int hook_choose_new_ip(map_gnode *hook_gnode, int hook_level, 
		struct free_nodes_hdr *fn_hdr, u_char *fnodes, 
		inet_prefix *gnode_ipstart)
{
	int new_gnode, e;
	
	/*
	 * Let's see if we can re-hook at `hook_gnode' or if we have
	 * to create a new gnode, in other words: update the join_rate.
	 */
	new_gnode=update_join_rate(hook_gnode, hook_level, qspn_old_gcount, 
			qspn_gnode_count, fn_hdr);
	if(new_gnode > 0) {
		/* 
		 * The `hook_gnode' gnode cannot take all the nodes of our 
		 * gnode so we just give up and create a new gnode, which has
		 * a gid based on the hash of our current gid.
		 */
		inet_copy(&me.cur_ip, &rk_gnode_ip);
		debug(DBG_NORMAL, "rehook_create_gnode: %s is our new ip", 
				inet_to_str(me.cur_ip));
	} else {
		/* 
		 * We are hooking fine,
		 * let's choose a random ip using the free nodes list we received.
		 */

		e=rand_range(0, fn_hdr->nodes-1);
		if(fn_hdr->level == 1) {
			new_gnode=0;
			postoip(fnodes[e], *gnode_ipstart, &me.cur_ip);
		} else {
			new_gnode=1;
			for(;;) {
				random_ip(gnode_ipstart, fn_hdr->level, fn_hdr->gid, 
						FAMILY_LVLS, me.ext_map, 0, 
						&me.cur_ip, my_family);
				if(!inet_validate_ip(me.cur_ip))
					break;
			}
		}
	}

	if(restricted_mode)
		inet_setip_localaddr(&me.cur_ip, my_family, restricted_class);
	hook_set_all_ips(me.cur_ip, me.cur_ifs, me.cur_ifs_n);

	/*
	 * Close all the rnl->tcp_sk sockets, 'cause we've changed IP and they
	 * aren't valid anymore 
	 */
	rnl_close_all_sk(rlist);

	return new_gnode;
}


/*
 * hook_get_ext_map
 *
 * gets the external map from the rnodes who sent us the free_nodes list. 
 * `rq' points to that rnode.
 * `old_ext_map' is the currently used ext_map; it will be merged with the
 * new received map. 
 *
 * If a new gnode has been created, 1 is returned.
 */
int hook_get_ext_map(int hook_level, int new_gnode, 
		struct rnode_list *rnl, struct free_nodes_hdr *fn_hdr, 
		map_gnode **old_ext_map, quadro_group *old_quadg)
{
	map_gnode **new_ext_map;

	/* 
	 * Fetch the ext_map from the node who gave us the free nodes list. 
	 */
	if(!(new_ext_map=get_ext_map(rnl->node, &me.cur_quadg))) 
		fatal("None of the rnodes in this area gave me the extern map");
	me.ext_map=new_ext_map;
	
	if(we_are_rehooking && hook_level) {
		int gcount, old_gid;

		/* 
		 * Since we are rehooking, our gnode will change and it will be
		 * dismantled, our old gcount has to be decremented from our
		 * old ext_map and the one we receive.
		 */
		gcount = new_ext_map[_EL(hook_level)][old_quadg->gid[hook_level]].gcount;
		qspn_dec_gcount((int*)qspn_gnode_count, hook_level+1, gcount);

		old_gid=old_quadg->gid[hook_level];
		new_ext_map[_EL(hook_level)][old_gid].gcount=0;
		old_ext_map[_EL(hook_level)][old_gid].gcount=0;

		/*
		 * We can also delete our old gid, 'cause it doesn't exist
		 * anymore
		 */
		gmap_node_del(&new_ext_map[_EL(hook_level)][old_gid]);
		gmap_node_del(&old_ext_map[_EL(hook_level)][old_gid]);
	}
	
	/* If we have to create new gnodes, let's do it. */
	if(new_gnode) {
		me.ext_map  = old_ext_map;
		old_ext_map = new_ext_map;
		memcpy(old_quadg, &me.cur_quadg, sizeof(quadro_group));
		
		/* Create a new gnode. After this we have a new ip,
		 * ext_map and quadro_group */
		create_gnodes(&me.cur_ip, we_are_rehooking ? hook_level : fn_hdr->level);
		
		/* Merge the received ext_map with our new empty ext_map */
		merge_ext_maps(me.ext_map, new_ext_map, me.cur_quadg, *old_quadg);
		free_extmap(old_ext_map, FAMILY_LVLS, 0);

		return 1;
	}
	
	free_extmap(old_ext_map, FAMILY_LVLS, 0);
	return 0;
}

/* 
 * hook_get_int_map
 * 
 * fetch the internal map from a rnode which belongs to our same gnode.
 */
void hook_get_int_map(void)
{
	struct radar_queue *rq=radar_q;

	map_node **merg_map, *new_root;
	int imaps=0, i;

	/* 
	 * We want a new shiny traslucent internal map 
	 */

	reset_int_map(me.int_map, 0);
	iptoquadg(me.cur_ip, me.ext_map, &me.cur_quadg, 
			QUADG_GID|QUADG_GNODE|QUADG_IPSTART);

	/* Increment the gnode seeds counter of level one, since
	 * we are new in that gnode */
	gnode_inc_seeds(&me.cur_quadg, 0);

	/* 
	 * Fetch the int_map from each rnode and merge them into a
	 * single, big, shiny map.
	 */
	imaps=0;
	rq=radar_q;
	merg_map=xzalloc(me.cur_node->links*sizeof(map_node *));

	for(i=0; i<me.cur_node->links; i++) {
		rq=find_node_radar_q((map_node *)me.cur_node->r_node[i].r_node);

		if(rq->node->flags & MAP_HNODE)
			continue;
		if(quadg_gids_cmp(rq->quadg, me.cur_quadg, 1)) 
			/* This node isn't part of our gnode, let's skip it */
			continue; 

		if((merg_map[imaps]=get_int_map(rq->node, &new_root))) {
			merge_maps(me.int_map, merg_map[imaps], me.cur_node, new_root);
			imaps++;
		}
	}
	if(!imaps)
		fatal("None of the rnodes in this area gave me the int_map");

	for(i=0; i<imaps; i++)
		free_map(merg_map[i], 0);
	xfree(merg_map);
}

void hook_get_bnode_map(void)
{
	struct radar_queue *rq=radar_q;

	map_bnode **old_bnode_map;	
	u_int *old_bnodes;

	int e, i;

	/* 
	 * Let's get the bnode map. Fast, fast, quick quick! 
	 */
	e=0;
	for(i=0; i<me.cur_node->links; i++) {
		rq=find_node_radar_q((map_node *)me.cur_node->r_node[i].r_node);
		if(rq->node->flags & MAP_HNODE)
			continue;
		if(quadg_gids_cmp(rq->quadg, me.cur_quadg, 1)) 
			/* This node isn't part of our gnode, let's skip it */
			continue; 
		old_bnode_map=me.bnode_map;	
		old_bnodes=me.bmap_nodes;
		me.bnode_map=get_bnode_map(rq->node, &me.bmap_nodes);
		if(me.bnode_map) {
			bmap_levels_free(old_bnode_map, old_bnodes);
			e=1;
			break;
		} else {
			me.bnode_map=old_bnode_map;
			me.bmap_nodes=old_bnodes;
		}
	}
	if(!e)
		loginfo("None of the rnodes in this area gave me the bnode map.");

}

void hook_get_igw(void)
{
	struct radar_queue *rq=radar_q;

	inet_gw **old_igws;
	int *old_igws_counter;

	int e, i;

	/* 
	 * Let's get the Internet Gateway list
	 */
	e=0;
	for(i=0; i<me.cur_node->links; i++) {
		rq=find_node_radar_q((map_node *)me.cur_node->r_node[i].r_node);
		if(rq->node->flags & MAP_HNODE)
			continue;
		if(quadg_gids_cmp(rq->quadg, me.cur_quadg, 1)) 
			/* This node isn't part of our gnode, let's skip it */
			continue; 
		
		old_igws=me.igws;
		old_igws_counter=me.igws_counter;
		me.igws=get_internet_gws(rq->node, &me.igws_counter);
		if(me.igws) {
			free_igws(old_igws, old_igws_counter, FAMILY_LVLS);
			e=1;
			break;
		} else {
			me.igws=old_igws;
			me.igws_counter=old_igws_counter;
		}
	}
	if(!e) {
		loginfo("None gave me the Internet Gateway list");
		reset_igws(me.igws, me.igws_counter, FAMILY_LVLS);
	}
}


/*
 * hook_finish: final part of the netsukuku_hook process
 */
void hook_finish(int new_gnode, struct free_nodes_hdr *fn_hdr)
{
	int tracer_levels, i;

	/* 
	 * We must reset the radar_queue because the first radar_scan, used while hooking,
	 * has to keep the list of the rnodes' "inet_prefix ip". In this way we know
	 * the rnodes' ips even if we haven't an int_map yet.
	 */
	reset_radar();
	
	/* Clear the allowed_rnode llist */
	reset_rnode_allowed(&alwd_rnodes, &alwd_rnodes_counter);

	/* We have finished the hook */
	me.cur_node->flags&=~MAP_HNODE;
	
	/* Disable the filter */
	op_filter_reset(OP_FILTER_ALLOW);

	if(new_gnode) {
		if(!me.cur_node->links)
			/* 
			 * We are a node lost in the desert, so we don't send
			 * anything because nobody is listening
			 */
			tracer_levels=0;
		else
			/* 
			 * We are a new gnode, so we send the tracer in all higher
			 * levels
			 */
			tracer_levels=fn_hdr->level;
	} else {
		/* 
		 * We are just a normal node inside a gnode, let's notice only
		 * the other nodes in this gnode.
		 */
		tracer_levels=2;
	}

	/*
	 * Initialize me.my_igws
	 */
	if(server_opt.share_internet) {
		free_my_igws(&me.my_igws);
		init_my_igws(me.igws, me.igws_counter, &me.my_igws, me.my_bandwidth,
				me.cur_node, &me.cur_quadg);
	}
	
	loginfo("Starting the second radar scan before sending our"
			" first tracer_pkt");
	if(radar_scan(0))
		fatal("%s:%d: Scan of the area failed. Cannot continue.", 
				ERROR_POS);
	
	/* 
	 * Now we send a simple tracer_pkt in all the level we have to. This pkt
	 * is just to say <<Hey there, I'm here, alive>>, thus the other nodes
	 * of the gnode will have the basic routes to reach us.
	 * Note that this is done only at the first time we hook.
	 */
	if(!we_are_rehooking) {
		usleep(rand_range(0, 999999));
		tracer_pkt_start_mutex=0;
		for(i=1; i<tracer_levels; i++)
			tracer_pkt_start(i-1);
	}

	/* Let's fill the krnl routing table */
	loginfo("Filling the kernel routing table");

	rt_full_update(0);
	if(restricted_mode && (server_opt.use_shared_inet ||
				server_opt.share_internet))
		igw_replace_def_igws(me.igws, me.igws_counter, 
				me.my_igws, me.cur_quadg.levels, my_family);
	
	/* (Re)Hook completed */
	loginfo("%sook completed", we_are_rehooking ? "Reh":"H");

	we_are_rehooking=0;
}

/*
 * netsukuku_hook: hooks/rehooks at an existing gnode or creates a new one.
 * `hook_level' specifies at what level we are hooking, generally it is 0.
 * If `hook_gnode' is not null, netsukuku_hook will try to hook only to the
 * rnodes which belongs to the `hook_gnode' at `hook_level' level.
 */
int netsukuku_hook(map_gnode *hook_gnode, int hook_level)
{	
	struct rnode_list *rnl=rlist;
	struct free_nodes_hdr fn_hdr;
	
	inet_prefix gnode_ipstart, old_ip;
	quadro_group old_quadg;

	int ret=0, new_gnode=0;
	u_char fnodes[MAXGROUPNODE];

	/* Save our current IP before resetting */
	inet_copy(&old_ip, &me.cur_ip);
	memcpy(&old_quadg, &me.cur_quadg, sizeof(quadro_group));

	/* Reset the hook */
	if(total_hooks) {
		hook_reset();
		we_are_rehooking=1;
	}
	total_hooks++;
	
	/* 	
	  	* *	   The beginning          * *	  	
	 */
	loginfo("The %s begins. Starting to scan the area", 
			we_are_rehooking ? "rehook" : "hook");
	new_gnode=hook_first_radar_scan(hook_gnode, hook_level, &old_quadg);
	if(new_gnode)
		goto finish;

	/* 
	 * Get the free nodes list
	 */
	qspn_backup_gcount(qspn_old_gcount, (int*)qspn_gnode_count);
	new_gnode=hook_get_free_nodes(hook_level, &fn_hdr, fnodes, 
			&gnode_ipstart, qspn_gnode_count, &rnl);
	if(new_gnode)
		goto finish;

	/* 
	 * Choose a new IP 
	 */
	new_gnode=hook_choose_new_ip(hook_gnode, hook_level, &fn_hdr, fnodes, 
			&gnode_ipstart);

	/*
	 * Get the external map 
	 */
	new_gnode=hook_get_ext_map(hook_level, new_gnode, rnl, &fn_hdr, 
			me.ext_map, &old_quadg);
	if(new_gnode)
		goto finish;

	/* 
	 * Get the internal map 
	 */
	hook_get_int_map();
	
	/*
	 * Fetch the bnode map
	 */
	hook_get_bnode_map();

	/*
	 * If we are in restricted mode, get the Internet Gateways
	 */
	if(restricted_mode && (server_opt.use_shared_inet ||
				server_opt.share_internet))
		hook_get_igw();
	
	/*
	 * And that's all, clean the mess
	 */

	if(free_the_tmp_cur_node) {
		xfree(me.cur_node);
		free_the_tmp_cur_node=0;
	}
	me.cur_node = &me.int_map[me.cur_quadg.gid[0]];
	map_node_del(me.cur_node);
	me.cur_node->flags &= ~MAP_VOID;
	me.cur_node->flags |= MAP_ME;

	/* We need a fresh me.cur_node */
	refresh_hook_root_node(); 
	
finish:
	hook_finish(new_gnode, &fn_hdr);
	return ret;
}

/*
 * And this is the end my dear.
 */
