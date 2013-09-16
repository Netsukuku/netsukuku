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
 * radar.c
 * 
 * The radar sends in broadcast a bouquet of MAX_RADAR_SCANS# packets and waits
 * for the ECHO_REPLY of the nodes which are alive. It then recollects the
 * replies and builds a small statistic, updates, if necessary, the internal 
 * maps, the bnode maps and the qspn buffer.
 * A radar is fired periodically by the radar_daemon(), which is started as a
 * thread.
 */

#include "includes.h"

#include "llist.c"
#include "endianness.h"
#include "if.h"
#include "bmap.h"
#include "route.h"
#include "request.h"
#include "pkts.h"
#include "qspn.h"
#include "radar.h"
#include "netsukuku.h"
#include "common.h"

pthread_attr_t radar_qspn_send_t_attr;

void first_init_radar(void)
{
	max_radar_wait=MAX_RADAR_WAIT;	

	pthread_attr_init(&radar_qspn_send_t_attr);
	pthread_attr_setdetachstate(&radar_qspn_send_t_attr, PTHREAD_CREATE_DETACHED);	 
	
	/* register the radar's ops in the pkt_op_table */
	add_pkt_op(ECHO_ME, SKT_BCAST, ntk_udp_radar_port, radard);
	add_pkt_op(ECHO_REPLY, SKT_UDP, ntk_udp_radar_port, radar_recv_reply);
	
	rlist=(struct rnode_list *)clist_init(&rlist_counter);
	alwd_rnodes=(struct allowed_rnode *)clist_init(&alwd_rnodes_counter);

	radar_daemon_ctl=0;
	init_radar();
}

void last_close_radar(void)
{
	close_radar();
	rnl_reset(&rlist, &rlist_counter);
}

void init_radar(void)
{
	hook_retry=0;
	my_echo_id=0;
	total_radar_scans=0;
	setzero(radar_scans, sizeof(radar_scans));
	radar_scan_mutex=0;
	
	radar_q=(struct radar_queue *)clist_init(&radar_q_counter);
	
	setzero(send_qspn_now, sizeof(u_char)*MAX_LEVELS);
}


void close_radar(void)
{
	if(radar_q_counter)
		clist_destroy(&radar_q, &radar_q_counter);
}

void reset_radar(void)
{
	if(me.cur_node->flags & MAP_HNODE) {
		free_new_node();
		rnl_reset(&rlist, &rlist_counter);
	}
	
	close_radar();
	init_radar();
}

/*
 * free_new_node
 * 
 * frees all the temporary alloced rq->node structs used at the
 * hook time.
 */
void free_new_node(void)
{
	struct radar_queue *rq;

	rq=radar_q;
	list_for(rq)
		if(rq->node && ((int)rq->node != RADQ_EXT_RNODE)) {
			xfree(rq->node);
			rq->node=0;
		}
}

/*
 * find_node_radar_q
 * 
 * returns the first radar_queue struct which has the 
 * rq->node pointer equal to `node'.
 */
struct radar_queue *find_node_radar_q(map_node *node)
{
	struct radar_queue *rq;

	rq=radar_q;
	list_for(rq)
		if(rq->node==node)
			return rq;
	return 0;
}

/*
 * find_ip_radar_q
 * 
 * returns the first radar_queue struct which has the rq->ip
 * member equal to the given `ip'.
 */
struct radar_queue *find_ip_radar_q(inet_prefix *ip)
{
	struct radar_queue *rq;

	rq=radar_q;
	list_for(rq)
		if(!memcmp(rq->ip.data, ip->data, MAX_IP_SZ))
			return rq;
		
	return 0;
}

/*
 * rnl_add
 * 
 * adds a new rnode_list struct in the `*rnlist' list. The new
 * allocated struct will be filled respectively with `rnode' and `dev'.
 * It returns the added `rnode_list' struct.
 */
struct rnode_list *rnl_add(struct rnode_list **rnlist, int *rnlist_counter, 
		map_node *rnode, interface *dev)
{
	struct rnode_list *rnl;

	rnl	       = xzalloc(sizeof(struct rnode_list));
	rnl->node      = (map_node *)rnode;
	rnl->dev[0]    = dev;
	rnl->dev_n++;

	clist_add(rnlist, rnlist_counter, rnl);
	
	return rnl;
}

/*
 * rnl_del
 * 
 * deletes the `rnl' struct from the `rnlist' rnode_list.
 * If `close_socket' is not zero, `rnl'->tcp_sk will be closed.
 */
void rnl_del(struct rnode_list **rnlist, int *rnlist_counter, 
		struct rnode_list *rnl, int close_socket)
{
	if(rnl) {
		if(close_socket && rnl->tcp_sk)
			inet_close(&rnl->tcp_sk);
		clist_del(rnlist, rnlist_counter, rnl);
	}
	if(!(*rnlist_counter))
		*rnlist=0;
}

/*
 * rnl_reset
 * 
 * reset the whole rnode_list
 */
void rnl_reset(struct rnode_list **rnlist, int *rnlist_counter)
{
	struct rnode_list *rnl=*rnlist, *next;

	list_safe_for(rnl, next)
		rnl_del(rnlist, rnlist_counter, rnl, 1);
	*rnlist=(struct rnode_list *)clist_init(rnlist_counter);
}


/*
 * rnl_del_dead_rnode
 * 
 * it removes all the rnode_list structs which are related
 * to a rnode which doesn't exist anymore in `root_node'
 * It returns the number of delete rnodes_list structs.
 */
int rnl_del_dead_rnode(struct rnode_list **rnlist, int *rnlist_counter, 
			map_node *root_node)
{
	struct rnode_list *rnl=*rnlist, *next;
	int i=0;
	
	list_safe_for(rnl, next)
		if(rnode_find(root_node, rnl->node) < 0) {
			rnl_del(rnlist, rnlist_counter, rnl, 1);
			i++;
		}

	return i;
}

/*
 * rnl_find_rpos
 * 
 * returns the first rnode_list struct, contained in
 * `rnlist', which has rnl->node equal to `node'.
 */
struct rnode_list *rnl_find_node(struct rnode_list *rnlist, map_node *node)
{
	struct rnode_list *rnl=rnlist;

	list_for(rnl)
		if(rnl->node == node)
			return rnl;

	return 0;
}

/*
 * rnl_add_dev
 * 
 * If `rnl' is 0 a new struct is added in `*rnlist' using `node'.
 * In both cases the `new_dev' is added in the rnl->dev[] array of
 * pointers (if it isn't already present there) and rnl->dev_n is
 * incremented.
 * On error -1 is returned.
 */
int rnl_add_dev(struct rnode_list **rnlist, int *rnlist_counter,
		struct rnode_list *rnl, map_node *node, interface *new_dev)
{
	int i;

	if(!rnl) {
		rnl=rnl_add(rnlist, rnlist_counter, node, new_dev);
		return 0;
	}

	if(rnl->dev_n >= MAX_INTERFACES)
		return -1;
	
	for(i=0; i<rnl->dev_n; i++)
		if(rnl->dev[i] == new_dev)
			return 0;

	rnl->dev[rnl->dev_n++]=new_dev;

	return 0;
}

/*
 * rnl_del_dev
 * 
 * It searches a pointer in the rnl->dev[] array equal to
 * `del_dev'. If it is found, it is set to 0 and rnl->dev_n is decremented,
 * otherwise 0 is returned.
 * If rnlist->dev_n is 0, the found rnlist struct is deleted from the llist.
 * On error -1 is returned.
 */
int rnl_del_dev(struct rnode_list **rnlist, int *rnlist_counter,
		struct rnode_list *rnl, interface *del_dev)
{
	int i;

	if(!rnl) 
		return 0;

	if(rnl->dev_n <= 0)
		return -1;
	
	for(i=0; i<rnl->dev_n; i++) {
		if(rnl->dev[i] == del_dev) {
			if(i == rnl->dev_n-1)
				rnl->dev[i]=0;
			else {
				rnl->dev[i]=rnl->dev[rnl->dev_n-1];
				rnl->dev[rnl->dev_n-1]=0;
			}
			rnl->dev_n--;
			break;
		}
	}

	if(!rnl->dev_n)
		rnl_del(rnlist, rnlist_counter, rnl, 1);
	
	return 0;
}

/*
 * rnl_update_devs
 * 
 * it updates the device array present in the rnode_list struct of `node'.
 * It searches in rnlist a struct which have rnlist->node == `node',
 * then it substitutes rnlist->dev with `devs' and rnlist->dev_n with `dev_n'.
 * If there is a difference between the new `devs' array and the old one, 1 is
 * returned.
 */
int rnl_update_devs(struct rnode_list **rnlist, int *rnlist_counter,
	                map_node *node, interface **devs, int dev_n)
{
	struct rnode_list *old_rnl, *new_rnl;
	int i, dev_pos, update=0;

	old_rnl=rnl_find_node(*rnlist, node);

	if(!dev_n) {
		/*
		 * The new `devs' array is empty, therefore delete old_rnl
		 */
		rnl_del(rnlist, rnlist_counter, old_rnl, 1);
		return 0;
	}

	if(old_rnl)
		/*
		 * Diff old_rnl->dev and `devs'
		 */
		for(i=0; i < dev_n; i++) {
			dev_pos = FIND_PTR(devs[i], old_rnl->dev, old_rnl->dev_n);
			if(dev_pos < 0) {
				update=1;
				break;
			}
		}
	else if(!old_rnl)
		update=1;
	
	if(update) {
		new_rnl=rnl_add(rnlist, rnlist_counter, node, devs[0]);
		for(i=1; i < dev_n; i++)
			rnl_add_dev(rnlist, rnlist_counter, new_rnl, node, devs[i]);

		new_rnl->tcp_sk = (old_rnl) ? old_rnl->tcp_sk : 0;
		rnl_del(rnlist, rnlist_counter, old_rnl, 0);
	}

	return update;
}

interface **rnl_get_dev(struct rnode_list *rnlist, map_node *node)
{
	struct rnode_list *rnl;

	rnl=rnl_find_node(rnlist, node);
	return !rnl ? 0 : rnl->dev;
}

interface *rnl_get_rand_dev(struct rnode_list *rnlist, map_node *node)
{
	struct rnode_list *rnl;

	return !(rnl=rnl_find_node(rnlist, node)) ? 
			0 : rnl->dev[rand_range(0, rnl->dev_n-1)];
}

/*
 * rnl_get_sk
 *
 * It returns the tcp socket associated to rnode `node'.
 * If the socket is set to zero, it tries to create a tcp connection to 
 * `node' to the `ntk_tcp_port' port.
 *
 * On error -1 is returned.
 */
int rnl_get_sk(struct rnode_list *rnlist, map_node *node)
{
	struct rnode_list *rnl;

	if(!(rnl=rnl_find_node(rnlist, node)))
		return -1;

	if(!rnl->tcp_sk) {
		inet_prefix to;
		int i;

		if(me.cur_node->flags & MAP_HNODE) {
			struct radar_queue *rq;

			/* If we are hooking, get the IP from the radar
			 * queue */
			if(!(rq=find_node_radar_q(rnl->node)))
				return -1;
			inet_copy(&to, &rq->ip);

		} else {
			rnodetoip((u_int)me.int_map, (u_int)node,
					me.cur_quadg.ipstart[1], &to);
		}

		/* Try to connect using the `i'th device. If it fails, try
		 * another device */
		for(i=0; i < rnl->dev_n && rnl->tcp_sk <= 0; i++)
			rnl->tcp_sk=pkt_tcp_connect(&to, ntk_tcp_port,
					rnl->dev[i]);

		/* If the socket is connected, set it to keepalive */
		if((rnl->tcp_sk = (rnl->tcp_sk <= 0) ? 0 : rnl->tcp_sk))
			set_keepalive_sk(rnl->tcp_sk);
		
	}
	
	return rnl->tcp_sk > 0 ? rnl->tcp_sk : -1;
}

/*
 * rnl_set_sk
 *
 * It sets the socket associated to rnode `node' to `sk'
 */
void rnl_set_sk(struct rnode_list *rnlist, map_node *node, int sk)
{
	struct rnode_list *rnl;

	if(!(rnl=rnl_find_node(rnlist, node)))
		return;

	rnl->tcp_sk=sk;
}

/*
 * rnl_close_all_sk
 *
 * It closes all the opened tcp_sk of the `rnlist' llist
 */
void rnl_close_all_sk(struct rnode_list *rnlist)
{
	struct rnode_list *rnl=rnlist;

	list_for(rnl)
		if(rnl->tcp_sk)
			inet_close(&rnl->tcp_sk);
}

/*
 * rnl_fill_rq
 *
 * It sets the `pkt'->sk and `pkt'->to variables.
 * The `pkt'->sk is retrieved using rnl_get_sk()
 *
 * On error -1 is returned.
 */
int rnl_fill_rq(map_node *rnode, PACKET *pkt)
{
	int tries=0;

retry:
	if(!pkt->sk && (pkt->sk=rnl_get_sk(rlist, rnode)) <= 0) {
		error(ERROR_MSG "Couldn't get the socket associated "
				"to dst_rnode", ERROR_FUNC);
		return -1;
	}

	if(inet_getpeername(pkt->sk, &pkt->to, 0) < 0) {
		tries++;
		if(tries < 2)
			goto retry;
		return -1;
	}

	return 0;
}

/*
 * rnl_send_rq
 *
 * It is a wrapper to send_rq. It is used to send or receive a packet to/from
 * the specified `rnode'.
 *
 * On error -1 is returned.
 *
 * Note: the pkt->sk must not be closed.
 */
int rnl_send_rq(map_node *rnode, 
		PACKET *pkt, int pkt_flags, u_char rq, int rq_id, u_char re, 
		int check_ack, PACKET *rpkt)
{
	int ret, tries=0;

retry:
	if(!pkt->sk && rnl_fill_rq(rnode, pkt) < 0)
		return -1;

	ret=send_rq(pkt, pkt_flags, rq, rq_id, re, check_ack, rpkt);
	if((ret == SEND_RQ_ERR_CONNECT || ret == SEND_RQ_ERR_SEND || 
		ret == SEND_RQ_ERR_RECV)) {

		/* The socket has been corrupted, set it to 0 and try again */
		inet_close(&pkt->sk);
		rnl_set_sk(rlist, rnode, 0);
		
		tries++;
		if(tries < 2)
			goto retry;
	}

	return ret;
}

/*
 * is_rnode_allowed
 * 
 * it verifies if the rnode described by the `rip' IP is 
 * present in the `alr' llist. If it is 1 is returned, otherwise 0.
 */
int is_rnode_allowed(inet_prefix rip, struct allowed_rnode *alr)
{
	int i, e, gid[MAX_LEVELS];

	iptogids(&rip, gid, FAMILY_LVLS);
	
	list_for(alr) {
		for(e=0, i=alr->min_level; i < alr->tot_level; i++)
			if(gid[i] != alr->gid[i]) {
				e=1;
				break;
			}
		if(!e)
			return 1;
	}

	return 0;
}

/*
 * new_rnode_allowed
 * 
 * add a new allowed rnode in the `alr' llist which has
 * already `*alr_counter' members. `gid', `min_lvl', and `tot_lvl' are the
 * respective field of the new allowed_rnode struct.
 */
void new_rnode_allowed(struct allowed_rnode **alr, int *alr_counter,
		int *gid, int min_lvl, int tot_lvl)
{
	struct allowed_rnode *new_alr;

	new_alr=xmalloc(sizeof(struct allowed_rnode));

	new_alr->min_level=min_lvl;
	new_alr->tot_level=tot_lvl;
	
	setzero(new_alr->gid, sizeof(int)*MAX_LEVELS);
	memcpy(&new_alr->gid[min_lvl], &gid[min_lvl], sizeof(int)*(tot_lvl-min_lvl));
	
	debug(DBG_SOFT, "new_rnode_allowed: %d, %d, %d, %d. min_lvl: %d, tot_lvl: %d", 
			gid[0], gid[1], gid[2], gid[3], min_lvl, tot_lvl);

	clist_add(alr, alr_counter, new_alr);
}

void reset_rnode_allowed(struct allowed_rnode **alr, int *alr_counter)
{
	if(*alr)
		list_destroy((*alr));
	*alr=(struct allowed_rnode *)clist_init(alr_counter);
}

/*
 * count_hooking_nodes
 * 
 * returns the number of hooking nodes, which are stored
 * in the radar_queue.
 */
int count_hooking_nodes(void) 
{
	struct radar_queue *rq;
	int total_hooking_nodes=0;

	rq=radar_q;
	list_for(rq) {
		if(!rq->node)
			continue;

		if(rq->node->flags & MAP_HNODE)
			total_hooking_nodes++;
	}
	
	return total_hooking_nodes;
}


/*
 * final_radar_queue
 * 
 * analyses the received ECHO_REPLY pkt and write the
 * average rtt of each found node in the radar_queue.
 */
void final_radar_queue(void)
{	
	struct radar_queue *rq;
	int e;
	struct timeval sum;
	u_int f_rtt;

	setzero(&sum, sizeof(struct timeval));

	rq=radar_q;
	list_for(rq) {
		if(!rq->node)
			continue;

		/* Sum the rtt of all the received pongs */
		for(e=0; e < rq->pongs; e++)
			timeradd(&rq->rtt[e], &sum, &sum);
		
		/* Add penality rtt for each pong lost */
		for(; e < MAX_RADAR_SCANS; e++)
			timeradd(&rq->rtt[e-rq->pongs], &sum, &sum);

		f_rtt=MILLISEC(sum)/MAX_RADAR_SCANS;
		MILLISEC_TO_TV(f_rtt, rq->final_rtt);
	}

	my_echo_id=0;
}

/* 
 * radar_remove_old_rnodes
 * 
 * It removes all the old rnodes ^_- It store in rnode_delete[level] the number
 * of deleted rnodes. This function is used by radar_update_map
 */
int radar_remove_old_rnodes(char *rnode_deleted) 
{
	map_node *node, *root_node, *broot_node;
	map_gnode *gnode;
	map_bnode *bnode;
	ext_rnode *e_rnode=0;
	ext_rnode_cache *erc;
	struct qspn_buffer *qb;
	struct rnode_list *rnl;
	int i, e, node_pos, bm, rnode_pos, bnode_rnode_pos, root_node_pos;
	int broot_node_pos;
	int level, blevel, external_node, total_levels, first_level;
	void *void_map, *void_gnode;

	if(!me.cur_node->links)
		return 0;

	for(i=0; i<me.cur_node->links; i++) {
		node=(map_node *)me.cur_node->r_node[i].r_node;

		if(!(node->flags & MAP_VOID))
			/* The rnode is not really dead! */
			continue;

		if(node->flags & MAP_ERNODE) {
			e_rnode=(ext_rnode *)node;
			external_node=1;
			total_levels=e_rnode->quadg.levels;
			first_level=1;
			quadg_setflags(&e_rnode->quadg, MAP_VOID);
		} else {
			external_node=0;
			total_levels=1;
			first_level=0;
		}

		for(level=first_level; level < total_levels; level++) {
			qspn_set_map_vars(level, 0, &root_node, &root_node_pos, 0);
			blevel=level-1;

			/* delete the rnode from the rnode_list */
			rnl=rnl_find_node(rlist, node);
			rnl_del(&rlist, &rlist_counter, rnl, 1);

			/*
			 * Just delete it from all the maps.
			 */
			
			if(!level && !external_node) {
				void_map=me.int_map;
				node_pos=pos_from_node(node, me.int_map);
				rnode_pos=i;
				
				debug(DBG_NORMAL, "radar: The node %d is dead", 
						node_pos);

				/* delete it from the int_map and update the gcount */
				map_node_del(node);
				qspn_dec_gcount((int*)qspn_gnode_count, level+1, 1); 
				
				/* delete the route */
				rt_update_node(0, node, 0,0,0, level); 
				
			 	send_qspn_now[level]=1;
			} else {
				void_map=me.ext_map;
				gnode=e_rnode->quadg.gnode[_EL(level)];
				
				/** delete the direct route to the ext_node */
				if(level == 1)
				  rt_update_node(&e_rnode->quadg.ipstart[0], 
						  e_rnode, 0, 0, 0, /*level=0*/ 0);
				/**/

				void_gnode=(void *)gnode;
				if(!void_gnode)
					continue;
				
				node_pos=pos_from_gnode(gnode, me.ext_map[_EL(level)]); 
				rnode_pos=g_rnode_find((map_gnode *)root_node, gnode);

				debug(DBG_NORMAL, "The ext_node (gid %d, lvl %d) is"
						" dead", e_rnode->quadg.gid[level], level);

				/* bnode_map update */
				for(e=0; blevel >= 0; blevel--) {
					qspn_set_map_vars(blevel, 0, &broot_node, &broot_node_pos, 0);
					bm=map_find_bnode(me.bnode_map[blevel], me.bmap_nodes[blevel],
							broot_node_pos);
					if(bm == -1)
						continue;

					bnode=&me.bnode_map[blevel][bm];
					bnode_rnode_pos=rnode_find(bnode, 
							(map_node *) e_rnode->quadg.gnode[_EL(level)]);
					if(bnode_rnode_pos != -1)
						rnode_del(bnode, bnode_rnode_pos);

					if(!bnode->links) {
						me.bnode_map[blevel]=map_bnode_del(me.bnode_map[blevel], 
								&me.bmap_nodes[blevel], bnode);
						broot_node->flags&=~MAP_BNODE;
					} else
						e=1;
				}
				if(!e) /* We are no more a bnode */
					me.cur_node->flags&=~MAP_BNODE;

				/* If we were the only bnode which bordered on
				 * `gnode', delete it from the map */
				if(map_find_bnode_rnode(me.bnode_map[level-1], me.bmap_nodes[level-1],
							gnode) == -1) {
					qspn_dec_gcount((int*)qspn_gnode_count, level+1, gnode->gcount);
					gmap_node_del(gnode);
					gnode_dec_seeds(&me.cur_quadg, level); /* update the seeds */
				}

				/* Delete the entries from the routing table */
				rt_update_node(0, 0, &e_rnode->quadg, 0, 0, level);
			 	
				send_qspn_now[level]=1;
			}
	
			if(rnode_pos >= 0 && root_node->links > 0)
				rnode_del(root_node, rnode_pos);

			if(!root_node->links) {
				/* We are alone in the dark. Sigh. */
				qspn_time_reset(level, level, FAMILY_LVLS);
			} else if(!external_node)
				erc_update_rnodepos(me.cur_erc, root_node, rnode_pos);

			/* Now we delete it from the qspn_buffer */
			if(qspn_b[level]) {
				qb=qspn_b[level];
				qb=qspn_b_find_rnode(qb, node);
				if(qb)
					qspn_b[level]=list_del(qspn_b[level], qb);
			}
			
			SET_BIT(rnode_deleted, level);
		}
		
		/* 
		 * Kick out the external_node from the root_node and destroy it
		 * from the ext_rnode_cache
		 */
		if(external_node) {
			/* external rnode cache update */
			erc=erc_find(me.cur_erc, e_rnode);
			if(erc)
				e_rnode_del(&me.cur_erc, &me.cur_erc_counter, erc);
			rnode_del(me.cur_node, i);
		}

		/* If the rnode we deleted from the root_node was swapped with
		 * the last rnodes, we have to inspect again the same
		 * root_node->r_node[ `i' ] rnode, because now it is another 
		 * rnode */
		if(i != (me.cur_node->links+1) - 1)
			i--;
	}

	if(!me.cur_node->links) {
		/* - Diary -
		 * Tue Mar 14 07:29:58 CET 2006
		 * Damn! All my rnodes died, I am the last survivor in this
		 * great lone land... I have to reset my memory... farewell!
		 */
		qspn_reset_counters(FAMILY_LVLS);
	}
	
	return 0;
}

/* 
 * radar_update_bmap
 *
 * updates the bnode map of the given `level' the root_node bnode in the bmap 
 * will also point to the gnode of level `gnode_level'+1 that is
 * `rq'->quadg.gnode[_EL(gnode_level+1)].
 */
void radar_update_bmap(struct radar_queue *rq, int level, int gnode_level)
{
	map_gnode *gnode;
	map_node  *root_node;
	map_rnode *rnode, rn;
	int  bm, rnode_pos, root_node_pos;
	void *void_map;

	if(level == me.cur_quadg.levels-1)
		return;

	qspn_set_map_vars(level, 0, &root_node, &root_node_pos, 0);
	void_map=me.ext_map;
	gnode=rq->quadg.gnode[_EL(gnode_level+1)];
	
	bm=map_find_bnode(me.bnode_map[level], me.bmap_nodes[level],
			root_node_pos);
	if(bm==-1) {
		bm=map_add_bnode(&me.bnode_map[level], &me.bmap_nodes[level], 
				root_node_pos, 0);
		rnode_pos=-1;
	} else
		rnode_pos=rnode_find(&me.bnode_map[level][bm], &gnode->g);
	
	if(rnode_pos == -1) {
		setzero(&rn, sizeof(map_rnode));
		rn.r_node=(int *)&gnode->g;
		rnode_add(&me.bnode_map[level][bm], &rn);
		rnode_pos=0;
	}

	rnode=&me.bnode_map[level][bm].r_node[rnode_pos];
	rnode->trtt=MILLISEC(rq->final_rtt);
}

/* 
 * radar_update_map
 * 
 * it updates the int_map and the ext_map if any bnodes are found.
 * Note that the rnodes in the map are held in a different way. First of all the qspn
 * is not applied to them (we already know how to reach them ;) and they have only
 * one rnode... ME. So me.cur_node->r_node[x].r_node->r_node[0] == me.cur_node.
 * Gotcha?
 */
void radar_update_map(void)
{
	struct qspn_buffer *qb;
	struct radar_queue *rq;
	ext_rnode_cache *erc;
	map_gnode *gnode=0;
	map_node  *node, *root_node;
	map_rnode rnn, *new_root_rnode;
	ext_rnode *e_rnode;
	
	int i, diff, rnode_pos;
	u_char rnode_added[MAX_LEVELS/8], rnode_deleted[MAX_LEVELS/8];
	int level, external_node, total_levels, root_node_pos, node_update;
	void *void_map;
	const char *ntop;
	char updated_rnodes, routes_update, devs_update;

	updated_rnodes=routes_update=devs_update=0;
	setzero(rnode_added, sizeof(rnode_added));
	setzero(rnode_deleted, sizeof(rnode_deleted));
	
	/**
	 * Let's consider all our rnodes void, in this way we'll know what
	 * rnodes will remain void after the update.
	 */
	for(i=0; i<me.cur_node->links; i++) {
		node=(map_node *)me.cur_node->r_node[i].r_node;
		node->flags|=MAP_VOID | MAP_UPDATE;
	}
	/**/

	rq=radar_q;
	list_for(rq) {
	           if(!rq->node)
			   continue;
		   if(!(me.cur_node->flags & MAP_HNODE) && (rq->flags & MAP_HNODE))
			   continue;

		   /* 
		    * We need to know if it is a node which is not in the gnode
		    * where we are (external_rnode).
		    */
		   if((int)rq->node == RADQ_EXT_RNODE) {
			   external_node=1;
			   total_levels=rq->quadg.levels;
		   } else {
			   external_node=0;
			   total_levels=1;
		   }

		   for(level=total_levels-1; level >= 0; level--) {
			   qspn_set_map_vars(level, 0, &root_node, &root_node_pos, 0);
			   node_update=devs_update=0;

			   if(!level) {
				   void_map=me.int_map;
				   node=rq->node;
			   } else {
				   /* Skip the levels where the ext_rnode belongs
				    * to our same gids */
				   if(!quadg_gids_cmp(rq->quadg, me.cur_quadg, level))
					   continue;
				   
				   /* Update only the gnodes which belongs to
				    * our same gid of the upper level, because
				    * we don't keep the internal info of the
				    * extern gnodes. */
				   if((level < rq->quadg.levels-1) &&
					quadg_gids_cmp(rq->quadg, me.cur_quadg, level+1)) {
					   rq->quadg.gnode[_EL(level)]=0;
					   continue;
				   }
				   
				   /* Ehi, we are a bnode */
				   root_node->flags|=MAP_BNODE;
				   me.cur_node->flags|=MAP_BNODE;
				   
				   void_map=me.ext_map;
				   gnode=rq->quadg.gnode[_EL(level)];
				   node=&gnode->g;
			   }

			   if(external_node && !level && me.cur_erc_counter) {
				   erc=e_rnode_find(me.cur_erc, &rq->quadg, 0);
				   if(!erc)
					   rnode_pos=-1;
				   else {
					   rnode_pos=erc->rnode_pos;
					   node=(map_node *)erc->e;
				   }
			   } else
				   rnode_pos=rnode_find(root_node, node);

			   if(rnode_pos == -1) { /* W00t, we've found a new rnode! */
				   node_update=1;
				   rnode_pos=root_node->links; 
				   
				   ntop=inet_to_str(rq->quadg.ipstart[level]);
				   if(server_opt.dbg_lvl || !level)
					   loginfo("Radar: New node found: %s, ext: %d, level: %d", 
							   ntop, external_node, level);

				   if(external_node && !level) {
					   /* 
					    * If this node we are processing is external, at level 0,
					    * in the root_node's rnodes we add a rnode which point 
					    * to a ext_rnode struct.
					    */

					   setzero(&rnn, sizeof(map_rnode));
					   e_rnode=xzalloc(sizeof(ext_rnode));

					   memcpy(&e_rnode->quadg, &rq->quadg, sizeof(quadro_group));
					   e_rnode->node.flags=MAP_BNODE | MAP_GNODE |  MAP_RNODE | 
						   MAP_ERNODE;
					   rnn.r_node=(int *)e_rnode;
					   node=rq->node=&e_rnode->node;
					   new_root_rnode=&rnn;
					  
					   /* Update the external_rnode_cache list */
					   e_rnode_add(&me.cur_erc, e_rnode, rnode_pos,
							   &me.cur_erc_counter);
				   } else {
					   /*We purge all the node's rnodes.*/
					   rnode_destroy(node);

					   /* 
					    * This node has only one rnode, 
					    * and that is the root_node.
					    */
					   setzero(&rnn, sizeof(map_rnode));
					   rnn.r_node=(int *)root_node;
					   rnode_add(node, &rnn);

					   /* It is a border node */
					   if(level)
						   node->flags|=MAP_BNODE | MAP_GNODE;
					   node->flags|=MAP_RNODE;

					   /* 
					    * Fill the rnode to be added in the
					    * root_node.
					    */
					   setzero(&rnn, sizeof(map_rnode));
					   rnn.r_node=(int *)node; 
					   new_root_rnode=&rnn;
				   }

				   /* 
				    * The new node is added in the root_node's
				    * rnodes.
				    */
				   rnode_add(root_node, new_root_rnode);
				   

				   /* Update the qspn_buffer */
				   if(!external_node || level) {
					   qb=xzalloc(sizeof(struct qspn_buffer));
					   qb->rnode=node;
					   qspn_b[level]=list_add(qspn_b[level], qb);

					   send_qspn_now[level]=1;
				   }
				   
				   /* If the new rnode wasn't present in the map, 
				    * then it is also a new node in the map, so
				    * update the seeds counter too */
				   if(!level && !external_node && (node->flags & MAP_VOID)) {
					   gnode_inc_seeds(&me.cur_quadg, level);
					   qspn_inc_gcount(qspn_gnode_count, level+1, 1);
				   }

				   SET_BIT(rnode_added, level);
			   } else {
				   /* 
				    * Nah, We have the node in the map. Let's see if 
				    * its rtt is changed
				    */

				   if(!send_qspn_now[level] && node->links) {
					   diff=abs(root_node->r_node[rnode_pos].trtt -
							   MILLISEC(rq->final_rtt));
					   if(diff >= RTT_DELTA) {
				   		   node_update=1;
						   send_qspn_now[level]=1;
						   debug(DBG_NOISE, "node %s rtt changed, diff: %d",
								   inet_to_str(rq->ip), diff);
					   }
				   }
			   }
			   
			   /* Restore the flags */
			   if(level)
				   gnode->flags&=~GMAP_VOID;
			   node->flags&=~MAP_VOID & ~MAP_UPDATE & ~QSPN_OLD;


			   /*
			    * Update the devices list of the rnode
			    */
			   if(!level) {
				  devs_update=rnl_update_devs(&rlist, &rlist_counter,
					  node, rq->dev, rq->dev_n);
				  if(devs_update)
					  routes_update++;
			   }


			   /* Nothing is really changed */
			   if(!node_update)
				   continue;
			   
			   /* Update the rtt */
		           root_node->r_node[rnode_pos].trtt=MILLISEC(rq->final_rtt);
			   
			   /* Bnode map stuff */
			   if(external_node && level) {
				   /* 
				    * All the root_node bnodes which are in the
				    * bmaps of level smaller than `level' points to
				    * the same gnode which is rq->quadg.gnode[_EL(level-1+1)].
				    * This is because the inferior levels cannot
				    * have knowledge about the bordering gnode 
				    * which is in an upper level, but it's necessary that
				    * they know which who the root_node borders on,
				    * so the get_route algorithm can descend to
				    * the inferior levels and it will still know
				    * what is the border node which is linked
				    * to the target gnode.
				    */
				   for(i=0; i < level; i++)
					   radar_update_bmap(rq, i, level-1);
				   send_qspn_now[level-1]=1;
			   }

			   if(node_update || devs_update)
				   node->flags|=MAP_UPDATE;

		   } /*for(level=0, ...)*/
		   
		   updated_rnodes++;
	} /*list_for(rq)*/

	/* Burn the deads */
	if(updated_rnodes < me.cur_node->links)
		radar_remove_old_rnodes((char*)rnode_deleted);

	/* <<keep your room tidy... order, ORDER>> */
	if(!is_bufzero(rnode_added, sizeof(rnode_added)) || 
			!is_bufzero(rnode_deleted, sizeof(rnode_deleted))) {

		/*** 
		 * qsort the rnodes of me.cur_node and me.cur_quadg comparing 
		 * their trtt */
		rnode_trtt_order(me.cur_node);

		for(i=1; i<me.cur_quadg.levels; i++)
			if(TEST_BIT(rnode_added, i) || TEST_BIT(rnode_deleted, i))
				rnode_trtt_order(&me.cur_quadg.gnode[_EL(i)]->g);
		/**/

		/* adjust the rnode_pos variables in the ext_rnode_cache list */
		erc_reorder_rnodepos(&me.cur_erc, &me.cur_erc_counter, me.cur_node);
	}

	/* Give a refresh to the kernel */
	if((!is_bufzero(rnode_added, sizeof(rnode_added)) ||
		routes_update) && !(me.cur_node->flags & MAP_HNODE))
		rt_rnodes_update(1);
}

/* 
 * add_radar_q
 * 
 * It returns the radar_q struct which handles the pkt.from node.
 * If the node is not present in the radar_q, it is added, and the
 * relative struct will be returned.
 */
struct
radar_queue *add_radar_q(PACKET pkt)
{
	map_node *rnode;
	quadro_group quadg;
	struct radar_queue *rq;
	u_int ret=0;
	int dev_pos;

	if(me.cur_node->flags & MAP_HNODE) {
		/* 
		 * We are hooking, we haven't yet an int_map, an ext_map,
		 * a stable ip, so we create fake nodes that will be delete after
		 * the hook.
		 */
		if(!(rq=find_ip_radar_q(&pkt.from))) {
			map_rnode rnn;

			rnode=xmalloc(sizeof(map_node));
			setzero(rnode, sizeof(map_node));
			setzero(&rnn, sizeof(map_rnode));

			rnn.r_node=(int *)me.cur_node;
			rnode_add(rnode, &rnn);
		} else
			rnode=rq->node;
	} 
	
	iptoquadg(pkt.from, me.ext_map, &quadg, QUADG_GID|QUADG_GNODE|QUADG_IPSTART);

	if(!(me.cur_node->flags & MAP_HNODE)) {
		iptomap((u_int)me.int_map, pkt.from, me.cur_quadg.ipstart[1], &rnode);
		ret=quadg_gids_cmp(me.cur_quadg, quadg, 1);
	}

	if(!ret)
		rq=find_node_radar_q(rnode);
	else
		rq=find_ip_radar_q(&pkt.from);
	
	if(!rq) { 
		/* 
		 * If pkt.from isn't already in the queue, add it. 
		 */

		rq=xzalloc(sizeof(struct radar_queue));
		
		if(ret)
			rq->node=(map_node *)RADQ_EXT_RNODE;
		else {
			rq->node=rnode;
			/* This pkt has been sent from another hooking
			 * node, let's remember this. */
			if(pkt.hdr.flags & HOOK_PKT)
				rq->node->flags|=MAP_HNODE;
		}

		if(pkt.hdr.flags & HOOK_PKT)
			rq->flags|=MAP_HNODE;

		inet_copy(&rq->ip, &pkt.from);
		memcpy(&rq->quadg, &quadg, sizeof(quadro_group));
		rq->dev[0] = pkt.dev;
		rq->dev_n++;
	
		clist_add(&radar_q, &radar_q_counter, rq);
	} else {
		/*
		 * Check if the input device is in the rq->dev array,
		 * if not add it.
		 */
		if(rq->dev_n < MAX_INTERFACES) {
			dev_pos=FIND_PTR(pkt.dev, rq->dev, rq->dev_n);
			if(dev_pos < 0)
				rq->dev[rq->dev_n++]=pkt.dev;
		}
	}

	return rq;
}

/* 
 * radar_exec_reply
 * 
 * It reads the received ECHO_REPLY pkt and updates the radar
 * queue, storing the calculated rtt and the other infos relative to the sender
 * node.
 */
int radar_exec_reply(PACKET pkt)
{
	struct timeval t;
	struct radar_queue *rq;
	u_int rtt_ms=0;
	int dev_pos;
	
	gettimeofday(&t, 0);

	/*
	 * Get the radar_queue struct relative to pkt.from
	 */
	rq=add_radar_q(pkt);

	dev_pos=ifs_get_pos(me.cur_ifs, me.cur_ifs_n, pkt.dev);
	if(dev_pos < 0)
		debug(DBG_NORMAL, "The 0x%x ECHO_REPLY pkt was received by a non "
				"existent interface", pkt.hdr.id);

	if(me.cur_node->flags & MAP_HNODE) {
		if(pkt.hdr.flags & HOOK_PKT) {
			u_char scanning;
			memcpy(&scanning, pkt.msg, sizeof(u_char));

			/* 
			 * If the pkt.from node has finished his scan, and we
			 * never received one of its ECHO_ME pkts, and we are
			 * still scanning, set the hook_retry.
			 */
			if(!scanning && !rq->pings && 
					(radar_scan_mutex ||
					 radar_scans[dev_pos]<=MAX_RADAR_SCANS)) {
				hook_retry=1;
			}
		}
	}

	if(rq->pongs < radar_scans[dev_pos]) {
		timersub(&t, &scan_start, &rq->rtt[(int)rq->pongs]);
		/* 
		 * Now we divide the rtt, because (t - scan_start) is the time
		 * the pkt used to reach B from A and to return to A from B
		 */
		rtt_ms=MILLISEC(rq->rtt[(int)rq->pongs])/2;
		MILLISEC_TO_TV(rtt_ms, rq->rtt[(int)rq->pongs]);

		rq->pongs++;
	}

	return 0;
}


/* 
 * radar_recv_reply
 * 
 * It handles the ECHO_REPLY pkts
 */
int radar_recv_reply(PACKET pkt)
{
	if(!my_echo_id || !radar_scan_mutex || !total_radar_scans)
		return -1;
	
	if(pkt.hdr.id != my_echo_id) {
		debug(DBG_NORMAL,"I received an ECHO_REPLY with id: 0x%x, but "
				"my current ECHO_ME is 0x%x", pkt.hdr.id, 
				my_echo_id);
		return -1;
	}

	/* 
	 * If the `alwd_rnodes_counter' counter isn't zero, verify that
	 * `pkt.from' is an allowed rnode, otherwise drop this pkt 
	 */
	if(alwd_rnodes_counter && !is_rnode_allowed(pkt.from, alwd_rnodes)) {
		debug(DBG_INSANE, "Filtering 0x%x ECHO_REPLY", pkt.hdr.id);
		return -1;
	}

	/*
	 * If the rnode is in restricted mode and we are not, drop the pkt.
	 * If we are in restricted mode and the rnode isn't, drop the pkt
	 */
	if((pkt.hdr.flags & RESTRICTED_PKT && !restricted_mode) ||
		(!(pkt.hdr.flags & RESTRICTED_PKT) && restricted_mode))
		return -1;
	
	return radar_exec_reply(pkt);
}

/* 
 * radar_qspn_send_t
 * 
 * This function is used only by radar_scan().
 * It just call the qspn_send() function. We use a thread
 * because the qspn_send() may sleep, and we don't want to halt the
 * radar_scan().
 */
void *radar_qspn_send_t(void *level)
{
	int *p;
	u_char i;

	p=(int *)level;
	i=(u_char)*p;

	xfree(p);
	qspn_send(i);

	return NULL;
}
		            
/* 
 * radar_scan
 * 
 * It starts the scan of the local area.
 *
 * It sends MAX_RADAR_SCANS packets in broadcast then it waits MAX_RADAR_WAIT
 * and in the while the echo replies are gathered. After MAX_RADAR_WAIT it 
 * stops to receive echo replies and it does a statistical analysis of the 
 * gathered echo replies, it updates the r_nodes in the map and sends a qspn 
 * round if something is changed in the map and if the `activate_qspn' argument
 * is non zero.
 *
 * It returns 1 if another radar_scan is in progress, -1 if something went
 * wrong, 0 on success.
 */
int radar_scan(int activate_qspn) 
{
	pthread_t thread;
	PACKET pkt;
	int i, d, *p;
	ssize_t err;
	u_char echo_scan;

	/* We are already doing a radar scan, that's not good */
	if(radar_scan_mutex)
		return 1;
	radar_scan_mutex=1;
	
	/*
	 * We create the PACKET 
	 */
	setzero(&pkt, sizeof(PACKET));
	inet_setip_bcast(&pkt.to, my_family);
	my_echo_id=rand();

	gettimeofday(&scan_start, 0);
	
	/*
	 * Send a bouquet of ECHO_ME pkts 
	 */
	
	if(me.cur_node->flags & MAP_HNODE) {
		pkt.hdr.sz=sizeof(u_char);
		pkt.hdr.flags|=HOOK_PKT|BCAST_PKT;
		pkt.msg=xmalloc(pkt.hdr.sz);
		debug(DBG_INSANE, "Radar scan 0x%x activated", my_echo_id);
	} else
		total_radars++;
	
	if(restricted_mode)
		pkt.hdr.flags|=RESTRICTED_PKT;

	/* Loop through the me.cur_ifs array, sending the bouquet using all the
	 * interfaces we have */
	for(d=0; d < me.cur_ifs_n; d++) {

		pkt_add_dev(&pkt, &me.cur_ifs[d], 1);
		pkt.sk=0; /* Create a new socket */
	
		/* Send MAX_RADAR_SCANS# packets using me.cur_ifs[d] as
		 * outgoing interface */
		for(i=0, echo_scan=0; i<MAX_RADAR_SCANS; i++, echo_scan++) {
			if(me.cur_node->flags & MAP_HNODE)
				memcpy(pkt.msg, &echo_scan, sizeof(u_char));

			err=send_rq(&pkt, 0, ECHO_ME, my_echo_id, 0, 0, 0);
			if(err < 0) {
				if(errno == ENODEV) {
					/* 
					 * The me.cur_ifs[d] device doesn't
					 * exist anymore. Delete it.
					 */
					fatal("The device \"%s\" has been removed",
							me.cur_ifs[d].dev_name);
					ifs_del(me.cur_ifs, &me.cur_ifs_n, d);
					d--;
				} else
					error(ERROR_MSG "Error while sending the"
						" scan 0x%x... skipping", 
						ERROR_FUNC, my_echo_id);
				break;
			}
			radar_scans[d]++;
			total_radar_scans++;
		}

		if(!radar_scans[d])
			error("radar_scan(): The scan 0x%x on the %s interface failed."
				" Not a single scan was sent", my_echo_id, 
				pkt.dev->dev_name);
	
		if(pkt.sk > 0)
			inet_close(&pkt.sk);
	}
	
	pkt_free(&pkt, 1);
	
	if(!total_radar_scans) {
		error("radar_scan(): The scan 0x%x failed. It wasn't possible "
				"to send a single scan", my_echo_id);
		return -1;
	}

	xtimer(max_radar_wait, max_radar_wait<<1, &radar_wait_counter);

	final_radar_queue();
	radar_update_map();

	if(activate_qspn)
		for(i=0; i<me.cur_quadg.levels; i++)
			if(send_qspn_now[i]) {
				p=xmalloc(sizeof(int));
				*p=i;
				/* We start a new qspn_round in the `i'-th level */
				pthread_create(&thread, &radar_qspn_send_t_attr, 
						radar_qspn_send_t, (void *)p);
			}

	if(!(me.cur_node->flags & MAP_HNODE))
		reset_radar();

	radar_scan_mutex=0;	
	return 0;
}


/* 
 * radard
 * 
 * It sends back to rpkt.from the ECHO_REPLY pkt in reply to the ECHO_ME
 * pkt received.
 */
int radard(PACKET rpkt)
{
	PACKET pkt;
	struct radar_queue *rq;
	ssize_t err;
	const char *ntop=0;
	int dev_pos;
	u_char echo_scans_count;

	if(alwd_rnodes_counter && !is_rnode_allowed(rpkt.from, alwd_rnodes)) {
		debug(DBG_INSANE, "Filtering 0x%x ECHO_ME", rpkt.hdr.id);
		return -1;
	}
	
	if((rpkt.hdr.flags & RESTRICTED_PKT && !restricted_mode) ||
		(!(rpkt.hdr.flags & RESTRICTED_PKT) && restricted_mode))
		return -1;

	dev_pos=ifs_get_pos(me.cur_ifs, me.cur_ifs_n, rpkt.dev);
	if(dev_pos < 0)
		debug(DBG_NORMAL, "The 0x%x ECHO_ME pkt was received by a non "
				"existent interface", rpkt.hdr.id);

	/* If we are hooking we reply only to others hooking nodes */
	if(me.cur_node->flags & MAP_HNODE) {
		if(rpkt.hdr.flags & HOOK_PKT) {
			memcpy(&echo_scans_count, rpkt.msg, sizeof(u_char));

			/* 
			 * So, we are hooking, but we haven't yet started the
			 * first scan or we have done less scans than rpkt.from,
			 * this means that this node, who is hooking
			 * too and sent us this rpkt, has started the hook 
			 * before us. If we are in a black zone, this flag
			 * will be used to decide which of the hooking nodes
			 * have to create the new gnode: if it is set we'll wait,
			 * the other hooking node will create the gnode, then we
			 * restart the hook. Clear?
			 */
			if(!radar_scan_mutex || echo_scans_count >= radar_scans[dev_pos])
				hook_retry=1;
		} else {
			/*debug(DBG_NOISE, "ECHO_ME pkt dropped: We are hooking");*/
			return 0;
		}
	}

	/* We create the ECHO_REPLY pkt */
	setzero(&pkt, sizeof(PACKET));
	pkt_addto(&pkt, &rpkt.from);
	pkt_addsk(&pkt, rpkt.from.family, rpkt.sk, SKT_UDP);

	if(me.cur_node->flags & MAP_HNODE) {
		/* 
		 * We attach in the ECHO_REPLY a flag that indicates if we have
		 * finished our radar_scan or not. This is usefull if we already
		 * sent all the ECHO_ME pkts of our radar scan and while we are
		 * waiting the MAX_RADAR_WAIT another node start the hooking:
		 * with this flag it can know if we came before him.
		 */
		u_char scanning=1;
		
		pkt.hdr.sz=sizeof(u_char);
		pkt.hdr.flags|=HOOK_PKT;
		pkt.msg=xmalloc(pkt.hdr.sz);
		if(radar_scans[dev_pos] == MAX_RADAR_SCANS)
			scanning=0;
		memcpy(pkt.msg, &scanning, sizeof(u_char));

		/* 
		 * W Poetry Palazzolo, the enlightening holy garden.
		 * Sat Mar 12 20:41:36 CET 2005 
		 */
	}
	
	if(restricted_mode)
		pkt.hdr.flags|=RESTRICTED_PKT;

	/* We send it */
	err=send_rq(&pkt, 0, ECHO_REPLY, rpkt.hdr.id, 0, 0, 0);
	pkt_free(&pkt, 0);
	if(err < 0) {
		error("radard(): Cannot send back the ECHO_REPLY to %s.", ntop);
		return -1;
	}

	/* 
	 * Ok, we have sent the reply, now we can update the radar_queue with
	 * calm.
	 */
	if(radar_q) {
		rq=add_radar_q(rpkt);
		rq->pings++;

#ifdef DEBUG
		if(server_opt.dbg_lvl && rq->pings==1 &&
				me.cur_node->flags & MAP_HNODE) {
			ntop=inet_to_str(pkt.to);
			debug(DBG_INSANE, "%s(0x%x) to %s", rq_to_str(ECHO_REPLY), 
					rpkt.hdr.id, ntop);
		}
#endif
	}
	return 0;
}

/* 
 * refresh_hook_root_node
 * 
 * At hooking the radar_scan doesn't have an int_map, so
 * all the nodes it found are stored in fake nodes. When we finish the hook,
 * instead, we have an int_map, so we convert all this fake nodes into real
 * nodes. To do this we modify each rq->node of the radar_queue and recall the
 * radar_update_map() func. 
 * rnode_list and qspn_b are also updated.
 * Note: the me.cur_node must be deleted prior the call of this function.
 */
int refresh_hook_root_node(void)
{
	struct radar_queue *rq;
	map_node *rnode;
	int ret;

	rq=radar_q;
	list_for(rq) {
		ret=iptomap((u_int)me.int_map, rq->ip, me.cur_quadg.ipstart[1], 
				&rnode);
		if(ret)
			rq->node=(map_node *)RADQ_EXT_RNODE;
		else
			rq->node=rnode;
	}

	radar_update_map();

	/* 
	 * Remove all the rnode_list structs which refers to the fake 
	 * rnodes.
	 */
	rnl_del_dead_rnode(&rlist, &rlist_counter, me.cur_node);

	/* Do the same for the qspn_b buffer */
	qspn_b_del_all_dead_rnodes();
	
	return 0;
}

/* 
 * radar_daemon
 * 
 * keeps the radar up until the end of the universe.
 */
void *radar_daemon(void *null)
{
	/* If `radar_daemon_ctl' is set to 0 the radar_daemon will stop.
	 * It will restart when it becomes again 1 */
	radar_daemon_ctl=1;
	
	debug(DBG_NORMAL, "Radar daemon up & running");
	for(;;) {
		while(!radar_daemon_ctl)
			sleep(1);

		radar_scan(1);
	}
}

/* 
 * radar_wait_new_scan
 * 
 * It sleeps until a new radar scan is sent 
 */
void radar_wait_new_scan(void)
{
	int old_echo_id, old_radar_wait_counter;
	
	old_echo_id=my_echo_id;
	old_radar_wait_counter=radar_wait_counter;

	for(; old_echo_id == my_echo_id; ) {
		usleep(505050);

		/* If the radar_wait_counter doesn't change, that means that
		 * the radar isn't active */
		if(radar_wait_counter == old_radar_wait_counter)
			break;
	}
}

/*EoW*/
