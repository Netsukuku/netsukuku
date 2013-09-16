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

#ifndef RADAR_H
#define RADAR_H

#define MAX_RADAR_SCANS		16
#define MAX_RADAR_WAIT		5	/*How much we wait to store the received
					  ECHO_REPLY pkts and then to close the
					  current radar session*/
#define RTT_DELTA		1000	/*If the change delta of the new rtt is
					  >= RTT_DELTA, the qspn_q.send_qspn 
					  will be set. (It's in millisec)*/

#ifdef DEBUG		
#undef MAX_RADAR_WAIT
#define MAX_RADAR_WAIT          3
#endif

int max_radar_wait;
int radar_wait_counter;			/* During the scan, it is incremented 
					   every 500 ms */

int radar_scans[MAX_INTERFACES];	/* How many ECHO_ME pkts we sent on 
					   each interface */
int total_radar_scans;			/* The sum of all the values of the 
					   `radar_scans' array */
int radar_scan_mutex;			/* A flag to see if we are already 
					   doing a scan */
int my_echo_id;			
u_char send_qspn_now[MAX_LEVELS];	/* Shall we send the qspn in level? 
					   If yes send_qspn_now[level] is 
					   != 0*/
int hook_retry;				/* If we've seen, while hooking, a 
					   node who was trying to hook before 
					   us, `hook_retry' is set to 1.*/
int radar_daemon_ctl;			/* If it is set to 0 the radar_daemon 
					   will stop until it becomes again 1*/
int total_radars;			/* Stupid statistic */

#define RADQ_VOID_RNODE		0
#define RADQ_EXT_RNODE		1

struct radar_queue
{
	LLIST_HDR	(struct radar_queue);

	inet_prefix	ip;			/*Node's ip*/
	interface	*dev[MAX_INTERFACES];	/*The pointers to the interface structs, present 
						  in me.cur_ifs, of the device where we got the 
						  node's pongs */
	int		dev_n;			/* Number of devices */
	
	map_node       *node;			/*The node we are pinging*/
	quadro_group	quadg;			/*Node's data for the ext_map*/
	u_short		flags;
				
	char 		pings;			/*The total ECHO_ME pkts received from this node*/
	char 		pongs;			/*The total pongs (ECHO_REPLY) received from this node*/
	struct timeval 	rtt[MAX_RADAR_SCANS];	/*The round rtt of each pong*/
	struct timeval 	final_rtt;		/*When all the rtt is filled, or when MAX_RADAR_WAIT
						  is expired, final_rtt will keep the average of all
						  the rtts */
};
struct radar_queue *radar_q;	/*the start of the linked list of radar_queue*/
int radar_q_counter;

struct timeval scan_start;	/*the start of the scan*/

/*
 * rnode_list keeps the list of all the rnodes. It is used to know on what
 * interface can be reached a wanted rnode.
 */
struct rnode_list
{
	LLIST_HDR	(struct rnode_list);

	map_node	*node;			/* The node which is pointed by this 
						   rnode */
	interface       *dev[MAX_INTERFACES];	/* The pointers to the interface structs
						   (in me.cur_ifs), which cointains the
						   devices which links ourself with this rnode. */
	int		dev_n;

	int		tcp_sk;			/* The direct tcp connection to this rnode uses
						   this socket. */
};
struct rnode_list *rlist;
int rlist_counter;

/*
 * When this list isn't empty, the radar will receive only the ECHO_REPLY sent
 * from rnodes which are in the allowed_rnode list.
 */
struct allowed_rnode
{
	LLIST_HDR	(struct allowed_rnode);
	
	/* 
	 * In order to see if the rnode X is part of this list we compare all
	 * its gids in the range of gids[min_level] and gids[tot_level-1] with
	 * the allowed_rnode.gid array.
	 */
	u_char 		min_level;
	u_char		tot_level;
	u_int		gid[MAX_LEVELS];
};
struct allowed_rnode *alwd_rnodes;
int alwd_rnodes_counter;

/* 
 * The ECHO_ME pkt:
 * It is just a normal pkt which contains in the body (pkt.msg) one 
 * u_char echo_scans_count, var. This is the number of scans sent.
 */

/*
 * During the hooking the ECHO_REPLY body pkt is one u_char which is set to 0
 * if we already finished our scans.
 */

/* * * Functions declaration * * */
void first_init_radar(void);
void last_close_radar(void);
void init_radar(void);
void close_radar(void);
void reset_radar(void);
void free_new_node(void);

struct radar_queue *find_node_radar_q(map_node *node);
struct radar_queue *find_ip_radar_q(inet_prefix *ip);
int count_hooking_nodes(void);

void rnl_reset(struct rnode_list **rnlist, int *rnlist_counter);
interface **rnl_get_dev(struct rnode_list *rnlist, map_node *node);
interface *rnl_get_rand_dev(struct rnode_list *rnlist, map_node *node);
int rnl_get_sk(struct rnode_list *rnlist, map_node *node);
void rnl_close_all_sk(struct rnode_list *rnlist);
int rnl_fill_rq(map_node *rnode, PACKET *pkt);
int rnl_send_rq(map_node *rnode, 
		PACKET *pkt, int pkt_flags, u_char rq, int rq_id, u_char re, 
		int check_ack, PACKET *rpkt);

void new_rnode_allowed(struct allowed_rnode **alr, int *alr_counter,
		int *gid, int min_lvl, int max_lvl);
void reset_rnode_allowed(struct allowed_rnode **alr, int *alr_counter);

void final_radar_queue(void);
void radar_update_map(void);

struct radar_queue *add_radar_q(PACKET pkt);
int radar_exec_reply(PACKET pkt);
int radar_scan(int activate_qspn);
int radard(PACKET rpkt);
int radar_recv_reply(PACKET pkt);
void *radar_daemon(void *null);
void radar_wait_new_scan(void);

int refresh_hook_root_node(void);

#endif /*RADAR_H*/
