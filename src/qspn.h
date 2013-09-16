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

#ifndef QSPN_H
#define QSPN_H

#include "gmap.h"

#define QSPN_WAIT_ROUND 	32	/*This is a crucial value. It is the number of 
					  seconds to be waited before the next qspn_round 
					  can be sent*/
#define QSPN_WAIT_ROUND_MS	QSPN_WAIT_ROUND*1000
#define QSPN_WAIT_DELTA_MS	64	/*If a qspn_round is sent while 
					  qspn_round_left() < QSPN_WAIT_DELTA_MS,
					  then it is acceptable*/

#ifdef DEBUG
#undef QSPN_WAIT_ROUND
#define QSPN_WAIT_ROUND		8
#endif

/*Wait time bound to a specific level:	y = (w/2)*x  + w/(x+1) */
#define QSPN_WAIT_ROUND_LVL(level) ((level)*(QSPN_WAIT_ROUND/2) + 	       \
					QSPN_WAIT_ROUND/((level)+1))
#define QSPN_WAIT_ROUND_MS_LVL(level) (QSPN_WAIT_ROUND_LVL(level)*1000)

/* The delta grows in this way:  y = x*(w/2) + 2*w*x + w; */
#define QSPN_WAIT_DELTA_MS_LVL(level) ((level)*(QSPN_WAIT_DELTA_MS/2) +	       \
		2*QSPN_WAIT_DELTA_MS*(level) + QSPN_WAIT_DELTA_MS)


/* This list keeps tracks of the qspn_pkts sent or
 * received by our rnodes*/
struct qspn_buffer
{	
	LLIST_HDR	(struct qspn_buffer);
	
	map_node      *	rnode;		/* the rnode this buf is referring to */
	u_int	 	replies;	/* How many replies we forwarded/sent
					   to `rnode' */
	u_char	      * replier;	/* Who has sent these replies (qspn_sub_id) */
	u_short	      * flags;
};


/*
 *  *  *  Global vars  *  *  *
 */

struct qspn_buffer **qspn_b; /*It is sizeof(struct qspn_buffer *)*levels big*/

int *qspn_send_mutex;	     /*It is sizeof(int)*levels big.*/

#define GCOUNT_LEVELS		(MAX_LEVELS-ZERO_LEVEL+UNITY_LEVEL)
/*
 * qspn_gnode_count[x] is the number of nodes present in the gnode
 * me.cur_quadg.gnode[x], it is updated at each qspn_round.
 * Use the _EL() macro!
 */ 
u_int qspn_gnode_count[GCOUNT_LEVELS];

/* gcount of the previous qspn_round */
u_int qspn_old_gcount[GCOUNT_LEVELS]; 


/*
 *  *  Functions declaration  *  *
 */
void qspn_time_reset(int start_level, int end_level, int levels);
void qspn_reset_counters(u_char levels);
void qspn_reset(u_char levels);
void qspn_init(u_char levels);
void qspn_free(void);
void qspn_set_map_vars(u_char level, map_node **map, map_node **root_node, 
		int *root_node_pos, map_gnode **gmap);

void qspn_b_clean(u_char level);
int  qspn_b_add(struct qspn_buffer *qb, u_char replier, u_short flags);
int  qspn_b_find_reply(struct qspn_buffer *qb, int sub_id);
struct qspn_buffer *qspn_b_find_rnode(struct qspn_buffer *qb, map_node *rnode);
int qspn_b_del_dead_rnodes(struct qspn_buffer **qb, map_node *root_node);
void qspn_b_del_all_dead_rnodes(void);

int  qspn_round_left(u_char level);
void update_qspn_time(u_char level, u_int new_qspn_time);

void qspn_inc_gcount(u_int *gcount, int level, int inc);
void qspn_dec_gcount(u_int *gcount, int level, int dec);
void qspn_reset_gcount(u_int *gcount, int level, int value);
void qspn_backup_gcount(u_int *old_gcount, int *gcount);

void qspn_new_round(u_char level, int new_qspn_id, u_int new_qspn_time);

int  qspn_send(u_char level);
int  qspn_close(PACKET rpkt);
int  qspn_open(PACKET rpkt);

#endif /*QSPN_H*/
