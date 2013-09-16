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

/*These define are used to activate/deactivate the different parts of QSPN*/
#undef Q_BACKPRO
#define Q_OPEN
#undef NO_JOINT

/*
 *			 	Map stuff
 * Here below there are all the structures and defines you can find in map.h,
 * but here are slightly modified.
 */

#define MAXGROUPNODE		20
#define MAXROUTES	 	5
#define MAXRTT			10		/*Max node <--> node rtt (in sec)*/
#define MAXLINKS		MAXROUTES

/*** flags ***/
#define MAP_ME		1		/*The root_node, in other words, me ;)*/
#define MAP_VOID	(1<<1)		/*It indicates a non existent node*/
#define MAP_HNODE	(1<<2)		/*Hooking node. The node is currently 
					  hooking*/
#define MAP_BNODE	(1<<3)		/*The node is a border_node. If this 
					  flag is set to a root_node, this means 
					  that we are a bnode at the root_node's 
					  level*/
#define MAP_ERNODE	(1<<4)		/*It is an External Rnode*/
#define MAP_GNODE	(1<<5)		/*It is a gnode*/
#define MAP_RNODE	(1<<6)		/*If a node has this set, it is one of the rnodes*/
#define MAP_UPDATE	(1<<7)		/*If it is set, the corresponding route 
					  in the krnl will be updated*/
#define QSPN_CLOSED	(1<<8)		/*This flag is set only to the rnodes, 
					  it puts a link in a QSPN_CLOSED state*/
#define QSPN_OPENED	(1<<9)		/*It puts a link in a QSPN_OPEN state*/
#define QSPN_OLD	(1<<10)		/*If a node isn't updated by the current
					  qspn_round it is marked with QSPN_ROUND.
					  If in the next qspn_round the same node 
					  isn't updated it is removed from the map.*/
#define QSPN_STARTER	(1<<11)		/*The root node is marked with this flag
					  if it is a qspn_starter*/
#define QSPN_OPENER	(1<<12)		/*If the root_node sent a new qspn_open
					  it is a qspn_opener*/
#define QSPN_BACKPRO	(1<<13)	

typedef struct
{
	u_short		flags;
	int	 	*r_node;	/*It's the pointer to the struct of the
					  r_node in the map*/
	struct timeval	rtt;	 	/*node <-> r_node round trip time
					  (in millisec)*/
	struct timeval	trtt;		
}map_rnode;

typedef struct
{
	u_int		flags;
	u_int		brdcast[MAXGROUPNODE];
	u_short		links;		 /*Number of r_nodes*/
	map_rnode	*r_node;	 /*These structs will be kept in ascending
					   order considering their rnode_t.rtt*/
}map_node;

INT_INFO map_rnode_iinfo  = { 3, 
			      { INT_TYPE_32BIT, INT_TYPE_32BIT, INT_TYPE_32BIT },
			      { 0, sizeof(int), sizeof(int)*2 },
			      { 1, 1, 1 }
			    };
#define MAP_RNODE_PACK_SZ (sizeof(int *)+sizeof(u_int)*2)
INT_INFO map_node_iinfo = { 3, 
			    { INT_TYPE_16BIT, INT_TYPE_32BIT, INT_TYPE_16BIT },
			    { 0, sizeof(short), sizeof(short)+sizeof(int) },
			    { 1, 1, 1 }
			  };

#define MAP_NODE_PACK_SZ (sizeof(u_short)*2 + sizeof(u_int))

#define MAXRNODEBLOCK		(MAXLINKS * MAXGROUPNODE * sizeof(map_rnode))
#define MAXRNODEBLOCK_PACK_SZ	(MAXLINKS * MAXGROUPNODE * MAP_RNODE_PACK_SZ)
#define INTMAP_END(mapstart)	((sizeof(map_node)*MAXGROUPNODE)+(mapstart))

struct int_map_hdr
{
	u_char root_node;
	size_t int_map_sz;
	size_t rblock_sz;
}_PACKED_;
INT_INFO int_map_hdr_iinfo = { 2, 
			       { INT_TYPE_32BIT, INT_TYPE_32BIT }, 
			       { sizeof(char), sizeof(char)+sizeof(size_t) },
			       { 1, 1 }
			     };
#define INT_MAP_BLOCK_SZ(int_map_sz, rblock_sz) (sizeof(struct int_map_hdr)+(int_map_sz)+(rblock_sz))


/*
 * 	* Qspn-empiric stuff begins here *	*
 */


pthread_mutex_t mutex[MAXGROUPNODE];
int total_threads=0, disable_joint=0;


map_node *int_map;

/*This struct keeps tracks of the qspn_pkts sent or received by our rnodes*/
struct qspn_queue
{
	int 	q_id;			/*qspn_id*/
	u_short replier[MAXGROUPNODE];	/*Who has sent these repliesi (qspn_sub_id)*/
	u_short	flags[MAXGROUPNODE];
}*qspn_q[MAXGROUPNODE];

struct qstat
{
	int total_pkts;
	int qspn_requests;
	int qspn_replies;
	int qspn_backpro;
};

int time_stat;
struct qstat gbl_stat;
struct qstat node_stat[MAXGROUPNODE];
short rt_stat[MAXGROUPNODE][MAXGROUPNODE];
short rt_total[MAXGROUPNODE];


#define OP_REQUEST 	82
#define OP_CLOSE 	OP_REQUEST
#define OP_OPEN 	28
#define OP_REPLY	69
#define OP_BACKPRO	66

#define QPKT_REPLY	1

struct q_pkt
{
	int q_id;
	int q_sub_id;
	short from;
	short to;
	int   broadcast;
	char  op;
	char  flags;
	short *tracer;
	short routes;
};

struct q_pkt **pkt_db[MAXGROUPNODE];
int pkt_dbc[MAXGROUPNODE];

struct q_opt
{
	struct q_pkt q;
	int sleep;
	int join;
};

void thread_joint(int joint, void * (*start_routine)(void *), void *nopt);
void gen_rnd_map(int start_node, int back_link, int back_link_rtt);
int print_map(map_node *map, char *map_file);
void *show_temp_stat(void *);
void print_data(char *file);
int store_tracer_pkt(struct q_opt *qopt);
void *send_qspn_backpro(void *argv);
void *send_qspn_reply(void *argv);
void *send_qspn_pkt(void *argv);
