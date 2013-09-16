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

#ifndef IGS_H
#define IGS_H

#include "route.h"


/*
 * The IGS_MULTI_GW feature relies heavily on netfilter and the linux advanced
 * routing.
 */
#ifdef GNU_LINUX
#define IGS_MULTI_GW
#endif

/*\
 *		 	* Bandwidth notes *
 *
 * When we talk of `bandwidth' we mean the average of the download and 
 * upload bandwidth of a particular node.
 * The bandwidth of a gnode is the average of all the bandwidths of the nodes
 * belonging to that gnode.
 * 
 * Internally we save the `bandwidth' as a u_char variable using the
 * `bandwidth_in_8bit' function (see igs.c)
\*/

/* Minum bandwidth necessary to share an internet connection */
#define MIN_CONN_BANDWIDTH	3		/* 16 Kb/s */

#define MAX_INTERNET_HNAMES	10
#define MAX_INTERNET_HNAME_SZ	64
#define INET_HOST_PING_TIMEOUT	3
#define IGW_HOST_PING_TIMEOUT	10
#define INET_NEXT_PING_WAIT	10

#define IGW_BW_DELTA		1		/* If the difference between the old and the new
						   igw->bandwidth is >= IGW_BW_DELTA, then 
						   me.igws is reordered and the routing table
						   updated */
#define MAXIGWS			MAXGROUPNODE	/* max number of internet 
						   gateways in each level */

#define RTTABLE_IGW		221		/* Routing tables from 221 to 244 */
#define RTTABLE_ALISHIELD	245		/* Anti Loop multi-Igw Shield
						   (what a damn long name, read the Ntk_IGS
						   RFC) */
#define FWMARK_ALISHIELD	25

#ifdef DEBUG
#undef INET_NEXT_PING_WAIT
#define INET_NEXT_PING_WAIT	5
#endif

/* 
 * inet_gw flags
 */
#define IGW_TUNNELED		1
#define IGW_ACTIVE		(1<<1)		/* This gw is being used in the
						   routing table */
#define IGW_RTRULE		(1<<2)		/* The relative routing rule is already
						   present */

/*
 * internet_gateway
 * 
 * This struct points to a particular (g)node which is sharing its Internet 
 * connection
 */
struct internet_gateway
{
	LLIST_HDR	(struct internet_gateway);

	u_int		ip[MAX_IP_INT];
	u_char		gid;
	map_node	*node;

	char		flags;
	u_char		bandwidth;	/* Its Internet bandwidth */
};
typedef struct internet_gateway inet_gw;

/* We pack only `gid' and `bandwidth' */
#define INET_GW_PACK_SZ		(sizeof(u_char)*2 + MAX_IP_SZ)

struct inet_gw_pack_hdr
{
	int16_t		gws[MAX_LEVELS];/* Number of inet_gws there are in the
					   pack, for each level */
	u_char		levels;
}_PACKED_;
INT_INFO inet_gw_pack_hdr_iinfo = { 1, { INT_TYPE_16BIT }, { 0 }, { MAX_LEVELS } };

/* 
 * The inet_gw_pack_body is:
 * 	inet_gw_pack	igw[hdr.gws[i]]	   for all the i that goes from 0 to
 * 					   hdr.levels
 */
#define IGWS_PACK_SZ(hdr)						\
({									\
	size_t _sz; int _pi;						\
	_sz=sizeof(struct inet_gw_pack_hdr);				\
	for(_pi=0; _pi<(hdr)->levels; _pi++)				\
		_sz+=INET_GW_PACK_SZ*((hdr)->gws[_pi]);			\
	_sz;								\
})

#define MAX_IGWS_PACK_SZ(levels)	(sizeof(struct inet_gw_pack_hdr) + \
						INET_GW_PACK_SZ*MAXIGWS*(levels))


/*\
 *
 *  *  *  Multi Internet Gateways  *  *  *
 *
\*/

/*
 * igw_nexthop
 * 
 * The multigw allows the simultaneus use of multiple internet gateways.
 * The multigw requires one routing table and one tunnel for each
 * nexthop in the default multipath route. With an array of `igw_nexthop' we
 * keep track of them.
 */
struct default_inet_gw_nexthop {
	inet_prefix	nexthop;

	u_char		flags;		/* inet_gw flags */
	
	u_char		table;
	u_char		tunl;		/* `tunl' is the number of the tunnel
					   we are using to reach this igw. 
					   (tunl = 4 means we are using the 
					   "tunl4" device) */
};
typedef struct default_inet_gw_nexthop igw_nexthop;


/*\
 * 		Notes on the IGW packed in a qspn pkt
 *
 * The simplest way to tell the other nodes that we are sharing our Internet
 * connection or that in our gnode there is an available gw is to use the
 * bnode block included in the qspn packets.
 * We consider an Internet gw as a bnode connected to a virtual gnode (the
 * Internet), therefore in the relative bnode_chunk we set:
 * 	bchunk.gnode	= 0; this value has no meaning
 *	bchunk.level	= GET_LEVELS(my_family) + 1;
 *	bchunk.rtt	= the bandwidth of the internet connection of the gw.
 *			  It is in the bandwidth_in_8bit() format.
\*/

#define MAX_IGW_PER_QSPN_CHUNK		16	/* Maximum number of IGWs 
						   contained in a single 
						   QSPN chunk */


/*\
 *
 * * *  Globals  * * *
 *
\*/

int active_gws;
igw_nexthop multigw_nh[MAX_MULTIPATH_ROUTES];


/*\
 *
 * * *  Functions declaration  * * 
 *
\*/

u_char bandwidth_in_8bit(u_int x);
int str_to_inet_gw(char *str, inet_prefix *gw, char **dev);
char **parse_internet_hosts(char *str, int *hosts);
void free_internet_hosts(char **hnames, int hosts);

void init_my_igw(void);
void init_igws(inet_gw ***igws, int **igws_counter, int levels);
void reset_igws(inet_gw **igws, int *igws_counter, int levels);
void free_igws(inet_gw **igws, int *igws_counter, int levels);
void init_my_igws(inet_gw **igws, int *igws_counter,
		inet_gw ***my_new_igws, u_char my_bandwidth, 
		map_node *cur_node, quadro_group *qg);
void free_my_igws(inet_gw ***my_igs);
void init_internet_gateway_search(void);
void close_internet_gateway_search(void);
inet_gw *igw_add_node(inet_gw **igws, int *igws_counter,  int level,
		int gid, map_node *node, int ip[MAX_IP_INT], u_char bandwidth);
int igw_del(inet_gw **igws, int *igws_counter, inet_gw *igw, int level);
inet_gw *igw_find_node(inet_gw **igws, int level, map_node *node);
inet_gw *igw_find_ip(inet_gw **igws, int level, u_int ip[MAX_IP_INT]);
int igw_del_node(inet_gw **, int *,  int, map_node *);
void igw_update_gnode_bw(int *, inet_gw **, inet_gw *, int, int, int);
void igw_order(inet_gw **igws, int *igws_counter, inet_gw **my_igws, int level);

int igw_check_inet_conn(void);
void *igw_check_inet_conn_t(void *null);
void *igw_monitor_igws_t(void *null);

int igw_exec_masquerade_sh(char *script, int stop);
int igw_exec_tcshaper_sh(char *script, int stop, 
		char *dev, int upload_bw, int dnload_bw);
void reset_igw_nexthop(igw_nexthop *igwn);
void reset_igw_rules(void);
int igw_replace_def_igws(inet_gw **igws, int *igws_counter, 
		inet_gw **my_igws, int max_levels, int family);

char *igw_build_bentry(u_char level, size_t *pack_sz, int *new_bblocks);
int igw_store_bblock(bnode_hdr *bblock_hdr, bnode_chunk *bchunk, u_char level);
char *pack_igws(inet_gw **igws, int *igws_counter, int levels, int *pack_sz);
int unpack_igws(char *pack, size_t pack_sz,
		map_node *int_map, map_gnode **ext_map, int levels,
		inet_gw ***new_igws, int **new_igws_counter);

#endif /*IGS_H*/
