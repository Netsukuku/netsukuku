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

#ifndef NETSUKUKU_H
#define NETSUKUKU_H

#include "config.h"
#include "igs.h"

#define VERSION_STR				"NetsukukuD "VERSION

#ifdef DEBUG
#undef VERSION_STR
#define VERSION_STR				"NetsukukuD "VERSION" (debug)"
#endif

/*
 * current_globals
 *
 * Here there are the main globals variables used among the code.
 */
struct current_globals
{
	/* 
	 * Internal map 
	 */
	map_node	*int_map;	/*Internal Map*/
	
	/* 
	 * External map 
	 */
	map_gnode	**ext_map;	/*External Map. */
	quadro_group	cur_quadg;
	
	/* 
	 * Border nodes maps.(bmap.h) 
	 */
	map_bnode	**bnode_map;
	u_int 		*bmap_nodes;		/* bnode counter for each map*/
	u_int		*bmap_nodes_closed;	/* number of closed bnodes   */
	u_int		*bmap_nodes_opened;	/*   "     " opened   "      */
	
	/* 
	 * Myself
	 */
	inet_prefix	cur_ip;
	map_node	*cur_node;

	/* 
	 * external rnode cache list. (see gmap.h) 
	 */
	ext_rnode_cache	*cur_erc;
	u_int		cur_erc_counter;

	/* 
	 * Current Qspn id and qspn time 
	 */
	int		*cur_qspn_id;	/*The current qspn_id we are processing. 
					  It is cur_qspn_id[levels] big*/
	struct timeval	*cur_qspn_time; /*When the last qspn round was received/sent 
					  (gettimeofday format)*/
	/*
	 * Internet gateways 
	 */
	inet_gw		**igws;
	int		*igws_counter;
	inet_gw		**my_igws;	/* my_igws[level] points to our inet gateway
					   present at igws[level]. It's the same of using
					   igw_find_node(igws, me.cur_quadg.gnode[_EL(level)]); */
	u_char		my_bandwidth;	/* The bandwidth of the Internet connection 
					   we are sharing*/
	u_char		inet_connected; /* If it is 1, we are connected to the Internet */
	
	/* 
	 * Network interfaces 
	 */
	interface	cur_ifs[MAX_INTERFACES];
	int		cur_ifs_n;	/* number of interfaces present
					   in `cur_ifs' */

	time_t		uptime;		/*The time when we finished the hooking, 
					  to get the the actual uptime just do: 
					  time(0)-me.uptime*/
}me;

#define NTK_TCP_PORT		269
#define NTK_UDP_RADAR_PORT	269

#define ANDNA_UDP_PORT 	   	277
#define ANDNA_TCP_PORT		277

const static u_short ntk_udp_radar_port	= NTK_UDP_RADAR_PORT,
		     ntk_tcp_port	= NTK_TCP_PORT;
const static u_short andna_udp_port	= ANDNA_UDP_PORT,
		     andna_tcp_port	= ANDNA_TCP_PORT;

#define NTK_CONFIG_FILE		CONF_DIR "/netsukuku.conf"
#define NTK_PID_FILE		PID_DIR  "/ntkd.pid"


#define INT_MAP_FILE		DATA_DIR "/ntk_internal_map"
#define EXT_MAP_FILE		DATA_DIR "/ntk_external_map"
#define BNODE_MAP_FILE		DATA_DIR "/ntk_bnode_map"

#define ANDNA_HNAMES_FILE	CONF_DIR "/andna_hostnames"
#define SNSD_NODES_FILE		CONF_DIR "/snsd_nodes"
#define ANDNA_CACHE_FILE	DATA_DIR "/andna_cache"
#define LCLKEY_FILE		DATA_DIR "/andna_lcl_keyring"
#define LCL_FILE		DATA_DIR "/andna_lcl_cache"
#define RHC_FILE		DATA_DIR "/andna_rh_cache"
#define COUNTER_C_FILE		DATA_DIR "/andna_counter_cache"

#define IPMASQ_SCRIPT_FILE	CONF_DIR "/ip_masquerade.sh"
#define TCSHAPER_SCRIPT_FILE	CONF_DIR "/tc_shaper.sh"

/*
 * ServOpt
 *
 * Options
 */
typedef struct
{
	char		*config_file;
	char		*pid_file;
	
	int 		family;

	char		*ifs[MAX_INTERFACES];
	int		ifs_n;	/* number of interfaces present in `ifs' */
	
	char 		*int_map_file;
	char 		*ext_map_file;
	char 		*bnode_map_file;

	char		*andna_hnames_file;
	char		*snsd_nodes_file;
	char 		*andna_cache_file;
	char 		*lclkey_file;
	char 		*lcl_file;
	char		*rhc_file;
	char 		*counter_c_file;

	char 		daemon;
	
	char 		restricted;
	int		restricted_class;
	char		inet_connection;/* If it's 1, we are connected 
					   to the Internet */
	char		share_internet;
	char		shape_internet;
	char		use_shared_inet;
	inet_prefix	inet_gw;
	char		*inet_gw_dev;
	char		**inet_hosts;	/* Hosts to be pinged in order to check
					   if the internet connection is up */
	int 		inet_hosts_counter;
	char		*ip_masq_script;
	char		*tc_shaper_script;
	
	/* The bandwidths of the Internet connection we are sharing.
	 * If we are just leeching they are all 0. */
	u_int 		my_upload_bw;
	u_int		my_dnload_bw;

	char		disable_andna;
	char		disable_resolvconf;

	int 		max_connections;
	int 		max_accepts_per_host;
	int 		max_accepts_per_host_time;
	
	char 		dbg_lvl;
}ServOpt;
ServOpt server_opt;

time_t sigterm_timestamp, sighup_timestamp, sigalrm_timestamp;

#endif /*NETSUKUKU_H*/
