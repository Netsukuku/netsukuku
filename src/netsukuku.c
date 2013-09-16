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
 * netsukuku.c:
 * Where main() resides.
 */

#include "includes.h"

#include "common.h"
#include "conf.h"
#include "libnetlink.h"
#include "ll_map.h"
#include "request.h"
#include "pkts.h"
#include "if.h"
#include "bmap.h"
#include "netsukuku.h"
#include "qspn.h"
#include "accept.h"
#include "daemon.h"
#include "crypto.h"
#include "andna_cache.h"
#include "andna.h"
#include "radar.h"
#include "hook.h"
#include "rehook.h"


extern int errno;
extern char *optarg;
extern int optind, opterr, optopt;

int destroy_netsukuku_mutex;
int pid_saved;

int options_parsed=0; /* How many times parse_options() has been called */

void save_pid(void)
{
	FILE *fd;

	if(!(fd=fopen(server_opt.pid_file, "w")))
		error("Couldn't create pid file \"%s\": %s",
				server_opt.pid_file, strerror(errno));
	fprintf(fd, "ntkd %ld\n", (long) getpid());

	fclose(fd);
	pid_saved=1;
}

/*
 * is_ntkd_already_running
 *
 * Returns 1 if there's already a ntkd running
 */
int is_ntkd_already_running(void)
{
	pid_t oldpid;
	FILE *fd;

	if(!(fd=fopen(server_opt.pid_file, "r"))) {
		if(errno != ENOENT)
			error("Cannot read pid file \"%s\": %s", 
					server_opt.pid_file, strerror(errno));
		return 0;
	}

	fscanf(fd, "ntkd %d\n", &oldpid);
        if(ferror(fd)) {
		error("error reading pid file \"%s\": %s\n", 
				server_opt.pid_file, strerror(errno));
		fclose(fd);
		return 0;
	}
	fclose(fd);

	return !kill(oldpid, 0);
}

int ntk_load_maps(void)
{
	if(file_exist(server_opt.int_map_file) && 
				(me.int_map=load_map(server_opt.int_map_file,
						     &me.cur_node)))
		debug(DBG_NORMAL, "Internal map loaded");
	else
		me.int_map=init_map(0);

#if 0 
	/* Don't load the bnode map, it's useless */
	if((me.bnode_map=load_bmap(server_opt.bnode_map_file, me.ext_map,
					FAMILY_LVLS, &me.bmap_nodes))) {
		debug(DBG_NORMAL, "Bnode map loaded");
	} else
#endif
	bmap_levels_init(BMAP_LEVELS(FAMILY_LVLS), &me.bnode_map,
				&me.bmap_nodes);
	bmap_counter_init(BMAP_LEVELS(FAMILY_LVLS), &me.bmap_nodes_closed, 
			&me.bmap_nodes_opened);

	if(file_exist(server_opt.ext_map_file) && 
			(me.ext_map=load_extmap(server_opt.ext_map_file, 
						&me.cur_quadg)))
		debug(DBG_NORMAL, "External map loaded");
	else
		me.ext_map=init_extmap(FAMILY_LVLS, 0);
	
	return 0;
}

int ntk_save_maps(void)
{
	debug(DBG_NORMAL, "Saving the internal map");
	save_map(me.int_map, me.cur_node, server_opt.int_map_file);

#ifdef DEBUG
	debug(DBG_NORMAL, "Saving the border nodes map");
	save_bmap(me.bnode_map, me.bmap_nodes, me.ext_map, me.cur_quadg, 
			server_opt.bnode_map_file);
#endif
	
	debug(DBG_NORMAL, "Saving the external map");
	save_extmap(me.ext_map, MAXGROUPNODE, &me.cur_quadg, 
			server_opt.ext_map_file);

	return 0;
}

int ntk_free_maps(void)
{
	bmap_levels_free(me.bnode_map, me.bmap_nodes);
	bmap_counter_free(me.bmap_nodes_closed, me.bmap_nodes_opened);
	free_extmap(me.ext_map, FAMILY_LVLS, 0);
	free_map(me.int_map, 0);

	return 0;
}

void usage(void)
{
	printf("Usage:\n"
		"     ntkd [-hvaldrRD46] [-i net_interface] [-c conf_file] [-l logfile]\n\n"
		" -4	ipv4\n"
		" -6	ipv6\n"
		" -i	interface\n\n"
		" -a	do not run the ANDNA daemon\n"
		" -R	do not edit /etc/resolv.conf\n"
		" -D	no daemon mode\n"
		"\n"
		" -r	run in restricted mode\n"
		" -m	share your internet connection\n"
		"\n"
		" -c	configuration file\n"
		" -l	log to file\n"
		"\n"
		" -d	debug (more d, more info)\n"
		" -h	this help\n"
		" -v	version\n");
}

/*
 * fill_default_options: fills the default values in the server_opt struct
 */
void fill_default_options(void)
{
	setzero(&server_opt, sizeof(server_opt));
	
	server_opt.family=AF_INET;
	
	server_opt.config_file=NTK_CONFIG_FILE;
	server_opt.pid_file=NTK_PID_FILE;

	server_opt.int_map_file=INT_MAP_FILE;
	server_opt.ext_map_file=EXT_MAP_FILE;
	server_opt.bnode_map_file=BNODE_MAP_FILE;

	server_opt.andna_hnames_file=ANDNA_HNAMES_FILE;
	server_opt.snsd_nodes_file=SNSD_NODES_FILE;
	server_opt.andna_cache_file=ANDNA_CACHE_FILE;
	server_opt.lclkey_file=LCLKEY_FILE;
	server_opt.lcl_file=LCL_FILE;
	server_opt.rhc_file=RHC_FILE;
	server_opt.counter_c_file=COUNTER_C_FILE;

	server_opt.daemon=1;
	server_opt.dbg_lvl=0;

	server_opt.disable_andna=0;
	server_opt.disable_resolvconf=0;
	server_opt.restricted=0;
	server_opt.restricted_class=0;

	server_opt.use_shared_inet=1;

	server_opt.ip_masq_script=IPMASQ_SCRIPT_FILE;
	server_opt.tc_shaper_script=TCSHAPER_SCRIPT_FILE;

	server_opt.max_connections=MAX_CONNECTIONS;
	server_opt.max_accepts_per_host=MAX_ACCEPTS;
	server_opt.max_accepts_per_host_time=FREE_ACCEPT_TIME;
}

/*
 * fill_loaded_cfg_options
 *
 * stores in server_opt the options loaded from the configuration file
 */
void fill_loaded_cfg_options(void)
{
	char *value;

	CONF_GET_STRN_VALUE ( CONF_NTK_INT_MAP_FILE, &server_opt.int_map_file, NAME_MAX-1  );
	CONF_GET_STRN_VALUE ( CONF_NTK_BNODE_MAP_FILE, &server_opt.bnode_map_file, NAME_MAX-1 );
	CONF_GET_STRN_VALUE ( CONF_NTK_EXT_MAP_FILE, &server_opt.ext_map_file, NAME_MAX-1 );

	CONF_GET_STRN_VALUE ( CONF_ANDNA_HNAMES_FILE, &server_opt.andna_hnames_file, NAME_MAX-1 );
	CONF_GET_STRN_VALUE ( CONF_SNSD_NODES_FILE, &server_opt.snsd_nodes_file, NAME_MAX-1 );

	CONF_GET_STRN_VALUE ( CONF_ANDNA_CACHE_FILE, &server_opt.andna_cache_file, NAME_MAX-1 );
	CONF_GET_STRN_VALUE ( CONF_ANDNA_LCLKEY_FILE, &server_opt.lclkey_file, NAME_MAX-1 );
	CONF_GET_STRN_VALUE ( CONF_ANDNA_LCL_FILE, &server_opt.lcl_file, NAME_MAX-1 );
	CONF_GET_STRN_VALUE ( CONF_ANDNA_RHC_FILE, &server_opt.rhc_file, NAME_MAX-1 );
	CONF_GET_STRN_VALUE ( CONF_ANDNA_COUNTER_C_FILE, &server_opt.counter_c_file, NAME_MAX-1 );

	CONF_GET_STRN_VALUE ( CONF_NTK_PID_FILE, &server_opt.pid_file, NAME_MAX-1 );
	CONF_GET_INT_VALUE ( CONF_NTK_MAX_CONNECTIONS, server_opt.max_connections );
	CONF_GET_INT_VALUE ( CONF_NTK_MAX_ACCEPTS_PER_HOST, server_opt.max_accepts_per_host );
	CONF_GET_INT_VALUE ( CONF_NTK_MAX_ACCEPTS_PER_HOST_TIME, server_opt.max_accepts_per_host_time );

	CONF_GET_INT_VALUE ( CONF_DISABLE_ANDNA, server_opt.disable_andna );
	CONF_GET_INT_VALUE ( CONF_DISABLE_RESOLVCONF, server_opt.disable_resolvconf );
	CONF_GET_INT_VALUE ( CONF_NTK_RESTRICTED_MODE, server_opt.restricted );
	CONF_GET_INT_VALUE ( CONF_NTK_RESTRICTED_CLASS, server_opt.restricted_class );

	CONF_GET_INT_VALUE ( CONF_NTK_INTERNET_CONNECTION, server_opt.inet_connection);
	if((value=CONF_GET_VALUE(CONF_NTK_INTERNET_GW))) {
		if(str_to_inet_gw(value, &server_opt.inet_gw, 
					&server_opt.inet_gw_dev))
			fatal("Malformed `%s' option: \"%s\". Its syntax is \"IP:dev\"",
					config_str[CONF_NTK_INTERNET_GW], value);
	}
	CONF_GET_INT_VALUE ( CONF_NTK_INTERNET_UPLOAD, server_opt.my_upload_bw );
	CONF_GET_INT_VALUE ( CONF_NTK_INTERNET_DOWNLOAD, server_opt.my_dnload_bw );
	if(server_opt.my_upload_bw && server_opt.my_dnload_bw)
		me.my_bandwidth =
			bandwidth_in_8bit((server_opt.my_upload_bw+server_opt.my_dnload_bw)/2);

	if((value=CONF_GET_VALUE(CONF_NTK_INTERNET_PING_HOSTS))) {
		server_opt.inet_hosts=parse_internet_hosts(value, 
				&server_opt.inet_hosts_counter);
		if(!server_opt.inet_hosts)
			fatal("Malformed `%s' option: \"%s\". "
				"Its syntax is host1:host2:...",
				config_str[CONF_NTK_INTERNET_PING_HOSTS], value);
	}
	CONF_GET_INT_VALUE ( CONF_SHARE_INTERNET, server_opt.share_internet );
	CONF_GET_INT_VALUE ( CONF_SHAPE_INTERNET, server_opt.shape_internet );
	CONF_GET_INT_VALUE ( CONF_USE_SHARED_INET, server_opt.use_shared_inet );
	CONF_GET_STRN_VALUE ( CONF_NTK_IP_MASQ_SCRIPT, &server_opt.ip_masq_script, NAME_MAX-1 );
	CONF_GET_STRN_VALUE ( CONF_NTK_TC_SHAPER_SCRIPT, &server_opt.tc_shaper_script, NAME_MAX-1 );

	/* Clean the enviroment */
	clear_config_env();
}

void free_server_opt(void)
{
	int i;
	
	if(server_opt.config_file != NTK_CONFIG_FILE)
		xfree(server_opt.config_file);
	if(server_opt.pid_file != NTK_PID_FILE)
		xfree(server_opt.pid_file);

	if(server_opt.int_map_file != INT_MAP_FILE)
		xfree(server_opt.int_map_file);
	if(server_opt.ext_map_file != EXT_MAP_FILE)
		xfree(server_opt.ext_map_file);
	if(server_opt.bnode_map_file != BNODE_MAP_FILE)
		xfree(server_opt.bnode_map_file);

	if(server_opt.andna_hnames_file != ANDNA_HNAMES_FILE)
		xfree(server_opt.andna_hnames_file);
	if(server_opt.snsd_nodes_file != SNSD_NODES_FILE)
		xfree(server_opt.snsd_nodes_file);
	if(server_opt.andna_cache_file != ANDNA_CACHE_FILE)
		xfree(server_opt.andna_cache_file);
	if(server_opt.lclkey_file != LCLKEY_FILE)
		xfree(server_opt.lclkey_file);
	if(server_opt.lcl_file != LCL_FILE)
		xfree(server_opt.lcl_file);
	if(server_opt.rhc_file != RHC_FILE)
		xfree(server_opt.rhc_file);
	if(server_opt.counter_c_file != COUNTER_C_FILE)
		xfree(server_opt.counter_c_file);

	if(server_opt.ip_masq_script != IPMASQ_SCRIPT_FILE)
		xfree(server_opt.ip_masq_script);
	if(server_opt.tc_shaper_script != TCSHAPER_SCRIPT_FILE)
		xfree(server_opt.tc_shaper_script);

	if(server_opt.inet_gw_dev)
		xfree(server_opt.inet_gw_dev);

	for(i=0; i<MAX_INTERFACES && server_opt.ifs[i]; i++)
		xfree(server_opt.ifs[i]);
}

void parse_options(int argc, char **argv)
{
	int c, saved_argc=argc;
	optind=0;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"help", 	0, 0, 'h'},
			{"iface", 	1, 0, 'i'},
			{"ipv6", 	0, 0, '6'},
			{"ipv4", 	0, 0, '4'},

			{"conf", 	1, 0, 'c'},
			{"logfile",	1, 0, 'l'},

			{"no_andna",	0, 0, 'a'},
			{"no_daemon", 	0, 0, 'D'},
			{"no_resolv",   0, 0, 'R'},
			
			{"restricted", 	0, 0, 'r'},
			{"share-inet",	0, 0, 'I'},
			
			{"debug", 	0, 0, 'd'},
			{"version",	0, 0, 'v'},
			{0, 0, 0, 0}
		};

		c = getopt_long (argc, argv,"i:c:l:hvd64DRrIa", long_options, 
				&option_index);
		if (c == -1)
			break;

		switch(c)
		{
			case 'v':
				printf("%s\n",VERSION_STR);
				exit(0); 
				break;
			case 'h':
				usage();
				exit(0);
				break;
			case '4':
				server_opt.family=AF_INET;
				break;
			case '6':
#ifdef IPV6_DISABLED
				fatal("The ipv6 is still not supported");
#endif
				loginfo("WARNING: The ipv6 support is still experimental and under "
						"development, nothing is assured to work.");
				server_opt.family=AF_INET6;
				break;
			case 'c': 
				server_opt.config_file=xstrndup(optarg, NAME_MAX-1);
				break;
			case 'l':
				if(log_to_file(optarg) < 0)
					fatal(0);
				break;
			case 'i': 
				if(server_opt.ifs_n+1 >= MAX_INTERFACES)
					fatal("The maximum number of interfaces is %d",
							MAX_INTERFACES);
				server_opt.ifs[server_opt.ifs_n++]=xstrndup(optarg, IFNAMSIZ-1);
				break;
			case 'D':
				server_opt.daemon=0;
				break;
			case 'a':
				server_opt.disable_andna=1;
				break;
			case 'R':
				server_opt.disable_resolvconf=1;
				break;
			case 'r':
				server_opt.restricted=1;

				/***
				 * This is a very dirty hack, but it handles
				 * the optional argument better than getopt.
				 *
				 * This is the problem:
				 * 	ntkd -abcrdefg
				 * If 'r' is an element that specifies an 
				 * optional argument, then the "defg" string
				 * is taken as its arg, but this is not what
				 * we want because in this case '-r' is
				 * specified without its argument.
				 *
				 * So, what we do is checking if the argv
				 * next to the arg of 'r' begins with a '-'
				 * or not. If not, it is the option of '-r'
				 *
				 * The only thing that won't work is:
				 * 	ntkd -rOPTION
				 * it has to be specified in this way:
				 * 	ntkd -r OPTION
				 */
				if(argc > optind && argv[optind][0] != '-') {
					server_opt.restricted_class=atoi(argv[optind]);
					saved_argc--;
				}
				/**/

				break;
			case 'I':
				server_opt.share_internet=1;
				if(!server_opt.restricted) {
					loginfo("Share_internet=1. Assuming restricted=1");
					server_opt.restricted=1;
				}
				if(!server_opt.inet_connection) {
					loginfo("Share_internet=1. Assuming inet_connection=1");
					server_opt.inet_connection=1;
				}
				break;
			case 'd':
				server_opt.dbg_lvl++;
				break;
			default:
				usage();
				exit(1);
				break;
		}
	}

	if (optind < saved_argc && !options_parsed) {
		usage();
		exit(1);
	}

	options_parsed++;
}

void check_conflicting_options(void)
{
#define FATAL_NOT_SPECIFIED(str) 	fatal("You didn't specified the `%s' " \
						"option in netsukuku.conf",    \
							(str));		       \
	
	if(!server_opt.pid_file)
		FATAL_NOT_SPECIFIED("pid_file");

	if(!server_opt.inet_hosts && server_opt.restricted)
		FATAL_NOT_SPECIFIED("internet_ping_hosts");


	if(server_opt.restricted && server_opt.share_internet && 
			!file_exist(server_opt.ip_masq_script))
		fatal("ip_masquerade_script \"%s\" is inexistent",
				server_opt.ip_masq_script);

	if(server_opt.shape_internet && 
			!file_exist(server_opt.tc_shaper_script))
		fatal("tc_shaper_script \"%s\" is inexistent",
				server_opt.ip_masq_script);

	if(!server_opt.restricted && server_opt.inet_connection)
		fatal("inet_connection=1 but ntk_restricted_mode=0. If you "
			"want to be compatible with the Internet, "
			"set the restricted mode in the options");
				
	if(!server_opt.restricted && 
		(server_opt.share_internet))
		fatal("You want to share your Internet connection,"
			"but I am not running in restricted mode (-r), "
			"'cause I'm not sure of what you want... "
			"I'm aborting.");

	if(server_opt.share_internet && me.my_bandwidth < MIN_CONN_BANDWIDTH)
		fatal("You want to share your Internet connection but "
			"your bandwidth is just TOO small. Do not share "
			"it, or your connection will be saturated");

	if(!server_opt.inet_connection && server_opt.share_internet) {	
		loginfo("You want to share your Internet connection,"
			"but `internet_connection' is set to 0."
			"We are assuming it is 1");
		server_opt.inet_connection=1;
	}

	if(server_opt.shape_internet && !server_opt.inet_connection)
		fatal("The Internet traffic shaping option is set, but "
			"the `internet_connection' is set to 0, please check "
			"your options.");
	
#ifdef IPV6_DISABLED
	if(server_opt.inet_gw.family == AF_INET6)
		fatal("Ipv6 is not supported");
#endif
}

void init_netsukuku(char **argv)
{
	xsrand();
	
        if(geteuid())
		fatal("Need root privileges");
	
	destroy_netsukuku_mutex=pid_saved=0;
	sigterm_timestamp=sighup_timestamp=sigalrm_timestamp=0;
	setzero(&me, sizeof(struct current_globals));

	if(is_ntkd_already_running())
		fatal("ntkd is already running. If it is not, remove \"%s\"",
				server_opt.pid_file);
	else
		save_pid();
	
	my_family=server_opt.family;
	restricted_mode =server_opt.restricted;
	restricted_class=server_opt.restricted_class ? RESTRICTED_172 : RESTRICTED_10;

	/* Check if the DATA_DIR exists, if not create it */
	if(check_and_create_dir(DATA_DIR))
		fatal("Cannot access to the %s directory. Exiting.", DATA_DIR);
	
	/* 
	 * Device initialization 
	 */
	if(if_init_all(server_opt.ifs, server_opt.ifs_n, 
				me.cur_ifs, &me.cur_ifs_n) < 0)
		fatal("Cannot initialize any network interfaces");

	/* 
	 * ANDNA init
	 */
	if(!server_opt.disable_andna)
		andna_init();

	/*
	 * Initialize the Internet gateway stuff
	 */
	if(server_opt.my_upload_bw && server_opt.my_dnload_bw)
	      me.my_bandwidth = bandwidth_in_8bit((server_opt.my_upload_bw + 
						   server_opt.my_dnload_bw)/2);
	init_internet_gateway_search();
	
	pkts_init(me.cur_ifs, me.cur_ifs_n, 0);
	qspn_init(FAMILY_LVLS);

	me.cur_erc=e_rnode_init(&me.cur_erc_counter);

	/* Radar init */
	rq_wait_idx_init(rq_wait_idx);
	first_init_radar();
	total_radars=0;

	ntk_load_maps();

#if 0
	/* TODO: activate and test it !! */
	debug(DBG_NORMAL, "ACPT: Initializing the accept_tbl: \n"
			"	max_connections: %d,\n"
			"	max_accepts_per_host: %d,\n"
			"	max_accept_per_host_time: %d", 
			server_opt.max_connections, 
			server_opt.max_accepts_per_host, 
			server_opt.max_accepts_per_host_time);
	init_accept_tbl(server_opt.max_connections, 
			server_opt.max_accepts_per_host, 
			server_opt.max_accepts_per_host_time);
#endif
	
	if(restricted_mode)
		loginfo("NetsukukuD is in restricted mode. "
			"Restricted class: %s",	
			server_opt.restricted_class?RESTRICTED_172_STR:RESTRICTED_10_STR);
	
	hook_init();
	rehook_init();

	me.uptime=time(0);
}

int destroy_netsukuku(void)
{
	if(destroy_netsukuku_mutex)
		return -1;
	destroy_netsukuku_mutex=1;

	unlink(server_opt.pid_file);
	
	ntk_save_maps();
	ntk_free_maps();
	if(!server_opt.disable_andna)
		andna_close();

	close_internet_gateway_search();
	last_close_radar();
	e_rnode_free(&me.cur_erc, &me.cur_erc_counter);
	destroy_accept_tbl();
	if_close_all();
	qspn_free();
	free_server_opt();

	return 0;
}

void sigterm_handler(int sig)
{
	time_t cur_t;

	if(sigterm_timestamp == (cur_t=time(0)))
		return;
	sigterm_timestamp=time(0);
	
	if(!destroy_netsukuku())
		fatal("Termination signal caught. Dying, bye, bye");
}

void *reload_hostname_thread(void *null)
{
	/* 
	 * Reload the file where the hostnames to be registered are and
	 * register the new ones
	 */
	loginfo("Reloading the andna hostnames file");
	load_hostnames(server_opt.andna_hnames_file, &andna_lcl, &lcl_counter);
	load_snsd(server_opt.snsd_nodes_file, andna_lcl);
	andna_update_hnames(1);

	return 0;
}

void sighup_handler(int sig)
{
	pthread_t thread;
	pthread_attr_t t_attr;
	
	time_t cur_t;

	if(sighup_timestamp == (cur_t=time(0)))
		return;
	sighup_timestamp=time(0);
	
	pthread_attr_init(&t_attr);
	pthread_attr_setdetachstate(&t_attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread, &t_attr, reload_hostname_thread, 0);
}

void *rh_cache_flush_thread(void *null)
{
	/* 
	 * Flush the resolved hostnames cache.
	 */
	loginfo("Flush the resolved hostnames cache");
	rh_cache_flush();

	return 0;
}

void sigalrm_handler(int sig)
{
	pthread_t thread;
	pthread_attr_t t_attr;
	
	time_t cur_t;

	if(sigalrm_timestamp == (cur_t=time(0)))
		return;
	sigalrm_timestamp=time(0);

	pthread_attr_init(&t_attr);
	pthread_attr_setdetachstate(&t_attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread, &t_attr, rh_cache_flush_thread, 0);
}

/*
 * The main flow shall never be stopped, and the sand of time will be
 * revealed.
 */
int main(int argc, char **argv)
{
	struct udp_daemon_argv ud_argv;
	u_short *port;
	pthread_t daemon_tcp_thread, daemon_udp_thread, andna_thread;
	pthread_t ping_igw_thread;
	pthread_attr_t t_attr;
	
	log_init(argv[0], 0, 1);
	
	/* Options loading... */
	fill_default_options();
	parse_options(argc, argv);

	/* reinit the logs using the new `dbg_lvl' value */
	log_init(argv[0], server_opt.dbg_lvl, 1);
	log_to_file(0);

	/* Load the option from the config file */
	load_config_file(server_opt.config_file);
	fill_loaded_cfg_options();
	
	/* If a same option was specified in the config file and in the
	 * command line, give priority to the latter */
	parse_options(argc, argv);

	check_conflicting_options();
	
	/* Initialize the whole netsukuku source code */
	init_netsukuku(argv);

	signal(SIGALRM, sigalrm_handler);
	signal(SIGHUP, sighup_handler);
	signal(SIGINT, sigterm_handler);
	signal(SIGTERM, sigterm_handler);
	signal(SIGQUIT, sigterm_handler);
	
	/* Angelic foreground or Daemonic background ? */
	if(server_opt.daemon) {
		loginfo("Forking to background");
		log_init(argv[0], server_opt.dbg_lvl, 0);
		if(daemon(0, 0) == -1)
			error("Impossible to daemonize: %s.", strerror(errno));
		
	}

	pthread_attr_init(&t_attr);
	pthread_attr_setdetachstate(&t_attr, PTHREAD_CREATE_DETACHED);
	setzero(&ud_argv, sizeof(struct udp_daemon_argv));
	port=xmalloc(sizeof(u_short));

	/* 
	 * These are the daemons, the main threads that keeps NetsukukuD
	 * up & running. 
	 */
	debug(DBG_NORMAL, "Activating all daemons");

	pthread_mutex_init(&udp_daemon_lock, 0);
	pthread_mutex_init(&tcp_daemon_lock, 0);

	debug(DBG_SOFT,   "Evoking the netsukuku udp radar daemon.");
	ud_argv.port=ntk_udp_radar_port;
	pthread_mutex_lock(&udp_daemon_lock);
	pthread_create(&daemon_udp_thread, &t_attr, udp_daemon, (void *)&ud_argv);
	pthread_mutex_lock(&udp_daemon_lock);
	pthread_mutex_unlock(&udp_daemon_lock);
	
	debug(DBG_SOFT,   "Evoking the netsukuku tcp daemon.");
	*port=ntk_tcp_port;
	pthread_mutex_lock(&tcp_daemon_lock);
	pthread_create(&daemon_tcp_thread, &t_attr, tcp_daemon, (void *)port);
	pthread_mutex_lock(&tcp_daemon_lock);
	pthread_mutex_unlock(&tcp_daemon_lock);

	
	/* Now we hook in Netsukuku */
	netsukuku_hook(0, 0);
	
	/*
	 * If not disabled, start the ANDNA daemon 
	 */
	if(!server_opt.disable_andna)
		pthread_create(&andna_thread, &t_attr, andna_main, 0);
	
	xfree(port);
	
	if(restricted_mode && (server_opt.share_internet || 
				server_opt.use_shared_inet)) {
		debug(DBG_SOFT, "Evoking the Internet Gateway Pinger daemon");
		pthread_create(&ping_igw_thread, &t_attr,
				igw_monitor_igws_t, 0);
	}

	/* We use this same process for the radar_daemon. */
	debug(DBG_SOFT,   "Evoking radar daemon.");
	radar_daemon(0);

	/* Not reached, hahaha */
	loginfo("Cya m8");
	pthread_attr_destroy(&t_attr);
	destroy_netsukuku();

	exit(0);
}
