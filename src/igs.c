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
 * igs.c:
 * Internet Gateway Search
 */

#include "includes.h"

#include "common.h"
#include "libnetlink.h"
#include "inet.h"
#include "krnl_route.h"
#include "request.h"
#include "endianness.h"
#include "pkts.h"
#include "bmap.h"
#include "qspn.h"
#include "radar.h"
#include "andns.h"
#include "netsukuku.h"
#include "route.h"
#include "krnl_rule.h"
#include "iptunnel.h"
#include "libping.h"
#include "libiptc/libiptc.h"
#include "mark.h"
#include "igs.h"
#include "err_errno.h"

int igw_multi_gw_disabled;

/*
 * bandwidth_in_8bit:
 * `x' is the bandwidth value expressed in Kb/s.
 * 
 * Since we consider `x' expressed in this form:
 * 	 x = y * 2^y; 
 * we can store just `y' in a u_char (8bit) variable.
 *
 * `bandwidth_in_8bit' returns `y' from `x'.
 *
 * `x' cannot be greater than 3623878656 (27*2^27), so if `x' is in Kb/s the
 * maximum bandwidth we can store in a byte is 3.6Tb/s.
 */
u_char bandwidth_in_8bit(u_int x)
{
	u_int i,z,a,b;
	u_int diff_2;

	for(z=27;z>=0;z--) {
		
		i=z<<z;
		if(i==x)
			/* x is exactly z*2^z */
			return (u_char)z;
	
		b=(z-1)<<(z-1);
		diff_2=(i-b)>>1;
		if(x >= i-diff_2 && x <=i)
			/* `x' is nearer to z*2^z than (z-1)*2^(z-1) */ 
			return z;

		a = z == 27 ? i : (z+1)<<(z+1);
		diff_2=(a-i)>>1;
		if(x <= i+diff_2 && x >= i)
			/* `x' is nearer to z*2^z than (z+1)*2^(z+1) */ 
			return z;
	}
	return 0;
}

/*
 * bandwidth_to_32bit: the inverse of bandwidth_in_8bit
 */
u_int bandwidth_to_32bit(u_char x)
{
	return (u_int)x<<x;
}

/*
 * str_to_inet_gw:
 * The syntax of `str' is IP:devname, i.e. 192.168.1.1:eth0.
 * str_to_inet_gw() stores the IP in `gw'.
 * In `*dev' is returned the pointer to a newly allocated string containing 
 * the device name.
 * On error -1 is returned.
 */
int str_to_inet_gw(char *str, inet_prefix *gw, char **dev)
{
	char *buf;

	setzero(dev, IFNAMSIZ);

	/* Copy :devname in `dev' */
	if(!(buf=rindex(str, ':')))
		return -1;
	*buf=0;
	buf++;
	if(!*buf)
		/* No device was specified */
		return -1;
	
	if(strlen(buf) >= IFNAMSIZ)
		/* It is too long, truncate it */
		buf[IFNAMSIZ-1]=0;
	*dev=xstrndup(buf, IFNAMSIZ);

	/* Extract the IP from the first part of `str' */
	if(str_to_inet(str, gw))
		return -1;

	return 0;
}

/*
 * parse_internet_hosts
 *
 * given a string which uses the following syntax:
 * 	"hostname1:hostname2:hostname3:..."
 * it stores each hostname in a new mallocated array and returns it.
 * The number of hostnames is written in `*hosts'
 * On error 0 is returned.
 */
char **parse_internet_hosts(char *str, int *hosts)
{
	char **hnames;
	
	hnames=split_string(str, ":", hosts, MAX_INTERNET_HNAMES,
			MAX_INTERNET_HNAME_SZ);
	return hnames;
}

void free_internet_hosts(char **hnames, int hosts)
{
	int i;
	for(i=0; i<hosts; i++)
		if(hnames[i])
			xfree(hnames[i]);
	if(hnames)
		xfree(hnames);
}

/*
 * internet_hosts_to_ip: replace the hostnames present in
 * `server_opt.inet_hosts' with IP strings. The IPs are obtained 
 * with a normal DNS resolution. The hosts which cannot be resolved are
 * deleted from the `inet_hosts' array.
 */
void internet_hosts_to_ip(void)
{
	int i;

	for(i=0; i < server_opt.inet_hosts_counter; i++) {
		inet_prefix ip;
		
		if(andns_gethostbyname(server_opt.inet_hosts[i], &ip)) {
			error("Cannot resolve \"%s\". Check your netsukuku.conf",
					server_opt.inet_hosts[i]);

			/* remove the hname from `inet_hosts' */
			xfree(server_opt.inet_hosts[i]);
			server_opt.inet_hosts[i] = server_opt.inet_hosts[server_opt.inet_hosts_counter-1];
			server_opt.inet_hosts_counter--;
		} else {
			xfree(server_opt.inet_hosts[i]);
			server_opt.inet_hosts[i]=xstrdup(inet_to_str(ip));
		}
	}
}

void init_igws(inet_gw ***igws, int **igws_counter, int levels)
{
	*igws=xzalloc(sizeof(inet_gw *) * levels);

	if(igws_counter)
		*igws_counter=(int *)xzalloc(sizeof(int)*levels);
}

void reset_igws(inet_gw **igws, int *igws_counter, int levels)
{
	int i;
	
	if(!igws)
		return;

	for(i=0; i<levels; i++) {
		if(igws[i])
			list_destroy(igws[i]);
		igws_counter[i]=0;
	}
}

void free_igws(inet_gw **igws, int *igws_counter, int levels)
{
	if(!igws)
		return;

	reset_igws(igws, igws_counter, levels);

	if(igws)
		xfree(igws);
	if(igws_counter)
		xfree(igws_counter);
}

/* 
 * init_my_igws
 *
 * initialiases the `my_igws' array. This list keeps inet_gw structs which
 * points to our (g)nodes, for example:
 * my_igws[0]->node == me.cur_node,
 * my_igws[1]->node == &me.cur_quadg.gnode[_EL(1)]->g,
 * ...
 */
void init_my_igws(inet_gw **igws, int *igws_counter,
		inet_gw ***my_new_igws, u_char my_bandwidth, 
		map_node *cur_node, quadro_group *qg)
{
	inet_gw *igw, **my_igws;
	map_node *node;
	int i=0, e, bw_mean;

	init_igws(&my_igws, 0, qg->levels);

	for(i=0; i<qg->levels; i++) {
		if(!i) {
			node=cur_node;
			bw_mean=my_bandwidth;
		} else {
			node=&qg->gnode[_EL(i)]->g;
			
			bw_mean=e=0;
			igw=igws[i-1];
			list_for(igw) {
				bw_mean+=igw->bandwidth;
				e++;
			}
			bw_mean/=e;
		}
		
		igw=igw_add_node(igws, igws_counter, i, qg->gid[i],
				node, (int*)qg->ipstart[0].data, 
				(u_char)bw_mean);
		my_igws[i]=igw;
	}
	
	*my_new_igws=my_igws;
}

void free_my_igws(inet_gw ***my_igs)
{
	if(*my_igs && *my_igs)
		xfree(*my_igs);
	*my_igs=0;
}

/*
 * init_internet_gateway_search: 
 * Initialization of the igs.c code.
 */
void init_internet_gateway_search(void)
{
	inet_prefix new_gw;
	char new_gw_dev[IFNAMSIZ];

	pthread_t ping_thread;
	pthread_attr_t t_attr;
	int i, ret,res,e;

	active_gws=0;
	igw_multi_gw_disabled=0;
	setzero(multigw_nh, sizeof(igw_nexthop)*MAX_MULTIPATH_ROUTES);

	/*
	 * Just return if we aren't in restricted mode or if the user doesn't
	 * want to use shared internet connections 
	 */
        if(!restricted_mode || (!server_opt.use_shared_inet && 
				!server_opt.share_internet))
		return;
	
	loginfo("Activating the Internet Gateway Search engine");
	
	init_igws(&me.igws, &me.igws_counter, GET_LEVELS(my_family));
	init_tunnels_ifs();

	/* delete all the old tunnels */
	del_all_tunnel_ifs(0, 0, 0, NTK_TUNL_PREFIX);
	
	/*
	 * Bring tunl0 up (just to test if the ipip module is loaded)
	 */
	loginfo("Configuring the \"" DEFAULT_TUNL_IF "\" tunnel device");
	if(tunnel_change(0, 0, 0, DEFAULT_TUNL_PREFIX, DEFAULT_TUNL_NUMBER) < 0)
		fatal("Cannot initialize \"" DEFAULT_TUNL_IF "\". "
			"Is the \"ipip\" kernel module loaded?\n"
			"  If you don't care about using the shared internet "
			"connections of the ntk nodes\n"
			"  around you, disable the \"use_shared_inet\" option "
			"in netsukuku.conf");
	ifs_del_all_name(me.cur_ifs, &me.cur_ifs_n, NTK_TUNL_PREFIX);
	ifs_del_all_name(me.cur_ifs, &me.cur_ifs_n, DEFAULT_TUNL_PREFIX);

	/*
	 * Delete old routing rules
	 */
	reset_igw_rules();

	/*
	 * Init netfilter
	 */
	 res=mark_init(server_opt.share_internet);
	 if (res) {
		 error(err_str);
		 error("Cannot set the netfilter rules needed for the multi-igw. "
				 "This feature will be disabled");
		 igw_multi_gw_disabled=1;
	 }

	/* 
	 * Check anomalies: from this point we initialize stuff only if we
	 * have an Inet connection
	 */
	if(!server_opt.inet_connection)
		return;
	if(!server_opt.inet_hosts)
		fatal("You didn't specified any Internet hosts in the "
			"configuration file. What hosts should I ping?");

	/*
	 * If we are sharing our internet connection, activate the
	 * masquerading.
	 */
	if(server_opt.share_internet)
                igw_exec_masquerade_sh(server_opt.ip_masq_script, 0);

	/*
	 * Get the default gateway route currently set in the kernel routing
	 * table
	 */
	setzero(&new_gw, sizeof(inet_prefix));
	ret=rt_get_default_gw(&new_gw, new_gw_dev);

	/* 
	 * If there is no IP set in the route, fetch it at least from the
	 * device included in it.
	 */
	if(!new_gw.family && *new_gw_dev) {
		if(get_dev_ip(&new_gw, my_family, new_gw_dev) < 0)
			(*new_gw_dev)=0;
	}
	
	if(ret < 0 || (!*new_gw_dev && !new_gw.family)) {
		/* Nothing useful has been found  */
		
		loginfo("The retrieval of the default gw from the kernel failed.");

		if(!server_opt.inet_gw.data[0])
			fatal("The default gw isn't set in the kernel and you "
				"didn't specified it in netsukuku.conf. "
				"Cannot continue!");
	} else if(!server_opt.inet_gw_dev || 
		   strncmp(new_gw_dev, server_opt.inet_gw_dev, IFNAMSIZ) || 
		   memcmp(new_gw.data, server_opt.inet_gw.data, MAX_IP_SZ)) {

		if(server_opt.inet_gw.data[0])
			loginfo("Your specified Internet gateway doesn't match with "
				"the one currently stored in the kernel routing table."
				"I'm going to use the kernel gateway: %s dev %s",
					inet_to_str(new_gw), new_gw_dev);

		if(!server_opt.inet_gw_dev)
			server_opt.inet_gw_dev=xstrdup(new_gw_dev);
		else
			strncpy(server_opt.inet_gw_dev, new_gw_dev, IFNAMSIZ);
		memcpy(&server_opt.inet_gw, &new_gw, sizeof(inet_prefix));

		/* Delete the default gw, we are replacing it */
		rt_delete_def_gw(0);
	}
	
	loginfo("Using \"%s dev %s\" as your first Internet gateway.", 
			inet_to_str(server_opt.inet_gw), server_opt.inet_gw_dev);
	if(rt_replace_def_gw(server_opt.inet_gw_dev, server_opt.inet_gw, 0))
		fatal("Cannot set the default gw to %s %s",
				inet_to_str(server_opt.inet_gw),
				server_opt.inet_gw_dev);
	active_gws++;

	/*
	 * Activate the anti-loop multi-igw shield
	 */
	if(server_opt.share_internet) {
		rule_add(0, 0, 0, 0, FWMARK_ALISHIELD, RTTABLE_ALISHIELD);
		if(rt_replace_def_gw(server_opt.inet_gw_dev, server_opt.inet_gw,
					RTTABLE_ALISHIELD)) {
			error("Cannot set the default route in the ALISHIELD table. "
					"Disabling the multi-inet_gw feature");
			igw_multi_gw_disabled=1;
		}
	}

	
	/*
	 * Activate the traffic shaping for the `server_opt.inet_gw_dev'
	 * device
	 */
	if(server_opt.shape_internet)
		igw_exec_tcshaper_sh(server_opt.tc_shaper_script, 0,
			server_opt.inet_gw_dev, server_opt.my_upload_bw, 
			server_opt.my_dnload_bw);

	for(i=0; i < me.cur_ifs_n; i++)
		if(!strcmp(me.cur_ifs[i].dev_name, server_opt.inet_gw_dev)) {
			for(e=0; e<server_opt.ifs_n; e++)
				if(!strcmp(server_opt.ifs[i], server_opt.inet_gw_dev))
					fatal("You specified the \"%s\" interface"
						" in the options, but this device is also"
						" part of the primary Internet gw route." 
						" Don't include \"%s\" in the list of "
						"interfaces utilised by the daemon", 
						server_opt.inet_gw_dev, server_opt.inet_gw_dev);
			
			loginfo("Deleting the \"%s\" interface from the device "
				"list since it is part of the primary Internet"
				" gw route.", me.cur_ifs[i].dev_name);

			ifs_del(me.cur_ifs, &me.cur_ifs_n, i);
			if(me.cur_ifs_n <= 0)
				fatal("The deleted interface cannot be used by NetsukukuD because it is part\n"
				      "  of your primary Internet gw route. You have to specify another\n"
				      "  interface with the -i option or you won't be able share your"
				      "  Internet connection");
		}

	loginfo("Launching the first ping to the Internet hosts");
	if(!server_opt.disable_andna)
		internet_hosts_to_ip();
	me.inet_connected=igw_check_inet_conn();
	if(me.inet_connected)
		loginfo("The Internet connection is up & running");
	else
		loginfo("The Internet connection appears to be down");
	if(!me.inet_connected && server_opt.share_internet)
		fatal("We are not connected to the Internet, but you want to "
			"share your connection. Please check your options");

	debug(DBG_SOFT,   "Evoking the Internet ping daemon.");
        pthread_attr_init(&t_attr);
        pthread_attr_setdetachstate(&t_attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&ping_thread, &t_attr, igw_check_inet_conn_t, 0);
}

void close_internet_gateway_search(void)
{
        if(!restricted_mode || (!server_opt.use_shared_inet && 
				!server_opt.share_internet))
		return;

	/* Flush the MASQUERADE rules */
	if(server_opt.share_internet)
		igw_exec_masquerade_sh(server_opt.ip_masq_script, 1);

	/* Disable the traffic shaping */
	if(server_opt.shape_internet)
		igw_exec_tcshaper_sh(server_opt.tc_shaper_script, 1,
				server_opt.inet_gw_dev, 0, 0);
	
	/* Delete all the added rules */
	reset_igw_rules();

	/* Destroy the netfilter rules */
	mark_close();

	/* Delete all the tunnels */
	del_all_tunnel_ifs(0, 0, 0, NTK_TUNL_PREFIX);

	free_igws(me.igws, me.igws_counter, me.cur_quadg.levels);
	free_my_igws(&me.my_igws);

	/* Free what has been malloced */
	free_internet_hosts(server_opt.inet_hosts, 
			    server_opt.inet_hosts_counter);
}

/*
 * igw_add_node: adds a new gw in the `igws[`level']' llist.
 * The pointer to the new inet_gw is returned.
 */
inet_gw *igw_add_node(inet_gw **igws, int *igws_counter,  int level,
		int gid, map_node *node, int ip[MAX_IP_INT], u_char bandwidth)
{
	inet_gw *igw;

	node->flags|=MAP_IGW;

	igw=xzalloc(sizeof(inet_gw));
	memcpy(igw->ip, ip, MAX_IP_SZ);
	igw->node=node;
	igw->gid=gid;
	igw->bandwidth=bandwidth;
		
	clist_add(&igws[level], &igws_counter[level], igw);

	return igw;
}

int igw_del(inet_gw **igws, int *igws_counter, inet_gw *igw, int level)
{
	if(!igw)
		return -1;

	igw->node->flags&=~MAP_IGW;
	
	if(!igws[level])
		return -1;

	clist_del(&igws[level], &igws_counter[level], igw);
	return 0;
}

/*
 * igw_find_node: finds an inet_gw struct in the `igws[`level']' llist which
 * points to the given `node'. the pointer to the found struct is
 * returned, otherwise 0 is the return value.
 */
inet_gw *igw_find_node(inet_gw **igws, int level, map_node *node)
{
	inet_gw *igw;

	igw=igws[level];
	list_for(igw)
		if(igw->node == node)
			return igw;
	return 0;
}

inet_gw *igw_find_ip(inet_gw **igws, int level, u_int ip[MAX_IP_INT])
{
	inet_gw *igw;

	igw=igws[level];
	list_for(igw)
		if(!memcmp(igw->ip, ip, MAX_IP_SZ))
			return igw;
	return 0;
}

/*
 * igw_del_node: deletes, from the `igws[`level']' llist, the inet_gw struct
 * which points to `node'. On success 0 is returned.
 */
int igw_del_node(inet_gw **igws, int *igws_counter,  int level,
		map_node *node)
{
	inet_gw *igw;

	igw=igw_find_node(igws, level, node);
	return igw_del(igws, igws_counter, igw, level);
}

/*
 * igw_update_gnode_bw: 
 * call this function _after_ adding and _before_ deleting the `igw->node' node
 * from the me.igws llist. This fuctions will update the `bandwidth' value of
 * the inet_gw which points to our (g)nodes.
 * Use `new'=1 if you are adding the node, otherwise use 0.
 */
void igw_update_gnode_bw(int *igws_counter, inet_gw **my_igws, inet_gw *igw,
		int new, int level, int maxlevels)
{
	int i, bw, old_bw=0;
	
	if(level >= maxlevels)
		return;

	if(new) {
		if(igws_counter[level] <= 0)
			return;
		
		bw = my_igws[level+1]->bandwidth * (igws_counter[level]-1);
		bw = (bw + igw->bandwidth) / igws_counter[level];
	} else {
		if(igws_counter[level] <= 1)
			return;

		bw = my_igws[level+1]->bandwidth * igws_counter[level];
		bw = (bw - igw->bandwidth) / (igws_counter[level]-1);
	}
	old_bw = my_igws[level+1]->bandwidth;
	my_igws[level+1]->bandwidth = bw;

	for(i=level+2; i<maxlevels; i++) {
		if(!my_igws[i] || igws_counter[i-1] <= 0)
			break;

		bw = my_igws[i]->bandwidth * igws_counter[i-1];
		bw = (bw - old_bw + my_igws[i-1]->bandwidth)/igws_counter[i-1];
		old_bw = my_igws[i]->bandwidth;
		my_igws[i]->bandwidth = bw;
	}
}


/*
 * igw_cmp: compares two inet_gw structs calculating their connection quality: 
 * bandwith - rtt/1000;
 */
int igw_cmp(const void *a, const void *b)
{
	inet_gw *gw_a=*(inet_gw **)a;
	inet_gw *gw_b=*(inet_gw **)b;

	u_int cq_a, cq_b, trtt;

	/* let's calculate the connection quality of both A and B */
	trtt = gw_a->node->links ? gw_a->node->r_node[0].trtt/1000 : 0;
	cq_a = bandwidth_to_32bit(gw_a->bandwidth) - trtt;
	trtt = gw_b->node->links ? gw_b->node->r_node[0].trtt/1000 : 0;
	cq_b = bandwidth_to_32bit(gw_b->bandwidth) - trtt;
	
	if(cq_a > cq_b)
		return 1;
	else if(cq_a == cq_b)
		return 0;
	else
		return -1;
}

/*
 * igw_order: orders in decrescent order the `igws[`level']' llist,
 * comparing the igws[level]->bandwidth and igws[level]->node->r_node[0].trtt 
 * values.
 * `my_igws[level]' will point to the inet_gw struct which refers to an our
 * (g)node.
 */
void igw_order(inet_gw **igws, int *igws_counter, inet_gw **my_igws, int level)
{
	inet_gw *igw, *new_head, *maxigws_ptr;
	int i;
		
	if(!igws_counter[level] || !igws[level])
		return;
	
	new_head=clist_qsort(igws[level], igws_counter[level], igw_cmp);
	
	igw=new_head;
	list_for(igw) {
		if(i >= MAXIGWS) {
			if(igw->node->flags & MAP_ME) {
				list_substitute(maxigws_ptr, igw);
				igw=maxigws_ptr;
			}
			
			/* The maximum number of igw has been exceeded */
			clist_del(&igws[level], &igws_counter[level], igw);
		}

		if(my_igws && igw->node->flags & MAP_ME)
			my_igws[level]=igw;
		
		if(i == MAXIGWS-1)
			maxigws_ptr=igw;

		i++;
	}

	igws[level]=new_head;
}

/*
 * igw_check_inet_conn: returns 1 if we are still connected to the Internet.
 * The check is done by pinging the `server_opt.inet_hosts'.
 */
int igw_check_inet_conn(void)
{
	int i, ret;

	for(i=0; server_opt.inet_hosts && server_opt.inet_hosts[i] && 
			i < server_opt.inet_hosts_counter; i++) {
		ret=pingthost(server_opt.inet_hosts[i], INET_HOST_PING_TIMEOUT);
		if(ret >= 1)
			return 1;
	}
	
	return 0;
}

/*
 * igw_check_inet_conn_t
 * 
 * checks if we are connected to the internet, then waits, then checks 
 * if we are connected, then ...
 */
void *igw_check_inet_conn_t(void *null)
{
	inet_prefix new_gw;
	char new_gw_dev[IFNAMSIZ];
	int old_status, ret;
	
	for(;;) {
		old_status=me.inet_connected;
		me.inet_connected=igw_check_inet_conn();

		if(old_status && !me.inet_connected) {
			/* Connection lost, disable me.my_igws[0] */
			loginfo("Internet connection lost. Inet connection sharing disabled");
					
			me.my_igws[0]->bandwidth=0;
			igw_update_gnode_bw(me.igws_counter, me.my_igws,
				me.my_igws[0], 0, 0, me.cur_quadg.levels);
			clist_join(&me.igws[0], &me.igws_counter[0], me.my_igws[0]);
			
		} else if(!old_status && me.inet_connected) {
			if(server_opt.share_internet) {
				/* Maybe the Internet gateway is changed, it's
				 * better to check it */

				ret=rt_get_default_gw(&new_gw, new_gw_dev);
				if(ret < 0) {
					/* 
					 * Something's wrong, we can reach Inet
					 * hosts, but we cannot take the default 
					 * gw, thus consider ourself not connected.
					 */
					me.inet_connected=0;
					goto skip_it;
				}
				if(strncmp(new_gw_dev, server_opt.inet_gw_dev, IFNAMSIZ) || 
					memcmp(new_gw.data, server_opt.inet_gw.data, MAX_IP_SZ)) {
					
					/* New Internet gw (dialup connection ?)*/
					strncpy(server_opt.inet_gw_dev, new_gw_dev, IFNAMSIZ);
					memcpy(&server_opt.inet_gw, &new_gw, sizeof(inet_prefix));
					loginfo("Our Internet gateway changed, now it is: %s dev %s",
							inet_to_str(new_gw), new_gw_dev);
				} else
					loginfo("Internet connection is alive again. "
							"Inet connection sharing enabled");
			}

			/* Yay! We're connected, enable me.my_igws[0] */
			me.my_igws[0]->bandwidth=me.my_bandwidth;
			clist_ins(&me.igws[0], &me.igws_counter[0], me.my_igws[0]);
			igw_update_gnode_bw(me.igws_counter, me.my_igws,
				me.my_igws[0], 1, 0, me.cur_quadg.levels);

		}
skip_it:	
		sleep(INET_NEXT_PING_WAIT);
	}
}

/*
 * igw_ping_igw: pings `igw->ip' and returns 1 if it replies.
 */
int igw_ping_igw(inet_gw *igw)
{
	inet_prefix ip;
	char ntop[INET6_ADDRSTRLEN]="\0";
	const char *ipstr;
	
	inet_setip_raw(&ip, igw->ip, my_family);
	if(!(ipstr=inet_to_str(ip)))
		return -1;
			
	strcpy(ntop, ipstr);
	return pingthost(ntop, IGW_HOST_PING_TIMEOUT) >= 1;
}

/*
 * igw_monitor_igws_t: it pings the Internet gateway which are currently
 * utilised in the kernel routing table and deletes the ones which don't
 * reply.
 */
void *igw_monitor_igws_t(void *null)
{
	inet_gw *igw, *next, *old_igw;
	int i, nexthops, ip[MAX_IP_INT], l, ni;
	
	nexthops=MAX_MULTIPATH_ROUTES/me.cur_quadg.levels;
	for(;;) {
		while(me.cur_node->flags & MAP_HNODE)
			sleep(1);

		for(i=0; i<me.cur_quadg.levels; i++) {

			while(me.cur_node->flags & MAP_HNODE)
				sleep(1);
			
			igw=me.igws[i];

			ni=0;
			list_safe_for(igw, next) {
				if(ni >= nexthops)
					break;

				if(!(igw->flags & IGW_ACTIVE))
					continue;

				if(!memcmp(igw->ip, me.cur_quadg.ipstart[0].data, MAX_IP_SZ))
					continue;

				if(!igw_ping_igw(igw)) {
					memcpy(ip, igw->ip, MAX_IP_SZ);
					
					loginfo("The Internet gw %s doesn't replies "
						"to pings. It is dead.", 
						ipraw_to_str(igw->ip, my_family));

					for(l=i, old_igw=igw; l<me.cur_quadg.levels; l++) {
						igw_del(me.igws, me.igws_counter, old_igw, l);
						if(l+1 < me.cur_quadg.levels)
							old_igw=igw_find_ip(me.igws, l+1, (u_int *)ip);
					}

					igw_replace_def_igws(me.igws, me.igws_counter,
							me.my_igws, me.cur_quadg.levels, my_family);
				}

				ni++;
			}
		}
		
		sleep(INET_NEXT_PING_WAIT);
	}
}

/*
 * igw_exec_masquerade_sh: executes `script', which activate the IP masquerade.
 * If `stop' is set to 1 the script will be executed as "script stop",
 * otherwise as "script start".
 */
int igw_exec_masquerade_sh(char *script, int stop)
{
	int ret;
	char argv[7]="";
	
	sprintf(argv, "%s", stop ? "stop" : "start");

	ret=exec_root_script(script, argv);
	if(ret == -1)
		fatal("%s wasn't executed. We cannot share the Inet "
				"connection, aborting.");
	return 0;
}

/*
 * igw_exec_tcshaper_sh: executes `script', which activate the Internet traffic
 * shaping.
 * If `stop' is set to 1 the script will be executed as "script stop `dev'".
 */
int igw_exec_tcshaper_sh(char *script, int stop, 
		char *dev, int upload_bw, int dnload_bw)
{
	int ret;
	char argv[7]="";
	
	if(stop)
		sprintf(argv, "%s %s", "stop", dev);
	else
		sprintf(argv, "%s %d %d", dev, upload_bw, dnload_bw);

	ret=exec_root_script(script, argv);
	
	if(ret == -1) {
		if(!stop)
			error("%s wasn't executed. The traffic shaping will be "
					"disabled.");
		else
			error("The traffic shaping is still enabled!");
	}
			
	return 0;
}


/*
 * add_igw_nexthop:
 * 	
 * 	`igwn' is an array of at leat MAX_MULTIPATH_ROUTES members.
 * 	`ip' is the ip of the nexthop
 *
 * add_igw_nexthop() searches `ip' in `igwn', if it is found the position in
 * the array of the igw_nexthop struct is returned, otherwise it adds `ip' in
 * the first empty member of the struct (its position is always returned).
 * In the first case `*new' is set to 0, in the second to 1.
 * If the array is full and nothing can be added -1 is returned.
 */
int add_igw_nexthop(igw_nexthop *igwn, inet_prefix *ip, int *new)
{
	int i;

	for(i=0; i<MAX_MULTIPATH_ROUTES; i++)
		if(!memcmp(igwn[i].nexthop.data, ip->data, MAX_IP_SZ)) {
			igwn[i].flags|=IGW_ACTIVE;
			*new=0;
			return i;
		}
	
	for(i=0; i<MAX_MULTIPATH_ROUTES; i++) {
		if(!(igwn[i].flags & IGW_ACTIVE)) {
			inet_copy(&igwn[i].nexthop, ip);
			igwn[i].tunl=i;
			igwn[i].table=RTTABLE_IGW+i;
			igwn[i].flags|=IGW_ACTIVE;
			*new=1;
			return i;
		}
	}

	*new=-1;
	return -1;
}

void set_igw_nexhtop_inactive(igw_nexthop *igwn)
{
	int i;

	for(i=0; i<MAX_MULTIPATH_ROUTES; i++)
		igwn[i].flags&=~IGW_ACTIVE;
}

void reset_igw_nexthop(igw_nexthop *igwn)
{
	setzero(igwn, sizeof(igw_nexthop)*MAX_MULTIPATH_ROUTES);
}

/* 
 * reset_igw_rules: flush all the routing rules
 */
void reset_igw_rules(void)
{
	/*
	 * Reset each rule added for a tunnel-nexthop
	 * and the rule used for the Anti-loop multi-igw shield.
	 */
	rule_flush_table_range(my_family, RTTABLE_IGW, 
			RTTABLE_IGW+MAX_MULTIPATH_ROUTES);
}

/*
 * igw_replace_def_igws: sets the default gw route to reach the
 * Internet. The route utilises multipath therefore there are more than one
 * gateway which can be used to reach the Internet, these gateways are choosen
 * from the `igws' llist.
 * On error -1 is returned.
 */
int igw_replace_def_igws(inet_gw **igws, int *igws_counter, 
		inet_gw **my_igws, int max_levels, int family)
{
	inet_gw *igw;
	inet_prefix to, ip;

	struct nexthop *nh=0, nh_tmp[2];
	int ni, ni_lvl, nexthops, level, max_multipath_routes, i, x;
	int res, new_nexhtop;

#ifdef DEBUG		
#define MAX_GW_IP_STR_SIZE (MAX_MULTIPATH_ROUTES*((INET6_ADDRSTRLEN+1)+IFNAMSIZ)+1)
	int n;
	char gw_ip[MAX_GW_IP_STR_SIZE]="";
#endif
	
	max_multipath_routes=MAX_MULTIPATH_ROUTES;
	
	/* to == 0.0.0.0 */
	inet_setip_anyaddr(&to, family);
	to.len=to.bits=0;

	nh=xzalloc(sizeof(struct nexthop)*MAX_MULTIPATH_ROUTES);
	ni=0; /* nexthop index */

	/* 
	 * If we are sharing our Internet connection use, as the primary 
	 * gateway `me.internet_gw'.
	 */
	if(server_opt.share_internet && me.inet_connected) {
		memcpy(&nh[ni].gw, &server_opt.inet_gw, sizeof(inet_prefix));
		inet_htonl(nh[ni].gw.data, nh[ni].gw.family);
		nh[ni].dev=server_opt.inet_gw_dev;
		nh[ni].hops=255-ni;
		ni++;
		max_multipath_routes--;
	}

	/* 
	 * Set all our saved nexthop as inactives, then mark as "active" only 
	 * the nexhtop we are going to re-pick, in this way we can know what
	 * nexthop have been dropped.
	 */
	set_igw_nexhtop_inactive(multigw_nh);
	
	/* We choose an equal number of nexthops for each level */
	nexthops=max_multipath_routes/max_levels;

	for(level=0; level<max_levels; level++) {
		
		/* Remember the nexthops we choose at each cycle */
		inet_gw *taken_nexthops[max_multipath_routes];
		
#ifndef IGS_MULTI_GW
		if(ni)
			break;
#else
		if(ni && igw_multi_gw_disabled)
			break;
#endif

		/* Reorder igws[level] */
		igw_order(igws, igws_counter, my_igws, level);

		
		/* 
		 * Take the first `nexthops'# gateways and add them in `ni' 
		 */
		
		ni_lvl=0;
		igw=igws[level];
		list_for(igw) {
			if(ni_lvl >= nexthops)
				break;

			/* Skip gateways which have a bandwidth too small */
			if(igw->bandwidth < MIN_CONN_BANDWIDTH)
				continue;

			/* Do not include ourself as an inet-gw */
			if(!memcmp(igw->ip, me.cur_ip.data, MAX_IP_SZ))
				continue;
		
			/* Avoid duplicates, do not choose gateways we already 
			 * included in the nexthops array */
			for(i=0, x=0; i<ni; i++)
				if(!memcmp(taken_nexthops[i]->ip, igw->ip, 
							MAX_IP_SZ)) {
					x=1;
					break;
				}
			if(x)
				continue;
			
			igw->flags|=IGW_ACTIVE;
			inet_setip(&nh[ni].gw, igw->ip, family);
			nh[ni].hops=max_multipath_routes-ni+1;

			if((x=add_igw_nexthop(multigw_nh, &nh[ni].gw,
							&new_nexhtop)) < 0)
					continue;
			
			nh[ni].dev=tunnel_ifs[multigw_nh[x].tunl].dev_name;

			/*
			 * If we are reusing a tunnel of an old inet-gw,
			 * delete it.
			 */
			if(*nh[ni].dev && new_nexhtop)
				del_tunnel_if(0, 0, nh[ni].dev, NTK_TUNL_PREFIX, 
						multigw_nh[x].tunl);
			
			if(!*nh[ni].dev) { 
				setzero(&nh_tmp, sizeof(struct nexthop)*2);
				memcpy(&nh_tmp[0], &nh[ni], sizeof(struct nexthop));
				inet_ntohl(nh_tmp[0].gw.data, nh_tmp[0].gw.family);
				
				/* 
				 * Initialize the `nh[ni].dev' tunnel, it's
				 * its first time.
				 */
				if((add_tunnel_if(&nh_tmp[0].gw, &me.cur_ip, 0, 
						NTK_TUNL_PREFIX, multigw_nh[x].tunl, 
						&me.cur_ip)) < 0)
					continue;
				
				/* 
				 * Add the table for the new tunnel-gw:
				 * 
				 * ip rule add from me.cur_ip    \
				 *   fwmark multigw_nh[x].tunl+1 \
				 *   lookup multigw_nh[x].table
				 */
				inet_copy(&ip, &me.cur_ip);
				if(multigw_nh[x].flags & IGW_RTRULE)
					rule_del(&ip, 0, 0, 0,
						multigw_nh[x].tunl, multigw_nh[x].table);
				inet_htonl(ip.data, ip.family);
				rule_add(&ip, 0, 0, 0, multigw_nh[x].tunl+1, 
						multigw_nh[x].table);
				multigw_nh[x].flags|=IGW_RTRULE;

				/*
				 * Add the default route in the added table:
				 * 
				 * ip route replace default via nh[ni].gw \ 
				 * 	table multigw_nh[x].table 	  \
				 * 	dev nh[ni].dev
				 */
				inet_htonl(nh_tmp[0].gw.data, nh_tmp[0].gw.family);
				if(route_replace(0, 0, 0, &to, nh_tmp, 0, multigw_nh[x].table))
					error("Cannote replace the default "
						"route of the table %d ",
						multigw_nh[x].table);
				
				 res=create_mark_rules(multigw_nh[x].tunl+1);
				 if (res==-1) 
					 error(err_str);
			}
			taken_nexthops[ni]=igw;
			
			ni++;
			ni_lvl++;
		}
		
		if(ni_lvl >= nexthops)
			/* All the other gateways are inactive */
			list_for(igw)
				igw->flags&=~IGW_ACTIVE;
	}
	nh[ni].dev=0;

	if(!ni && active_gws) {
#ifdef DEBUG
		debug(DBG_INSANE, RED("igw_def_gw: no Internet gateways "
				"available. Deleting the default route"));
#endif
		rt_delete_def_gw(0);
		active_gws=0;
		return 0;
	} else if(!ni)
		return 0;

#ifdef DEBUG
	for(n=0; nh && nh[n].dev; n++){ 
		strcat(gw_ip, inet_to_str(nh[n].gw));
		strcat(gw_ip, "|");
		strcat(gw_ip, nh[n].dev);
		strcat(gw_ip, ":");
	}
	debug(DBG_INSANE, RED("igw_def_gw: default via %s"), gw_ip);
#endif

	if(route_replace(0, 0, 0, &to, nh, 0, 0))
		error("WARNING: Cannot update the default route "
				"lvl %d", level);
	active_gws=ni;
	
	return 0;
}

/* 
 * igw_build_bentry: It builds the Internet gateway bnode blocks to be added
 * in the bnode's entry in the tracer pkt. For the specification of this type
 * of bnode block read igs.h
 * 
 * It returns the mallocated package containing the bblock, in `*pack_sz' it
 * stores the package's size.
 * The number of different bblock contained in the package is written in
 * `*bblocks' if `bblocks' is not zero.
 *
 * On error it returns NULL.
 */
char *igw_build_bentry(u_char level, size_t *pack_sz, int *new_bblocks)
{
	bnode_hdr *bhdr;
	bnode_chunk *bchunk;
	inet_gw *igws_buf[MAX_IGW_PER_QSPN_CHUNK], *igw;
	inet_prefix ip;
	
	int i, e, lvl, found_gws=0, max_igws, gids[FAMILY_LVLS];
	size_t total_bblocks_sz, bblock_sz;
	char *bblock, *buf;
	u_char *bnode_gid;

	*pack_sz=0;
	if(new_bblocks)
		*new_bblocks=0;
	ip.family=my_family;

	/*
	 * Select the Internet gateways to be included in the bblock
	 */
	max_igws=!level ? 1 : MAX_IGW_PER_QSPN_CHUNK;
	if(!level && me.my_igws[level]->bandwidth)
		igws_buf[found_gws++]=me.my_igws[level];
	else {
		for(lvl=level-1, found_gws=0; 
			lvl >= 0 && found_gws < max_igws; lvl--) {

			igw=me.igws[lvl];
			list_for(igw) {
				igws_buf[found_gws++]=igw;
				if(found_gws == max_igws)
					break;
			}
		}
	}

	if(!found_gws)
		/* nothing found */
		return 0;

	*new_bblocks = found_gws;

	/*
	 * Create enough space for the bblock
	 */
	bblock_sz = BNODEBLOCK_SZ(level+1, 1);
	total_bblocks_sz = bblock_sz * found_gws;
	bblock=xzalloc(total_bblocks_sz);

	/* 
	 * Write each IGW in the bblock
	 */
	for(i=0, buf=(char *)bblock; i<found_gws; i++) {
		bhdr=(bnode_hdr *)buf;
		bhdr->bnode_levels=level+1;
		bhdr->links=1;

		bnode_gid=(u_char *)(buf + sizeof(bnode_hdr));
		bchunk=(bnode_chunk *)((char *)bnode_gid +
				sizeof(u_char)*bhdr->bnode_levels);

		/*
		 * Get the gids of `igw'
		 */
		memcpy(ip.data, igws_buf[i]->ip, MAX_IP_SZ);
		iptogids(&ip, gids, bhdr->bnode_levels);
		for(e=0; e < bhdr->bnode_levels; e++)
			bnode_gid[e] = gids[e];

		if(!i || igws_buf[i-1]->ip[0] != igws_buf[i]->ip[0])
			debug(DBG_INSANE, "igw_build_bentry: ip %s", inet_to_str(ip));

		/* Fill the bnode chunk */
		bchunk[0].gnode=0;
		bchunk[0].level=FAMILY_LVLS+1;
		bchunk[0].rtt=igws_buf[i]->bandwidth;

		buf+=bblock_sz;
	}

	*pack_sz=total_bblocks_sz;
	return (char *)bblock;
}

/*
 * igw_store_bblock
 * 
 * It creates an inet_gw struct in me.igws using the bblock contained in 
 * `bchunk'. The hdr of the bblock is `bblock_hdr'.
 * The bblock has been packed using igw_build_bentry().
 * `level' is the level where the qspn_pkt which carries the bblock is being
 * spread. 
 * The kernel routing table is also updated.
 * On error -1 is returned.
 */
int igw_store_bblock(bnode_hdr *bblock_hdr, bnode_chunk *bchunk, u_char level)
{
	inet_prefix gw_ip;
	map_node *node=0;
	map_gnode *gnode=0;

	inet_gw *igw;
	int gids[me.cur_quadg.levels], ret=0;
	u_char *bnode_gid;

	int i, update=0;
	
	/*
	 * Extract the IP of the Internet gateway
	 */
	bnode_gid=(u_char *)bblock_hdr + sizeof(bnode_hdr);
	for(i=0; i<bblock_hdr->bnode_levels; i++)
		gids[i]=bnode_gid[i];
	for(; i < me.cur_quadg.levels; i++)
		gids[i]=me.cur_quadg.gid[i];

	gidtoipstart(gids, me.cur_quadg.levels, me.cur_quadg.levels, my_family,
			&gw_ip);
	
#ifdef DEBUG
	if(server_opt.dbg_lvl)
		debug(DBG_NOISE, GREEN("igw_store_bblock: storing %s IGW, level %d"),
					inet_to_str(gw_ip), level);
#endif
				
	/*
	 * Add `gw_ip' in all the levels >= `level' of me.igws
	 */
	for(i=level; i<me.cur_quadg.levels; i++) {
		if(!i)
			node=node_from_pos(gids[i], me.int_map);
		else {
			gnode = gnode_from_pos(gids[i], me.ext_map[_EL(i)]);
			node  = &gnode->g;
		}
		
		igw=igw_find_ip(me.igws, i, gw_ip.data);
		if(igw) {
			if(abs(igw->bandwidth - (char)bchunk->rtt) >= IGW_BW_DELTA) {
				igw->bandwidth = (char)bchunk->rtt;
				update=1;
			}
		} else {
			igw_add_node(me.igws, me.igws_counter, i, gids[i], node, 
					(int*)gw_ip.data, bchunk->rtt);
			update=1;
		}
	}

	if(!update)
		/* we've finished */
		return 0;
	
	/* 
	 * Refresh the Kernel routing table 
	 */
	ret=igw_replace_def_igws(me.igws, me.igws_counter, me.my_igws, 
			me.cur_quadg.levels, my_family);
	if(ret == -1) {
		debug(DBG_SOFT, ERROR_MSG "cannot replace default gateway", 
				ERROR_POS);
		return -1;
	}
	return 0;
}

char *pack_inet_gw(inet_gw *igw, char *pack)
{
	char *buf;

	buf=pack;

	memcpy(buf, igw->ip, MAX_IP_SZ);
	inet_htonl((u_int *)buf, my_family);
	buf+=MAX_IP_SZ;
	
	memcpy(buf, &igw->gid, sizeof(u_char));
	buf+=sizeof(u_char);

	memcpy(buf, &igw->bandwidth, sizeof(u_char));
	buf+=sizeof(u_char);

	return pack;
}

inet_gw *unpack_inet_gw(char *pack, inet_gw *igw)
{
	char *buf=pack;

	memcpy(igw->ip, buf, MAX_IP_SZ);
	inet_ntohl(igw->ip, my_family);
	buf+=MAX_IP_SZ;
	
	memcpy(&igw->gid, buf, sizeof(u_char));
	buf+=sizeof(u_char);

	memcpy(&igw->bandwidth, buf, sizeof(u_char));
	buf+=sizeof(u_char);

	return igw;
}

/*
 * pack_igws: it packs the each `igws[`level']' llist and sets the package size
 * in `pack_sz'. The package is returned, otherwise, on error, NULL is the
 * value returned.
 */
char *pack_igws(inet_gw **igws, int *igws_counter, int levels, int *pack_sz)
{
	struct inet_gw_pack_hdr hdr;
	inet_gw *igw;
	
	int lvl;
	char *pack, *buf;

	setzero(&hdr, sizeof(struct inet_gw_pack_hdr));

	/* 
	 * Fill the pack header and calculate the total pack size 
	 */
	hdr.levels=levels;
	*pack_sz=sizeof(struct inet_gw_pack_hdr);
	for(lvl=0; lvl<levels; lvl++) {
		hdr.gws[lvl]=igws_counter[lvl];
		(*pack_sz)+=hdr.gws[lvl]*INET_GW_PACK_SZ;
	}

	buf=pack=xzalloc(*pack_sz);

	memcpy(buf, &hdr, sizeof(struct inet_gw_pack_hdr));
	ints_host_to_network(buf, inet_gw_pack_hdr_iinfo);
	buf+=sizeof(struct inet_gw_pack_hdr);

	/* Pack `igws' */
	for(lvl=0; lvl<levels; lvl++) {
		igw=igws[lvl];
		list_for(igw) {
			pack_inet_gw(igw, buf);
			buf+=INET_GW_PACK_SZ;
		}
	}

	return pack;
}

/*
 * unpack_igws: upacks what pack_igws() packed.
 * `pack' is the package which is `pack_sz' big.
 * The pointer to the unpacked igws are stored in `new_igws' and 
 * `new_igws_counter'. 
 * On error -1 is returned.
 */
int unpack_igws(char *pack, size_t pack_sz,
		map_node *int_map, map_gnode **ext_map, int levels,
		inet_gw ***new_igws, int **new_igws_counter)
{
	struct inet_gw_pack_hdr *hdr;
	inet_gw *igw, **igws;
	
	size_t sz;
	int i, lvl=0, *igws_counter;
	char *buf;

	hdr=(struct inet_gw_pack_hdr *)pack;
	ints_network_to_host(hdr, inet_gw_pack_hdr_iinfo);
	sz=IGWS_PACK_SZ(hdr);

	/* Verify the package header */
	if(sz != pack_sz || sz > MAX_IGWS_PACK_SZ(levels) || 
			hdr->levels > levels) {
		debug(DBG_NORMAL, "Malformed igws package");
		return -1;
	}

	init_igws(&igws, &igws_counter, levels);

	buf=pack+sizeof(struct inet_gw_pack_hdr);
	for(lvl=0; lvl<hdr->levels; lvl++) {
		for(i=0; i<hdr->gws[lvl]; i++) {
			igw=xzalloc(sizeof(inet_gw));

			unpack_inet_gw(buf, igw);
			igw->node = node_from_pos(igw->gid, int_map);
			clist_add(&igws[lvl], &igws_counter[lvl], igw);

			buf+=INET_GW_PACK_SZ;
		}
	}
		
	*new_igws=igws;
	*new_igws_counter=igws_counter;
	return 0;
}
