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
 * andna.c:
 * Here there are all the functions that send, receive and exec ANDNA packets.
 * All the threads of the ANDNA daemon and the main andna functions are here 
 * too.
 */

#include "includes.h"

#include "inet.h"
#include "endianness.h"
#include "map.h"
#include "gmap.h"
#include "bmap.h"
#include "route.h"
#include "request.h"
#include "tracer.h"
#include "qspn.h"
#include "radar.h"
#include "netsukuku.h"
#include "daemon.h"
#include "crypto.h"
#include "snsd_cache.h"
#include "andna_cache.h"
#include "andna.h"
#include "andns.h"
#include "dns_wrapper.h"
#include "hash.h"
#include "common.h"


/*
 * 
 *  *  *  *  (de)-Initialization functions  *  *  *
 *
 */

/*
 * andna_load_caches
 * 
 * loads all the ANDNA caches
 */
int andna_load_caches(void)
{
	int ret=0;
	
	if(file_exist(server_opt.lclkey_file) && 
			(!load_lcl_keyring(&lcl_keyring, 
					  server_opt.lclkey_file)))
		debug(DBG_NORMAL, "Andna LCL Keyring loaded");
	
	if(file_exist(server_opt.lcl_file) && 
			(andna_lcl=load_lcl_cache(server_opt.lcl_file,
						  &lcl_counter)))
		debug(DBG_NORMAL, "Andna Local Cache loaded");

	if(file_exist(server_opt.andna_cache_file) && 
			(andna_c=load_andna_cache(server_opt.andna_cache_file,
						  &andna_c_counter)))
		debug(DBG_NORMAL, "Andna cache loaded");

	if(file_exist(server_opt.counter_c_file) && 
			(andna_counter_c=load_counter_c(server_opt.counter_c_file,
							&cc_counter)))
		debug(DBG_NORMAL, "Counter cache loaded");

	if(file_exist(server_opt.rhc_file) && 
			(andna_rhc=load_rh_cache(server_opt.rhc_file,
						 &rhc_counter)))
		debug(DBG_NORMAL, "Resolved hostnames cache loaded");

	if(file_exist(server_opt.andna_hnames_file) && 
			!(load_hostnames(server_opt.andna_hnames_file,
					 &andna_lcl, &lcl_counter)))
		debug(DBG_NORMAL, "Hostnames file loaded");
	
	if(file_exist(server_opt.snsd_nodes_file) && 
			!(ret=load_snsd(server_opt.snsd_nodes_file, andna_lcl)))
		debug(DBG_NORMAL, "SNSD nodes loaded");
	else if(ret == -2)
		fatal("Malformed %s file", server_opt.snsd_nodes_file);

	return 0;
}

int andna_save_caches(void)
{
	debug(DBG_NORMAL, "Saving the andna local cache");
	save_lcl_cache(andna_lcl, server_opt.lcl_file);

	debug(DBG_NORMAL, "Saving the andna cache");
	save_andna_cache(andna_c, server_opt.andna_cache_file);

	debug(DBG_NORMAL, "Saving the andna counter cache");
	save_counter_c(andna_counter_c, server_opt.counter_c_file);

	debug(DBG_NORMAL, "Saving the resolved hnames cache");
	save_rh_cache(andna_rhc, server_opt.rhc_file);

	return 0;
}

/*
 * andna_resolvconf_modify: modifies /etc/resolv.conf. See add_resolv_conf().
 */
void andna_resolvconf_modify(void)
{
	int ret;
	char *my_nameserv;
	
	if(!server_opt.disable_resolvconf) {
		loginfo("Modifying /etc/resolv.conf");

		my_nameserv = my_family == AF_INET ? MY_NAMESERV : MY_NAMESERV_IPV6;
		ret=add_resolv_conf(my_nameserv, ETC_RESOLV_CONF);
		if(ret < 0)
			error("It wasn't possible to modify %s, you have to add "
					"\"%s\" by yourself", ETC_RESOLV_CONF, my_nameserv);
	} else
		loginfo("Modification of /etc/resolv.conf is disabled: do it by yourself.");
}

void andna_resolvconf_restore(void)
{
	char *my_nameserv;

	/* 
	 * If there are valid nameserver in /etc/resolv.conf (excluding
	 * "127.0.0.1", do not restore the backup. Probably /etc/resolv.conf
	 * has been edited manually. Damn you, user! Why can't we code you ;)
	 */
	reset_andns_ns();
	if(collect_resolv_conf(ETC_RESOLV_CONF) != -1)
		return;
	reset_andns_ns();

	my_nameserv = my_family == AF_INET ? MY_NAMESERV : MY_NAMESERV_IPV6;
	del_resolv_conf(my_nameserv, ETC_RESOLV_CONF);
}

void andna_init(void)
{
	/* register the andna's ops in the pkt_op_table */
	add_pkt_op(ANDNA_REGISTER_HNAME, SKT_TCP, andna_tcp_port, andna_recv_reg_rq);
	add_pkt_op(ANDNA_CHECK_COUNTER,  SKT_TCP, andna_tcp_port, andna_recv_check_counter);
	add_pkt_op(ANDNA_RESOLVE_HNAME,  SKT_UDP, andna_udp_port, andna_recv_resolve_rq);
	add_pkt_op(ANDNA_RESOLVE_REPLY,  SKT_UDP, andna_udp_port, 0);
	add_pkt_op(ANDNA_RESOLVE_IP,     SKT_TCP, andna_tcp_port, andna_recv_rev_resolve_rq);
	add_pkt_op(ANDNA_REV_RESOLVE_REPLY,  SKT_TCP, andna_tcp_port, 0);
	add_pkt_op(ANDNA_GET_ANDNA_CACHE,SKT_TCP, andna_tcp_port, put_andna_cache);
	add_pkt_op(ANDNA_PUT_ANDNA_CACHE,SKT_TCP, andna_tcp_port, 0);
	add_pkt_op(ANDNA_GET_COUNT_CACHE,SKT_TCP, andna_tcp_port, put_counter_cache);
	add_pkt_op(ANDNA_PUT_COUNT_CACHE,SKT_TCP, andna_tcp_port, 0);
	add_pkt_op(ANDNA_GET_SINGLE_ACACHE,SKT_UDP, andna_udp_port, put_single_acache);
	add_pkt_op(ANDNA_SPREAD_SACACHE, SKT_UDP, andna_udp_port, recv_spread_single_acache);


	if(!server_opt.disable_resolvconf)
		/* Restore resolv.conf if our backup is still there */
		andna_resolvconf_restore();

	pkt_queue_init();
	
	andna_caches_init(my_family);
	snsd_cache_init(my_family);

	/* Load the good old caches */
	andna_load_caches();

	if(!lcl_keyring.priv_rsa) {
		/*
		 * No keyring was loaded, generate a new one save it 
		 */
		lcl_new_keyring(&lcl_keyring);

		debug(DBG_NORMAL, "Saving the new andna local keyring");
		save_lcl_keyring(&lcl_keyring, server_opt.lclkey_file);
		/**/
	}

	/* Init ANDNS */
	if(andns_init(restricted_mode, ETC_RESOLV_CONF,my_family) < 0)
		if(andns_init(restricted_mode, ETC_RESOLV_CONF_BAK,my_family) < 0) {
			error("In %s there isn't a single Internet nameserver.", 
					ETC_RESOLV_CONF);
			loginfo("Internet hostname resolution is disabled");
		}
	
	setzero(last_reg_pkt_id, sizeof(int)*ANDNA_MAX_FLOODS);
	setzero(last_counter_pkt_id, sizeof(int)*ANDNA_MAX_FLOODS);
	setzero(last_spread_acache_pkt_id, sizeof(int)*ANDNA_MAX_FLOODS);

	/* Modify /etc/resolv.conf if requested */
	andna_resolvconf_modify();
}

void andna_close(void)
{
	andna_save_caches();
	if(!server_opt.disable_resolvconf)
		andna_resolvconf_restore();
	andns_close();
	lcl_destroy_keyring(&lcl_keyring);
	lcl_cache_destroy(andna_lcl, &lcl_counter);
	andna_cache_destroy();
	counter_c_destroy();
	rh_cache_flush();
	pkt_queue_close();
}


/*
 *
 *  *  *  *  Hash_node search functions  *  *  *
 *
 */

/*
 * andna_hash_by_family
 *
 * If `family' is equal to AF_INET, in `hash' it stores the
 * 32bit hash of the `msg', otherwise it just copies `msg' to `hash_ip'. 
 * Note that this function is used to hash other hashes, so it operates on the
 * ANDNA_HASH_SZ fixed length.
 */
void andna_hash_by_family(int family, void *msg, u_int hash[MAX_IP_INT])
{
	setzero(hash, ANDNA_HASH_SZ);
	
	if(family==AF_INET)
		hash[0] = fnv_32_buf((u_char *)msg, ANDNA_HASH_SZ, 
				FNV1_32_INIT);
	else
		memcpy(hash, msg, ANDNA_HASH_SZ);
}

/*
 * andna_hash
 *
 * This function makes a digest of `msg' which is `len' bytes big and 
 * stores it in `hash'. 
 * If `family'is equal to AF_INET, in `ip_hash' it stores the 32bit hash
 * of the `hash', otherwise it just copies `hash' to `ip_hash'.
 * 
 * Note: `hash' is a single string of `MAX_IP_INT'*4 bytes, it is the MD5 hash
 * of `msg', therefore do not attempt to convert it to network order.
 */
void andna_hash(int family, void *msg, int len, u_int hash[MAX_IP_INT],
		u_int ip_hash[MAX_IP_INT])
{
	hash_md5(msg, len, (u_char *)hash);
	andna_hash_by_family(family, (u_char *)hash, ip_hash);	
}

/*
 * is_hgnode_excluded: it converts the `qg'->gid to an ip, then it searches a
 * member of `excluded_hgnode', which has all its gids, from the level `lvl` to
 * FAMILY_LVLS, equal to the ip. If it is found 1 is returned, otherwise 0
 * will be the return value.
 * This function is utilised by find_hash_gnode() to exclude from the search
 * the hash_gnodes not wanted.
 * All the `excluded_hgnode[x]' which are a null pointer are skipped.
 */
int is_hgnode_excluded(quadro_group *qg, u_int **excluded_hgnode,
		int tot_excluded_hgnodes, int lvl)
{
	int i, e, x, total_levels=FAMILY_LVLS;
	inet_prefix ip;
	
	for(e=0; e<tot_excluded_hgnodes; e++) {
		x=0;
		if(!excluded_hgnode[e])
			continue;

		inet_setip_raw(&ip, excluded_hgnode[e], my_family);
		for(i=lvl; i<total_levels; i++) {
#ifdef DEBUG
			debug(DBG_INSANE, "is_hgnode_excluded: l %d, qg->gid %d, ipgid %d", i, 
					qg->gid[i], iptogid(&ip, i));
#endif
			if(qg->gid[i] != iptogid(&ip, i)) {
				x=1;
				break;
			}
		}
		if(!x)
			return 1;
	}
	return 0;
}

/*
 * is_hgnodeip_excluded: is a wrapper of is_hgnode_excluded() which takes as
 * first argv an inet_prefix instead of a quadro_group
 */
int is_hgnodeip_excluded(inet_prefix *hgnodeip, u_int **excluded_hgnode,
		int tot_excluded_hgnodes)
{
	quadro_group qg;
	
	iptoquadg(*hgnodeip, 0, &qg, QUADG_GID);
	return is_hgnode_excluded(&qg, excluded_hgnode, tot_excluded_hgnodes, 0);
}

/*
 * random_gid_level_0: chooses a random gid of level 0, which is up, and
 * stores it in `qg'->gid[0], then convert it to an ip and stores it in `to'.
 * If `exclude_me' isn't zero, it won't choose ourself as the gid of level 0.
 * If the gid is found 0 is returned otherwise -1 is the return value.
 * If the gid found is also a MAP_ME node, 2 is returned.
 */
int random_gid_level_0(quadro_group *qg, inet_prefix *to, int exclude_me)
{
	int x, e, i;

	/* 
	 * Set `e' and `i' to a rand value from 0 to MAXGROUPNODE-1.
	 * In the first for go from `e' to MAXGROUPNODE-1, if nothing is found
	 * continue in the second for and go from `i' to 0. If nothing is
	 * found return -1. 
	 */

	for(x=0, e=i=rand_range(0, MAXGROUPNODE-1); e<MAXGROUPNODE; e++) {
		if(!(me.int_map[e].flags & MAP_VOID)) {
			if(exclude_me && (me.int_map[e].flags & MAP_ME))
				continue;
			qg->gid[0]=e;
			x=1;
			break;
		}
	}
	if(!x)
		for(x=0; i>=0; i--) {
			if(!(me.int_map[i].flags & MAP_VOID)) {
				if(exclude_me && (me.int_map[i].flags & MAP_ME))
					continue;
				qg->gid[0]=i;
				x=1;
				break;
			}
		}
	if(x) {
		gidtoipstart(qg->gid, me.cur_quadg.levels, me.cur_quadg.levels, 
				my_family, to);
		debug(DBG_NOISE, "find_hashgnode: Internal found: gid0 %d, to "
				"%s!", qg->gid[0], inet_to_str(*to));
		return me.int_map[qg->gid[0]].flags & MAP_ME ? 2 : 0;
	}

	return -1;
}

/*
 * find_hash_gnode_recurse: it recurse itself to create multiple sub tree. The
 * tree is started by find_hash_gnode()
 */
int find_hash_gnode_recurse(quadro_group qg, int level, inet_prefix *to,
		u_int **excluded_hgnode, int tot_excluded_hgnodes,
		int exclude_me)
{
	int gid, i, e, steps, err, ret;
	map_gnode *gnode;

	if(!level)
		return random_gid_level_0(&qg, to, exclude_me);

	/*
	 * This is how the ip nearer to `hash' is found:
	 * - find_hash_gnode() calls, for the first time, 
	 *   find_hash_gnode_recurse(). The hash's ip is converted as a 
	 *   quadro_group and stored in the argv `qg' and the parameter `level'
	 *   is set to the number of total levels available minus one.
	 * - if `level' is equal to 0 choose a random gid of level 0 an
	 *   convert `qg' in the inet_prefix format, store it in `to' and
	 *   return.
	 * loop1:
	 * 	- If the gnode `gq'.gid[level] is down increment or decrement 
	 * 	  (alternatively) `gq'.gid[level] and continue the loop1.
	 *	  If (it is up) {
	 *	  	if (`gq'.gid[level] is a gnode where we belong) {
	 *	  		call recursively find_hash_gnode_recurse,
	 *	  		giving the new modified `qg' and `level'-1 as
	 *	  		new parametres.
	 *	  		If (the return value is not an error) {
	 *	  			return now with that value because in
	 *	  			a sub tree, the hash_gnode was already
	 *	  			found. 
	 *	  		} 
	 *	  	} otherwise {
	 *	  		return and stor into `to' the ip of the
	 *	  		border_node that will be used to forward the 
	 *	  		pkt to the hash_gnode.
	 *	  	}
	 *	  }
	 * - return -1
	 */
	
#if 0	/* TOO NOISY */
	debug(DBG_INSANE, "find_hashgnode: lvl %d, start gid %d", level, qg.gid[level]);
#endif

	/* the maximum steps required to complete the for. */
	steps = qg.gid[level] >= MAXGROUPNODE/2 ? qg.gid[level] : MAXGROUPNODE-qg.gid[level];

	for(i=0, e=1, gid=qg.gid[level]; i < steps; e&1 ? i++ : i, e=(~(e & 1)) & 1) {
		/* `i' is incremented only when `e' is odd, while `e'
		 * is always alternated between 0 and 1. */

		if(!(e & 1) && (qg.gid[level]+i < MAXGROUPNODE))
			gid=qg.gid[level]+i;
		else if(qg.gid[level]-i >= 0)
			gid=qg.gid[level]-i;
		else 
			continue;

		gnode=gnode_from_pos(gid, me.ext_map[_EL(level)]);
		if(!(gnode->g.flags & MAP_VOID) &&
				!(gnode->flags & GMAP_VOID)) {
			qg.gid[level]=gid;

#if 0	/* TOO NOISY */
			debug(DBG_NOISE, "find_hashgnode: 	lvl %d gid %d", level, qg.gid[level]);
#endif

			if(!quadg_gids_cmp(qg, me.cur_quadg, level)) {
				/* Is this hash_gnode not wanted ? */
				if(excluded_hgnode && level == 1 &&
						is_hgnode_excluded(&qg, excluded_hgnode, 
							tot_excluded_hgnodes, 1))
					continue; /* yea, exclude it */

				ret=find_hash_gnode_recurse(qg, level-1, to, excluded_hgnode,
						tot_excluded_hgnodes, exclude_me);
				if(ret != -1)
					/* We have found it in some sub trees. */
					return ret;
			} else {
				/* Check if it is excluded */
				if(excluded_hgnode && 
						is_hgnode_excluded(&qg, excluded_hgnode,
							tot_excluded_hgnodes, level))
					continue; /* Yes, it is */
				
				err=get_gw_ips(me.int_map, me.ext_map, me.bnode_map,
						me.bmap_nodes, &me.cur_quadg,
						gnode, level, 0, to, 0, 1);
				debug(DBG_NOISE, "find_hashgnode: ext_found, err %d, to %s!",
						err, inet_to_str(*to));

				if(err >= 0)
					/* 
					 * Forward the pkt to the found
					 * border_node, which will forward it
					 * to the hash_gnode
					 */
					return 1;
			}
		}

	} /* for(...) */


#if 0	/* TOO NOISY */
	debug(DBG_INSANE, "find_hashgnode: Exausted: lvl %d gid %d", level, qg.gid[level]);
#endif
	/* We didn't find anything in the this level, so
	 * returns from this tree */
	return -1;
}

/*
 * find_hash_gnode: It stores in `to' the ip of the node nearer to the
 * `hash'_gnode and returns 0. If we aren't part of the hash_gnode, it sets in 
 * `to' the ip of the bnode_gnode that will route the pkt and returns 1.
 * If the found hash_gnode is the MAP_ME node itself then 2 is returned.
 * If either a hash_gnode and a bnode_gnode aren't found, -1 is returned.
 * All the hash_gnodes included in `excluded_hgnode' will be excluded by the
 * algorithm.
 * If `exclude_me' is set to 1, it will not return ourself as the hash_gnode.
 */
int find_hash_gnode(u_int hash[MAX_IP_INT], inet_prefix *to, 
	u_int **excluded_hgnode, int tot_excluded_hgnodes,
	int exclude_me)
{
	int total_levels;
	quadro_group qg;
	
	total_levels=FAMILY_LVLS;

	/* Hash to ip and quadro_group conversion */
	inet_setip(to, hash, my_family);
	inet_htonl(to->data, to->family);
	iptoquadg(*to, me.ext_map, &qg, QUADG_GID|QUADG_GNODE);
	
		
	return find_hash_gnode_recurse(qg, total_levels-1, to, excluded_hgnode,
			tot_excluded_hgnodes, exclude_me);
}


/*
 *
 *  *  *  *  Packets  *  *  *
 *
 */

/*
 * andna_flood_pkt: Sends the `rpkt' pkt to all the rnodes of our same gnode
 * and exclude the the rpkt->from node if `exclude_rfrom' is non zero.
 * The return value of flood_pkt_send() is returned.
 */
int andna_flood_pkt(PACKET *rpkt, int exclude_rfrom)
{
	PACKET flood_pkt;
	int real_from_rpos=-1, ret;
	int(*exclude_function)(TRACER_PKT_EXCLUDE_VARS);

	pkt_copy(&flood_pkt, rpkt);
	flood_pkt.sk=0;
	/* be sure that the other nodes don't reply to rfrom again */
	flood_pkt.hdr.flags&=~ASYNC_REPLY;
	flood_pkt.hdr.flags|=BCAST_PKT;
	
	/* If the pkt was sent from an our rnode, ignore it while flooding */
	if(exclude_rfrom)
		real_from_rpos=ip_to_rfrom(flood_pkt.from, 0, 0, 0);
	if(real_from_rpos < 0 || !exclude_rfrom) {
		exclude_function=exclude_glevel;
		real_from_rpos=-1;
	} else
		exclude_function=exclude_from_and_glevel;
	ret=flood_pkt_send(exclude_function, 1, -1, real_from_rpos, flood_pkt);

	return ret;
}

/* 
 * andna_find_flood_pkt_id: Search in the `ids_array' a member which is equal
 * to `pkt_id', if it is found its array position is returned otherwise -1
 * will be the return value
 */
int andna_find_flood_pkt_id(int *ids_array, int pkt_id)
{
	int i;
	
	for(i=0; i < ANDNA_MAX_FLOODS; i++)
		if(ids_array[i] == pkt_id)
			return i;
	return -1;
}

/*
 * andna_add_flood_pkt_id: If the `pkt_id' is already present in the
 * `ids_array', 1 is returned, otherwise `pkt_id' is added at the 0 position
 * of the array. All the array elements, except the last one, will be
 * preserved and shifted of one position like a FIFO.
 */
int andna_add_flood_pkt_id(int *ids_array, int pkt_id)
{
	int i;

	if((i=andna_find_flood_pkt_id(ids_array, pkt_id)) < 0) {
		int tmp_array[ANDNA_MAX_FLOODS-1];
		
		/* Shift the array of one position to free the position 0
		 * where the new id will be added */
		memcpy(tmp_array, ids_array, sizeof(int)*(ANDNA_MAX_FLOODS-1));
		memcpy(&ids_array[1], tmp_array, sizeof(int)*(ANDNA_MAX_FLOODS-1));
		ids_array[0]=pkt_id;

		return 0;
	}

	return 1;
}


/*
 *
 *  *  *  *  Hostname registration  *  *  *
 *
 */

/*
 * andna_register_hname
 * 
 * Registers or updates the `alcl->hostname' hostname. It also registers the
 * snsd records present in `alcl->service'.
 * 
 * If `snsd_delete' is not null, the registration request becomes a deletion
 * request: it will ask to andna to delete all the snsd records equal to
 * `snsd_delete'.
 */
int andna_register_hname(lcl_cache *alcl, snsd_service *snsd_delete)
{
	PACKET pkt, rpkt;
	struct andna_reg_pkt req;
	u_int hash_gnode[MAX_IP_INT];
	inet_prefix to;
		
	snsd_service *snsd;
	char *sign=0, *buf;
	const char *ntop; 
	int ret=0;
	ssize_t err, pkt_sz=0;
	time_t  cur_t;

	setzero(&req, sizeof(req));
	setzero(&pkt, sizeof(pkt));
	setzero(&rpkt, sizeof(rpkt));
	cur_t=time(0);

	if(alcl->flags & ANDNA_UPDATING) 
		/* we are already updating this node! */
		return 0;

	alcl->flags|=ANDNA_UPDATING;
	
	if(alcl->timestamp) {
		if(cur_t > alcl->timestamp && 
			(cur_t - alcl->timestamp) < ANDNA_MIN_UPDATE_TIME)
			/* We have too wait a little more before sending an
			 * update */
			return -1;

		req.flags|=ANDNA_PKT_UPDATE;
		req.hname_updates = ++alcl->hname_updates;
	}

	/* Don't register the hname while we are (re)-hooking, 
	 * our IP might change */
	while(me.cur_node->flags & MAP_HNODE)
		sleep(1);
	
	/* 
	 * Filling the request structure 
	 */

	inet_copy_ipdata(req.rip, &me.cur_ip); 
	andna_hash(my_family, alcl->hostname, strlen(alcl->hostname),
			req.hash, hash_gnode);
	memcpy(req.pubkey, lcl_keyring.pubkey, ANDNA_PKEY_LEN);

	/* Convert the pkt from host to network order */
	ints_host_to_network((void *)&req, andna_reg_pkt_iinfo);
	
	/* Sign the packet */
	sign=(char*)rsa_sign((u_char *)&req, ANDNA_REG_SIGNED_BLOCK_SZ, 
			lcl_keyring.priv_rsa, 0);
	memcpy(req.sign, sign, ANDNA_SIGNATURE_LEN);
	
	/* Find the hash_gnode that corresponds to the hash `hash_gnode'*/
	if((err=find_hash_gnode(hash_gnode, &to, 0, 0, 1)) < 0) {
		debug(DBG_SOFT, "andna_register_hname: hash_gnode not found ;(");
		ERROR_FINISH(ret, -1, finish);
	} else if(err == 1)
		req.flags|=ANDNA_PKT_FORWARD;

	if(snsd_delete) {
		snsd=snsd_delete;
		req.flags|=ANDNA_PKT_SNSD_DEL;
	} else
		snsd=alcl->service;
		
	ntop=inet_to_str(to);
	debug(DBG_INSANE, "Quest %s to %s", rq_to_str(ANDNA_REGISTER_HNAME), ntop);
	
	/* Fill the packet and send the request */
	pkt_sz=ANDNA_REG_PKT_SZ+SNSD_SERVICE_LLIST_PACK_SZ(alcl->service);
	pkt_addto(&pkt, &to);
	pkt_addcompress(&pkt);
	pkt_fill_hdr(&pkt.hdr, ASYNC_REPLY, 0, ANDNA_REGISTER_HNAME, pkt_sz);
	
	pkt.msg=buf=xmalloc(pkt_sz);
	
	memcpy(pkt.msg, &req, ANDNA_REG_PKT_SZ);
	buf+=ANDNA_REG_PKT_SZ;
	
	if(snsd_pack_all_services(buf, pkt_sz-ANDNA_REG_PKT_SZ, snsd) < 0) {
		debug(DBG_SOFT, "andna_register_hname: couldn't pack "
				"alcl->service");
		ERROR_FINISH(ret, -1, finish);
	}
	
	err=send_rq(&pkt, 0, ANDNA_REGISTER_HNAME, 0, ACK_AFFERMATIVE, 1, &rpkt);
	if(err < 0) {
		error("andna_register_hname(): Registration of \"%s\" to %s "
				"failed.", alcl->hostname, ntop);
		ERROR_FINISH(ret, -1, finish);
	}

	/* Ehi, we've registered it! Update the hname timestamp */
	alcl->timestamp=cur_t;

finish:
	alcl->flags&=~ANDNA_UPDATING;
	if(sign)
		xfree(sign);
	pkt_free(&pkt, 1);
	pkt_free(&rpkt, 0);
	return ret;
}

/* 
 * andna_recv_reg_rq
 *
 * It takes care of a registration request. If we aren't
 * the rightful hash_gnode, we forward the request (again), otherwise the
 * request is examined. If it is valid the hostname is registered or updated
 * in the andna_cache.
 */
int andna_recv_reg_rq(PACKET rpkt)
{
	PACKET pkt, rpkt_local_copy;
	struct andna_reg_pkt *req;
	u_int hash_gnode[MAX_IP_INT], *excluded_hgnode[1];
	inet_prefix rfrom, to;
	
	RSA *pubkey=0;
	andna_cache_queue *acq=0;
	andna_cache *ac=0;
	snsd_service *snsd_unpacked=0;
	snsd_node *snd=0;
	
	time_t cur_t;
	u_short snsd_counter;
	int ret=0, err;
	size_t unpacked_sz, packed_sz;
	char *ntop=0, *rfrom_ntop=0, *snsd_pack;
	u_char forwarded_pkt=0;
	const u_char *pk;

	pkt_copy(&rpkt_local_copy, &rpkt);

	req=(struct andna_reg_pkt *)rpkt_local_copy.msg;
	if(rpkt.hdr.sz < ANDNA_REG_PKT_SZ || 
			rpkt.hdr.sz > SNSD_SERVICE_MAX_LLIST_PACK_SZ)
		ERROR_FINISH(ret, -1, finish);
	
	packed_sz=rpkt.hdr.sz - ANDNA_REG_PKT_SZ;
	snsd_pack=rpkt_local_copy.msg+ANDNA_REG_PKT_SZ;

	if(rpkt.hdr.flags & BCAST_PKT)
		/* The pkt we received has been only forwarded to us */
		forwarded_pkt=1;

	/* Check if we already received this pkt during the flood */
	if(forwarded_pkt && 
			andna_add_flood_pkt_id(last_reg_pkt_id, rpkt.hdr.id)) {
		debug(DBG_INSANE, "Dropped 0x%0x andna pkt, we already "
				"received it", rpkt.hdr.id);
		ERROR_FINISH(ret, 0, finish);
	}

	/* Save the real sender of the request */
	inet_setip(&rfrom, req->rip, my_family);

	ntop=xstrdup(inet_to_str(rpkt.from));
	rfrom_ntop=xstrdup(inet_to_str(rfrom));
	debug(DBG_SOFT, "Received %s%sfrom %s, rfrom %s", rq_to_str(rpkt.hdr.op),
			forwarded_pkt ? " (forwarded) " : " ", ntop, rfrom_ntop);

	memcpy(&pkt, &rpkt, sizeof(PACKET));
	inet_copy(&pkt.from, &rfrom);

	/* Send the replies in UDP, they are so tiny */
	pkt_addsk(&pkt, my_family, 0, SKT_UDP);
	
	/* Verify the signature */
	pk=(const u_char*)req->pubkey;
	pubkey=get_rsa_pub(&pk, ANDNA_PKEY_LEN);
	if(!pubkey || !verify_sign((u_char *)req, ANDNA_REG_SIGNED_BLOCK_SZ,
				(u_char*)req->sign, ANDNA_SIGNATURE_LEN, pubkey)) {
		/* Bad, bad signature */
		debug(DBG_SOFT, "Invalid signature of the 0x%x reg request", 
				rpkt.hdr.id);
		if(!forwarded_pkt)
			pkt_err(pkt, E_INVALID_SIGNATURE, 0);
		ERROR_FINISH(ret, -1, finish);
	}

	/* Revert the packet from network to host order */
	ints_network_to_host((void *)req, andna_reg_pkt_iinfo);

	/* If we don't belong to the gnode of `rfrom', then we have to exclude
	 * it from the find_hash_gnode search, since we have received the 
	 * pkt from that gnode and it is likely that `rfrom' is the only node 
	 * of that gnode.
	 */
	excluded_hgnode[0] = ip_gids_cmp(rfrom, me.cur_ip, 1) ? rfrom.data : 0;

	/* 
	 * Are we the hash_gnode for req->hash? Check also if we have to
	 * continue to forward the pkt to make it reach the real hash_gnode
	 */

	andna_hash_by_family(my_family, (u_char *)req->hash, hash_gnode);
	if((err=find_hash_gnode(hash_gnode, &to, excluded_hgnode, 1, 0)) < 0) {
		debug(DBG_SOFT, "We are not the right (rounded)hash_gnode. "
				"Rejecting the 0x%x reg request", rpkt.hdr.id);
		if(!forwarded_pkt)
			pkt_err(pkt, E_ANDNA_WRONG_HASH_GNODE, 0);
		ERROR_FINISH(ret, -1, finish);
	} else if(err == 1) {
		if(!(req->flags & ANDNA_PKT_FORWARD)) {
			if(!forwarded_pkt)
				pkt_err(pkt, E_ANDNA_WRONG_HASH_GNODE, 0);
			ERROR_FINISH(ret, -1, finish);
		}

		/* Continue to forward the received pkt */
		debug(DBG_SOFT, "The reg request pkt will be forwarded to: %s",
				inet_to_str(to));
		ret=forward_pkt(rpkt, to);
		goto finish;
	}

	/* Are we a new hash_gnode ? */
	if(time(0)-me.uptime < (ANDNA_EXPIRATION_TIME/3) && 
			!(ac=andna_cache_findhash((int*)req->hash))) {
		/*
		 * We are a new hash_gnode and we haven't this hostname in our
		 * andna_cache, so we have to check if there is an
		 * old hash_gnode which has already registered this hostname.
		 */
		if((ac=get_single_andna_c(req->hash, hash_gnode))) {
			/* 
			 * The hostname was already registered, so we save it
			 * in our andna_cache.
			 */
			clist_add(&andna_c, &andna_c_counter, ac);
			
			/* Spread it in our gnode */
			spread_single_acache(req->hash);
		}
	}

	/* Ask the counter_node if it is ok to register/update the hname */
	if(!(req->flags & ANDNA_PKT_SNSD_DEL)) {
		if(andna_check_counter(rpkt) == -1) {
			debug(DBG_SOFT, "Registration rq 0x%x rejected: %s", 
					rpkt.hdr.id,
					rq_strerror(E_ANDNA_CHECK_COUNTER));
			if(!forwarded_pkt)
				pkt_err(pkt, E_ANDNA_CHECK_COUNTER, 0);
			ERROR_FINISH(ret, -1, finish);
		}
	}

	/***
	 * Finally, let's register/update the hname 
	 */
	cur_t=time(0);	
	ac=andna_cache_addhash((int*)req->hash);
	acq=ac_queue_add(ac, req->pubkey);
	if(!acq) {
		debug(DBG_SOFT, "Registration rq 0x%x rejected: %s", 
				rpkt.hdr.id, rq_strerror(E_ANDNA_QUEUE_FULL));
		if(!forwarded_pkt)
			pkt_err(pkt, E_ANDNA_QUEUE_FULL, 0);
		ERROR_FINISH(ret, -1, finish);
	}
	/***/

	/**
	 * Check if the counter of number of updates matches with the pkt */
	if(acq->hname_updates > req->hname_updates) {
		debug(DBG_SOFT, "Registration rq 0x%x rejected: hname_updates"
				" mismatch %d > %d", rpkt.hdr.id, 
				acq->hname_updates, req->hname_updates);
		if(!forwarded_pkt)
			pkt_err(pkt, E_ANDNA_HUPDATE_MISMATCH, 0);
		ERROR_FINISH(ret, -1, finish);
	}
	/**/

	/**
	 * Has the registration request been sent too early ? */
	if(cur_t > acq->timestamp && 
			(cur_t - acq->timestamp) < ANDNA_MIN_UPDATE_TIME) {
		debug(DBG_SOFT, "Registration rq 0x%x rejected: %s", 
			rpkt.hdr.id, rq_strerror(E_ANDNA_UPDATE_TOO_EARLY));
		if(!forwarded_pkt)
			pkt_err(pkt, E_ANDNA_UPDATE_TOO_EARLY, 0);
		ERROR_FINISH(ret, -1, finish);
	}
	/**/


	/*
	 * SNSD services registration
	 */

	if(acq != ac->acq) {
		/* 
		 * This request has been queued in the acq. We store the main
		 * ip and discard the rest of the snsd records 
		 */
		snsd_add_mainip(&snsd_unpacked, &snsd_counter,
					SNSD_MAX_QUEUE_RECORDS, rfrom.data);
	} else {
		/* 
		 * Register the snsd records 
		 */

		/* unpack the snsd services */
		snsd_unpacked=snsd_unpack_all_service(snsd_pack, packed_sz, 
				&unpacked_sz, &snsd_counter);
		
		if((!snsd_unpacked && req->flags & ANDNA_PKT_SNSD_DEL) ||
			(snsd_counter > SNSD_MAX_RECORDS-1)) {

			debug(DBG_SOFT, "Registration rq 0x%x rejected: couldn't unpack"
					" the snsd llist", rpkt.hdr.id);
			if(!forwarded_pkt)
				pkt_err(pkt, E_INVALID_REQUEST, 0);
			ERROR_FINISH(ret, -1, finish);
		}

		if(req->flags & ANDNA_PKT_SNSD_DEL) {
			/*
			 * Delete, from the andna_cache, all the snsd records
			 * which are equal to those included in the 
			 * registration pkt.
			 */
			snsd_record_del_selected(&acq->service, &acq->snsd_counter,
						 snsd_unpacked);
		} else {
			/*
			 * Register the snsd services in our andna_cache 
			 */

			/* Add the mainip and update its IP */
			snd=snsd_add_mainip(&snsd_unpacked, &snsd_counter,
						  SNSD_MAX_RECORDS, rfrom.data);
			inet_copy_ipdata_raw(snd->record, &rfrom);

			/**
			 * Set the mainip flag only to the real mainip record,
			 * in this way we're sure that there is only one. */
			snsd_unset_all_flags(snsd_unpacked, SNSD_NODE_MAIN_IP);
			snd->flags|=SNSD_NODE_MAIN_IP;
			/**/
		
		}
	}

	/*
	 * substitute the old snsd records with the new ones 
	 */
	snsd_service_llist_del(&acq->service);
	acq->service=snsd_unpacked;
	acq->snsd_counter=snsd_counter;

	/* 
	 * Final registration step: touch the hname timestamp
	 */
	acq->hname_updates=req->hname_updates+1;
	acq->timestamp=cur_t;

	/* Reply to the requester: <<Yes, don't worry, it worked.>> */
	if(!forwarded_pkt) {
		debug(DBG_SOFT, "Registration rq 0x%x accepted.", rpkt.hdr.id);
		pkt.msg=0;
		pkt_fill_hdr(&pkt.hdr, ASYNC_REPLIED, rpkt.hdr.id, ACK_AFFERMATIVE, 0);
		ret=forward_pkt(pkt, rfrom);
	}
	
	/**
	 * Broadcast the request to the entire gnode of level 1 to let the
	 * other nodes register the hname.
	 */
	if(!forwarded_pkt)
		andna_add_flood_pkt_id(last_reg_pkt_id, rpkt.hdr.id);
	andna_flood_pkt(&rpkt, 1);
	/**/
	
finish:
	if(ntop)
		xfree(ntop);
	if(rfrom_ntop)
		xfree(rfrom_ntop);
	if(pubkey)
		RSA_free(pubkey);
	pkt_free(&rpkt_local_copy, 0);
	
	return ret;
}

/*
 * andna_check_counter
 *
 * asks the counter_node if it is ok to accept the registration request in 
 * `pkt' and register the requested hname.
 *
 * If -1 is returned the answer is no.
 */
int andna_check_counter(PACKET pkt)
{
	PACKET rpkt;
	int ret=0, err;
	u_int rip_hash[MAX_IP_INT], hash_gnode[MAX_IP_INT];
	struct andna_reg_pkt *req;
	const char *ntop;
	u_char forwarded_pkt=0;

	setzero(&rpkt, sizeof(PACKET));
	req=(struct andna_reg_pkt *)pkt.msg;
	pkt.msg=0;

	if(pkt.hdr.flags & BCAST_PKT)
		forwarded_pkt=1;
	
	/* Calculate the hash of the IP of the sender node. This hash will
	 * be used to reach its counter node. */
	andna_hash(my_family, req->rip, MAX_IP_SZ, rip_hash, hash_gnode);
	
	/* Find a hash_gnode for the rip_hash */
	req->flags&=~ANDNA_PKT_FORWARD;

	if((err=find_hash_gnode(hash_gnode, &pkt.to, 0, 0, 1)) < 0) {
		debug(DBG_INSANE, "andna_check_counter: Couldn't find a decent"
				" counter_gnode");
		ERROR_FINISH(ret, -1, finish);
	} else if(err == 1)
		req->flags|=ANDNA_PKT_FORWARD;
	
	ntop=inet_to_str(pkt.to);
	debug(DBG_INSANE, "Quest %s to %s", rq_to_str(ANDNA_CHECK_COUNTER), ntop);
	
	pkt.hdr.flags|=ASYNC_REPLY;
	
	/* Append our ip in the pkt */
	pkt.hdr.sz=ANDNA_REG_PKT_SZ+MAX_IP_SZ;
	pkt.msg=xmalloc(pkt.hdr.sz);
	memcpy(pkt.msg, req, ANDNA_REG_PKT_SZ);
	inet_copy_ipdata((u_int *)(pkt.msg+ANDNA_REG_PKT_SZ), &me.cur_ip);
	
	/* If we are checking a registration pkt which has been only
	 * forwarded to us (and already registered), we tell the counter_node
	 * to just check the request. We don't want it to update its
	 * hname_updates counter */
	if(forwarded_pkt) {
		req=(struct andna_reg_pkt *)pkt.msg;
		req->flags|=ANDNA_PKT_JUST_CHECK;
		
		/* Adjust the flags */
		pkt.hdr.flags&=~BCAST_PKT; 
	}

	/* Throw it */
	pkt.sk=0;  /* Create a new connection */
	ret=send_rq(&pkt, 0, ANDNA_CHECK_COUNTER, 0, ACK_AFFERMATIVE, 1, &rpkt);
	ret=(ret < 0) ? -1 : ret;

finish:
	pkt_free(&pkt, 1);
	pkt_free(&rpkt, 0);
	return ret;
}

int andna_recv_check_counter(PACKET rpkt)
{
	PACKET pkt, rpkt_local_copy;
	struct andna_reg_pkt *req;
	inet_prefix rfrom, to;
	RSA *pubkey=0;
	counter_c *cc;
	counter_c_hashes *cch;
	u_int rip_hash[MAX_IP_INT], hash_gnode[MAX_IP_INT], *excluded_hgnode[1];
	int ret=0, err, old_updates;

	char *ntop=0, *rfrom_ntop=0, *buf;
	u_char forwarded_pkt=0, just_check=0;
	const u_char *pk;

	pkt_copy(&rpkt_local_copy, &rpkt);
	ntop=xstrdup(inet_to_str(rpkt.from));
	
	req=(struct andna_reg_pkt *)rpkt_local_copy.msg;
	if(rpkt.hdr.sz != ANDNA_REG_PKT_SZ+MAX_IP_SZ) {
		debug(DBG_SOFT, ERROR_MSG "Malformed check_counter pkt from %s: %d != %d", 
				ERROR_FUNC, ntop, rpkt.hdr.sz, ANDNA_REG_PKT_SZ+MAX_IP_SZ);
		ERROR_FINISH(ret, -1, finish);
	}
	
	if(rpkt.hdr.flags & BCAST_PKT)
		/* The pkt we received has been only forwarded to us */
		forwarded_pkt=1;

	if(req->flags & ANDNA_PKT_JUST_CHECK)
		just_check=1;

	/* Check if we already received this pkt during the flood */
	if(forwarded_pkt && 
			andna_add_flood_pkt_id(last_counter_pkt_id, rpkt.hdr.id)) {
		debug(DBG_INSANE, "Dropped 0x%0x andna pkt, we already "
				"received it", rpkt.hdr.id);
		ERROR_FINISH(ret, 0, finish);
	}

	/* Save the real sender of the request */
	buf=rpkt.msg+ANDNA_REG_PKT_SZ;
	inet_setip(&rfrom, (u_int *)buf, my_family);

	rfrom_ntop=xstrdup(inet_to_str(rfrom));
	debug(DBG_SOFT, "Received %s%sfrom %s, rfrom %s", rq_to_str(rpkt.hdr.op),
			forwarded_pkt ? " (forwarded) " : " ", ntop, rfrom_ntop);
	
	memcpy(&pkt, &rpkt, sizeof(PACKET));
	inet_copy(&pkt.from, &rfrom);

	/* Reply to rfrom using a UDP sk, since the replies are very small */
	pkt_addsk(&pkt, my_family, 0, SKT_UDP);
	
	/* Verify the signature */
	pk=(const u_char*)req->pubkey;
	pubkey=get_rsa_pub(&pk, ANDNA_PKEY_LEN);
	if(!pubkey || !verify_sign((u_char *)req, ANDNA_REG_SIGNED_BLOCK_SZ, 
				(u_char*)req->sign, ANDNA_SIGNATURE_LEN, pubkey)) {
		/* Bad signature */
		debug(DBG_SOFT, "Invalid signature of the 0x%x check "
				"counter request", rpkt.hdr.id);
		if(!forwarded_pkt)
			pkt_err(pkt, E_INVALID_SIGNATURE, 0);
		ERROR_FINISH(ret, -1, finish);
	}

	/* Revert the packet from network to host order */
	ints_network_to_host((void *)req, andna_reg_pkt_iinfo);

	/* If don't belong to the gnode of `rfrom', then we have to exclude
	 * it from the find_hash_gnode search, since we have received the 
	 * pkt from that gnode and it is likely that `rfrom' is the only node 
	 * of that gnode.
	 */
	excluded_hgnode[0] = ip_gids_cmp(rfrom, me.cur_ip, 1) ? rfrom.data : 0;
	debug(DBG_INSANE, "excluded_hgnode: %x ", excluded_hgnode[0]);

	/* 
	 * Check if we are the real counter node or if we have to continue to 
	 * forward the pkt 
	 */

	andna_hash(my_family, req->rip, MAX_IP_SZ, rip_hash, hash_gnode);
	if((err=find_hash_gnode(hash_gnode, &to, excluded_hgnode, 1, 0)) < 0) {
		debug(DBG_SOFT, "We are not the real (rounded)hash_gnode. "
				"Rejecting the 0x%x check_counter request",
				rpkt.hdr.id);
		if(!forwarded_pkt)
			pkt_err(pkt, E_ANDNA_WRONG_HASH_GNODE, 0);
		ERROR_FINISH(ret, -1, finish);
	} else if(err == 1) {
		if(!(req->flags & ANDNA_PKT_FORWARD)) {
			if(!forwarded_pkt)
				pkt_err(pkt, E_ANDNA_WRONG_HASH_GNODE, 0);
			ERROR_FINISH(ret, -1, finish);
		}

		/* Continue to forward the received pkt */
		debug(DBG_SOFT, "The check_counter rq pkt will be forwarded "
				"to: %s", inet_to_str(to));
		ret=forward_pkt(rpkt, to);
		goto finish;
	}

	/* Finally, let's register/update the hname */
	cc=counter_c_add(&rfrom, req->pubkey);
	if(!just_check)
		cch=cc_hashes_add(cc,(int*) req->hash);
	else
		cch=cc_findhash(cc, (int*)req->hash);
	if(!cch) {
		debug(DBG_SOFT, "Request %s (0x%x) rejected: %s", 
				rq_to_str(rpkt.hdr.op), rpkt.hdr.id, 
				rq_strerror(E_ANDNA_TOO_MANY_HNAME));
		if(!forwarded_pkt)
			pkt_err(pkt, E_ANDNA_TOO_MANY_HNAME, 0);
		ERROR_FINISH(ret, -1, finish);
	}

	old_updates = cch->hname_updates;
	old_updates-= !!just_check;
	if(old_updates > req->hname_updates) {
		debug(DBG_SOFT, "Request %s (0x%x) rejected: hname_updates"
			" mismatch %d > %d", rq_to_str(rpkt.hdr.op), rpkt.hdr.id,
				old_updates, req->hname_updates);
		if(!forwarded_pkt)
			pkt_err(pkt, E_ANDNA_HUPDATE_MISMATCH, 0);
		ERROR_FINISH(ret, -1, finish);
	} else if(!just_check) {
		/* Touch the hname */
		cch->hname_updates=req->hname_updates+1;
		cch->timestamp=time(0);
	}
		
	/* Report the successful result to rfrom */
	if(!forwarded_pkt || just_check) {
		debug(DBG_SOFT, "Check_counter rq 0x%x accepted.",
				rpkt.hdr.id);
		pkt_fill_hdr(&pkt.hdr, ASYNC_REPLIED, rpkt.hdr.id,
				ACK_AFFERMATIVE, 0);
		pkt.msg=0;
		ret=forward_pkt(pkt, rfrom);
	}

	/* 
	 * Broadcast the request to the entire gnode of level 1 to let the
	 * other counter_nodes register the hname.
	 */
	if(!just_check) {
		if(!forwarded_pkt)
			andna_add_flood_pkt_id(last_counter_pkt_id, rpkt.hdr.id);
		andna_flood_pkt(&rpkt, forwarded_pkt);
	}

finish: 
	if(ntop)
		xfree(ntop);
	if(rfrom_ntop)
		xfree(rfrom_ntop);
	if(pubkey)
		RSA_free(pubkey);
	pkt_free(&rpkt_local_copy, 0);
	
	return ret;
}


/*
 * 
 *  *  *  *  Hostname/IP resolution  *  *  *
 *
 */

/*
 * andna_resolve_hash_locally
 *
 * It tries to resolve the given md5 hname-hash by searching in the
 * local andna caches.
 * It uses the same arguments of `andna_resolve_hash' see below).
 */
snsd_service *andna_resolve_hash_locally(u_int hname_hash[MAX_IP_INT], int service, 
					  u_char proto,int *records)
{
	struct andna_resolve_rq_pkt req;
	lcl_cache *lcl;
	rh_cache *rhc;
	andna_cache *ac;
	snsd_service *ret;
	u_int hash;

	setzero(&req, sizeof(req));
	
	hash = fnv_32_buf(hname_hash, ANDNA_HASH_SZ, FNV1_32_INIT);

#ifndef ANDNA_DEBUG

	/*
	 * Search the hostname in the local cache first. Maybe we are so
	 * dumb that we are trying to resolve the same ip we registered.
	 */
	if((lcl=lcl_cache_find_hash(andna_lcl, hash))) {
		u_short fake_counter=0;

		*records=lcl->snsd_counter;
		ret=snsd_service_llist_copy(lcl->service, service, proto);

		/* Add our current main ip */
		if(service == SNSD_ALL_SERVICE || 
				service == SNSD_DEFAULT_SERVICE || !ret)
			snsd_add_mainip(&ret, &fake_counter,
					SNSD_MAX_RECORDS, me.cur_ip.data);
		return ret;
	}
	
	/*
	 * Last try before asking to ANDNA: let's see if we have it in
	 * the resolved_hnames cache
	 */
	if((rhc=rh_cache_find_hash(hash))) {
		*records=rhc->snsd_counter;
		ret=snsd_service_llist_copy(rhc->service, service, proto);

		if(!ret && (service != SNSD_ALL_SERVICE) && 
				(service != SNSD_DEFAULT_SERVICE))
			/* The specific service hasn't been found, fallback to
			 * SNSD_DEFAULT_SERVICE */
			ret=snsd_service_llist_copy(rhc->service, 
						    SNSD_DEFAULT_SERVICE, 
						    0);
		if(ret)
			return ret;
	}
	
#endif

	/*
	 * If we manage an andna_cache, it's better to peek at it.
	 */
	if((ac=andna_cache_gethash((int*)hname_hash))) {
		*records=ac->acq->snsd_counter;
		
		ret=snsd_service_llist_copy(ac->acq->service, service, proto);

		if(!ret && (service != SNSD_ALL_SERVICE) && 
				(service != SNSD_DEFAULT_SERVICE))
			/* The specific service hasn't been found, fallback to
			 * SNSD_DEFAULT_SERVICE */
			ret=snsd_service_llist_copy(ac->acq->service, 
						    SNSD_DEFAULT_SERVICE, 
						    0);
		if(ret)
			return ret;
	}

	return 0;
}

/*
 * andna_resolve_hash
 * 
 * It returns a snsd_service llist (see snsd.h) which contains the snsd
 * records of the resolved hostname. Among them there's at least the mainip
 * record which can be found using snsd_find_mainip().
 *
 * `hname_hash' is the full MD5 hash of the hostname we want to resolve.
 *
 * `service' specifies the service number of the resolution. If it is equal to
 * -1 the resolution will return all the registered snds records.
 *
 * `proto' is the protocol of the `service', it must be specified in the
 * proto_to_8bit() format.
 * 
 * In `*records' the number of records stored in the returned snsd_service
 * llist is written.
 * 
 * It returns 0 on error
 */
snsd_service *andna_resolve_hash(u_int hname_hash[MAX_IP_INT], int service, 
				 u_char proto, int *records)
{
	PACKET pkt, rpkt;
	struct andna_resolve_rq_pkt req;
	struct andna_resolve_reply_pkt *reply;
	rh_cache *rhc;
	snsd_service *sns_dup;
	u_int hash_gnode[MAX_IP_INT], hash32;
	inet_prefix to;

	snsd_service *sns, *snsd_unpacked, *ret=0;

	const char *ntop;
	char *snsd_packed;
	u_short snsd_counter=0;
	size_t packed_sz, unpacked_sz;
	ssize_t err;

	*records=0;
	setzero(&req, sizeof(req));
	setzero(&pkt, sizeof(pkt));
	setzero(&rpkt, sizeof(pkt));

	hash32=fnv_32_buf((u_char *)hname_hash, ANDNA_HASH_SZ, FNV1_32_INIT);

	/* Try to resolve the hostname locally */
	sns=andna_resolve_hash_locally(hname_hash, service, proto, records);
	if(sns)
		return sns;

	/* 
	 * Fill the request structure.
	 */
	req.service=service;
	req.proto=proto;
	inet_copy_ipdata(req.rip, &me.cur_ip);
	memcpy(req.hash, hname_hash, ANDNA_HASH_SZ);
	andna_hash_by_family(my_family, hname_hash, hash_gnode);
	
	/* 
	 * Ok, we have to ask to someone for the resolution.
	 * Let's see to whom we have to send the pkt 
	 */
	if((err=find_hash_gnode(hash_gnode, &to, 0, 0, 1)) < 0)
		ERROR_FINISH(ret, 0, finish);
	else if(err == 1)
		req.flags|=ANDNA_PKT_FORWARD;
		
	ntop=inet_to_str(to);
	debug(DBG_INSANE, "Quest %s to %s", rq_to_str(ANDNA_RESOLVE_HNAME), ntop);

	
	/* 
	 * Fill the packet and send the request 
	 */
	
	/* host -> network order */
	ints_host_to_network(&req, andna_resolve_rq_pkt_iinfo);
	
	pkt_addto(&pkt, &to);
	pkt.pkt_flags|=PKT_SET_LOWDELAY;
	pkt.hdr.flags|=ASYNC_REPLY;
	pkt.hdr.sz=ANDNA_RESOLVE_RQ_PKT_SZ;
	pkt.msg=xmalloc(pkt.hdr.sz);
	memcpy(pkt.msg, &req, pkt.hdr.sz);
	
	setzero(&rpkt, sizeof(PACKET));
	err=send_rq(&pkt, 0, ANDNA_RESOLVE_HNAME, 0, ANDNA_RESOLVE_REPLY, 1, &rpkt);
	if(err < 0) {
		debug(DBG_NORMAL, ERROR_MSG "Resolution of 0x%x failed.",
				  ERROR_FUNC, pkt.hdr.id);
		ERROR_FINISH(ret, 0, finish);
	}

	if(rpkt.hdr.sz <= ANDNA_RESOLVE_REPLY_PKT_SZ || 
			rpkt.hdr.sz > (SNSD_SERVICE_MAX_PACK_SZ +
					ANDNA_RESOLVE_REPLY_PKT_SZ))
		ERROR_FINISH(ret, 0, finish);

	/* 
	 * Take the ip we need from the replied pkt 
	 */
	reply=(struct andna_resolve_reply_pkt *)rpkt.msg;
	
	/* network -> host order */
	ints_network_to_host(reply, andna_resolve_reply_pkt_iinfo);

	/* Unpack the received snsd records */
	snsd_packed=rpkt.msg+sizeof(struct andna_resolve_reply_pkt);
	packed_sz=rpkt.hdr.sz-sizeof(struct andna_resolve_reply_pkt);
	if(service == -1)
		snsd_unpacked=snsd_unpack_all_service(snsd_packed, packed_sz,
							&unpacked_sz, 
							&snsd_counter);
	else
		snsd_unpacked=snsd_unpack_service(snsd_packed, packed_sz,
							&unpacked_sz,
							&snsd_counter);
		
	if(!snsd_unpacked ||
		((service == SNSD_ALL_SERVICE || 
		  service == SNSD_DEFAULT_SERVICE) &&
		 !snsd_find_mainip(snsd_unpacked))) {
		debug(DBG_SOFT, ERROR_MSG "Malformed resolution reply (0x%x)",
				ERROR_FUNC, rpkt.hdr.id);
		ERROR_FINISH(ret, 0, finish);
	}
	*records=snsd_counter;
	ret=snsd_unpacked;
	
	/* 
	 * Add the hostname in the resolved_hnames cache since it was
	 * successful resolved ;)
	 */
	reply->timestamp = time(0) - reply->timestamp;
	rhc=rh_cache_add_hash(hash32, reply->timestamp);
	sns_dup=snsd_service_llist_copy(snsd_unpacked, SNSD_ALL_SERVICE, 0);
	snsd_service_llist_merge(&rhc->service, &rhc->snsd_counter, sns_dup);
	
finish:
	pkt_free(&pkt, 1);
	pkt_free(&rpkt, 0);
	return ret;
}

/*
 * andna_resolve_hname
 * 
 * It is a wrapper to andna_resolve_hash() (see above): it hashes the given
 * `hname' string and calls andna_resolve_hash.
 * 
 * It returns 0 on error
 */
snsd_service *andna_resolve_hname(char *hname, int service, u_char proto, 
				  int *records)
{
	u_int hname_hash[MAX_IP_INT];

	hash_md5((u_char*)hname, strlen(hname), (u_char *)hname_hash);

	return andna_resolve_hash(hname_hash, service, proto, records);
}

/*
 * andna_recv_resolve_rq
 * 
 * replies to a hostname resolve request by giving the snsd records associated 
 * to the hostname.
 */
int andna_recv_resolve_rq(PACKET rpkt)
{
	PACKET pkt, rpkt_local_copy;
	struct andna_resolve_rq_pkt *req;
	struct andna_resolve_reply_pkt reply;
	
	andna_cache *ac;
	snsd_service *sns;

	u_int hash_gnode[MAX_IP_INT];
	inet_prefix rfrom, to;
	u_short service;
	size_t pack_sz;
	int ret=0, err;
	char *ntop=0, *rfrom_ntop=0, *buf;
	u_char spread_the_acache=0;

	
	if(rpkt.hdr.sz != ANDNA_RESOLVE_RQ_PKT_SZ)
		ERROR_FINISH(ret, -1, finish);
	
	pkt_copy(&rpkt_local_copy, &rpkt);
	req=(struct andna_resolve_rq_pkt *)rpkt_local_copy.msg;
	
	/* Save the real sender of the request */
	inet_setip(&rfrom, req->rip, my_family);

	ntop=xstrdup(inet_to_str(rpkt.from));
	rfrom_ntop=xstrdup(inet_to_str(rfrom));
	debug(DBG_NOISE, "Andna Resolve request 0x%x from: %s, real from: %s",
			rpkt.hdr.id, ntop, rfrom_ntop);
	
	memcpy(&pkt, &rpkt, sizeof(PACKET));
	inet_copy(&pkt.from, &rfrom);
	pkt_addsk(&pkt, my_family, 0, SKT_UDP);
	pkt_addcompress(&pkt);
	pkt_addlowdelay(&pkt);
	pkt_addlowdelay(&rpkt);

	/* network -> host order conversion of the rpkt_local_copy.smg */
	ints_network_to_host((void *)req, andna_resolve_rq_pkt_iinfo);

	/*
	 * Are we the right hash_gnode or have we to still forward the pkt ?
	 */
	andna_hash_by_family(my_family, (u_char *)req->hash, hash_gnode);
	if((err=find_hash_gnode(hash_gnode, &to, 0, 0, 0)) < 0) {
		debug(DBG_SOFT, "We are not the real (rounded)hash_gnode. "
				"Rejecting the 0x%x resolve_hname request",
				rpkt.hdr.id);
		pkt_err(pkt, E_ANDNA_WRONG_HASH_GNODE, 0);
		ERROR_FINISH(ret, -1, finish);
	} else if(err == 1) {
		if(!(req->flags & ANDNA_PKT_FORWARD)) {
			pkt_err(pkt, E_ANDNA_WRONG_HASH_GNODE, 0);
			ERROR_FINISH(ret, -1, finish);
		}

		/* Continue to forward the received pkt */
		debug(DBG_SOFT, "The resolve_hame rq pkt will be forwarded "
				"to: %s", inet_to_str(to));
		ret=forward_pkt(rpkt, to);
		goto finish;
	}

	/* 
	 * Search the hostname to resolve in the andna_cache 
	 */
	if(!(ac=andna_cache_gethash((int*)req->hash))) {

		/* We don't have that hname in our andna_cache */
	
		if(time(0)-me.uptime < (ANDNA_EXPIRATION_TIME/2)) {
			/*
			 * We are a new hash_gnode, let's see if there is
			 * an old hash_gnode which has this hostname.
			 */
			if((ac=get_single_andna_c(req->hash, hash_gnode))) {
				/* 
				 * We got the andna_cache from the old
				 * hash_gnode. Save it in our andna_cache, then
				 * reply to `rfrom' and diffuse it in our gnode
				 */
				clist_add(&andna_c, &andna_c_counter, ac);

				spread_the_acache=1;
				goto reply_resolve_rq;
			}
		}


		/* Nothing to do, there isn't it, bye. */
		debug(DBG_SOFT, "Request %s (0x%x) rejected: %s", 
				rq_to_str(rpkt.hdr.op), rpkt.hdr.id, 
				rq_strerror(E_ANDNA_NO_HNAME));
		pkt_err(pkt, E_ANDNA_NO_HNAME, 0);
		ERROR_FINISH(ret, -1, finish);
	}
	
reply_resolve_rq:
	/* 
	 * Send back the ip associated to the hname 
	 */
	debug(DBG_SOFT, "Resolve request 0x%x accepted", rpkt.hdr.id);
	
	/* Write the reply */
	setzero(&reply, sizeof(reply));
	reply.timestamp=time(0) - ac->acq->timestamp;

	/* host -> network order */
	ints_host_to_network((void *)&reply, andna_resolve_reply_pkt_iinfo);

	pack_sz=sizeof(reply);
	pack_sz+=req->service == SNSD_ALL_SERVICE ?
		  SNSD_SERVICE_LLIST_PACK_SZ(ac->acq->service) : 
			  SNSD_SERVICE_SINGLE_PACK_SZ(ac->acq->service);
	pkt_fill_hdr(&pkt.hdr, ASYNC_REPLIED, rpkt.hdr.id, ANDNA_RESOLVE_REPLY,
			pack_sz);
	
	pkt.msg=buf=xmalloc(pkt.hdr.sz);
	memcpy(pkt.msg, &reply, sizeof(reply));
	buf+=sizeof(reply);
	pack_sz-=sizeof(reply);
	
	if(req->service == SNSD_ALL_SERVICE)
		/* Pack all the registered snsd records */
		ret=snsd_pack_all_services(buf, pack_sz, ac->acq->service);
	else {
		/* Pack the snsd records of the specified service number */
		service=(u_short)req->service;
		sns=snsd_find_service(ac->acq->service, service, req->proto);

		if(!sns && service != SNSD_DEFAULT_SERVICE) {
			/*
			 * The specified service and proto record hasn't been
			 * found, fallback to SNSD_DEFAULT_SERVICE 
			 */
			sns=snsd_find_service(ac->acq->service, 
						SNSD_DEFAULT_SERVICE, 0);
		}

		/* pack what we found */
		ret=snsd_pack_service(buf, pack_sz, sns);
	}
	if(ret < 0) {
		debug(DBG_NORMAL, "Cannot pack the services for the 0x%x "
					"resolve request", rpkt.hdr.id);
		goto finish;
	}

	/* Forward it */
	ret=forward_pkt(pkt, rfrom);
	pkt_free(&pkt, 0);

	if(spread_the_acache) {
		/* Spread the received andna_cache in our gnode */
		spread_single_acache(req->hash);
	}
	
finish:
	if(ntop)
		xfree(ntop);
	if(rfrom_ntop)
		xfree(rfrom_ntop);
	pkt_free(&rpkt_local_copy, 0);

	return ret;
}

/*
 * andna_reverse_resolve
 *
 * It returns the copy of the local cache of a remote node.
 * The ip of the node is specified in `ip'.
 *
 * On error 0 is returned.
 */
lcl_cache *andna_reverse_resolve(inet_prefix ip)
{
	PACKET pkt, rpkt;
	lcl_cache *unpacked_lcl=0, *ret=0;
	inet_prefix to;
	
	const char *ntop; 
	int tmp_counter;
	ssize_t err;

	setzero(&pkt, sizeof(PACKET));
	setzero(&rpkt, sizeof(PACKET));
	inet_copy(&to, &ip);
	
	ntop=inet_to_str(to);
	debug(DBG_INSANE, "Quest %s to %s", rq_to_str(ANDNA_RESOLVE_IP), ntop);

	/* We have been asked to reverse resolve our same IP */
	if(!memcmp(to.data, me.cur_ip.data, MAX_IP_SZ) || 
			LOOPBACK(htonl(to.data[0])))
		return lcl_get_registered_hnames(andna_lcl);
	
	/* 
	 * Fill the packet and send the request 
	 */
	pkt_addto(&pkt, &to);
	pkt_addfrom(&rpkt, &to);
	pkt_addtimeout(&pkt, ANDNA_REV_RESOLVE_RQ_TIMEOUT, 1, 1);
	
	err=send_rq(&pkt, 0, ANDNA_RESOLVE_IP, 0, ANDNA_REV_RESOLVE_REPLY, 1, &rpkt);
	if(err < 0) {
		error(ERROR_MSG "Reverse resolution of the %s "
				"ip failed.", ERROR_FUNC, inet_to_str(to));
		ERROR_FINISH(ret, 0, finish);
	}

	unpacked_lcl=unpack_lcl_cache(rpkt.msg, rpkt.hdr.sz, &tmp_counter);
	if(tmp_counter > ANDNA_MAX_HOSTNAMES || tmp_counter < 0)
		ERROR_FINISH(ret, 0, finish);
	ret=unpacked_lcl;

finish:
	pkt_free(&pkt, 1);
	pkt_free(&rpkt, 1);
	return ret;
}

/*
 * andna_recv_rev_resolve_rq
 *
 * It replies to a reverse hostname resolve request which asks all the 
 * hostnames associated with a given ip.
 */
int andna_recv_rev_resolve_rq(PACKET rpkt)
{
	PACKET pkt;

	const char *ntop;
	int ret=0, err;
	
	lcl_cache *alcl=andna_lcl;

	setzero(&pkt, sizeof(PACKET));

	ntop=inet_to_str(rpkt.from);
	debug(DBG_INSANE, "Andna reverse resolve request received 0x%x from %s",
			rpkt.hdr.id, ntop);
	
	/*
	 * Build the reply pkt
	 */
	
	pkt_fill_hdr(&pkt.hdr, 0, rpkt.hdr.id, ANDNA_REV_RESOLVE_REPLY, 0);

	/* Build the list of registered hnames */
	if(!(pkt.msg=pack_lcl_cache(alcl, &pkt.hdr.sz))) {
		pkt_err(rpkt, E_ANDNA_NO_HNAME, 0);
		ERROR_FINISH(ret, -1, finish);
	}

	debug(DBG_INSANE, "Reverse resolve request 0x%x accepted", rpkt.hdr.id);
	
	/*
	 * Send it.
	 */

        pkt_addto(&pkt, &rpkt.from);
	pkt_addsk(&pkt, my_family, rpkt.sk, rpkt.sk_type);
	pkt_addcompress(&pkt);
        err=send_rq(&pkt, 0, ANDNA_REV_RESOLVE_REPLY, rpkt.hdr.id, 0, 0, 0);
        if(err < 0)
		ERROR_FINISH(ret, -1, finish);
finish:
	pkt_free(&pkt, 0);
	return ret;
}


/*
 *
 *  *  *  *  Andna caches transfer  *  *  *
 *  
 */

/*
 * get_single_andna_c
 * 
 * It sends the ANDNA_GET_SINGLE_ACACHE request to the old `hash_gnode' of `hash'
 * to retrieve the andna_cache that contains the information about `hash'.
 */
andna_cache *get_single_andna_c(u_int hash[MAX_IP_INT],
		u_int hash_gnode[MAX_IP_INT])
{
	PACKET pkt, rpkt;
	struct single_acache_hdr req_hdr;
	andna_cache *andna_cache, *ret=0;
	u_int *new_hgnodes[1];
	size_t pack_sz;
	int err, counter;
	const char *ntop;
	char *pack;
	
	setzero(&pkt, sizeof(PACKET));
	setzero(&rpkt, sizeof(PACKET));
	setzero(&req_hdr, sizeof(struct single_acache_hdr));
	
	/*
	 * Find the old hash_gnode that corresponds to the hash `hash_gnode',
	 * but exclude from the search ourself 'cause we are a new hash_gnode
	 * and we are trying to reach the new one.
	 */
	new_hgnodes[0]=me.cur_ip.data;
	if((err=find_hash_gnode(hash_gnode, &pkt.to, new_hgnodes, 1, 1)) < 0) {
		debug(DBG_SOFT, "get_single_andna_c: old hash_gnode not found");
		ERROR_FINISH(ret, 0, finish);
	} else if(err == 1)
		req_hdr.flags|=ANDNA_PKT_FORWARD;
	
	req_hdr.hgnodes=1;
	inet_copy_ipdata(req_hdr.rip, &me.cur_ip);
	memcpy(req_hdr.hash, hash, MAX_IP_SZ);

	/* host -> network order */
	ints_host_to_network((void *)&req_hdr, single_acache_hdr_iinfo);
	
	/* Pack the request */
	pkt.hdr.flags|=ASYNC_REPLY;
	pkt.hdr.sz=SINGLE_ACACHE_PKT_SZ(1);
	pkt.msg=xmalloc(pkt.hdr.sz);
	memcpy(pkt.msg, &req_hdr, pkt.hdr.sz);

	/* Append our ip at the end of the pkt */
	inet_copy_ipdata((u_int *)(pkt.msg+sizeof(struct single_acache_hdr)), 
				&me.cur_ip);
	
	ntop=inet_to_str(pkt.to);
	debug(DBG_INSANE, "Quest %s to %s", rq_to_str(ANDNA_GET_SINGLE_ACACHE), ntop);
	err=send_rq(&pkt, 0, ANDNA_GET_SINGLE_ACACHE, 0, ACK_AFFERMATIVE, 1, &rpkt);
	if(err < 0)
		ERROR_FINISH(ret, 0, finish);

	/* Unpack the waited reply */
	pack_sz=rpkt.hdr.sz;
	pack=rpkt.msg;
	ret=andna_cache=unpack_andna_cache(pack, pack_sz, &counter,
			ACACHE_PACK_PKT);
	if(!andna_cache && counter < 0) {
		error("get_single_acache(): Malformed andna_cache.");
		ERROR_FINISH(ret, 0, finish);
	}
	
finish:
	pkt_free(&pkt, 1);
	pkt_free(&rpkt, 0);
	return ret;
}

/*
 * put_single_acache
 * 
 * It replies to a get_single_acache request as described
 * in andna.h (near the single_acache_hdr struct).
 */
int put_single_acache(PACKET rpkt)
{
	PACKET pkt, rpkt_local_copy;
	struct single_acache_hdr *req_hdr;
	u_int hash_gnode[MAX_IP_INT], **new_hgnodes=0;
	inet_prefix rfrom, to;
	andna_cache *ac, *ac_tmp=0;
	char *buf;
	char *ntop=0, *rfrom_ntop=0;
	int ret=0, i;
	ssize_t err=0;
	size_t pkt_sz=0;
	
	
	pkt_copy(&rpkt_local_copy, &rpkt);
	req_hdr=(struct single_acache_hdr *)rpkt_local_copy.msg;
	
	/* Save the real sender of the request */
	inet_setip(&rfrom, req_hdr->rip, my_family);

	ntop=xstrdup(inet_to_str(rpkt.from));
	rfrom_ntop=xstrdup(inet_to_str(rfrom));
	debug(DBG_NOISE, "Andna get single cache request 0x%x from: %s, real "
			"from: %s", rpkt.hdr.id, ntop, rfrom_ntop);
	
	memcpy(&pkt, &rpkt, sizeof(PACKET));
	inet_copy(&pkt.from, &rfrom);
	pkt_addsk(&pkt, my_family, 0, SKT_UDP);
	pkt_addcompress(&pkt);

	/* network -> host order */
	ints_network_to_host(req_hdr, single_acache_hdr_iinfo);

	/* Verify the validity of the header */
	if(rpkt.hdr.sz != SINGLE_ACACHE_PKT_SZ(req_hdr->hgnodes) ||
			req_hdr->hgnodes > ANDNA_MAX_NEW_GNODES) {
		debug(DBG_NOISE, "Malformed GET_SINGLE_ACACHE pkt: %d, %d, %d",
			rpkt.hdr.sz, SINGLE_ACACHE_PKT_SZ(req_hdr->hgnodes),
			req_hdr->hgnodes);
		pkt_err(pkt, E_INVALID_REQUEST, 0);
		ERROR_FINISH(ret, -1, finish);
	}

	/* Unpack the hash_gnodes to exclude */
	new_hgnodes=xmalloc(sizeof(u_int *) * (req_hdr->hgnodes+1));
	buf=rpkt.msg+sizeof(struct single_acache_hdr);
	for(i=0; i<req_hdr->hgnodes; i++) {
		new_hgnodes[i]=(u_int *)buf;
		inet_ntohl(new_hgnodes[i], me.cur_ip.family);
		buf+=MAX_IP_SZ;
	}

	/* 
	 * Check if we are the destined old hash_gnode or if we have to still
	 * forward the pkt 
	 */
	
	andna_hash_by_family(my_family, (u_char *)req_hdr->hash, hash_gnode);
	if((err=find_hash_gnode(hash_gnode, &to, new_hgnodes, 
					req_hdr->hgnodes, 0)) < 0) {
		debug(DBG_SOFT, "We are not the real (rounded)hash_gnode. "
				"Rejecting the 0x%x get_single_acache request",
				rpkt.hdr.id);
		pkt_err(pkt, E_ANDNA_WRONG_HASH_GNODE, 0);
		ERROR_FINISH(ret, -1, finish);
	} else if(err == 1) {
		/* Continue to forward the received pkt */
		debug(DBG_SOFT, "The 0x%x rq pkt will be forwarded "
				"to: %s", rpkt.hdr.id, inet_to_str(to));
		ret=forward_pkt(rpkt, to);
		goto finish;
	}

		
	/*
	 * Search in our andna_cache if we have what `rfrom' wants.
	 */
	if(!(ac=andna_cache_gethash((int*)req_hdr->hash))) {

		/*
		 * Nothing found! Maybe it's because we have an uptime less than
		 * (ANDNA_EXPIRATION_TIME/2) and so we are a new hash_gnode, 
		 * therefore we have to forward the pkt to an older hash_gnode.
		 */ 
		if(time(0)-me.uptime < (ANDNA_EXPIRATION_TIME/2)) {
			new_hgnodes[req_hdr->hgnodes]=me.cur_ip.data;
			if((err=find_hash_gnode(hash_gnode, &to, new_hgnodes, 
							req_hdr->hgnodes+1, 1)) < 0) {
				/* An older hash_gnode doesn't exist */
				debug(DBG_SOFT, "put_single_andna_c: old hash_gnode not found");
				ERROR_FINISH(ret, -1, finish);
			}

			/*
			 * Append our ip at the end of the pkt and forward it
			 * to the older hash_gnode.
			 */
			memcpy(&pkt, &rpkt, sizeof(PACKET));
			pkt.sk=0;
			pkt.hdr.sz=rpkt.hdr.sz+MAX_IP_SZ;
			pkt.msg=xmalloc(pkt.hdr.sz);
			memcpy(pkt.msg, rpkt.msg, rpkt.hdr.sz);
			inet_copy_ipdata((u_int *)(pkt.msg+rpkt.hdr.sz), &me.cur_ip);

			debug(DBG_SOFT, "The 0x%x rq pkt will be forwarded "
					"to an older hgnode: %s", rpkt.hdr.id,
					inet_to_str(to));
			ret=forward_pkt(pkt, to);
			pkt_free(&pkt, 1);
			goto finish;
		}


		/*
		 * We are neither a new hash_gnode so the
		 * get_andna_single_cache propagation ends here and we reply to
		 * `rfrom': <<That andna_cache doesn't exist, bye bye!>> 
		 */
		debug(DBG_SOFT, "Request %s (0x%x) rejected: %s", 
				rq_to_str(rpkt.hdr.op), rpkt.hdr.id, 
				rq_strerror(E_ANDNA_NO_HNAME));
		pkt_err(pkt, E_ANDNA_NO_HNAME, 0);
		ERROR_FINISH(ret, -1, finish);
	}
	
	/*
	 * We found the andna_cache! Let's reply.
	 * Pack the `ac' andna_cache and send it to `rfrom' 
	 */
	
	setzero(&pkt, sizeof(PACKET));
	pkt_fill_hdr(&pkt.hdr, ASYNC_REPLIED, rpkt.hdr.id, ACK_AFFERMATIVE, 0);
	pkt_addto(&pkt, &rfrom);
	pkt_addsk(&pkt, my_family, 0, SKT_TCP);
	pkt_addport(&pkt, rpkt.port);
	pkt_addcompress(&pkt);

	/* Exctract the `ac' cache from the llist, so we can pack it alone */
	ac_tmp=list_dup(ac);
	pkt.msg=pack_andna_cache(ac_tmp, &pkt_sz, ACACHE_PACK_PKT);
	pkt.hdr.sz=pkt_sz;

	debug(DBG_INSANE, "Reply put_single_acache to %s", ntop);
	err=send_rq(&pkt, 0, ACK_AFFERMATIVE, rpkt.hdr.id, 0, 0, 0);
	pkt_free(&pkt, 0);
	if(err < 0) {
		error("put_andna_cache(): Cannot send the put_single_acache "
				"reply to %s.", ntop);
		ERROR_FINISH(ret, -1, finish);
	}
finish:
	if(ac_tmp)
		xfree(ac_tmp);
	if(new_hgnodes)
		xfree(new_hgnodes);
	if(ntop)
		xfree(ntop);
	if(rfrom_ntop)
		xfree(rfrom_ntop);
	pkt_free(&rpkt_local_copy, 0);

	return ret;
}

/*
 * spread_single_acache
 * 
 * It tells to all the rnodes to get the single andna_cache of `hash' 
 * using get_single_andna_c()
 */
int spread_single_acache(u_int hash[MAX_IP_INT])
{
	PACKET pkt;
	struct spread_acache_pkt req;

	setzero(&pkt, sizeof(PACKET));
	memcpy(req.hash, hash, MAX_IP_SZ);
	
	ints_host_to_network(&req, spread_acache_pkt_info);

	pkt_fill_hdr(&pkt.hdr, 0, 0, ANDNA_SPREAD_SACACHE, 
			SPREAD_ACACHE_PKT_SZ);
	pkt.msg=xmalloc(pkt.hdr.sz);
	memcpy(pkt.msg, &req, pkt.hdr.sz);
	
	debug(DBG_NOISE, "Spreading the single andna_cache 0x%x", pkt.hdr.id);
	andna_add_flood_pkt_id(last_spread_acache_pkt_id, pkt.hdr.id);
	return andna_flood_pkt(&pkt, 0);
}

/*
 * recv_spread_single_acache
 * 
 * It receives and execute the ANDNA_SPREAD_SACACHE request.
 */
int recv_spread_single_acache(PACKET rpkt)
{
	PACKET rpkt_local_copy;
	struct spread_acache_pkt *req;
	andna_cache *ac;
	u_int hash_gnode[MAX_IP_INT];
	int ret=0;

	pkt_copy(&rpkt_local_copy, &rpkt);
	req=(struct spread_acache_pkt *)rpkt_local_copy.msg;
	
	if(rpkt.hdr.sz != SPREAD_ACACHE_PKT_SZ)
		ERROR_FINISH(ret, -1, finish);
	
	/* network -> host order */
	ints_network_to_host(req, spread_acache_pkt_info);
	
	/* Check if we already received this pkt during the flood */
	if(andna_add_flood_pkt_id(last_spread_acache_pkt_id, rpkt.hdr.id)) {
		debug(DBG_INSANE, "Dropped 0x%0x andna pkt, we already "
				"received it", rpkt.hdr.id);
		ERROR_FINISH(ret, 0, finish);
	}

	if(time(0)-me.uptime > (ANDNA_EXPIRATION_TIME/2) ||
			(ac=andna_cache_findhash((int*)req->hash))) {
		/* We don't need to get the andna_cache from an old
		 * hash_gnode, since we currently are one of them! */
		debug(DBG_NOISE, "recv_spread_single_acache: We are an old "
				"hash_gnode, dropping 0x%x", rpkt.hdr.id);
		ERROR_FINISH(ret, -1, finish);
	}
	
	debug(DBG_NOISE, "Received the spreaded andna_cache 0x%x", rpkt.hdr.id);
	
	/* 
	 * Do as the rpkt tells us to do: retrieve the andna_hash for
	 * req->hash from the old hash_gnode and store it.
	 */
	andna_hash_by_family(my_family, (u_char *)req->hash, hash_gnode);
	if((ac=get_single_andna_c(req->hash, hash_gnode))) {
		/* Save it in our andna_cache.*/
		clist_add(&andna_c, &andna_c_counter, ac);
	} else {
		debug(DBG_NOISE, "recv_spread_single_acache: (0x%x) "
				"get_single_andna_c request failed", 
				rpkt.hdr.id);
		ERROR_FINISH(ret, -1, finish);
	}

	/* Continue to forward the pkt in the gnode */
	andna_flood_pkt(&rpkt, 1);

finish:
	pkt_free(&rpkt_local_copy, 0);
	return ret;
}

/*
 * get_andna_cache
 *
 * sends the ANDNA_GET_ANDNA_CACHE request to rnode `dst_rnode' to retrieve its
 * andna_cache.
 */
andna_cache *get_andna_cache(map_node *dst_rnode, int *counter)
{
	PACKET pkt, rpkt;
	andna_cache *andna_cache, *ret=0;
	size_t pack_sz;
	int err;
	char *pack;
	
	setzero(&pkt, sizeof(PACKET));
	setzero(&rpkt, sizeof(PACKET));

	if(rnl_fill_rq(dst_rnode, &pkt) < 0)
		ERROR_FINISH(ret, 0, finish);
	if(server_opt.dbg_lvl) {
		const char *ntop;
		ntop=inet_to_str(pkt.to);
		debug(DBG_INSANE, "Quest %s to %s", 
				rq_to_str(ANDNA_GET_ANDNA_CACHE), ntop);
	}
	pkt_addtimeout(&pkt, ANDNA_HOOK_TIMEOUT, 1, 1);

	err=send_rq(&pkt, 0, ANDNA_GET_ANDNA_CACHE, 0, 
			ANDNA_PUT_ANDNA_CACHE, 1, &rpkt);
	if(err < 0) {
		ret=0;
		goto finish;
	}
	
	pack_sz=rpkt.hdr.sz;
	pack=rpkt.msg;
	ret=andna_cache=unpack_andna_cache(pack, pack_sz, counter, 
			ACACHE_PACK_PKT);
	if(!andna_cache && counter < 0)
		error("get_andna_cache(): Malformed or empty andna_cache. "
				"Cannot load it");
	
finish:
	pkt_free(&pkt, 0);
	pkt_free(&rpkt, 0);
	return ret;
}

/*
 * put_andna_cache
 *
 * replies to a ANDNA_GET_ANDNA_CACHE request, sending back the complete 
 * andna cache
 */
int put_andna_cache(PACKET rq_pkt)
{
	PACKET pkt;
	const char *ntop; 
	int ret=0;
	ssize_t err=0;
	size_t pkt_sz=0;
	
	ntop=inet_to_str(rq_pkt.from);
	
	setzero(&pkt, sizeof(PACKET));
	pkt_addto(&pkt, &rq_pkt.from);
	pkt_addsk(&pkt, my_family, rq_pkt.sk, rq_pkt.sk_type);
	pkt_addcompress(&pkt);

	pkt.msg=pack_andna_cache(andna_c, &pkt_sz, ACACHE_PACK_PKT);
	pkt.hdr.sz=pkt_sz;
	debug(DBG_INSANE, "Reply %s to %s", re_to_str(ANDNA_PUT_ANDNA_CACHE), ntop);
	err=send_rq(&pkt, 0, ANDNA_PUT_ANDNA_CACHE, rq_pkt.hdr.id, 0, 0, 0);
	if(err < 0) {
		error("put_andna_cache(): Cannot send the ANDNA_PUT_ANDNA_CACHE reply to %s.", ntop);
		ERROR_FINISH(ret, -1, finish);
	}
finish:
	pkt_free(&pkt, 0);
	return ret;
}


/*
 * get_counter_cache
 * 
 * sends the ANDNA_GET_COUNT_CACHE request to rnode `dst_rnode' to retrieve its
 * counter_cache.
 */
counter_c *get_counter_cache(map_node *dst_rnode, int *counter)
{
	PACKET pkt, rpkt;
	counter_c *ccache, *ret=0;
	size_t pack_sz;
	int err;
	char *pack;
	
	setzero(&pkt, sizeof(PACKET));
	setzero(&rpkt, sizeof(PACKET));

	if(rnl_fill_rq(dst_rnode, &pkt) < 0)
		ERROR_FINISH(ret, 0, finish);
	if(server_opt.dbg_lvl) {
		const char *ntop;
		ntop=inet_to_str(pkt.to);
		debug(DBG_INSANE, "Quest %s to %s", 
				rq_to_str(ANDNA_GET_COUNT_CACHE), ntop);
	}
	pkt_addtimeout(&pkt, ANDNA_HOOK_TIMEOUT, 1, 1);

	err=send_rq(&pkt, 0, ANDNA_GET_COUNT_CACHE, 0,
			ANDNA_PUT_COUNT_CACHE, 1, &rpkt);
	if(err < 0) {
		ret=0;
		goto finish;
	}
	
	pack_sz=rpkt.hdr.sz;
	pack=rpkt.msg;
	ret=ccache=unpack_counter_cache(pack, pack_sz, counter);
	if(!ccache && counter < 0)
		error(ERROR_MSG "Malformed counter_cache. Cannot load it",
		      ERROR_FUNC);
	
finish:
	pkt_free(&pkt, 0);
	pkt_free(&rpkt, 0);
	return ret;
}

/*
 * put_counter_cache
 * 
 * replies to a ANDNA_GET_COUNT_CACHE request, sending back the
 * complete andna cache.
 */
int put_counter_cache(PACKET rq_pkt)
{
	PACKET pkt;
	const char *ntop; 
	int ret=0;
	ssize_t err=0;
	size_t pkt_sz=0;
	
	ntop=inet_to_str(rq_pkt.from);
	
	setzero(&pkt, sizeof(PACKET));
	pkt_addto(&pkt, &rq_pkt.from);
	pkt_addsk(&pkt, my_family, rq_pkt.sk, rq_pkt.sk_type);
	pkt_addcompress(&pkt);

	pkt.msg=pack_counter_cache(andna_counter_c, &pkt_sz);
	pkt.hdr.sz=pkt_sz;
	debug(DBG_INSANE, "Reply %s to %s", re_to_str(ANDNA_PUT_COUNT_CACHE), ntop);
	err=send_rq(&pkt, 0, ANDNA_PUT_COUNT_CACHE, rq_pkt.hdr.id, 0, 0, 0);
	if(err < 0) {
		error("put_counter_cache(): Cannot send the ANDNA_PUT_COUNT_CACHE reply to %s.", ntop);
		ERROR_FINISH(ret, -1, finish);
	}
finish:
	pkt_free(&pkt, 0);
	return ret;
}


/*
 *
 *  *  *  *  ANDNA threads  *  *  *
 *  
 */

/*
 * andna_hook
 * 
 * The andna_hook gets the andna_cache and the counter_node cache from
 * the nearest rnodes.
 */
void *andna_hook(void *null)
{
	inet_prefix to;
	map_node *node;
	int e=0, i;
	
	setzero(&to, sizeof(inet_prefix));

	/* Block these requests */
        op_filter_set(ANDNA_SPREAD_SACACHE);

	loginfo("Starting the ANDNA hook.");
	
	if(!me.cur_node->links) {
		/* nothing to do */
		debug(DBG_NORMAL, "There are no nodes, skipping the ANDNA hook."); 
		goto finish;
	}

	/* 
	 * Send the GET_ANDNA_CACHE request to the nearest rnode we have, if it
	 * fails send it to the second rnode and so on...
	 */
	for(i=0, e=0; i < me.cur_node->links; i++) {
		node=(map_node *)me.cur_node->r_node[i].r_node;
		if(!node || node->flags & MAP_ERNODE)
			continue;

		andna_c=get_andna_cache(node, &andna_c_counter);
		if(andna_c) {
			e=1;
			break;
		}
	}
	if(!e)
		loginfo("None of the rnodes in this area gave me the andna_cache.");

	/* 
	 * Send the GET_COUNT_CACHE request to the nearest rnode we have, if it
	 * fails send it to the second rnode and so on...
	 */
	for(i=0, e=0; i < me.cur_node->links; i++) {
		node=(map_node *)me.cur_node->r_node[i].r_node;
		if(!node || node->flags & MAP_ERNODE)
			continue;
		
		andna_counter_c=get_counter_cache(node, &cc_counter);
		if(andna_counter_c) {
			e=1;
			break;
		}
	}
	if(!e)
		loginfo("None of the rnodes in this area gave me the counter_cache.");

finish:
	/* Un-block these requests */
        op_filter_clr(ANDNA_SPREAD_SACACHE);

	loginfo("ANDNA hook completed");

	return 0;
}

/*
 * andna_min_update_retry
 *
 * waits ANDNA_MIN_UPDATE_TIME seconds and then updates `void_alcl'.
 */
void *andna_min_update_retry(void *void_alcl)
{
	lcl_cache *alcl=(lcl_cache *)void_alcl;
	int ret;

	sleep(ANDNA_MIN_UPDATE_TIME);

	ret=andna_register_hname(alcl, 0);
	if(!ret)
		loginfo("Hostname \"%s\" registered/updated "
				"successfully", alcl->hostname);

	return 0;
}

/*
 * andna_update_hnames
 *
 * updates/registers all the hostnames present in the local cache. 
 * If `only_new_hname' is not zero, it registers only the new hostnames
 * added in the local cache.
 */
void andna_update_hnames(int only_new_hname)
{
	pthread_t thread;
	lcl_cache *alcl=andna_lcl;
	int ret, updates=0;

	list_for(alcl) {
		if(only_new_hname && alcl->timestamp)
			/* don't register old hnames */
			continue;
		
		ret=andna_register_hname(alcl, 0);
		if(!ret) {
			loginfo("Hostname \"%s\" registered/updated "
					"successfully", alcl->hostname);
			updates++;
		} else {
			/* Wait ANDNA_MIN_UPDATE_TIME seconds then retry to
			 * update it */
			pthread_create(&thread, 0, andna_min_update_retry, (void *)alcl);
			pthread_detach(thread);
		}
	}
	if(updates)
		save_lcl_cache(andna_lcl, server_opt.lcl_file);
}

/*
 * andna_maintain_hnames_active
 * 
 * periodically registers and keep up to date the hostnames of the local cache.
 */
void *andna_maintain_hnames_active(void *null)
{
	lcl_cache *alcl;
	int ret, updates;

	/* Wait a bit before trying to register the hname. The first QSPN must
	 * be already sent */
	while(time(0)-me.uptime < QSPN_WAIT_ROUND/2)
		sleep(1);

	for(;;) {
		updates=0;
		alcl=andna_lcl;

		/** If we don't have rnodes, it's useless to try
		 * anything */
		while(!me.cur_node->links)
			sleep(2);
		/**/

		list_for(alcl) {
			ret=andna_register_hname(alcl, 0);
			if(!ret) {
				loginfo("Hostname \"%s\" registered/updated "
						"successfully", alcl->hostname);
				updates++;
			}
		}
		
		if(updates)
			save_lcl_cache(andna_lcl, server_opt.lcl_file);

		sleep((ANDNA_EXPIRATION_TIME/2) + rand_range(1, 10));
	}

	return 0;
}

void *andna_main(void *null)
{
	struct udp_daemon_argv ud_argv;
	u_short *port;
	pthread_t thread;
	pthread_attr_t t_attr;
	
	pthread_attr_init(&t_attr);
	pthread_attr_setdetachstate(&t_attr, PTHREAD_CREATE_DETACHED);

	setzero(&ud_argv, sizeof(struct udp_daemon_argv));
	port=xmalloc(sizeof(u_short));

	pthread_mutex_init(&udp_daemon_lock, 0);
	pthread_mutex_init(&tcp_daemon_lock, 0);

	debug(DBG_SOFT,   "Evoking the andna udp daemon.");
	ud_argv.port=andna_udp_port;
	ud_argv.flags|=UDP_THREAD_FOR_EACH_PKT;
	pthread_mutex_lock(&udp_daemon_lock);
	pthread_create(&thread, &t_attr, udp_daemon, (void *)&ud_argv);
	pthread_mutex_lock(&udp_daemon_lock);
	pthread_mutex_unlock(&udp_daemon_lock);

	debug(DBG_SOFT,   "Evoking the andna tcp daemon.");
	*port=andna_tcp_port;
	pthread_mutex_lock(&tcp_daemon_lock);
	pthread_create(&thread, &t_attr, tcp_daemon, (void *)port);
	pthread_mutex_lock(&tcp_daemon_lock);
	pthread_mutex_unlock(&tcp_daemon_lock);

	/*
	 * Start the ANDNA hook 
	 */
	pthread_create(&thread, &t_attr, andna_hook, 0);

	/*
	 * DNS wrapper
	 */
	debug(DBG_SOFT, "Evoking the DNS wrapper daemon.");
	pthread_create(&thread, &t_attr, dns_wrapper_thread, 0);

	/* 
	 * Start the hostnames updater and register 
	 */
	andna_maintain_hnames_active(0);
	
	xfree(port);
	return 0;
}
