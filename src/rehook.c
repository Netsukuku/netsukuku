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
 * rehook.c: 
 * This code manages the rehook of gnodes, the challenges that must be solved
 * and generated in order to prove the number of nodes present in a gnode.
 */

#include "includes.h"

#include "common.h"
#include "hash.h"
#include "llist.c"
#include "libnetlink.h"
#include "ll_map.h"
#include "inet.h"
#include "if.h"
#include "krnl_route.h"
#include "endianness.h"
#include "bmap.h"
#include "route.h"
#include "iptunnel.h"
#include "request.h"
#include "pkts.h"
#include "tracer.h"
#include "qspn.h"
#include "andna.h"
#include "hook.h"
#include "rehook.h"
#include "radar.h"
#include "netsukuku.h"
#include "common.h"

/*
 * rehook_argv: argv for the new_rehook_thread thread
 */
struct rehook_argv {
	int gid;
	map_gnode *gnode;
	int level;
	int gnode_count;
};

pthread_attr_t new_rehook_thread_attr;

void rehook_init(void)
{
	total_rehooks=0;
	last_instance_rehook=0;
	rehook_mutex=0;

	pthread_attr_init(&new_rehook_thread_attr);
	pthread_attr_setdetachstate(&new_rehook_thread_attr, PTHREAD_CREATE_DETACHED);	 
}

/*
 * rehook_compute_new_gnode: computes the IP which shall be used to create a
 * new gnode if the we cannot rehook to any gnode.
 * The computed ip is stored in `new_ip'.
 * `old_ip' is the IP we used before the rehook was launched.
 */
void rehook_compute_new_gnode(inet_prefix *old_ip, inet_prefix *new_ip, 
		int hook_level)
{
	quadro_group qg;
	int hash_gid;

	iptoquadg(*old_ip, me.ext_map, &qg, QUADG_GID);

	/* 
	 * Hash our gids starting from the `hook_level' level,
	 * then xor the bytes of the hash merging them in a single byte.
	 */
	hash_gid=fnv_32_buf(&qg.gid[hook_level], 
			(FAMILY_LVLS-hook_level),
			FNV1_32_INIT);
	qg.gid[hook_level]=xor_int(hash_gid);

	/* Be sure to choose VOID gnodes */
	void_gids(&qg, hook_level, me.ext_map, me.int_map);

	/* Save the new ip in `new_ip' */
	gidtoipstart(qg.gid, FAMILY_LVLS, FAMILY_LVLS, my_family, new_ip);
}

int send_challenge(int gnode, int level, int gnode_count)
{
	/* TODO ^_^ */
	
	return 0;
}


/*
 * update_rehook_time: updates the rehook_time counter. If the limits are
 * reached -1 is returned and nothing is changed, otherwise 0 is the returned
 * value. (See rehook.h for more info on the limits).
 */
int update_rehook_time(int level)
{
	time_t cur_t, sec_elapsed;

	cur_t=time(0);
	sec_elapsed=(cur_t - last_instance_rehook);
	
	if(total_rehooks && sec_elapsed > REHOOK_INSTANCE_TIME(level)) {
		/* 
		 * REHOOK_INSTANCE_TIME expired: we cannot take anymore rehooks
		 * in this instance. 
		 */
		
		if(sec_elapsed > REHOOK_WAIT_TIME(level))
			/* REHOOK_WAIT_TIME expired: a new instance begins */
			total_rehooks=0;
		else
			return -1;
	}
	
	if(total_rehooks > REHOOK_PER_INSTANCE)
		/* Too many rehooks in this instance */
		return -1;
	
	if(!total_rehooks)
		last_instance_rehook=cur_t;
	total_rehooks++;

	return 0;
}

/*
 * wait_new_rnode: it waits until we have a rnode, which belongs to
 * `rargv->gnode' or to `rk_gnode_ip'.
 */
void wait_new_rnode(struct rehook_argv *rargv)
{
	ext_rnode_cache *erc;
	int gid_a[MAX_LEVELS], gid_b[MAX_LEVELS];
	int e=0, i, retries;

	debug(DBG_NOISE, "wait_new_rnode: waiting the %d rnode %d lvl appearance",
			rargv->gid, rargv->level);

	memcpy(&gid_a, me.cur_quadg.gid, sizeof(me.cur_quadg.gid));
	gid_a[rargv->level]=rargv->gid;
	
	iptogids(&rk_gnode_ip, gid_b, me.cur_quadg.levels);
			
	retries = QSPN_WAIT_ROUND_LVL(rargv->level)/MAX_RADAR_WAIT + 1;
	for(i=0; i<retries; i++) {
		e=0;
		erc=me.cur_erc;
		list_for(erc) {
			if(!gids_cmp(erc->e->quadg.gid, gid_a, rargv->level,
						me.cur_quadg.levels)) {
				e=1;
				break;
			}
			
			if(!gids_cmp(erc->e->quadg.gid, gid_b, rargv->level,
						me.cur_quadg.levels)) {
				e=1;
				break;
			}
		}
		if(e) {
			debug(DBG_NOISE, "wait_new_rnode: %d rnode %d "
					"lvl found", rargv->gid, rargv->level);
			return;
		}
		radar_wait_new_scan();
	}

	debug(DBG_NORMAL, "wait_new_rnode: not found! Anyway, trying to rehook");
}

/*
 * new_rehook_thread: a thread for each rehook() is necessary because the
 * rehook has to run without stopping the calling thread.
 */
void *new_rehook_thread(void *r)
{
	struct rehook_argv *rargv=(struct rehook_argv *)r;
	ext_rnode_cache *erc;
	map_node *root_node;
	map_gnode *gnode;
	int i;
	
	/*
	 * Send a new challenge if `CHALLENGE_THRESHOLD' was exceeded 
	 */
	if(rargv->level && rargv->gnode_count >= CHALLENGE_THRESHOLD)
		if(send_challenge(rargv->gid, rargv->level, 
					rargv->gnode_count))
			/* Challenge failed, do not rehook */
			goto finish;

	/* Store in `rk_gnode_ip' our new gnode ip to be used when the rehook
	 * fails, just in case */
	rehook_compute_new_gnode(&me.cur_ip, &rk_gnode_ip, rargv->level);

#if 0
	/* Before rehooking, at least one qspn_round has to be completed */
	while(!me.cur_qspn_id[rargv->level])
		usleep(505050);
#endif
	
	/* Wait the radar_daemon, we need it up & running */
	while(!radar_daemon_ctl)
		usleep(505050);

	if(rargv->gid != me.cur_quadg.gid[rargv->level])
		wait_new_rnode(rargv);

	/*
	 * Rehook now
	 */
	rehook(rargv->gnode, rargv->level);

	if(rargv->level) {
		/* Mark all the gnodes we border on as HOOKED, in this way
		 * we won't try to rehook each time */
		erc=me.cur_erc;
		list_for(erc) {	
			if(!erc->e)
				continue;
			if(erc->e->quadg.gnode[_EL(rargv->level)])
				erc->e->quadg.gnode[_EL(rargv->level)]->flags|=GMAP_HGNODE;
		}

		/* Mark also rargv->gnode */
		rargv->gnode->flags|=GMAP_HGNODE;
	
		/* Mark all the gnodes which are rnodes of our gnode of the
		 * `rargv->level' level. */
		root_node=&me.cur_quadg.gnode[_EL(rargv->level)]->g;
		for(i=0; i<root_node->links; i++) {
			gnode=(map_gnode *)root_node->r_node[i].r_node;
			gnode->g.flags|=GMAP_HGNODE;
		}
	}

finish:	
	xfree(rargv);
	rehook_mutex=0;	
	return 0;
}

/*
 * new_rehook: takes in exam the `gnode' composed by `gnode_count'# nodes, which
 * is at level `level' and which has a gnode id equal to `gid'.
 * When `level' is 0, `gnode' is a node and gnode_count isn't considered.
 */
void new_rehook(map_gnode *gnode, int gid, int level, int gnode_count)
{
	struct rehook_argv *rargv;
	pthread_t thread;

	if(restricted_mode && level == me.cur_quadg.levels-1 && 
			gid != me.cur_quadg.gid[level])
		/* We are in restricted mode. The `gnode' is too restricted.
		 * Our restricted class isn't the same of `gnode', therefore
		 * do nothing. The restricted class are immutable. */
		return;

	if(!level && gid != me.cur_quadg.gid[level])
		/* We rehook at level 0 only if we have the same gid of
		 * another node, so in this case we don't have to rehook */
		return;
	else if(level) {
		if(gnode_count < qspn_gnode_count[_EL(level)])
			/* We have more nodes, we don't have to rehook! */
			return;
		else if(gnode_count == qspn_gnode_count[_EL(level)] &&
				gid < me.cur_quadg.gid[level])
			/* We have the same number of nodes, but `gid' is
			 * smaller than our gnode id, so it must rehook, 
			 * not us */
			return;
		else if(gnode_count == qspn_gnode_count[_EL(level)] &&
				gid == me.cur_quadg.gid[level] &&
				gnode->g.flags & MAP_RNODE)
			/* If `gnode' has our same gid and it is our rnode,
			 * it's alright. */
			return;
	} 

	if(gid == me.cur_quadg.gid[level]) {
		/* 
		 * There is a (g)node which has our same gid, hence we rehook
		 * to our gnode of the higher level (hopefully we get a new
		 * gid).
		 */
		if(level+1 < me.cur_quadg.levels)
			level++;
		gid   = me.cur_quadg.gid[level];
		gnode = me.cur_quadg.gnode[_EL(level)];

	} else if(level && gnode->flags & GMAP_HGNODE)
		/* `gnode' is marked as HOOKED, return. */
		return;

	debug(DBG_NORMAL, "new_rehook: me.gid %d, gnode %d, level %d, gnode_count %d, "
			"qspn_gcount %d, our rnode: %d", 
			me.cur_quadg.gid[level], gid, level,
			gnode_count, qspn_gnode_count[_EL(level)], 
			gnode->g.flags & MAP_RNODE);

	/*
	 * Update the rehook time and let's see if we can take this new rehook
	 */
	if(update_rehook_time(level)) {
		debug(DBG_SOFT, "new_rehook: we have to wait before accepting "
				"another rehook");
		return;
	}

	if(rehook_mutex)
		return;
	rehook_mutex=1;

	rargv = xmalloc(sizeof(struct rehook_argv));
	rargv->gid	   = gid;
	rargv->gnode	   = gnode;
	rargv->level	   = level;
	rargv->gnode_count = gnode_count;
	pthread_create(&thread, &new_rehook_thread_attr, new_rehook_thread, 
			(void *)rargv);
}

/*
 * rehook: resets all the global variables set during the last hook/rehook,
 * and launches the netsukuku_hook() again. All the previous map will be lost
 * if not saved, the IP will also change. 
 * During the rehook, the radar_daemon and andna_maintain_hnames_active() are
 * stopped.
 * After the rehook, the andna_hook will be launched and the stopped daemon
 * reactivated.
 */
int rehook(map_gnode *hook_gnode, int hook_level)
{
	int ret=0;

	/* Stop the radar_daemon */
	radar_daemon_ctl=0;

	/* Wait the end of the current radar */
	radar_wait_new_scan();

	/* Mark ourself as hooking, this will stop
	 * andna_maintain_hnames_active() daemon too. */
	me.cur_node->flags|=MAP_HNODE;

	/* 
	 * Reset the rnode list and external rnode list 
	 */
	rnl_reset(&rlist, &rlist_counter);
	e_rnode_free(&me.cur_erc, &me.cur_erc_counter);
	
	if(restricted_mode) {
		/* 
		 * Delete all the tunnels, and reset all the structs used by
		 * igs.c
		 */

		del_all_tunnel_ifs(0, 0, 0, NTK_TUNL_PREFIX);
		reset_igw_nexthop(multigw_nh);
		reset_igws(me.igws, me.igws_counter, me.cur_quadg.levels);
		reset_igw_rules();	
		free_my_igws(&me.my_igws);
	}

	/* Andna reset */
	if(!server_opt.disable_andna) {
		andna_cache_destroy();
		counter_c_destroy();
		rh_cache_flush();
	}
	
	/* Clear the uptime */
	me.uptime=time(0);

	/*
	 * * *  REHOOK!  * * *
	 */
	netsukuku_hook(hook_gnode, hook_level);

	/* Restart the radar daemon */
	radar_daemon_ctl=1;

	if(!server_opt.disable_andna) {
		/* Rehook in ANDNA and update our hostnames */
		andna_hook(0);
		andna_update_hnames(0);
	}

	return ret;
}
