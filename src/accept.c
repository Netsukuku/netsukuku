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
 * accept.c: This is how it works:
 *
 * When a new accept is made add_accept is called. It first updates the accept
 * table and then, if the accept_tbl isn't full add the new accept in the tbl.
 * If the accept_tbl is full the connection is dropped.
 * Each accept in the table last for free_accept_time after the close of that
 * connection, so if an host has fulled the accept_tbl has to wait 
 * free_accept_time of seconds to be able to reconnect again.
 */

#include "includes.h"

#include "request.h"
#include "inet.h"
#include "accept.h"
#include "xmalloc.h"
#include "log.h"


void init_accept_tbl(int startups, int accepts, int time)
{
	/* TODO: activate and test it !! */
#if 0
	int i;

	max_connections=startups;
	max_accepts_per_host=accepts;
	free_accept_time=time;
	accept_idx=accept_sidx=0;
	pthread_mutex_init(&mtx_acpt_idx, NULL);
	pthread_mutex_init(&mtx_acpt_sidx, NULL);
	
	accept_tbl=(struct accept_table *)xmalloc(sizeof(struct accept_table)*max_connections);
	memset(accept_tbl, '\0', sizeof(struct accept_table)*max_connections);

	for(i=0; i<max_connections; i++) {
		accept_tbl[i].pid=(pid_t *)xmalloc(sizeof(pid_t)*max_accepts_per_host);
		memset(accept_tbl[i].pid, '\0', sizeof(pid_t)*max_accepts_per_host);
			
		accept_tbl[i].closed=(unsigned char *)xmalloc(sizeof(unsigned char)*max_accepts_per_host);
		memset(accept_tbl[i].closed, '\0', sizeof(unsigned char)*max_accepts_per_host);
			
		accept_tbl[i].acp_t=(time_t *)xmalloc(sizeof(time_t)*max_accepts_per_host);
		memset(accept_tbl[i].acp_t, '\0', sizeof(time_t)*max_accepts_per_host);
	}
#endif
}

void destroy_accept_tbl(void)
{
	/* TODO: activate and test it !! */
#if 0
	int i; 
	
	if(!accept_tbl)
		return;
	for(i=0; i<max_connections; i++) {
		xfree(accept_tbl[i].pid);
		xfree(accept_tbl[i].closed);
		xfree(accept_tbl[i].acp_t);
	}
	xfree(accept_tbl);
	accept_tbl=0;
#endif
}


void update_accept_tbl(void)
{
	time_t cur_t, passed_time;
	int i,e,k,ee, pid_exists;
	
	if(update_accept_tbl_mutex)
		return;
	else
		update_accept_tbl_mutex=1;
	
	time(&cur_t);
	
	for(i=0; i < max_connections; i++) {
		if(!accept_tbl[i].ip.len)
			continue;
		if(accept_tbl[i].accepts) {
			for(e=0; e<max_accepts_per_host; e++) {
				if(!accept_tbl[i].acp_t[e])
					continue;
				
				if(accept_tbl[i].pid[e]) {
					k=kill(accept_tbl[i].pid[e], 0);
					pid_exists = !(k==-1 && errno==ESRCH);
				} else
					pid_exists=0;

#if 0
				debug(DBG_NOISE, "ACPT: Updating tbl: cur_t: %d, "
						"accept_tbl[%d].acp_t[%d]:%d+%d, "
						"accept_tbl[i].pid[e]: %d, "
						"kill=%d (ESRCH=%d)",
						cur_t, i,e, accept_tbl[i].acp_t[e], 
						free_accept_time, accept_tbl[i].pid[e], 
						k, ESRCH);
#endif

				passed_time=accept_tbl[i].acp_t[e]+free_accept_time;
				if((accept_tbl[i].closed[e] || !pid_exists) && 
						passed_time <= cur_t) {
					ee=e;
					del_accept(i, &ee);
				}
			}
		}
	}
	update_accept_tbl_mutex=0;
}

int find_ip_acpt(inet_prefix ip)
{
	int i;
	
	for(i=0; i<max_accepts_per_host; i++) {
		if(!memcmp(accept_tbl[i].ip.data, &ip.data, MAX_IP_SZ))
			return i;
	}

	return -1;
}

int find_first_free(void)
{
	int i;
	
	for(i=0; i<max_connections; i++)
		if(!accept_tbl[i].accepts)
			return i;
	return -1;
}

int is_ip_acpt_free(inet_prefix ip, int *index)
{
	int idx;
	
	update_accept_tbl();
	
	if((idx=find_ip_acpt(ip))==-1)
		if((idx=find_first_free())==-1)
			return E_TOO_MANY_CONN;
	
	/*debug(DBG_NOISE, "ACPT: accept_tbl[%d].accepts: %d, max_acp: %d", idx,
			accept_tbl[idx].accepts, max_accepts_per_host); */

	if(accept_tbl[idx].accepts >= max_accepts_per_host)
		return E_ACCEPT_TBL_FULL;

	*index=idx;
	return 0;
}

int find_free_acp_t(int idx)
{
	int e;
	
	for(e=0; e < max_accepts_per_host; e++) {
		if(!accept_tbl[idx].acp_t[e])
			return e;
	}
	
	return -1;	/*This happens if the rq_tbl is full for the "rq" request*/
}

int new_accept(int idx, inet_prefix ip)
{
	int cl=0;
	/* TODO: activate and test it !! */
#if 0
	time_t cur_t;
	
	time(&cur_t);
	
	if((cl=find_free_acp_t(idx))==-1)
		return -1;
	accept_tbl[idx].accepts++;
	accept_tbl[idx].acp_t[cl]=cur_t;
	accept_tbl[idx].closed[cl]=0;
	inet_copy(&accept_tbl[idx].ip, &ip);
#endif
	return cl;
}

/* 
 * add_accept: It adds a new accept of `ip'. If `replace' is not 0 the `ip's
 * accepts are not incremented and accept_sidx is set to 0.
 */
int add_accept(inet_prefix ip, int replace)
{
	/* TODO: activate and test it !! */
#if 0
	int err, idx, cl;
	
	if((err=is_ip_acpt_free(ip, &idx)))
		return err;

	if(!replace || !accept_tbl[idx].accepts) {
		cl=new_accept(idx, ip);
		if(cl < 0)
			return -1;
	} else 
		cl=0;

	/*This global var will be given to the thread*/
	pthread_mutex_lock(&mtx_acpt_idx);
	accept_idx=idx;
	pthread_mutex_unlock(&mtx_acpt_idx);

	pthread_mutex_lock(&mtx_acpt_sidx);
	accept_sidx=cl;
	pthread_mutex_unlock(&mtx_acpt_sidx);
#endif
	return 0;
}

void del_accept(int idx, int *sidx)
{
#if 0
	if(!accept_tbl[idx].accepts) 
		return;

	if(accept_tbl[idx].acp_t[*sidx]) {
		accept_tbl[idx].accepts--;
		accept_tbl[idx].acp_t[*sidx]=0;
		accept_tbl[idx].closed[*sidx]=0;
		if(!accept_tbl[idx].accepts)
			memset(&accept_tbl[idx].ip, '\0', sizeof(inet_prefix));
		(*sidx)--;
	}
#endif
}

int close_accept(int idx, int sidx)
{
#if 0
	if(!accept_tbl[idx].accepts) 
		return -1;
	
	accept_tbl[idx].closed[sidx]=1;
#endif
	return 0;
}

void add_accept_pid(pid_t pid, int idx, int sidx)
{
	/* TODO: activate and test it !! */
#if 0
	accept_tbl[idx].pid[sidx]=pid;
/*	debug(DBG_NOISE, "ACPT: Added pig %d in accept_tbl[%d].pid[%d]", 
			accept_tbl[idx].pid[sidx], idx, sidx);
*/
#endif
}
