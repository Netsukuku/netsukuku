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

#ifndef ACCEPT_H
#define ACCEPT_H

#define MAX_CONNECTIONS		512

#define MAX_ACCEPTS		16
#define FREE_ACCEPT_TIME	4		/*in seconds*/

/*
 * This struct keep tracks of single connection to the server.
 * The thread_daemon who handle the connection knows the connection
 * position in the accept_tbl.
 */
struct accept_table
{
	inet_prefix	   ip;			/*Ip of the node connected*/
	unsigned char	   accepts;		/*Number of connection from this node*/
	pid_t              *pid;   	        /*The pid of each child that have accepted the conn*/
	unsigned char      *closed; 		/*Each element of this array is 1 or 0. It indicates if the connection has
                                                  been closed*/
	time_t		   *acp_t;		/*The time when the connection was accepted. The "accepts" counter
						  will decrement when one of the acp_t+FREE_ACCEPT_TIME will 
						  be <= current_time AND (the relative pid will be non existent OR
						  the relative closed element will be == 1)
						 */
	struct request_tbl rqtbl;		/*The request table*/
};

/* This struct keeps all the info regarding each node connected */
struct accept_table *accept_tbl;

/* 
 * accept_idx is the position of the accept_tbl of a thread.
 * accept_sidx is the second index, it is used for example in pid[accept_sidx] 
 * note: this var are used only in the child and the child doesn't need to modify them!
 */
int accept_idx, accept_sidx;
pthread_mutex_t mtx_acpt_idx, mtx_acpt_sidx;

int update_accept_tbl_mutex;

int max_connections, max_accepts_per_host, free_accept_time;

void init_accept_tbl(int startups, int accepts, int time);
void destroy_accept_tbl(void);
void update_accept_tbl(void);
int  find_ip_acpt(inet_prefix ip);
int  find_first_free(void);
int  is_ip_acpt_free(inet_prefix ip, int *index);
int  find_free_acp_t(int idx);
int new_accept(int idx, inet_prefix ip);
int add_accept(inet_prefix ip, int replace);
void del_accept(int idx, int *sidx);
int  close_accept(int idx, int sidx);
void add_accept_pid(pid_t pid, int idx, int sidx);

#endif /*ACCEPT_H*/
