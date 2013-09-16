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

#ifndef DAEMON_H
#define DAEMON_H

#define MAX_LISTENING_SOCKETS		MAX_INTERFACES

/* These mutexes are used to wait the complete start up of the daemons when
 * launched. */
pthread_mutex_t udp_daemon_lock;
pthread_mutex_t tcp_daemon_lock;

/* flags for udp_exec_pkt_argv and udp_daemon_argv */
#define UDP_THREAD_FOR_EACH_PKT		1	/* For each incoming udp
						   packets use threads */

/* Argv passed to udp_exec_pkt() */
struct udp_exec_pkt_argv {
	PACKET 		*recv_pkt;
	int		acpt_idx;
	int		acpt_sidx;
	u_char		flags;
};

/* Argv passed to udp_daemon */
struct udp_daemon_argv {
	u_short		port;
	u_char		flags;
};

pthread_mutex_t udp_exec_lock;
pthread_mutex_t tcp_exec_lock;

int prepare_listen_socket(int family, int socktype, u_short port, interface *dev);
void *tcp_recv_loop(void *recv_pkt);
void *tcp_daemon(void *null);
void *udp_daemon(void *door);

#endif /*DAEMON_H*/
