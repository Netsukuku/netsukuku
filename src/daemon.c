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

#include "includes.h"

#include "common.h"
#include "inet.h"
#include "request.h"
#include "if.h"
#include "pkts.h"
#include "bmap.h"
#include "daemon.h"
#include "netsukuku.h"
#include "accept.h"

extern int errno;

/* 
 * prepare_listen_socket: 
 * It creates a new socket of the desired `family' and binds it to the 
 * specified `port'. It sets also the reuseaddr and NONBLOCK
 * socket options, because this new socket shall be used to listen() and
 * accept().
 * If `dev' is not null, the socket will be binded to the device named 
 * `dev'->dev_name with the SO_BINDTODEVICE socket option.
 * The created socket is returned.
 */
int prepare_listen_socket(int family, int socktype, u_short port, 
		interface *dev)
{
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	int err, s;

	setzero(&hints, sizeof(struct addrinfo));
	hints.ai_family=family;
	hints.ai_socktype=socktype;
	hints.ai_flags=AI_PASSIVE;
	snprintf(strport, NI_MAXSERV, "%u", port);
	
	err=getaddrinfo(NULL, strport, &hints, &aitop);
	if(err) {
		error("Getaddrinfo error: %s", gai_strerror(err));
		return -1;
	}

	for (ai = aitop; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s == -1)
			/* Maybe we can use another socket...*/
			continue;

		/* Bind the created socket to the device named dev->dev_name */
		if(dev && (set_bindtodevice_sk(s, dev->dev_name) < 0)) {
			inet_close(&s);
			continue;
		}

		if(set_reuseaddr_sk(s) < 0) {
			inet_close(&s);
			continue;
		}

		/* Let's bind it! */
		if(bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			error("Cannot bind the port %d: %s. Trying another "
					"socket...", port, strerror(errno));
			inet_close(&s);
			continue;
		}
		freeaddrinfo(aitop);
		return s;
	}
	
	error("Cannot open inbound socket on port %d: %s", port, strerror(errno));
	freeaddrinfo(aitop);
	return -1;
}


/*
 * sockets_all_ifs
 *
 * creates a socket for each interface which is in the `ifs' array. 
 * The array has `ifs_n' members.
 * Each created socket is stored in the `dev_sk' array, which has `ifs_n'#
 * members.
 * The created socket will be bound to the relative interface.
 * In `max_sk_idx' is stored the index of the `dev_sk' array, which has the
 * biggest dev_sk.
 *
 * On error 0 is returned, otherwise the number of utilised interfaces is
 * returned.
 * If the error is fatal, a negative value is returned.
 */
int sockets_all_ifs(int family, int socktype, u_short port, 
			interface *ifs, int ifs_n, 
			int *dev_sk, int *max_sk_idx)
{
	int i, n, e=0;

	*max_sk_idx=0;

	for(i=0, n=0; i<ifs_n; i++) {
		dev_sk[i] = prepare_listen_socket(family, socktype, port,
				&ifs[i]);
		
		if(dev_sk[i] < 0) {
			error("Cannot create a socket on the %s interface! "
					"Ignoring it", ifs[i].dev_name);
			dev_sk[i]=0;
			e++;
			continue;
		}

		if(dev_sk[i] >= dev_sk[*max_sk_idx])
			*max_sk_idx=i;
		
		n++;
	}

	if(e == ifs_n)
		return -1;

	return n;
}

/*
 *  udp_exec_pkt: passes the received udp packet to pkt_exec().
 * `passed_argv' is a pointer to a udp_exec_pkt_argv struct 
 */
void *udp_exec_pkt(void *passed_argv)
{
	struct udp_exec_pkt_argv argv;
	
	PACKET rpkt;
	const char *ntop;

	memcpy(&argv, passed_argv, sizeof(struct udp_exec_pkt_argv));
	memcpy(&rpkt, argv.recv_pkt, sizeof(PACKET));

	if(argv.flags & UDP_THREAD_FOR_EACH_PKT)
		pthread_mutex_unlock(&udp_exec_lock);
	
	/* Drop any packet we sent in broadcast */
	if(!memcmp(rpkt.from.data, me.cur_ip.data, MAX_IP_SZ)) {
		pkt_free(&rpkt, 0);
		return 0;
	}

	if(add_accept(rpkt.from, 1)) {
		ntop=inet_to_str(rpkt.from);
		debug(DBG_NORMAL, "ACPT: dropped UDP pkt from %s: "
				"Accept table full.", ntop);
		return 0;
	} 

	pkt_exec(rpkt, argv.acpt_idx);
	pkt_free(&rpkt, 0);
	
	return 0;
}

/*
 * udp_daemon: Takes care of receiving udp packets.
 * `passed_argv' is a pointer to a udp_daemon_argv struct
 */
void *udp_daemon(void *passed_argv)
{
	struct udp_daemon_argv argv;
	struct udp_exec_pkt_argv exec_pkt_argv;
	
	interface *ifs;
	int max_sk_idx, dev_sk[me.cur_ifs_n];

	PACKET rpkt;
	fd_set fdset;
	int ret, i, err;
	u_short udp_port;
	
	pthread_t thread;
	pthread_attr_t t_attr;
	
#ifdef DEBUG
	int select_errors=0;
#endif
	
	memcpy(&argv, passed_argv, sizeof(struct udp_daemon_argv));
	udp_port=argv.port;
	setzero(&exec_pkt_argv, sizeof(struct udp_exec_pkt_argv));

	if(argv.flags & UDP_THREAD_FOR_EACH_PKT) {
		pthread_attr_init(&t_attr);
		pthread_attr_setdetachstate(&t_attr, PTHREAD_CREATE_DETACHED);
		exec_pkt_argv.flags|=UDP_THREAD_FOR_EACH_PKT;
	}

	debug(DBG_SOFT, "Preparing the udp listening socket on port %d", udp_port);
	
	err=sockets_all_ifs(my_family, SOCK_DGRAM, udp_port, me.cur_ifs,
				me.cur_ifs_n, dev_sk, &max_sk_idx);
	if(!err)
		return NULL;
	else if(err < 0)
		fatal("Creation of the %s daemon aborted. "
			"Is there another ntkd running?", "udp");
	
	debug(DBG_NORMAL, "Udp daemon on port %d up & running", udp_port);
	pthread_mutex_unlock(&udp_daemon_lock);

	pthread_mutex_init(&udp_exec_lock, 0);
	
	for(;;) {
		FD_ZERO(&fdset);

		if(!me.cur_ifs_n) {
			/* All the devices have been removed while ntkd was
			 * running, sleep well */
			sleep(1);
			continue;
		}

		for(i=0; i < me.cur_ifs_n; i++)
			if(dev_sk[i])
				FD_SET(dev_sk[i], &fdset);

		ret=select(dev_sk[max_sk_idx]+1, &fdset, NULL, NULL, NULL);
		if(sigterm_timestamp)
			/* NetsukukuD has been closed */
			break;
		if (ret < 0) {
#ifdef DEBUG
			if(select_errors > 20)
				break;
			select_errors++;
#endif
			error("daemon_udp: select error: %s", strerror(errno));
			continue;
		}

		for(i=0; i < me.cur_ifs_n; i++) {
			ifs=&me.cur_ifs[i];
			if(!dev_sk[i])
				continue;
			
			if(!FD_ISSET(dev_sk[i], &fdset))
				continue;

			setzero(&rpkt, sizeof(PACKET));
			pkt_addsk(&rpkt, my_family, dev_sk[i], SKT_UDP);
			pkt_add_dev(&rpkt, ifs, 0);
			rpkt.flags=MSG_WAITALL;
			pkt_addport(&rpkt, udp_port);

			if(pkt_recv(&rpkt) < 0) {
				pkt_free(&rpkt, 0);
				continue;
			}

			exec_pkt_argv.acpt_idx=accept_idx;
			exec_pkt_argv.acpt_sidx=accept_sidx;

			if(argv.flags & UDP_THREAD_FOR_EACH_PKT) {
				exec_pkt_argv.recv_pkt=&rpkt;
				pthread_mutex_lock(&udp_exec_lock);
				pthread_create(&thread, &t_attr, udp_exec_pkt,
						&exec_pkt_argv);
				pthread_mutex_lock(&udp_exec_lock);
				pthread_mutex_unlock(&udp_exec_lock);
			} else {
				exec_pkt_argv.recv_pkt=&rpkt;
				udp_exec_pkt(&exec_pkt_argv);
			}
		}
	}

	destroy_accept_tbl();
	return NULL;
}

void *tcp_recv_loop(void *recv_pkt)
{
	PACKET rpkt;
	int acpt_idx, acpt_sidx;

	acpt_idx=accept_idx;
	acpt_sidx=accept_sidx;
	memcpy(&rpkt, recv_pkt, sizeof(PACKET));
	pthread_mutex_unlock(&tcp_exec_lock);

#if 0
	add_accept_pid(getpid(), acpt_idx, acpt_sidx);
#endif

	while( pkt_recv(&rpkt) != -1 ) {
		if(pkt_exec(rpkt, acpt_idx) < 0) {
			goto close;
			break;
		} else
			pkt_free(&rpkt, 0);
	}

close:
	pkt_free(&rpkt, 1);
	close_accept(acpt_idx, acpt_sidx);

	return NULL;
}

void *tcp_daemon(void *door)
{
	pthread_t thread;
	pthread_attr_t t_attr;
	
	PACKET rpkt;
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof addr;
	inet_prefix ip;
	
	fd_set fdset;
	int fd, ret, err, i;

	interface *ifs;
	int max_sk_idx, dev_sk[me.cur_ifs_n];
	
	u_short tcp_port=*(u_short *)door;
	const char *ntop;

	pthread_attr_init(&t_attr);
	pthread_attr_setdetachstate(&t_attr, PTHREAD_CREATE_DETACHED);
	
	debug(DBG_SOFT, "Preparing the tcp listening socket on port %d", tcp_port);

	err=sockets_all_ifs(my_family, SOCK_STREAM, tcp_port, me.cur_ifs, 
				me.cur_ifs_n, dev_sk, &max_sk_idx);
	if(!err)
		return NULL;
	else if(err < 0)
		fatal("Creation of the %s daemon aborted. "
			"Is there another ntkd running?", "tcp");

	pthread_mutex_init(&tcp_exec_lock, 0);

	for(i=0; i<me.cur_ifs_n; i++) {
		if(!dev_sk[i])
			continue;
		/* 
		 * While we are accepting the connections we keep the socket non
		 * blocking.
		 */
		if(set_nonblock_sk(dev_sk[i]))
			return NULL;

		/* Shhh, it's listening... */
		if(listen(dev_sk[i], 5) == -1) {
			inet_close(&dev_sk[i]);
			return NULL;
		}
	}
	
	debug(DBG_NORMAL, "Tcp daemon on port %d up & running", tcp_port);
	pthread_mutex_unlock(&tcp_daemon_lock);
	for(;;) {
		FD_ZERO(&fdset);

		if(!me.cur_ifs_n) {
			/* All the devices have been removed while ntkd was
			 * running, sleep well */
			sleep(1);
			continue;
		}

		for(i=0; i < me.cur_ifs_n; i++)
			if(dev_sk[i])
				FD_SET(dev_sk[i], &fdset);

		ret=select(dev_sk[max_sk_idx]+1, &fdset, NULL, NULL, NULL);
		if(sigterm_timestamp)
			/* NetsukukuD has been closed */
			break;
		if(ret < 0 && errno != EINTR)
			error("daemon_tcp: select error: %s", strerror(errno));
		if(ret < 0)
			continue;

		for(i=0; i < me.cur_ifs_n; i++) {
			ifs=&me.cur_ifs[i];
			if(!dev_sk[i])
				continue;

			if(!FD_ISSET(dev_sk[i], &fdset))
				continue;

			fd=accept(dev_sk[i], (struct sockaddr *)&addr, &addrlen);
			if(fd == -1) {
				if (errno != EINTR && errno != EWOULDBLOCK)
					error("daemon_tcp: accept(): %s", strerror(errno));
				continue;
			}

			setzero(&rpkt, sizeof(PACKET));
			pkt_addsk(&rpkt, my_family, fd, SKT_TCP);
			pkt_add_dev(&rpkt, ifs, 0);
			rpkt.flags=MSG_WAITALL;
			pkt_addport(&rpkt, tcp_port);

			ntop=0;
			sockaddr_to_inet((struct sockaddr *)&addr, &ip, 0);
			pkt_addfrom(&rpkt, &ip);
			if(server_opt.dbg_lvl)
				ntop=inet_to_str(ip);

			if((ret=add_accept(ip, 0))) {
				debug(DBG_NORMAL, "ACPT: drop connection with %s: "
						"Accept table full.", ntop);

				/* Omg, we cannot take it anymore, go away: ACK_NEGATIVE */
				pkt_err(rpkt, ret, 1);
				inet_close(&fd);
				continue;
			} else {
				/* 
				 * Ok, the connection is good, send back the
				 * ACK_AFFERMATIVE.
				 */
				pkt_addto(&rpkt, &rpkt.from);
				send_rq(&rpkt, 0, ACK_AFFERMATIVE, 0, 0, 0, 0);
			}

			if(unset_nonblock_sk(fd))
				continue;

			pthread_mutex_lock(&tcp_exec_lock);
			err=pthread_create(&thread, &t_attr, tcp_recv_loop, (void *)&rpkt);
			pthread_detach(thread);
			pthread_mutex_lock(&tcp_exec_lock);
			pthread_mutex_unlock(&tcp_exec_lock);
		}
	}
	return NULL;
}
