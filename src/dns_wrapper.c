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
 * dns_wrapper.c:
 *
 * The DNS wrapper listens to the port 53 for DNS hostname resolution queries,
 * it then resolves the hostname by using the ANDNA system and sends back the
 * resolved ip. In this way, every program can use ANDNA: just set 
 * "nameserver localhost"
 * in /etc/resolv.conf ;)
 */

#include "includes.h"

#include "inet.h"
#include "endianness.h"
#include "map.h"
#include "gmap.h"
#include "bmap.h"
#include "route.h"
#include "request.h"
#include "pkts.h"
#include "tracer.h"
#include "qspn.h"
#include "radar.h"
#include "netsukuku.h"
#include "daemon.h"
#include "crypto.h"
#include "andna_cache.h"
#include "andna.h"
#include "andns.h"
#include "dns_wrapper.h"
#include "common.h"

/*
 * dns_exec_pkt: resolve the hostname contained in the DNS query and sends
 * the reply to from. 
 * `passed_argv' is a pointer to a dns_exec_pkt_argv struct.
 */
void *dns_exec_pkt(void *passed_argv)
{
	struct dns_exec_pkt_argv argv;

	char buf[MAX_DNS_PKT_SZ];
	char answer_buffer[ANDNS_MAX_SZ];
	int answer_length;
	int bytes_sent;

	memcpy(&argv, passed_argv, sizeof(struct dns_exec_pkt_argv));
	memcpy(&buf, argv.rpkt, argv.rpkt_sz);
	pthread_mutex_unlock(&dns_exec_lock);

	if (argv.rpkt_sz < MIN_PKT_SZ) {
		debug(DBG_NORMAL, "Received malformed DNS packet");
		return 0;
	}

	/* Unpack the DNS query and resolve the hostname */
	if(!andns_rslv(buf, argv.rpkt_sz, answer_buffer, &answer_length))
		return 0;

	/* Send the DNS reply */
	bytes_sent=inet_sendto(argv.sk, answer_buffer, answer_length, 0,
			&argv.from, argv.from_len);
	if(bytes_sent != answer_length)
		debug(DBG_SOFT, ERROR_MSG "inet_sendto error: %s", ERROR_POS,
				strerror(errno));

	return 0;
}

/*
 * dns_wrapper_daemon: It receives DNS query pkts, resolves them in ANDNA and
 * replies with a DNS reply.
 * It listens to `port'.
 */
void dns_wrapper_daemon(u_short port)
{
	struct dns_exec_pkt_argv exec_pkt_argv;
	char buf[MAX_DNS_PKT_SZ];

	fd_set fdset;
	int ret, sk;
	pthread_t thread;
	pthread_attr_t t_attr;
	ssize_t err=-1;

#ifdef DEBUG
	int select_errors=0;
#endif
	
	pthread_attr_init(&t_attr);
	pthread_attr_setdetachstate(&t_attr, PTHREAD_CREATE_DETACHED);
	pthread_mutex_init(&dns_exec_lock, 0);

	debug(DBG_SOFT, "Preparing the dns_udp listening socket on port %d", port);
	sk=prepare_listen_socket(my_family, SOCK_DGRAM, port, 0);
	if(sk == -1)
		return;

	debug(DBG_NORMAL, "DNS wrapper daemon on port %d up & running", port);
	for(;;) {
		if(!sk)
			fatal("The dns_wrapper_daemon socket got corrupted");
		
		FD_ZERO(&fdset);
		FD_SET(sk, &fdset);
		
		ret = select(sk+1, &fdset, NULL, NULL, NULL);
		if(sigterm_timestamp)
			/* NetsukukuD has been closed */
			break;
		if (ret < 0) {
#ifdef DEBUG
			if(select_errors > 20)
				break;
			select_errors++;
#endif
			error("dns_wrapper_daemonp: select error: %s", 
					strerror(errno));
			continue;
		}
		if(!FD_ISSET(sk, &fdset))
			continue;

		setzero(&buf, MAX_DNS_PKT_SZ);
		setzero(&exec_pkt_argv.from, sizeof(struct sockaddr));
		setzero(&exec_pkt_argv, sizeof(struct dns_exec_pkt_argv));
		
		exec_pkt_argv.from_len = my_family == AF_INET ?
			sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

		/* we get the DNS query */
		err=inet_recvfrom(sk, buf, MAX_DNS_PKT_SZ, MSG_WAITALL,
				&exec_pkt_argv.from, &exec_pkt_argv.from_len);
		if(err < 0) {
			debug(DBG_NOISE, "dns_wrapper_daemonp: recv of the dns"
					" query pkt aborted!");
			continue;
		}
		
		/* Exec the pkt in another thread */
		exec_pkt_argv.sk=sk;
		exec_pkt_argv.rpkt_sz=err;
		exec_pkt_argv.rpkt=buf;
		
		pthread_mutex_lock(&dns_exec_lock);
		pthread_create(&thread, &t_attr, dns_exec_pkt, 
				(void *)&exec_pkt_argv);
		pthread_mutex_lock(&dns_exec_lock);
		pthread_mutex_unlock(&dns_exec_lock);
	}
}

void *dns_wrapper_thread(void *null)
{
	dns_wrapper_daemon(DNS_WRAPPER_PORT);
	return 0;
}
