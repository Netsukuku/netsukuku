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

#ifndef DNS_WRAPPER_H
#define DNS_WRAPPER_H

#define DNS_WRAPPER_PORT	53
#define MAX_DNS_PKT_SZ		512
#define MIN_PKT_SZ		7

/* DNS wrapper resolver api */
void resolver_process(const char *question, unsigned question_length, 
		char *answer, unsigned *answer_length,
		int (*callback)(const char *name, uint32_t *ip));

/*
 * dns_exec_pkt_argv is the struct passed to dns_exec_pkt() as argument 
 */
struct dns_exec_pkt_argv 
{
	char		*rpkt;	/* Received dns query pkt */
	ssize_t		rpkt_sz;

	int		sk;
	struct sockaddr	from;
	socklen_t	from_len;
};

pthread_mutex_t dns_exec_lock;

/* * * Functions declarations * * */

void *dns_wrapper_thread(void *null);

#endif /*DNS_WRAPPER_H*/
