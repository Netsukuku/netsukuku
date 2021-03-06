			 /**************************************
	        *     AUTHOR: Federico Tomassini        *
	       *     Copyright (C) Federico Tomassini    *
	      *     Contact effetom@gmail.com             *
	     ***********************************************
	     *******          BEGIN 4/2006          ********
*************************************************************************
*                                              				* 
*  This program is free software; you can redistribute it and/or modify	*
*  it under the terms of the GNU General Public License as published by	*
*  the Free Software Foundation; either version 2 of the License, or	*
*  (at your option) any later version.					*
*									*
*  This program is distributed in the hope that it will be useful,	*
*  but WITHOUT ANY WARRANTY; without even the implied warranty of	*
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the	*
*  GNU General Public License for more details.				*
*									*
************************************************************************/

#ifndef ANDNS_NET_H
#define ANDNS_NET_H

#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>



int idp_inet_ntop(int family, struct sockaddr *addr, char *buf,
				  int buflen);
int w_socket(int family, int type, int proto, int die);
int w_connect(struct addrinfo *ai, int die);
int serial_connect(struct addrinfo *ai, int die);
int host_connect(const char *host, uint16_t port, int type, int die);
int ai_connect(struct addrinfo *ai, int die, int free_ai);
ssize_t w_send(int sk, const void *buf, size_t len, int die);
ssize_t w_recv(int sk, void *buf, size_t len, int die);
ssize_t w_send_timeout(int s, const void *buf, size_t len, int die,
					   int timeout);
ssize_t w_recv_timeout(int s, void *buf, size_t len, int die, int timeout);
ssize_t ai_send_recv_close(struct addrinfo *ai, void *buf, size_t buflen,
						   void *anbuf, size_t anlen, int die, int free_ai,
						   int timeout);
ssize_t hn_send_recv_close(const char *host, uint16_t port, int type,
						   void *buf, size_t buflen, void *anbuf,
						   size_t anlen, int die, int timeout);
void char_print(char *buf, int len);


#endif							/* ANDNS_NET_H */
