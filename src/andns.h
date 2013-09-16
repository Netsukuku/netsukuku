	         /**************************************
	        *     AUTHOR: Federico Tomassini        *
	       *     Copyright (C) Federico Tomassini    *
	      *     Contact effetom@gmail.com	          *
	     ***********************************************
	     *******          BEGIN 3/2006          ********
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
#ifndef ANDNS_H
#define ANDNS_H

#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include "dnslib.h"
#include "andns_lib.h"
#include "inet.h"

#define ANDNS_TIMEOUT		15

#define MAXNSSERVERS 		3
#define DNS_REPLY_TIMEOUT       10      /* seconds */

#define DNS_PORT		53
#define DNS_PORT_STR		"53"

/* PREFIX TO QUERY THE INET REALM */
#define INET_REALM_PREFIX       ".INT"
#define NTK_REALM_PREFIX        ".NTK"
#define PTR_INET_REALM_PREFIX   "INT."
#define PTR_NTK_REALM_PREFIX    "NTK."
#define REALM_PREFIX_LEN        4

#define DNS_PROTO		0
#define ANDNS_PROTO		1

#define NK_DNS			0
#define NK_NTK			1
#define NK_INET			2
#define GET_NK_BIT(msg)		(*((msg+3))>>4)&0x03

#define RCODE_NOERR		0	
#define RCODE_EINTRPRT		1
#define RCODE_ESRVFAIL		2
#define RCODE_ENSDMN 		3
#define RCODE_ENIMPL		4
#define RCODE_ERFSD		5



	/* FUNCTIONS */

int store_ns(char *ns);
int collect_resolv_conf(char *resolve_conf);
void reset_andns_ns(void);
int andns_init(int restricted, char *resolv_conf,int family);
void andns_close(void);
int ns_general_send(char *msg,int msglen,char *answer,int anslen);
void dpktacpy(dns_pkt *dst,dns_pkt *src,const char *prefix);
dns_pkt* dpktcpy(dns_pkt *src,const char *prefix);
char* rm_realm_prefix(char *from,char *dst,int type);
dns_pkt* dpktcpy_rm_pref(dns_pkt *src);
int andns_gethostbyname(char *hname, inet_prefix *ip);
int andns_realm(dns_pkt_qst *dpq,int *prefixed);
int is_prefixed(dns_pkt *dp);
int dns_forward(dns_pkt *dp,char *msg,int msglen,char* answer);
int inet_rslv(dns_pkt *dp,char *msg,int msglen,char *answer);
int nk_rslv(andns_pkt *ap,char *msg,int msglen,char *answer);
int qtype_a_to_d(andns_pkt *ap);
int apqsttodpqst(andns_pkt *ap,dns_pkt **dpsrc);
int dpanswtoapansw(dns_pkt *dp,andns_pkt *ap);
int nk_forward(andns_pkt *ap,char *msg,int msglen,char *answer);
char *andns_rslv(char *msg, int msglen,char *answer, int *answ_len);

#endif /* ANDNS_H */
