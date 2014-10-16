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

#ifndef ANDNS_SNSD_H
#define ANDNS_SNSD_H

#include "dnslib.h"
#include "andns_lib.h"
#include "andna_cache.h"

#define ANDNS_SNSD_PROTO_TCP	1
#define ANDNS_SNSD_PROTO_UDP	2

/* functions */

int snsd_main_ip(u_int * hname_hash, snsd_node * dst);
int snsd_node_to_data(char *buf, snsd_node * sn, u_char prio, int iplen,
					  int recursion);
size_t snsd_node_to_aansw(char *buf, snsd_node * sn, u_char prio,
						  int iplen);
int snsd_prio_to_aansws(char *buf, snsd_prio * sp, int iplen,
						int recursion, int *count);
int snsd_service_to_aansws(char *buf, snsd_service * ss, int iplen,
						   int *count, int recursion);
int snsd_node_to_dansw(dns_pkt * dp, snsd_node * sn, int iplen);
int snsd_prio_to_dansws(dns_pkt * dp, snsd_prio * sp, int iplen);
int lcl_cache_to_dansws(dns_pkt * dp, lcl_cache * lc);
size_t lcl_cache_to_aansws(char *buf, lcl_cache * lc, int *count);
#endif							/* ANDNS_SNSD_H */
