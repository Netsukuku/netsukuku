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

#ifndef ANDNA_H
#define ANDNA_H

#include "andna_cache.h"
#include "pkts.h"

#define MY_NAMESERV		"nameserver 127.0.0.1"
#define MY_NAMESERV_IPV6	"nameserver ::1"
#define ETC_RESOLV_CONF		"/etc/resolv.conf"
#define ETC_RESOLV_CONF_BAK	"/etc/resolv.conf.bak"

/* How many different andna pkt can be flooded simultaneusly */
#define ANDNA_MAX_FLOODS	(ANDNA_MAX_QUEUE*3+1) 

/* How many new hash_gnodes are supported in the andna hash_gnode mutation */
#define ANDNA_MAX_NEW_GNODES	1024

/* 
 * These arrays keeps the latest reg_pkt and counter_check IDs to drop pkts
 * alreay received during the floods. These arrays are a FIFO, so the
 * last pkt_id will be always at the 0 position, while the first one will be
 * at the last position 
 */
int last_reg_pkt_id[ANDNA_MAX_FLOODS];
int last_counter_pkt_id[ANDNA_MAX_FLOODS];
int last_spread_acache_pkt_id[ANDNA_MAX_FLOODS];

/*\
 *			   *** ANDNA hash notes ***
 * 
 * In ANDNA there are three type of hashes: MD5, 32bit, 32bit hash of a MD5
 * hash. These hashes are generally applied on hostnames.
 *
 * The andna_hash() function, defined in andna.c, is used to calculate 
 * the IP of a hash_node/hash_gnode/counter_node. It makes a MD5 digest of the
 * input data. If we are working on ipv4, then a 32bit hash is applied to the
 * previously calculated MD5 digest. The result is the IP of the hash_gnode.
 * If we are in ipv6, we'll use directly the MD5 digest as the hash_gnode IP.
 *
 * In all the other cases we'll use directly the MD5 hash of the hostname,
 * f.e. the hname hash of the registration and resolution packets is a MD5.
 * The only exceptions are the lcl_cache and the rh_cache, which use
 * internally a 32bit hash to speed up the hname lookups.
 * 
 * The general guideline for new implementation is to always use big hashes
 * (i.e. MD5) where we might get collisions (f.e in an andna_cache), and to
 * use small hashes where we are safe (f.e. in the rhc_cache).
 *
\*/


/*\
 *
 *  * * *  ANDNA requests/replies pkt stuff  * * * 
 *
\*/

#define ANDNA_HOOK_TIMEOUT		8	/* seconds */
#define ANDNA_REV_RESOLVE_RQ_TIMEOUT	60

/* * * andna pkt flags * * */
#define ANDNA_PKT_UPDATE	1		/* Update the hostname */
#define ANDNA_PKT_FORWARD	(1<<1)		/* Forward this pkt, plz */
#define ANDNA_PKT_REV_RESOLVE	(1<<2)		/* Give me your hostnames */
#define ANDNA_PKT_JUST_CHECK	(1<<3)		/* Check only, don't update
						   anything */
#define ANDNA_PKT_SNSD_DEL	(1<<4)		/* SNSD delete request */

/*
 * andna_reg_pkt
 * 
 * Andna registration request pkt used to send the registration and update
 * requests to the hash_gnode, backup_gnode and counter_gnode.
 * When the pkt is sent to a counter_gnode, a second `rip', which is the ip
 * of the hash_gnode who is contacting the counter_gnode, is appended at the
 * end of the pkt.
 *
 * When the packet is sent to a hash_gnode, at the end of the packet is 
 * included a packed snsd_service linked list. It is the list of snsd_records
 * that have to be registered. However the packet forwarded to the counter 
 * node won't keep this part.
 */
struct andna_reg_pkt
{
	u_int	 	rip[MAX_IP_INT];	/* register_node ip */
 	u_int		hash[MAX_IP_INT];	/* md5 hash of the host name to
						   register. */
 	char		pubkey[ANDNA_PKEY_LEN];	/* public key of the register
 						   node. */
	u_short		hname_updates;		/* number of updates already 
						   made for the hostname */
	
 	char		sign[ANDNA_SIGNATURE_LEN]; /* RSA signature of the 
						      entire pkt (excluding 
						      `sign' itself and `flags'
						    */
	char 		flags;
	
} _PACKED_;
#define ANDNA_REG_PKT_SZ	     (sizeof(struct andna_reg_pkt))
#define ANDNA_REG_SIGNED_BLOCK_SZ (ANDNA_REG_PKT_SZ - ANDNA_SIGNATURE_LEN - \
				 	sizeof(char))
INT_INFO andna_reg_pkt_iinfo = 	{ 1, /* `rip' and `hash' aren't considered */
				 { INT_TYPE_16BIT },
				 { MAX_IP_SZ*2 + ANDNA_PKEY_LEN },
				 { 1 },
			  	};
				 

/*
 *   andna_resolve_rq_pkt
 *
 * The andna resolve request pkt is used to resolve hostnames, IPs and MX
 * hostnames.
 */
struct andna_resolve_rq_pkt
{
	u_int	 	rip[MAX_IP_INT];	/* the ip of the requester node */
	char		flags;
	
	u_int           hash[MAX_IP_INT];       /* md5 hash of the hostname to
						   resolve. */
	int		service;		/* the snsd service of the hname */
	u_char		proto;			/* the protocol of `service' */
} _PACKED_;
#define ANDNA_RESOLVE_RQ_PKT_SZ		(sizeof(struct andna_resolve_rq_pkt))
INT_INFO andna_resolve_rq_pkt_iinfo =	{ 1, /* `rip' and `hash' are ignored */
					  { INT_TYPE_32BIT },
					  { MAX_IP_SZ*2+sizeof(char) },
					  { 1 },
					};

/* 
 * The reply to the resolve request
 */
struct andna_resolve_reply_pkt
{
	uint32_t	timestamp;		/* the difference between the current
						   time and the last time the resolved
						   hname was updated */
	/*
	 * the rest of the pkt is a pack of one snsd_service llist:
	 * char		service[SNSD_SERVICE_LLIST_PACK_SZ(service)];
	 */
} _PACKED_;
#define ANDNA_RESOLVE_REPLY_PKT_SZ	(sizeof(struct andna_resolve_reply_pkt))
INT_INFO andna_resolve_reply_pkt_iinfo = { 1, /* `ip' is ignored */
					   { INT_TYPE_32BIT }, 
					   { 0 }, 
					   { 1 }
					 };


/* 
 * The reply to the reverse resolve request is just the packed local cache.
 */


/* 
 * single_acache
 *
 * The single_acache pkt is used to get from an old hash_gnode a single
 * andna_cache, which has the wanted `hash'. Its propagation method is similar
 * to that of andna_resolve_rq_pkt, but each new hash_gnode, which receives
 * the pkt, adds in the body pkt its ip. The added ips are used as excluded 
 * hash_gnode by find_hash_gnode(). In this way each time an old hash_gnode 
 * receives the pkt, can verify if it is, at that current time, the true old 
 * hash_gnode by excluding the hash_gnodes listed in the pkt body. If it 
 * notices that there's an hash_gnode older than it, it will append its ip in 
 * the pkt body and will forward it to that older hash_gnode. And so on, until
 * the pkt reaches a true old hash_gnode, or cannot be forwarded anymore since
 * there are no more older hash_gnodes.
 */
struct single_acache_hdr
{
	u_int		rip[MAX_IP_INT];	/* the ip of the requester node */
	u_int		hash[MAX_IP_INT];
	u_short		hgnodes;		/* Number of hgnodes in the 
						   body. */
	u_char		flags;
} _PACKED_;
INT_INFO single_acache_hdr_iinfo = { 1, /* `rip' and `hash' are ignored */
				     { INT_TYPE_16BIT },
				     { MAX_IP_SZ*2 },
				     { 1 },
				   };
/*
 * The single_acache body is:
 * struct {
 * 	u_int		hgnode[MAX_IP_INT];
 * } body[new_hash_gnode_hdr.hgnodes];
 */
#define SINGLE_ACACHE_PKT_SZ(hgnodes)	(sizeof(struct single_acache_hdr)+\
						MAX_IP_SZ*(hgnodes))

/*
 * The single_acache_reply is just an andna_cache_pkt with a single cache.
 */


/*
 * Tell the node, which receives the pkt, to send a ANDNA_GET_SINGLE_ACACHE
 * request to fetch the andna_cache for the `hash' included in the pkt.
 */
struct spread_acache_pkt
{
	u_int		hash[MAX_IP_INT];
} _PACKED_;
#define SPREAD_ACACHE_PKT_SZ	(sizeof(struct spread_acache_pkt))
INT_INFO spread_acache_pkt_info = { 0, { 0 }, { 0 }, { 0 } };



/*\
 *
 *   * * *  Function declaration  * * *
 *
\*/

int andna_load_caches(void);
int andna_save_caches(void);

void andna_init(void);
void andna_close(void);
void andna_resolvconf_modify(void);
void andna_resolvconf_restore(void);

int andna_register_hname(lcl_cache *alcl, snsd_service *snsd_delete);
int andna_recv_reg_rq(PACKET rpkt);

int andna_check_counter(PACKET pkt);
int andna_recv_check_counter(PACKET rpkt);

snsd_service *andna_resolve_hash(u_int hname_hash[MAX_IP_INT], int service, 
				 u_char proto, int *records);
snsd_service *andna_resolve_hname(char *hname, int service, u_char proto, 
				  int *records);
int andna_recv_resolve_rq(PACKET rpkt);

lcl_cache *andna_reverse_resolve(inet_prefix ip);
int andna_recv_rev_resolve_rq(PACKET rpkt);

int spread_single_acache(u_int hash[MAX_IP_INT]);
int recv_spread_single_acache(PACKET rpkt);
andna_cache *get_single_andna_c(u_int hash[MAX_IP_INT], u_int hash_gnode[MAX_IP_INT]);
int put_single_acache(PACKET rpkt);
int put_andna_cache(PACKET rq_pkt);
int put_counter_cache(PACKET rq_pkt);

void *andna_hook(void *);
void andna_update_hnames(int only_new_hname);
void *andna_maintain_hnames_active(void *null);
void *andna_main(void *);

#endif /*ANDNA_H*/
