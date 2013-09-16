/* This file is part of Netsukuku
 * (c) Copyright 2006 Andrea Lo Pumo aka AlpT <alpt@freaknet.org>
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

#ifndef SNSD_H
#define SNSD_H

#include "inet.h"
#include "crypto.h"
#include "endianness.h"
#include "llist.c"

/*
 * SNSD definitions
 */

#define SNSD_MAX_RECORDS		256	/* Number of maximum SNSD records
						   which can be stored in an
						   andna_cache */
#define SNSD_MAX_QUEUE_RECORDS		1	/* There can be only one snsd 
						   record for the queued hnames */
#define SNSD_MAX_REC_SERV		16	/* Maximum records per service */

#define SNSD_ALL_SERVICE		(-1)	/* A service number equal to -1
						   refers to all the available
						   services */
#define SNSD_DEFAULT_SERVICE		0
#define SNSD_DEFAULT_PROTO		1	/* tcp */
#define SNSD_DEFAULT_PRIO		16
#define SNSD_DEFAULT_WEIGHT		1

#define SNSD_WEIGHT(x)			((x) & 0x7f) 	/* The snsd weight has to 
						   	   be <= 127 */

/* Fields used in the syntax for the `snsd_nodes' file:
 * 	hostname:snsd_hostname:service:priority:weight[:pub_key_file]
 */
#define MAX_SNSD_LINE_SZ                (ANDNA_MAX_HNAME_LEN*4)
#define MAX_SNSD_FIELDS			6
#define MIN_SNSD_FIELDS			5

/* * snsd_node flags * */
#define SNSD_NODE_HNAME			1	/* A hname is associated in the 
					 	   snsd record */
#define SNSD_NODE_IP			(1<<1)	/* An IP is associated in the 
					   	   snsd record */
#define SNSD_NODE_MAIN_IP		(1<<2)	/* This is the first IP registered 
						   to the hname, it can't be
						   deleted */


/*
 * snsd_node, snsd_service, snsd_prio
 *
 * They are three linked list. They are all orthogonal to each other.
 * The snsd_node llist is inside each snsd_prio struct which is inside each
 * snsd_service struct:
 * || service X          <->   service Y          <->   service Z  <-> ... ||
 *        |		           |			    |
 *        V		           V			    V
 *    snsd_prio_1-->node       snsd_prio_1-->node          ...-->...
 *        |		           |
 *        V		           V
 *    snsd_prio_2-->node	  ...-->node
 *    	  |
 *    	  V
 *    	 ...-->node
 *
 * Using this schema, we don't have to sort them, ever. The nodes are already
 * grouped by service and in each service by priority.
 * 
 * These llist are directly embedded in the andna_cache, lcl_cache and
 * rh_cache.
 * 
 * The andna_cache keeps all the SNSD nodes associated to the registered
 * hostname. The andna_cache doesn't need `snsd_node->pubkey'.
 *
 * The rh_cache stores only records which are of the SNSD_NODE_IP type.
 *
 * When the lcl_cache is saved, its snsd llist is discarded because it is
 * loaded each time from the /etc/netsukuku/snsd_nodes file.
 */
struct snsd_node
{ 
	LLIST_HDR	(struct snsd_node);
	
	u_int		record[MAX_IP_INT];	/* It can be the IP or the md5
						   hash of the hname of the 
						   SNSD node */
	RSA		*pubkey;		/* pubkey of the snsd_node */
	char		flags;			/* This will tell us what 
						   `record' is */
	
	u_char		weight;
};
typedef struct snsd_node snsd_node;
/* In the pack of a snsd_node we don't save the `pubkey' */
#define SNSD_NODE_PACK_SZ		(MAX_IP_SZ+sizeof(char)*2)

struct snsd_prio
{
	LLIST_HDR	(struct snsd_prio);
	
	u_char		prio;			/* Priority of the SNSD node */
	
	snsd_node	*node;
};
typedef struct snsd_prio snsd_prio;
#define SNSD_PRIO_PACK_SZ		(sizeof(char))

struct snsd_service
{
	LLIST_HDR	(struct snsd_service);

	u_short		service;		/* Service number */
	u_char		proto;			/* TCP/UDP, see the `proto_str'
						   static array below */
	
	snsd_prio	*prio;
};
typedef struct snsd_service snsd_service;
#define SNSD_SERVICE_PACK_SZ		(sizeof(u_short)+sizeof(u_char))


/*
 * 
 *  * * * snsd structs package * * *
 *  
 */

struct snsd_node_llist_hdr
{
	u_short		count;		/* # of snsd_node structs packed 
					   in the body */
}_PACKED_;
INT_INFO snsd_node_llist_hdr_iinfo = { 1, { INT_TYPE_16BIT }, { 0 }, { 1 } };
/*
 * the body of the pkt is:
 * 
 * struct snsd_node_pack {
 *	u_int           record[MAX_IP_INT];
 *	char            flags;
 *	u_char          weight;
 * } pack[hdr.nodes];
 */
#define SNSD_NODE_LLIST_PACK_SZ(head) 	(list_count((head))*SNSD_NODE_PACK_SZ  \
					  + sizeof(struct snsd_node_llist_hdr))
		
struct snsd_prio_llist_hdr
{
	u_short		count;		/* number of structs packed in 
					   the body */
}_PACKED_;
INT_INFO snsd_prio_llist_hdr_iinfo = { 1, { INT_TYPE_16BIT }, { 0 }, { 1 } };
/*
 * the body is:
 *
 * snsd_prio_pack {
 * 	u_char		prio;
 * 	char		snsd_node_llist_pack[SNSD_NODE_LLIST_PACK_SZ];
 * } pack[hdr.count];
 */
#define SNSD_PRIO_LLIST_PACK_SZ(head)					\
({									\
	snsd_prio *_p=(head);						\
	int _priosz=0;							\
									\
	list_for(_p) {							\
		_priosz+=SNSD_NODE_LLIST_PACK_SZ(_p->node);		\
 		_priosz+=SNSD_PRIO_PACK_SZ;				\
 	}								\
	_priosz+=sizeof(struct snsd_prio_llist_hdr);			\
	_priosz;							\
})


struct snsd_service_llist_hdr
{
	u_short		count;
}_PACKED_;
INT_INFO snsd_service_llist_hdr_iinfo = { 1, { INT_TYPE_16BIT }, { 0 }, { 1 } };
/*
 * the body is:
 * 	u_short		service;
 * 	u_char		proto;
 * 	char		snsd_prio_llist_pack[SNSD_PRIO_LLIST_PACK_SZ];
 */
#define SNSD_SERVICE_LLIST_PACK_SZ(head)				\
({									\
	snsd_service *_s=(head);					\
	int _srvsz=0;							\
 	if(_s) {							\
		 list_for(_s) {						\
			 _srvsz+=SNSD_PRIO_LLIST_PACK_SZ(_s->prio);	\
 			 _srvsz+=SNSD_SERVICE_PACK_SZ;			\
 		 }							\
		 _srvsz+=sizeof(struct snsd_service_llist_hdr);		\
	 }								\
	_srvsz;								\
})

#define SNSD_SERVICE_SINGLE_PACK_SZ(head)				\
({	SNSD_SERVICE_PACK_SZ +						\
		SNSD_PRIO_LLIST_PACK_SZ((head)->prio);			\
})
 	
#define SNSD_SERVICE_MAX_PACK_SZ					\
(	( (SNSD_NODE_PACK_SZ + SNSD_PRIO_PACK_SZ) * 			\
		 	(SNSD_MAX_REC_SERV) 		) + 		\
	SNSD_SERVICE_PACK_SZ 				  +		\
	sizeof(struct snsd_prio_llist_hdr) 		  +		\
	sizeof(struct snsd_service_llist_hdr)				\
)

#define SNSD_SERVICE_MAX_LLIST_PACK_SZ					\
((	SNSD_NODE_PACK_SZ + SNSD_PRIO_PACK_SZ + SNSD_SERVICE_PACK_SZ +	\
		sizeof(struct snsd_prio_llist_hdr))*SNSD_MAX_RECORDS +  \
        sizeof(struct snsd_service_llist_hdr)				\
)


/*
 * This array is used to associate a 8bit number to a protocol name.
 * The number is the position of the protocol name in this array.
 * For example: "tcp" is in the first position so its associated number is 1,
 * while the number for "udp" is 2.
 *
 * Since we limit the proto number to an 8bit number, there can be only 255
 * protocols in this array.
 */
const static char proto_str[][5] =
{
	{ "tcp" },
	{ "udp" },
	{ 0 },
};



/*
 * 
 * * * Functions' declaration * * *
 *
 */

void snsd_cache_init(int family);
u_char str_to_snsd_proto(char *proto_name);
const char *snsd_proto_to_str(u_char proto);
int str_to_snsd_service(char *str, int *service, u_char *proto);
struct servent *snsd_service_to_str(int service, u_char proto, 
				    char **service_str, char **proto_str);

snsd_service *snsd_find_service(snsd_service *sns, u_short service, u_char proto);
snsd_service *snsd_add_service(snsd_service **head, u_short service, u_char proto);
snsd_prio *snsd_find_prio(snsd_prio *snp, u_char prio);
snsd_prio *snsd_add_prio(snsd_prio **head, u_char prio);
snsd_node *snsd_find_node_by_record(snsd_node *snd, u_int record[MAX_IP_INT]);
snsd_node *snsd_add_node(snsd_node **head, u_short *counter, 
			 u_short max_records, u_int record[MAX_IP_INT]);
snsd_node *snsd_add_mainip(snsd_service **head, u_short *counter,
				u_short max_records, u_int record[MAX_IP_INT]);
void snsd_service_llist_del(snsd_service **head);
void snsd_record_del_selected(snsd_service **head, u_short *snd_counter, 
			snsd_service *selected);

int snsd_pack_service(char *pack, size_t free_sz, snsd_service *service);
snsd_service *snsd_unpack_service(char *pack, size_t pack_sz, 
				  size_t *unpacked_sz, u_short *nodes_counter);
int snsd_pack_all_services(char *pack, size_t pack_sz, snsd_service *head);
snsd_service *snsd_unpack_all_service(char *pack, size_t pack_sz, 
				        size_t *unpacked_sz, u_short *nodes_counter);

snsd_node *snsd_choose_wrand(snsd_node *head);
snsd_prio *snsd_highest_prio(snsd_prio *head);
snsd_node *snsd_find_mainip(snsd_service *sns);
void snsd_unset_all_flags(snsd_service *sns, u_char flag);
snsd_service *snsd_service_llist_copy(snsd_service *sns, int service, 
					u_char proto);

void snsd_merge_node(snsd_node **head, u_short *snsd_counter, snsd_node *new);
void snsd_node_llist_merge(snsd_node **dst, u_short *snsd_counter, snsd_node *src);
void snsd_merge_prio(snsd_prio **head, u_short *snsd_counter, snsd_prio *new);
void snsd_prio_llist_merge(snsd_prio **dst, u_short *snsd_counter, snsd_prio *src);
void snsd_merge_service(snsd_service **head, u_short *snsd_counter, 
			snsd_service *new);
void snsd_service_llist_merge(snsd_service **dst, u_short *snsd_counter,
			      snsd_service *src);

int snsd_count_nodes(snsd_node *head);
int snsd_count_prio_nodes(snsd_prio *head);
int snsd_count_service_nodes(snsd_service *head);
#endif /*SNSD_H*/
