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
 *
 * --  
 * snsd.c
 *
 * Scattered Name Service Digregation
 *
 * Here there are the main functions used to add/modify/delete/pack/unpack 
 * the records in the SNSD linked lists.
 * The functions which handle SNSD requests/replies are in andna.c.
 */

#include "includes.h"

#include "snsd_cache.h"
#include "common.h"

int net_family;

void snsd_cache_init(int family)
{
	net_family=family;
}

/*
 * str_to_snsd_proto
 *
 * It returns the protocol number associated to `proto_name'.
 * (See the `proto_str' static array in snsd.h)
 *
 * If no protocol matched, 0 is returned.
 */
u_char str_to_snsd_proto(char *proto_name)
{
	int i;
	
	for(i=0; i<=256; i++) {
		if(!proto_str[i])
			break;
		if(!strcmp(proto_name, proto_str[i]))
			return i+1;
	}

	return 0;
}

const char *snsd_proto_to_str(u_char proto)
{
	return proto_str[proto-1];
}

/*
 * str_to_snsd_service
 *
 * `str' is a string which specifies the service of a snsd record. It 
 * is one of the service listed in /etc/services. It can be expressed 
 * also in numeric form.
 * It is also possible to specify the protocol, f.e: 
 * 	"domain", "53", "53/udp", "domain/udp"
 * are valid service strings.
 *
 * This function converts `str' to a service number and a protocol 
 * number in the str_to_snsd_proto() format.
 *
 * On error a negative value is returned.
 *	 If the service is invalid  -1 is returned.
 *	 If the protocol is invalid -2 is returned.
 */
int str_to_snsd_service(char *str, int *service, u_char *proto)
{
	struct servent *st;
	char *servname, *servproto;

	servname=str;
	if((servproto=strchr(str, '/'))) {
		*servproto=0;
		servproto++;
		if(!(*proto=str_to_snsd_proto(servproto)))
			return -1;
	} else
		*proto=SNSD_DEFAULT_PROTO;

	if(!isdigit(servname[0])) {
		if(!(st=getservbyname(servname, 0)))
			return -2;

		*service=ntohs(st->s_port);
	} else
		*service=atoi(servname);

	return 0;
}

/*
 * snsd_service_to_str
 *
 * Converts the `service' and `proto' numbers to a servent struct, and sets
 * the pointer `service_str' to the service string while `proto_str' to the
 * protocol string.
 * A pointer to the servent structure is returned.
 *
 * On error 0 is returned.
 */
struct servent *
snsd_service_to_str(int service, u_char proto, char **service_str, 
		    char **proto_str)
{
	struct servent *st=0;

	if(!(st=getservbyport(service, snsd_proto_to_str(proto))))
		return 0;

	*service_str=st->s_name;
	*proto_str=st->s_proto;

	return st;
}


/*\
 *
 *  *  *  SNSD structs functions  *  *  *
 *
\*/

snsd_service *snsd_find_service(snsd_service *sns, u_short service, 
				u_char proto)
{
	list_for(sns)
		if(sns->service == service &&
				(sns->proto == proto || 
				 service == SNSD_DEFAULT_SERVICE))
			return sns;
	return 0;
}

snsd_service *snsd_add_service(snsd_service **head, u_short service, 
				u_char proto)
{
	snsd_service *sns, *new;

	if((sns=snsd_find_service(*head, service, proto)))
		return sns;

	new=xzalloc(sizeof(snsd_service));
	new->service=service;
	new->proto=proto;
	
	*head=list_add(*head, new);

	return new;
}

snsd_prio *snsd_find_prio(snsd_prio *snp, u_char prio)
{
	list_for(snp)
		if(snp->prio == prio)
			return snp;
	return 0;
}

snsd_prio *snsd_add_prio(snsd_prio **head, u_char prio)
{
	snsd_prio *snp, *new;

	if((snp=snsd_find_prio(*head, prio)))
		return snp;

	new=xzalloc(sizeof(snsd_prio));
	new->prio=prio;
	
	*head=list_add(*head, new);

	return new;
}

snsd_node *snsd_find_node_by_record(snsd_node *snd, u_int record[MAX_IP_INT])
{
	list_for(snd)
		if(!memcmp(snd->record, record, MAX_IP_SZ))
			return snd;
	return 0;
}


/*
 * snsd_add_node
 *
 * If `record' is not NULL, it searches for a snsd_node struct which has
 * the same `record' of the argument. If it is found, it is returned.
 * If it isn't found or `record' is NULL, it adds a new snsd_node struct 
 * in the `*head' llist and returns it.
 * `max_records' is the max number of records allowed in the llist. If no
 * empty place are left to add the new struct, 0 is returned.
 */
snsd_node *snsd_add_node(snsd_node **head, u_short *counter, 
			 u_short max_records, u_int record[MAX_IP_INT])
{
	snsd_node *snd;

	if(record && (snd=snsd_find_node_by_record(*head, record)))
		return snd;

	if(*counter >= max_records)
		/* The llist is full */
		return 0;

	snd=xzalloc(sizeof(snsd_node));

	if(record)
		memcpy(snd->record, record, MAX_IP_SZ);

	clist_add(head, counter, snd);

	return snd;
}

/*
 * snsd_add_first_node
 *
 * It adds a new node in the llist if `*head' or `*counter' is zero. 
 * The new node is returned.
 * If it isn't zero, it returns the first struct of the llist.
 */
snsd_node *snsd_add_first_node(snsd_node **head, u_short *counter,
				u_short max_records, u_int record[MAX_IP_INT])
{
	if(!(*head) || !(*counter))
		return snsd_add_node(head, counter, max_records, record);
	
	return *head;
}

/*
 * just a wrapper
 */
snsd_node *snsd_add_mainip(snsd_service **head, u_short *counter,
				u_short max_records, u_int record[MAX_IP_INT])
{
	snsd_service *sns;
	snsd_prio *snp;
	snsd_node *snd;

	if(!(sns=snsd_add_service(head, SNSD_DEFAULT_SERVICE, 
					SNSD_DEFAULT_PROTO)) ||
		!(snp=snsd_add_prio(&sns->prio, 
					SNSD_DEFAULT_PRIO))  ||
		!(snd=snsd_add_node(&snp->node, counter, 
					max_records, record)))
		return 0;
	snd->flags|=SNSD_NODE_IP | SNSD_NODE_MAIN_IP;
	snd->weight=SNSD_DEFAULT_WEIGHT;

	return snd;
}


/*\
 * 
 *  *  *  *  Destroyer functions  *  *  *
 *
\*/

void snsd_node_llist_del(snsd_node **head, u_short *counter)
{
	clist_destroy(head, counter);
}

void snsd_prio_llist_del(snsd_prio **head)
{
	snsd_prio *snp=(*head);
	u_short counter;

	list_for(snp)
		snsd_node_llist_del(&snp->node, &counter);
	clist_destroy(head, &counter);
	(*head)=(snsd_prio *)clist_init(&counter);
}

void snsd_service_llist_del(snsd_service **head)
{
	snsd_service *sns=(*head);
	int counter;
	
	list_for(sns)
		snsd_prio_llist_del(&sns->prio);
	clist_destroy(head, &counter);
}

/*
 * snsd_record_del_selected
 *
 * It deletes from the `*head' llist all the snsd records 
 * which are found in the `selected' llist. In other words, if a snsd record
 * present in the `selected' llist is found `*head', it is removed from
 * `*head'.
 * `snsd_counter' is the record counter of `*head'.
 */
void snsd_record_del_selected(snsd_service **head, u_short *snd_counter, 
			snsd_service *selected)
{
	snsd_service *sns;
	snsd_prio *snp, *snp_sel;
	snsd_node *snd, *snd_sel;

	list_for(selected) {
		sns=snsd_find_service(*head, selected->service, 
				selected->proto);
		if(!sns)
			continue;

		snp_sel=selected->prio;
		list_for(snp_sel) {
			if(!(snp=snsd_find_prio(sns->prio, snp_sel->prio)))
				continue;

			snd_sel=snp_sel->node;
			list_for(snd_sel) {
				while((snd=snsd_find_node_by_record(snp->node,
							snd_sel->record))) {
					/* 
					 * there can be multiple nodes with the same
					 * record, delete them all with this
					 * `while'.
					 */

					clist_del(&snp->node, snd_counter, snd);
				}
			}

			if(!snp->node)
				/* if we emptied the snp->node llist, delete
				 * this prio struct too */
				sns->prio=list_del(sns->prio, snp);
		}

		if(!sns->prio)
			/* if we emptied the sns->prio llist, delete
			 * this service struct too */
			*head=list_del((*head), sns);
	}
}


/*\
 *
 *  *  *  *  Pack/Unpack functions  *  *  *
 *
\*/

/*
 * snsd_pack_node
 *
 * It packs the `node' snsd_node struct. The package is written in `pack'.
 * `free_sz' is the number of free bytes of `pack'. If `free_sz' is less than
 * SNSD_NODE_PACK_SZ, -1 is returned.
 * The number of bytes written in `pack' is returned.
 */
int snsd_pack_node(char *pack, size_t free_sz, snsd_node *node)
{
	char *buf=pack;
	
	if(free_sz < SNSD_NODE_PACK_SZ)
		return -1;

	memcpy(buf, node->record, MAX_IP_SZ);
	if(node->flags & SNSD_NODE_IP)
		inet_htonl((u_int *)buf, net_family);
	buf+=MAX_IP_SZ;

	memcpy(buf, &node->flags, sizeof(char));
	buf+=sizeof(char);

	memcpy(buf, &node->weight, sizeof(char));
	buf+=sizeof(char);

	return SNSD_NODE_PACK_SZ;
}

/*
 * snsd_unpack_node
 *
 * It returns the unpacked snsd_node struct.
 * `pack' is the buffer which contains the packed struct.
 * 
 * We are assuming that the total size of the package is >= SNSD_NODE_PACK_SZ.
 */
snsd_node *snsd_unpack_node(char *pack)
{
	snsd_node *snd;
	char *buf;
	
	snd=xzalloc(sizeof(snsd_node));

	buf=pack;
	memcpy(snd->record, buf, MAX_IP_SZ);
	buf+=MAX_IP_SZ;
	
	memcpy(&snd->flags, buf, sizeof(char));
	buf+=sizeof(char);
	
	snd->weight=SNSD_WEIGHT((*((char *)(buf))));
	buf+=sizeof(char);

	if(snd->flags & SNSD_NODE_IP)
		inet_ntohl(snd->record, net_family);
	
	return snd;
}

/*
 * snsd_pack_all_nodes
 *
 * It packs all the snsd_node structs present in the `head' linked list.
 * The pack is written in `pack' which has to have enough space to contain the
 * packed llist. The size of the llist can be calculate using:
 * SNSD_NODE_LLIST_PACK_SZ(head)
 *
 * `pack_sz' is the number of free bytes allocated in `pack'.
 * 
 * The number of bytes written in `pack' is returned.
 * 
 * On error -1 is returned.
 */
int snsd_pack_all_nodes(char *pack, size_t pack_sz, snsd_node *head)
{
	struct snsd_node_llist_hdr *hdr;
	snsd_node *snd=head;
	int sz=0, wsz=0, counter=0;

	hdr=(struct snsd_node_llist_hdr *)pack;
	pack+=sizeof(struct snsd_node_llist_hdr);
	wsz+=sizeof(struct snsd_node_llist_hdr);
	
	list_for(snd) {
		sz=snsd_pack_node(pack, pack_sz-wsz, snd);
		if(sz <= 0)
			return -1;
		
		wsz+=sz; pack+=sz; counter++;
	}
	
	hdr->count=htons(counter);
	return wsz;
}

/*
 * snsd_unpack_all_nodes
 *
 * It unpacks a packed linked list of snsd_nodes, which is pointed by `pack'.
 * The number of unpacked structs is written in `nodes_counter'.
 *
 * `*unpacked_sz' is incremented by the number of unpacked bytes.
 * 
 * The head of the unpacked llist is returned.
 * On error 0 is returned.
 */
snsd_node *snsd_unpack_all_nodes(char *pack, size_t pack_sz, 
					size_t *unpacked_sz, u_short *nodes_counter)
{
	snsd_node *snd_head=0, *snd;
	char *buf=pack;
	int i, sz=0;
	u_short counter;
	
	if((sz+=sizeof(struct snsd_node_llist_hdr)) > pack_sz)
		ERROR_FINISH(snd_head, 0, finish);

	counter=ntohs((*(short *)buf));
	buf+=sizeof(short);

	if(counter > SNSD_MAX_REC_SERV)
		ERROR_FINISH(snd_head, 0, finish);
	
	*nodes_counter=0;
	for(i=0; i<counter; i++) {
		if((sz+=SNSD_NODE_PACK_SZ) > pack_sz)
			ERROR_FINISH(snd_head, 0, finish);
		
		snd=snsd_unpack_node(buf);
		buf+=SNSD_NODE_PACK_SZ;

		clist_add(&snd_head, nodes_counter, snd);
	}

finish:
	(*unpacked_sz)+=sz;
	return snd_head;
}

/*
 * snsd_pack_prio
 *
 * It packs the `prio' snsd_prio struct in the `pack' buffer, which has 
 * `free_sz' bytes allocated.
 * In the packs it includes the `prio'->node llist too.
 *
 * On error -1 is returned, otherwise the size of the package is returned.
 */
int snsd_pack_prio(char *pack, size_t free_sz, snsd_prio *prio)
{
	char *buf=pack;
	int wsz=0, sz=0;

	if(free_sz < SNSD_PRIO_PACK_SZ)
		return -1;
	
	*buf=prio->prio;
	buf+=sizeof(char);
	wsz+=sizeof(char);
	
	sz=snsd_pack_all_nodes(buf, free_sz-wsz, prio->node);
	if(sz <= 0)
		return -1;
	wsz+=sz;
	
	return wsz;
}

/*
 * snsd_unpack_prio
 *
 * It unpacks a packed snsd_prio struct and returns it.
 * `pack' is the package, which is `pack_sz' big.
 *
 * The number of unpacked snsd_node structs is written in `nodes_counter'.
 *
 * `*unpacked_sz' is incremented by the number of unpacked bytes.
 * 
 * On error 0 is returned
 */
snsd_prio *snsd_unpack_prio(char *pack, size_t pack_sz, size_t *unpacked_sz,
				u_short *nodes_counter)
{
	snsd_prio *snp;
	u_short counter=0;

	*nodes_counter=counter;
	snp=xzalloc(sizeof(snsd_prio));
	
	snp->prio=*pack;
	pack+=sizeof(char);
	(*unpacked_sz)+=sizeof(char);

	snp->node=snsd_unpack_all_nodes(pack, pack_sz-sizeof(char), unpacked_sz,
					&counter);
	if(!snp->node || counter > SNSD_MAX_REC_SERV)
		return 0;

	*nodes_counter=counter;
	return snp;
}

/*
 * snsd_pack_all_prios
 *
 * It packs the whole snsd_prio linked list whose head is `head'.
 * `pack' is the buffer where the package will be stored.
 * `pack' is `pack_sz' bytes big.
 * Use SNSD_PRIO_LLIST_PACK_SZ(head) to calculate the pack size.
 *
 * The number of bytes stored in `pack' is returned.
 *
 * On error -1 is returned.
 */
int snsd_pack_all_prios(char *pack, size_t pack_sz, snsd_prio *head)
{
	struct snsd_prio_llist_hdr *hdr;
	snsd_prio *snp=head;
	int sz=0, wsz=0, counter=0;

	hdr=(struct snsd_prio_llist_hdr *)pack;
	pack+=sizeof(struct snsd_prio_llist_hdr);
	wsz+=sizeof(struct snsd_prio_llist_hdr);
	
	list_for(snp) {
		sz=snsd_pack_prio(pack, pack_sz-wsz, snp);
		if(sz <= 0)
			return -1;
		wsz+=sz;
		pack+=sz;
		counter++;
	}
	
	hdr->count=htons(counter);
	return wsz;
}

/*
 * snsd_unpack_all_prios
 *
 * It unpacks the packed snsd_prio llist.
 * The head of the newly allocated llist is returned.
 *
 * The number of unpacked snsd_node structs is written in `nodes_counter'.
 *
 * `*unpacked_sz' is incremented by the number of unpacked bytes.
 *
 * On error 0 is returned.
 */
snsd_prio *snsd_unpack_all_prios(char *pack, size_t pack_sz, 
				 size_t *unpacked_sz, u_short *nodes_counter)
{
	snsd_prio *snp_head=0, *snp;
	char *buf=pack;
	u_short counter=0, ncounter=0, tmp_counter=0;
	int i, sz=0, tmp_sz, usz=0;

	*nodes_counter=ncounter;

	if((sz+=sizeof(struct snsd_prio_llist_hdr)) > pack_sz)
		ERROR_FINISH(snp_head, 0, finish);

	counter=ntohs((*(short *)buf));
	buf+=sizeof(short);
	usz+=sizeof(short);
	(*unpacked_sz)+=sizeof(short);

	if(counter > SNSD_MAX_REC_SERV || counter <= 0)
		ERROR_FINISH(snp_head, 0, finish);
	
	for(i=0; i<counter; i++) {
		if((sz+=SNSD_PRIO_PACK_SZ) > pack_sz)
			ERROR_FINISH(snp_head, 0, finish);

		tmp_sz=(*unpacked_sz);
		snp=snsd_unpack_prio(buf, pack_sz-usz, unpacked_sz, 
				     &tmp_counter);
		ncounter+=tmp_counter;
		if(!snp || ncounter > SNSD_MAX_REC_SERV)
			ERROR_FINISH(snp_head, 0, finish);

		/* tmp_sz=how much we've read so far from `buf' */
		tmp_sz=(*unpacked_sz)-tmp_sz;	
		buf+=tmp_sz;
		usz+=tmp_sz;

		clist_add(&snp_head, &tmp_counter, snp);
	}

finish:
	*nodes_counter=ncounter;
	return snp_head;
}

/*
 * snsd_pack_service
 *
 * It packs the `service' snsd_service struct in the `pack' buffer, which has 
 * `free_sz' bytes allocated.
 * In the packs it includes the `service'->prio llist too.
 *
 * On error -1 is returned, otherwise the size of the package is returned.
 */
int snsd_pack_service(char *pack, size_t free_sz, snsd_service *service)
{
	char *buf=pack;
	int wsz=0, sz=0;

	if(!service || free_sz < SNSD_SERVICE_PACK_SZ)
		return -1;
	
	(*(u_short *)(buf))=htons(service->service);
	buf+=sizeof(short);
	
	(*(u_char *)(buf))=service->proto;
	buf+=sizeof(u_char);
	
	wsz+=SNSD_SERVICE_PACK_SZ;
	
	sz=snsd_pack_all_prios(buf, free_sz-wsz, service->prio);
	if(sz <= 0)
		return -1;
	wsz+=sz;
	
	return wsz;
}

/*
 * snsd_unpack_service
 *
 * It unpacks a packed snsd_service struct and returns it.
 * `pack' is the package, which is `pack_sz' big.
 *
 * The number of unpacked snsd_node structs is written in `nodes_counter'.
 *
 * `*unpacked_sz' is incremented by the number of unpacked bytes.
 * 
 * On error 0 is returned
 */
snsd_service *snsd_unpack_service(char *pack, size_t pack_sz, 
				  size_t *unpacked_sz, u_short *nodes_counter)
{
	snsd_service *sns;
	u_short tmp_counter=0, counter=0;

	*nodes_counter=counter;
	sns=xzalloc(sizeof(snsd_service));
	
	sns->service=ntohs((*(u_short *)pack));
	pack+=sizeof(short);
	
	sns->proto=(*(u_char *)pack);
	pack+=sizeof(u_char);
	
	(*unpacked_sz)+=SNSD_SERVICE_PACK_SZ;
	pack_sz-=SNSD_SERVICE_PACK_SZ;

	sns->prio=snsd_unpack_all_prios(pack, pack_sz, unpacked_sz, 
					&tmp_counter);
	counter+=tmp_counter;
	if(!sns->prio || counter > SNSD_MAX_REC_SERV)
		return 0;

	*nodes_counter=counter;
	return sns;
}

/*
 * snsd_pack_all_services
 *
 * It packs the whole snsd_service linked list whose head is `head'.
 * `pack' is the buffer where the package will be stored, it must have already
 * `pack_sz' bytes allocated.
 * Use SNSD_SERVICE_LLIST_PACK_SZ(head) to calculate the pack size.
 *
 * The number of bytes stored in `pack' is returned.
 *
 * On error -1 is returned.
 */
int snsd_pack_all_services(char *pack, size_t pack_sz, snsd_service *head)
{
	struct snsd_service_llist_hdr *hdr;
	snsd_service *sns=head;
	int sz=0, wsz=0, counter=0;

	hdr=(struct snsd_service_llist_hdr *)pack;
	pack+=sizeof(struct snsd_service_llist_hdr);
	wsz+=sizeof(struct snsd_service_llist_hdr);
	
	list_for(sns) {
		sz=snsd_pack_service(pack, pack_sz-wsz, sns);
		if(sz <= 0)
			return -1;
		
		wsz+=sz; pack+=sz; counter++;
	}
	
	hdr->count=htons(counter);
	return wsz;
}

/*
 * snsd_unpack_all_service
 *
 * It unpacks the packed snsd_service llist.
 * The head of the newly allocated llist is returned.
 *
 * The number of unpacked snsd_node structs is written in `nodes_counter'.
 *
 * `*unpacked_sz' is incremented by the number of unpacked bytes.
 *
 * On error 0 is returned.
 */
snsd_service *snsd_unpack_all_service(char *pack, size_t pack_sz, 
				        size_t *unpacked_sz, u_short *nodes_counter)
{
	snsd_service *sns_head=0, *sns=0;
	char *buf=pack;
	u_short counter=0, ncounter=0, tmp_counter=0;
	int i, sz=0, tmp_sz, usz=0;
	
	if(nodes_counter)
		*nodes_counter=ncounter;
	
	if((sz+=sizeof(struct snsd_service_llist_hdr)) > pack_sz)
		ERROR_FINISH(sns_head, 0, finish);

	counter=ntohs((*(short *)buf));
	buf+=sizeof(short);
	usz+=sizeof(short);
	(*unpacked_sz)+=sizeof(short);


	if(counter > SNSD_MAX_RECORDS || counter <= 0)
		ERROR_FINISH(sns_head, 0, finish);
	
	for(i=0; i<counter; i++) {
		if((sz+=SNSD_SERVICE_PACK_SZ) > pack_sz)
			ERROR_FINISH(sns_head, 0, finish);

		tmp_sz=(*unpacked_sz);
		sns=snsd_unpack_service(buf, pack_sz-usz, unpacked_sz, 
					&tmp_counter);
		ncounter+=tmp_counter;
		if(!sns || ncounter > SNSD_MAX_RECORDS)
			ERROR_FINISH(sns_head, 0, finish);

		/* tmp_sz=how much we've read from `buf' */
		tmp_sz=(*unpacked_sz)-tmp_sz;	
		buf+=tmp_sz;
		usz+=tmp_sz;

		clist_add(&sns_head, &tmp_counter, sns);
	}

finish:
	if(nodes_counter)
		*nodes_counter=ncounter;
	return sns_head;
}

/*\
 *
 *   *  *  *  Misc functions  *  *  *
 *   
\*/

int snsd_count_nodes(snsd_node *head)
{
	return list_count(head);
}

int snsd_count_prio_nodes(snsd_prio *head)
{
	int count=0;
	
	list_for(head)
		count+=snsd_count_nodes(head->node);
	return count;
}

int snsd_count_service_nodes(snsd_service *head)
{
	int count=0;
	
	list_for(head)
		count+=snsd_count_prio_nodes(head->prio);
	return count;
}

/*
 * snsd_choose_wrand
 *
 * It returns a snsd_node of the `head' llist. The snsd_node is chosen
 * randomly. The weight of a node is proportional to its probability of being
 * picked.
 * On error (no nodes?) 0 is returned.
 */
snsd_node *snsd_choose_wrand(snsd_node *head)
{
	snsd_node *snd=head;
	int tot_w=0, r=0, nmemb=0;

	nmemb=list_count(snd);
	list_for(snd)
		tot_w+=snd->weight;

	if(!tot_w)
		return list_pos(snd, rand_range(0, nmemb-1));
		
	r=rand_range(1, tot_w);

	tot_w=0; snd=head;
	list_for(snd) {
		if(r > tot_w && (r <= tot_w+snd->weight))
			return snd;
		tot_w+=snd->weight;
	}
	
	return 0;
}

/*
 * snsd_highest_prio
 *
 * It returns the snsd_prio struct which has the highest `prio' value.
 */
snsd_prio *snsd_highest_prio(snsd_prio *head)
{
	snsd_prio *highest=head;

	list_for(head)
		if(head->prio > highest->prio)
			highest=head;

	return highest;
}

/*
 * snsd_find_mainip
 *
 * It searches through the whole `sns' llist a snsd_node which has the
 * SNSD_NODE_MAIN_IP flag set.
 * 
 * If it is found, it returns a pointer to it, otherwise 0 it returned.
 */
snsd_node *snsd_find_mainip(snsd_service *sns)
{
	snsd_prio *snp;
	snsd_node *snd;
	
	list_for(sns) {
		snp=sns->prio;
		list_for(snp) {
			snd=snp->node;
			list_for(snd)
				if(snd->flags & SNSD_NODE_MAIN_IP)
					return snd;
		}
	}

	return 0;
}

/*
 * snsd_unset_all_flags
 *
 * It unset the given `flag' in all the snsd records of the `sns' llist.
 */
void snsd_unset_all_flags(snsd_service *sns, u_char flag)
{
	snsd_prio *snp;
	snsd_node *snd;
	
	list_for(sns) {
		snp=sns->prio;
		list_for(snp) {
			snd=snp->node;
			list_for(snd)
				snd->flags&=~flag;
		}
	}

	return;
}


/*\
 *
 *  *  *  *   Linked list copy functions   *  *  *
 *
\*/


/*
 * snsd_node_llist_copy
 * 
 * It duplicates an entire snsd_node llist in a new mallocated space.
 * The other sub-llist are duplicated too.
 * The head of the new llist is returned.
 */
snsd_node *snsd_node_llist_copy(snsd_node *snd)
{
	snsd_node *new_snd=0;

	snd=new_snd=list_copy_all(snd);
	list_for(snd)
		if(snd->pubkey)
			snd->pubkey=RSAPublicKey_dup(snd->pubkey);

	return new_snd;
}

/*
 * snsd_prio_llist_copy
 * 
 * It duplicates an entire snsd_prio llist in a new mallocated space.
 * The other sub-llist are duplicated too.
 * The head of the new llist is returned.
 */
snsd_prio *snsd_prio_llist_copy(snsd_prio *snp)
{
	snsd_prio *new_snp=0;
	
	snp=new_snp=list_copy_all(snp);
	list_for(snp)
		snp->node=snsd_node_llist_copy(snp->node);
	
	return new_snp;
}

int is_equal_to_serv_proto(snsd_service *sns, u_short service, u_char proto)
{
	return sns->service == service && 
		(sns->proto == proto || sns->service == SNSD_DEFAULT_SERVICE);
}

/*
 * snsd_service_llist_copy
 *
 * If `service' is equal to -1, it duplicates an entire snsd_service llist 
 * in a new mallocated space, otherwise it duplicates only the snsd_service
 * structures which have the same service and proto values of `service' and
 * `proto'.
 * The other sub-llist are duplicated too.
 *
 * The head of the new llist is returned.
 * If nothing has been duplicated, 0 is returned.
 */
snsd_service *snsd_service_llist_copy(snsd_service *sns, int service, 
					u_char proto)
{
	snsd_service *new_sns=0;
	u_short	short_service=(u_short)service;
	
	if(!sns)
		return 0;
	
	if(service == -1)
		sns=new_sns=list_copy_all(sns);
	else
		sns=new_sns=list_copy_some(sns, is_equal_to_serv_proto, 
					   short_service, proto);
	list_for(sns)
		sns->prio=snsd_prio_llist_copy(sns->prio);

	return new_sns;
}


/*\
 *
 *  *  *  *   Linked list merging functions   *  *  *
 *
 * For an explanation of these things, 
 * read snsd_service_llist_merge()
\*/

void snsd_merge_node(snsd_node **head, u_short *snsd_counter, snsd_node *new)
{
	snsd_node *snd;

	if(!(snd=snsd_find_node_by_record(*head, new->record))) {
		clist_add(head, snsd_counter, new);
		return;
	}

	list_copy(snd, new);
}

void snsd_node_llist_merge(snsd_node **dst, u_short *snsd_counter, snsd_node *src)
{
	list_for(src)
		snsd_merge_node(dst, snsd_counter, src);
}

void snsd_merge_prio(snsd_prio **head, u_short *snsd_counter, snsd_prio *new)
{
	snsd_prio *snp;

	if(!(snp=snsd_find_prio(*head, new->prio))) {
		*head=list_add(*head, new);
		return;
	}

	snsd_node_llist_merge(&snp->node, snsd_counter, new->node);
}

void snsd_prio_llist_merge(snsd_prio **dst, u_short *snsd_counter, snsd_prio *src)
{
	list_for(src)
		snsd_merge_prio(dst, snsd_counter, src);
}

void snsd_merge_service(snsd_service **head, u_short *snsd_counter, 
			snsd_service *new)
{
	snsd_service *sns;

	if(!(sns=snsd_find_service(*head, new->service, new->proto))) {
		/* `new' doesn't exists in `head'. Add it. */
		*head=list_add(*head, new);
		return;
	}

	snsd_prio_llist_merge(&sns->prio, snsd_counter, new->prio);
}

/*
 * snsd_service_llist_merge
 *
 * It merges the `*dst' and `src' linked lists into a unique list, which
 * contains all the common elements between `*dst' and `src'.
 * In other words it is the result of the AND of the `*dst' and `src' sets.
 *
 * The result is written in the `*dst' llist itself and no memory is
 * allocated, thus if you don't want to modify `*dst', you have to do a copy
 * first using snsd_service_llist_copy().
 */
void snsd_service_llist_merge(snsd_service **dst, u_short *snsd_counter,
			      snsd_service *src)
{
	list_for(src)
		snsd_merge_service(dst, snsd_counter, src);
}



/*\
 *
 *  *  *  *   Dump functions   *  *  *
 *          (that don't stink)
\*/

void snsd_dump_node(snsd_node *snd, int single)
{
	list_for(snd) {
		printf("\t\t{\n "
				"\t\trecord = %x:%x:%x:%x\n "
				"\t\tpubkey = %p\n "
				"\t\tflags = %d\n "
				"\t\tweight = %d\n",
			snd->record[0], snd->record[1], 
			snd->record[2], snd->record[3], 
			(char *)snd->pubkey, (int)snd->flags, 
			(int)snd->weight);
		if(single)
			goto finish;
	}
finish:
	printf("\t\t}\n");
	return;
}

void snsd_dump_prio(snsd_prio *snp, int single, int level)
{
	list_for(snp) {
		printf("\t{\n \tprio = %d\n", snp->prio);
		snsd_dump_node(snp->node, !(level > 2));
		printf("\t}\n");
		if(single)
			goto finish;
	}
finish:
	printf("\t}\n");
	return;
}

void snsd_dump_service(snsd_service *sns, int single, int level)
{
	list_for(sns) {
		printf("{\n service = %d\n proto = %d\n",
				sns->service, sns->proto);
		snsd_dump_prio(sns->prio, !(level > 1), level);
		printf("}\n");
		if(single)
			goto finish;
	}
finish:
	printf("}\n");
	return;
}
