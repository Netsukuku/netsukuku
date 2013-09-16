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

#ifndef REQUEST_H
#define REQUEST_H

#include "misc.h"

#define REQUEST_TIMEOUT		300	/* The timeout in seconds for all the 
					   requests */
#ifdef DEBUG
#undef REQUEST_TIMEOUT
#define REQUEST_TIMEOUT		20
#endif

/*
 * In this enum there are all the requests/replies op used by netsukuku 
 */
enum pkt_op
{
	ECHO_ME,			/*The node requests to be echoed by the dst_node*/
	ECHO_REPLY,			/*Yep, this isn't really a reply*/
	GET_FREE_NODES,			/*it means: <<Get the list of free ips in your gnode, plz>>*/
	GET_QSPN_ROUND,			/*<<Yo, Gimme the qspn ids and qspn times>>*/
	
	GET_INTERNET_GWS,		/*Get Internet Gateways */
	SET_FOREIGN_ROUTE,		/* Set the route in the foreign	groupnode */
	DEL_FOREIGN_ROUTE,
	NEW_BACKROUTE,			/*Tells the dst_node to use a different route to reply*/
	DELAYED_BROADCAST,		/*Broadcast packet to be spread only in the dst groupnode*/
	SPLIT_ROUTE,			/*This pkt advices the src_node to split the socket in two route*/
	SET_NO_IDENTITY,		/*Pkt that specify to the last node in the route to change 
					  the src ip of the future incoming pkts*/

	QSPN_CLOSE,			/*The qspn_pkt used to trace the entire g_node*/
	QSPN_OPEN,			/*The qspn_pkt sent by the extreme nodes*/
	QSPN_RFR,			/*RequestForRoute: This is used to get additional routes*/
	GET_DNODEBLOCK ,		/* Not used. */
	GET_DNODEIP,			/* Not used. */
	TRACER_PKT,			/*A tracer pkt. This pkt is used mainly to send only a tracer pkt.
					  Normally a bcast pkt is marked with the BCAST_TRACER_PKT flag.*/
	TRACER_PKT_CONNECT,		/*This is the tracer_pkt used to connect to the dst_node.
					  In the first entry of the tcr_pkt there's the src node, in the
					  second the dst_node, the remaining are as usual*/

	DEL_SNODE,			/* Not used. */
	DEL_GNODE,			/* Not used. */

	GET_INT_MAP,
	GET_EXT_MAP,
	GET_BNODE_MAP,
	
	ANDNA_REGISTER_HNAME,
	ANDNA_CHECK_COUNTER,		/* Check request for the counter node */
	ANDNA_RESOLVE_HNAME,
	ANDNA_RESOLVE_IP,
	ANDNA_RESOLVE_MX,
	ANDNA_GET_ANDNA_CACHE,
	ANDNA_GET_SINGLE_ACACHE,
	ANDNA_SPREAD_SACACHE,		/* Spread single andna_cache */
	ANDNA_GET_COUNT_CACHE,

	/*  *  *  Replies  *  *  */
	PUT_FREE_NODES,			/*it means: "Here it is the list of free ips in your gnode, cya"*/
	PUT_QSPN_ROUND,
	PUT_INTERNET_GWS,
	PUT_DNODEIP,
	EMPTY_REPLY_SLOT,
	EMPTY_REPLY_SLOT1,
	PUT_INT_MAP,
	PUT_EXT_MAP,
	PUT_BNODE_MAP,
	ANDNA_RESOLVE_REPLY,
	ANDNA_REV_RESOLVE_REPLY,
	ANDNA_MX_RESOLVE_REPLY,
	ANDNA_PUT_COUNT_CACHE,
	ANDNA_PUT_ANDNA_CACHE,

	/*Acks*/
	ACK_AFFERMATIVE,		/*Ack affermative. Everything is fine.*/
	ACK_NEGATIVE			/*The request is rejected. The error is in the pkt's body.*/
};

/*
 * WARNING* Keep it up to date!! *WARNING *
 */
#define TOTAL_OPS		(ACK_NEGATIVE+1)
#define TOTAL_REQUESTS          (ANDNA_GET_COUNT_CACHE+1)
#define TOTAL_REPLIES		(TOTAL_OPS-TOTAL_REQUESTS)

enum errors
{
	/*Request errors*/
	E_INVALID_REQUEST,
	E_ACCEPT_TBL_FULL,
	E_REQUEST_TBL_FULL,
	E_QGROUP_FULL,
	E_NTK_FULL,
	E_INVALID_SIGNATURE,
	E_CANNOT_FORWARD,
	
	E_ANDNA_WRONG_HASH_GNODE,
	E_ANDNA_QUEUE_FULL,
	E_ANDNA_UPDATE_TOO_EARLY,
	E_ANDNA_TOO_MANY_HNAME,
	E_ANDNA_HUPDATE_MISMATCH,
	E_ANDNA_NO_HNAME,
	E_ANDNA_CHECK_COUNTER,
	
	E_TOO_MANY_CONN
};
#define TOTAL_ERRORS		(E_TOO_MANY_CONN+1)

/* 
 * Request_table: It prevents requests flood and it is used in each connection.
 * Each element of the "rq" array corresponds to a request; it (the element)
 * keeps the number of requests served. If this number is equal
 * to [REQUEST]_MAXRQ, the maximum of simultaneous requests is reached.
 * 
 * Each element in rq_wait corresponds to a single request so it is formed by:
 * { [REQUEST 0]_MAXRQ elements | [REQUEST 1]_MAXRQ elements | ... };
 * rq_wait_idx keeps track of this but it must be initialized once with
 * rq_wait_idx_init().
 * Each element of rq_wait keeps the time when that request arrived. 
 * When the current time is >= [REQUEST]_WAIT+rq_wait, a new request is 
 * available and the corresponding request counter in "rq" is decremented. 
 */

#define TOTAL_MAXRQ	31
struct request_tbl
{
	u_char 	rq[TOTAL_REQUESTS];
	time_t	rq_wait[TOTAL_MAXRQ];
};
typedef struct request_tbl rq_tbl;

int rq_wait_idx[TOTAL_REQUESTS];

int update_rq_tbl_mutex;

/* 
 * Each bit of this array corresponds to a request or a reply. If the bit is 
 * set, the request or reply will be dropped, otherwise it will be executed by
 * pkts.c/pkt_exec().
 */
char filtered_op[TOTAL_OPS>>3];
#define OP_FILTER_DROP		1
#define OP_FILTER_ALLOW		0
#define op_filter_set(op)	SET_BIT(filtered_op, (op))
#define op_filter_clr(op)	CLR_BIT(filtered_op, (op))
#define op_filter_test(op)	TEST_BIT(filtered_op, (op))
#define op_filter_reset(bit)	memset(filtered_op, (bit), sizeof(filtered_op))


/* 
 * Functions declaration starts here
 */
void rq_wait_idx_init(int *rq_wait_idx);
const u_char *rq_strerror(int err);
#define re_strerror(err) (rq_strerror((err)))
const u_char *re_to_str(u_char re);
const u_char *rq_to_str(u_char rq);
int op_verify(u_char );
int rq_verify(u_char );
int re_verify(u_char );
void update_rq_tbl(rq_tbl *);
int is_rq_full(u_char , rq_tbl *);
int find_free_rq_wait(u_char , rq_tbl *);
int add_rq(u_char , rq_tbl *);

void op_filter_reset_re(int bit);
void op_filter_reset_rq(int bit);

#endif /*REQUEST_H*/
