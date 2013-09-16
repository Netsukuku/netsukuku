/* This file is part of Netsukuku system
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

#ifndef PKTS_H
#define PKTS_H

#include "if.h"
#include "request.h"
#include "llist.c"

#define NETSUKUKU_ID		"ntk"
#define MAXMSGSZ		65536

/*\
 *
 * Pkt's op definitions
 * (The requests and replies are in request.h)
 *
\*/

/* Pkt.sk_type */
#define SKT_TCP 		1
#define SKT_UDP			2
#define SKT_BCAST		3

/* 
 * Pkt.pkt_flags flags 
 */
#define PKT_BIND_DEV		1	/* Bind the pkt.sk socket to pkt.dev */
#define PKT_RECV_TIMEOUT	(1<<1)
#define PKT_SEND_TIMEOUT	(1<<2)
#define PKT_SET_LOWDELAY	(1<<3)
#define PKT_COMPRESSED		(1<<4)	/* If set the packet will be Z 
					   compressed before being sent */
#define PKT_KEEPALIVE		(1<<5)  /* Let the pkt.sk socket be alive */
#define PKT_NONBLOCK		(1<<6)	/* Socket must not block */

/* 
 * Pkt.hdr flags 
 */
#define SEND_ACK		1
#define BCAST_PKT		(1<<1)	/* In this pkt there is encapsulated a 
					 * broadcast/flood pkt. Woa */
#define HOOK_PKT		(1<<2)  /* All the pkts sent while hooking have
					 * this flag set      */
#define ASYNC_REPLY		(1<<3)	/* Tells the receiver to reply with a new 
					   connection. The reply pkt will be
					   handled by the pkt_queue. */
#define ASYNC_REPLIED		(1<<4)
#define LOOPBACK_PKT		(1<<5)  /* This is a packet destinated to me */
#define RESTRICTED_PKT		(1<<6)	/* Packet sent from a node in restricted 
					   mode */
#define COMPRESSED_PKT		(1<<7)  /* The whole packet is Z compressed */


/*
 * Broacast ptk's flags
 */
#define BCAST_TRACER_PKT	1	/*When a bcast is marked with this, it 
					  acts as a tracer_pkt ;)*/
#define BCAST_TRACER_BBLOCK	(1<<1)  /*When set, the tracer pkt carries also
					  bnodes blocks.*/
#define BCAST_TRACER_STARTERS	(1<<2)  /*Tracer pkt bound to the qspn starter 
					  continual group*/
#define QSPN_BNODE_CLOSED	(1<<3)	/*The last bnode, who forwarded this 
					  qspn pkt has all its links closed.*/
#define QSPN_BNODE_OPENED	(1<<4)

/* General defines */
#define PKT_MAX_MSG_SZ		1048576	/* bytes */
#define PKT_COMPRESS_LEVEL	Z_DEFAULT_COMPRESSION
#define PKT_COMPRESS_THRESHOLD	1024	/* If the flag PKT_COMPRESSED is set 
					   and hdr.sz > PKT_COMPRESS_THRESHOLD,
					   then compress the packet */

/*
 * pkt_hdr: the pkt_hdr is always put at the very beginning of any netsukuku
 * packets
 */
typedef struct
{
	char		ntk_id[3];
	int 		id;
	u_char		flags; 
	u_char 		op;
	size_t 		sz;		/* The size of the message */
	size_t		uncompress_sz;	/* The size of the decompressed packet. */
}_PACKED_  pkt_hdr;
INT_INFO pkt_hdr_iinfo = { 3, 
			   { INT_TYPE_32BIT, INT_TYPE_32BIT, INT_TYPE_32BIT },
			   { sizeof(char)*3, sizeof(char)*5+sizeof(int), 
			     sizeof(char)*5+sizeof(int)+sizeof(size_t) },
			   { 1, 1, 1 }
			 };
#define PACKET_SZ(sz) (sizeof(pkt_hdr)+(sz))

/*
 * PACKET
 *
 * this struct is used only to represent internally a packet, which
 * will be sent or received.
 */
typedef struct
{
	/* General informations of the packet */
	
	inet_prefix 	from;		/* The sender ip of this packet */
	inet_prefix 	to;		/* Where to send this packet */

	interface	*dev;		/* Device used to send/receive the 
					   packet. `sk' will be bound to it
					   if `dev' is not null and if the 
					   PKT_BIND_DEV flag is set in
					   `pkt_flags'. `dev' is a pointer
					   to a struct contained in the 
					   me.cur_ifs array. */
	
	int		family;
	int 		sk;
	char 		sk_type;
	u_short 	port;

	u_char		pkt_flags;	/*Flags for this PACKET*/
	int 		flags;		/*Flags used by send/recv*/

	u_int		timeout;	/*After `timeout' seconds give up the
					  send/recv of the packet. 
					  The PKT_[RECV/SEND]_TIMEOUT flags are
					  used to determine its scope (send, 
					  recv or both).*/

	/* Body of the packet */
	pkt_hdr 	hdr;
	char 		*msg;
} PACKET;
	
/*Broadcast packet*/
typedef struct
{
	u_char		g_node;		/*The gnode the brdcast_pkt is restricted to*/
	u_char 		level;		/*The level of the g_node*/
	u_char	 	gttl;		/*Gnode ttl: How many gnodes the packet
					  can traverse*/
	u_char	 	sub_id;		/*The sub_id is the node who sent the pkt,
					  but is only used by the qspn_open*/
	size_t 		sz;		/*Sizeof(the pkt)*/
	char 		flags;		/*Various flags*/
}_PACKED_ brdcast_hdr;

INT_INFO brdcast_hdr_iinfo = { 1, { INT_TYPE_32BIT }, { sizeof(char)*4 }, { 1 } };
#define BRDCAST_SZ(pkt_sz) 	(sizeof(brdcast_hdr)+(pkt_sz))
#define BRDCAST_HDR_PTR(msg)	((brdcast_hdr *)(msg))


/* 
 * In this stable, each op (request or reply) is associated with a
 * `pkt_exec_func', which pkt_exec() will use to handle the incoming packets of
 * the same op.
 * Each op is also associated with its specific socket type (udp, tcp, bcast)
 * with `sk_type', and the `port' where the pkt will be sent or received.
 * Each element in the table is equivalent to a request or reply, ie the
 * function to handle the x request is at pkt_op_table[x].exec_func;
 */
struct pkt_op_table {
	char 		sk_type;
	u_short 	port;
	void 		*exec_func;
} pkt_op_tbl[TOTAL_OPS];

/* pkt_queue's flags */
#define PKT_Q_MTX_LOCKED	1		/* We are waiting the reply */
#define PKT_Q_PKT_RECEIVED	(1<<1)		/* The reply was received */
#define PKT_Q_TIMEOUT		(1<<2)		/* None replied ._, */
#define PKT_Q_CHECK_FROM	(1<<3)		/* Check the from ip while
						   receiving the async pkt */

/*
 * The pkt_queue is used when a reply will be received with a completely new 
 * connection. This is how it works:
 * The pkt.hdr.flags is ORed with ASYNC_REPLY, a new struct is added in the
 * pkt_q linked list, pkt_q->pkt.hdr.id is set to the id of the outgoing pkt
 * and pkt_q->pkt.hdr.op is set to the waited reply op.
 * The function x() it's started as a new thread and the request is sent; to 
 * receive the reply, x() locks twice `mtx'. The thread is now freezed.
 * The reply is received by pkt_exec() which passes the pkt to the function
 * y(). y() searches in the pkt_q a struct which has the same pkt.hdr.id of
 * the received pkt. The reply pkt is copied in the found struct and `mtx' is
 * unlocked. x() can now continue to read the reply and unlocks `mtx'.
 * Note that the reply pkt must have the ASYNC_REPLIED flag set in pkt.hdr.flags.
 */
struct pkt_queue{
	LLIST_HDR	(struct pkt_queue);

	PACKET 		pkt;
	pthread_mutex_t mtx;

	char 		flags;
};
typedef  struct pkt_queue pkt_queue;

pkt_queue *pkt_q;
int pkt_q_counter;

/*Functions' declarations*/
void pkts_init(interface *ifs, int ifs_n, int queue_init);
	
void pkt_addfrom(PACKET *pkt, inet_prefix *from);
void pkt_addto(PACKET *pkt, inet_prefix *to);
void pkt_add_dev(PACKET *pkt, interface *dev, int bind_the_socket);
void pkt_addsk(PACKET *pkt, int family, int sk, int sk_type);
void pkt_addport(PACKET *pkt, u_short port);
void pkt_addflags(PACKET *pkt, int flags);
void pkt_addtimeout(PACKET *pkt, u_int timeout, int recv, int send);
void pkt_addcompress(PACKET *pkt);
void pkt_addlowdelay(PACKET *pkt);
void pkt_addnonblock(PACKET *pkt);
void pkt_addhdr(PACKET *pkt, pkt_hdr *hdr);
void pkt_addmsg(PACKET *pkt, char *msg);
void pkt_copy(PACKET *dst, PACKET *src);
void pkt_clear(PACKET *pkt);

void pkt_free(PACKET *pkt, int close_socket);
char *pkt_pack(PACKET *pkt);

int pkt_verify_hdr(PACKET pkt);
ssize_t pkt_send(PACKET *pkt);
ssize_t pkt_recv(PACKET *pkt);
int pkt_tcp_connect(inet_prefix *host, short port, interface *dev);

void pkt_fill_hdr(pkt_hdr *hdr, u_char flags, int id, u_char op, size_t sz);

#define SEND_RQ_ERR		-1
#define SEND_RQ_ERR_RQ		-2
#define SEND_RQ_ERR_RE		-3
#define SEND_RQ_ERR_PORT	-4
#define SEND_RQ_ERR_TO		-5
#define SEND_RQ_ERR_CONNECT	-6
#define SEND_RQ_ERR_SEND	-7
#define SEND_RQ_ERR_RECV	-8
#define SEND_RQ_ERR_RECVOP	-9
#define SEND_RQ_ERR_RECVID	-10
#define SEND_RQ_ERR_REPLY	-11
int send_rq(PACKET *pkt, int pkt_flags, u_char rq, int rq_id, u_char re, 
		int check_ack, PACKET *rpkt);

int forward_pkt(PACKET rpkt, inet_prefix to);
int pkt_err(PACKET pkt, u_char err, int free_pkt);

void add_pkt_op(u_char op, char sk_type, u_short port, int (*exec_f)(PACKET pkt));
int pkt_exec(PACKET pkt, int acpt_idx);

void pkt_queue_init(void);
void pkt_queue_close(void);
int pkt_q_wait_recv(int id, inet_prefix *from, PACKET *rpkt, pkt_queue **ret_pq);
int pkt_q_add_pkt(PACKET pkt);
void pkt_q_del(pkt_queue *pq, int close_socket);

#endif /*PKTS_H*/
