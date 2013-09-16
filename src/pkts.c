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
 * pkts.c:
 * General functions to forge, pack, send, receive, forward and unpack
 * packets. 
 */

#include "includes.h"
#include <zlib.h>

#include "inet.h"
#include "request.h"
#include "endianness.h"
#include "pkts.h"
#include "accept.h"
#include "common.h"

interface cur_ifs[MAX_INTERFACES];
int cur_ifs_n;

/*
 * pkts_init:
 * Initialize the vital organs of the pkts.c's functions.
 * `ifs' is the array which keeps all the the `ifs_n'# network 
 * interface that will be used.
 * If `queue_init' is not 0, the pkt_queue is initialized too.
 */
void pkts_init(interface *ifs, int ifs_n, int queue_init)
{
	cur_ifs_n = ifs_n > MAX_INTERFACES ? ifs_n : MAX_INTERFACES;
	memcpy(cur_ifs, ifs, sizeof(interface)*cur_ifs_n);
	
	pkt_q_counter=0;
	if(queue_init)
		pkt_queue_init();
	
	op_filter_reset(OP_FILTER_ALLOW);
}

/* 
 * * * Handy functions to build the PACKET * * 
 */
void pkt_addfrom(PACKET *pkt, inet_prefix *from)
{
	if(!from)
		setzero(&pkt->from, sizeof(inet_prefix));
	else
		inet_copy(&pkt->from, from);
}

void pkt_addto(PACKET *pkt, inet_prefix *to)
{
	if(!to)
		setzero(&pkt->to, sizeof(inet_prefix));
	else
		inet_copy(&pkt->to, to);
}

void pkt_add_dev(PACKET *pkt, interface *dev, int bind_the_socket)
{
	pkt->dev=dev;
	if(dev && bind_the_socket)
		pkt->pkt_flags|=PKT_BIND_DEV;
}

void pkt_addsk(PACKET *pkt, int family, int sk, int sk_type)
{
	pkt->family=family;
	pkt->sk=sk;
	pkt->sk_type=sk_type;
}

void pkt_addport(PACKET *pkt, u_short port)
{
	pkt->port=port;
}

void pkt_addtimeout(PACKET *pkt, u_int timeout, int recv, int send)
{
	if((pkt->timeout=timeout)) {
		if(recv)
			pkt->pkt_flags|=PKT_RECV_TIMEOUT;
		if(send)
			pkt->pkt_flags|=PKT_SEND_TIMEOUT;
	}
}

void pkt_addcompress(PACKET *pkt)
{
	pkt->pkt_flags|=PKT_COMPRESSED;
}

void pkt_addlowdelay(PACKET *pkt)
{
	pkt->pkt_flags|=PKT_SET_LOWDELAY;
}

void pkt_addnonblock(PACKET *pkt)
{
	pkt->pkt_flags|=PKT_NONBLOCK;
}

void pkt_addhdr(PACKET *pkt, pkt_hdr *hdr)
{
	if(!hdr)
		setzero(&pkt->hdr, sizeof(pkt_hdr));
	else
		memcpy(&pkt->hdr, hdr, sizeof(pkt_hdr));
}

void pkt_addmsg(PACKET *pkt, char *msg)
{
	pkt->msg=msg;
}
/* * * End of handy stupid functions (^_+) * * */


/* 
 * pkt_clear: blanks the entire PACKET struct, leaving intact only `hdr' 
 * and `msg' 
 */
void pkt_clear(PACKET *pkt)
{
	pkt_addfrom(pkt, 0);
	pkt_addto(pkt, 0);
	pkt_addsk(pkt, 0,0,0);
	pkt_addport(pkt, 0);
	pkt->flags=pkt->pkt_flags=0;
}

/* 
 * pkt_copy: Copy the `src' PACKET in `dst'. It xmallocs also a new msg block in
 * `dst->msg' of `src->hdr.sz' size and copies in it `src->msg'
 */
void pkt_copy(PACKET *dst, PACKET *src)
{
	memcpy(dst, src, sizeof(PACKET));
	
	if(src->hdr.sz && src->msg) {
		dst->msg=xmalloc(src->hdr.sz);
		memcpy(dst->msg, src->msg, src->hdr.sz);
	}
}


void pkt_free(PACKET *pkt, int close_socket)
{
	if(close_socket && pkt->sk)
		inet_close(&pkt->sk);
	
	if(pkt->msg) {
		xfree(pkt->msg);
		pkt->msg=0;
	}
}

/*
 * pkt_compress
 *
 * It compresses `pkt'->msg and stores the result in `dst'.
 * `dst_msg' must have at least `newhdr'->sz bytes big.
 * It is also assumed that `pkt'->msg is not 0.
 *
 * The size of the compressed msg is stored in `newhdr'->sz, while
 * the size of the orignal one is written in `newhdr'->uncompress_sz.
 * If the compression doesn't fail, `newhdr'->sz will be always less than
 * `newhdr'->uncompress_sz.
 *
 * Nothing in `pkt' is modified.
 *
 * If the packet was compressed  0 is returned and the COMPRESSED_PKT flag is
 * set to `newhdr'->.flags.
 * On error a negative value is returned.
 */
int pkt_compress(PACKET *pkt, pkt_hdr *newhdr, char *dst_msg)
{
	uLongf bound_sz;
	int ret;

	bound_sz=compressBound(pkt->hdr.sz);

	unsigned char dst[bound_sz];

	ret=compress2(dst, &bound_sz, (u_char*)pkt->msg, pkt->hdr.sz, 
			PKT_COMPRESS_LEVEL);
	if(ret != Z_OK) {
		error(RED(ERROR_MSG) "cannot compress the pkt. "
				"It will be sent uncompressed.", ERROR_FUNC);
		return -1;
	}

	if(bound_sz >= pkt->hdr.sz)
		/* Disgregard compression, it isn't useful in this case */
		return -pkt->hdr.sz;

	memcpy(dst_msg, dst, bound_sz);
	newhdr->uncompress_sz=pkt->hdr.sz;
	newhdr->sz=bound_sz;
	newhdr->flags|=COMPRESSED_PKT;

	return 0;
}

/*
 * pkt_pack
 *
 * It packs the packet with its `pkt'->header in a single buffer.
 * If PKT_COMPRESSED is set in `pkt'->pkt_flags, `pkt'->msg will be compressed
 * if its size is > PKT_COMPRESS_THRESHOLD.
 */
char *pkt_pack(PACKET *pkt)
{
	char *buf, *buf_hdr, *buf_body;
	
	buf=(char *)xmalloc(PACKET_SZ(pkt->hdr.sz));
	buf_hdr=buf;
	buf_body=buf+sizeof(pkt_hdr);

	/***
	 * Copy the header
	 */
	memcpy(buf_hdr, &pkt->hdr, sizeof(pkt_hdr));

	/* host -> network order */
	ints_host_to_network(buf_hdr, pkt_hdr_iinfo);
	/***/
	
	if(pkt->hdr.sz) {

                /*
		 * compress the packet if necessary 
		 */
                if((pkt->pkt_flags & PKT_COMPRESSED && 
				pkt->hdr.sz >= PKT_COMPRESS_THRESHOLD)) {
			
			if(!pkt_compress(pkt, &pkt->hdr, buf_body)) {
				/* 
				 * Re-copy the header in `buf', because
				 * it has been changed during compression. */
				memcpy(buf_hdr, &pkt->hdr, sizeof(pkt_hdr));
				ints_host_to_network(buf_hdr, pkt_hdr_iinfo);
			}
		} else
			/* Just copy the body of the packet */
			memcpy(buf_body, pkt->msg, pkt->hdr.sz);
		/**/
	}
	
	return buf;
}

/*
 * pkt_uncompress
 *
 * It uncompress the compressed `pkt' and stores the result in `pkt' itself
 * On error -1 is returned.
 */
int pkt_uncompress(PACKET *pkt)
{
	uLongf dstlen;
	int ret=0;
	unsigned char *dst=0;
	
	dstlen=pkt->hdr.uncompress_sz;
	dst=xmalloc(dstlen);
	
	ret=uncompress(dst, &dstlen, (u_char*) pkt->msg, pkt->hdr.sz);
	if(ret != Z_OK)
		ERROR_FINISH(ret, -1, finish);
	else
		ret=0;

	/**
	 * Restore the uncompressed packet
	 */
	xfree(pkt->msg);
	pkt->msg=(char*)dst;
	pkt->hdr.sz=pkt->hdr.uncompress_sz;
	pkt->hdr.uncompress_sz=0;
	pkt->hdr.flags&=~COMPRESSED_PKT;
	/**/

finish:
	if(ret && dst)
		xfree(dst);
	return ret;
}

/*
 * pkt_unpack
 *
 * `pkt' must be already in host order
 */
int pkt_unpack(PACKET *pkt)
{
	if(pkt->hdr.sz && pkt->msg && 
			pkt->hdr.flags & COMPRESSED_PKT)
		if(pkt_uncompress(pkt))
			return -1;

	return 0;
}

int pkt_verify_hdr(PACKET pkt)
{
	if(strncmp(pkt.hdr.ntk_id, NETSUKUKU_ID, 3) ||
			pkt.hdr.sz > MAXMSGSZ)
		return 1;

	if(pkt.hdr.flags & COMPRESSED_PKT && 
			(pkt.hdr.sz >= pkt.hdr.uncompress_sz ||
			 pkt.hdr.uncompress_sz > PKT_MAX_MSG_SZ))
		/* Invalid compression */
		return 1;

	return 0;
}

ssize_t pkt_send(PACKET *pkt)
{
	ssize_t ret=0;
	char *buf=0;

	buf=pkt_pack(pkt);

	if(pkt->sk_type==SKT_UDP || pkt->sk_type==SKT_BCAST) {
		struct sockaddr_storage saddr_sto;
		struct sockaddr *to = (struct sockaddr *)&saddr_sto;
		socklen_t tolen;
		
		if(inet_to_sockaddr(&pkt->to, pkt->port, to, &tolen) < 0) {
			debug(DBG_NOISE, "Cannot pkt_send(): %d "
					"Family not supported", pkt->to.family);
			ERROR_FINISH(ret, -1, finish);
		}
		
		if(pkt->pkt_flags & PKT_SEND_TIMEOUT)
			ret=inet_sendto_timeout(pkt->sk, buf, 
					PACKET_SZ(pkt->hdr.sz), pkt->flags, to,
					tolen, pkt->timeout);
		else
			ret=inet_sendto(pkt->sk, buf, PACKET_SZ(pkt->hdr.sz),
				pkt->flags, to, tolen);

	} else if(pkt->sk_type==SKT_TCP) {
		if(pkt->pkt_flags & PKT_SEND_TIMEOUT)
			ret=inet_send_timeout(pkt->sk, buf, PACKET_SZ(pkt->hdr.sz),
					pkt->flags, pkt->timeout);
		else
			ret=inet_send(pkt->sk, buf, PACKET_SZ(pkt->hdr.sz), 
					pkt->flags);
	} else
		fatal("Unkown socket_type. Something's very wrong!! Be aware");

finish:
	if(buf)
		xfree(buf);
	return ret;
}

ssize_t pkt_recv_udp(PACKET *pkt)
{
	ssize_t err=-1;
	struct sockaddr from;
	socklen_t fromlen;
	char buf[MAXMSGSZ];

	setzero(buf, MAXMSGSZ);
	setzero(&from, sizeof(struct sockaddr));

	if(pkt->family == AF_INET)
		fromlen=sizeof(struct sockaddr_in);
	else if(pkt->family == AF_INET6)
		fromlen=sizeof(struct sockaddr_in6);
	else {
		error("pkt_recv udp: family not set");
		return -1;
	}

	/* we get the whole pkt, */
	if(pkt->pkt_flags & PKT_RECV_TIMEOUT)
		err=inet_recvfrom_timeout(pkt->sk, buf, PACKET_SZ(MAXMSGSZ),
				pkt->flags, &from, &fromlen, pkt->timeout);
	else
		err=inet_recvfrom(pkt->sk, buf, PACKET_SZ(MAXMSGSZ), 
				pkt->flags, &from, &fromlen);

	if(err < sizeof(pkt_hdr)) {
		debug(DBG_NOISE, "inet_recvfrom() of the hdr aborted!");
		return -1;
	}

	/* then we extract the hdr... and verify it */
	memcpy(&pkt->hdr, buf, sizeof(pkt_hdr));
	/* network -> host order */
	ints_network_to_host(&pkt->hdr, pkt_hdr_iinfo);
	if(pkt_verify_hdr(*pkt) || pkt->hdr.sz+sizeof(pkt_hdr) > err) {
		debug(DBG_NOISE, RED(ERROR_MSG) "Malformed header", ERROR_POS);
		return -1;
	}

	if(sockaddr_to_inet(&from, &pkt->from, 0) < 0) {
		debug(DBG_NOISE, "Cannot pkt_recv(): %d"
				" Family not supported", from.sa_family);
		return -1;
	}

	pkt->msg=0;
	if(pkt->hdr.sz) {
		/*let's get the body*/
		pkt->msg=xmalloc(pkt->hdr.sz);
		memcpy(pkt->msg, buf+sizeof(pkt_hdr), pkt->hdr.sz);
	}
	
	return err;
}

ssize_t pkt_recv_tcp(PACKET *pkt)
{
	ssize_t err=-1;

	/* we get the hdr... */
	if(pkt->pkt_flags & PKT_RECV_TIMEOUT)
		err=inet_recv_timeout(pkt->sk, &pkt->hdr, sizeof(pkt_hdr),
				pkt->flags, pkt->timeout);
	else
		err=inet_recv(pkt->sk, &pkt->hdr, sizeof(pkt_hdr), 
				pkt->flags);
	if(err != sizeof(pkt_hdr))
		return -1;

	/* ...and verify it */
	ints_network_to_host(&pkt->hdr, pkt_hdr_iinfo);
	if(pkt_verify_hdr(*pkt)) {
		debug(DBG_NOISE, RED(ERROR_MSG) "Malformed header", ERROR_POS);
		return -1;
	}

	pkt->msg=0;
	if(pkt->hdr.sz) {
		/* let's get the body */
		pkt->msg=xmalloc(pkt->hdr.sz);

		if(pkt->pkt_flags & PKT_RECV_TIMEOUT)
			err=inet_recv_timeout(pkt->sk, pkt->msg, pkt->hdr.sz, 
					pkt->flags, pkt->timeout);
		else
			err=inet_recv(pkt->sk, pkt->msg, pkt->hdr.sz, 
					pkt->flags);

		if(err != pkt->hdr.sz) {
			debug(DBG_NOISE, RED(ERROR_MSG) "Cannot recv the "
					"pkt's body", ERROR_FUNC);
			return -1;
		}
	}

	return err;
}

ssize_t pkt_recv(PACKET *pkt)
{
	ssize_t err=-1;

	switch(pkt->sk_type) {
		case SKT_UDP:
		case SKT_BCAST:
			err=pkt_recv_udp(pkt);
			break;

		case SKT_TCP:
			err=pkt_recv_tcp(pkt);
			break;

		default:
			fatal("Unkown socket_type. Something's very wrong!! Be aware");
			break;
	}

	/* let's finish it */
	pkt_unpack(pkt);

	return err;
}

int pkt_tcp_connect(inet_prefix *host, short port, interface *dev)
{
	int sk;
	PACKET pkt;
	const char *ntop;
	ssize_t err;

	ntop=inet_to_str(*host);
	setzero(&pkt, sizeof(PACKET));
	
	if((sk=new_tcp_conn(host, port, dev?dev->dev_name:0))==-1)
		goto finish;
	
	/*
	 * Now we receive the first pkt from the server. 
	 * It is an ack. 
	 * Let's hope it isn't NEGATIVE (-_+)
	 */
	pkt_addsk(&pkt, host->family, sk, SKT_TCP);
	pkt.flags=MSG_WAITALL;
	pkt_addport(&pkt, port);

	if((err=pkt_recv(&pkt)) < 0) {
		error("Connection to %s failed: it wasn't possible to receive "
				"the ACK", ntop);
		ERROR_FINISH(sk, -1, finish);
	}
	
	/* ...Last famous words */
	if(pkt.hdr.op != ACK_AFFERMATIVE) {
		u_char err;
		
		memcpy(&err, pkt.msg, pkt.hdr.sz);
		error("Cannot connect to %s:%d: %s", 
				ntop, port, rq_strerror(err));
		ERROR_FINISH(sk, -1, finish);
	}
	
finish:
	pkt_free(&pkt, 0);
	return sk;
}

void pkt_fill_hdr(pkt_hdr *hdr, u_char flags, int id, u_char op, size_t sz)
{
	hdr->ntk_id[0]='n';
	hdr->ntk_id[1]='t';
	hdr->ntk_id[2]='k';

	hdr->id	   = !id ? rand() : id;
	hdr->flags = flags;
	hdr->op	   = op;
	hdr->sz	   = sz;
}

	
/* 
 * add_pkt_op: Add the `exec_f' in the pkt_exec_functions array.
 * `op' must be add int the pkt_op_tbl if it is a request that will be
 * received or if it is an op that will be sent with send_rq().
 */
void add_pkt_op(u_char op, char sk_type, u_short port, int (*exec_f)(PACKET pkt))
{
	pkt_op_tbl[op].sk_type   = sk_type;
	pkt_op_tbl[op].port	 = port;
	pkt_op_tbl[op].exec_func = exec_f;
}


/*
 * send_rq
 *
 * This functions send a `rq' request, with an id set to `rq_id', to
 * `pkt->to'.
 *
 * If `pkt->sk' is non zero, it will be used to send the request.
 * If `pkt->sk' is 0, it will create a new socket and connection to `pkt->to',
 * the new socket is stored in `pkt->sk'.
 *
 * If `pkt->hdr.sz` is > 0 it includes the `pkt->msg' in the packet otherwise
 * it will be NULL. 
 *
 * If `rpkt' is not null it will receive and store the reply pkt in `rpkt'.
 *
 * If `check_ack' is set, send_rq checks the reply pkt ACK and its id; if the
 * test fails it gives an appropriate error message.
 *
 * If `rpkt'  is not null send_rq confronts the OP of the received reply pkt 
 * with `re'; if the test fails it gives an appropriate error message.
 *
 * If `pkt'->hdr.flags has the ASYNC_REPLY set, the `rpkt' will be received with
 * the pkt_queue, in this case, if `rpkt'->from is set to a valid ip, it will
 * be used to check the sender ip of the reply pkt.
 *
 * If `pkt'->dev is not null and the PKT_BIND_DEV flag is set in
 * `pkt'->pkt_flags, it will bind the socket of the outgoing/ingoing packet to
 * the device named `pkt'->dev->dev_name.
 *
 *
 * On failure a negative value is returned, otherwise 0.
 * The error values are defined in pkts.h.
 */
int send_rq(PACKET *pkt, int pkt_flags, u_char rq, int rq_id, u_char re, 
		int check_ack, PACKET *rpkt)
{
	ssize_t err;
	int ret=0;
	const char *ntop=0;
	const u_char *rq_str=0, *re_str=0;
	inet_prefix *wanted_from=0;


	if(op_verify(rq)) {
		error("\"%s\" request/reply is not valid!", rq_str);
		return SEND_RQ_ERR_RQ;
	}
	rq_str = !re_verify(rq) ? re_to_str(rq) : rq_to_str(rq);
	if(re && re_verify(re)) {
		error("\"%s\" reply is not valid!", re_str);
		return SEND_RQ_ERR_RE;
	}

	ntop=inet_to_str(pkt->to);

	/* * * the request building process * * */
	if(check_ack)
		pkt->hdr.flags|=SEND_ACK;
	
	pkt_fill_hdr(&pkt->hdr, pkt->hdr.flags, rq_id, rq, pkt->hdr.sz);
	if(!pkt->hdr.sz)
		pkt->msg=0;

	if(!pkt->port) {
		if(!pkt_op_tbl[rq].port && !pkt->sk) {
			error("send_rq: The rq %s doesn't have an associated "
					"port.", rq_str);
			ERROR_FINISH(ret, SEND_RQ_ERR_PORT, finish);
		}
		pkt_addport(pkt, pkt_op_tbl[rq].port);
	}

	/* If the PKT_BIND_DEV flag is set we can use pkt->dev */
	pkt->dev = (pkt->pkt_flags & PKT_BIND_DEV) ? pkt->dev : 0;

	if(!pkt->sk_type)
		pkt->sk_type=pkt_op_tbl[rq].sk_type;

	if(!pkt->sk) {
		if(!pkt->to.family || !pkt->to.len) {
			error("pkt->to isn't set. I can't create the new connection");
			ERROR_FINISH(ret, SEND_RQ_ERR_TO, finish);
		}
		
		if(pkt->sk_type==SKT_TCP)
			pkt->sk=pkt_tcp_connect(&pkt->to, pkt->port, pkt->dev);
		else if(pkt->sk_type==SKT_UDP)
			pkt->sk=new_udp_conn(&pkt->to, pkt->port, pkt->dev->dev_name);
		else if(pkt->sk_type==SKT_BCAST) {
			if(!pkt->dev)
				fatal(RED(ERROR_MSG) "cannot broadcast the packet: "
						"device not specified", ERROR_FUNC);
			pkt->sk=new_bcast_conn(&pkt->to, pkt->port, pkt->dev->dev_idx);
		} else
			fatal("Unkown socket_type. Something's very wrong!! Be aware");

		if(pkt->sk==-1) {
			error("Couldn't connect to %s to launch the %s request", ntop, rq_str);
			ERROR_FINISH(ret, SEND_RQ_ERR_CONNECT, finish);
		}
	}

	/* Set the LOWDELAY TOS if necessary */
	if(pkt->pkt_flags & PKT_SET_LOWDELAY)
		set_tos_sk(pkt->sk, 1);

	if(pkt->pkt_flags & PKT_NONBLOCK)
		set_nonblock_sk(pkt->sk);

	/*Let's send the request*/
	err=pkt_send(pkt);
	if(err==-1) {
		error("Cannot send the %s request to %s:%d.", rq_str, ntop, pkt->port);
		ERROR_FINISH(ret, SEND_RQ_ERR_SEND, finish);
	}

	/*
	 *  * * the reply * * 
	 */
	if(rpkt) {
		if(rpkt->from.data[0] && rpkt->from.len) {
			wanted_from=&rpkt->from;
			ntop=inet_to_str(rpkt->from);
		}

		setzero(rpkt, sizeof(PACKET));
		pkt_addport(rpkt, pkt->port);
		pkt_addsk(rpkt, pkt->to.family, pkt->sk, pkt->sk_type);
		rpkt->flags=MSG_WAITALL;
		pkt_addtimeout(rpkt, pkt->timeout, pkt->pkt_flags&PKT_RECV_TIMEOUT,
				pkt->pkt_flags&PKT_SEND_TIMEOUT);
		if(pkt->pkt_flags & PKT_COMPRESSED)
			pkt_addcompress(rpkt);
		
		debug(DBG_NOISE, "Receiving reply for the %s request"
				" (id 0x%x)", rq_str, pkt->hdr.id);

		if(pkt->hdr.flags & ASYNC_REPLY) {
			pkt_queue *pq;
			/* Receive the pkt in the async way */
			err=pkt_q_wait_recv(pkt->hdr.id, wanted_from, rpkt, &pq);
			pkt_q_del(pq, 0);
		} else {
			if(pkt->sk_type==SKT_UDP) {
				inet_copy(&rpkt->from, &pkt->to);
				ntop=inet_to_str(rpkt->from);
			}

			/* Receive the pkt in the standard way */
			err=pkt_recv(rpkt);
		}

		if(err==-1) {
			error("Error while receving the reply for the %s request"
					" from %s.", rq_str, ntop);
			ERROR_FINISH(ret, SEND_RQ_ERR_RECV, finish);
		}

		if((rpkt->hdr.op == ACK_NEGATIVE) && check_ack) {
			u_char err_ack;
			memcpy(&err_ack, rpkt->msg, sizeof(u_char));
			error("%s failed. The node %s replied: %s", rq_str, ntop, 
					rq_strerror(err_ack));
			ERROR_FINISH(ret, SEND_RQ_ERR_REPLY, finish);
		} else if(rpkt->hdr.op != re && check_ack) {
			error("The node %s replied %s but we asked %s!", ntop, 
					re_to_str(rpkt->hdr.op), re_str);
			ERROR_FINISH(ret, SEND_RQ_ERR_RECVOP, finish);
		}

		if(check_ack && rpkt->hdr.id != pkt->hdr.id) {
			error("The id (0x%x) of the reply (%s) doesn't match the"
					" id of our request (0x%x)", rpkt->hdr.id,
					re_str, pkt->hdr.id);
			ERROR_FINISH(ret, SEND_RQ_ERR_RECVID, finish);
		}
	}

finish:
	return ret;
}

/*
 * forward_pkt: forwards the received packet `rpkt' to `to'.
 */
int forward_pkt(PACKET rpkt, inet_prefix to)
{
	int err;

	rpkt.sk=0; /* create a new connection */
	pkt_addto(&rpkt, &to);
	
	err=send_rq(&rpkt, 0, rpkt.hdr.op, rpkt.hdr.id, 0, 0, 0);
	if(!err)
		inet_close(&rpkt.sk);

	return err;
}

/* 
 * pkt_err: Sends back to "pkt.from" an error pkt, with ACK_NEGATIVE, 
 * containing the "err" code.
 * If `free_pkt' is not 0, `pkt' will be freed.
 */
int pkt_err(PACKET pkt, u_char err, int free_pkt)
{
	char *msg;
	u_char flags=0;
	
	pkt_addto(&pkt, &pkt.from);
	if(pkt.hdr.flags & ASYNC_REPLY) {
		flags|=ASYNC_REPLIED;
		pkt.sk=0;
	}

	/* It's useless to compress this pkt */
	pkt.pkt_flags&=~PKT_COMPRESSED;

	pkt_fill_hdr(&pkt.hdr, flags, pkt.hdr.id, ACK_NEGATIVE, sizeof(u_char));
	
	pkt.msg=msg=xmalloc(sizeof(u_char));
	memcpy(msg, &err, sizeof(u_char));
		
	err=send_rq(&pkt, 0, ACK_NEGATIVE, pkt.hdr.id, 0, 0, 0);

	if(pkt.hdr.flags & ASYNC_REPLY)
		pkt_free(&pkt, 1);
	else
		pkt_free(&pkt, 0);
	return err;
}


/*
 * pkt_exec
 *
 * It "executes" the received `pkt' passing it to the function which associated 
 * to `pkt'.hdr.op.
 *
 * `acpt_idx' is the accept table index of the connection where the pkt was
 * received.
 */
int pkt_exec(PACKET pkt, int acpt_idx)
{
	const char *ntop;
	const u_char *op_str;
	int (*exec_f)(PACKET pkt);
	int err=0;

	if(!re_verify(pkt.hdr.op))
		op_str=re_to_str(pkt.hdr.op);
	else if(!rq_verify(pkt.hdr.op))
		op_str=rq_to_str(pkt.hdr.op);
	else {
		debug(DBG_SOFT, "Dropped pkt from %s: bad op value", 
				inet_to_str(pkt.from));
		return -1;	/* bad op */
	}

	if((err=add_rq(pkt.hdr.op, &accept_tbl[acpt_idx].rqtbl))) {
		ntop=inet_to_str(pkt.from);
		error("From %s: Cannot process the %s request: %s", ntop, 
				op_str, rq_strerror(err));
		pkt_err(pkt, err, 1);
		return -1;
	}

	if(op_filter_test(pkt.hdr.op)) {
		/* Drop the pkt, `pkt.hdr.op' has been filtered */ 
#ifdef DEBUG
		ntop=inet_to_str(pkt.from);
		debug(DBG_INSANE, "FILTERED %s from %s, id 0x%x", op_str, ntop,
				pkt.hdr.id);
#endif
		return err;
	}
		
	/* Call the function associated to `pkt.hdr.op' */
	exec_f = pkt_op_tbl[pkt.hdr.op].exec_func;
#ifdef DEBUG
	if(pkt.hdr.op != ECHO_ME && pkt.hdr.op != ECHO_REPLY) {
		ntop=inet_to_str(pkt.from);
		debug(DBG_INSANE, "Received %s from %s, id 0x%x", op_str, ntop,
				pkt.hdr.id);
	}
#endif

	if(exec_f)
		err=(*exec_f)(pkt);
	else if(pkt_q_counter) {
		debug(DBG_INSANE, "pkt_exec: %s Async reply, id 0x%x", op_str,
				pkt.hdr.id);
		/* 
		 * There isn't a function to handle this pkt, so maybe it is
		 * an async reply
		 */
		pkt_q_add_pkt(pkt);
	}

	return err;
}

/*
 * * * Pkt queue functions * * *
 */

pthread_attr_t wait_and_unlock_attr;
void pkt_queue_init(void)
{
	pkt_q=(pkt_queue *)clist_init(&pkt_q_counter);

	pthread_attr_init(&wait_and_unlock_attr);
        pthread_attr_setdetachstate(&wait_and_unlock_attr, PTHREAD_CREATE_DETACHED);
}

void pkt_queue_close(void)
{
	pkt_queue *pq=pkt_q, *next;
	if(pkt_q_counter)
		list_safe_for(pq, next)
			pkt_q_del(pq, 1);
	pthread_attr_destroy(&wait_and_unlock_attr);
}

/* 
 * wait_and_unlock
 * 
 * It waits REQUEST_TIMEOUT seconds, then it unlocks `pq'->mtx.
 * This prevents the dead lock in pkt_q_wait_recv()
 */
void *wait_and_unlock(void *m)
{
	pkt_queue *pq, **pq_ptr;
	int i;

	pq_ptr=(pkt_queue **)m;
	pq=*pq_ptr;
	if(!pq)
		return 0;

	for(i=0; i<REQUEST_TIMEOUT; i++) {
		sleep(1);
		if(!(*pq_ptr) || (pq->flags & PKT_Q_PKT_RECEIVED) ||
				!(pq->flags & PKT_Q_MTX_LOCKED) ||
				pthread_mutex_trylock(&pq->mtx) != EBUSY)
			break;
	}

	if(!(*pq_ptr) || (pq->flags & PKT_Q_PKT_RECEIVED) ||
			!(pq->flags & PKT_Q_MTX_LOCKED) ||
			pthread_mutex_trylock(&pq->mtx) != EBUSY)
		goto finish;

	debug(DBG_INSANE, "pq->pkt.hdr.id: 0x%x Timeoutted. mtx: 0x%X", pq->pkt.hdr.id, &pq->mtx);
	pthread_mutex_unlock(&pq->mtx);
	pq->flags|=PKT_Q_TIMEOUT;
	
finish:
	if(pq_ptr)
		xfree(pq_ptr);
	return 0;
}

/*
 * pkt_q_wait_recv
 *
 * adds a new struct in pkt_q and waits REQUEST_TIMEOUT
 * seconds until a reply with an id equal to `id' is received.
 * If `from' is not null, the sender ip of the reply is considered too.
 * The received reply pkt is copied in `rpkt' (if `rpkt' isn't null).
 * In `ret_pq' is stored the address of the pkt_queue struct that 
 * corresponds to `rpkt'.
 * After the use of this function pkt_q_del() must be called.
 * On error -1 is returned.
 */
int pkt_q_wait_recv(int id, inet_prefix *from, PACKET *rpkt, pkt_queue **ret_pq)
{
	pthread_t thread;
	pkt_queue *pq, **pq_ptr;

	
	pq=xzalloc(sizeof(pkt_queue));
	pq_ptr=xmalloc(sizeof(pkt_queue *));
	*pq_ptr=pq;
	
	pthread_mutex_init(&pq->mtx, 0);
	pq->flags|=PKT_Q_MTX_LOCKED;
	*ret_pq=pq;
	
	if(!pkt_q_counter)
		pkt_queue_init();

	pq->pkt.hdr.id=id;
	if(from) {
		debug(DBG_INSANE, "0x%x wanted_rfrom %s activated", id, 
				inet_to_str(*from));
		inet_copy(&pq->pkt.from, from);
		pq->flags|=PKT_Q_CHECK_FROM;
	}

	clist_add(&pkt_q, &pkt_q_counter, pq);

	/* Be sure to unlock me after the timeout */
	pthread_create(&thread, &wait_and_unlock_attr, wait_and_unlock, 
			(void *)pq_ptr);

	if(pq->flags & PKT_Q_MTX_LOCKED) {
		debug(DBG_INSANE, "pkt_q_wait_recv: Locking 0x%x!", &pq->mtx);

		/* Freeze! */
		pthread_mutex_lock(&pq->mtx);
		pthread_mutex_lock(&pq->mtx);
	}

	debug(DBG_INSANE, "We've been unlocked: timeout %d", (pq->flags & PKT_Q_TIMEOUT));
	if(pq->flags & PKT_Q_TIMEOUT)
		return -1;

	if(rpkt)
		pkt_copy(rpkt, &pq->pkt);

	/* When *pq_ptr is set to 0, the wait_and_unlock thread exits */
	*pq_ptr=0;

	return 0;
}

/*
 * pkt_q_add_pkt: Copy the reply pkt in the struct of pkt_q which has the same
 * hdr.id, then unlock the mutex of the pkt_q struct.
 * If the struct in pkt_q isn't found, -1 is returned.
 */
int pkt_q_add_pkt(PACKET pkt)
{
	pkt_queue *pq=pkt_q, *next=0;
	int ret=-1;
	
	list_safe_for(pq, next) {
		debug(DBG_INSANE, "pkt_q_add_pkt: %d == %d. data[0]: %d, async replied: %d",
				pq->pkt.hdr.id, pkt.hdr.id, pq->pkt.from.data[0],
				(pkt.hdr.flags & ASYNC_REPLIED));
		if(pq->pkt.hdr.id == pkt.hdr.id) {
			if(pq->pkt.from.data[0] && (pq->flags & PKT_Q_CHECK_FROM) &&
					memcmp(pq->pkt.from.data, pkt.from.data, MAX_IP_SZ))
					continue; /* The wanted from ip and the
						     real from ip don't match */
			if(!(pkt.hdr.flags & ASYNC_REPLIED))
				continue;

			pkt_copy(&pq->pkt, &pkt);
			
			/* Now it's possible to read the reply,
			 * pkt_q_wait_recv() is now hot again */
			while(pthread_mutex_trylock(&pq->mtx) != EBUSY)
				usleep(5000);
			debug(DBG_INSANE, "pkt_q_add_pkt: Unlocking 0x%X ", &pq->mtx);
			pq->flags&=~PKT_Q_MTX_LOCKED & ~PKT_Q_TIMEOUT;
			pq->flags|=PKT_Q_PKT_RECEIVED;
			pthread_mutex_unlock(&pq->mtx);
			pthread_mutex_unlock(&pq->mtx);
			ret=0;
		}
	}

	return ret;
}

/*
 * pkt_q_del: Deletes `pq' from the pkt_q llist and frees the `pq' struct. The 
 * `pq'->pkt is also freed and the pq->pkt.sk socket is closed if `close_socket' 
 * is non zero.
 */
void pkt_q_del(pkt_queue *pq, int close_socket)
{
	pthread_mutex_unlock(&pq->mtx);
	pthread_mutex_destroy(&pq->mtx);

	pkt_free(&pq->pkt, close_socket);
	clist_del(&pkt_q, &pkt_q_counter, pq);
}
