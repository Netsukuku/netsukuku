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

#include "includes.h"
#include "request.h"
#include "xmalloc.h"
#include "log.h"

const static u_char request_str[][30]=
{ 
	{ "ECHO_ME" },
	{ "ECHO_REPLY" },
	{ "GET_FREE_NODES" },
	{ "GET_QSPN_ROUND" },

	{ "GET_INTERNET_GWS" },
	{ "SET_FOREIGN_ROUTE" },
	{ "DEL_FOREIGN_ROUTE"},
	{ "NEW_BACKROUTE"},
	{ "DELAYED_BROADCAST" },
	{ "SPLIT_ROUTE" },
	{ "SET_NO_IDENTITY" },
	{ "QSPN_CLOSE"},
	{ "QSPN_OPEN"},
	{ "QSPN_RFR"},
	{ "GET_DNODE_BLOCK" },
	{ "GET_DNODE_IP"},
	{ "TRACER_PKT" },
	{ "TRACER_PKT_CONNECT" },
	{ "DEL_SNODE" },
	{ "DEL_GNODE" },
	{ "GET_INT_MAP" },
	{ "GET_EXT_MAP" },
	{ "GET_BNODE_MAP" },

	{ "ANDNA_REGISTER_HNAME" },
	{ "ANDNA_CHECK_COUNTER"},
	{ "ANDNA_RESOLVE_HNAME"},
	{ "ANDNA_RESOLVE_IP"},
	{ "ANDNA_RESOLVE_MX"},
	{ "ANDNA_GET_ANDNA_CACHE" },
	{ "ANDNA_GET_SINGLE_ACACHE" },
	{ "ANDNA_SPREAD_SACACHE" },
	{ "ANDNA_GET_COUNT_CACHE"}

};

const static char 	unknown_reply[]="Unknow reply";
const static u_char	reply_str[][30]=
{
	{ "PUT_FREE_NODES" },
	{ "PUT_QSPN_ROUND" },
	{ "PUT_INTERNET_GWS" },
	{ "PUT_DNODEIP"	   },
	{ "EMPTY_REPLY_SLOT" },
	{ "EMPTY_REPLY_SLOT1" },
	{ "PUT_INT_MAP"	   },
	{ "PUT_EXT_MAP"     },
	{ "PUT_BNODE_MAP" },
	{ "ANDNA_RESOLVE_REPLY"   },
	{ "ANDNA_REV_RESOLVE_REPLY"   },
	{ "ANDNA_MX_RESOLVE_REPLY"   },
	{ "ANDNA_PUT_COUNT_CACHE" },
	{ "ANDNA_PUT_ANDNA_CACHE" },

	{ "ACK_AFFERMATIVE"},
	{ "ACK_NEGATIVE"   }
};

const static u_char unknown_error[]="Unknow error";
const static u_char error_str[][40]=
{	
	{ "Invalid request" },
	{ "Accept table full" },
	{ "Request table full" },
	{ "Quadro Group full" },
	{ "Netsukuku is full" },
	{ "Invalid signature" },
	{ "Cannot forward the pkt" },
	{ "Invalid hash_gnode" },
	{ "ANDNA cache queue full" },
	{ "Hostname update too early" },
	{ "Too many hostname registered" },
	{ "Hname updates counter mismatch" },
	{ "Inexistent host name" },
	{ "Counter check failed" },
	{ "Too many connection" },
};

/*Wait time*/
#define ECHO_ME_WAIT			5		/*(in seconds)*/
#define ECHO_REPLY_WAIT			5
#define GET_FREE_NODES_WAIT		10
#define GET_QSPN_ROUND_WAIT		10

#define GET_INTERNET_GWS_WAIT		5
#define SET_FOREIGN_ROUTE_WAIT		5
#define DEL_FOREIGN_ROUTE_WAIT		5
#define NEW_BACKROUTE_WAIT		10
#define DELAYED_BROADCAST_WAIT		5
#define SPLIT_ROUTE_WAIT		20
#define SET_NO_IDENTITY_WAIT		20

#define QSPN_CLOSE_WAIT			0
#define QSPN_OPEN_WAIT			0
#define QSPN_RFR_WAIT			5
#define GET_DNODEBLOCK_WAIT		20
#define GET_DNODEIP_WAIT	     	5
#define TRACER_PKT_WAIT			10
#define TRACER_PKT_CONNECT_WAIT		10

#define DEL_SNODE_WAIT			10
#define DEL_GNODE_WAIT			10

#define GET_INT_MAP_WAIT		10
#define GET_EXT_MAP_WAIT		10
#define GET_BNODE_MAP_WAIT		10

#define ANDNA_REGISTER_HNAME_WAIT	5
#define ANDNA_CHECK_COUNTER_WAIT	5
#define ANDNA_RESOLVE_HNAME_WAIT	2
#define ANDNA_RESOLVE_IP_WAIT		5
#define ANDNA_RESOLVE_MX_WAIT		5
#define ANDNA_GET_ANDNA_CACHE_WAIT	10
#define ANDNA_GET_SINGLE_ACACHE_WAIT	10
#define ANDNA_SPREAD_SACACHE_WAIT	10
#define	ANDNA_GET_COUNT_CACHE_WAIT	10


/*Max simultaneous requests*/ 
#define ECHO_ME_MAXRQ			0	/*NO LIMITS*/
#define ECHO_REPLY_MAXRQ		20
#define GET_FREE_NODES_MAXRQ		5
#define GET_QSPN_ROUND_MAXRQ		5

#define GET_INTERNET_GWS_MAXRQ		5
#define SET_FOREIGN_ROUTE_MAXRQ		30
#define DEL_FOREIGN_ROUTE_MAXRQ		30
#define NEW_BACKROUTE_MAXRQ		10
#define DELAYED_BROADCAST_MAXRQ		5
#define SPLIT_ROUTE_MAXRQ		1
#define SET_NO_IDENTITY_MAXRQ		1

#define QSPN_CLOSE_MAXRQ		0	/*NO LIMITS*/
#define QSPN_OPEN_MAXRQ			0	/*NO LIMITS*/
#define QSPN_RFR_MAXRQ			10
#define GET_DNODEBLOCK_MAXRQ		1
#define GET_DNODEIP_MAXRQ		10
#define TRACER_PKT_MAXRQ		20
#define TRACER_PKT_CONNECT_MAXRQ	10

#define DEL_SNODE_MAXRQ			20
#define DEL_GNODE_MAXRQ			5

#define GET_INT_MAP_MAXRQ		2
#define GET_EXT_MAP_MAXRQ		2
#define GET_BNODE_MAP_MAXRQ		2

#define ANDNA_REGISTER_HNAME_MAXRQ	30
#define ANDNA_CHECK_COUNTER_MAXRQ	0	/*NO LIMITS*/
#define ANDNA_RESOLVE_HNAME_MAXRQ	80
#define ANDNA_RESOLVE_IP_MAXRQ		40
#define ANDNA_RESOLVE_MX_MAXRQ		40
#define ANDNA_GET_ANDNA_CACHE_MAXRQ	5
#define ANDNA_GET_SINGLE_ACACHE_MAXRQ	10
#define ANDNA_SPREAD_SACACHE_MAXRQ	10
#define	ANDNA_GET_COUNT_CACHE_MAXRQ	5

const static u_char unknown_request[]="Unknow request";
const static u_char request_array[][2]=
{ 
	{ ECHO_ME_WAIT,        ECHO_ME_MAXRQ	    },
	{ ECHO_REPLY_WAIT,     ECHO_REPLY_MAXRQ	    },
	{ GET_FREE_NODES_WAIT, GET_FREE_NODES_MAXRQ },
	{ GET_QSPN_ROUND_WAIT, GET_QSPN_ROUND_MAXRQ },
	
	{ GET_INTERNET_GWS_WAIT,  GET_INTERNET_GWS_MAXRQ  },
	{ SET_FOREIGN_ROUTE_WAIT, SET_FOREIGN_ROUTE_MAXRQ },
	{ DEL_FOREIGN_ROUTE_WAIT, DEL_FOREIGN_ROUTE_MAXRQ },
	{ NEW_BACKROUTE_WAIT,     NEW_BACKROUTE_MAXRQ 	  },
	{ DELAYED_BROADCAST_WAIT, DELAYED_BROADCAST_MAXRQ },
	{ SPLIT_ROUTE_WAIT,       SPLIT_ROUTE_MAXRQ       },
	{ SET_NO_IDENTITY_WAIT,   SET_NO_IDENTITY_MAXRQ   },
	{ QSPN_CLOSE_WAIT,        QSPN_CLOSE_MAXRQ        },
	{ QSPN_OPEN_WAIT,         QSPN_OPEN_MAXRQ         },
	{ QSPN_RFR_WAIT,	  QSPN_RFR_MAXRQ	  },
	{ GET_DNODEBLOCK_WAIT,    GET_DNODEBLOCK_MAXRQ    },
	{ GET_DNODEIP_WAIT,       GET_DNODEIP_MAXRQ       },
	{ TRACER_PKT_WAIT,	  TRACER_PKT_MAXRQ	  },
	{ TRACER_PKT_CONNECT_WAIT,TRACER_PKT_CONNECT_MAXRQ},
	{ DEL_SNODE_WAIT,         DEL_SNODE_MAXRQ         },
	{ DEL_GNODE_WAIT,         DEL_GNODE_MAXRQ         },
	{ GET_INT_MAP_WAIT,	  GET_INT_MAP_MAXRQ	  },
	{ GET_EXT_MAP_WAIT,	  GET_EXT_MAP_MAXRQ	  },
	{ GET_BNODE_MAP_WAIT,	  GET_BNODE_MAP_MAXRQ	  },

	{ ANDNA_REGISTER_HNAME_WAIT,   ANDNA_REGISTER_HNAME_MAXRQ   },
	{ ANDNA_CHECK_COUNTER_WAIT,    ANDNA_CHECK_COUNTER_MAXRQ    },
	{ ANDNA_RESOLVE_HNAME_WAIT,    ANDNA_RESOLVE_HNAME_MAXRQ    },
	{ ANDNA_RESOLVE_IP_WAIT,       ANDNA_RESOLVE_IP_MAXRQ	    },
	{ ANDNA_RESOLVE_MX_WAIT,       ANDNA_RESOLVE_MX_MAXRQ	    },
	{ ANDNA_GET_ANDNA_CACHE_WAIT,  ANDNA_GET_ANDNA_CACHE_MAXRQ  },
	{ ANDNA_GET_SINGLE_ACACHE_WAIT,ANDNA_GET_SINGLE_ACACHE_MAXRQ},
	{ ANDNA_SPREAD_SACACHE_WAIT,   ANDNA_SPREAD_SACACHE_MAXRQ   },
	{ ANDNA_GET_COUNT_CACHE_WAIT,  ANDNA_GET_COUNT_CACHE_MAXRQ  }
};

/* 
 * Request_array indexes defines:
 * ex: request_array[SET_FOREIGN_ROUTE][RQ_WAIT]
 */
#define RQ_WAIT 	0
#define RQ_MAXRQ	1

void rq_wait_idx_init(int *rq_wait_idx)
{
	int e, idx;
	
	for(e=0, idx=0; e<TOTAL_REQUESTS; e++) {
		rq_wait_idx[e]=idx;
		idx+=request_array[e][RQ_MAXRQ];
	}
}

int op_verify(u_char op)
{
	return op >= TOTAL_OPS;
}

int rq_verify(u_char rq)
{
	return rq >= TOTAL_REQUESTS;
}

int re_verify(u_char re)
{
	return ((op_verify(re)) || (re < TOTAL_REQUESTS));
}

int err_verify(u_char err)
{
	return err >= TOTAL_ERRORS;
}

const u_char *rq_strerror(int err)
{
	if(err_verify(err))
		return unknown_error;
	return error_str[err];
}

const u_char *rq_to_str(u_char rq)
{
	if(rq_verify(rq))
		return unknown_request;
	return request_str[rq];
}

const u_char *re_to_str(u_char re)
{
	if(re_verify(re))
		return (const u_char*)unknown_reply;
	return reply_str[re-TOTAL_REQUESTS];
}

void update_rq_tbl(rq_tbl *tbl)
{
	u_char i=0,e=0, idx=0;
	time_t cur_t;

	if(update_rq_tbl_mutex)
		return;
	else
		update_rq_tbl_mutex=1;

	time(&cur_t);

	for(; i<TOTAL_REQUESTS; i++) {
		for(e=0; e < request_array[i][RQ_MAXRQ]; e++) {
			if(tbl->rq_wait[idx] && (tbl->rq_wait[idx]+request_array[i][RQ_WAIT]) <= cur_t) {
				tbl->rq_wait[idx]=0;
				tbl->rq[i]--;
			}
			idx++;
		}
	}

	update_rq_tbl_mutex=0;
}
	
int is_rq_full(u_char rq, rq_tbl *tbl)
{
	if(rq_verify(rq))
		return E_INVALID_REQUEST;
	
	update_rq_tbl(tbl);
	
	if(tbl->rq[rq] >= request_array[rq][RQ_MAXRQ] && request_array[rq][RQ_MAXRQ])
		return E_REQUEST_TBL_FULL;
	else if(!request_array[rq][RQ_MAXRQ])
		return -1; /* No limits */
	else
		return 0;
}



int find_free_rq_wait(u_char rq, rq_tbl *tbl)
{
	int e, idx;
	
	for(e=0; e < request_array[rq][RQ_MAXRQ]; e++) {
		idx = rq_wait_idx[rq] + e;
		if(!tbl->rq_wait[idx])
			return idx;
	}
	
	return -1;	/*This happens if the rq_tbl is full for the "rq" request*/
}

int add_rq(u_char rq, rq_tbl *tbl)
{
	int err;
	time_t cur_t;
	
	/* TODO: XXX: Activate it and test it!!! */
	return 0;
	/* TODO: XXX: Activate it and test it!!! */
	
	if((err=is_rq_full(rq, tbl)) > 0)
		return err;
	else if(err < 0)
		return 0; /* no limits */
	
	time(&cur_t);
	
	tbl->rq[rq]++;
	tbl->rq_wait[find_free_rq_wait(rq, tbl)]=cur_t;	
	return 0;
}

/*
 * op_filter_reset_re: resets all the replies
 */
void op_filter_reset_re(int bit)
{
	int i;
	for(i=TOTAL_REQUESTS; i<TOTAL_OPS; i++)
		if(bit)
			op_filter_set(i);
		else
			op_filter_clr(i);
}

/*
 * op_filter_reset_rq: resets all the requests
 */
void op_filter_reset_rq(int bit)
{
	int i;
	for(i=0; i<TOTAL_REQUESTS; i++)
		if(bit)
			op_filter_set(i);
		else
			op_filter_clr(i);
}
