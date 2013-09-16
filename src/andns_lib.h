                 /**************************************
                *     AUTHOR: Federico Tomassini        *
               *     Copyright (C) Federico Tomassini    *
              *     Contact effetom@gmail.com             *
             ***********************************************
             *******          BEGIN 3/2006          ********
*************************************************************************
*                                                                       *
*  This program is free software; you can redistribute it and/or modify *
*  it under the terms of the GNU General Public License as published by *
*  the Free Software Foundation; either version 2 of the License, or    *
*  (at your option) any later version.                                  *
*                                                                       *
*  This program is distributed in the hope that it will be useful,      *
*  but WITHOUT ANY WARRANTY; without even the implied warranty of       *
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
*  GNU General Public License for more details.                         *
*                                                                       *
************************************************************************/

#ifndef ANDNS_LIB_H
#define ANDNS_LIB_H

#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#define ANDNS_MAX_QUESTION_LEN	263 /* TODO */
#define ANDNS_MAX_ANSWER_LEN	516
#define ANDNS_MAX_ANSWERS_NUM	256
#define ANDNS_MAX_PK_LEN	ANDNS_MAX_QUESTION_LEN+\
				ANDNS_MAX_ANSWERS_NUM*ANDNS_MAX_ANSWER_LEN

#define ANDNS_MAX_DATA_LEN	512
#define ANDNS_MAX_QST_LEN	512
#define ANNDS_DNS_MAZ_QST_LEN	255
#define ANDNS_MAX_ANSW_IP_LEN	20
#define ANDNS_MAX_ANSW_H_LEN	516

#define ANDNS_HASH_H		16

#define ANDNS_COMPR_LEVEL	Z_BEST_COMPRESSION
#define ANDNS_COMPR_THRESHOLD	1000

struct andns_pkt_data
{
	uint8_t			m;
	uint8_t			wg;
	uint8_t			prio;
        uint16_t                rdlength;
        uint16_t                service;
        char                    *rdata;
        struct andns_pkt_data   *next;
};
typedef struct andns_pkt_data andns_pkt_data;
#define ANDNS_PKT_DATA_SZ sizeof(andns_pkt_data)
#define APD_ALIGN(apd)	(apd)->rdata=(char*)xmalloc((apd)->rdlength+1);		\
				     memset((apd)->rdata,0,(apd)->rdlength+1)
#define APD_MAIN_IP	1<<0
#define APD_IP		1<<1
#define APD_TCP		1<<2
#define APD_UDP		1<<3

typedef struct andns_pkt
{
        uint16_t        id;
        uint8_t         r;
        uint8_t         qr;
        uint8_t         p;
        uint8_t         z;
        uint8_t         qtype;
        uint16_t        ancount;
        uint8_t         ipv;
        uint8_t         nk;
        uint8_t         rcode;
        uint16_t        service; 
        uint16_t        qstlength;
        char            *qstdata;
        andns_pkt_data  *pkt_answ;
} andns_pkt;
#define ANDNS_PKT_SZ sizeof(andns_pkt)
#define AP_ALIGN(ap)	(ap)->qstdata=(char*)xmalloc((ap)->qstlength)

#define ANDNS_HDR_SZ	4
#define ANDNS_HDR_Z	4
#define ANDNS_MAX_SZ 	ANDNS_HDR_SZ+ANDNS_MAX_QST_LEN+ANDNS_MAX_QST_LEN+4


#define ANDNS_SET_RCODE(s,c)    *((s)+3)=(((*((s)+3))&0xf0)|c)
#define ANDNS_SET_QR(s)         (*((s)+2))|=0x80
#define ANDNS_SET_ANCOUNT(s,n)  *(s+2)|=((n)>>1);*(s+3)|=((n)<<7);
#define ANDNS_SET_Z(s)		*(s+3)|=0x20;
#define ANDNS_UNSET_Z(s)	*(s+3)&=0xdf;

/* ANDNS PROTO-TYPE */
#define ANDNS_PROTO_TCP	0
#define ANDNS_PROTO_UDP	1
/* ANDNS QUERY-TYPE */
#define AT_A            0 /* h->ip */
#define AT_PTR          1 /* ip->h */
#define AT_G          	2 /* global */
/* RCODES: The rcodes are portable between ANDNS and DNS */
#define ANDNS_RCODE_NOERR     0       /* No error */
#define ANDNS_RCODE_EINTRPRT  1       /* Intepret error */
#define ANDNS_RCODE_ESRVFAIL  2       /* Server failure */
#define ANDNS_RCODE_ENSDMN    3       /* No such domain */
#define ANDNS_RCODE_ENIMPL    4       /* Not implemented */
#define ANDNS_RCODE_ERFSD     5       /* Refused */
/* REALMS TO SEARCH */
#define NTK_REALM               1
#define INET_REALM              2
/* IP VERSION */
#define ANDNS_IPV4		0
#define ANDNS_IPV6		1

int andns_compress(char *src,int srclen);
char* andns_uncompress(char *src,int srclen,int *dstlen) ;
int a_hdr_u(char *buf,andns_pkt *ap);
int a_qst_u(char *buf,andns_pkt *ap,int limitlen);
int a_answ_u(char *buf,andns_pkt *ap,int limitlen);
int a_answs_u(char *buf,andns_pkt *ap,int limitlen);
int a_u(char *buf,int pktlen,andns_pkt **app);
int a_hdr_p(andns_pkt *ap,char *buf);
int a_qst_p(andns_pkt *ap,char *buf,int limitlen);
int a_answ_p(andns_pkt *ap,andns_pkt_data *apd,char *buf,int limitlen);
int a_answs_p(andns_pkt *ap,char *buf, int limitlen);
int a_p(andns_pkt *ap, char *buf);
andns_pkt* create_andns_pkt(void);
andns_pkt_data* create_andns_pkt_data(void);
andns_pkt_data* andns_add_answ(andns_pkt *ap);
void destroy_andns_pkt_data(andns_pkt_data *apd);
void andns_del_answ(andns_pkt *ap);
void destroy_andns_pkt_datas(andns_pkt *ap);
void destroy_andns_pkt(andns_pkt *ap);

#endif /* ANDNS_LIB_H */
