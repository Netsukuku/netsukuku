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
#ifndef DNSLIB_H
#define DNSLIB_H

#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define LBL_PTR_MASK		0xC0                    /* Network byte order */
#define LBL_PTR_OFF_MASK	0x3f                   /* N.b. order */
#define LBL_PTR(c)		((c)&LBL_PTR_MASK)      /* AND whith 0xC000 */

#define MAX_RECURSION_PTR	20

/* PREFIXES FOR PTR QUERY */
#define DNS_INV_PREFIX          ".IN-ADDR.ARPA"
#define DNS_INV_PREFIX6         ".IP6.ARPA"
#define OLD_DNS_INV_PREFIX6     ".IP6.INT" /* For backward compatibility */

/* DNS QUERY-TYPE: others type will be discarded */

#define T_AAAA  28      /* h->ip IPV6  */
#define T_A     1       /* h->ip IPV4 */
#define T_PTR   12      /* ip->h */
#define T_MX    15      /* h->mx */
/* RCODES */
#define DNS_RCODE_NOERR     0       /* No error */
#define DNS_RCODE_EINTRPRT  1       /* Intepret error */
#define DNS_RCODE_ESRVFAIL  2       /* Server failure */
#define DNS_RCODE_ENSDMN    3       /* No such domain */
#define DNS_RCODE_ENIMPL    4       /* Not implemented */
#define DNS_RCODE_ERFSD     5       /* Refused */

/* INET CLASS */
#define C_IN    1

/* RFC */
#define DNS_MAX_SZ		512
#define DNS_HDR_SZ		12
#define DNS_MAX_LABELS		63
#define DNS_MAX_HNAME_LEN	255
#define DNS_TTL 86400;

#define min(x,y)		((x)<(y))?(x):(y)

typedef struct dns_pkt_hdr {
        uint16_t       id;
        uint8_t        qr;
        uint8_t        opcode;
        uint8_t        aa;
        uint8_t        tc;
        uint8_t        rd;
        uint8_t        ra;
        uint8_t        z;
        uint8_t        rcode;
        uint8_t        qdcount;
        uint8_t        ancount;
        uint8_t        nscount;
        uint8_t        arcount;
} dns_pkt_hdr;
#define DNS_PKT_HDR_SZ sizeof(dns_pkt_hdr)

/* DNS_PKT_HDR MACROS */
#define DP_QDCOUNT(dp)  ((dp)->pkt_hdr).qdcount
#define DP_ANCOUNT(dp)  ((dp)->pkt_hdr).ancount
#define DP_NSCOUNT(dp)  ((dp)->pkt_hdr).nscount
#define DP_ARCOUNT(dp)  ((dp)->pkt_hdr).arcount


struct dns_pkt_qst {
        char                    qname[DNS_MAX_HNAME_LEN];
        uint16_t                qtype;
        uint16_t                qclass;
        struct dns_pkt_qst      *next;
};
typedef struct dns_pkt_qst dns_pkt_qst;
#define DNS_PKT_QST_SZ sizeof(dns_pkt_qst)

struct dns_pkt_a
{
        char                    name[DNS_MAX_HNAME_LEN];
        uint16_t                type;
        uint16_t                cl;
        uint32_t                ttl;
        uint16_t                rdlength;
        char                    rdata[DNS_MAX_HNAME_LEN];
        struct dns_pkt_a        *next;
};
typedef struct dns_pkt_a dns_pkt_a;
#define DNS_PKT_A_SZ sizeof(dns_pkt_a)

typedef struct dns_pkt
{
        dns_pkt_hdr     pkt_hdr;
        dns_pkt_qst     *pkt_qst;
        dns_pkt_a       *pkt_answ;
        dns_pkt_a       *pkt_auth;
        dns_pkt_a       *pkt_add;
} dns_pkt;
#define DNS_PKT_SZ sizeof(dns_pkt)

/* USER MACRO */
#define DNS_GET_ID(dp)		(dp)->pkt_hdr.id
#define DNS_GET_QR(dp)		(dp)->pkt_hdr.qr
#define DNS_GET_OPCODE(dp)	(dp)->pkt_hdr.opcode
#define DNS_GET_AA(dp)		(dp)->pkt_hdr.aa
#define DNS_GET_TC(dp)		(dp)->pkt_hdr.tc
#define DNS_GET_RD(dp)		(dp)->pkt_hdr.rd
#define DNS_GET_RA(dp)		(dp)->pkt_hdr.ra
#define DNS_GET_Z(dp)		(dp)->pkt_hdr.z
#define DNS_GET_RCODE(dp)	(dp)->pkt_hdr.rcode
#define DNS_GET_QDCOUNT(dp)	(dp)->pkt_hdr.qdcount
#define DNS_GET_ANCOUNT(dp)	(dp)->pkt_hdr.ancount
#define DNS_GET_NSCOUNT(dp)	(dp)->pkt_hdr.nscount
#define DNS_GET_ARCOUNT(dp)	(dp)->pkt_hdr.arcount

#define DNS_SET_ID(dp,x)	(dp)->pkt_hdr.id=x
#define DNS_SET_QR(dp,x)	(dp)->pkt_hdr.qr=x
#define DNS_SET_OPCODE(dp,x)	(dp)->pkt_hdr.opcode=x
#define DNS_SET_AA(dp,x)	(dp)->pkt_hdr.aa=x
#define DNS_SET_TC(dp,x)	(dp)->pkt_hdr.tc=x
#define DNS_SET_RD(dp,x)	(dp)->pkt_hdr.rd=x
#define DNS_SET_RA(dp,x)	(dp)->pkt_hdr.ra=x
#define DNS_SET_Z(dp,x)		(dp)->pkt_hdr.z=x
#define DNS_SET_RCODE(dp,x)	(dp)->pkt_hdr.rcode=x
#define DNS_SET_QDCOUNT(dp,x)	(dp)->pkt_hdr.qdcount=x
#define DNS_SET_ANCOUNT(dp,x)	(dp)->pkt_hdr.ancount=x
#define DNS_SET_NSCOUNT(dp,x)	(dp)->pkt_hdr.nscount=x
#define DNS_SET_ARCOUNT(dp,x)	(dp)->pkt_hdr.arcount=x

#define DP_ADD_ANSWER(dp)       dns_add_a(&((dp)->pkt_answ));DP_ANCOUNT(dp)+=1;	
#define DP_ADD_AUTH(dp)         dns_add_a(&((dp)->pkt_auth));DP_NSCOUNT(dp)+=1;	
#define DP_ADD_ADD(dp)          dns_add_a(&((dp)->pkt_add));DP_ARCOUNT(dp)+=1;	


	/* Functions */
int getlblptr(char *buf);
int read_label_octet(const char *src,char *dst,int limit);
int lbltoname(char *buf,char *start_pkt,char *dst,int limit);
int swap_straddr(char *src,char *dst);
int swap_straddr6(char *src,char *dst);
int rm_inv_prefix(char *src,char *dst) ;
int add_inv_prefix(char *s,int family);
int swapped_straddr(char *src,char *dst) ;
int swapped_straddr_pref(char *src,char *dst,int family);
int nametolbl(char *name,char *dst);
int d_hdr_u(char *buf,dns_pkt_hdr *dph);
int d_qst_u(char *start_buf,char *buf,dns_pkt *dp,int limit_len);
int d_qsts_u(char *start_buf,char *buf,dns_pkt *dp,int limit_len);
int d_a_u(char *start_buf,char *buf,dns_pkt_a **dpa_orig,int limit_len);
int d_as_u(char *start_buf,char *buf,dns_pkt_a **dpa,int limit_len,int count);
int d_u(char *buf,int pktlen,dns_pkt **dpp);
int d_hdr_p(dns_pkt *dp,char *buf);
int d_qst_p(dns_pkt_qst *dpq,char *buf, int limitlen);
int d_qsts_p(dns_pkt *dp,char *buf,int limitlen);
int d_a_p(dns_pkt_a *dpa,char *buf,int limitlen);
int d_as_p(dns_pkt_a *dpa,char *buf,int limitlen,int count);
int d_p(dns_pkt *dp,char *buf);
dns_pkt* create_dns_pkt(void);
dns_pkt_qst* create_dns_pkt_qst(void);
dns_pkt_a* create_dns_pkt_a(void);
dns_pkt_qst* dns_add_qst(dns_pkt *dp);
void dns_del_last_qst(dns_pkt *dp);
dns_pkt_a* dns_add_a(dns_pkt_a **dpa);
void dns_a_default_fill(dns_pkt *dp,dns_pkt_a *dpa);
void destroy_dns_pkt(dns_pkt *dp);


#endif /* DNSLIB_H */

