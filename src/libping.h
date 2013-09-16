/**
 * PING header
 *
 * Copyright (C) 2001 Jeffrey Fulmer <jdfulmer@armstrong.com>
 * This file is part of LIBPING
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#ifndef PING_H
#define PING_H

#include "includes.h"

#if defined( __linux__ )

#define ICMP_ECHOREPLY          0 
#define ICMP_ECHO               8
#define ICMP_MINLEN             8

struct ip {
#if (BYTE_ORDER == LITTLE_ENDIAN || BYTE_ORDER == PDP_ENDIAN)
        u_char  ip_hl:4,                /* header length */
                ip_v:4;                 /* version */
#else
        u_char  ip_v:4,                 /* version */
                ip_hl:4;                /* header length */
#endif
        u_char  ip_tos;                 /* type of service */
        short   ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        short   ip_off;                 /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

#define n_short u_short                 /* normally defined in in_systm.h */
#define n_long  u_int                   /* redefine for 64-bit machines */
#define n_time  u_int                   /* redefine for 64-bit machines */

struct icmp {
        u_char  icmp_type;              /* type of message, see below */
        u_char  icmp_code;              /* type sub code */
        u_short icmp_cksum;             /* ones complement cksum of struct */
        union {
                u_char ih_pptr;                 /* ICMP_PARAMPROB */
                struct in_addr ih_gwaddr;       /* ICMP_REDIRECT */
                struct ih_idseq {
                        n_short icd_id;
                        n_short icd_seq;
                } ih_idseq;
                int ih_void;
        } icmp_hun;
#define icmp_pptr       icmp_hun.ih_pptr
#define icmp_gwaddr     icmp_hun.ih_gwaddr
#define icmp_id         icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void       icmp_hun.ih_void
        union {
                struct id_ts {
                        n_time its_otime;
                        n_time its_rtime;
                        n_time its_ttime;
                } id_ts;
                struct id_ip  {
                        struct ip idi_ip;
                        /* options and then 64 bits of data */
                } id_ip;
                n_long  id_mask;
                char    id_data[1];
        } icmp_dun;
#define icmp_otime      icmp_dun.id_ts.its_otime
#define icmp_rtime      icmp_dun.id_ts.its_rtime
#define icmp_ttime      icmp_dun.id_ts.its_ttime
#define icmp_ip         icmp_dun.id_ip.idi_ip
#define icmp_mask       icmp_dun.id_mask
#define icmp_data       icmp_dun.id_data
};

#else
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
#endif /* defined(__linux__) */   

#define IDENT_DEFAULT 0
#define TIMO_DEFAULT 2

struct ping_priv {
  int   ident;
  int   timo;
  int   rrt;
  int   sock;
};

struct ping_priv ping_priv_default (void);

int pinghost  ( const char *hostname );
int pingthost ( const char *hostname, int t );
int tpinghost ( const char *hostname );
int tpingthost( const char *hostname, int t );

#endif/*PING_H*/
