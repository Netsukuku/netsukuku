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

#include "andns_lib.h"
#include "andns_net.h"
#include "log.h"
#include "err_errno.h"
#include "xmalloc.h"

#include <arpa/inet.h>
#include <zlib.h>

int andns_compress(char *src,int srclen)
{
	int res;
	uLongf space;
	
	src+=ANDNS_HDR_SZ;
	srclen-=ANDNS_HDR_SZ;
	space=compressBound(srclen);

	unsigned char dst[space+ANDNS_HDR_Z];

		/* The first four bytes will store
		 * the uncompressed size */
	res=compress2(dst+ANDNS_HDR_Z, &space,(u_char *) src, srclen,
			ANDNS_COMPR_LEVEL);
	if (res!=Z_OK) 
		err_ret(ERR_ZLIBCP,-1);
	if (space >= srclen-ANDNS_HDR_Z) /* We have to consider the four 
				  		bytes too */
		err_ret(ERR_ZLIBNU,-1); /* This is a 
					silent return */
	res=htonl(srclen);
	memcpy(dst,&res,ANDNS_HDR_Z);
	memcpy(src, dst, space);

	return (int)space;
}
char* andns_uncompress(char *src,int srclen,int *dstlen) 
{
	unsigned char *dst;
	uLongf space;
	int res;
	int c_len;
	const int hdrsz=ANDNS_HDR_SZ+ANDNS_HDR_Z;

	memcpy(&c_len,src+ANDNS_HDR_SZ,ANDNS_HDR_Z);
	c_len=ntohl(c_len);
	dst=xmalloc(c_len+ANDNS_HDR_SZ); 

	space=c_len;

	res=uncompress(dst+ANDNS_HDR_SZ,&space,(u_char*) src+hdrsz, srclen-hdrsz);
	if (res!=Z_OK) {
		xfree(dst);
		err_ret(ERR_ZLIBUP,NULL);
	}
	if ((int)space!=c_len) {
		xfree(dst);
		err_ret(ERR_ANDMAP,NULL);
	}

	memcpy(dst, src, ANDNS_HDR_SZ);
	*dstlen=c_len+ANDNS_HDR_SZ; 

	return (char*)dst;
}

/*
 * Takes the buffer stream and translate headers to
 * andns_pkt struct.
 * Returns ALWAYS 4. The pkt_len has to be controlled
 * elsewhere.
 */
int a_hdr_u(char *buf,andns_pkt *ap)
{
        uint8_t c;
        uint16_t s;
        char *start_buf;

        start_buf=buf;

	ap->r=*(buf+1)&0x01;
        memcpy(&s,buf,2);
        ap->id=ntohs(s);
	ap->id>>=1;
        buf+=2;

        memcpy(&c,buf,2);
        ap->qr=(c>>7)&0x01;
        ap->p=c&0x40?ANDNS_PROTO_UDP:ANDNS_PROTO_TCP;
	ap->z=c&0x20;
        ap->qtype=(c>>3)&0x03;
        ap->ancount=(c<<1)&0x0e;

        buf++;
        memcpy(&c,buf,sizeof(uint8_t));
        if (((*buf)&0x80)) ap->ancount++;

	ap->ipv=(c>>6)&0x01;
        ap->nk=(c>>4)&0x03;
        ap->rcode=c&0x0f;
        return ANDNS_HDR_SZ;
}
/*
 * Translate the andns_pkt question stream to andns_pkt struct.
 * -1 on error. Bytes readed otherwise.
 *  NOTE: The qst-data size is controlled: apkt won't need
 *  this control.
 */
int a_qst_u(char *buf,andns_pkt *ap,int limitlen)
{
	int ret;
	uint16_t s;

	if (limitlen<3)
		err_ret(ERR_ANDMAP,-1);

	switch(ap->qtype) {
		case AT_A:
			memcpy(&s,buf,2);
			ap->service=ntohs(s);
			buf+=2;
			if (ap->nk==NTK_REALM) {
				ap->qstlength=ANDNS_HASH_H;
				if (ap->qstlength>limitlen-2)
                			err_ret(ERR_ANDPLB,-1);
				AP_ALIGN(ap);
				memcpy(ap->qstdata,buf,ANDNS_HASH_H);
				ret=ANDNS_HASH_H+2;
			} else if (ap->nk==INET_REALM) {
				memcpy(&s,buf,2);
				ap->qstlength=ntohs(s);
				buf+=2;
        			if (ap->qstlength>=ANDNS_MAX_QST_LEN || 
					ap->qstlength>limitlen-4)
                			err_ret(ERR_ANDPLB,-1);
				AP_ALIGN(ap);
        			memcpy(ap->qstdata,buf,ap->qstlength);
				ret=ap->qstlength+4;
			} else
				return -1;
			break;
		case AT_PTR:
			ap->qstlength=ap->ipv?16:4;
			if (ap->qstlength>limitlen)
				err_ret(ERR_ANDMAP,-1)
			AP_ALIGN(ap);
			memcpy(ap->qstdata,buf,ap->qstlength);
			ret=ap->qstlength;
			break;
		case AT_G:
			if (ap->nk!=NTK_REALM)
				err_ret(ERR_ANDMAP,-1);
			ap->qstlength=ANDNS_HASH_H;
			if (ap->qstlength>limitlen)
                		err_ret(ERR_ANDPLB,-1);
			AP_ALIGN(ap);
			memcpy(ap->qstdata,buf,ANDNS_HASH_H);
			ret=ap->qstlength;
			break;
		default:
			debug(DBG_INSANE,"In a_qst_u: unknow query type.");
			err_ret(ERR_ANDMAP,-1)
	}
	return ret;
}
int a_answ_u(char *buf,andns_pkt *ap,int limitlen)
{
        uint16_t alen;
        andns_pkt_data *apd;
	int limit;

	if (limitlen<3)
		err_ret(ERR_ANDMAP,-1);
	switch (ap->qtype) {
		case AT_A:
			limit=2;
			if (limitlen<limit)
				err_ret(ERR_ANDPLB,-1);
			apd=andns_add_answ(ap);
			if (*buf&0x40) {
				apd->m|=APD_IP;
				if (*buf&0x80)
					apd->m|=APD_MAIN_IP;
				limit=ap->ipv?16:4;
			} else
				limit=ANDNS_HASH_H;
			if (limitlen<limit+2)
				err_ret(ERR_ANDPLB,-1);
			apd->wg=(*buf&0x3f);
			apd->prio=(*(buf+1));
			apd->rdlength=limit;
			APD_ALIGN(apd);
			memcpy(apd->rdata,buf+2,limit);
			limit+=2;
			break;
		case AT_PTR:
        		memcpy(&alen,buf,2);
		        alen=ntohs(alen);
        		if (alen+2>limitlen)
		                err_ret(ERR_ANDPLB,-1);
        		if (alen>ANDNS_MAX_DATA_LEN)
                		err_ret(ERR_ANDPLB,-1);
		        apd=andns_add_answ(ap);
        		apd->rdlength=alen;
			APD_ALIGN(apd);
        		memcpy(apd->rdata,buf+2,alen);
			limit=alen+2;
			break;
		case AT_G:
			if (limitlen<8)
				err_ret(ERR_ANDMAP,-1);
			apd=andns_add_answ(ap);
			if (*buf&0x40) {
				apd->m|=APD_IP;
				if (*buf&0x80)
					apd->m|=APD_MAIN_IP;
			}
			apd->m|=*buf&0x20?APD_UDP:
				APD_TCP;
			apd->wg=(*buf&0x1f);
			apd->prio=(*(buf+1));
			buf+=2;
			memcpy(&alen,buf,2);
			apd->service=ntohs(alen);
			buf+=2;
			if (apd->m&APD_IP) 
				apd->rdlength=(ap->ipv?16:4);
			else
				apd->rdlength=ANDNS_HASH_H;
			limit=4+apd->rdlength;
			if (limitlen<limit)
				err_ret(ERR_ANDPLB,-1);
			APD_ALIGN(apd);
			memcpy(apd->rdata,buf,apd->rdlength);
			break;
		default:
			err_ret(ERR_ANDMAP,-1);
	}
        return limit;
}
int a_answs_u(char *buf,andns_pkt *ap,int limitlen)
{
        int ancount,i;
        int offset=0,res;
	uint16_t alen;

	if (ap->qtype==AT_G) {
		memcpy(&alen,buf,sizeof(uint16_t));
		ap->ancount=ntohs(alen);
		offset+=2;
	} 		
	ancount=ap->ancount;
        for (i=0;i<ancount;i++) {
                res=a_answ_u(buf+offset,ap,limitlen-offset);
                if (res==-1) {
                        error(err_str);
                        err_ret(ERR_ANDMAD,-1);
                }
                offset+=res;
        }
        return offset;
}
/*
 * This is a main function: takes the pkt-buf and translate
 * it in structured data.
 * It cares about andns_pkt allocation.
 * The apkt is allocate here.
 *
 * Returns:
 * -1 on E_INTRPRT
 *  0 if pkt must be discarded.
 *  Number of bytes readed otherwise
 */
int a_u(char *buf,int pktlen,andns_pkt **app)
{
        andns_pkt *ap;
        int offset,res;
        int limitlen,u_len;
	char *u_buf;

        if (pktlen<ANDNS_HDR_SZ)
                err_ret(ERR_ANDPLB,0);
        *app=ap=create_andns_pkt();
        offset=a_hdr_u(buf,ap);

	if (ap->z) { /* Controls the space to read 
			uncompressed size */
		if (pktlen<ANDNS_HDR_SZ+ANDNS_HDR_Z) {
			destroy_andns_pkt(ap);
                	err_ret(ERR_ANDPLB,0);
		}
		if (!(u_buf=andns_uncompress(buf,pktlen,&u_len))) 
			goto andmap;
		destroy_andns_pkt(ap); 
		ANDNS_UNSET_Z(u_buf);
		res=a_u(u_buf,u_len,app);
		xfree(u_buf);
		return res;
	}
        buf+=offset;
        limitlen=pktlen-offset;
        if ((res=a_qst_u(buf,ap,limitlen))==-1) 
		goto andmap;
	offset+=res;
	if (!ap->ancount) /*No answers */
		return offset;
	buf+=res;
	limitlen-=res;
	if ((res=a_answs_u(buf,ap,limitlen))==-1) 
		goto andmap;
	offset+=res;
	if (offset!=pktlen)
		error("In a_u(): pktlen differs from readed contents: ID query %d.",ap->id);
        return offset;
andmap:
	destroy_andns_pkt(ap);
	error(err_str);
	err_ret(ERR_ANDMAP,-1);
}

int a_hdr_p(andns_pkt *ap,char *buf)
{
        uint16_t s;
	uint8_t an;
	
	ap->id<<=1;
        s=htons(ap->id);
        memcpy(buf,&s,sizeof(uint16_t));
	if (ap->r)
		*(buf+1)|=0x01;
	else	
		*(buf+1)&=0xfe;
        buf+=2;
        if (ap->qr)
                (*buf)|=0x80;
	if (ap->p)
		(*buf)|=0x40;
	if (ap->z)
		(*buf)|=0x20;
        (*buf)|=( (ap->qtype)<<3);
	an=ap->ancount;
        (*buf++)|=( (an)>>1);
        (*buf)|=( (ap->ancount)<<7);
	if (ap->ipv)
		*buf|=0x40;
        (*buf)|=( (ap->nk)<<4);
        (*buf)|=(  ap->rcode);
        return ANDNS_HDR_SZ;
}
int a_qst_p(andns_pkt *ap,char *buf,int limitlen)
{
	int ret=0;
        uint16_t s;
	int limit;

	switch(ap->qtype){
		case AT_A:
			limit=ap->nk==NTK_REALM?ANDNS_HASH_H+2:ap->qstlength+4;
			if (limitlen<limit)
				err_ret(ERR_ANDMAD,-1);
			s=htons(ap->service);
			memcpy(buf,&s,2);
			buf+=2; /* here INET and NTK REALM change */
			if (ap->nk==NTK_REALM) {
				memcpy(buf,ap->qstdata,ANDNS_HASH_H);
				ret=ANDNS_HASH_H+2;
			} else if (ap->nk==INET_REALM) {
				s=htons(ap->qstlength);
				memcpy(buf,&s,2);
				buf+=2; 
				memcpy(buf,ap->qstdata,ap->qstlength);
				ret=ap->qstlength+4;
			} else
				err_ret(ERR_ANDMAD,-1);
			break;
		case AT_PTR:
			limit=ap->ipv?16:4;
			if (limitlen<limit)
				err_ret(ERR_ANDMAD,-1);
			memcpy(buf,ap->qstdata,limit);
			ret=limit;
			break;
		case AT_G:
			limit=ANDNS_HASH_H;
			if (limitlen<limit)
				err_ret(ERR_ANDMAD,-1);
			memcpy(buf,ap->qstdata,ANDNS_HASH_H);
			ret=ANDNS_HASH_H;
			break;
		default:
			debug(DBG_INSANE,"In a_qst_p: unknow query type.");
			err_ret(ERR_ANDMAD,-1);
			break;
	}
	return ret;
}
int a_answ_p(andns_pkt *ap,andns_pkt_data *apd,char *buf,int limitlen)
{
        uint16_t s;
	int limit;
	int ret;
	
	switch(ap->qtype) {
		case AT_A:
			limit=ap->ipv?16:4;
			if (limitlen<limit+2)
                		err_ret(ERR_ANDPLB,-1);
			if (apd->m)
				*buf|=0x80;
			*buf++|= (apd->wg&0x7f);
			*buf++|=apd->prio;
			memcpy(buf,apd->rdata,limit);
			ret=limit+2;
			break;
		case AT_PTR:
			if (limitlen<apd->rdlength+2)
                		err_ret(ERR_ANDPLB,-1);
        		s=htons(apd->rdlength);
		        memcpy(buf,&s,sizeof(uint16_t));
		        buf+=2;
        		memcpy(buf,apd->rdata,apd->rdlength);
			ret=apd->rdlength+2;
			break;
		case AT_G: /* TODO */
			if (limitlen<4)
                		err_ret(ERR_ANDPLB,-1);
			if (apd->m==1)
				(*buf)|=0xc0;
			else if (apd->m)
				(*buf)|=0x40;
			*buf++|= (apd->wg&0x3f);
			*buf++|=apd->prio;
			s=htons(apd->service);
			memcpy(buf,&s,2);
			if (apd->m) {
				limit=ap->ipv?16:4;
				if (limitlen<limit+4)
                			err_ret(ERR_ANDPLB,-1);
				memcpy(buf,apd->rdata,limit);
				ret=limit+4;
			} else {
				limit=strlen(apd->rdata);
				if (limitlen<limit+6)
                			err_ret(ERR_ANDPLB,-1);
				s=htons(limit);
				memcpy(buf,&s,2);
				buf+=2;
				memcpy(buf,apd->rdata,limit);
				ret=limit+6;
			}
			break;
		default:
			debug(DBG_INSANE,"In a_answ_p(): unknow query type.");
			err_ret(ERR_ANDMAD,-1);
			break;
	}
	return ret;
}
int a_answs_p(andns_pkt *ap,char *buf, int limitlen)
{
        andns_pkt_data *apd;
        int i;
        int offset=0,res;
	uint16_t s;

	if (ap->qtype==AT_G) {
		if (limitlen<2)
			err_ret(ERR_ANDPLB,-1);
		s=htons(ap->ancount);
		memcpy(buf,&s,2);
		offset+=2;
	} 
        apd=ap->pkt_answ;
        for (i=0;i<ap->ancount && apd;i++) {
                if((res=a_answ_p(ap,apd,buf+offset,limitlen-offset))==-1) {
                        error(err_str);
                        err_ret(ERR_ANDMAD,-1);
                }
                offset+=res;
                apd=apd->next;
        }
        return offset;
}
int a_p(andns_pkt *ap, char *buf)
{
        int offset,res;

        memset(buf,0,ANDNS_MAX_SZ);

        offset=a_hdr_p(ap,buf);
        buf+=offset;
        if ((res=a_qst_p(ap,buf,ANDNS_MAX_SZ-offset))==-1)
                goto server_fail;
        offset+=res;
        buf+=res;
	if (ap->ancount) {
	        if ((res=a_answs_p(ap,buf,ANDNS_MAX_SZ-offset))==-1)
        	        goto server_fail;
	        offset+=res;
	}
        destroy_andns_pkt(ap);
	/* Compression */
	if (offset>ANDNS_COMPR_THRESHOLD) {
		res=andns_compress(buf,offset);
		if (res==-1)
			error(err_str);
		else
			return res;
	}
	/* end compression */
        return offset;
server_fail:
        destroy_andns_pkt(ap);
        error(err_str);
        err_ret(ERR_ANDMAD,-1);
}


/* MEM */

	/* Borning functions */
andns_pkt* create_andns_pkt(void)
{
        andns_pkt *ap;
        ap=xmalloc(ANDNS_PKT_SZ);
	memset(ap,0,ANDNS_PKT_SZ);
        return ap;
}

andns_pkt_data* create_andns_pkt_data(void)
{
        andns_pkt_data *apd;
        apd=xmalloc(ANDNS_PKT_DATA_SZ);
	memset(apd,0,ANDNS_PKT_DATA_SZ);
        return apd;
}
andns_pkt_data* andns_add_answ(andns_pkt *ap)
{
        andns_pkt_data *apd,*a;

        apd=create_andns_pkt_data();
        a=ap->pkt_answ;
        if (!a) {
                ap->pkt_answ=apd;
                return apd;
        }
        while (a->next) a=a->next;
        a->next=apd;
        return apd;
}
	/* Death functions */
void destroy_andns_pkt_data(andns_pkt_data *apd)
{
	if (apd->rdata)
		xfree(apd->rdata);
	xfree(apd);
}
void andns_del_answ(andns_pkt *ap)
{
	andns_pkt_data *apd,*apdt;

	apd=ap->pkt_answ;
	if (!apd)
		return;
	apdt=apd->next;
	while (apdt) {
		apd=apdt;
		apdt=apdt->next;
	}
	apd->next=NULL;
	destroy_andns_pkt_data(apdt);
}

void destroy_andns_pkt_datas(andns_pkt *ap)
{
	andns_pkt_data *apd,*apd_t;
	apd=ap->pkt_answ;
	while(apd) {
		apd_t=apd->next;
		destroy_andns_pkt_data(apd);
		apd=apd_t;
	}
}
void destroy_andns_pkt(andns_pkt *ap)
{
	if (ap->qstdata)
		xfree(ap->qstdata);
	destroy_andns_pkt_datas(ap);
        xfree(ap);
}
