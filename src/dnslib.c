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
#define _GNU_SOURCE
#include <string.h>
#include "dnslib.h"
#include "err_errno.h"
#include "log.h"
#include "xmalloc.h"

/*
 * Takes a label: is there a ptr?
 * Returns:
 *      -1  is a malformed label is found
 *       0  if there's no pointer
 *      <offset from start_pkt> if a pointer is found
 */
int getlblptr(char *buf)
{
        uint16_t dlbl;
        char c[2];

        memcpy(c,buf,2);

        if (!LBL_PTR(*c)) /* No ptr */ 
		return 0;
        if (LBL_PTR(*c)!=LBL_PTR_MASK) {
		debug(DBG_INSANE,"In getlblptr: invalid octet %02x",(unsigned char)c[0]);
                err_ret(ERR_DNSMLO,-1);
	}
        (*c)&=LBL_PTR_OFF_MASK;
        memcpy(&dlbl,c,2);
        dlbl=ntohs(dlbl);
        return dlbl; /* offset */
}
/*
 * Reads a contiguous octet-sequence-label.
 * Writes on dst.
 * There are two limits: 
 * 	the name has to be less than MAX_SEQ_LBL_LEN
 * 	we must stay in pkt_len
 * -limit- is the less limit
 * 
 * Returns:
 *      -1 On error
 *      Bytes readed if OK
 */
int read_label_octet(const char *src,char *dst,int limit)
{
        int how;

        how=*src++;
	if ( how > limit || how > DNS_MAX_LABELS) {
		error("In read_label_octet: got %d with limti %d\n",how,limit);
		err_ret(ERR_DNSMSL,-1);
	}
	memcpy(dst,src,how);
	return how;
}
/*
 * Converts a dns compliant sequence label name to string.
 * we start to read at -buf-
 * we need start_pkt for pointers
 * we need limit to remain under pktlen
 * Returns:
 *      Bytes readed if OK
 *      -1 on error
 */
int lbltoname(char *buf,char *start_pkt,char *dst,int limit)
{
        char *crow;
        int how,recursion=0;
        int ptr;
        int writed=0,readed=0;
        int new_limit=limit;

        crow=buf;

        while (*crow) {
                ptr=getlblptr(crow);
                if (ptr) { /* Got a pointer.... or got an error*/
                        if (ptr==-1) {
                                debug(DBG_INSANE,err_str);
                                err_ret(ERR_DNSMSL,-1);
                        }
                        if (++recursion>MAX_RECURSION_PTR) 
                                err_ret(ERR_DNSTRP,-1);
                        if (recursion==1) readed+=2; /* we read the pointer */
                        crow=start_pkt+ptr;
                        new_limit=limit - (int)(crow - buf);
                        if (new_limit<=0 || new_limit > (int)(buf-start_pkt)+limit) 
                                err_ret(ERR_DNSPLB,-1);
                        if (getlblptr(crow)) 
                                err_ret(ERR_DNSPTP,-1);
                }
                how=read_label_octet(crow,dst,min(new_limit,DNS_MAX_HNAME_LEN-writed));
                if (how==-1) {
			debug(DBG_INSANE,err_str);
                        err_ret(ERR_DNSMSL,-1);
		}
                if (!recursion)
                        readed+=how+1;
                writed+=how+1;
                dst+=how;
                crow+=how+1;
                *dst++=(*crow)?'.':0;
        }
        if (!recursion) readed++;
        return readed;
}
/*
 * DNS PTR query ask for 4.3.2.1.in-addr.arpa to know
 * who is 1.2.3.4.
 * This function reads this type of query transalting it
 * in the second form.
 * Writes result on *dst.
 * -1 on error.
 */

int swap_straddr(char *src,char *dst)
{
        char a[3];
        int i,slen;
        char *crow,*tmp,*atom;
        int count=0,offset=0;

        slen=strlen(src);
        if (slen>DNS_MAX_HNAME_LEN)
                goto mlf_addr;
        tmp=src;
        for (i=0;i<4;i++) {
                count=0;
                atom=a;
                while (*tmp && *tmp!='.') {
                        if (count>2)
                                goto mlf_addr;
                        *atom++=*tmp++;
                        count++;
                }
                if (!count)
                        goto mlf_addr;
                crow=dst+slen-count-offset;
                strncpy(crow,a,count);
                offset+=count;
                if (!(*tmp))
                        break;
                else {
                        if (i==3)
                                goto mlf_addr;
                        *(crow-1)='.';
                        offset++;
                        tmp++;
                }

        }
        *(dst+slen)=0;
        return 0;
mlf_addr:
        debug(DBG_INSANE,"in swap_straddr: invalid address `%s`.\n",src);
	err_ret(ERR_DNSMDD,-1);
}
int swap_straddr6(char *src,char *dst)
{
        int slen;
        char *tmp;
        slen=strlen(src);
        tmp=src+slen-1;
        while (tmp!=src)
                *dst++=*tmp--;
        *dst++=*tmp;
        *dst=0;
        return 0;
}
int rm_inv_prefix(char *src,char *dst) 
{
	char *temp;
	int ret;
        if (!src) {
                debug(DBG_INSANE,"In rm_inv_prefix: NULL argument!");
                err_ret(ERR_DNSMDD,-1);
        }
        if( ! \
          ( (temp=(char*)strcasestr(src,DNS_INV_PREFIX))  ||\
            (temp=(char*)strcasestr(src,DNS_INV_PREFIX6)) ||\
            (temp=(char*)strcasestr(src,OLD_DNS_INV_PREFIX6)))) {
                debug(DBG_INSANE,"In rm_inv_prefix(): no suffix for PTR query.");
                err_ret(ERR_DNSMDD,-1);
        }
	if (temp-src>=DNS_MAX_HNAME_LEN) {
		error("In rm_inv_prefix(): name too long.");
                err_ret(ERR_DNSMDD,-1);
        }
	ret=strstr(temp,"6")?AF_INET6:AF_INET;
	strncpy(dst,src,temp-src);
	dst[temp-src]=0;
	return ret;
}
int add_inv_prefix(char *s,int family)
{
	int len;

	len=strlen(s);
	if (family==AF_INET) 
		strcat(s,DNS_INV_PREFIX);
	else
		strcat(s,DNS_INV_PREFIX6);
	return 0;
}
	
int swapped_straddr(char *src,char *dst) 
{
	char temp[DNS_MAX_HNAME_LEN];
	int res;

	res=rm_inv_prefix(src,temp);
	if (res==-1) {
		error(err_str);
		err_ret(ERR_DNSMDD,-1);
	}
	if (res==AF_INET)
		res=swap_straddr(temp,dst);
	else
		res=swap_straddr6(temp,dst);
	if (res==-1) {
		error(err_str);
		err_ret(ERR_DNSMDD,-1);
	}
	return 0;
}
int swapped_straddr_pref(char *src,char *dst,int family)
{
	int res;

	if (family==AF_INET)
		res=swap_straddr(src,dst);
	else
		res=swap_straddr6(src,dst);
	if (res==-1) {
		error(err_str);
		err_ret(ERR_DNSMDD,-1);
	}
	add_inv_prefix(dst,family);
	return 0;
}

/*
 * Converts a domain_name_string into a sequence label format,
 * dns compliant. Writes on dst.
 * -1 on error, number of bytes writed on success
 */
int nametolbl(char *name,char *dst)
{
        char *crow;
        int offset=0,res;

	if (strlen(name)>DNS_MAX_HNAME_LEN) {
		debug(DBG_INSANE,"Malformed name: %s.",name);
		err_ret(ERR_DNSMDA,-1);
	}
        while ((crow=strstr(name+1,"."))) {
                res=crow-name;
                if (res>DNS_MAX_LABELS) {
			debug(DBG_INSANE,"Malformed name: %s.",name);
			err_ret(ERR_DNSMDA,-1);
		}
                *dst=(char)res; /* write the octet length */
                dst++;
                offset++;
                memcpy(dst,name,(size_t)res); /* write label */
                name+=res+1;dst+=res;offset+=res; /* shift ptrs */
        }
        if (!name) return offset;
        if((res=(char)strlen(name))>DNS_MAX_LABELS) {
                        debug(DBG_INSANE,"Malformed name: %s",name);
                        err_ret(ERR_DNSMDA,-1);
        }
        *dst++=(char)res;
        strcpy(dst,name);
        offset+=res+2;
        return offset;
}
/*
 * Disassembles DNS packet headers, writing a yet allocated
 * dns_pkt_hdr struct.
 * No controls on len, bcz <<--the min_pkt_len is controlled
 * by recv.-->>
 * Returns the number of bytes readed (always DNS_HDR_SZ).
 */
int d_hdr_u(char *buf,dns_pkt_hdr *dph)
{
        uint8_t c;
        uint16_t s;

                // ROW 1
        memcpy(&s,buf,sizeof(uint16_t));
        dph->id=ntohs(s);
                // ROW 2
        buf+=2;
        memcpy(&c,buf,sizeof(uint8_t));
        dph->qr= (c>>7)&0x01;
        dph->opcode=(c>>3)&0x0f;
        dph->aa=(c>>2)&0x01;
        dph->tc=(c>>1)&0x01;
        dph->rd=c&0x01;

        buf++;
        memcpy(&c,buf,sizeof(uint8_t));
        dph->ra=(c>>7)&0x01;
        dph->z=(c>>4)&0x07;
        dph->rcode=c&0x0f;

                // ROW 3
        buf++;
        memcpy(&s,buf,sizeof(uint16_t));
        dph->qdcount=ntohs(s);
                // ROW 4
        buf+=2;
        memcpy(&s,buf,sizeof(uint16_t));
        dph->ancount=ntohs(s);
                // ROW 5
        buf+=2;
        memcpy(&s,buf,sizeof(uint16_t));
        dph->nscount=ntohs(s);
                // ROW 6
        buf+=2;
        memcpy(&s,buf,sizeof(uint16_t));
        dph->arcount=ntohs(s);

        buf+=2;
        return DNS_HDR_SZ; // i.e. 12 :)
}
/*
 * This function alloc a new dns_pkt_qst to store a dns_question_section.
 * The new dns_pkt_qst is also added to the principal dp-struct
 * Returns bytes readed if OK. -1 otherwise.
 */
int d_qst_u(char *start_buf,char *buf,dns_pkt *dp,int limit_len)
{
        int count;
        uint16_t s;
        dns_pkt_qst *dpq;

        dpq=dns_add_qst(dp);

        /* get name */
        if((count=lbltoname(buf,start_buf,dpq->qname,limit_len))==-1) {
                error(err_str);
                err_ret(ERR_DNSMDD,1);
        }
        buf+=count;
        /* Now we have to write 2+2 bytes */
        if (count+4>limit_len)
                err_ret(ERR_DNSPLB,1);

        /* shift to type and class */
        memcpy(&s,buf,2);
        dpq->qtype=ntohs(s);
        count+=2;
        buf+=2;

        memcpy(&s,buf,2);
        dpq->qclass=ntohs(s);
        count+=2;

        return count;
}

/*
 * Disassembles a DNS qst_section_set.
 * Use the above function for each question section.
 * -1 on error. Number of bytes readed on success.
 *  If -1 is returned, rcode ha sto be set to E_INTRPRT
 */
int d_qsts_u(char *start_buf,char *buf,dns_pkt *dp,int limit_len)
{
        int offset=0,res;
        int i,count;

        if (!(count=DP_QDCOUNT(dp)))
                return 0; /* No questions. */

        for(i=0;i<count;i++) {
                if ( (res=d_qst_u(start_buf,buf+offset,dp,limit_len-offset))==-1) {
                        error(err_str);
                        err_ret(ERR_DNSMDD,-1);
                }
                offset+=res;
        }
        return offset;
}
/*
 * The behavior of this function is in all similar to dpkttoqst.
 * Returns -1 on error. Bytes readed otherwise.
 */
int d_a_u(char *start_buf,char *buf,dns_pkt_a **dpa_orig,int limit_len)
{
        int count,rdlen;
        dns_pkt_a *dpa;
        uint16_t s;
        uint32_t ui;

        dpa=dns_add_a(dpa_orig);

        /* get name */
        if((count=lbltoname(buf,start_buf,dpa->name,limit_len))==-1) {
                error(err_str);
                err_ret(ERR_DNSMDD,-1);
        }
        buf+=count;
        /* Now we have to write 2+2+4+2 bytes */
        if (count+10>limit_len)
                err_ret(ERR_DNSPLB,-1);

        memcpy(&s,buf,2);
        dpa->type=ntohs(s);
        count+=2;
        buf+=2;

        memcpy(&s,buf,2);
        dpa->cl=ntohs(s);
        count+=2;
        buf+=2;

        memcpy(&ui,buf,4);
        dpa->ttl=ntohl(ui);
        count+=4;
        buf+=4;

        memcpy(&s,buf,2);
        dpa->rdlength=ntohs(s);
        count+=2;
        buf+=2;

        rdlen=dpa->rdlength;
        if (rdlen>DNS_MAX_HNAME_LEN) 
		err_ret(ERR_DNSMDD,-1);
        /* Now we have to write dpa->rdlength bytes */
        if (count+rdlen>limit_len)
                err_ret(ERR_DNSPLB,-1);
        if (dpa->type==T_A) {
                memcpy(dpa->rdata,buf,rdlen); /* 32bit address */
		count+=rdlen;
	}
        else if (dpa->type==T_MX) {
		memcpy(dpa->rdata,buf,2);
                if ((ui=lbltoname(buf+2,start_buf,dpa->rdata+2,rdlen-2))==-1) {
                        error(err_str);
                        err_ret(ERR_DNSMDD,-1);
                }
		if (rdlen!=ui+2) {
			debug(DBG_NORMAL,"In d_a_u(): rdlen (%d) differs from readed bytes (%d).",rdlen,ui+2);
			err_ret(ERR_DNSMDD,-1);
		}
		count+=2+ui;
	} else {
                if ((ui=lbltoname(buf,start_buf,dpa->rdata,rdlen))==-1) {
                        error(err_str);
                        err_intret(ERR_DNSMDD);
                }
		if (rdlen!=ui) {
			debug(DBG_NORMAL,"In d_a_u(): rdlen (%d) differs from readed bytes (%d).",rdlen,ui);
			err_ret(ERR_DNSMDD,-1);
		}
		count+=ui;
	}
        return count;
}
/*
 * like d_qs_u. count is the number of section to read.
 * -1 on error.  Bytes readed otherwise.
 */
int d_as_u(char *start_buf,char *buf,dns_pkt_a **dpa,int limit_len,int count)
{
        int offset=0,res;
        int i;

        if (!count) return 0;
        for(i=0;i<count;i++) {
                if ((res=d_a_u(start_buf,buf+offset,dpa,limit_len-offset))==-1) {
                        error(err_str);
                        err_intret(ERR_DNSMDD);
                }
                offset+=res;
        }
        return offset;
}
/*
 * This is a main function: takes the pkt-buf and translate
 * it in structured data.
 * It cares about dns_pkt allocations.
 *
 * Returns:
 * -1 on E_INTRPRT
 *  0 if pkt must be discarded.
 *  Number of bytes readed otherwise
 */
int d_u(char *buf,int pktlen,dns_pkt **dpp)
{
        dns_pkt *dp;
        int offset=0,res;
        char *crow;

        crow=buf;
        /* Controls pkt consistency: we must at least read pkt headers */
        if (pktlen<DNS_HDR_SZ) 
		err_ret(ERR_DNSMDP,0);
        *dpp=dp=create_dns_pkt();

        /* Writes headers */
        offset+=d_hdr_u(buf,&(dp->pkt_hdr));
        if (pktlen > DNS_MAX_SZ) /* If pkt is too long: the headers are written,
                                  * so we can reply with E_INTRPRT
				  */
                err_intret(ERR_DNSPLB);
        crow+=offset;
        /* Writes qsts */
	if (dp->pkt_hdr.qdcount) {
	        if ((res=d_qsts_u(buf,crow,dp,pktlen-offset))==-1) {
        	        error(err_str);
                	err_intret(ERR_DNSMDP);
        	}
        	offset+=res;
        	crow+=res;
	}

	if (dp->pkt_hdr.ancount) {
	        if ((res=d_as_u(buf,crow,&(dp->pkt_answ),pktlen-offset,DP_ANCOUNT(dp)))==-1) {
        	        error(err_str);
                	err_intret(ERR_DNSMDP);
	        }
        	offset+=res;
	}
        /*crow+=res;
        if ((res=dpkttoas(buf,crow,&(dp->pkt_auth),pktlen-offset,DP_NSCOUNT(dp)))==-1)
                return -1;
        offset+=res;
        crow+=res;
        if ((res=dpkttoas(buf,crow,&(dp->pkt_add),pktlen-offset,DP_ARCOUNT(dp)))==-1)
                return -1;*/
        return offset;
}
/*
 * This function is the d_hdr_u inverse.
 * Takes a dns_pkt struct and builds the
 * header pkt-buffer
 * Returns the number of bytes writed.
 */
int d_hdr_p(dns_pkt *dp,char *buf)
{
        char *crow=buf;
        uint16_t u;
        dns_pkt_hdr *dph;

        dph=&(dp->pkt_hdr);
        u=htons(dph->id);
        memcpy(buf,&u,2);
        buf+=2;

        if (dph->qr) *buf|=0x80;
        *buf|=dph->opcode<<3;
        *buf|=dph->aa<<2;
        *buf|=dph->tc<<1;
        *buf|=dph->rd;

        buf++;
        *buf|=dph->ra<<7;
        *buf|=dph->z<<4;
        *buf|=dph->rcode;

        buf++;

        u=htons(dph->qdcount);
        memcpy(buf,&u,2);
        buf+=2;
        u=htons(dph->ancount);
        memcpy(buf,&u,2);
        buf+=2;
        u=htons(dph->nscount);
        memcpy(buf,&u,2);
        buf+=2;
        u=htons(dph->arcount);
        memcpy(buf,&u,2);
        buf+=2;
        return (int)(buf-crow);
}
/*
 * Translate a struct dns_pkt_qst in the dns-buffer buf.
 * Returns:
 *      -1 On error
 *      Bytes writed otherwise.
 */
int d_qst_p(dns_pkt_qst *dpq,char *buf, int limitlen)
{
        int offset;
        uint16_t u;

        if((offset=nametolbl(dpq->qname,buf))==-1) {
                error(err_str);
                err_ret(ERR_DNSMDA,-1);
        }
        if (offset+4>limitlen) 
                err_ret(ERR_DNSPLB,-1);
        buf+=offset;
        u=htons(dpq->qtype);
        memcpy(buf,&u,2);
        buf+=2;offset+=2;
        u=htons(dpq->qclass);
        memcpy(buf,&u,2);
        buf+=2;offset+=2;
        return offset;
}
/*
 * Translates the question sections of a struct dns_pkt
 * into buf.
 * Returns:
 *      -1 on error.
 *      Number of bytes writed otherwise,
 */
int d_qsts_p(dns_pkt *dp,char *buf,int limitlen)
{
        int offset=0,res;
        int i;
        dns_pkt_qst *dpq;
        dpq=dp->pkt_qst;

        for (i=0;dpq && i<DP_QDCOUNT(dp);i++) {
                if ((res=d_qst_p(dpq,buf+offset,limitlen-offset))==-1) {
                        error(err_str);
                        err_ret(ERR_DNSMDA,-1);
                }
                offset+=res;
                dpq=dpq->next;
        }
        return offset;
}
int d_a_p(dns_pkt_a *dpa,char *buf,int limitlen)
{
        int offset,rdlen;
        uint16_t u;
        int i;

        if((rdlen=nametolbl(dpa->name,buf))==-1)
                return -1;
        offset=rdlen;
        if (offset+10>limitlen)
                err_intret(ERR_DNSPLB);
        buf+=offset;
        u=htons(dpa->type);
        memcpy(buf,&u,2);
        buf+=2;offset+=2;
        u=htons(dpa->cl);
        memcpy(buf,&u,2);
        buf+=2;offset+=2;
        i=htonl(dpa->ttl);
        memcpy(buf,&i,4);
        buf+=4;offset+=4;

        if (dpa->type==T_A) {
                if (offset+dpa->rdlength>limitlen)
                        err_intret(ERR_DNSPLB);
                memcpy(buf+2,dpa->rdata,dpa->rdlength);
                offset+=dpa->rdlength;
        } else if (dpa->type==T_MX) {
		memcpy(buf+2,dpa->rdata,2);
                if ((rdlen=nametolbl(dpa->rdata+2,buf+4))==-1) {
                        error(err_str);
                        err_ret(ERR_DNSMDA,-1);
                }
                offset+=rdlen+2;
                if (offset>limitlen)
                        err_ret(ERR_DNSPLB,-1);
                dpa->rdlength=rdlen+2;
	} else {
                if ((rdlen=nametolbl(dpa->rdata,buf+2))==-1) {
                        error(err_str);
                        err_ret(ERR_DNSMDA,-1);
                }
                offset+=rdlen;
                if (offset>limitlen)
                        err_ret(ERR_DNSPLB,-1);
                dpa->rdlength=rdlen;
        }
        u=htons(dpa->rdlength);
        memcpy(buf,&u,2);
        offset+=2;
        return offset;
}
int d_as_p(dns_pkt_a *dpa,char *buf,int limitlen,int count)
{
        int offset=0,res;
        int i;
        for (i=0;dpa && i<count;i++) {
                if ((res=d_a_p(dpa,buf+offset,limitlen-offset))==-1) {
                        error(err_str);
                        err_ret(ERR_DNSMDA,-1);
                }
                offset+=res;
                dpa=dpa->next;
        }
        return offset;
}
/*
 * Transform a dns_pkt structure in char stream.
 *
 * Returns:
 *      -1 on error
 *      len(stream) if OK
 *
 * The stream has at least the header section writed.
 * `buf' must be at least of DNS_MAX_SZ bytes.
 *
 * DANGER: This function realeses *ALWAYS* the dns_pkt *dp!!!!
 */
int d_p(dns_pkt *dp,char *buf)
{
        int offset,res;

        memset(buf,0,DNS_MAX_SZ);

        offset=d_hdr_p(dp,buf);
        buf+=offset;
        if((res=d_qsts_p(dp,buf,DNS_MAX_SZ-offset))==-1)
                goto server_fail;
        offset+=res;
        buf+=res;
        if ( (res=d_as_p(dp->pkt_answ,buf,DNS_MAX_SZ-offset,DP_ANCOUNT(dp)))==-1)
                goto server_fail;
        offset+=res;
        /*buf+=res;
        if ( (res=astodpkt(dp->pkt_auth,buf,DNS_MAX_SZ-offset,DP_NSCOUNT(dp)))==-1)
                goto server_fail;
        offset+=res;
        buf+=res;*/
        /*if ( (res=astodpkt(dp->pkt_add,buf,DNS_MAX_SZ-offset,DP_ARCOUNT(dp)))==-1)
                goto server_fail;
        offset+=res;*/
        destroy_dns_pkt(dp);
        return offset;
server_fail:
        error(err_str);
        destroy_dns_pkt(dp);
	err_ret(ERR_DNSPDS,-1);
}


/* Memory Functions */

dns_pkt* create_dns_pkt(void)
{
        dns_pkt *dp;
        dp=xmalloc(DNS_PKT_SZ);
        memset(dp,0,DNS_PKT_SZ);
        dp->pkt_qst=NULL;
        dp->pkt_answ=NULL;
        dp->pkt_add=NULL;
        dp->pkt_auth=NULL;
        return dp;
}

dns_pkt_qst* create_dns_pkt_qst(void)
{
        dns_pkt_qst *dpq;
        dpq=xmalloc(DNS_PKT_QST_SZ);
        dpq->next=NULL;
        memset(dpq->qname,0,DNS_MAX_HNAME_LEN);
        return dpq;
}
dns_pkt_a* create_dns_pkt_a(void)
{
        dns_pkt_a *dpa;
        dpa=xmalloc(DNS_PKT_A_SZ);
        memset(dpa->name,0,DNS_MAX_HNAME_LEN);
        memset(dpa->rdata,0,DNS_MAX_HNAME_LEN);
        dpa->next=NULL;
        return dpa;
}

dns_pkt_qst* dns_add_qst(dns_pkt *dp)
{
        dns_pkt_qst *dpq,*temp;
        dpq=create_dns_pkt_qst();
        temp=dp->pkt_qst;
        if (!temp) {
                dp->pkt_qst=dpq;
                return dpq;
        }
        while (temp->next) temp=temp->next;
        temp->next=dpq;
        return dpq;
}
void dns_del_last_qst(dns_pkt *dp)
{
        dns_pkt_qst *dpq=dp->pkt_qst;
        if (!dpq) return;
        if (!(dpq->next)){
                xfree(dpq);
                dp->pkt_qst=NULL;
                return;
        }
        while ((dpq->next)->next);
        xfree(dpq->next);
        dpq->next=NULL;
        return;
}

dns_pkt_a* dns_add_a(dns_pkt_a **dpa)
{
        dns_pkt_a *dpa_add,*a;
        int count=0;

        a=*dpa;
        dpa_add=create_dns_pkt_a();
        if (!a) {
                (*dpa)=dpa_add;
        }
        else {
                while (a->next) {
                        a=a->next;
                        count++;
                }
                a->next=dpa_add;
        }
        return dpa_add;
}
void dns_a_default_fill(dns_pkt *dp,dns_pkt_a *dpa)
{
	strcpy(dpa->name,dp->pkt_qst->qname);
	dpa->cl=C_IN;
	dpa->ttl=DNS_TTL;
	dpa->type=dp->pkt_qst->qtype;
}
void destroy_dns_pkt(dns_pkt *dp)
{
        dns_pkt_a *dpa,*dpa_t;
        dns_pkt_qst *dpq,*dpq_t;

        if (dp->pkt_qst) {
                dpq=dp->pkt_qst;
                while (dpq) {
                        dpq_t=dpq->next;
                        xfree(dpq);
                        dpq=dpq_t;
                }
        }
        if (dp->pkt_answ) {
                dpa=dp->pkt_answ;
                while (dpa) {
                        dpa_t=dpa->next;
                        xfree(dpa);
                        dpa=dpa_t;
                }
        }
        if (dp->pkt_add) {
                dpa=dp->pkt_add;
                while (dpa) {
                        dpa_t=dpa->next;
                        xfree(dpa);
                        dpa=dpa_t;
                }
        }
        if (dp->pkt_auth) {
                dpa=dp->pkt_auth;
                while (dpa) {
                        dpa_t=dpa->next;
                        xfree(dpa);
                        dpa=dpa_t;
                }
        }
        xfree(dp);
        return;
}

