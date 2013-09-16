#include "includes.h"

#include "llist.c"
#include "andns_snsd.h"
#include "err_errno.h"
#include "andna.h"
#include "log.h"



	/* h2ip functions */

/*
 * Given a a hostname hash, makes a resolution 
 * call (service=0) and search the main ip entry,
 * storing it to snsd_node dst.
 *
 * Returns:
 * 	0
 * 	-1
 */
int snsd_main_ip(u_int *hname_hash,snsd_node *dst)
{
	snsd_service *ss;
	snsd_prio *sp;
	snsd_node *sn;
	int records;

	ss=andna_resolve_hash(hname_hash,0,0,&records);
	if (!ss) 
		err_ret(ERR_SNDMRF,-1);
	if (!(sp=ss->prio)) {
		goto destroy_return;
	}
	list_for(sp) {
		sn=sp->node;
		list_for(sn) 
			if (sn->flags & SNSD_NODE_MAIN_IP) {
				memcpy(dst,sn,sizeof(snsd_node));
				snsd_service_llist_del(&ss);
				return 0;
			}
	}
	goto destroy_return;
destroy_return:
	snsd_service_llist_del(&ss);
	err_ret(ERR_SNDMRF,-1);
}

/*
 * Convert a snsd_node to a binary ip.
 * If snsd_node does not contain a ip, but a hostname hash,
 * calls another resolution with service=0.
 *
 * Returns:
 * 	bytes writed
 * 	
 */
int snsd_node_to_data(char *buf,snsd_node *sn,u_char prio,int iplen,int recursion)
{
	int res;
	int family;

	if (recursion!=-1) {
		*buf|=sn->weight&0x3f;
		*(buf+1)|=prio;
	}

        if (! (sn->flags & SNSD_NODE_HNAME)) {
		*buf|=0x40;
		if (sn->flags & SNSD_NODE_MAIN_IP )
			*buf|=0x80;
                memcpy(buf+2,sn->record,iplen); 
		family=(iplen==4)?AF_INET:AF_INET6;
		inet_htonl((u_int*)(buf+2),family);
		return iplen+2;
        } else if (recursion) {
                snsd_node snt;
                res=snsd_main_ip(sn->record,&snt);
		if (!res) { /* I love recursion */
                	res=snsd_node_to_data(buf,&snt,prio,iplen,-1);
			return res;
		}
	}
	memcpy(buf+2,sn->record,ANDNS_HASH_H);
	return ANDNS_HASH_H+2;
}

/*
 * Converts a snsd_node struct to andns data.
 * data means a packed answer.
 * buf has to be ANDNS_MAX_ANSW_IP_LEN long.
 *
 * returns -1 on error, answer len otherwise.
 *
 *  O B S O L E T E

size_t snsd_node_to_aansw(char *buf,snsd_node *sn,u_char prio,int iplen)
{
	int res;

	res=snsd_node_to_data(buf+2,sn,iplen);
	if (res==-1) {
		error(err_str);
		return -1;
	}
	if (sn->flags & SNSD_NODE_MAIN_IP)
		*buf|=0x80;
	*buf++=sn->weight;
	*buf=prio;
	return 0; 
}
*/


/*
 * Converts a snsd_prio list to andns data.
 * data means a set of contiguous answers ready 
 * to be sent.
 *
 * Returns the number of bytes writed to buf.
 * The size is computable with iplen.
 *
 * buf has to be long enough, ie, you have to count node
 * in prio list and take ANDNS_MAX_ANSW_IP_LEN * n space.
 *
 */
int snsd_prio_to_aansws(char *buf,snsd_prio *sp,int iplen,int recursion,int *count)
{
	int res=0;
	snsd_node *sn;
	int c=0;
	
	if(!sp || !buf)
		return 0;

	sn=sp->node;
	list_for(sn) { 
		res+=snsd_node_to_data(buf+res,sn,sp->prio,
			iplen,recursion);
		c++;
	}
	*count=c;
	return res;
}

int snsd_service_to_aansws(char *buf,snsd_service *ss,int iplen,int *count,int recursion)
{
	int family,c=0;
	uint16_t service;
	uint8_t prio,proto;
	snsd_prio *sp;
	snsd_node *sn;
	char *rem;
	snsd_node snt;

	if (!ss || !buf)
		return 0;
	rem=buf;
	
	list_for(ss) {
		service=htons(ss->service);
		proto=ss->proto;
		sp=ss->prio;
		list_for(sp) {
			prio=sp->prio;
			sn=sp->node;
			list_for(sn) {
				if (sn->flags & SNSD_NODE_MAIN_IP)
					(*buf)|=0xc0;
				else if (sn->flags & SNSD_NODE_IP)
					(*buf)|=0x40;
				if (proto==ANDNS_SNSD_PROTO_UDP)
					(*buf)|=0x20;
				*buf++|=(sn->weight&0x1f);
				*buf++|=prio;
				memcpy(buf,&service,2);
				buf+=2;
				if (sn->flags & SNSD_NODE_MAIN_IP ||
				    sn->flags & SNSD_NODE_IP ) {
                			memcpy(buf,sn->record,iplen); 
					family=(iplen==4)?AF_INET:AF_INET6;
					inet_htonl((u_int*)buf,family);
					buf+=iplen;
				} else { 
					if (recursion && !snsd_main_ip(sn->record,&snt)) {
						memcpy(buf,snt.record,iplen);
						*(buf-4)|=0x40;
						family=(iplen==4)?AF_INET:AF_INET6;
						inet_htonl((u_int*)buf,family);
						buf+=iplen;
					} else {
						memcpy(buf,sn->record, ANDNS_HASH_H);
						buf+=ANDNS_HASH_H;
					}
/*					service=strlen((char*)sn->record);
					temp=htons(service);
					memcpy(buf,&temp,2);
					memcpy(buf+2,sn->record,service);
					buf+=ANDNS_HASH_H;
					res=snsd_main_ip(sn->record,&snt);
					if (res) {
						buf-=4;
						continue;
					}
					memcpy(buf,snt.record,iplen);
					family=(iplen==4)?AF_INET:AF_INET6;
					inet_htonl((u_int*)buf,family);
					buf+=iplen; */
				}
				c++;
			}
		}
	}
	*count=c;
	return (int)(buf-rem);
}
					
				
				
/*
 * Given a dns_packet, this function add an answer to it
 * and returns 0;
 * Otherwise returns -1.
 */
int snsd_node_to_dansw(dns_pkt *dp,snsd_node *sn,int iplen)
{
	char temp[18];
	dns_pkt_a *dpa;
	snsd_node snt,*s;
	int res;

	if (!(sn->flags & SNSD_NODE_HNAME)) {
		if (!(res=snsd_main_ip(sn->record,&snt)))
			return -1;
		s=&snt;
	} else 
		s=sn;

        memcpy(temp,sn->record,iplen);
        inet_htonl((u_int*)(temp),
		(iplen==4)?AF_INET:AF_INET6);
			
	dpa=DP_ADD_ANSWER(dp);
	dns_a_default_fill(dp,dpa);
	dpa->rdlength=iplen;
	memcpy(dpa->rdata,temp,iplen);
	return 0;
}
/*
 * Converts a snsd_prio struct, adding a set of answers to
 * the dns_packet dp.
 * Returns the number of answers added to dp.
 */
int snsd_prio_to_dansws(dns_pkt *dp,snsd_prio *sp,int iplen)
{
	int res=0;
	snsd_node *sn;
	
	sn=sp->node;
	list_for(sn) 
		if (!snsd_node_to_dansw(dp,sn,iplen))
			res++;
	return res;
}
		
		
		
	/* ip2h functions */

/*
 * Converts a lcl_cache struct to a set of dns answers.
 * Returns the number of answers added.
 */
int lcl_cache_to_dansws(dns_pkt *dp,lcl_cache *lc)
{
	dns_pkt_a *dpa;
	int res=0;
	
	list_for(lc) {
		dpa=DP_ADD_ANSWER(dp);
		dns_a_default_fill(dp,dpa);
		strcpy(dpa->rdata,lc->hostname);
		res++;
	}

	if(lc)
		lcl_cache_free(lc);

	return res;
}

/* 
 * Converts a lcl_cache to andns data. 
 * Returns the number of bytes writed.
 */
size_t lcl_cache_to_aansws(char *buf,lcl_cache *lc,int *count)
{
	uint16_t slen;
	size_t ret=0;
	int lcount=0;
	lcl_cache *lcl=lc;
	
	list_for(lcl) {
		slen=strlen(lc->hostname);
		ret+=2+slen;
		slen=htons(slen);
		memcpy(buf,&slen,2);
		buf+=2;
		strcpy(buf,lc->hostname);
		lcount++;
	}
	*count=lcount;
	lcl_cache_free(lc);
	return ret;
}
