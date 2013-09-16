	         /**************************************
	        *     AUTHOR: Federico Tomassini        *
	       *     Copyright (C) Federico Tomassini    *
	      *     Contact effetom@gmail.com             *
	     ***********************************************
	     *******          BEGIN 4/2006          ********
*************************************************************************
*                                              				* 
*  This program is free software; you can redistribute it and/or modify	*
*  it under the terms of the GNU General Public License as published by	*
*  the Free Software Foundation; either version 2 of the License, or	*
*  (at your option) any later version.					*
*									*
*  This program is distributed in the hope that it will be useful,	*
*  but WITHOUT ANY WARRANTY; without even the implied warranty of	*
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the	*
*  GNU General Public License for more details.				*
*									*
************************************************************************/

#include "log.h"
#include "andns_net.h"

int idp_inet_ntop(int family,struct sockaddr *addr,char *buf,int buflen)
{
	const char *res;
	struct sockaddr_in *saddr;
	struct sockaddr_in6 *saddr6;

	switch(family) {
		case AF_INET:
			saddr=(struct sockaddr_in*)addr;
			res=inet_ntop(family,(void*)(&(saddr->sin_addr)),buf,buflen);
			break;
		case AF_INET6:
			saddr6=(struct sockaddr_in6*)addr;
			res=inet_ntop(family,(void*)(&(saddr6->sin6_addr)),buf,buflen);
			break;
		default:
			return -1;
	}
	if (!res)
		return -1;
	return 0;
}
/* Connection Layer */

int w_socket(int family,int type, int proto,int die)
{
	int sk;
	sk=socket(family,type,proto);
	if (sk==-1) {
		if (die)
			fatal("w_socket: %s.",strerror(errno));
		debug(DBG_NORMAL,"w_socket: %s.",strerror(errno));
		return -1;
	}
	return sk;
}

int w_connect(struct addrinfo *ai,int die) 
{
	int sk,res;
	sk=w_socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol,die);
	res=connect(sk,ai->ai_addr,ai->ai_addrlen);
	if (!res) 
		return sk;
	if (die)
		fatal("Unable to connect: %s.", strerror(errno));
	debug(DBG_NORMAL,"w_connect: %s.",strerror(errno));
	close(sk);
	return -1;
}
int serial_connect(struct addrinfo *ai,int die)
{
	int res;
	struct addrinfo *temp;

	temp=ai;
	if (!temp) {
		if (die)
			fatal("Unable to connect: no host specified.");
		debug(DBG_NORMAL,"serial_connect: no host specified.");
		return -1;
	}
	do {
		res=w_connect(temp,0);
		temp=temp->ai_next;
	} while (res==-1 && temp);
	if (res==-1)  {
		if (die)
			fatal("Unable to connect.");
		debug(DBG_NORMAL,"serial_connect: unable to connect.");
		return -1;
	}
	return res;
}
	
/*
 * host_connect returns a connected socket to (host,port)
 * endpoint. It is protocol independent.
 * -1 on error.
 */
int host_connect(const char *host,uint16_t port,int type,int die) 
{
	int res;
	char portstr[6];
	struct addrinfo *ai,filter;

	memset(&filter,0,sizeof(struct addrinfo));
	filter.ai_socktype=type;
	if (!host)
		fatal("w_connect: malicious call.");
	memset(portstr,0,6);
	res=snprintf(portstr,6,"%d",port);
	if (res<0 || res>=6) {
		printf("Depousceve\n");
		return -1;
	}
	res=getaddrinfo(host,portstr,&filter,&ai);
	if (res!=0) {
		printf("w_connect: error %s.\n",gai_strerror(errno));
		return -1;
	}
	res=serial_connect(ai,die);
	freeaddrinfo(ai);
	return res;
}
int ai_connect(struct addrinfo *ai,int die,int free_ai)
{
	int res;

	res=serial_connect(ai,die);
	if (free_ai)
		freeaddrinfo(ai);
	return res;
}

/* Communication Layer */

ssize_t w_send(int sk,const void *buf,size_t len,int die) 
{
	ssize_t ret;

	ret=send(sk,buf,len,0);
	if (ret!=len) {
		if (die)
			fatal("Unable to send(): %s.",strerror(errno));
		debug(DBG_NORMAL,"w_send(): %s.",strerror(errno));
	}
	return ret;
}

ssize_t w_recv(int sk,void *buf,size_t len,int die)
{
	ssize_t ret;

	ret=recv(sk,buf,len,0);
	if (ret<=0) {
		if (die)
			fatal("Unable to recv(): %s.",strerror(errno));
		debug(DBG_INSANE,"w_recv(): %s.",strerror(errno));
	}
	return ret;
}


/* 
 * These two functions and the MACRO are
 * almost VERBATIM copied from inet.c and inet.h.
 * Functions by AlpT, Andrea Lo Pumo.
 */

#define MILLISEC_TO_TV(x,t)                                             \
do{                                                                     \
        (t).tv_sec=(x)/1000;                                            \
        (t).tv_usec=((x) - ((x)/1000)*1000)*1000;                       \
}while(0)

ssize_t w_send_timeout(int s,const void *buf,size_t len,int die,int timeout)
{
        struct timeval timeout_t;
        fd_set fdset;
        int ret;

        MILLISEC_TO_TV(timeout*1000, timeout_t);

        FD_ZERO(&fdset);
        FD_SET(s, &fdset);

        ret = select(s+1, &fdset, NULL, NULL, &timeout_t);
        if (ret == -1) {
		if (die)
			fatal("send(): select error.");
		debug(DBG_NORMAL,"send(): select error.");
		return ret;
        }

        if(FD_ISSET(s, &fdset))
                return w_send(s, buf, len, die);
        return -1;
}

ssize_t w_recv_timeout(int s,void *buf,size_t len,int die,int timeout)
{
        struct timeval timeout_t;
        fd_set fdset;
        int ret;

        MILLISEC_TO_TV(timeout*1000, timeout_t);

        FD_ZERO(&fdset);
        FD_SET(s, &fdset);

        ret = select(s+1, NULL, &fdset, NULL, &timeout_t);

        if (ret == -1) {
		if (die)
			fatal("recv(): select error.");
		debug(DBG_NORMAL,"recv(): select error.");
		return ret;
        }

        if(FD_ISSET(s, &fdset))
                return w_recv(s, buf, len, die);
        return -1;
}


	
/* Dialog Layer */

/* "Botta e risposta" */
ssize_t hn_send_recv_close(const char *host,uint16_t port,int type,void *buf,
		size_t buflen,void *anbuf,size_t anlen,int die,int timeout)
{
	ssize_t ret;
	int res;

	res=host_connect(host,port,type,die);
	if (res==-1) 
		return -1;
	if (timeout)
		ret=w_send_timeout(res,buf,buflen,die,timeout);
	else
		ret=w_send(res,buf,buflen,die);
	if (ret==-1) 
		return -2;
	if (timeout)
		ret=w_recv_timeout(res,anbuf,anlen,die,timeout);
	else
		ret=w_recv(res,anbuf,anlen,die);
	if (ret==-1)
		return -3;
	close(res);
	return ret;
}
/* "Botta e risposta" */
ssize_t ai_send_recv_close(struct addrinfo *ai,void *buf,size_t buflen,
		void *anbuf,size_t anlen,int die,int free_ai,int timeout)
{
	ssize_t ret;
	int res;

	res=ai_connect(ai,die,free_ai);
	if (res==-1) 
		return -1;
	if (timeout)
		ret=w_send_timeout(res,buf,buflen,die,timeout);
	else
		ret=w_send(res,buf,buflen,die);
	if (ret==-1) 
		return -2;
	if (timeout)
		ret=w_recv_timeout(res,anbuf,anlen,die,timeout);
	else
		ret=w_recv(res,anbuf,anlen,die);
	if (ret==-1) 
		return -3;
	close(res);
	return ret;
}
	
void char_print(char *buf, int len)
{
        int i,count=0;

        printf("Printing %d bytes\n",len);
        for (i=0;i<len;i++) {
                printf("%02X ", (unsigned char)(buf[i]));
                count++;
                if ((count%16)==0) printf("\n");
        }
        printf("\n");
        return;
}

