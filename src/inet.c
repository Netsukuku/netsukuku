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

#include "common.h"
#include "ipv6-gmp.h"
#include "libnetlink.h"
#include "ll_map.h"
#include "inet.h"
#include "endianness.h"


/* 
 * inet_ntohl: Converts each element of `data' from network to host order. If
 * `family' is equal to AF_INET6, the array is swapped too (on big endian
 * machine).
 */
void inet_ntohl(u_int *data, int family)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	if(family==AF_INET) {
		data[0]=ntohl(data[0]);
	} else {
		int i;
		swap_ints(MAX_IP_INT, data, data);
		for(i=0; i<MAX_IP_INT; i++)
			data[i]=ntohl(data[i]);
	}
#endif
}

/* 
 * inet_htonl: Converts each element of `data' from host to network order. If
 * `family' is equal to AF_INET6, the array is swapped too (on big endian
 * machine).
 */
void inet_htonl(u_int *data, int family)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	if(family==AF_INET) {
		data[0]=htonl(data[0]);
	} else {
		int i;
		swap_ints(MAX_IP_INT, data, data);
		for(i=0; i<MAX_IP_INT; i++)
			data[i]=htonl(data[i]);
	}
#endif
}

/*
 * inet_setip_raw: fills the `ip' inet_prefix struct with `data' and `family'.
 */
int inet_setip_raw(inet_prefix *ip, u_int *data, int family)
{
	ip->family=family;
	setzero(ip->data, sizeof(ip->data));
	
	if(family==AF_INET) {
		ip->data[0]=data[0];
		ip->len=4;
	} else if(family==AF_INET6) {
		memcpy(ip->data, data, sizeof(ip->data));
		ip->len=16;
	} else 
		fatal(ERROR_MSG "family not supported", ERROR_POS);

	ip->bits=ip->len<<3; /* bits=len*8 */
	
	return 0;
}


/*
 * inet_setip: fills the `ip' inet_prefix struct with `data' and `family'.
 * Note that it does a network to host order conversion on `data'.
 */
int inet_setip(inet_prefix *ip, u_int *data, int family)
{
	inet_setip_raw(ip, data, family);
	inet_ntohl(ip->data, ip->family);
	return 0;
}

int inet_setip_bcast(inet_prefix *ip, int family)
{
	if(family==AF_INET) {
		u_int data[MAX_IP_INT]={0, 0, 0, 0};
		data[0]=INADDR_BROADCAST;
		inet_setip(ip, data, family);
	} else if(family==AF_INET6) {
		u_int data[MAX_IP_INT]=IPV6_ADDR_BROADCAST;
		inet_setip(ip, data, family);
	} else 
		fatal(ERROR_MSG "family not supported", ERROR_POS);

	return 0;
}

int inet_setip_anyaddr(inet_prefix *ip, int family)
{
	if(family==AF_INET) {
		u_int data[MAX_IP_INT]={0, 0, 0, 0};
		
		data[0]=INADDR_ANY;
		inet_setip(ip, data, family);
	} else if(family==AF_INET6) {
		struct in6_addr ipv6=IN6ADDR_ANY_INIT;
		inet_setip(ip, (u_int *)(&ipv6), family);
	} else 
		fatal(ERROR_MSG "family not supported", ERROR_POS);

	return 0;
}

int inet_setip_loopback(inet_prefix *ip, int family)
{
	if(family==AF_INET) {
		u_int data[MAX_IP_INT]={0, 0, 0, 0};
		
		data[0]=LOOPBACK_IP;
		inet_setip(ip, data, family);
		inet_htonl(ip->data, ip->family);
	} else if(family==AF_INET6) {
		u_int data[MAX_IP_INT]=LOOPBACK_IPV6;
		inet_setip(ip, data, family);
	} else 
		fatal(ERROR_MSG "family not supported", ERROR_POS);

	return 0;
}

/* 
 * inet_setip_localaddr: Restrict the `ip' to a local private class changing the
 * first byte of the `ip'. `class' specifies what restricted class is currently 
 * being used (10.x.x.x or 172.16.x.x). In ipv6 the site local class is the
 * default.
 */
int inet_setip_localaddr(inet_prefix *ip, int family, int class)
{
	if(family==AF_INET) {
		if(class == RESTRICTED_10)
			ip->data[0] = NTK_RESTRICTED_10_MASK(ip->data[0]);
		else 
			ip->data[0] = NTK_RESTRICTED_172_MASK(ip->data[0]);
	} else if(family==AF_INET6) {
		ip->data[0] = NTK_RESTRICTED_IPV6_MASK(ip->data[0]);
	} else 
		fatal(ERROR_MSG "family not supported", ERROR_POS);

	return 0;
}

/*
 * inet_is_ip_local: verifies if `ip' is a local address. If it is, 1 is
 * returned. `class' specifies what restricted class is currently 
 * being used (10.x.x.x or 172.16.x.x). In ipv6 the site local class is the
 * default.
 */
int inet_is_ip_local(inet_prefix *ip, int class)
{
	if(ip->family==AF_INET) {
		if(class == RESTRICTED_10)
			return ip->data[0] == NTK_RESTRICTED_10_MASK(ip->data[0]);
		else
			return ip->data[0] == NTK_RESTRICTED_172_MASK(ip->data[0]);
	} else if(ip->family==AF_INET6)
		return ip->data[0] == NTK_RESTRICTED_IPV6_MASK(ip->data[0]);
	else
		fatal(ERROR_MSG "family not supported", ERROR_POS);
	return 0;
}

void inet_copy(inet_prefix *dst, inet_prefix *src)
{
	memcpy(dst, src, sizeof(inet_prefix));
}

/*
 * inet_copy_ipdata_raw: copies `ip'->data in `dst_data'.
 */
void inet_copy_ipdata_raw(u_int *dst_data, inet_prefix *ip)
{
	memcpy(dst_data, ip->data, MAX_IP_SZ);
}

/*
 * inet_copy_ipdata: copies `ip'->data in `dst_data' and converts it in network
 * order.
 */
void inet_copy_ipdata(u_int *dst_data, inet_prefix *ip)
{
	inet_prefix tmp_ip;

	inet_copy(&tmp_ip, ip);
	inet_htonl(tmp_ip.data, tmp_ip.family);
	memcpy(dst_data, tmp_ip.data, MAX_IP_SZ);
}

/*
 * pack_inet_prefix: packs the `ip' inet_prefix struct and stores it in
 * `pack', which must be INET_PREFIX_PACK_SZ bytes big. `pack' will be in
 * network order.
 */
void pack_inet_prefix(inet_prefix *ip, char *pack)
{
	char *buf;

	buf=pack;

	memcpy(buf, &ip->family, sizeof(u_char));
	buf+=sizeof(u_char);

	memcpy(buf, &ip->len, sizeof(u_short));
	buf+=sizeof(u_short);

	memcpy(buf, &ip->bits, sizeof(u_char));
	buf+=sizeof(u_char);

	memcpy(buf, ip->data, MAX_IP_SZ);
	inet_htonl((u_int *)buf, ip->family);
	buf+=MAX_IP_SZ;
	
	ints_host_to_network(pack, inet_prefix_iinfo);
}

/*
 * unpack_inet_prefix: restores in `ip' the inet_prefix struct contained in `pack'.
 * Note that `pack' will be modified during the restoration.
 */
void unpack_inet_prefix(inet_prefix *ip, char *pack)
{
	char *buf;

	buf=pack;
	
	ints_network_to_host(pack, inet_prefix_iinfo);

	memcpy(&ip->family, buf, sizeof(u_char));
	buf+=sizeof(u_char);

	memcpy(&ip->len, buf, sizeof(u_short));
	buf+=sizeof(u_short);

	memcpy(&ip->bits, buf, sizeof(u_char));
	buf+=sizeof(u_char);

	memcpy(ip->data, buf, MAX_IP_SZ);
	inet_ntohl(ip->data, ip->family);
	buf+=MAX_IP_SZ;
}

/* 
 * inet_addr_match: without hesitating this function was robbed from iproute2.
 * It compares a->data wih b->data matching `bits'# bits.
 */
int inet_addr_match(const inet_prefix *a, const inet_prefix *b, int bits)
{
        uint32_t *a1 = a->data;
        uint32_t *a2 = b->data;
        int words = bits >> 0x05;
        
        bits &= 0x1f;
        
        if (words)
                if (memcmp(a1, a2, words << 2))
                        return -1;

        if (bits) {
                uint32_t w1, w2;
                uint32_t mask;

                w1 = a1[words];
                w2 = a2[words];

                mask = htonl((0xffffffff) << (0x20 - bits));

                if ((w1 ^ w2) & mask)
                        return 1;
        }

	return 0;
}

int ipv6_addr_type(inet_prefix addr)
{
	int type;
	u_int st;

	st = htonl(addr.data[0]);

	if ((st & htonl(0xFF000000)) == htonl(0xFF000000)) {
		type = IPV6_ADDR_MULTICAST;

		switch((st & htonl(0x00FF0000))) {
			case __constant_htonl(0x00010000):
				type |= IPV6_ADDR_LOOPBACK;
				break;

			case  __constant_htonl(0x00020000):
				type |= IPV6_ADDR_LINKLOCAL;
				break;

			case  __constant_htonl(0x00050000):
				type |= IPV6_ADDR_SITELOCAL;
				break;
		};
		return type;
	}

	type = IPV6_ADDR_UNICAST;

	/* Consider all addresses with the first three bits different of
	   000 and 111 as finished.
	 */
	if ((st & htonl(0xE0000000)) != htonl(0x00000000) &&
	    (st & htonl(0xE0000000)) != htonl(0xE0000000))
		return type;
	
	if ((st & htonl(0xFFC00000)) == htonl(0xFE800000))
		return (IPV6_ADDR_LINKLOCAL | type);

	if ((st & htonl(0xFFC00000)) == htonl(0xFEC00000))
		return (IPV6_ADDR_SITELOCAL | type);

	if ((addr.data[0] | addr.data[1]) == 0) {
		if (addr.data[2] == 0) {
			if (addr.data[3] == 0)
				return IPV6_ADDR_ANY;

			if (htonl(addr.data[3]) == htonl(0x00000001))
				return (IPV6_ADDR_LOOPBACK | type);

			return (IPV6_ADDR_COMPATv4 | type);
		}

		if (htonl(addr.data[2]) == htonl(0x0000ffff))
			return IPV6_ADDR_MAPPED;
	}

	st &= htonl(0xFF000000);
	if (st == 0)
		return IPV6_ADDR_RESERVED;
	st &= htonl(0xFE000000);
	if (st == htonl(0x02000000))
		return IPV6_ADDR_RESERVED;	/* for NSAP */
	if (st == htonl(0x04000000))
		return IPV6_ADDR_RESERVED;	/* for IPX */
	return type;
}

/*
 * inet_validate_ip: returns 0 is `ip' a valid IP which can be set by
 * Netsukuku to a network interface
 */
int inet_validate_ip(inet_prefix ip)
{
	int type, ipv4;

	if(ip.family==AF_INET) {
		ipv4=htonl(ip.data[0]);
		if(MULTICAST(ipv4) || BADCLASS(ipv4) || ZERONET(ipv4) 
			|| LOOPBACK(ipv4) || NTK_PRIVATE_C(ipv4) ||
			(!restricted_mode && NTK_PRIVATE_B(ipv4)))
			return -EINVAL;

	} else if(ip.family==AF_INET6) {
		type=ipv6_addr_type(ip);
		if( (type & IPV6_ADDR_MULTICAST) || (type & IPV6_ADDR_RESERVED) || 
				(type & IPV6_ADDR_LOOPBACK))
			return -EINVAL;
	}

	if(is_bufzero((char *)ip.data, MAX_IP_SZ))
		return -EINVAL;

	return 0;
}


/*\
 *
 *  *  *  Conversion functions...  *  * 
 * 
\*/

/*
 * ipraw_to_str: It returns the string which represents the given ip in host
 * order.
 */
const char *ipraw_to_str(u_int ip[MAX_IP_INT], int family)
{
	struct in_addr src;
	struct in6_addr src6;
	static char dst[INET_ADDRSTRLEN], dst6[INET6_ADDRSTRLEN];

	if(family==AF_INET) {
		src.s_addr=htonl(ip[0]);
		inet_ntop(family, &src, dst, INET_ADDRSTRLEN);
		
		return dst;
	} else if(family==AF_INET6) {
		inet_htonl(ip, family);
		memcpy(&src6, ip, MAX_IP_SZ);
		inet_ntop(family, &src6, dst6, INET6_ADDRSTRLEN);

		return dst6;
	}

	return 0;
}

/*
 * inet_to_str: returns the string rapresentation of `ip'
 */
const char *inet_to_str(inet_prefix ip)
{
	return ipraw_to_str(ip.data, ip.family);
}

/*
 * str_to_inet: it converts the IP address string contained in `src' and
 * terminated by a `\0' char to an inet_prefix struct. The result is stored in
 * `ip'. On error -1 is returned.
 */
int str_to_inet(const char *src, inet_prefix *ip)
{
	struct in_addr dst;
	struct in6_addr dst6;
	int family,res;
	u_int *data;

	setzero(ip, sizeof(inet_prefix));

	if(strstr(src, ":")) {
		family=AF_INET6;
		data=(u_int *)&dst6;
	} else {
		family=AF_INET;
		data=(u_int *)&dst;
	}

	if((res=inet_pton(family, src, (void *)data)) < 0) {
		debug(DBG_NORMAL, ERROR_MSG "error -> %s.", 
				ERROR_FUNC, strerror(errno));
		return -1;
	}
	if (!res) {
		debug(DBG_NORMAL, ERROR_MSG "impossible to convert \"%s\":"
				" invalid address.", ERROR_FUNC, src);
		return -1;
	}

	inet_setip(ip, data, family);
	return 0;
}

/*
 * inet_to_sockaddr: Converts a inet_prefix struct to a sockaddr struct
 */
int inet_to_sockaddr(inet_prefix *ip, u_short port, struct sockaddr *dst,
		socklen_t *dstlen)
{
	port=htons(port);
	
	if(ip->family==AF_INET) {
		struct sockaddr_in sin;
		setzero(&sin,  sizeof(struct sockaddr_in));
		
		sin.sin_family = ip->family;
		sin.sin_port = port;
		sin.sin_addr.s_addr = htonl(ip->data[0]);
		memcpy(dst, &sin, sizeof(struct sockaddr_in));
		
		if(dstlen)
			*dstlen=sizeof(struct sockaddr_in);

	} else if(ip->family==AF_INET6) {
		struct sockaddr_in6 sin6;
		setzero(&sin6,  sizeof(struct sockaddr_in6));
		
		sin6.sin6_family = ip->family;
		sin6.sin6_port = port;
		sin6.sin6_flowinfo = 0;
		
		memcpy(&sin6.sin6_addr, ip->data, MAX_IP_SZ);
		inet_htonl((u_int *)&sin6.sin6_addr, ip->family);

		memcpy(dst, &sin6, sizeof(struct sockaddr_in6));

		if(dstlen)
			*dstlen=sizeof(struct sockaddr_in6);
	} else
		fatal(ERROR_MSG "family not supported", ERROR_POS);

	return 0;
}

int sockaddr_to_inet(struct sockaddr *ip, inet_prefix *dst, u_short *port)
{
	u_short po;
	char *p;
	
	setzero(dst,  sizeof(inet_prefix));
	
	dst->family=ip->sa_family;
	memcpy(&po, &ip->sa_data, sizeof(u_short));
	if(port)
		*port=ntohs(po);
	
	if(ip->sa_family==AF_INET)
		p=(char *)ip->sa_data+sizeof(u_short);
	else if(ip->sa_family==AF_INET6)
		p=(char *)ip->sa_data+sizeof(u_short)+sizeof(int);
	else {
		error(ERROR_MSG "family not supported", ERROR_POS);
		return -1;
	}
		
	inet_setip(dst, (u_int *)p, ip->sa_family);

	return 0;
}

/*\
 *
 *   *  *  Socket operations  *  *
 *
\*/

int new_socket(int sock_type)
{
	int sockfd;
	if((sockfd=socket(sock_type, SOCK_STREAM, 0)) == -1 ) {
		error("Socket SOCK_STREAM creation failed: %s", strerror(errno));
		return -1;
	}

	return sockfd;
}

int new_dgram_socket(int sock_type)
{
	int sockfd;
	if((sockfd=socket(sock_type, SOCK_DGRAM, 0)) == -1 ) {
		error("Socket SOCK_DGRAM creation failed: %s", strerror(errno));
		return -1;
	}

	return sockfd;
}

/* 
 * inet_close
 *
 * It closes the `*sk' socket and sets it to zero.
 * It always returns 0;
 */
int inet_close(int *sk)
{
	close(*sk);
	return (*sk=0);
}

int inet_getpeername(int sk, inet_prefix *ip, short *port)
{
	struct sockaddr_storage saddr_sto;
	struct sockaddr	*sa=(struct sockaddr *)&saddr_sto;
	socklen_t alen;

	alen = sizeof(saddr_sto);
	setzero(sa, alen);
	if(getpeername(sk, sa, &alen) == -1) {
		error("Cannot getpeername: %s", strerror(errno));
		return -1;
	}

	return sockaddr_to_inet(sa, ip, port);
}

/* 
 * join_ipv6_multicast: It adds the membership to the IPV6_ADDR_BROADCAST
 * multicast group. The device with index `idx' will be used. 
 */
int join_ipv6_multicast(int socket, int idx)
{
	struct ipv6_mreq    mreq6;
	const int addr[MAX_IP_INT]=IPV6_ADDR_BROADCAST;
	
	setzero(&mreq6, sizeof(struct ipv6_mreq));
	memcpy(&mreq6.ipv6mr_multiaddr,	addr, sizeof(struct in6_addr));
	mreq6.ipv6mr_interface=idx;
	
	if(setsockopt(socket, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, 
				sizeof(mreq6)) < 0) {
		error("Cannot set IPV6_JOIN_GROUP: %s", strerror(errno));
	        close(socket);
		return -1;
	}

	return socket;
}

int set_multicast_if(int socket, int idx)
{
	/* man ipv6 */

	if (setsockopt(socket, IPPROTO_IPV6, IPV6_MULTICAST_IF,
				&idx, sizeof(int)) < 0) {
		error("set_multicast_if(): cannot set IPV6_MULTICAST_IF: %s",
				strerror(errno));
		close(socket);
		return -1;
	}

	return 0;
}
		
int set_nonblock_sk(int fd)
{
	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		error("set_nonblock_sk(): cannot set O_NONBLOCK: %s", 
				strerror(errno));
		close(fd);
		return -1;
	}
	return 0;
}

int unset_nonblock_sk(int fd)
{
	if (fcntl(fd, F_SETFL, 0) < 0) {
		error("unset_nonblock_sk(): cannot unset O_NONBLOCK: %s", 
				strerror(errno));
		close(fd);
		return -1;
	}
	return 0;
}

int set_reuseaddr_sk(int socket)
{
	int reuseaddr=1, ret;
	/*
	 * SO_REUSEADDR: <<Go ahead and reuse that port even if it is in
	 * TIME_WAIT state.>>
	 */
	ret=setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int));
	if(ret < 0)
		error("setsockopt SO_REUSEADDR: %s", strerror(errno));
	return ret;
}

int set_bindtodevice_sk(int socket, char *dev)
{
	struct ifreq ifr;
	int ret=0;
	
	setzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	
	ret=setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev)+1);
	if(ret < 0)
		error("setsockopt SO_BINDTODEVICE: %s", strerror(errno));

        return ret;
}

/*
 * `loop': 0 = disable, 1 = enable (default) 
 */
int set_multicast_loop_sk(int family, int socket, u_char loop)
{
	int ret=0;

	/*
	 * <<The IPV6_MULTICAST_LOOP option gives the sender explicit control
	 * over whether or not subsequent datagrams are looped bac.>>
	 */
	if(family==AF_INET6)
		ret=setsockopt(socket, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop));
	if(ret < 0)
		error("setsockopt IP_MULTICAST_LOOP: %s", strerror(errno));
	return ret;
}

int set_broadcast_sk(int socket, int family, inet_prefix *host, short port,
		int dev_idx)
{
	struct sockaddr_storage saddr_sto;
	struct sockaddr	*sa=(struct sockaddr *)&saddr_sto;
	socklen_t alen;
	int broadcast=1;
	
	if(family == AF_INET) {
		if (setsockopt(socket, SOL_SOCKET, SO_BROADCAST, &broadcast,
					sizeof(broadcast)) < 0) {
			error("Cannot set SO_BROADCAST to socket: %s", strerror(errno));
			close(socket);
			return -1;
		}
	} else if(family == AF_INET6) {
		if(join_ipv6_multicast(socket, dev_idx) < 0)
			return -1;
		if(set_multicast_loop_sk(family, socket, 0) < 0)
			return -1;
		set_multicast_if(socket, dev_idx);
	} else
		fatal(ERROR_MSG "family not supported", ERROR_POS);
	
	/* What's my name ? */
	alen = sizeof(saddr_sto);
	setzero(sa, alen);
	if (getsockname(socket, sa, &alen) == -1) {
		error("Cannot getsockname: %s", strerror(errno));
		close(socket);
		return -1;
	}
	
	/* Let's bind it! */
	if(bind(socket, sa, alen) < 0) {
		error("Cannot bind the broadcast socket: %s", strerror(errno));
		close(socket);
		return -1;
	}
	
	return socket;
}

int unset_broadcast_sk(int socket, int family)
{
	int broadcast=0;
	if(family == AF_INET) {
		if (setsockopt(socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
			error ("Cannot unset broadcasting: %s", strerror(errno));
			return -1;
		}
	}
	return 0;
}

int set_keepalive_sk(int socket)
{
	int on=1;

	if(setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, 
				sizeof(on)) < 0){
		error("Cannot set keepalive socket: %s", strerror(errno));
		return -1;
	}
	return 0;
}

int unset_keepalive_sk(int socket)
{
	int off=0;

	if(setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, (void *)&off, 
				sizeof(off)) < 0){
		error("Cannot unset keepalive socket: %s", strerror(errno));
		return -1;
	}
	return 0;
}

int set_tos_sk(int socket, int lowdelay)
{
	int tos = lowdelay ? IPTOS_LOWDELAY : IPTOS_THROUGHPUT;

	/* Only for Ipv4 */
	if (setsockopt(socket, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0) {
		error("setsockopt IP_TOS %d: %s", tos, strerror(errno));
		return -1;
	}

	return 0;
}

/*\
 *
 *   *  *  Connection functions  *  * 
 *
\*/

int new_tcp_conn(inet_prefix *host, short port, char *dev)
{
	int sk;
	socklen_t sa_len;
	struct sockaddr_storage saddr_sto;
	struct sockaddr	*sa=(struct sockaddr *)&saddr_sto;
	const char *ntop;
	ntop=inet_to_str(*host);
	
	if(inet_to_sockaddr(host, port, sa, &sa_len)) {
		error("Cannot new_tcp_connect(): %d Family not supported", host->family);
		ERROR_FINISH(sk, -1, finish);
	}
	
	if((sk = new_socket(host->family)) == -1)
		ERROR_FINISH(sk, -1, finish);

	if(dev) /* if `dev' is not null bind the socket to it */
		if(set_bindtodevice_sk(sk, dev) < 0)
			ERROR_FINISH(sk, -1, finish);
	
	if (connect(sk, sa, sa_len) == -1) {
		error("Cannot tcp_connect() to %s: %s", ntop, strerror(errno));
		ERROR_FINISH(sk, -1, finish);
	}
finish:
	return sk;
}

int new_udp_conn(inet_prefix *host, short port, char *dev)
{	
	int sk;
	socklen_t sa_len;
	struct sockaddr_storage saddr_sto;
	struct sockaddr	*sa=(struct sockaddr *)&saddr_sto;
	const char *ntop;
	ntop=inet_to_str(*host);

	if(inet_to_sockaddr(host, port, sa, &sa_len)) {
		error("Cannot new_udp_connect(): %d Family not supported", host->family);
		ERROR_FINISH(sk, -1, finish);
	}

	if((sk = new_dgram_socket(host->family)) == -1) 
		ERROR_FINISH(sk, -1, finish);
	
	if(dev) /* if `dev' is not null bind the socket to it */
		if(set_bindtodevice_sk(sk, dev) < 0)
			ERROR_FINISH(sk, -1, finish);

	if (connect(sk, sa, sa_len) == -1) {
		error("Cannot connect to %s: %s", ntop, strerror(errno));
		ERROR_FINISH(sk, -1, finish);
	}
	
finish:
	return sk;
}
	
int new_bcast_conn(inet_prefix *host, short port, int dev_idx)
{	
	struct sockaddr_storage saddr_sto;
	struct sockaddr	*sa=(struct sockaddr *)&saddr_sto;
	socklen_t alen;
	int sk;
	const char *ntop;

	if((sk = new_dgram_socket(host->family)) == -1)
		return -1;
	sk=set_broadcast_sk(sk, host->family, host, port, dev_idx);
	
	/*
	 * Connect 
	 */
	if(inet_to_sockaddr(host, port, sa, &alen)) {
		error("set_broadcast_sk: %d Family not supported", host->family);
		return -1;
	}
	
	if(host->family == AF_INET6) {
		struct sockaddr_in6 *sin6=(struct sockaddr_in6 *)sa;
		sin6->sin6_scope_id = dev_idx;
	}
	
	if(set_bindtodevice_sk(sk, (char *)ll_index_to_name(dev_idx)) < 0)
		return -1;
	
	if(connect(sk, sa, alen) == -1) {
		ntop=inet_to_str(*host);
		error("Cannot connect to the broadcast (%s): %s", ntop,	
				strerror(errno));
		return -1;
	}

	return sk;
}


/*\
 *
 *   *  *  Recv/Send functions  *  *
 *
\*/

ssize_t inet_recv(int s, void *buf, size_t len, int flags)
{
	ssize_t err;
	fd_set fdset;
	int ret;

	if((err=recv(s, buf, len, flags))==-1) {
		switch(errno) 
		{
			default:
				/* Probably connection was closed */
				debug(DBG_NORMAL, "inet_recv: Cannot recv(): %s",
						strerror(errno));
				return err;
				break;
		}
	}
	return err;
}

/* 
 * inet_recv_timeout
 * 
 * is the same as inet_recv() but if no reply is received for `timeout'
 * seconds it returns -1.
 */
ssize_t inet_recv_timeout(int s, void *buf, size_t len, int flags, u_int timeout)
{
	struct timeval timeout_t;
	fd_set fdset;
	int ret;

	MILLISEC_TO_TV(timeout*1000, timeout_t);

	FD_ZERO(&fdset);
	FD_SET(s, &fdset);

	ret = select(s+1, &fdset, NULL, NULL, &timeout_t);
	if (ret == -1) {
		error(ERROR_MSG "select error: %s", ERROR_FUNC, strerror(errno));
		return ret;
	}

	return FD_ISSET(s, &fdset) ? inet_recv(s, buf, len, flags) : -1;
}

ssize_t inet_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
	ssize_t err;
	fd_set fdset;
	int ret;

	if((err=recvfrom(s, buf, len, flags, from, fromlen)) < 0) {
		switch(errno) 
		{
			default:
				error("inet_recvfrom: Cannot recv(): %s", strerror(errno));
				return err;
				break;
		}
	}
	return err;
}

/* 
 * inet_recvfrom_timeout: is the same as inet_recvfrom() but if no reply is
 * received for `timeout' seconds it returns -1.
 */
ssize_t inet_recvfrom_timeout(int s, void *buf, size_t len, int flags, 
		struct sockaddr *from, socklen_t *fromlen, u_int timeout)
{
	struct timeval timeout_t;
	fd_set fdset;
	int ret;

	MILLISEC_TO_TV(timeout*1000, timeout_t);

	FD_ZERO(&fdset);
	FD_SET(s, &fdset);

	ret = select(s+1, &fdset, NULL, NULL, &timeout_t);
	if (ret == -1) {
		error(ERROR_MSG "select error: %s", ERROR_FUNC, strerror(errno));
		return ret;
	}

	if(FD_ISSET(s, &fdset))
		return inet_recvfrom(s, buf, len, flags, from, fromlen);
	
	return -1;
}
			
ssize_t inet_send(int s, const void *msg, size_t len, int flags)
{
	ssize_t err;
	fd_set fdset;
	int ret;

	if((err=send(s, msg, len, flags)) < 0) {
		switch(errno) 
		{
			case EMSGSIZE:
				inet_send(s, msg, len/2, flags);
				err=inet_send(s, (const char *)msg+(len/2), 
						len-(len/2), flags);
				break;

			default:
				error("inet_send: Cannot send(): %s", strerror(errno));
				return err;
				break;
		}
	}
	return err;
}

/*
 * inet_send_timeout: is the same as inet_send() but if the packet isn't sent
 * in `timeout' seconds it timeouts and returns -1.
 */
ssize_t inet_send_timeout(int s, const void *msg, size_t len, int flags, u_int timeout)
{
	struct timeval timeout_t;
	fd_set fdset;
	int ret;

	MILLISEC_TO_TV(timeout*1000, timeout_t);
	
	FD_ZERO(&fdset);
	FD_SET(s, &fdset);

	ret = select(s+1, NULL, &fdset, NULL, &timeout_t);

	if (ret == -1) {
		error(ERROR_MSG "select error: %s", ERROR_FUNC, strerror(errno));
		return ret;
	}

	if(FD_ISSET(s, &fdset))
		return inet_send(s, msg, len, flags);
	return -1;
}



ssize_t inet_sendto(int s, const void *msg, size_t len, int flags, 
		const struct sockaddr *to, socklen_t tolen)
{
	ssize_t err;
	fd_set fdset;
	int ret;

	if((err=sendto(s, msg, len, flags, to, tolen))==-1) {
		switch(errno)
		{
			case EMSGSIZE:
				inet_sendto(s, msg, len/2, flags, to, tolen);
				err=inet_sendto(s, ((const char *)msg+(len/2)), 
						len-(len/2), flags, to, tolen);
				break;

			default:
				error("inet_sendto: Cannot send(): %s", strerror(errno));
				return err;
				break;
		}
	}
	return err;
}

/*
 * inet_sendto_timeout: is the same as inet_sendto() but if the packet isn't sent
 * in `timeout' seconds it timeouts and returns -1.
 */
ssize_t inet_sendto_timeout(int s, const void *msg, size_t len, int flags, 
		const struct sockaddr *to, socklen_t tolen, u_int timeout)
{
	struct timeval timeout_t;
	fd_set fdset;
	int ret;

	MILLISEC_TO_TV(timeout*1000, timeout_t);
	
	FD_ZERO(&fdset);
	FD_SET(s, &fdset);

	ret = select(s+1, NULL, &fdset, NULL, &timeout_t);

	if (ret == -1) {
		error(ERROR_MSG "select error: %s", ERROR_FUNC, strerror(errno));
		return ret;
	}

	if(FD_ISSET(s, &fdset))
		return inet_sendto(s, msg, len, flags, to, tolen);
	return -1;
}


ssize_t inet_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
	ssize_t err;
	fd_set fdset;
	int ret;

	if((err=sendfile(out_fd, in_fd, offset, count))==-1)
		error("inet_sendfile: Cannot sendfile(): %s", strerror(errno));
	return err;
}
