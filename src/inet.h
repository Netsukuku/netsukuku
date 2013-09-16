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

#ifndef INET_H
#define INET_H

#include "endianness.h"

#define MAX_IP_INT	4
#define MAX_IP_SZ	(MAX_IP_INT*sizeof(int))

/*
 * This is the "link-scope all-hosts multicast" address: ff02::1.
 */
#define IPV6_ADDR_BROADCAST		{ 0xff020000, 0x0, 0x0, 0x1 }

#define LOOPBACK_IP			0x7f000001
#define LOOPBACK_NET			0x7f000000
#define LOOPBACK_BCAST			0x7fffffff

#define LOOPBACK_IPV6			{ 0x0, 0x0, 0x0, 0x1 }

/*
 * `x' is in host byte order
 * 
 * NTK_RESTRICTED_10_MASK(x):
 * given an ipv4 IP it returns the equivalent in the 10.x.x.x class, i.e.
 * 212.13.4.1 --> 10.13.4.1
 *
 * NTK_RESTRICTED_172_MASK(x): it's the same of NTK_RESTRICTED_10_MASK() but
 * it converts the IP in the 172.16.0.0 - 172.31.255.255 range.
 *
 * NTK_RESTRICTED_IPV6_MASK(x):
 * `x' in this case is the first integer of the four of an ipv6 IP.
 * The conversion is:  `x' --> fec0:xxxx:...
 *
 */
#define NTK_RESTRICTED_10_MASK(x)	(((x) & ~0xff000000)|0x0a000000)
#define NTK_RESTRICTED_172_MASK(x)	(((((x) & ~0xff000000) | 0xac000000) & ~0x00e00000) | 0x00100000)
#define NTK_RESTRICTED_IPV6_MASK(x)	(((x) & ~0xffff0000)|0xfec00000) 


/* `x' is in network order.
 * Is `x' an IP in the range of 192.168.0.0 - 192.168.255.255 ? */
#define NTK_PRIVATE_C(x)	(((x) & __constant_htonl(0xffff0000)) == __constant_htonl(0xc0a80000))

/* `x' is in network order.
 * Is `x' in 172.16.0.0 - 172.31.255.255 ? */
#define NTK_PRIVATE_B(x)	(((x) & __constant_htonl(0xff000000)) == __constant_htonl(0xac000000))\
					&& ((x) & __constant_htonl(0x00100000)) && 	\
						!((x) & __constant_htonl(0x00e00000))


/*
 * The inet_prefix struct is used to store IP addresses in the internals of
 * the Netsukuku code
 */
typedef struct
{
	u_char	family;		     /* AF_INET or AF_INET6 */
	u_short len;		     /* IP length: 4 or 16 (bytes) */
	u_char	bits;		     /* Number of used bits of the IP */
	u_int	data[MAX_IP_INT];    /* The address is kept in host long format, 
				       word ORDER 1 (most significant word first) */
}inet_prefix;

/* int_info struct used for packing the inet_prefix struct.
 * Note that `data' is ignored 'cause it will be converted with
 * inet_htonl() / inet_ntohl() */
INT_INFO inet_prefix_iinfo = { 1,
			       { INT_TYPE_16BIT },
			       { sizeof(u_char) },
			       { 1 }
			     };
#define INET_PREFIX_PACK_SZ (sizeof(u_char) + sizeof(u_short) +\
				sizeof(u_char) + MAX_IP_SZ)


/* * * defines from linux/in.h * * */
#define LOOPBACK(x)	(((x) & htonl(0xff000000)) == htonl(0x7f000000))
#define MULTICAST(x)	(((x) & htonl(0xf0000000)) == htonl(0xe0000000))
#define BADCLASS(x)	(((x) & htonl(0xf0000000)) == htonl(0xf0000000))
#define ZERONET(x)	(((x) & htonl(0xff000000)) == htonl(0x00000000))
#define LOCAL_MCAST(x)	(((x) & htonl(0xFFFFFF00)) == htonl(0xE0000000))

/* * * defines from linux/include/net/ipv6.h * * */
#define IPV6_ADDR_ANY		0x0000U

#define IPV6_ADDR_UNICAST      	0x0001U	
#define IPV6_ADDR_MULTICAST    	0x0002U	

#define IPV6_ADDR_LOOPBACK	0x0010U
#define IPV6_ADDR_LINKLOCAL	0x0020U
#define IPV6_ADDR_SITELOCAL	0x0040U

#define IPV6_ADDR_COMPATv4	0x0080U

#define IPV6_ADDR_SCOPE_MASK	0x00f0U

#define IPV6_ADDR_MAPPED	0x1000U
#define IPV6_ADDR_RESERVED	0x2000U	/* reserved address space */

/*
 * Type of Service
 */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY		0x10
#define IPTOS_THROUGHPUT	0x08
#define IPTOS_RELIABILITY	0x04
#define IPTOS_LOWCOST		0x02
#define IPTOS_MINCOST		IPTOS_LOWCOST
#endif /* IPTOS_LOWDELAY */


/* 
 * Globals
 */

#define RESTRICTED_10		1	/* We are using the 10.x.x.x class for 
					   the restricted mode */
#define RESTRICTED_172		2	/* 172.16.0.0-172.31.255.255 class */

#define RESTRICTED_10_STR	"10.0.0.0-10.255.255.255"
#define RESTRICTED_172_STR	"172.16.0.0-172.31.255.255"

int my_family, restricted_mode, restricted_class;
	
/* 
 * * * Functions declaration * * 
 */
void inet_ntohl(u_int *data, int family);
void inet_htonl(u_int *data, int family);
int inet_setip_raw(inet_prefix *ip, u_int *data, int family);
int inet_setip(inet_prefix *ip, u_int *data, int family);
int inet_setip_bcast(inet_prefix *ip, int family);
int inet_setip_anyaddr(inet_prefix *ip, int family);
int inet_setip_loopback(inet_prefix *ip, int family);
int inet_setip_localaddr(inet_prefix *ip, int family, int class);
int inet_is_ip_local(inet_prefix *ip, int class);
void inet_copy_ipdata_raw(u_int *dst_data, inet_prefix *ip);
void inet_copy_ipdata(u_int *dst_data, inet_prefix *ip);
void inet_copy(inet_prefix *dst, inet_prefix *src);
void pack_inet_prefix(inet_prefix *ip, char *pack);
void unpack_inet_prefix(inet_prefix *ip, char *pack);
int inet_addr_match(const inet_prefix *a, const inet_prefix *b, int bits);
int ipv6_addr_type(inet_prefix addr);
int inet_validate_ip(inet_prefix ip);

const char *ipraw_to_str(u_int ip[MAX_IP_INT], int family);
const char *inet_to_str(inet_prefix ip);
int str_to_inet(const char *src, inet_prefix *ip);
int inet_to_sockaddr(inet_prefix *ip, u_short port, struct sockaddr *dst, socklen_t *dstlen);
int sockaddr_to_inet(struct sockaddr *ip, inet_prefix *dst, u_short *port);

int new_socket(int sock_type);
int new_dgram_socket(int sock_type);
int inet_close(int *sk);
int inet_getpeername(int sk, inet_prefix *ip, short *port);
int join_ipv6_multicast(int socket, int idx);

int set_keepalive_sk(int socket);
int unset_keepalive_sk(int socket);
int set_nonblock_sk(int fd);
int unset_nonblock_sk(int fd);
int set_reuseaddr_sk(int socket);
int set_bindtodevice_sk(int socket, char *dev);
int set_broadcast_sk(int socket, int family, inet_prefix *host, short port, 
		int dev_idx);
int new_broadcast_sk(int family, int dev_idx);
int set_tos_sk(int socket, int lowdelay);

int new_tcp_conn(inet_prefix *host, short port, char *dev);
int new_udp_conn(inet_prefix *host, short port, char *dev);
int new_bcast_conn(inet_prefix *host, short port, int dev_idx);

ssize_t inet_recv(int s, void *buf, size_t len, int flags);
ssize_t inet_recvfrom(int s, void *buf, size_t len, int flags, 
		struct sockaddr *from, socklen_t *fromlen);
ssize_t inet_recv_timeout(int s, void *buf, size_t len, int flags, u_int timeout);
ssize_t inet_recvfrom_timeout(int s, void *buf, size_t len, int flags, 
		struct sockaddr *from, socklen_t *fromlen, u_int timeout);
ssize_t inet_send(int s, const void *msg, size_t len, int flags);
ssize_t inet_sendto(int s, const void *msg, size_t len, int flags, 
		const struct sockaddr *to, socklen_t tolen);
ssize_t inet_send_timeout(int s, const void *msg, size_t len, int flags, u_int timeout);
ssize_t inet_sendto_timeout(int s, const void *msg, size_t len, int flags, 
		const struct sockaddr *to, socklen_t tolen, u_int timeout);
ssize_t inet_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

#endif /*INET_H*/
