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
 *
 * - 
 *
 * Various parts are ripped from iproute2/iproute.c
 * written by Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>.
 */

#include "includes.h"

#include "if.h"
#include "libnetlink.h"
#include "inet.h"
#include "krnl_route.h"
#include "libnetlink.h"
#include "ll_map.h"
#include "common.h"

#ifdef LINUX_2_6_14
#include <linux/ip_mp_alg.h>
#define NTK_MULTIPATH_ALGO IP_MP_ALG_WRANDOM
#endif

static struct
{
        int tb;
        int flushed;
        char *flushb;
        int flushp;
        int flushe;
        struct rtnl_handle *rth;
        int protocol, protocolmask;
        int scope, scopemask;
        int type, typemask;
        int tos, tosmask;
        int iif, iifmask;
        int oif, oifmask;
        int realm, realmmask;
        inet_prefix rprefsrc;
        inet_prefix rvia;
        inet_prefix rdst;
        inet_prefix mdst;
        inet_prefix rsrc;
        inet_prefix msrc;
} filter;

void route_reset_filter()
{
        setzero(&filter, sizeof(filter));
        filter.mdst.bits = -1;
        filter.msrc.bits = -1;
}

int route_exec(int route_cmd, int route_type, int route_scope, unsigned flags,
		inet_prefix *src, inet_prefix *to, struct nexthop *nhops, 
		char *dev, u_char table);

int route_add(ROUTE_CMD_VARS)
{
	return route_exec(RTM_NEWROUTE, type, scope, NLM_F_CREATE | NLM_F_EXCL,
			src, to, nhops, dev, table);
}

int route_del(ROUTE_CMD_VARS)
{
	return route_exec(RTM_DELROUTE, type, scope, 0, src, to, nhops, dev, table);
}

/*If it doesn't exist, CREATE IT! de ih oh oh*/
int route_replace(ROUTE_CMD_VARS)
{
	return route_exec(RTM_NEWROUTE, type, scope, NLM_F_REPLACE | NLM_F_CREATE,
			src, to, nhops, dev, table);
}

int route_change(ROUTE_CMD_VARS)
{
	return route_exec(RTM_NEWROUTE, type, scope, NLM_F_REPLACE, src, to, nhops, 
			dev, table);
}

int route_append(ROUTE_CMD_VARS)
{
	return route_exec(RTM_NEWROUTE, type, scope, NLM_F_CREATE|NLM_F_APPEND,
			src, to, nhops, dev, table);
}

int add_nexthops(struct nlmsghdr *n, struct rtmsg *r, struct nexthop *nhop)
{
	char buf[1024];
	struct rtattr *rta = (void*)buf;
	struct rtnexthop *rtnh;
	int i=0, idx;

	rta->rta_type = RTA_MULTIPATH;
	rta->rta_len = RTA_LENGTH(0);
	rtnh = RTA_DATA(rta);

	if(!nhop[i+1].dev) {
		/* Just one gateway */
		r->rtm_family = nhop[i].gw.family;
		addattr_l(n, sizeof(struct rt_request), RTA_GATEWAY, &nhop[i].gw.data, nhop[i].gw.len);

		if(nhop[0].dev) {
			if ((idx = ll_name_to_index(nhop[0].dev)) == 0) {
				error(ERROR_MSG "Device \"%s\" doesn't really exist\n", 
						ERROR_POS, nhop[0].dev);
				return -1;
			}
			addattr32(n, sizeof(struct rt_request), RTA_OIF, idx);
		}

		return 0;
	}

#if 0
	/* We have more than one nexthop, equalize them */
	req.rt.rtm_flags|=RTM_F_EQUALIZE;
#endif

	while (nhop[i].dev!=0) {
		setzero(rtnh, sizeof(*rtnh));
		rtnh->rtnh_len = sizeof(*rtnh);
		rta->rta_len += rtnh->rtnh_len;

		if (nhop[i].gw.len) {
			if(nhop[i].gw.family==AF_INET)
				rta_addattr32(rta, 4096, RTA_GATEWAY, nhop[i].gw.data[0]);
			else if(nhop[i].gw.family==AF_INET6)
				rta_addattr_l(rta, 4096, RTA_GATEWAY, nhop[i].gw.data, nhop[i].gw.len);
			rtnh->rtnh_len += sizeof(struct rtattr) + nhop[i].gw.len;
		}

		if (nhop[i].dev) 
			if ((rtnh->rtnh_ifindex = ll_name_to_index(nhop[i].dev)) == 0)
				fatal("%s:%d, Cannot find device \"%s\"\n", ERROR_POS, nhop[i].dev);

		if (nhop[i].hops == 0) {
			debug(DBG_NORMAL, "hops=%d is invalid. Using hops=255\n", nhop[i].hops);
			rtnh->rtnh_hops=255;
		} else
			rtnh->rtnh_hops = nhop[i].hops - 1;

		rtnh = RTNH_NEXT(rtnh);
		i++;
	}

	if (rta->rta_len > RTA_LENGTH(0))
		addattr_l(n, 1024, RTA_MULTIPATH, RTA_DATA(rta), RTA_PAYLOAD(rta));
	return 0;
}

/*
 * route_exec: replaces, adds or deletes a route from the routing table.
 * `to' and nhops->gw must be addresses given in network order
 */
int route_exec(int route_cmd, int route_type, int route_scope, unsigned flags,
		inet_prefix *src, inet_prefix *to, struct nexthop *nhops, 
		char *dev, u_char table)
{
	struct rt_request req;
	struct rtnl_handle rth;

	setzero(&req, sizeof(req));

	if(!table)
		table=RT_TABLE_MAIN;

	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST|flags;
	req.nh.nlmsg_type = route_cmd;
	req.rt.rtm_family = AF_UNSPEC;
	req.rt.rtm_table = table;
	req.rt.rtm_protocol = RTPROT_NETSUKUKU;
	req.rt.rtm_scope = RT_SCOPE_NOWHERE;
	req.rt.rtm_type = RTN_UNSPEC;

	/* kernel protocol layer */
	if(table == RT_TABLE_LOCAL)
		req.rt.rtm_protocol = RTPROT_KERNEL;
	
	if (route_cmd != RTM_DELROUTE) {
		req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
		req.rt.rtm_type = RTN_UNICAST;
	}
	
	if(route_type)
		req.rt.rtm_type = route_type;

	if(route_scope)
		req.rt.rtm_scope = route_scope;
	else if(req.rt.rtm_type==RTN_LOCAL)
		req.rt.rtm_scope=RT_SCOPE_HOST;

	
	if (rtnl_open(&rth, 0) < 0)
		return -1;

	if (dev || nhops) 
		ll_init_map(&rth);

#ifdef LINUX_2_6_14
	uint32_t mp_alg = NTK_MULTIPATH_ALGO;
	addattr_l(&req.n, sizeof(req), RTA_MP_ALGO, &mp_alg, sizeof(mp_alg));
#endif

	if (dev) {
		int idx;

		if ((idx = ll_name_to_index(dev)) == 0) {
			error("%s:%d, Device \"%s\" doesn't really exist\n", ERROR_POS, dev);
			return -1;
		}
		addattr32(&req.nh, sizeof(req), RTA_OIF, idx);
	}

	if(to) {
		req.rt.rtm_family = to->family;
		req.rt.rtm_dst_len = to->bits;

		if(!to->data[0] && !to->data[1] && !to->data[2] && !to->data[3]) {
			/* Modify the default gw*/
			if(route_cmd == RTM_DELROUTE)
				req.rt.rtm_protocol=0;
		}

		if(to->len)		
			addattr_l(&req.nh, sizeof(req), RTA_DST, &to->data, to->len);
	}

	if(src) {
		if (req.rt.rtm_family == AF_UNSPEC)
			req.rt.rtm_family = src->family;
		addattr_l(&req.nh, sizeof(req), RTA_PREFSRC, &src->data, src->len);
	}
	
	if(nhops)
		add_nexthops(&req.nh, &req.rt, nhops);
	
        if (req.rt.rtm_family == AF_UNSPEC)
                req.rt.rtm_family = AF_INET;

	/*Finaly stage: <<Hey krnl, r u there?>>*/
	if (rtnl_talk(&rth, &req.nh, 0, 0, NULL, NULL, NULL) < 0)
		return -1;

	rtnl_close(&rth);

	return 0;
}

/*
 * route_get_gw: if the route stored in `who' and `n' is matched by the
 * `filter', it stores the gateway address of that route in `arg', which
 * is a pointer to an inet_prefix struct. The address is stored in host order.
 * The dev name of the route is appended at `arg'+sizeof(inet_prefix).
 * Only the non-deleted routes are considered.
 */
int route_get_gw(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr * tb[RTA_MAX+1];
	inet_prefix dst;
	inet_prefix via;
	int host_len = -1;


	if (n->nlmsg_type != RTM_NEWROUTE && n->nlmsg_type != RTM_DELROUTE)
		return 0;
	if (filter.flushb && n->nlmsg_type != RTM_NEWROUTE)
		return 0;
	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0)
		return -1;

	if (r->rtm_family == AF_INET6)
		host_len = 128;
	else if (r->rtm_family == AF_INET)
		host_len = 32;
	else if (r->rtm_family == AF_DECnet)
		host_len = 16;
	else if (r->rtm_family == AF_IPX)
		host_len = 80;

	if (r->rtm_family == AF_INET6) {
		if (filter.tb) {
			if (filter.tb < 0) {
				if (!(r->rtm_flags&RTM_F_CLONED))
					return 0;
			} else {
				if (r->rtm_flags&RTM_F_CLONED)
					return 0;
				if (filter.tb == RT_TABLE_LOCAL) {
					if (r->rtm_type != RTN_LOCAL)
						return 0;
				} else if (filter.tb == RT_TABLE_MAIN) {
					if (r->rtm_type == RTN_LOCAL)
						return 0;
				} else {
					return 0;
				}
			}
		}
	} else {
		if (filter.tb > 0 && filter.tb != r->rtm_table)
			return 0;
	}
	if ((filter.protocol^r->rtm_protocol)&filter.protocolmask)
		return 0;
	if ((filter.scope^r->rtm_scope)&filter.scopemask)
		return 0;
	if ((filter.type^r->rtm_type)&filter.typemask)
		return 0;
	if ((filter.tos^r->rtm_tos)&filter.tosmask)
		return 0;
	if (filter.rdst.family &&
			(r->rtm_family != filter.rdst.family || filter.rdst.bits > r->rtm_dst_len))
		return 0;
	if (filter.mdst.family &&
			(r->rtm_family != filter.mdst.family ||
			 (filter.mdst.bits < r->rtm_dst_len)))
		return 0;
	if (filter.rsrc.family &&
			(r->rtm_family != filter.rsrc.family || filter.rsrc.bits > r->rtm_src_len))
		return 0;
	if (filter.msrc.family &&
			(r->rtm_family != filter.msrc.family ||
			 (filter.msrc.bits < r->rtm_src_len)))
		return 0;
	if (filter.rvia.family && r->rtm_family != filter.rvia.family)
		return 0;
	if (filter.rprefsrc.family && r->rtm_family != filter.rprefsrc.family)
		return 0;

	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);

	setzero(&dst, sizeof(dst));
	dst.family = r->rtm_family;
	if (tb[RTA_DST]) {
		memcpy(&dst.data, RTA_DATA(tb[RTA_DST]), (r->rtm_dst_len+7)/8);
	}
	if (filter.rdst.family && inet_addr_match(&dst, &filter.rdst, filter.rdst.bits))
		return 0;
	if (filter.mdst.family &&
			inet_addr_match(&dst, &filter.mdst, r->rtm_dst_len))
		return 0;

	if (n->nlmsg_type == RTM_DELROUTE)
		return 0;

	/*
	 * ... and finally if all the tests passed, copy the gateway address
	 */
	if(tb[RTA_GATEWAY]) {
		memcpy(&via.data, RTA_DATA(tb[RTA_GATEWAY]), host_len/8);
		via.family=r->rtm_family;
		inet_setip(arg, (u_int *)&via.data, via.family);
	} else if(tb[RTA_MULTIPATH]) {
		struct rtnexthop *nh = RTA_DATA(tb[RTA_MULTIPATH]);

		len = RTA_PAYLOAD(tb[RTA_MULTIPATH]);

		for (;;) {
			if (len < sizeof(*nh))
				break;
			if (nh->rtnh_len > len)
				break;
			if (r->rtm_flags&RTM_F_CLONED && r->rtm_type == RTN_MULTICAST)
				goto skip_nexthop;

			if (nh->rtnh_len > sizeof(*nh)) {
				parse_rtattr(tb, RTA_MAX, RTNH_DATA(nh), nh->rtnh_len - sizeof(*nh));
				if (tb[RTA_GATEWAY]) {
					memcpy(&via.data, RTA_DATA(tb[RTA_GATEWAY]), host_len/8);
					via.family=r->rtm_family;
					inet_setip(arg, (u_int *)&via.data, via.family);

					/* Copy the interface name */
					strncpy((char *)arg+sizeof(inet_prefix),
						ll_index_to_name(nh->rtnh_ifindex), IFNAMSIZ);
					break;
				}
			}
skip_nexthop:
			len -= NLMSG_ALIGN(nh->rtnh_len);
			nh = RTNH_NEXT(nh);
		}
	}


	/* Copy the interface name */
	if (tb[RTA_OIF] && filter.oifmask != -1)
		strncpy((char *)arg+sizeof(inet_prefix),
			ll_index_to_name(*(int*)RTA_DATA(tb[RTA_OIF])), IFNAMSIZ);
	
	return 0;
}

/*
 * route_get_exact_prefix: it dumps the routing table and search for a route
 * which has the prefix equal to `prefix', if it is found its destination
 * address is stored in `dst' and its interface name in `dev_name' (which must
 * be IFNAMSIZ big).
 */
int route_get_exact_prefix_dst(inet_prefix prefix, inet_prefix *dst, 
		char *dev_name)
{
	int do_ipv6 = AF_UNSPEC;
	struct rtnl_handle rth;
	char dst_data[sizeof(inet_prefix) + IFNAMSIZ];

	route_reset_filter();
	filter.tb = RT_TABLE_MAIN;

	filter.mdst=prefix;
	filter.rdst = filter.mdst;

	if (do_ipv6 == AF_UNSPEC && filter.tb)
		do_ipv6 = AF_INET;

	if (rtnl_open(&rth, 0) < 0)
		return -1;

	ll_init_map(&rth);

	if (rtnl_wilddump_request(&rth, do_ipv6, RTM_GETROUTE) < 0) {
		error(ERROR_MSG"Cannot send dump request"ERROR_POS);
		return -1;
	}

	setzero(dst_data, sizeof(dst_data));
	if (rtnl_dump_filter(&rth, route_get_gw, dst_data, NULL, NULL) < 0) {
		debug(DBG_NORMAL, ERROR_MSG "Dump terminated" ERROR_POS);
		return -1;
	}
	inet_copy(dst, (inet_prefix *)dst_data);
	memcpy(dev_name, dst_data+sizeof(inet_prefix), IFNAMSIZ);
	
	rtnl_close(&rth);

	return 0;
}

int route_flush_cache(int family)
{
	int len, err;
	int flush_fd;
	char ROUTE_FLUSH_SYSCTL[]="/proc/sys/net/ipvX/route/flush";
	char *buf = "-1";

	len = strlen(buf);
	if(family==AF_INET)
		ROUTE_FLUSH_SYSCTL[17]='4';
	else if(family==AF_INET6)
		ROUTE_FLUSH_SYSCTL[17]='6';
	else
		return -1;

	flush_fd=open(ROUTE_FLUSH_SYSCTL, O_WRONLY);
	if (flush_fd < 0) {
		debug(DBG_NORMAL, "Cannot open \"%s\"\n", ROUTE_FLUSH_SYSCTL);
		return -1;
	}
		
	if ((err=write (flush_fd, (void *)buf, len)) == 0) {
		debug(DBG_NORMAL, "Warning: Route Cache not flushed\n");
		return -1;
	} else if(err==-1) {
		debug(DBG_NORMAL, "Cannot flush routing cache: %s\n", strerror(errno));
		return -1;
	}
	close(flush_fd);

	return 0;
}

int route_ip_forward(int family, int enable)
{
	int len, err;
	int flush_fd;
	char *ROUTE_FORWARD_SYSCTL="/proc/sys/net/ipv4/ip_forward";
	char *ROUTE_FORWARD_SYSCTL_6="/proc/sys/net/ipv6/conf/all/forwarding";
	char *sysctl_path, buf[2];

	buf[0]='1';
	buf[1]=0;
	
	len = strlen(buf);
	if(family==AF_INET)
		sysctl_path = ROUTE_FORWARD_SYSCTL;
	else if(family==AF_INET6)
		sysctl_path = ROUTE_FORWARD_SYSCTL_6;
	else
		return -1;

	if(!enable)
		buf[0]='0';

	flush_fd=open(sysctl_path, O_WRONLY);
	if (flush_fd < 0) {
		debug(DBG_NORMAL, "Cannot open \"%s\"\n", sysctl_path);
		return -1;
	}
		
	if ((err=write (flush_fd, (void *)buf, len)) == 0) {
		debug(DBG_NORMAL, "Warning: ip_forward setting changed\n");
		return -1;
	} else if(err==-1) {
		debug(DBG_NORMAL, "Cannot change the ip_forward setting: %s\n", strerror(errno));
		return -1;
	}
	close(flush_fd);

	return 0;
}

/*
 * route_rp_filter
 *
 * Modifies the /proc/sys/net/ipv4/conf/INTERFACE/rp_filter config file.
 */
int route_rp_filter(int family, char *dev, int enable)
{
	int len, err, ret=0;
	int flush_fd;
	
	/* The path is /proc/sys/net/ipv4/conf/INTERFACE/rp_filter */
	const char *RP_FILTER_SYSCTL_1="/proc/sys/net/ipv4/conf/";
	const char *RP_FILTER_SYSCTL_1_IPV6="/proc/sys/net/ipv6/conf/";
	const char *RP_FILTER_SYSCTL_2="/rp_filter";
	char *final_path=0, buf[2];

	buf[0]='1';
	buf[1]=0;
#define RP_FILTER_PATH_SZ (strlen(RP_FILTER_SYSCTL_1)+		   \
			   strlen(RP_FILTER_SYSCTL_2)+IF_NAMESIZE+1)
	final_path=xzalloc(RP_FILTER_PATH_SZ);

	len = strlen(buf);
	if(family==AF_INET) {
		strcpy(final_path, RP_FILTER_SYSCTL_1);
	} else if(family==AF_INET6) {
		strcpy(final_path, RP_FILTER_SYSCTL_1_IPV6);
	} else
		ERROR_FINISH(ret, -1, finish);

	strcat(final_path, dev);
	strcat(final_path, RP_FILTER_SYSCTL_2);

	if(!enable)
		buf[0]='0';

	flush_fd=open(final_path, O_WRONLY);
	if (flush_fd < 0) {
		debug(DBG_NORMAL, "Cannot open \"%s\"\n", final_path);
		ERROR_FINISH(ret, -1, finish);
	}
		
	if ((err=write (flush_fd, (void *)buf, len)) == 0) {
		debug(DBG_NORMAL, "Warning: rp_filter setting changed\n");
		ERROR_FINISH(ret, -1, finish);
	} else if(err==-1) {
		debug(DBG_NORMAL, "Cannot change the rp_filter setting: %s\n", strerror(errno));
		ERROR_FINISH(ret, -1, finish);
	}
	close(flush_fd);

finish:
	if(final_path)
		xfree(final_path);
	return ret;
}

/*
 * route_rp_filter_all_dev: do route_rp_filter() for all the interfaces
 * present in the `ifs' array.
 */
int route_rp_filter_all_dev(int family, interface *ifs, int ifs_n, int enable)
{
	int i, ret=0;

	for(i=0; i<ifs_n; i++)
		ret+=route_rp_filter(family, ifs[i].dev_name, enable);

	return ret;
}

/*Life is strange*/
