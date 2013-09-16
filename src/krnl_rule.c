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
 * --
 * This code derives from iproute2/iprule.c
 * written by Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>.
 */

#include "includes.h"

#include "libnetlink.h"
#include "inet.h"
#include "krnl_route.h"
#include "krnl_rule.h"
#include "common.h"

int rule_exec(int rtm_cmd, inet_prefix *from, inet_prefix *to, char *dev, 
		int prio, u_int fwmark, u_char table);

int rule_add(inet_prefix *from, inet_prefix *to, char *dev, 
		int prio, u_int fwmark, u_char table)
{
	return rule_exec(RTM_NEWRULE, from, to, dev, prio, fwmark, table);
}

int rule_del(inet_prefix *from, inet_prefix *to, char *dev, 
		int prio, u_int fwmark, u_char table)
{
	return rule_exec(RTM_DELRULE, from, to, dev, prio, fwmark, table);
}

int rule_replace(inet_prefix *from, inet_prefix *to, char *dev,
		int prio, u_int fwmark, u_char table)
{
	rule_del(from, to, dev, prio, fwmark, table);
	return	rule_add(from, to, dev, prio, fwmark, table);
}

/*
 * rule_exec:
 * `from' and `to' have to be in network order
 */
int rule_exec(int rtm_cmd, inet_prefix *from, inet_prefix *to, char *dev, 
		int prio, u_int fwmark, u_char table)
{
	struct {
		struct nlmsghdr 	nh;
		struct rtmsg 		rt;
		char   			buf[1024];
	} req;
	struct rtnl_handle rth;

	setzero(&req, sizeof(req));
	table = !table ? RT_TABLE_MAIN : table;
	
	req.nh.nlmsg_type = rtm_cmd;
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST;
	req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
	req.rt.rtm_type = RTN_UNSPEC;
	req.rt.rtm_family = AF_UNSPEC;
	req.rt.rtm_protocol = RTPROT_NETSUKUKU;
	req.rt.rtm_table = table;

	if (rtm_cmd == RTM_NEWRULE) {
		req.nh.nlmsg_flags |= NLM_F_CREATE|NLM_F_EXCL;
		req.rt.rtm_type = RTN_UNICAST;
	}

	if (from) {
		req.rt.rtm_src_len = from->bits;
		addattr_l(&req.nh, sizeof(req), RTA_SRC, &from->data, from->len);
		req.rt.rtm_family=from->family;
	}

	if (to) {
		req.rt.rtm_dst_len = to->bits;
		addattr_l(&req.nh, sizeof(req), RTA_DST, &to->data, to->len);
		req.rt.rtm_family=to->family;
	} 

	if (prio)
		addattr32(&req.nh, sizeof(req), RTA_PRIORITY, prio);

	if (fwmark)
		addattr32(&req.nh, sizeof(req), RTA_PROTOINFO, fwmark);

	if (dev) {
		addattr_l(&req.nh, sizeof(req), RTA_IIF, dev, strlen(dev)+1);
	} 

	if (req.rt.rtm_family == AF_UNSPEC)
		req.rt.rtm_family = AF_INET;

	if (rtnl_open(&rth, 0) < 0)
		return 1;

	if (rtnl_talk(&rth, &req.nh, 0, 0, NULL, NULL, NULL) < 0)
		return 2;

	rtnl_close(&rth);

	return 0;
}

/* 
 * rule_flush_table_range_filter: rtnl_dump filter for
 * rule_flush_table_range() (see below)
 */
int rule_flush_table_range_filter(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
        struct rtnl_handle rth2;
        struct rtmsg *r = NLMSG_DATA(n);
        int len = n->nlmsg_len;
        struct rtattr *tb[RTA_MAX+1];
	u_int a=*(u_int *)arg;
	u_int b=*((u_int *)arg+1);

        len -= NLMSG_LENGTH(sizeof(*r));
        if (len < 0)
                return -1;

        parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);

        if (tb[RTA_PRIORITY] && (r->rtm_table >= a && r->rtm_table <= b)) {
                n->nlmsg_type = RTM_DELRULE;
                n->nlmsg_flags = NLM_F_REQUEST;

                if (rtnl_open(&rth2, 0) < 0)
                        return -1;

                if (rtnl_talk(&rth2, n, 0, 0, NULL, NULL, NULL) < 0)
                        return -2;

                rtnl_close(&rth2);
        }

        return 0;
}

/*
 * rule_flush_table_range: deletes all the rules which lookup the table X.
 * The table X is any table in the range of `a' <= X <= `b'.
 */
int rule_flush_table_range(int family, int a, int b)
{
	struct rtnl_handle rth;
	int arg[2];
	
	if (rtnl_open(&rth, 0) < 0)
		return 1;

        if (rtnl_wilddump_request(&rth, family, RTM_GETRULE) < 0) {
                error("Cannot dump the routing rule table");
                return -1;
        }
        
	arg[0]=a;
	arg[1]=b;
        if (rtnl_dump_filter(&rth, rule_flush_table_range_filter, arg, NULL, NULL) < 0) {
                error("Flush terminated");
                return -1;
        }
	
	rtnl_close(&rth);
	
        return 0;
}
