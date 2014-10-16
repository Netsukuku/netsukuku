/* This file is part of Netsukuku
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
 */

#ifndef __LIBNETLINK_H__
#define __LIBNETLINK_H__ 1

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

struct rtnl_handle {
	int fd;
	struct sockaddr_nl local;
	struct sockaddr_nl peer;
	uint32_t seq;
	uint32_t dump;
};

extern int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions);
extern int rtnl_open_byproto(struct rtnl_handle *rth,
							 unsigned subscriptions, int protocol);
extern void rtnl_close(struct rtnl_handle *rth);
extern int rtnl_wilddump_request(struct rtnl_handle *rth, int fam,
								 int type);
extern int rtnl_dump_request(struct rtnl_handle *rth, int type, void *req,
							 int len);

typedef int (*rtnl_filter_t) (const struct sockaddr_nl *,
							  struct nlmsghdr * n, void *);
extern int rtnl_dump_filter(struct rtnl_handle *rth, rtnl_filter_t filter,
							void *arg1, rtnl_filter_t junk, void *arg2);
extern int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
					 pid_t peer, unsigned groups, struct nlmsghdr *answer,
					 rtnl_filter_t junk, void *jarg);
extern int rtnl_send(struct rtnl_handle *rth, const char *buf, int);


extern int addattr32(struct nlmsghdr *n, int maxlen, int type,
					 uint32_t data);
extern int addattr_l(struct nlmsghdr *n, int maxlen, int type,
					 const void *data, int alen);
extern int addraw_l(struct nlmsghdr *n, int maxlen, const void *data,
					int len);
extern int rta_addattr32(struct rtattr *rta, int maxlen, int type,
						 uint32_t data);
extern int rta_addattr_l(struct rtattr *rta, int maxlen, int type,
						 const void *data, int alen);

extern int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta,
						int len);
extern int parse_rtattr_byindex(struct rtattr *tb[], int max,
								struct rtattr *rta, int len);

#define parse_rtattr_nested(tb, max, rta) \
	(parse_rtattr((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta)))

extern int rtnl_listen(struct rtnl_handle *, rtnl_filter_t handler,
					   void *jarg);
extern int rtnl_from_file(FILE *, rtnl_filter_t handler, void *jarg);

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#endif							/* __LIBNETLINK_H__ */
