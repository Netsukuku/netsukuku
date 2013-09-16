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
#include <fnmatch.h>

#include "common.h"
#include "inet.h"
#include "if.h"
#include "libnetlink.h"
#include "ll_map.h"

extern int errno;

static struct
{       
        int ifindex;
        int family;
        int oneline;
        int showqueue;
        inet_prefix pfx;
        int scope, scopemask;
        int flags, flagmask;
        int up;
        char *label;
        int flushed;
        char *flushb;
        int flushp;
        int flushe; 
        struct rtnl_handle *rth;
} filter;

/*
 * ifs_find_idx: returns the pointer to the interface struct of the 
 * device which has the index equal to `dev_idx'.
 * `ifs' is the array which keeps the interface list and has `ifs_n' elements.
 */
interface *ifs_find_idx(interface *ifs, int ifs_n, int dev_idx)
{
	int i;

	for(i=0; i<ifs_n; i++)
		if(ifs[i].dev_idx == dev_idx)
			return &ifs[i];

	return 0;
}

int ifs_find_devname(interface *ifs, int ifs_n, char *dev_name)
{
	int i;

	if(!dev_name)
		return -1;

	for(i=0; i<ifs_n; i++)
		if(ifs[i].dev_name && 
			!strncmp(ifs[i].dev_name, dev_name, IFNAMSIZ))
			return i;

	return -1;
}

/*
 * ifs_del: removes from the `ifs' array the device which is at the
 * `if_pos'th position. `*ifs_n' is then decremented.
 */
void ifs_del(interface *ifs, int *ifs_n, int if_pos)
{
	if(if_pos == (*ifs_n)-1)
		setzero(&ifs[if_pos], sizeof(interface));
	else {
		memcpy(&ifs[if_pos], &ifs[(*ifs_n)-1], sizeof(interface));
		setzero(&ifs[(*ifs_n)-1], sizeof(interface));
	}

	(*ifs_n)--;
}

/*
 * ifs_del_byname: deletes from the `ifs' array the device whose name is equal
 * to `dev_name'
 */
void ifs_del_byname(interface *ifs, int *ifs_n, char *dev_name)
{
	int if_pos;

	if_pos=ifs_find_devname(ifs, *ifs_n, dev_name);
	if(if_pos < 0)
		return;

	ifs_del(ifs, ifs_n, if_pos);
}

/*
 * ifs_del_all_name: deleted from the `ifs' array all the device which have a
 * device name that begins with `dev_name'. For example, 
 * ifs_del_all_name(ifs, ifs_n, "tun") deletes all the tunnel iifs
 */
void ifs_del_all_name(interface *ifs, int *ifs_n, char *dev_name)
{
	int i, dev_len;

	if(!dev_name || (dev_len=strlen(dev_name)) > IFNAMSIZ)
		return;
	
	for(i=0; i<(*ifs_n); i++) {
		if(ifs[i].dev_name && 
			!strncmp(ifs[i].dev_name, dev_name, dev_len)) {

				ifs_del(ifs, ifs_n, i);
				if(i <= (*ifs_n)-1)
					i--;
		}
	}
}

/*
 * ifs_get_pos: this is a stupid functions which returns the position of the
 * struct in the `ifs' array which has the dev_idx element equal to
 * `dev'->dev_idx. The `ifs' array has `ifs_n' members.
 * If it is not found -1 is returned.
 */
int ifs_get_pos(interface *ifs, int ifs_n, interface *dev)
{
	int i;

	for(i=0; i<ifs_n; i++)
		if(ifs[i].dev_idx == dev->dev_idx)
			return i;

	return -1;
}

/* 
 * get_dev: It returs the first dev it finds up and sets `*dev_ids' to the
 * device's index. On error NULL is returned.
 */
const char *get_dev(int *dev_idx) 
{
	int idx;

	if((idx=ll_first_up_if()) == -1) {
		error("Couldn't find \"up\" devices. Set one dev \"up\", or "
				"specify the device name in the options.");
		return 0;
	}
	if(dev_idx)
		*dev_idx=idx;
	return ll_index_to_name(idx);
}

/*
 * get_all_ifs: It fills the `ifs' array with all the network interfaces it
 * finds up. The `ifs' array has `ifs_n'# members.
 * It returns the number of filled interfaces.
 */
int get_all_up_ifs(interface *ifs, int ifs_n)
{
	int i, idx, n;

	for(i=0, n=0; i<ifs_n; i++) {
		idx=ll_nth_up_if(n+1);
		if(idx <= 0)
			continue;
		
		ifs[n].dev_idx=idx;
	        strncpy(ifs[n].dev_name, ll_index_to_name(idx), IFNAMSIZ);
		loginfo("Network interface \"%s\" detected", ifs[n].dev_name);
		n++;

		if((idx-1) > i)
			i=idx-1;
	}
	
	return n;
}

int set_flags(char *dev, u_int flags, u_int mask)
{
	struct ifreq ifr;
	int s;

	strcpy(ifr.ifr_name, dev);
	if((s=new_socket(AF_INET)) < 0) {
		error("Error while setting \"%s\" flags: Cannot open socket", dev);
		return -1;
	}

	if(ioctl(s, SIOCGIFFLAGS, &ifr)) {
		error("Error while setting \"%s\" flags: %s", dev, strerror(errno));
		close(s);
		return -1;
	}

	ifr.ifr_flags &= ~mask;
	ifr.ifr_flags |= mask&flags;
	if(ioctl(s, SIOCSIFFLAGS, &ifr)) {
		error("Error while setting \"%s\" flags: %s", dev, strerror(errno));
		close(s);
		return -1;
	}
	close(s);
	return 0;
}

int set_dev_up(char *dev)
{
	u_int mask=0, flags=0;
	
	mask |= IFF_UP;
	flags |= IFF_UP;
	return set_flags(dev, flags, mask);
}

int set_dev_down(char *dev)
{
	u_int mask=0, flags=0;
	
	mask |= IFF_UP;
	flags &= ~IFF_UP;
	return set_flags(dev, flags, mask);
}

/*
 * set_all_ifs: for all the `ifs_n' interfaces present in the `ifs' array, it
 * calls the `set_func' functions, passing as argument ifs[i].dev_name.
 * (All the above set_* functions can be used as `set_func').
 * It returns the sum of all each return code, of set_func, therefore if it
 * returns a negative value, some `set_func' gave an error.
 */
int set_all_ifs(interface *ifs, int ifs_n, int (*set_func)(char *dev))
{
	int i, ret=0;

	for(i=0; i<ifs_n; i++)
		ret+=set_func(ifs[i].dev_name);

	return ret;
}

/*
 * if_init_all: it initializes all the `ifs_n'# interfaces present in the
 * `ifs' array. If `ifs_n' is zero it gets all the current up interfaces and
 * stores them in `new_ifs', updating the `new_ifs_n' counter too. Then it
 * initializes them.
 * In the `new_ifs' array, which must be at least big as the `ids' array, it
 * stores all the initialized interfaces, updating the `new_ifs_n' counter.
 * On error -1 is returned.
 */
int if_init_all(char *ifs_name[MAX_INTERFACES], int ifs_n, 
		interface *new_ifs, int *new_ifs_n)
{
	struct rtnl_handle rth;
	int ret=0, i, n;

	if (rtnl_open(&rth, 0) < 0) {
		error("Cannot open the rtnetlink socket to talk to the kernel's "
				"soul");
		return -1;
	}
	ll_init_map(&rth);

	if(!ifs_n) {
		ret=get_all_up_ifs(new_ifs, MAX_INTERFACES);

		if(!ret)
			return -1;

		*new_ifs_n=ret;
	} else {
		for(i=0, n=0; i<ifs_n; i++) {
			
			new_ifs[n].dev_idx=ll_name_to_index(ifs_name[n]);
			if(!new_ifs[n].dev_idx) {
				error("Cannot initialize the %s interface. "
						"Ignoring it", ifs_name[n]);
				continue;
			}

			strncpy(new_ifs[n].dev_name, ifs_name[n], IFNAMSIZ);
			n++;
		}
		
		if(!n)
			return -1;
			
		*new_ifs_n=n;
	}

	if(set_all_ifs(new_ifs, *new_ifs_n, set_dev_up) < 0)
		return -1;

	rtnl_close(&rth);

	return ret;
}

void if_close_all(void)
{
#if 0
	/* XXX: disabled for now, it is buggy */
	ll_free_index();
#endif
}

/*
 * set_dev_ip: Assign the given `ip' to the interface named `dev'
 * On success 0 is returned, -1 otherwise.
 */
int set_dev_ip(inet_prefix ip, char *dev)
{
	int s=-1;

	if(ip.family == AF_INET) {
		struct ifreq req;

		if((s=new_socket(AF_INET)) < 0) {
			error("Error while setting \"%s\" ip: Cannot open socket", dev);
			return -1;
		}

		strncpy(req.ifr_name, dev, IFNAMSIZ);
		inet_to_sockaddr(&ip, 0, &req.ifr_addr, 0);

		if(ioctl(s, SIOCSIFADDR, &req)) {
			error("Error while setting \"%s\" ip: %s", dev, strerror(errno));
			close(s);
			return -1;
		}
	} else if(ip.family == AF_INET6) {
		struct in6_ifreq req6;
		struct sockaddr_in6 sin6;
		struct sockaddr *sa=(struct sockaddr *)&sin6;

		if((s=new_socket(AF_INET6)) < 0) {
			error("Error while setting \"%s\" ip: Cannot open socket", dev);
			return -1;
		}
		
		req6.ifr6_ifindex=ll_name_to_index(dev);
		req6.ifr6_prefixlen=0;
		inet_to_sockaddr(&ip, 0, sa, 0);
		memcpy(&req6.ifr6_addr, sin6.sin6_addr.s6_addr32, ip.len);

		if(ioctl(s, SIOCSIFADDR, &req6)) {
			error("Error while setting \"%s\" ip: %s", dev, strerror(errno));
			close(s);
			return -1;
		}

	}

	close(s);
	return 0;
}

/* 
 * set_all_dev_ip: it sets the given `ip' to all the `ifs_n'# interfaces
 * present in the `ifs' array.
 * On error -1 is returned.
 */
int set_all_dev_ip(inet_prefix ip, interface *ifs, int ifs_n)
{
	int i, ret=0;
	
	for(i=0; i<ifs_n; i++)
		ret+=set_dev_ip(ip, ifs[i].dev_name);

	return ret;
}

/*
 * get_dev_ip: fetches the ip currently assigned to the interface named `dev'
 * and stores it to `ip'.
 * On success 0 is returned, -1 otherwise.
 */
int get_dev_ip(inet_prefix *ip, int family, char *dev)
{
	int s=-1;
	int ret=0;

	setzero(ip, sizeof(inet_prefix));

	if((s=new_socket(family)) < 0) {
		error("Error while setting \"%s\" ip: Cannot open socket", dev);
		return -1;
	}

	if(family == AF_INET) {
		struct ifreq req;

		strncpy(req.ifr_name, dev, IFNAMSIZ);
		req.ifr_addr.sa_family = family;
		
		if(ioctl(s, SIOCGIFADDR, &req))
			ERROR_FINISH(ret, -1, finish);

		sockaddr_to_inet(&req.ifr_addr, ip, 0);
	} else if(family == AF_INET6) {
		struct in6_ifreq req6;

		/*
		 * XXX: NOT TESTED
		 */

		req6.ifr6_ifindex=ll_name_to_index(dev);
		req6.ifr6_prefixlen=0;

		if(ioctl(s, SIOCGIFADDR, &req6))
			ERROR_FINISH(ret, -1, finish);

		inet_setip(ip, (u_int *)&req6.ifr6_addr, family);
	}

finish:
	if(s != -1)
		close(s);
	return ret;
}


/*
 * All the code below this point is ripped from iproute2/iproute.c
 * written by Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>.
 *
 * Modified lightly
 */
static int flush_update(void)
{                       
        if (rtnl_send(filter.rth, filter.flushb, filter.flushp) < 0) {
                error("Failed to send flush request: %s", strerror(errno));
                return -1;
        }               
        filter.flushp = 0;
        return 0;
}

int print_addrinfo(const struct sockaddr_nl *who, struct nlmsghdr *n, 
		   void *arg)
{
	struct ifaddrmsg *ifa = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr * rta_tb[IFA_MAX+1];
	char b1[64];

	if (n->nlmsg_type != RTM_NEWADDR && n->nlmsg_type != RTM_DELADDR)
		return 0;
	len -= NLMSG_LENGTH(sizeof(*ifa));
	if (len < 0) {
		error("BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (filter.flushb && n->nlmsg_type != RTM_NEWADDR)
		return 0;

	parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(ifa), n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

	if (!rta_tb[IFA_LOCAL])
		rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];
	if (!rta_tb[IFA_ADDRESS])
		rta_tb[IFA_ADDRESS] = rta_tb[IFA_LOCAL];

	if (filter.ifindex && filter.ifindex != ifa->ifa_index)
		return 0;
	if ((filter.scope^ifa->ifa_scope)&filter.scopemask)
		return 0;
	if ((filter.flags^ifa->ifa_flags)&filter.flagmask)
		return 0;
	if (filter.label) {
		const char *label;
		if (rta_tb[IFA_LABEL])
			label = RTA_DATA(rta_tb[IFA_LABEL]);
		else
			label = ll_idx_n2a(ifa->ifa_index, b1);
		if (fnmatch(filter.label, label, 0) != 0)
			return 0;
	}
	if (filter.pfx.family) {
		if (rta_tb[IFA_LOCAL]) {
			inet_prefix dst;
			setzero(&dst, sizeof(dst));
			dst.family = ifa->ifa_family;
			memcpy(&dst.data, RTA_DATA(rta_tb[IFA_LOCAL]), 
					RTA_PAYLOAD(rta_tb[IFA_LOCAL]));
			if (inet_addr_match(&dst, &filter.pfx, filter.pfx.bits))
				return 0;
		}
	}

	if (filter.flushb) {
		struct nlmsghdr *fn;
		if (NLMSG_ALIGN(filter.flushp) + n->nlmsg_len > filter.flushe) {
			if (flush_update())
				return -1;
		}
		fn = (struct nlmsghdr*)(filter.flushb + NLMSG_ALIGN(filter.flushp));
		memcpy(fn, n, n->nlmsg_len);
		fn->nlmsg_type = RTM_DELADDR;
		fn->nlmsg_flags = NLM_F_REQUEST;
		fn->nlmsg_seq = ++filter.rth->seq;
		filter.flushp = (((char*)fn) + n->nlmsg_len) - filter.flushb;
		filter.flushed++;
	}

	return 0;
}

struct nlmsg_list
{
        struct nlmsg_list *next;
        struct nlmsghdr   h;
};

static int store_nlmsg(const struct sockaddr_nl *who, struct nlmsghdr *n,
                       void *arg)
{
        struct nlmsg_list **linfo = (struct nlmsg_list**)arg;
        struct nlmsg_list *h;
        struct nlmsg_list **lp;

        h = malloc(n->nlmsg_len+sizeof(void*));
        if (h == NULL)
                return -1;

        memcpy(&h->h, n, n->nlmsg_len);
        h->next = NULL;

        for (lp = linfo; *lp; lp = &(*lp)->next) /* NOTHING */;
        *lp = h;

        ll_remember_index((struct sockaddr_nl *)who, n, NULL);
        return 0;
}

int ip_addr_flush(int family, char *dev, int scope)
{
	struct nlmsg_list *linfo = NULL;
	struct rtnl_handle rth;
	char *filter_dev = NULL;

	setzero(&filter, sizeof(filter));
	filter.showqueue = 1;

	filter.family = family;
	filter_dev = dev;

	if (rtnl_open(&rth, 0) < 0)
		return -1;

	if (rtnl_wilddump_request(&rth, family, RTM_GETLINK) < 0) {
		error("Cannot send dump request: %s", strerror(errno));
		return -1;
	}

	if (rtnl_dump_filter(&rth, store_nlmsg, &linfo, NULL, NULL) < 0) {
		error("Dump terminated");
		return -1;
	}

	filter.ifindex = ll_name_to_index(filter_dev);
	if (filter.ifindex <= 0) {
		error("Device \"%s\" does not exist.", filter_dev);
		return -1;
	}

	int round = 0;
	char flushb[4096-512];

	filter.flushb = flushb;
	filter.flushp = 0;
	filter.flushe = sizeof(flushb);
	filter.rth = &rth;
        filter.scopemask = -1;
	filter.scope = scope;
	
	for (;;) {
		if (rtnl_wilddump_request(&rth, filter.family, RTM_GETADDR) < 0) {
			error("Cannot send dump request: %s", strerror(errno));
			return -1;
		}
		filter.flushed = 0;
		if (rtnl_dump_filter(&rth, print_addrinfo, stdout, NULL, NULL) < 0) {
			error("Flush terminated: %s", errno);
			return -1;
		}
		if (filter.flushed == 0)
			return 0;

		round++;
		if (flush_update() < 0)
			return -1;
	}

	rtnl_close(&rth);
}

int ip_addr_flush_all_ifs(interface *ifs, int ifs_n, int family, int scope)
{
	int i, ret=0;
	
	for(i=0; i<ifs_n; i++)
		ret+=ip_addr_flush(family, ifs[i].dev_name, scope);

	return ret;
}
