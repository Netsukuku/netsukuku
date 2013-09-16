#ifndef LL_MAP_H
#define LL_MAP_H

void ll_free_index(void);
int ll_remember_index(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg);
int ll_init_map(struct rtnl_handle *rth);
int ll_name_to_index(const char *name);
const char *ll_index_to_name(int idx);
const char *ll_idx_n2a(int idx, char *buf);
int ll_index_to_type(int idx);
unsigned ll_index_to_flags(int idx);
int ll_first_up_if(void);
int ll_nth_up_if(int n);

#endif /*LL_MAP_H*/
