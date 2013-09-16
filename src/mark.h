#ifndef MARK_H
#define MARK_H

#include "libiptc/libiptc.h"
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ip_conntrack_tuple.h>
#include "libiptc/ipt_conntrack.h"
#include "libiptc/ipt_connmark.h"
#include "libiptc/ipt_CONNMARK.h"


#define MANGLE_TABLE		"mangle"
#define FILTER_TABLE		"filter"
#define NTK_MARK_CHAIN		"ntk_mark_chain"
#define CHAIN_OUTPUT		"OUTPUT"
#define CHAIN_POSTROUTING	"POSTROUTING"
#define CHAIN_PREROUTING	"PREROUTING"
#define CHAIN_POSTROUTING	"POSTROUTING"
#define CHAIN_FORWARD		"FORWARD"

#define MOD_CONNTRACK		"conntrack"
#define MOD_CONNMARK		"CONNMARK"
#define MARK_TARGET		"MARK"

#define NTK_NET_STR		"10.0.0.0"
#define NTK_NET_MASK_STR	"255.0.0.0"

#define IPT_ENTRY_SZ		sizeof(struct ipt_entry)
#define IPT_ENTRY_MATCH_SZ	sizeof(struct ipt_entry_match)
#define IPT_ENTRY_TARGET_SZ	sizeof(struct ipt_entry_target)
#define IPT_CT_INFO_SZ		sizeof(struct ipt_conntrack_info)
#define IPT_CM_TARGET_INFO_SZ	sizeof(struct ipt_connmark_target_info)

#define MATCH_SZ		IPT_ENTRY_MATCH_SZ+IPT_CT_INFO_SZ
#define TARGET_SZ		IPT_ENTRY_TARGET_SZ+IPT_CM_TARGET_INFO_SZ

#define RESTORE_OUTPUT_RULE_SZ	IPT_ENTRY_SZ+MATCH_SZ+TARGET_SZ	

#define OFFSET_MATCH		IPT_ENTRY_SZ
#define OFFSET_MATCH_INFO	OFFSET_MATCH+IPT_ENTRY_MATCH_SZ
#define OFFSET_TARGET		OFFSET_MATCH_INFO+IPT_CT_INFO_SZ
#define OFFSET_TARGET_INFO	OFFSET_TARGET+IPT_ENTRY_TARGET_SZ
		
#define MARK_RULE_SZ		IPT_ENTRY_SZ+TARGET_SZ
#define MAX_MARK_RULES		100

#define NTK_FORWARD_RULE_SZ	OFFSET_TARGET_INFO+4

#define IGW_FILTER_RULE_SZ	IPT_ENTRY_SZ+IPT_ENTRY_SZ+4
#define INET_MARK		25

#define MAX_RULE_SZ		RESTORE_OUTPUT_RULE_SZ

//struct in_addr inet_dst,inet_dst_mask;

typedef struct rule_store {
	char			e[RESTORE_OUTPUT_RULE_SZ];
	int			sz;
	char 			*chain;
} rule_store;

/* Functions */

int table_init(const char *table, iptc_handle_t *t);
int insert_rule(const char *rule,iptc_handle_t *t,const char *chain,int pos);
int append_rule(const char *rule,iptc_handle_t *t,const char *chain);
int commit_rules(iptc_handle_t *t);
void restore_output_rule_init(char *rule);
void ntk_forward_rule_init(char *rule);
void mark_rule_init(char *rule,char *outiface,int outiface_num);
void igw_mark_rule_init(char *rule);
int ntk_mark_chain_init(iptc_handle_t *t);
int store_rules();
int mark_init(int igw);
int count_ntk_mark_chain(iptc_handle_t *t);
int create_mark_rules(int n);
int delete_ntk_forward_chain(iptc_handle_t *t);
int delete_first_rule(iptc_handle_t *t,const char *chain);
int rule_position(rule_store *rule,iptc_handle_t *t);
int delete_rule(rule_store *rule,iptc_handle_t *t);
int mark_close();

#endif /* MARK_H */
