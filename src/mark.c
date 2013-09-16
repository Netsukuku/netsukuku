	         /**************************************
	        *     AUTHOR: Federico Tomassini        *
	       *     Copyright (C) Federico Tomassini    *
	      *     Contact effetom@gmail.com             *
	     ***********************************************
	     *******          BEGIN 3/2006          ********
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

/* 
 * This code is written with my blood.
 * My hand was hurt. The keyboard was red.
 * In this code you can find my sacrifice.
 *
 * This code is a netfilter iptc library.
 * iptc is very bad documented: wisdom and 
 * debuggers was my friends to understand 
 * netfilter behavior. 
 * I hope you'll never need to code netfilter 
 * apps.
 * Memory dumpers are with you.
 */
#include "includes.h"
#include "config.h"

// to delete
#include <fcntl.h>

#include "iptunnel.h"
#include "mark.h"
#include "err_errno.h"
#include "log.h"

static int death_loop_rule;
static int clean_on_exit;
static rule_store rr,fr,dr;
static int dumped;

/* Table init: is too easy for comments. 
 * Returns:
 * 	0
 * 	-1
 */
int table_init(const char *table, iptc_handle_t *t)
{
	*t=iptc_init(table);
	if (!(*t)) {
		error("In table_init, table %s: -> %s", table,iptc_strerror(errno));
		err_ret(ERR_NETFIL,-1);
	}
	return 0;

}
/* 
 * insert the rule -rule- on chain -chain- 
 * at the position pos.
 * Returns:
 * 	0
 * 	-1
 */
int insert_rule(const char *rule,iptc_handle_t *t,const char *chain,int pos)
{
	int res;
	res=iptc_insert_entry(chain,(struct ipt_entry*)rule,0,t);
	if (!res) {
		error("In insert_rule: %s.",iptc_strerror(errno));
		err_ret(ERR_NETRUL,-1);
	}
	return 0;
}
/* 
 * append the rule -rule- on chain -chain-.
 * Returns:
 * 	0
 * 	-1
 */
int append_rule(const char *rule,iptc_handle_t *t,const char *chain)
{
	int res;
	res=iptc_append_entry(chain,(struct ipt_entry*)rule,t);
	if (!res) {
		error("In append_rule: %s.",iptc_strerror(errno));
		err_ret(ERR_NETRUL,-1);
	}
	return 0;
}
/*
 * commit modified rules and chains.
 * Returns:
 * 	0
 * 	-1
 */
int commit_rules(iptc_handle_t *t)
{
	int res;
	res=iptc_commit(t);
	if (!res) {
		error("In commit_rules: %s.",iptc_strerror(errno));
		err_ret(ERR_NETCOM,-1);
	}
	return 0;
}


/* 
 * Put in -rule- the netfilter rule:
 * 
 *  -A OUTPUT -o ntk_tunl+ -m conntrack  \
 *  --ctstate RELATED,ESTABLISHED -j CONNMARK \
 *  --restore-mark
 *  
 * -rule- has to be RESTORE_OUTPUT_RULE_SZ-sized
 */
void restore_output_rule_init(char *rule)
{
	struct ipt_entry *ee;
	struct ipt_entry_match *em;
	struct ipt_entry_target *et;
	struct ipt_conntrack_info *ici;
	struct ipt_connmark_target_info *icmi;

	memset(rule,0,RESTORE_OUTPUT_RULE_SZ);
	
	ee=(struct ipt_entry*)(rule);
	em=(struct ipt_entry_match*)(rule+OFFSET_MATCH);
	ici=(struct ipt_conntrack_info*)(rule+OFFSET_MATCH_INFO);
	et=(struct ipt_entry_target*)(rule+OFFSET_TARGET);
	icmi=(struct ipt_connmark_target_info*)(rule+OFFSET_TARGET_INFO);

	ee->next_offset=RESTORE_OUTPUT_RULE_SZ;
	ee->target_offset=OFFSET_TARGET;
	
	snprintf(ee->ip.outiface,IFNAMSIZ,"%s+",NTK_TUNL_PREFIX);
	memset(ee->ip.outiface_mask,0xFF,strlen(ee->ip.outiface)-1);

	strcpy(em->u.user.name,MOD_CONNTRACK);
	em->u.match_size=MATCH_SZ;;
	em->u.user.match_size=em->u.match_size;
	
	et->u.target_size=TARGET_SZ;
	et->u.user.target_size=et->u.target_size;
	strcpy(et->u.user.name,MOD_CONNMARK);

	ici->flags=1;
	ici->statemask|=IPT_CONNTRACK_STATE_BIT(IP_CT_RELATED);
	ici->statemask|=IPT_CONNTRACK_STATE_BIT(IP_CT_ESTABLISHED);

	icmi->mode=IPT_CONNMARK_RESTORE;
	icmi->mask= 0xffffffffUL;
}
/* 
 * Put in -rule- the netfilter rule:
 * 
 *  -A POSTROUTING -o ntk_tunl+ -m conntrack 
 *  --ctstate NEW -j ntk_mark_chain
 *  
 * -rule- has to be NTK_FORWARD_RULE_SZ-sized
 */
void ntk_forward_rule_init(char *rule)
{
	struct ipt_entry *ee;
	struct ipt_entry_match *em;
	struct ipt_entry_target *et;
	struct ipt_conntrack_info *ici;
	
	memset(rule,0,NTK_FORWARD_RULE_SZ);
	
	ee=(struct ipt_entry*)(rule);
	em=(struct ipt_entry_match*)(rule+IPT_ENTRY_SZ);
	ici=(struct ipt_conntrack_info*)(rule+OFFSET_MATCH_INFO);
	et=(struct ipt_entry_target*)(rule+OFFSET_TARGET);

	ee->next_offset=NTK_FORWARD_RULE_SZ;
	ee->target_offset=OFFSET_TARGET;
	snprintf(ee->ip.outiface,IFNAMSIZ,"%s+",NTK_TUNL_PREFIX);
	memset(ee->ip.outiface_mask,0xFF,strlen(ee->ip.outiface)-1);

	strcpy(em->u.user.name,MOD_CONNTRACK);
	em->u.match_size=MATCH_SZ;
	em->u.user.match_size=em->u.match_size;

	ici->flags=1;
	ici->statemask|=IPT_CONNTRACK_STATE_BIT(IP_CT_NEW);

	et->u.target_size=IPT_ENTRY_TARGET_SZ+4;
	et->u.user.target_size=et->u.target_size;
	strcpy(et->u.user.name,NTK_MARK_CHAIN);
}
/* 
 * Put in -rule- the netfilter rule:
 * 
 * 
 *  -A ntk_mark_chain -o ntk_tunl<outiface_num>
 *  -j CONNMARK --set-mark <outiface_num>
 *  
 * -rule- has to be MARK_RULE_SZ-sized
 */
void mark_rule_init(char *rule,char *outiface,int outiface_num)
{
	struct ipt_entry *ee;
	struct ipt_entry_target *et;
	struct ipt_connmark_target_info *icmi;

	memset(rule,0,MARK_RULE_SZ);
	
	ee=(struct ipt_entry*)(rule);
	et=(struct ipt_entry_target*)(rule+IPT_ENTRY_SZ);
	icmi=(struct ipt_connmark_target_info*)(rule+IPT_ENTRY_SZ+IPT_ENTRY_TARGET_SZ);

	ee->next_offset=MARK_RULE_SZ;
	ee->target_offset=IPT_ENTRY_SZ;

	et->u.target_size=TARGET_SZ;
	et->u.user.target_size=et->u.target_size;
	strcpy(et->u.user.name,MOD_CONNMARK);

	icmi->mode=IPT_CONNMARK_SET;
	icmi->mask= 0xffffffffUL;
	snprintf(ee->ip.outiface,IFNAMSIZ,"%s%d",outiface,outiface_num);
	memset(ee->ip.outiface_mask,0xFF,strlen(ee->ip.outiface));
	icmi->mark=outiface_num+1;
}
/* 
 * Put in -rule- the netfilter rule:
 * 
 * 
 *  -A PREROUTING -o ntk_tunl+ \
 *  -j CONNMARK --set-mark 25
 *  
 * -rule- has to be IGW_FILTER_RULE_SZ-sized
 */
void igw_mark_rule_init(char *rule)
{
	int res;
	struct ipt_entry *e;
	struct ipt_entry_target *et;

	memset(rule,0,IGW_FILTER_RULE_SZ);
	e=(struct ipt_entry*)rule;
	et=(struct ipt_entry_target*)(rule+IPT_ENTRY_SZ);
	
	e->next_offset=IGW_FILTER_RULE_SZ;
	e->target_offset=IPT_ENTRY_SZ;
	snprintf(e->ip.iniface,IFNAMSIZ,"%s+",NTK_TUNL_PREFIX);
	memset(e->ip.iniface_mask,0xFF,strlen(e->ip.iniface)-1);

	et->u.target_size=IPT_ENTRY_TARGET_SZ+4;
	et->u.user.target_size=et->u.target_size;
	strcpy(et->u.user.name,MARK_TARGET);
	res=INET_MARK;
	memcpy(et->data,&res,4);
}
/*
 * Build the chain ntk_mark_chain on 
 * mangle table.
 */
int ntk_mark_chain_init(iptc_handle_t *t)
{
	int res;
	res=iptc_is_chain(NTK_MARK_CHAIN,*t);
	if (res) {
		debug(DBG_NORMAL,"In mark_init: bizarre, ntk mangle" 
				 "chain is present yet. it will be flushed.");
		res=iptc_flush_entries(NTK_MARK_CHAIN,t);
		if (!res) 
			goto dontwork;
	} else {
		res=iptc_create_chain(NTK_MARK_CHAIN,t);
		if (!res) 
			goto dontwork;
	}
	return 0;
dontwork:
	error("In ntk_mark_chain_init: -> %s", iptc_strerror(errno));
	err_ret(ERR_NETCHA,-1)
}
/*
 * Takes committed rules and copies them
 * to structs. This is usefule to delete
 * the rules on exit, even if netfilter
 * was modified before the deletion/
 * Returns:
 * 	0
 * 	-1
 */
int store_rules()
{
	int res;
	iptc_handle_t t;
	struct ipt_entry *r,*f,*d;

	res=table_init(MANGLE_TABLE,&t);
	if (res) {
		error(err_str);
		err_ret(ERR_NETSTO,-1);
	}
	r=(struct ipt_entry*)iptc_first_rule(CHAIN_OUTPUT,&t);
	f=(struct ipt_entry*)iptc_first_rule(CHAIN_POSTROUTING,&t);
	/* Not elegant style, but faster */
	if (death_loop_rule) {
		d=(struct ipt_entry*)iptc_first_rule(CHAIN_PREROUTING,&t);
		if (r && f && d) {
			rr.sz=RESTORE_OUTPUT_RULE_SZ;
			memcpy(rr.e,r,rr.sz);
			rr.chain=CHAIN_OUTPUT;
			fr.sz=NTK_FORWARD_RULE_SZ;
			memcpy(fr.e,f,fr.sz);
			fr.chain=CHAIN_POSTROUTING;
			dr.sz=IGW_FILTER_RULE_SZ;
			memcpy(dr.e,d,dr.sz);
			dr.chain=CHAIN_PREROUTING;
			commit_rules(&t);
			return 0;
		}
		else {
			commit_rules(&t);
			error("In store_rules: %s.",iptc_strerror(errno));
			err_ret(ERR_NETSTO,-1);
		}
	}
	if (r && f ) {
		rr.sz=RESTORE_OUTPUT_RULE_SZ;
		memcpy(rr.e,r,rr.sz);
		rr.chain=CHAIN_OUTPUT;
		fr.sz=NTK_FORWARD_RULE_SZ;
		memcpy(fr.e,f,fr.sz);
		fr.chain=CHAIN_POSTROUTING;
		commit_rules(&t);
		return 0;
	}
	commit_rules(&t);
	err_ret(ERR_NETSTO,-1);
}

/* Two debugging functions: to delete */
int dump_rules()
{
	int fd;

	fd=open(DATA_DIR"/mark_rules",O_CREAT | O_WRONLY | O_TRUNC,0540);
	if (fd==-1) {
		dumped=0;
		error("Storing rules to fs: %s.", strerror(errno));
		return -1;
	}
	write(fd,&rr,sizeof(rule_store));
	write(fd,&fr,sizeof(rule_store));
	write(fd,&dr,sizeof(rule_store));
	close(fd);
	dumped=1;
	return 0;
}
int load_dump_rules()
{
	int fd;
	rule_store d_rr,d_fr,d_dr;
	if (!dumped)
		return 0;
	fd=open("/usr/share/netsukuku/mark_rules",O_RDONLY );
	if (fd==-1) 
		return -1;
	read(fd,&d_rr,sizeof(rule_store));
	read(fd,&d_fr,sizeof(rule_store));
	read(fd,&d_dr,sizeof(rule_store));
	close(fd);
	if (memcmp(&rr,&d_rr,sizeof(rule_store)))
		error("Stored rule rr differs from original.");
	if (memcmp(&fr,&d_fr,sizeof(rule_store)))
		error("Stored rule fr differs from original.");
	if (memcmp(&dr,&d_dr,sizeof(rule_store)))
		error("Stored rule dr differs from original.");
	return 0;
}

/*
 * This function builds:
 * 	- OUTPUT rule
 * 	- POSTROUTING rule
 * 	- PREROUTING rule
 * 	- ntk_mark_chain
 * and store rules for future deletion.
 *
 * Returns:
 * 	0
 * 	-1
 *
 * If -1, any rule will be committed.
 */
int mark_init(int igw)
{
	int res;
	iptc_handle_t t;
	char rule[MAX_RULE_SZ];

	/*res=inet_aton(NTK_NET_STR,&inet_dst);
	if (!res) {
		error("Can not convert str to addr.");
		goto cannot_init;
	}
	res=inet_aton(NTK_NET_MASK_STR,&inet_dst_mask);
	if (!res) {
		error("Can not convert str to addr.");
		goto cannot_init;
	}*/

	res=table_init(MANGLE_TABLE,&t);
	if (res) {
		error(err_str);
		goto cannot_init;
	}
	res=ntk_mark_chain_init(&t);
	if (res) {
		error(err_str);
		error("Unable to create netfilter ntk_mark_chain.");
		goto cannot_init;
	}
	restore_output_rule_init(rule);
	res=insert_rule(rule,&t,CHAIN_OUTPUT,0);
	if (res) {
		error(err_str);
		error("Unable to create netfilter restore-marking rule.");
		goto cannot_init;
	}
	ntk_forward_rule_init(rule);
	res=insert_rule(rule,&t,CHAIN_POSTROUTING,0);
	if (res) {
		error(err_str);
		error("Unable to create netfilter forwarding rule.");
		goto cannot_init;
	}	
	if (igw) {
		death_loop_rule=1; 
		igw_mark_rule_init(rule);
		res=insert_rule(rule,&t,CHAIN_PREROUTING,0);
		if (res) {
			error(err_str);
			error("Unable to create netfilter igw death loop rule.");
			death_loop_rule=0;
			goto cannot_init;
		}  
	}
	else
		death_loop_rule=0;

	res=commit_rules(&t);
	if (res) {
		error(err_str);
		error("Netfilter mangle table was not altered!");
		goto cannot_init;
	}
	res=store_rules();
	if (res) {
		error(err_str);
		error("Rules storing failed: autocleaning netfilter on exit disable.");
		clean_on_exit=0;
	}
	else
		clean_on_exit=1;
	dump_rules();
	debug(DBG_NORMAL,"Netfilter chain ntk_mark_chain created (mangle).");
	debug(DBG_NORMAL,"Netfilter restoring rule created (mangle->output).");
	debug(DBG_NORMAL,"Netfilter forwarding rule created (mangle->postrouting).");
	if (igw)
		debug(DBG_NORMAL,"Netfilter death loop igw rule created.");
	debug(DBG_NORMAL,"mark_init(), netfilter mangle table initialized.");
	loginfo("Netfilter mangle table modified.");
	return 0;
cannot_init:
	err_ret(ERR_MRKINI,-1);

}
/* 
 * Count the number of rules in ntk_mangle_chain.
 *
 * Returns the number of rules present in 
 * this chain.
 */ 
int count_ntk_mark_chain(iptc_handle_t *t)
{
	int nchain=0;
	const struct ipt_entry *e;

	e=iptc_first_rule(NTK_MARK_CHAIN,t);
	while (e) {
		nchain++;
		e=iptc_next_rule(e,t);
	}
	return nchain;
}
/*
 * This function build the rules:
 *
 * -A ntk_mark_chain -o ntk_tunl<m>
 *  -j CONNMARK --set-mark m
 *
 * If:
 *
 * s= n-number_of_rules_present
 * then:
 * 	if s>0, will be created s rules,
 * else:
 * 	nothing.
 *
 * Returns:
 * 	0
 * 	-1
 */
int create_mark_rules(int n)
{
	int nchain;
	int res,i;
	char rule[MARK_RULE_SZ];
	iptc_handle_t t;

	res=table_init(MANGLE_TABLE,&t);
	if (res) {
		error(err_str);
		err_ret(ERR_NETRUL,-1);
	}
	nchain=count_ntk_mark_chain(&t);
	if (nchain==-1) {
		error("In create_mark_rules: can not read ntk_mark_chain.");
		err_ret(ERR_NETRUL,-1);
	} 
	if (nchain>=n) {
		debug(DBG_NORMAL,"In create_mark_rules: rules present yet.");
		return 0;
	}
	for (i=nchain;i<n;i++) {
		mark_rule_init(rule,NTK_TUNL_PREFIX,i);
		res=append_rule(rule,&t,NTK_MARK_CHAIN);
		if (res) {
			error(err_str);
			err_ret(ERR_NETRUL,-1);
		}
	}
	res=commit_rules(&t);
	if (res) {
		error(err_str);
		err_ret(ERR_NETRUL,-1);
	}
	debug(DBG_NORMAL,"Created %d marking rules.", n-nchain);
	return 0;
}
/*
 * Deltion function: 
 * this delete the chain ntk_mark_chain
 * Returns:
 * 	0
 * 	-1
 */

int delete_ntk_forward_chain(iptc_handle_t *t)
{	
	int res;

	res=iptc_is_chain(NTK_MARK_CHAIN,*t);
	if (!res)
		return 0;
	res=iptc_flush_entries(NTK_MARK_CHAIN,t);
        if (!res) 
		goto cannot_delete;
	res=iptc_delete_chain(NTK_MARK_CHAIN,t);
	if (!res) 
		goto cannot_delete;
	return 0;
        	
cannot_delete:	
	error("In delete_ntk_forward_chain: -> %s", iptc_strerror(errno));
	err_ret(ERR_NETDEL,-1);
}
/* delete the first rule of a chain.
 * Unused.
 */
int delete_first_rule(iptc_handle_t *t,const char *chain)
{
	int res;
	const struct ipt_entry *e;

	e=iptc_first_rule(chain,t);
	if (!e)
		return 0;
	res=iptc_delete_num_entry(chain,0,t);
	if (!res)
		goto cannot_delete;
	return 0;
cannot_delete:	
	error("In delete_first_rule: -> %s", iptc_strerror(errno));
	err_ret(ERR_NETDEL,-1);
}
/*
 * Search for the position of rule -rule.rule-
 * on the chain rule.chain
 * Returns:
 * 	pos if rule was found
 * 	-1  if rule wasn't found
 */
int rule_position(rule_store *rule,iptc_handle_t *t)
{
	const struct ipt_entry *e;
	int res,count=-1,found=0;

	e=iptc_first_rule(rule->chain,t);
	while (e) {
		count++;
		res=memcmp(e,rule->e,rule->sz);
		if (!res) {
			found=1;
			break;
		}
		e=iptc_next_rule(e,t);
	}
	return found?count:-1;
}
/* 
 * Delete rule -rule.rule- on chain rule.chain.
 * Returns
 * 	0 if deletion is Ok or if nothing
 * 		has to be deleted
 * 	-1 error
 */
int delete_rule(rule_store *rule,iptc_handle_t *t)
{
	int pos,res;
	pos=rule_position(rule,t);
	if (pos==-1) {
		debug(DBG_NORMAL,"No rule in %s to be deleted.",rule->chain);
		return 0;
	}
	res=iptc_delete_num_entry(rule->chain,pos,t);
	if (!res) {
		debug(DBG_NORMAL,"Unable to delete rule in chain %s.",rule->chain);
		err_ret(ERR_NETDEL,-1);
	}
	return 0;
}
/* 
 * clean the rules committed by:
 * 	- mark_init
 * 	- create_mark_rules()
 * Returns:
 * 	0
 * 	-1
 */
		
int mark_close()
{
	iptc_handle_t t;
	int res;

	if (!clean_on_exit) {
		debug(DBG_NORMAL,"mark_close: cleaning is not my task.");
		return 0;
	}
	load_dump_rules();
	res=table_init(MANGLE_TABLE,&t);
	if (res) 
		goto reset_error;
	res=0;
	res+=delete_rule(&rr,&t);
	res+=delete_rule(&fr,&t);
	if (death_loop_rule) {
		debug(DBG_INSANE,"In mark_close: I'm an IGW: deleting death loop rule.");
		res+=delete_rule(&dr,&t);
	}
	if (res) 
		goto reset_error;
	res=delete_ntk_forward_chain(&t);
	if (res)
		goto reset_error;
	res=commit_rules(&t);
	if (res) 
		goto reset_error;
	debug(DBG_NORMAL,"Netfilter completely restored.");
	return 0;
reset_error:
	error(err_str);
	loginfo("Netfilter was not restored. To clean, run:\n"
		"\tiptables -t mangle -F\n"
		"\tiptables -t mangle -X %s",NTK_MARK_CHAIN);
	err_ret(ERR_NETRST,-1);
}
