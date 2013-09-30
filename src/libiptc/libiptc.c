/* Library which manipulates firewall rules.  Version $Revision: 1.1 $ */

/* Architecture of firewall rules is as follows:
 *
 * Chains go INPUT, FORWARD, OUTPUT then user chains.
 * Each user chain starts with an ERROR node.
 * Every chain ends with an unconditional jump: a RETURN for user chains,
 * and a POLICY for built-ins.
 */

/* (C) 1999 Paul ``Rusty'' Russell - Placed under the GNU GPL (See
 * COPYING for details). 
 * (C) 2000-2004 by the Netfilter Core Team <coreteam@netfilter.org>
 *
 * 2003-Jun-20: Harald Welte <laforge@netfilter.org>:
 *	- Reimplementation of chain cache to use offsets instead of entries
 * 2003-Jun-23: Harald Welte <laforge@netfilter.org>:
 * 	- performance optimization, sponsored by Astaro AG (http://www.astaro.com/)
 * 	  don't rebuild the chain cache after every operation, instead fix it
 * 	  up after a ruleset change.  
 * 2004-Aug-18: Harald Welte <laforge@netfilter.org>:
 * 	- futher performance work: total reimplementation of libiptc.
 * 	- libiptc now has a real internal (linked-list) represntation of the
 * 	  ruleset and a parser/compiler from/to this internal representation
 * 	- again sponsored by Astaro AG (http://www.astaro.com/)
 */
#include <sys/types.h>
#include <sys/socket.h>

#include "linux_list.h"

//#define IPTC_DEBUG2 1

#ifdef IPTC_DEBUG2
#include <fcntl.h>
#define DEBUGP(x, args...)	fprintf(stderr, "%s: " x, __FUNCTION__, ## args)
#define DEBUGP_C(x, args...)	fprintf(stderr, x, ## args)
#else
#define DEBUGP(x, args...)
#define DEBUGP_C(x, args...)
#endif

#ifndef IPT_LIB_DIR
#define IPT_LIB_DIR "/usr/local/lib/iptables"
#endif

static int sockfd = -1;
static int sockfd_use = 0;
static void *iptc_fn = NULL;

static const char *hooknames[]
= { [HOOK_PRE_ROUTING]  "PREROUTING",
    [HOOK_LOCAL_IN]     "INPUT",
    [HOOK_FORWARD]      "FORWARD",
    [HOOK_LOCAL_OUT]    "OUTPUT",
    [HOOK_POST_ROUTING] "POSTROUTING",
#ifdef HOOK_DROPPING
    [HOOK_DROPPING]	"DROPPING"
#endif
};

#if 0
/* Convenience structures */
struct ipt_error_target
{
	STRUCT_ENTRY_TARGET t;
	char error[TABLE_MAXNAMELEN];
};
#endif

struct chain_head;
struct rule_head;

struct counter_map
{
	enum {
		COUNTER_MAP_NOMAP,
		COUNTER_MAP_NORMAL_MAP,
		COUNTER_MAP_ZEROED,
		COUNTER_MAP_SET
	} maptype;
	unsigned int mappos;
};

enum iptcc_rule_type {
	IPTCC_R_STANDARD,		/* standard target (ACCEPT, ...) */
	IPTCC_R_MODULE,			/* extension module (SNAT, ...) */
	IPTCC_R_FALLTHROUGH,		/* fallthrough rule */
	IPTCC_R_JUMP,			/* jump to other chain */
};

struct rule_head
{
	struct list_head list;
	struct chain_head *chain;
	struct counter_map counter_map;

	unsigned int index;		/* index (needed for counter_map) */
	unsigned int offset;		/* offset in rule blob */

	enum iptcc_rule_type type;
	struct chain_head *jump;	/* jump target, if IPTCC_R_JUMP */

	unsigned int size;		/* size of entry data */
	STRUCT_ENTRY entry[0];
};

struct chain_head
{
	struct list_head list;
	char name[TABLE_MAXNAMELEN];
	unsigned int hooknum;		/* hook number+1 if builtin */
	unsigned int references;	/* how many jumps reference us */
	int verdict;			/* verdict if builtin */

	STRUCT_COUNTERS counters;	/* per-chain counters */
	struct counter_map counter_map;

	unsigned int num_rules;		/* number of rules in list */
	struct list_head rules;		/* list of rules */

	unsigned int index;		/* index (needed for jump resolval) */
	unsigned int head_offset;	/* offset in rule blob */
	unsigned int foot_index;	/* index (needed for counter_map) */
	unsigned int foot_offset;	/* offset in rule blob */
};

STRUCT_TC_HANDLE
{
	int changed;			 /* Have changes been made? */

	struct list_head chains;
	
	struct chain_head *chain_iterator_cur;
	struct rule_head *rule_iterator_cur;

	STRUCT_GETINFO info;
	STRUCT_GET_ENTRIES *entries;
};

/* allocate a new chain head for the cache */
static struct chain_head *iptcc_alloc_chain_head(const char *name, int hooknum)
{
	struct chain_head *c = malloc(sizeof(*c));
	if (!c)
		return NULL;
	memset(c, 0, sizeof(*c));

	strncpy(c->name, name, TABLE_MAXNAMELEN);
	c->hooknum = hooknum;
	INIT_LIST_HEAD(&c->rules);

	return c;
}

/* allocate and initialize a new rule for the cache */
static struct rule_head *iptcc_alloc_rule(struct chain_head *c, unsigned int size)
{
	struct rule_head *r = malloc(sizeof(*r)+size);
	if (!r)
		return NULL;
	memset(r, 0, sizeof(*r));

	r->chain = c;
	r->size = size;

	return r;
}

/* notify us that the ruleset has been modified by the user */
static void
set_changed(TC_HANDLE_T h)
{
	h->changed = 1;
}

#ifdef IPTC_DEBUG
static void do_check(TC_HANDLE_T h, unsigned int line);
#define CHECK(h) do { if (!getenv("IPTC_NO_CHECK")) do_check((h), __LINE__); } while(0)
#else
#define CHECK(h)
#endif


/**********************************************************************
 * iptc blob utility functions (iptcb_*)
 **********************************************************************/

static inline int
iptcb_get_number(const STRUCT_ENTRY *i,
	   const STRUCT_ENTRY *seek,
	   unsigned int *pos)
{
	if (i == seek)
		return 1;
	(*pos)++;
	return 0;
}

static inline int
iptcb_get_entry_n(STRUCT_ENTRY *i,
	    unsigned int number,
	    unsigned int *pos,
	    STRUCT_ENTRY **pe)
{
	if (*pos == number) {
		*pe = i;
		return 1;
	}
	(*pos)++;
	return 0;
}

static inline STRUCT_ENTRY *
iptcb_get_entry(TC_HANDLE_T h, unsigned int offset)
{
	return (STRUCT_ENTRY *)((char *)h->entries->entrytable + offset);
}

static unsigned int
iptcb_entry2index(const TC_HANDLE_T h, const STRUCT_ENTRY *seek)
{
	unsigned int pos = 0;

	if (ENTRY_ITERATE(h->entries->entrytable, h->entries->size,
			  iptcb_get_number, seek, &pos) == 0) {
		fprintf(stderr, "ERROR: offset %u not an entry!\n",
			(unsigned int)((char *)seek - (char *)h->entries->entrytable));
		abort();
	}
	return pos;
}

static inline STRUCT_ENTRY *
iptcb_offset2entry(TC_HANDLE_T h, unsigned int offset)
{
	return (STRUCT_ENTRY *) ((void *)h->entries->entrytable+offset);
}


static inline unsigned long
iptcb_entry2offset(const TC_HANDLE_T h, const STRUCT_ENTRY *e)
{
	return (void *)e - (void *)h->entries->entrytable;
}

static inline unsigned int
iptcb_offset2index(const TC_HANDLE_T h, unsigned int offset)
{
	return iptcb_entry2index(h, iptcb_offset2entry(h, offset));
}

/* Returns 0 if not hook entry, else hooknumber + 1 */
static inline unsigned int
iptcb_ent_is_hook_entry(STRUCT_ENTRY *e, TC_HANDLE_T h)
{
	unsigned int i;

	for (i = 0; i < NUMHOOKS; i++) {
		if ((h->info.valid_hooks & (1 << i))
		    && iptcb_get_entry(h, h->info.hook_entry[i]) == e)
			return i+1;
	}
	return 0;
}


/**********************************************************************
 * iptc cache utility functions (iptcc_*)
 **********************************************************************/

/* Is the given chain builtin (1) or user-defined (0) */
static unsigned int iptcc_is_builtin(struct chain_head *c)
{
	return (c->hooknum ? 1 : 0);
}

/* Get a specific rule within a chain */
static struct rule_head *iptcc_get_rule_num(struct chain_head *c,
					    unsigned int rulenum)
{
	struct rule_head *r;
	unsigned int num = 0;

	list_for_each_entry(r, &c->rules, list) {
		num++;
		if (num == rulenum)
			return r;
	}
	return NULL;
}

/* Get a specific rule within a chain backwards */
static struct rule_head *iptcc_get_rule_num_reverse(struct chain_head *c,
					    unsigned int rulenum)
{
	struct rule_head *r;
	unsigned int num = 0;

	list_for_each_entry_reverse(r, &c->rules, list) {
		num++;
		if (num == rulenum)
			return r;
	}
	return NULL;
}

/* Returns chain head if found, otherwise NULL. */
static struct chain_head *
iptcc_find_chain_by_offset(TC_HANDLE_T handle, unsigned int offset)
{
	struct list_head *pos;

	if (list_empty(&handle->chains))
		return NULL;

	list_for_each(pos, &handle->chains) {
		struct chain_head *c = list_entry(pos, struct chain_head, list);
		if (offset >= c->head_offset && offset <= c->foot_offset)
			return c;
	}

	return NULL;
}
/* Returns chain head if found, otherwise NULL. */
static struct chain_head *
iptcc_find_label(const char *name, TC_HANDLE_T handle)
{
	struct list_head *pos;

	if (list_empty(&handle->chains))
		return NULL;

	list_for_each(pos, &handle->chains) {
		struct chain_head *c = list_entry(pos, struct chain_head, list);
		if (!strcmp(c->name, name))
			return c;
	}

	return NULL;
}

/* called when rule is to be removed from cache */
static void iptcc_delete_rule(struct rule_head *r)
{
	DEBUGP("deleting rule %p (offset %u)\n", r, r->offset);
	/* clean up reference count of called chain */
	if (r->type == IPTCC_R_JUMP
	    && r->jump)
		r->jump->references--;

	list_del(&r->list);
	free(r);
}


/**********************************************************************
 * RULESET PARSER (blob -> cache)
 **********************************************************************/

/* Delete policy rule of previous chain, since cache doesn't contain
 * chain policy rules.
 * WARNING: This function has ugly design and relies on a lot of context, only
 * to be called from specific places within the parser */
static int __iptcc_p_del_policy(TC_HANDLE_T h, unsigned int num)
{
	if (h->chain_iterator_cur) {
		/* policy rule is last rule */
		struct rule_head *pr = (struct rule_head *)
			h->chain_iterator_cur->rules.prev;

		/* save verdict */
		h->chain_iterator_cur->verdict = 
			*(int *)GET_TARGET(pr->entry)->data;

		/* save counter and counter_map information */
		h->chain_iterator_cur->counter_map.maptype = 
						COUNTER_MAP_NORMAL_MAP;
		h->chain_iterator_cur->counter_map.mappos = num-1;
		memcpy(&h->chain_iterator_cur->counters, &pr->entry->counters, 
			sizeof(h->chain_iterator_cur->counters));

		/* foot_offset points to verdict rule */
		h->chain_iterator_cur->foot_index = num;
		h->chain_iterator_cur->foot_offset = pr->offset;

		/* delete rule from cache */
		iptcc_delete_rule(pr);
		h->chain_iterator_cur->num_rules--;

		return 1;
	}
	return 0;
}

/* alphabetically insert a chain into the list */
static inline void iptc_insert_chain(TC_HANDLE_T h, struct chain_head *c)
{
	struct chain_head *tmp;

	/* sort only user defined chains */
	if (!c->hooknum) {
		list_for_each_entry(tmp, &h->chains, list) {
			if (!tmp->hooknum && strcmp(c->name, tmp->name) <= 0) {
				list_add(&c->list, tmp->list.prev);
				return;
			}
		}
	}

	/* survived till end of list: add at tail */
	list_add_tail(&c->list, &h->chains);
}

/* Another ugly helper function split out of cache_add_entry to make it less
 * spaghetti code */
static void __iptcc_p_add_chain(TC_HANDLE_T h, struct chain_head *c,
				unsigned int offset, unsigned int *num)
{
	__iptcc_p_del_policy(h, *num);

	c->head_offset = offset;
	c->index = *num;

	iptc_insert_chain(h, c);
	
	h->chain_iterator_cur = c;
}

/* main parser function: add an entry from the blob to the cache */
static int cache_add_entry(STRUCT_ENTRY *e, 
			   TC_HANDLE_T h, 
			   STRUCT_ENTRY **prev,
			   unsigned int *num)
{
	unsigned int builtin;
	unsigned int offset = (char *)e - (char *)h->entries->entrytable;

	DEBUGP("entering...");

	/* Last entry ("policy rule"). End it.*/
	if (iptcb_entry2offset(h,e) + e->next_offset == h->entries->size) {
		/* This is the ERROR node at the end of the chain */
		DEBUGP_C("%u:%u: end of table:\n", *num, offset);

		__iptcc_p_del_policy(h, *num);

		h->chain_iterator_cur = NULL;
		goto out_inc;
	}

	/* We know this is the start of a new chain if it's an ERROR
	 * target, or a hook entry point */

	if (strcmp(GET_TARGET(e)->u.user.name, ERROR_TARGET) == 0) {
		struct chain_head *c = 
			iptcc_alloc_chain_head((const char *)GET_TARGET(e)->data, 0);
		DEBUGP_C("%u:%u:new userdefined chain %s: %p\n", *num, offset, 
			(char *)c->name, c);
		if (!c) {
			errno = -ENOMEM;
			return -1;
		}

		__iptcc_p_add_chain(h, c, offset, num);

	} else if ((builtin = iptcb_ent_is_hook_entry(e, h)) != 0) {
		struct chain_head *c =
			iptcc_alloc_chain_head((char *)hooknames[builtin-1], 
						builtin);
		DEBUGP_C("%u:%u new builtin chain: %p (rules=%p)\n", 
			*num, offset, c, &c->rules);
		if (!c) {
			errno = -ENOMEM;
			return -1;
		}

		c->hooknum = builtin;

		__iptcc_p_add_chain(h, c, offset, num);

		/* FIXME: this is ugly. */
		goto new_rule;
	} else {
		/* has to be normal rule */
		struct rule_head *r;
new_rule:

		if (!(r = iptcc_alloc_rule(h->chain_iterator_cur, 
					   e->next_offset))) {
			errno = ENOMEM;
			return -1;
		}
		DEBUGP_C("%u:%u normal rule: %p: ", *num, offset, r);

		r->index = *num;
		r->offset = offset;
		memcpy(r->entry, e, e->next_offset);
		r->counter_map.maptype = COUNTER_MAP_NORMAL_MAP;
		r->counter_map.mappos = r->index;

		/* handling of jumps, etc. */
		if (!strcmp(GET_TARGET(e)->u.user.name, STANDARD_TARGET)) {
			STRUCT_STANDARD_TARGET *t;

			t = (STRUCT_STANDARD_TARGET *)GET_TARGET(e);
			if (t->target.u.target_size
			    != ALIGN(sizeof(STRUCT_STANDARD_TARGET))) {
				errno = EINVAL;
				return -1;
			}

			if (t->verdict < 0) {
				DEBUGP_C("standard, verdict=%d\n", t->verdict);
				r->type = IPTCC_R_STANDARD;
			} else if (t->verdict == r->offset+e->next_offset) {
				DEBUGP_C("fallthrough\n");
				r->type = IPTCC_R_FALLTHROUGH;
			} else {
				DEBUGP_C("jump, target=%u\n", t->verdict);
				r->type = IPTCC_R_JUMP;
				/* Jump target fixup has to be deferred
				 * until second pass, since we migh not
				 * yet have parsed the target */
			}
		} else {
			DEBUGP_C("module, target=%s\n", GET_TARGET(e)->u.user.name);
			r->type = IPTCC_R_MODULE;
		}

		list_add_tail(&r->list, &h->chain_iterator_cur->rules);
		h->chain_iterator_cur->num_rules++;
	}
out_inc:
	(*num)++;
	return 0;
}


/* parse an iptables blob into it's pieces */
static int parse_table(TC_HANDLE_T h)
{
	STRUCT_ENTRY *prev;
	unsigned int num = 0;
	struct chain_head *c;

	/* First pass: over ruleset blob */
	ENTRY_ITERATE(h->entries->entrytable, h->entries->size,
			cache_add_entry, h, &prev, &num);

	/* Second pass: fixup parsed data from first pass */
	list_for_each_entry(c, &h->chains, list) {
		struct rule_head *r;
		list_for_each_entry(r, &c->rules, list) {
			struct chain_head *c;
			STRUCT_STANDARD_TARGET *t;

			if (r->type != IPTCC_R_JUMP)
				continue;

			t = (STRUCT_STANDARD_TARGET *)GET_TARGET(r->entry);
			c = iptcc_find_chain_by_offset(h, t->verdict);
			if (!c)
				return -1;
			r->jump = c;
			c->references++;
		}
	}

	/* FIXME: sort chains */

	return 1;
}


/**********************************************************************
 * RULESET COMPILATION (cache -> blob)
 **********************************************************************/

/* Convenience structures */
struct iptcb_chain_start{
	STRUCT_ENTRY e;
	struct ipt_error_target name;
};
#define IPTCB_CHAIN_START_SIZE	(sizeof(STRUCT_ENTRY) +			\
				 ALIGN(sizeof(struct ipt_error_target)))

struct iptcb_chain_foot {
	STRUCT_ENTRY e;
	STRUCT_STANDARD_TARGET target;
};
#define IPTCB_CHAIN_FOOT_SIZE	(sizeof(STRUCT_ENTRY) +			\
				 ALIGN(sizeof(STRUCT_STANDARD_TARGET)))

struct iptcb_chain_error {
	STRUCT_ENTRY entry;
	struct ipt_error_target target;
};
#define IPTCB_CHAIN_ERROR_SIZE	(sizeof(STRUCT_ENTRY) +			\
				 ALIGN(sizeof(struct ipt_error_target)))



/* compile rule from cache into blob */
static inline int iptcc_compile_rule (TC_HANDLE_T h, STRUCT_REPLACE *repl, struct rule_head *r)
{
	/* handle jumps */
	if (r->type == IPTCC_R_JUMP) {
		STRUCT_STANDARD_TARGET *t;
		t = (STRUCT_STANDARD_TARGET *)GET_TARGET(r->entry);
		/* memset for memcmp convenience on delete/replace */
		memset(t->target.u.user.name, 0, FUNCTION_MAXNAMELEN);
		strcpy(t->target.u.user.name, STANDARD_TARGET);
		/* Jumps can only happen to builtin chains, so we
		 * can safely assume that they always have a header */
		t->verdict = r->jump->head_offset + IPTCB_CHAIN_START_SIZE;
	} else if (r->type == IPTCC_R_FALLTHROUGH) {
		STRUCT_STANDARD_TARGET *t;
		t = (STRUCT_STANDARD_TARGET *)GET_TARGET(r->entry);
		t->verdict = r->offset + r->size;
	}
	
	/* copy entry from cache to blob */
	memcpy((char *)repl->entries+r->offset, r->entry, r->size);

	return 1;
}

/* compile chain from cache into blob */
static int iptcc_compile_chain(TC_HANDLE_T h, STRUCT_REPLACE *repl, struct chain_head *c)
{
	int ret;
	struct rule_head *r;
	struct iptcb_chain_start *head;
	struct iptcb_chain_foot *foot;

	/* only user-defined chains have heaer */
	if (!iptcc_is_builtin(c)) {
		/* put chain header in place */
		head = (void *)repl->entries + c->head_offset;
		head->e.target_offset = sizeof(STRUCT_ENTRY);
		head->e.next_offset = IPTCB_CHAIN_START_SIZE;
		strcpy(head->name.target.u.user.name, ERROR_TARGET);
		head->name.target.u.target_size = 
				ALIGN(sizeof(struct ipt_error_target));
		strcpy(head->name.errorname, c->name);
	} else {
		repl->hook_entry[c->hooknum-1] = c->head_offset;	
		repl->underflow[c->hooknum-1] = c->foot_offset;
	}

	/* iterate over rules */
	list_for_each_entry(r, &c->rules, list) {
		ret = iptcc_compile_rule(h, repl, r);
		if (ret < 0)
			return ret;
	}

	/* put chain footer in place */
	foot = (void *)repl->entries + c->foot_offset;
	foot->e.target_offset = sizeof(STRUCT_ENTRY);
	foot->e.next_offset = IPTCB_CHAIN_FOOT_SIZE;
	strcpy(foot->target.target.u.user.name, STANDARD_TARGET);
	foot->target.target.u.target_size =
				ALIGN(sizeof(STRUCT_STANDARD_TARGET));
	/* builtin targets have verdict, others return */
	if (iptcc_is_builtin(c))
		foot->target.verdict = c->verdict;
	else
		foot->target.verdict = RETURN;
	/* set policy-counters */
	memcpy(&foot->e.counters, &c->counters, sizeof(STRUCT_COUNTERS));

	return 0;
}

/* calculate offset and number for every rule in the cache */
static int iptcc_compile_chain_offsets(TC_HANDLE_T h, struct chain_head *c,
				       unsigned int *offset, unsigned int *num)
{
	struct rule_head *r;

	c->head_offset = *offset;
	DEBUGP("%s: chain_head %u, offset=%u\n", c->name, *num, *offset);

	if (!iptcc_is_builtin(c))  {
		/* Chain has header */
		*offset += sizeof(STRUCT_ENTRY) 
			     + ALIGN(sizeof(struct ipt_error_target));
		(*num)++;
	}

	list_for_each_entry(r, &c->rules, list) {
		DEBUGP("rule %u, offset=%u, index=%u\n", *num, *offset, *num);
		r->offset = *offset;
		r->index = *num;
		*offset += r->size;
		(*num)++;
	}

	DEBUGP("%s; chain_foot %u, offset=%u, index=%u\n", c->name, *num, 
		*offset, *num);
	c->foot_offset = *offset;
	c->foot_index = *num;
	*offset += sizeof(STRUCT_ENTRY)
		   + ALIGN(sizeof(STRUCT_STANDARD_TARGET));
	(*num)++;

	return 1;
}

/* put the pieces back together again */
static int iptcc_compile_table_prep(TC_HANDLE_T h, unsigned int *size)
{
	struct chain_head *c;
	unsigned int offset = 0, num = 0;
	int ret = 0;

	/* First pass: calculate offset for every rule */
	list_for_each_entry(c, &h->chains, list) {
		ret = iptcc_compile_chain_offsets(h, c, &offset, &num);
		if (ret < 0)
			return ret;
	}

	/* Append one error rule at end of chain */
	num++;
	offset += sizeof(STRUCT_ENTRY)
		  + ALIGN(sizeof(struct ipt_error_target));

	/* ruleset size is now in offset */
	*size = offset;
	return num;
}

static int iptcc_compile_table(TC_HANDLE_T h, STRUCT_REPLACE *repl)
{
	struct chain_head *c;
	struct iptcb_chain_error *error;

	/* Second pass: copy from cache to offsets, fill in jumps */
	list_for_each_entry(c, &h->chains, list) {
		int ret = iptcc_compile_chain(h, repl, c);
		if (ret < 0)
			return ret;
	}

	/* Append error rule at end of chain */
	error = (void *)repl->entries + repl->size - IPTCB_CHAIN_ERROR_SIZE;
	error->entry.target_offset = sizeof(STRUCT_ENTRY);
	error->entry.next_offset = IPTCB_CHAIN_ERROR_SIZE;
	error->target.target.u.user.target_size = 
		ALIGN(sizeof(struct ipt_error_target));
	strcpy((char *)&error->target.target.u.user.name, ERROR_TARGET);
	strcpy((char *)&error->target.errorname, "ERROR");

	return 1;
}

/**********************************************************************
 * EXTERNAL API (operates on cache only)
 **********************************************************************/

/* Allocate handle of given size */
static TC_HANDLE_T
alloc_handle(const char *tablename, unsigned int size, unsigned int num_rules)
{
	size_t len;
	TC_HANDLE_T h;

	len = sizeof(STRUCT_TC_HANDLE) + size;

	h = malloc(sizeof(STRUCT_TC_HANDLE));
	if (!h) {
		errno = ENOMEM;
		return NULL;
	}
	memset(h, 0, sizeof(*h));
	INIT_LIST_HEAD(&h->chains);
	strcpy(h->info.name, tablename);

	h->entries = malloc(sizeof(STRUCT_GET_ENTRIES) + size);
	if (!h->entries)
		goto out_free_handle;

	strcpy(h->entries->name, tablename);
	h->entries->size = size;

	return h;

out_free_handle:
	free(h);

	return NULL;
}


TC_HANDLE_T
TC_INIT(const char *tablename)
{
	TC_HANDLE_T h;
	STRUCT_GETINFO info;
	unsigned int tmp;
	socklen_t s;

	iptc_fn = TC_INIT;

	if (strlen(tablename) >= TABLE_MAXNAMELEN) {
		errno = EINVAL;
		return NULL;
	}
	
	if (sockfd_use == 0) {
		sockfd = socket(TC_AF, SOCK_RAW, IPPROTO_RAW);
		if (sockfd < 0)
			return NULL;
	}
	sockfd_use++;

	s = sizeof(info);

	strcpy(info.name, tablename);
	if (getsockopt(sockfd, TC_IPPROTO, SO_GET_INFO, &info, &s) < 0) {
		if (--sockfd_use == 0) {
			close(sockfd);
			sockfd = -1;
		}
		return NULL;
	}

	DEBUGP("valid_hooks=0x%08x, num_entries=%u, size=%u\n",
		info.valid_hooks, info.num_entries, info.size);

	if ((h = alloc_handle(info.name, info.size, info.num_entries))
	    == NULL) {
		if (--sockfd_use == 0) {
			close(sockfd);
			sockfd = -1;
		}
		return NULL;
	}

	/* Initialize current state */
	h->info = info;

	h->entries->size = h->info.size;

	tmp = sizeof(STRUCT_GET_ENTRIES) + h->info.size;

	if (getsockopt(sockfd, TC_IPPROTO, SO_GET_ENTRIES, h->entries,
		       &tmp) < 0)
		goto error;

#ifdef IPTC_DEBUG2
	{
		int fd = open("/tmp/libiptc-so_get_entries.blob", 
				O_CREAT|O_WRONLY);
		if (fd >= 0) {
			write(fd, h->entries, tmp);
			close(fd);
		}
	}
#endif

	if (parse_table(h) < 0)
		goto error;

	CHECK(h);
	return h;
error:
	if (--sockfd_use == 0) {
		close(sockfd);
		sockfd = -1;
	}
	TC_FREE(&h);
	return NULL;
}

void
TC_FREE(TC_HANDLE_T *h)
{
	struct chain_head *c, *tmp;

	iptc_fn = TC_FREE;
	if (--sockfd_use == 0) {
		close(sockfd);
		sockfd = -1;
	}

	list_for_each_entry_safe(c, tmp, &(*h)->chains, list) {
		struct rule_head *r, *rtmp;

		list_for_each_entry_safe(r, rtmp, &c->rules, list) {
			free(r);
		}

		free(c);
	}

	free((*h)->entries);
	free(*h);

	*h = NULL;
}

static inline int
print_match(const STRUCT_ENTRY_MATCH *m)
{
	printf("Match name: `%s'\n", m->u.user.name);
	return 0;
}

/*static int dump_entry(STRUCT_ENTRY *e, const TC_HANDLE_T handle);*/
 
void
TC_DUMP_ENTRIES(const TC_HANDLE_T handle)
{
	iptc_fn = TC_DUMP_ENTRIES;
	CHECK(handle);
#if 0
	printf("libiptc v%s. %u bytes.\n",
	       IPTABLES_VERSION, handle->entries->size);
	printf("Table `%s'\n", handle->info.name);
	printf("Hooks: pre/in/fwd/out/post = %u/%u/%u/%u/%u\n",
	       handle->info.hook_entry[HOOK_PRE_ROUTING],
	       handle->info.hook_entry[HOOK_LOCAL_IN],
	       handle->info.hook_entry[HOOK_FORWARD],
	       handle->info.hook_entry[HOOK_LOCAL_OUT],
	       handle->info.hook_entry[HOOK_POST_ROUTING]);
	printf("Underflows: pre/in/fwd/out/post = %u/%u/%u/%u/%u\n",
	       handle->info.underflow[HOOK_PRE_ROUTING],
	       handle->info.underflow[HOOK_LOCAL_IN],
	       handle->info.underflow[HOOK_FORWARD],
	       handle->info.underflow[HOOK_LOCAL_OUT],
	       handle->info.underflow[HOOK_POST_ROUTING]);

	ENTRY_ITERATE(handle->entries->entrytable, handle->entries->size,
		      dump_entry, handle);
#endif
}

/* Does this chain exist? */
int TC_IS_CHAIN(const char *chain, const TC_HANDLE_T handle)
{
	iptc_fn = TC_IS_CHAIN;
	return iptcc_find_label(chain, handle) != NULL;
}

static void iptcc_chain_iterator_advance(TC_HANDLE_T handle)
{
	struct chain_head *c = handle->chain_iterator_cur;

	if (c->list.next == &handle->chains)
		handle->chain_iterator_cur = NULL;
	else
		handle->chain_iterator_cur = 
			list_entry(c->list.next, struct chain_head, list);
}

/* Iterator functions to run through the chains. */
const char *
TC_FIRST_CHAIN(TC_HANDLE_T *handle)
{
	struct chain_head *c = list_entry((*handle)->chains.next,
					  struct chain_head, list);

	iptc_fn = TC_FIRST_CHAIN;


	if (list_empty(&(*handle)->chains)) {
		DEBUGP(": no chains\n");
		return NULL;
	}

	(*handle)->chain_iterator_cur = c;
	iptcc_chain_iterator_advance(*handle);

	DEBUGP(": returning `%s'\n", c->name);
	return c->name;
}

/* Iterator functions to run through the chains.  Returns NULL at end. */
const char *
TC_NEXT_CHAIN(TC_HANDLE_T *handle)
{
	struct chain_head *c = (*handle)->chain_iterator_cur;

	iptc_fn = TC_NEXT_CHAIN;

	if (!c) {
		DEBUGP(": no more chains\n");
		return NULL;
	}

	iptcc_chain_iterator_advance(*handle);
	
	DEBUGP(": returning `%s'\n", c->name);
	return c->name;
}

/* Get first rule in the given chain: NULL for empty chain. */
const STRUCT_ENTRY *
TC_FIRST_RULE(const char *chain, TC_HANDLE_T *handle)
{
	struct chain_head *c;
	struct rule_head *r;

	iptc_fn = TC_FIRST_RULE;

	DEBUGP("first rule(%s): ", chain);

	c = iptcc_find_label(chain, *handle);
	if (!c) {
		errno = ENOENT;
		return NULL;
	}

	/* Empty chain: single return/policy rule */
	if (list_empty(&c->rules)) {
		DEBUGP_C("no rules, returning NULL\n");
		return NULL;
	}

	r = list_entry(c->rules.next, struct rule_head, list);
	(*handle)->rule_iterator_cur = r;
	DEBUGP_C("%p\n", r);

	return r->entry;
}

/* Returns NULL when rules run out. */
const STRUCT_ENTRY *
TC_NEXT_RULE(const STRUCT_ENTRY *prev, TC_HANDLE_T *handle)
{
	struct rule_head *r;

	iptc_fn = TC_NEXT_RULE;
	DEBUGP("rule_iterator_cur=%p...", (*handle)->rule_iterator_cur);

	if (!(*handle)->rule_iterator_cur) {
		DEBUGP_C("returning NULL\n");
		return NULL;
	}
	
	r = list_entry((*handle)->rule_iterator_cur->list.next, 
			struct rule_head, list);

	iptc_fn = TC_NEXT_RULE;

	DEBUGP_C("next=%p, head=%p...", &r->list, 
		&(*handle)->rule_iterator_cur->chain->rules);

	if (&r->list == &(*handle)->rule_iterator_cur->chain->rules) {
		(*handle)->rule_iterator_cur = NULL;
		DEBUGP_C("finished, returning NULL\n");
		return NULL;
	}

	(*handle)->rule_iterator_cur = r;

	/* NOTE: prev is without any influence ! */
	DEBUGP_C("returning rule %p\n", r);
	return r->entry;
}

/* How many rules in this chain? */
unsigned int
TC_NUM_RULES(const char *chain, TC_HANDLE_T *handle)
{
	struct chain_head *c;
	iptc_fn = TC_NUM_RULES;
	CHECK(*handle);

	c = iptcc_find_label(chain, *handle);
	if (!c) {
		errno = ENOENT;
		return (unsigned int)-1;
	}
	
	return c->num_rules;
}

const STRUCT_ENTRY *TC_GET_RULE(const char *chain,
				unsigned int n,
				TC_HANDLE_T *handle)
{
	struct chain_head *c;
	struct rule_head *r;
	
	iptc_fn = TC_GET_RULE;

	CHECK(*handle);

	c = iptcc_find_label(chain, *handle);
	if (!c) {
		errno = ENOENT;
		return NULL;
	}

	r = iptcc_get_rule_num(c, n);
	if (!r)
		return NULL;
	return r->entry;
}

/* Returns a pointer to the target name of this position. */
const char *standard_target_map(int verdict)
{
	switch (verdict) {
		case RETURN:
			return LABEL_RETURN;
			break;
		case -NF_ACCEPT-1:
			return LABEL_ACCEPT;
			break;
		case -NF_DROP-1:
			return LABEL_DROP;
			break;
		case -NF_QUEUE-1:
			return LABEL_QUEUE;
			break;
		default:
			fprintf(stderr, "ERROR: %d not a valid target)\n",
				verdict);
			abort();
			break;
	}
	/* not reached */
	return NULL;
}

/* Returns a pointer to the target name of this position. */
const char *TC_GET_TARGET(const STRUCT_ENTRY *ce,
			  TC_HANDLE_T *handle)
{
	STRUCT_ENTRY *e = (STRUCT_ENTRY *)ce;
	struct rule_head *r = container_of(e, struct rule_head, entry[0]);

	iptc_fn = TC_GET_TARGET;

	switch(r->type) {
		int spos;
		case IPTCC_R_FALLTHROUGH:
			return "";
			break;
		case IPTCC_R_JUMP:
			DEBUGP("r=%p, jump=%p, name=`%s'\n", r, r->jump, r->jump->name);
			return r->jump->name;
			break;
		case IPTCC_R_STANDARD:
			spos = *(int *)GET_TARGET(e)->data;
			DEBUGP("r=%p, spos=%d'\n", r, spos);
			return standard_target_map(spos);
			break;
		case IPTCC_R_MODULE:
			return GET_TARGET(e)->u.user.name;
			break;
	}
	return NULL;
}
/* Is this a built-in chain?  Actually returns hook + 1. */
int
TC_BUILTIN(const char *chain, const TC_HANDLE_T handle)
{
	struct chain_head *c;
	
	iptc_fn = TC_BUILTIN;

	c = iptcc_find_label(chain, handle);
	if (!c) {
		errno = ENOENT;
		return 0;
	}

	return iptcc_is_builtin(c);
}

/* Get the policy of a given built-in chain */
const char *
TC_GET_POLICY(const char *chain,
	      STRUCT_COUNTERS *counters,
	      TC_HANDLE_T *handle)
{
	struct chain_head *c;

	iptc_fn = TC_GET_POLICY;

	DEBUGP("called for chain %s\n", chain);

	c = iptcc_find_label(chain, *handle);
	if (!c) {
		errno = ENOENT;
		return NULL;
	}

	if (!iptcc_is_builtin(c))
		return NULL;

	*counters = c->counters;

	return standard_target_map(c->verdict);
}

static int
iptcc_standard_map(struct rule_head *r, int verdict)
{
	STRUCT_ENTRY *e = r->entry;
	STRUCT_STANDARD_TARGET *t;

	t = (STRUCT_STANDARD_TARGET *)GET_TARGET(e);

	if (t->target.u.target_size
	    != ALIGN(sizeof(STRUCT_STANDARD_TARGET))) {
		errno = EINVAL;
		return 0;
	}
	/* memset for memcmp convenience on delete/replace */
	memset(t->target.u.user.name, 0, FUNCTION_MAXNAMELEN);
	strcpy(t->target.u.user.name, STANDARD_TARGET);
	t->verdict = verdict;

	r->type = IPTCC_R_STANDARD;

	return 1;
}

static int
iptcc_map_target(const TC_HANDLE_T handle,
	   struct rule_head *r)
{
	STRUCT_ENTRY *e = r->entry;
	STRUCT_ENTRY_TARGET *t = GET_TARGET(e);

	/* Maybe it's empty (=> fall through) */
	if (strcmp(t->u.user.name, "") == 0) {
		r->type = IPTCC_R_FALLTHROUGH;
		return 1;
	}
	/* Maybe it's a standard target name... */
	else if (strcmp(t->u.user.name, LABEL_ACCEPT) == 0)
		return iptcc_standard_map(r, -NF_ACCEPT - 1);
	else if (strcmp(t->u.user.name, LABEL_DROP) == 0)
		return iptcc_standard_map(r, -NF_DROP - 1);
	else if (strcmp(t->u.user.name, LABEL_QUEUE) == 0)
		return iptcc_standard_map(r, -NF_QUEUE - 1);
	else if (strcmp(t->u.user.name, LABEL_RETURN) == 0)
		return iptcc_standard_map(r, RETURN);
	else if (TC_BUILTIN(t->u.user.name, handle)) {
		/* Can't jump to builtins. */
		errno = EINVAL;
		return 0;
	} else {
		/* Maybe it's an existing chain name. */
		struct chain_head *c;
		DEBUGP("trying to find chain `%s': ", t->u.user.name);

		c = iptcc_find_label(t->u.user.name, handle);
		if (c) {
			DEBUGP_C("found!\n");
			r->type = IPTCC_R_JUMP;
			r->jump = c;
			c->references++;
			return 1;
		}
		DEBUGP_C("not found :(\n");
	}

	/* Must be a module?  If not, kernel will reject... */
	/* memset to all 0 for your memcmp convenience: don't clear version */
	memset(t->u.user.name + strlen(t->u.user.name),
	       0,
	       FUNCTION_MAXNAMELEN - 1 - strlen(t->u.user.name));
	r->type = IPTCC_R_MODULE;
	set_changed(handle);
	return 1;
}

/* Insert the entry `fw' in chain `chain' into position `rulenum'. */
int
TC_INSERT_ENTRY(const IPT_CHAINLABEL chain,
		const STRUCT_ENTRY *e,
		unsigned int rulenum,
		TC_HANDLE_T *handle)
{
	struct chain_head *c;
	struct rule_head *r;
	struct list_head *prev;

	iptc_fn = TC_INSERT_ENTRY;

	if (!(c = iptcc_find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	/* first rulenum index = 0
	   first c->num_rules index = 1 */
	if (rulenum > c->num_rules) {
		errno = E2BIG;
		return 0;
	}

	/* If we are inserting at the end just take advantage of the
	   double linked list, insert will happen before the entry
	   prev points to. */
	if (rulenum == c->num_rules) {
		prev = &c->rules;
	} else if (rulenum + 1 <= c->num_rules/2) {
		r = iptcc_get_rule_num(c, rulenum + 1);
		prev = &r->list;
	} else {
		r = iptcc_get_rule_num_reverse(c, c->num_rules - rulenum);
		prev = &r->list;
	}

	if (!(r = iptcc_alloc_rule(c, e->next_offset))) {
		errno = ENOMEM;
		return 0;
	}

	memcpy(r->entry, e, e->next_offset);
	r->counter_map.maptype = COUNTER_MAP_SET;

	if (!iptcc_map_target(*handle, r)) {
		free(r);
		return 0;
	}

	list_add_tail(&r->list, prev);
	c->num_rules++;

	set_changed(*handle);

	return 1;
}

/* Atomically replace rule `rulenum' in `chain' with `fw'. */
int
TC_REPLACE_ENTRY(const IPT_CHAINLABEL chain,
		 const STRUCT_ENTRY *e,
		 unsigned int rulenum,
		 TC_HANDLE_T *handle)
{
	struct chain_head *c;
	struct rule_head *r, *old;

	iptc_fn = TC_REPLACE_ENTRY;

	if (!(c = iptcc_find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	if (rulenum >= c->num_rules) {
		errno = E2BIG;
		return 0;
	}

	/* Take advantage of the double linked list if possible. */
	if (rulenum + 1 <= c->num_rules/2) {
		old = iptcc_get_rule_num(c, rulenum + 1);
	} else {
		old = iptcc_get_rule_num_reverse(c, c->num_rules - rulenum);
	}

	if (!(r = iptcc_alloc_rule(c, e->next_offset))) {
		errno = ENOMEM;
		return 0;
	}

	memcpy(r->entry, e, e->next_offset);
	r->counter_map.maptype = COUNTER_MAP_SET;

	if (!iptcc_map_target(*handle, r)) {
		free(r);
		return 0;
	}

	list_add(&r->list, &old->list);
	iptcc_delete_rule(old);

	set_changed(*handle);

	return 1;
}

/* Append entry `fw' to chain `chain'.  Equivalent to insert with
   rulenum = length of chain. */
int
TC_APPEND_ENTRY(const IPT_CHAINLABEL chain,
		const STRUCT_ENTRY *e,
		TC_HANDLE_T *handle)
{
	struct chain_head *c;
	struct rule_head *r;

	iptc_fn = TC_APPEND_ENTRY;
	if (!(c = iptcc_find_label(chain, *handle))) {
		DEBUGP("unable to find chain `%s'\n", chain);
		errno = ENOENT;
		return 0;
	}

	if (!(r = iptcc_alloc_rule(c, e->next_offset))) {
		DEBUGP("unable to allocate rule for chain `%s'\n", chain);
		errno = ENOMEM;
		return 0;
	}

	memcpy(r->entry, e, e->next_offset);
	r->counter_map.maptype = COUNTER_MAP_SET;

	if (!iptcc_map_target(*handle, r)) {
		DEBUGP("unable to map target of rule for chain `%s'\n", chain);
		free(r);
		return 0;
	}

	list_add_tail(&r->list, &c->rules);
	c->num_rules++;

	set_changed(*handle);

	return 1;
}

static inline int
match_different(const STRUCT_ENTRY_MATCH *a,
		const unsigned char *a_elems,
		const unsigned char *b_elems,
		unsigned char **maskptr)
{
	const STRUCT_ENTRY_MATCH *b;
	unsigned int i;

	/* Offset of b is the same as a. */
	b = (void *)b_elems + ((unsigned char *)a - a_elems);

	if (a->u.match_size != b->u.match_size)
		return 1;

	if (strcmp(a->u.user.name, b->u.user.name) != 0)
		return 1;

	*maskptr += ALIGN(sizeof(*a));

	for (i = 0; i < a->u.match_size - ALIGN(sizeof(*a)); i++)
		if (((a->data[i] ^ b->data[i]) & (*maskptr)[i]) != 0)
			return 1;
	*maskptr += i;
	return 0;
}

static inline int
target_same(struct rule_head *a, struct rule_head *b,const unsigned char *mask)
{
	unsigned int i;
	STRUCT_ENTRY_TARGET *ta, *tb;

	if (a->type != b->type)
		return 0;

	ta = GET_TARGET(a->entry);
	tb = GET_TARGET(b->entry);

	switch (a->type) {
	case IPTCC_R_FALLTHROUGH:
		return 1;
	case IPTCC_R_JUMP:
		return a->jump == b->jump;
	case IPTCC_R_STANDARD:
		return ((STRUCT_STANDARD_TARGET *)ta)->verdict
			== ((STRUCT_STANDARD_TARGET *)tb)->verdict;
	case IPTCC_R_MODULE:
		if (ta->u.target_size != tb->u.target_size)
			return 0;
		if (strcmp(ta->u.user.name, tb->u.user.name) != 0)
			return 0;

		for (i = 0; i < ta->u.target_size - sizeof(*ta); i++)
			if (((ta->data[i] ^ tb->data[i]) & mask[i]) != 0)
				return 0;
		return 1;
	default:
		fprintf(stderr, "ERROR: bad type %i\n", a->type);
		abort();
	}
}

static unsigned char *
is_same(const STRUCT_ENTRY *a,
	const STRUCT_ENTRY *b,
	unsigned char *matchmask);

/* Delete the first rule in `chain' which matches `fw'. */
int
TC_DELETE_ENTRY(const IPT_CHAINLABEL chain,
		const STRUCT_ENTRY *origfw,
		unsigned char *matchmask,
		TC_HANDLE_T *handle)
{
	struct chain_head *c;
	struct rule_head *r, *i;

	iptc_fn = TC_DELETE_ENTRY;
	if (!(c = iptcc_find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	/* Create a rule_head from origfw. */
	r = iptcc_alloc_rule(c, origfw->next_offset);
	if (!r) {
		errno = ENOMEM;
		return 0;
	}

	memcpy(r->entry, origfw, origfw->next_offset);
	r->counter_map.maptype = COUNTER_MAP_NOMAP;
	if (!iptcc_map_target(*handle, r)) {
		DEBUGP("unable to map target of rule for chain `%s'\n", chain);
		free(r);
		return 0;
	}

	list_for_each_entry(i, &c->rules, list) {
		unsigned char *mask;

		mask = is_same(r->entry, i->entry, matchmask);
		if (!mask)
			continue;

		if (!target_same(r, i, mask))
			continue;

		/* If we are about to delete the rule that is the
		 * current iterator, move rule iterator back.  next
		 * pointer will then point to real next node */
		if (i == (*handle)->rule_iterator_cur) {
			(*handle)->rule_iterator_cur = 
				list_entry((*handle)->rule_iterator_cur->list.prev,
					   struct rule_head, list);
		}

		c->num_rules--;
		iptcc_delete_rule(i);

		set_changed(*handle);
		free(r);
		return 1;
	}

	free(r);
	errno = ENOENT;
	return 0;
}


/* Delete the rule in position `rulenum' in `chain'. */
int
TC_DELETE_NUM_ENTRY(const IPT_CHAINLABEL chain,
		    unsigned int rulenum,
		    TC_HANDLE_T *handle)
{
	struct chain_head *c;
	struct rule_head *r;

	iptc_fn = TC_DELETE_NUM_ENTRY;

	if (!(c = iptcc_find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	if (rulenum >= c->num_rules) {
		errno = E2BIG;
		return 0;
	}

	/* Take advantage of the double linked list if possible. */
	if (rulenum + 1 <= c->num_rules/2) {
		r = iptcc_get_rule_num(c, rulenum + 1);
	} else {
		r = iptcc_get_rule_num_reverse(c, c->num_rules - rulenum);
	}

	/* If we are about to delete the rule that is the current
	 * iterator, move rule iterator back.  next pointer will then
	 * point to real next node */
	if (r == (*handle)->rule_iterator_cur) {
		(*handle)->rule_iterator_cur = 
			list_entry((*handle)->rule_iterator_cur->list.prev,
				   struct rule_head, list);
	}

	c->num_rules--;
	iptcc_delete_rule(r);

	set_changed(*handle);

	return 1;
}

/* Check the packet `fw' on chain `chain'.  Returns the verdict, or
   NULL and sets errno. */
const char *
TC_CHECK_PACKET(const IPT_CHAINLABEL chain,
		STRUCT_ENTRY *entry,
		TC_HANDLE_T *handle)
{
	iptc_fn = TC_CHECK_PACKET;
	errno = ENOSYS;
	return NULL;
}

/* Flushes the entries in the given chain (ie. empties chain). */
int
TC_FLUSH_ENTRIES(const IPT_CHAINLABEL chain, TC_HANDLE_T *handle)
{
	struct chain_head *c;
	struct rule_head *r, *tmp;

	iptc_fn = TC_FLUSH_ENTRIES;
	if (!(c = iptcc_find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	list_for_each_entry_safe(r, tmp, &c->rules, list) {
		iptcc_delete_rule(r);
	}

	c->num_rules = 0;

	set_changed(*handle);

	return 1;
}

/* Zeroes the counters in a chain. */
int
TC_ZERO_ENTRIES(const IPT_CHAINLABEL chain, TC_HANDLE_T *handle)
{
	struct chain_head *c;
	struct rule_head *r;

	iptc_fn = TC_ZERO_ENTRIES;
	if (!(c = iptcc_find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	list_for_each_entry(r, &c->rules, list) {
		if (r->counter_map.maptype == COUNTER_MAP_NORMAL_MAP)
			r->counter_map.maptype = COUNTER_MAP_ZEROED;
	}

	set_changed(*handle);

	return 1;
}

STRUCT_COUNTERS *
TC_READ_COUNTER(const IPT_CHAINLABEL chain,
		unsigned int rulenum,
		TC_HANDLE_T *handle)
{
	struct chain_head *c;
	struct rule_head *r;

	iptc_fn = TC_READ_COUNTER;
	CHECK(*handle);

	if (!(c = iptcc_find_label(chain, *handle))) {
		errno = ENOENT;
		return NULL;
	}

	if (!(r = iptcc_get_rule_num(c, rulenum))) {
		errno = E2BIG;
		return NULL;
	}

	return &r->entry[0].counters;
}

int
TC_ZERO_COUNTER(const IPT_CHAINLABEL chain,
		unsigned int rulenum,
		TC_HANDLE_T *handle)
{
	struct chain_head *c;
	struct rule_head *r;
	
	iptc_fn = TC_ZERO_COUNTER;
	CHECK(*handle);

	if (!(c = iptcc_find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	if (!(r = iptcc_get_rule_num(c, rulenum))) {
		errno = E2BIG;
		return 0;
	}

	if (r->counter_map.maptype == COUNTER_MAP_NORMAL_MAP)
		r->counter_map.maptype = COUNTER_MAP_ZEROED;

	set_changed(*handle);

	return 1;
}

int 
TC_SET_COUNTER(const IPT_CHAINLABEL chain,
	       unsigned int rulenum,
	       STRUCT_COUNTERS *counters,
	       TC_HANDLE_T *handle)
{
	struct chain_head *c;
	struct rule_head *r;
	STRUCT_ENTRY *e;

	iptc_fn = TC_SET_COUNTER;
	CHECK(*handle);

	if (!(c = iptcc_find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	if (!(r = iptcc_get_rule_num(c, rulenum))) {
		errno = E2BIG;
		return 0;
	}

	e = r->entry;
	r->counter_map.maptype = COUNTER_MAP_SET;

	memcpy(&e->counters, counters, sizeof(STRUCT_COUNTERS));

	set_changed(*handle);

	return 1;
}

/* Creates a new chain. */
/* To create a chain, create two rules: error node and unconditional
 * return. */
int
TC_CREATE_CHAIN(const IPT_CHAINLABEL chain, TC_HANDLE_T *handle)
{
	static struct chain_head *c;

	iptc_fn = TC_CREATE_CHAIN;

	/* find_label doesn't cover built-in targets: DROP, ACCEPT,
           QUEUE, RETURN. */
	if (iptcc_find_label(chain, *handle)
	    || strcmp(chain, LABEL_DROP) == 0
	    || strcmp(chain, LABEL_ACCEPT) == 0
	    || strcmp(chain, LABEL_QUEUE) == 0
	    || strcmp(chain, LABEL_RETURN) == 0) {
		DEBUGP("Chain `%s' already exists\n", chain);
		errno = EEXIST;
		return 0;
	}

	if (strlen(chain)+1 > sizeof(IPT_CHAINLABEL)) {
		DEBUGP("Chain name `%s' too long\n", chain);
		errno = EINVAL;
		return 0;
	}

	c = iptcc_alloc_chain_head(chain, 0);
	if (!c) {
		DEBUGP("Cannot allocate memory for chain `%s'\n", chain);
		errno = ENOMEM;
		return 0;

	}

	DEBUGP("Creating chain `%s'\n", chain);
	list_add_tail(&c->list, &(*handle)->chains);

	set_changed(*handle);

	return 1;
}

/* Get the number of references to this chain. */
int
TC_GET_REFERENCES(unsigned int *ref, const IPT_CHAINLABEL chain,
		  TC_HANDLE_T *handle)
{
	struct chain_head *c;

	iptc_fn = TC_GET_REFERENCES;
	if (!(c = iptcc_find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	*ref = c->references;

	return 1;
}

/* Deletes a chain. */
int
TC_DELETE_CHAIN(const IPT_CHAINLABEL chain, TC_HANDLE_T *handle)
{
	unsigned int references;
	struct chain_head *c;

	iptc_fn = TC_DELETE_CHAIN;

	if (!(c = iptcc_find_label(chain, *handle))) {
		DEBUGP("cannot find chain `%s'\n", chain);
		errno = ENOENT;
		return 0;
	}

	if (TC_BUILTIN(chain, *handle)) {
		DEBUGP("cannot remove builtin chain `%s'\n", chain);
		errno = EINVAL;
		return 0;
	}

	if (!TC_GET_REFERENCES(&references, chain, handle)) {
		DEBUGP("cannot get references on chain `%s'\n", chain);
		return 0;
	}

	if (references > 0) {
		DEBUGP("chain `%s' still has references\n", chain);
		errno = EMLINK;
		return 0;
	}

	if (c->num_rules) {
		DEBUGP("chain `%s' is not empty\n", chain);
		errno = ENOTEMPTY;
		return 0;
	}

	/* If we are about to delete the chain that is the current
	 * iterator, move chain iterator firward. */
	if (c == (*handle)->chain_iterator_cur)
		iptcc_chain_iterator_advance(*handle);

	list_del(&c->list);
	free(c);

	DEBUGP("chain `%s' deleted\n", chain);

	set_changed(*handle);

	return 1;
}

/* Renames a chain. */
int TC_RENAME_CHAIN(const IPT_CHAINLABEL oldname,
		    const IPT_CHAINLABEL newname,
		    TC_HANDLE_T *handle)
{
	struct chain_head *c;
	iptc_fn = TC_RENAME_CHAIN;

	/* find_label doesn't cover built-in targets: DROP, ACCEPT,
           QUEUE, RETURN. */
	if (iptcc_find_label(newname, *handle)
	    || strcmp(newname, LABEL_DROP) == 0
	    || strcmp(newname, LABEL_ACCEPT) == 0
	    || strcmp(newname, LABEL_QUEUE) == 0
	    || strcmp(newname, LABEL_RETURN) == 0) {
		errno = EEXIST;
		return 0;
	}

	if (!(c = iptcc_find_label(oldname, *handle))
	    || TC_BUILTIN(oldname, *handle)) {
		errno = ENOENT;
		return 0;
	}

	if (strlen(newname)+1 > sizeof(IPT_CHAINLABEL)) {
		errno = EINVAL;
		return 0;
	}

	strncpy(c->name, newname, sizeof(IPT_CHAINLABEL));
	
	set_changed(*handle);

	return 1;
}

/* Sets the policy on a built-in chain. */
int
TC_SET_POLICY(const IPT_CHAINLABEL chain,
	      const IPT_CHAINLABEL policy,
	      STRUCT_COUNTERS *counters,
	      TC_HANDLE_T *handle)
{
	struct chain_head *c;

	iptc_fn = TC_SET_POLICY;

	if (!(c = iptcc_find_label(chain, *handle))) {
		DEBUGP("cannot find chain `%s'\n", chain);
		errno = ENOENT;
		return 0;
	}

	if (!iptcc_is_builtin(c)) {
		DEBUGP("cannot set policy of userdefinedchain `%s'\n", chain);
		errno = ENOENT;
		return 0;
	}

	if (strcmp(policy, LABEL_ACCEPT) == 0)
		c->verdict = -NF_ACCEPT - 1;
	else if (strcmp(policy, LABEL_DROP) == 0)
		c->verdict = -NF_DROP - 1;
	else {
		errno = EINVAL;
		return 0;
	}

	if (counters) {
		/* set byte and packet counters */
		memcpy(&c->counters, counters, sizeof(STRUCT_COUNTERS));
		c->counter_map.maptype = COUNTER_MAP_SET;
	} else {
		c->counter_map.maptype = COUNTER_MAP_NOMAP;
	}

	set_changed(*handle);

	return 1;
}

/* Without this, on gcc 2.7.2.3, we get:
   libiptc.c: In function `TC_COMMIT':
   libiptc.c:833: fixed or forbidden register was spilled.
   This may be due to a compiler bug or to impossible asm
   statements or clauses.
*/
static void
subtract_counters(STRUCT_COUNTERS *answer,
		  const STRUCT_COUNTERS *a,
		  const STRUCT_COUNTERS *b)
{
	answer->pcnt = a->pcnt - b->pcnt;
	answer->bcnt = a->bcnt - b->bcnt;
}


static void counters_nomap(STRUCT_COUNTERS_INFO *newcounters,
			   unsigned int index)
{
	newcounters->counters[index] = ((STRUCT_COUNTERS) { 0, 0});
	DEBUGP_C("NOMAP => zero\n");
}

static void counters_normal_map(STRUCT_COUNTERS_INFO *newcounters,
				STRUCT_REPLACE *repl,
				unsigned int index,
				unsigned int mappos)
{
	/* Original read: X.
	 * Atomic read on replacement: X + Y.
	 * Currently in kernel: Z.
	 * Want in kernel: X + Y + Z.
	 * => Add in X + Y
	 * => Add in replacement read.
	 */
	newcounters->counters[index] = repl->counters[mappos];
	DEBUGP_C("NORMAL_MAP => mappos %u \n", mappos);
}

static void counters_map_zeroed(STRUCT_COUNTERS_INFO *newcounters,
				STRUCT_REPLACE *repl,
				unsigned int index,
				unsigned int mappos,
				STRUCT_COUNTERS *counters)
{
	/* Original read: X.
	 * Atomic read on replacement: X + Y.
	 * Currently in kernel: Z.
	 * Want in kernel: Y + Z.
	 * => Add in Y.
	 * => Add in (replacement read - original read).
	 */
	subtract_counters(&newcounters->counters[index],
			  &repl->counters[mappos],
			  counters);
	DEBUGP_C("ZEROED => mappos %u\n", mappos);
}

static void counters_map_set(STRUCT_COUNTERS_INFO *newcounters,
			     unsigned int index,
			     STRUCT_COUNTERS *counters)
{
	/* Want to set counter (iptables-restore) */

	memcpy(&newcounters->counters[index], counters,
		sizeof(STRUCT_COUNTERS));

	DEBUGP_C("SET\n");
}


int
TC_COMMIT(TC_HANDLE_T *handle)
{
	/* Replace, then map back the counters. */
	STRUCT_REPLACE *repl;
	STRUCT_COUNTERS_INFO *newcounters;
	struct chain_head *c;
	int ret;
	size_t counterlen;
	int new_number;
	unsigned int new_size;

	iptc_fn = TC_COMMIT;
	CHECK(*handle);

	/* Don't commit if nothing changed. */
	if (!(*handle)->changed)
		goto finished;

	new_number = iptcc_compile_table_prep(*handle, &new_size);
	if (new_number < 0) {
		errno = ENOMEM;
		return 0;
	}

	repl = malloc(sizeof(*repl) + new_size);
	if (!repl) {
		errno = ENOMEM;
		return 0;
	}
	memset(repl, 0, sizeof(*repl) + new_size);

#if 0
	TC_DUMP_ENTRIES(*handle);
#endif

	counterlen = sizeof(STRUCT_COUNTERS_INFO)
			+ sizeof(STRUCT_COUNTERS) * new_number;

	/* These are the old counters we will get from kernel */
	repl->counters = malloc(sizeof(STRUCT_COUNTERS)
				* (*handle)->info.num_entries);
	if (!repl->counters) {
		free(repl);
		errno = ENOMEM;
		return 0;
	}
	/* These are the counters we're going to put back, later. */
	newcounters = malloc(counterlen);
	if (!newcounters) {
		free(repl->counters);
		free(repl);
		errno = ENOMEM;
		return 0;
	}
	memset(newcounters, 0, counterlen);

	strcpy(repl->name, (*handle)->info.name);
	repl->num_entries = new_number;
	repl->size = new_size;

	repl->num_counters = (*handle)->info.num_entries;
	repl->valid_hooks = (*handle)->info.valid_hooks;

	DEBUGP("num_entries=%u, size=%u, num_counters=%u\n",
		repl->num_entries, repl->size, repl->num_counters);

	ret = iptcc_compile_table(*handle, repl);
	if (ret < 0) {
		errno = ret;
		free(repl->counters);
		free(repl);
		return 0;
	}


#ifdef IPTC_DEBUG2
	{
		int fd = open("/tmp/libiptc-so_set_replace.blob", 
				O_CREAT|O_WRONLY);
		if (fd >= 0) {
			write(fd, repl, sizeof(*repl) + repl->size);
			close(fd);
		}
	}
#endif

	if (setsockopt(sockfd, TC_IPPROTO, SO_SET_REPLACE, repl,
		       sizeof(*repl) + repl->size) < 0) {
		free(repl->counters);
		free(repl);
		free(newcounters);
		return 0;
	}

	/* Put counters back. */
	strcpy(newcounters->name, (*handle)->info.name);
	newcounters->num_counters = new_number;

	list_for_each_entry(c, &(*handle)->chains, list) {
		struct rule_head *r;

		/* Builtin chains have their own counters */
		if (iptcc_is_builtin(c)) {
			DEBUGP("counter for chain-index %u: ", c->foot_index);
			switch(c->counter_map.maptype) {
			case COUNTER_MAP_NOMAP:
				counters_nomap(newcounters, c->foot_index);
				break;
			case COUNTER_MAP_NORMAL_MAP:
				counters_normal_map(newcounters, repl,
						    c->foot_index, 
						    c->counter_map.mappos);
				break;
			case COUNTER_MAP_ZEROED:
				counters_map_zeroed(newcounters, repl,
						    c->foot_index, 
						    c->counter_map.mappos,
						    &c->counters);
				break;
			case COUNTER_MAP_SET:
				counters_map_set(newcounters, c->foot_index,
						 &c->counters);
				break;
			}
		}

		list_for_each_entry(r, &c->rules, list) {
			DEBUGP("counter for index %u: ", r->index);
			switch (r->counter_map.maptype) {
			case COUNTER_MAP_NOMAP:
				counters_nomap(newcounters, r->index);
				break;

			case COUNTER_MAP_NORMAL_MAP:
				counters_normal_map(newcounters, repl,
						    r->index, 
						    r->counter_map.mappos);
				break;

			case COUNTER_MAP_ZEROED:
				counters_map_zeroed(newcounters, repl,
						    r->index,
						    r->counter_map.mappos,
						    &r->entry->counters);
				break;

			case COUNTER_MAP_SET:
				counters_map_set(newcounters, r->index,
						 &r->entry->counters);
				break;
			}
		}
	}


#ifdef KERNEL_64_USERSPACE_32
	{
		/* Kernel will think that pointer should be 64-bits, and get
		   padding.  So we accomodate here (assumption: alignment of
		   `counters' is on 64-bit boundary). */
		u_int64_t *kernptr = (u_int64_t *)&newcounters->counters;
		if ((unsigned long)&newcounters->counters % 8 != 0) {
			fprintf(stderr,
				"counters alignment incorrect! Mail rusty!\n");
			abort();
		}
		*kernptr = newcounters->counters;
	}
#endif /* KERNEL_64_USERSPACE_32 */

#ifdef IPTC_DEBUG2
	{
		int fd = open("/tmp/libiptc-so_set_add_counters.blob", 
				O_CREAT|O_WRONLY);
		if (fd >= 0) {
			write(fd, newcounters, counterlen);
			close(fd);
		}
	}
#endif

	if (setsockopt(sockfd, TC_IPPROTO, SO_SET_ADD_COUNTERS,
		       newcounters, counterlen) < 0) {
		free(repl->counters);
		free(repl);
		free(newcounters);
		return 0;
	}

	free(repl->counters);
	free(repl);
	free(newcounters);

 finished:
	TC_FREE(handle);
	return 1;
}

/* Get raw socket. */
int
TC_GET_RAW_SOCKET()
{
	return sockfd;
}

/* Translates errno numbers into more human-readable form than strerror. */
const char *
TC_STRERROR(int err)
{
	unsigned int i;
	struct table_struct {
		void *fn;
		int err;
		const char *message;
	} table [] =
	  { { TC_INIT, EPERM, "Permission denied (you must be root)" },
	    { TC_INIT, EINVAL, "Module is wrong version" },
	    { TC_INIT, ENOENT, 
		    "Table does not exist (do you need to insmod?)" },
	    { TC_DELETE_CHAIN, ENOTEMPTY, "Chain is not empty" },
	    { TC_DELETE_CHAIN, EINVAL, "Can't delete built-in chain" },
	    { TC_DELETE_CHAIN, EMLINK,
	      "Can't delete chain with references left" },
	    { TC_CREATE_CHAIN, EEXIST, "Chain already exists" },
	    { TC_INSERT_ENTRY, E2BIG, "Index of insertion too big" },
	    { TC_REPLACE_ENTRY, E2BIG, "Index of replacement too big" },
	    { TC_DELETE_NUM_ENTRY, E2BIG, "Index of deletion too big" },
	    { TC_READ_COUNTER, E2BIG, "Index of counter too big" },
	    { TC_ZERO_COUNTER, E2BIG, "Index of counter too big" },
	    { TC_INSERT_ENTRY, ELOOP, "Loop found in table" },
	    { TC_INSERT_ENTRY, EINVAL, "Target problem" },
	    /* EINVAL for CHECK probably means bad interface. */
	    { TC_CHECK_PACKET, EINVAL,
	      "Bad arguments (does that interface exist?)" },
	    { TC_CHECK_PACKET, ENOSYS,
	      "Checking will most likely never get implemented" },
	    /* ENOENT for DELETE probably means no matching rule */
	    { TC_DELETE_ENTRY, ENOENT,
	      "Bad rule (does a matching rule exist in that chain?)" },
	    { TC_SET_POLICY, ENOENT,
	      "Bad built-in chain name" },
	    { TC_SET_POLICY, EINVAL,
	      "Bad policy name" },

	    { NULL, 0, "Incompatible with this kernel" },
	    { NULL, ENOPROTOOPT, "iptables who? (do you need to insmod?)" },
	    { NULL, ENOSYS, "Will be implemented real soon.  I promise ;)" },
	    { NULL, ENOMEM, "Memory allocation problem" },
	    { NULL, ENOENT, "No chain/target/match by that name" },
	  };

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((!table[i].fn || table[i].fn == iptc_fn)
		    && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}
