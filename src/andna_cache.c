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
 * andna_cache.c: 
 * Functions to manipulate all the andna's caches.
 */

#include "includes.h"

#include "crypto.h"
#include "andna_cache.h"
#include "snsd_cache.h"
#include "common.h"
#include "hash.h"


int net_family;

void andna_caches_init(int family)
{
	net_family = family;

	setzero(&lcl_keyring, sizeof(lcl_keyring));

	andna_lcl=(lcl_cache *)clist_init(&lcl_counter);
	andna_c=(andna_cache *)clist_init(&andna_c_counter);
	andna_counter_c=(counter_c *)clist_init(&cc_counter);
	andna_rhc=(rh_cache *)clist_init(&rhc_counter);
}

/*
 * andna_32bit_hash
 *
 * It returns the 32bit hash of the md5 hash of the `hname' string.
 */
u_int andna_32bit_hash(char *hname)
{
	u_char hashm5[ANDNA_HASH_SZ];
	
	hash_md5((u_char*)hname, strlen(hname), hashm5);
	return fnv_32_buf(hashm5, ANDNA_HASH_SZ, FNV1_32_INIT);
}

/*
 * 
 *  *  *  *  Local Cache functions  *  *  *
 *  
 */

/*
 * lcl_new_keyring
 *
 * It generates a new keyring.
 */
void lcl_new_keyring(lcl_cache_keyring *keyring)
{
	setzero(keyring, sizeof(lcl_cache_keyring));
	loginfo("Generating a new ANDNA keyring");

	/* Generate the new key pair for the first time */
	keyring->priv_rsa = genrsa(ANDNA_PRIVKEY_BITS, &keyring->pubkey, 
			&keyring->pkey_len, &keyring->privkey, &keyring->skey_len);
}

/*
 * lcl_destroy_keyring
 *
 * destroys accurately the keyring ^_^ 
 */
void lcl_destroy_keyring(lcl_cache_keyring *keyring)
{
	if(keyring->priv_rsa)
		RSA_free(keyring->priv_rsa);
	if(keyring->pubkey)
		xfree(keyring->pubkey);
	if(keyring->privkey)
		xfree(keyring->privkey);
	
	setzero(keyring, sizeof(lcl_cache_keyring));
}

/*
 * lcl_cache_new: builds a new lcl_cache generating a new rsa key pair and
 * setting the hostname in the struct 
 */
lcl_cache *lcl_cache_new(char *hname)
{
	lcl_cache *alcl;
	
	alcl=(lcl_cache *)xzalloc(sizeof(lcl_cache));

	alcl->hostname = xstrdup(hname);
	alcl->hash = andna_32bit_hash(hname);

	return alcl;
}

void lcl_cache_free(lcl_cache *alcl) 
{
	if(alcl->hostname)
		xfree(alcl->hostname);
	alcl->snsd_counter=0;
	if(alcl->service)
		snsd_service_llist_del(&alcl->service);
}

void lcl_cache_destroy(lcl_cache *head, int *counter)
{
	lcl_cache *alcl=head, *next;
	
	if(!alcl || !lcl_counter)
		return;
	
	list_safe_for(alcl, next) {
		lcl_cache_free(alcl);
		xfree(alcl);
	}
	*counter=0;
}

lcl_cache *lcl_cache_find_hname(lcl_cache *alcl, char *hname)
{
	u_int hash;
	
	if(!alcl || !lcl_counter)
		return 0;

	hash = andna_32bit_hash(hname);
	list_for(alcl)
		if(alcl->hash == hash && alcl->hostname && 
			!strncmp(alcl->hostname, hname, ANDNA_MAX_HNAME_LEN))
			return alcl;
	return 0;
}

lcl_cache *lcl_cache_find_hash(lcl_cache *alcl, u_int hash)
{
	if(!alcl || !lcl_counter)
		return 0;

	list_for(alcl)
		if(alcl->hash == hash && alcl->hostname)
			return alcl;
	return 0;
}

int is_lcl_hname_registered(lcl_cache *alcl)
{
	return alcl->timestamp;
}

/*
 * lcl_get_registered_hnames
 * 
 * It returns a duplicated lcl_cache of `alcl', which contains only 
 * hostnames already registered.
 * Note that the structs present in the returned cache are in a different
 * mallocated space, so you should free them.
 */
lcl_cache *lcl_get_registered_hnames(lcl_cache *alcl)
{
	lcl_cache *lcl;

	lcl=list_copy_some(alcl, is_lcl_hname_registered);
	list_for(lcl) {
		lcl->hostname=xstrdup(lcl->hostname);
		lcl->service=snsd_service_llist_copy(lcl->service, 
						     SNSD_ALL_SERVICE, 0);
	}

	return lcl;
}

/*
 * 
 *  *  *  *  Andna Cache functions  *  *  *
 *  
 */

andna_cache_queue *ac_queue_findpubk(andna_cache *ac, char *pubk)
{
	andna_cache_queue *acq=ac->acq;
	
	if(!acq)
		return 0;
	list_for(acq)
		if(!memcmp(acq->pubkey, pubk, ANDNA_PKEY_LEN))
				return acq;
	return 0;
}

/*
 * ac_queue_add
 *
 * adds a new entry in the andna cache queue, which is `ac'->acq. 
 * The elements in the new `ac'->acq are updated.
 * If an `ac'->acq struct with an `ac'->acq->pubkey equal to `pubkey' already
 * exists, then only the timestamp and the IP will be updated.
 *
 * It returns the pointer to the acq struct. If it isn't possible to add a new
 * entry in the queue, 0 will be returned.
 *
 * Remember to update the acq->timestamp value after this call.
 */
andna_cache_queue *ac_queue_add(andna_cache *ac, char *pubkey)
{
	andna_cache_queue *acq;

	/* 
	 * This call is not necessary because it's already done by
	 * andna_cache_del_expired().
	 * * ac_queue_del_expired(ac); * * 
	 */
	
	if(!(acq=ac_queue_findpubk(ac, pubkey))) {
		if(ac->queue_counter >= ANDNA_MAX_QUEUE || ac->flags & ANDNA_FULL)
			return 0;

		acq=xzalloc(sizeof(andna_cache_queue));
		memcpy(acq->pubkey, pubkey, ANDNA_PKEY_LEN);
		clist_append(&ac->acq, 0, &ac->queue_counter, acq);
	} 

	
	if(ac->queue_counter >= ANDNA_MAX_QUEUE)
		ac->flags|=ANDNA_FULL;

	return acq;
}

void ac_queue_del(andna_cache *ac, andna_cache_queue *acq)
{
	
	acq->snsd_counter=0;
	if(acq->service)
		snsd_service_llist_del(&acq->service);
	clist_del(&ac->acq, &ac->queue_counter, acq);
	ac->flags&=~ANDNA_FULL;
}

/*
 * ac_queue_del_expired: removes the expired entries from the
 * andna_cache_queue `ac'->acq.
 */
void ac_queue_del_expired(andna_cache *ac)
{
	andna_cache_queue *acq, *next;
	time_t cur_t;
	
	if(!ac || !ac->acq)
		return;

	cur_t=time(0);
	acq=ac->acq;
	list_safe_for(acq, next)
		if(cur_t - acq->timestamp > ANDNA_EXPIRATION_TIME)
			ac_queue_del(ac, acq);
}

/*
 * ac_queue_destroy: destroys an andna_cache_queue 
 */
void ac_queue_destroy(andna_cache *ac)
{
	andna_cache_queue *acq, *next;
	
	if(!ac || !ac->acq)
		return;

	acq=ac->acq;
	list_safe_for(acq, next)
		ac_queue_del(ac, acq);
}

andna_cache *andna_cache_findhash(int hash[MAX_IP_INT])
{
	andna_cache *ac=andna_c;

	if(!andna_c_counter)
		return 0;

	list_for(ac)
		if(!memcmp(ac->hash, hash, ANDNA_HASH_SZ))
			return ac;
	return 0;
}

/*
 * andna_cache_gethash
 *
 * It searches an andna_cache entry which has the same hash of `hash'. 
 * If it found but this entry is expired, it is deleted from the cache and 0 is
 * returned. 
 * If it isn't found 0 is returned, otherwise a pointer to the entry is 
 * returned.
 */
andna_cache *andna_cache_gethash(int hash[MAX_IP_INT])
{
	andna_cache *ac;

	ac=andna_cache_findhash(hash);
	if(ac && andna_cache_del_ifexpired(ac))
		return 0;

	return ac;
}

andna_cache *andna_cache_addhash(int hash[MAX_IP_INT])
{
	andna_cache *ac;

	andna_cache_del_expired();
	
	if(!(ac=andna_cache_findhash(hash))) {
		ac=xzalloc(sizeof(andna_cache));
		memcpy(ac->hash, hash, ANDNA_HASH_SZ);

		clist_add(&andna_c, &andna_c_counter, ac);
	}

	return ac;
}

/*
 * andna_cache_del_ifexpired
 *
 * If `ac' is expired, it deletes it and returns 1; otherwise 0 is returned.
 */
int andna_cache_del_ifexpired(andna_cache *ac)
{
	ac_queue_del_expired(ac);
	
	if(!ac->queue_counter) {
		clist_del(&andna_c, &andna_c_counter, ac);
		return 1;
	}

	return 0;
}

void andna_cache_del_expired(void)
{
        andna_cache *ac=andna_c, *next;

        if(!andna_c_counter)
                return;

	list_safe_for(ac, next)
		andna_cache_del_ifexpired(ac);
}

/*
 * andna_cache_destroy
 *
 * destroys the andna_c llist 
 */
void andna_cache_destroy(void)
{
	andna_cache *ac=andna_c, *next;

        if(!andna_c_counter)
                return;

	list_safe_for(ac, next) {
		ac_queue_destroy(ac);
		clist_del(&andna_c, &andna_c_counter, ac);
	}
}


/*
 * 
 *  *  *  *  Counter Cache functions  *  *  *
 *  
 */

/*
 * Remeber to update the cch->timestamp value after this call.
 */
counter_c_hashes *cc_hashes_add(counter_c *cc, int hash[MAX_IP_INT])
{
	counter_c_hashes *cch;

	/* The purge is already done in counter_c_del_expired(), so it is not
	 * necessary to call it here.
	 * * cc_hashes_del_expired(cc); * *
	 */

	if(!(cch=cc_findhash(cc, hash))) {
		if(cc->hashes >= ANDNA_MAX_HOSTNAMES || cc->flags & ANDNA_FULL)
			return 0;
		
		cch=xzalloc(sizeof(counter_c_hashes));
		memcpy(cch->hash, hash, ANDNA_HASH_SZ);

		clist_add(&cc->cch, &cc->hashes, cch);
	}
	
	if(cc->hashes >= ANDNA_MAX_HOSTNAMES)
		cc->flags|=ANDNA_FULL;
	
	return cch;
}

void cc_hashes_del(counter_c *cc, counter_c_hashes *cch)
{
	clist_del(&cc->cch, &cc->hashes, cch);
	cc->flags&=~ANDNA_FULL;
}

void cc_hashes_del_expired(counter_c *cc)
{
	counter_c_hashes *cch, *next;
	time_t cur_t;
	
	if(!cc || !cc->cch || !cc->hashes)
		return;
	
	cur_t=time(0);
	cch=cc->cch;

	list_safe_for(cch, next)
		if(cur_t - cch->timestamp > ANDNA_EXPIRATION_TIME)
			cc_hashes_del(cc, cch);
}

void cc_hashes_destroy(counter_c *cc)
{
	counter_c_hashes *cch, *next;
	
	if(!cc || !cc->cch || !cc->hashes)
		return;

	cch=cc->cch;
	list_safe_for(cch, next)
		cc_hashes_del(cc, cch);
}

counter_c_hashes *cc_findhash(counter_c *cc, int hash[MAX_IP_INT])
{
	counter_c_hashes *cch=cc->cch;

	if(!cc->hashes || !cch)
		return 0;
	
	list_for(cch)
		if(!memcmp(cch->hash, hash, ANDNA_HASH_SZ))
			return cch;
	return 0;
}

counter_c *counter_c_findpubk(char *pubk)
{
	counter_c *cc=andna_counter_c;
	
	if(!cc_counter || !cc)
		return 0;

	list_for(cc)
		if(!memcmp(&cc->pubkey, pubk, ANDNA_PKEY_LEN))
			return cc;
	return 0;
}

counter_c *counter_c_add(inet_prefix *rip, char *pubkey)
{
	counter_c *cc;

	counter_c_del_expired();

	if(!(cc=counter_c_findpubk(pubkey))) {
		cc=xzalloc(sizeof(counter_c));

		memcpy(cc->pubkey, pubkey, ANDNA_PKEY_LEN);
		clist_add(&andna_counter_c, &cc_counter, cc);
	}

	return cc;
}

void counter_c_del_expired(void)
{
	counter_c *cc=andna_counter_c, *next;
	
	if(!cc)
		return;
	
	list_safe_for(cc, next) {
		cc_hashes_del_expired(cc);
		if(!cc->hashes)
			clist_del(&andna_counter_c, &cc_counter, cc);
	}
}

/*
 * counter_c_destroy
 *
 * destroy the andna_counter_c llist
 */
void counter_c_destroy(void)
{
	counter_c *cc=andna_counter_c, *next;
	
	if(!cc)
		return;
	
	list_safe_for(cc, next) {
		cc_hashes_destroy(cc);
		clist_del(&andna_counter_c, &cc_counter, cc);
	}
}

/*
 * 
 *  *  *  *  Resolved hostnames cache functions  *  *  *
 *  
 */

rh_cache *rh_cache_new_hash(u_int hash, time_t timestamp)
{
	rh_cache *rhc;
	
	rhc=xzalloc(sizeof(rh_cache));
	rhc->hash=hash;
	rhc->timestamp=timestamp;

	return rhc;
}

rh_cache *rh_cache_new(char *hname, time_t timestamp)
{
	return rh_cache_new_hash(andna_32bit_hash(hname), timestamp);
}

/*
 * rh_cache_add_hash
 *
 * It searches a struct in the rh_cache which has the hash value equal to
 * `hash'.
 * If it isn't found a new one is added. In both cases the pointer to the
 * struct will be returned.
 * 
 * On error 0 is returned.
 */
rh_cache *rh_cache_add_hash(u_int hash, time_t timestamp)
{
	rh_cache *rhc;

	if(!(rhc=rh_cache_find_hash(hash))) {
		if(rhc_counter >= ANDNA_MAX_HOSTNAMES) {
			/* Delete the expired hnames and see if there's empty
			 * space */
			rh_cache_del_expired();
			
			if(rhc_counter >= ANDNA_MAX_HOSTNAMES) {
				/* Delete the oldest struct in cache */
				rhc=list_last(andna_rhc);
				clist_del(&andna_rhc, &rhc_counter, rhc);
			}
		}

		rhc=rh_cache_new_hash(hash, timestamp);
		clist_add(&andna_rhc, &rhc_counter, rhc);
	}

	rhc->timestamp=timestamp;

	return rhc;
}

/*
 * rh_cache_add
 *
 * It searches a struct in the rh_cache which is associated to `hname'.
 * If it isn't found a new one is added. In both cases the pointer to the
 * struct will be returned.
 * 
 * On error 0 is returned.
 */
rh_cache *rh_cache_add(char *hname, time_t timestamp)
{
	return rh_cache_add_hash(andna_32bit_hash(hname), timestamp);
}

rh_cache *rh_cache_find_hash(u_int hash)
{
	rh_cache *rhc=andna_rhc, *next;
	time_t cur_t;

	if(!rhc || !rhc_counter)
		return 0;
	
	cur_t=time(0);
	
	list_safe_for(rhc, next)
		if(rhc->hash == hash) {
			if(cur_t - rhc->timestamp > ANDNA_EXPIRATION_TIME) {
				/* This hostname expired, delete it from the
				 * cache */
				rh_cache_del(rhc);
				continue;
			} else
				/* Each time we find a hname in the rh_cache,
				 * we move it on top of the llist. */
				andna_rhc=list_moveontop(andna_rhc, rhc);
			return rhc;
		}
	return 0;
}

rh_cache *rh_cache_find_hname(char *hname)
{
	u_int hash;

	hash=andna_32bit_hash(hname);
	return rh_cache_find_hash(hash);
}

void rh_cache_del(rh_cache *rhc)
{
	rhc->snsd_counter=0;
	if(rhc->service)
		snsd_service_llist_del(&rhc->service);

	clist_del(&andna_rhc, &rhc_counter, rhc);
}

void rh_cache_del_expired(void)
{
	rh_cache *rhc=andna_rhc, *next;
	time_t cur_t;

	if(!rhc || !rhc_counter)
		return;

	cur_t=time(0);
	
	list_safe_for(rhc, next)
		if(cur_t - rhc->timestamp > ANDNA_EXPIRATION_TIME)
			rh_cache_del(rhc);
}

void rh_cache_flush(void)
{
	rh_cache *rhc=andna_rhc, *next;

	list_safe_for(rhc, next)
		rh_cache_del(rhc);
}

/*
 * 
 *  *  *  *  Pack/Unpack functions  *  *  *
 *  
 */

char *pack_lcl_keyring(lcl_cache_keyring *keyring, size_t *pack_sz)
{
	struct lcl_keyring_pkt_hdr key_hdr;
	size_t sz;
	char *pack, *buf;

	key_hdr.skey_len=keyring->skey_len;
	key_hdr.pkey_len=keyring->pkey_len;
	sz=LCL_KEYRING_HDR_PACK_SZ(&key_hdr);
	
	pack=buf=xmalloc(sz);
	bufput(&key_hdr, sizeof(struct lcl_keyring_pkt_hdr));
	ints_host_to_network(pack, lcl_keyring_pkt_hdr_iinfo);

	bufput(keyring->privkey, keyring->skey_len);
	bufput(keyring->pubkey, keyring->pkey_len);
	
	*pack_sz=sz;
	return pack;
}

/*
 * unpack_lcl_keyring: unpacks a lcl keyring. On error it returns -1.
 * In `keyring' it restores the packed keys. 
 */
int unpack_lcl_keyring(lcl_cache_keyring *keyring, char *pack, size_t pack_sz)
{
	struct lcl_keyring_pkt_hdr *hdr;
	char *buf;
	u_char *pk;

	
	hdr=(struct lcl_keyring_pkt_hdr *)pack;
	ints_network_to_host(hdr, lcl_keyring_pkt_hdr_iinfo);

	/*
	 * Restore the keyring 
	 */
	keyring->skey_len=hdr->skey_len;
	keyring->pkey_len=hdr->pkey_len;
	if(keyring->skey_len > ANDNA_SKEY_MAX_LEN) {
		error(ERROR_MSG "Invalid keyring header", ERROR_FUNC);
		return -1;
	}
	
	keyring->privkey=xmalloc(hdr->skey_len);
	keyring->pubkey=xmalloc(hdr->pkey_len);

	/* extract the private key */
	buf=pack+sizeof(struct lcl_keyring_pkt_hdr);
	bufget(keyring->privkey, hdr->skey_len);

	/* public key */
	bufget(keyring->pubkey, hdr->pkey_len);
	
	pk=keyring->privkey;
	if(!(keyring->priv_rsa=get_rsa_priv((const u_char **)&pk,
					keyring->skey_len))) {
		error(ERROR_MSG "Cannot unpack the priv key from the"
				" lcl_pack: %s", ERROR_POS, ssl_strerr());
		return -1;
	}

	return 0;
}

/*
 * pack_lcl_cache
 *
 * packs the entire local cache linked list that starts with the head 
 * `local_cache'. The size of the pack is stored in `pack_sz'.
 * The pointer to the newly allocated pack is returned.
 * Note that the pack is in network byte order.
 */
char *pack_lcl_cache(lcl_cache *local_cache, size_t *pack_sz)
{
	struct lcl_cache_pkt_hdr lcl_hdr;
	lcl_cache *alcl=local_cache;
	size_t sz=0, slen;
	char *pack, *buf, *body;

	lcl_hdr.tot_caches=0;
	sz=LCL_CACHE_HDR_PACK_SZ;
	
	/* Calculate the final pack size */
	list_for(alcl) {
		sz+=LCL_CACHE_BODY_PACK_SZ(strlen(alcl->hostname)+1);
		lcl_hdr.tot_caches++;
	}

	pack=buf=xmalloc(sz);
	bufput(&lcl_hdr, sizeof(struct lcl_cache_pkt_hdr));
	ints_host_to_network(pack, lcl_cache_pkt_hdr_iinfo);
		
	*pack_sz=0;
	if(lcl_hdr.tot_caches) {
		alcl=local_cache;
		
		list_for(alcl) {
			body=buf;
			
			bufput(&alcl->hname_updates, sizeof(u_short));
			bufput(&alcl->timestamp, sizeof(time_t));

			slen=strlen(alcl->hostname)+1;
			bufput(alcl->hostname, slen);
			
			ints_host_to_network(body, lcl_cache_pkt_body_iinfo);
		}
	}

	*pack_sz=sz;
	return pack;
}

/*
 * unpack_lcl_cache
 *
 * Unpacks a packed local cache linked list and returns its head.
 * `counter' is set to the number of struct in the llist.
 *
 * On error 0 is returned and `*counter' is set to -1.
 *
 * Note: `pack' is modified during the unpacking.
 */
lcl_cache *unpack_lcl_cache(char *pack, size_t pack_sz, int *counter)
{
	struct lcl_cache_pkt_hdr *hdr;
	lcl_cache *alcl, *alcl_head=0;
	char *buf;
	size_t slen, unpacked_sz;
	int i=0;
		
	hdr=(struct lcl_cache_pkt_hdr *)pack;
	buf=pack+sizeof(struct lcl_cache_pkt_hdr);
	unpacked_sz=sizeof(struct lcl_cache_pkt_hdr);
	ints_network_to_host(hdr, lcl_cache_pkt_hdr_iinfo);
	*counter=0;

	if(hdr->tot_caches > ANDNA_MAX_HOSTNAMES)
		ERROR_FINISH(*counter, -1, finish);

	*counter=0;
	if(hdr->tot_caches) {
		for(i=0; i<hdr->tot_caches; i++) {
			unpacked_sz+=LCL_CACHE_BODY_PACK_SZ(0);
			if(unpacked_sz > pack_sz)
				ERROR_FINISH(*counter, -1, finish);
			
			slen=strlen(buf+sizeof(u_short)+sizeof(time_t))+1;
			if(slen > ANDNA_MAX_HNAME_LEN || 
					(unpacked_sz+=slen) > pack_sz)
				ERROR_FINISH(*counter, -1, finish);

			ints_network_to_host(buf, lcl_cache_pkt_body_iinfo);
		
			alcl=xzalloc(sizeof(lcl_cache));
			
			bufget(&alcl->hname_updates,  sizeof(u_short));
			bufget(&alcl->timestamp, sizeof(time_t));
			
			alcl->hostname=xstrdup(buf);
			alcl->hash=andna_32bit_hash(alcl->hostname);
			buf+=slen;

			clist_add(&alcl_head, counter, alcl);
		}
	}

finish:
	return alcl_head;
}

/*
 * pack_andna_cache_queue
 *
 * It packs an andna_cache_queue struct. The package is stored in `pack' which
 * has `tot_pack_sz' allocated bytes.
 * `acq' is the struct which will be packed.
 * `pack_type' is equal to ACACHE_PACK_FILE or ACACHE_PACK_PKT, it specify if
 * the package will be stored in a file or will be sent over a network.
 *
 * The number of bytes written in `pack' is returned.
 */
int pack_andna_cache_queue(char *pack, size_t tot_pack_sz, 
			   andna_cache_queue *acq, int pack_type)
{
	char *buf=pack;
	u_int t;
	int pack_sz=0;
	
	if(pack_type == ACACHE_PACK_PKT)
		t = time(0) - acq->timestamp;
	else 
		t = acq->timestamp;
	
	bufput(&t, sizeof(uint32_t));
	bufput(&acq->hname_updates, sizeof(u_short));
	bufput(&acq->pubkey, ANDNA_PKEY_LEN);
	bufput(&acq->snsd_counter, sizeof(u_short));

	pack_sz+=ACQ_BODY_PACK_SZ;
	ints_host_to_network(pack, acq_body_iinfo);
	
	pack_sz+=snsd_pack_all_services(buf, tot_pack_sz, acq->service);
	
	return pack_sz;
}

/*
 * pack_single_andna_cache
 *
 * It packs an andna_cache struct. The package is stored in `pack' which
 * has `tot_pack_sz' allocated bytes.
 * `ac' is the struct which will be packed.
 * `pack_type' is equal to ACACHE_PACK_FILE or ACACHE_PACK_PKT, it specify if
 * the package will be stored in a file or will be sent over a network.
 *
 * The number of bytes written in `pack' is returned.
 */
int pack_single_andna_cache(char *pack, size_t tot_pack_sz,
			    andna_cache *ac, int pack_type)
{
	andna_cache_queue *acq;
	char *buf=pack;
	int pack_sz=0;
	size_t psz;

	bufput(ac->hash, ANDNA_HASH_SZ);
	bufput(&ac->flags, sizeof(char));
	bufput(&ac->queue_counter, sizeof(u_short));
	
	pack_sz+=ACACHE_BODY_PACK_SZ;
	ints_host_to_network(pack, andna_cache_body_iinfo);

	acq=ac->acq;
	list_for(acq) {
		psz=pack_andna_cache_queue(buf, tot_pack_sz, acq, pack_type);
		buf+=psz;
		pack_sz+=psz;
		tot_pack_sz-=psz;
	}

	return pack_sz;
}

/*
 * pack_andna_cache
 * 
 * It packs the entire andna cache linked list that starts with
 * the head `acache'. 
 * The size of the pack is stored in `pack_sz'.
 * `pack_type' specifies if the package will be saved in a file or sent over
 * the net, it is equal to ACACHE_PACK_FILE or to ACACHE_PACK_PKT.
 * 
 * The pointer to the newly allocated pack is returned.
 * The pack is written in network order.
 */
char *pack_andna_cache(andna_cache *acache, size_t *pack_sz, int pack_type)
{
	struct andna_cache_pkt_hdr hdr;
	andna_cache *ac=acache;
	andna_cache_queue *acq;
	char *pack, *buf;
	size_t sz, free_sz, acq_sz, service_sz, psz;
	
	/* Calculate the pack size */
	ac=acache;
	hdr.tot_caches=0;
	sz=sizeof(struct andna_cache_pkt_hdr);
	list_for(ac) {
		acq=ac->acq;
		acq_sz=0;
		list_for(acq) {
			service_sz = SNSD_SERVICE_LLIST_PACK_SZ(acq->service);
			acq_sz	   = ACQ_PACK_SZ(service_sz);
		}
		sz+=ACACHE_PACK_SZ(acq_sz);
		hdr.tot_caches++;
	}
	
	
	free_sz=sz;
	buf=pack=xmalloc(sz);
	
	/* Write the header of the package */
	bufput(&hdr, sizeof(struct andna_cache_pkt_hdr));
	free_sz-=sizeof(struct andna_cache_pkt_hdr);

	ints_host_to_network(pack, andna_cache_pkt_hdr_iinfo);
	
	if(!hdr.tot_caches)
		goto finish;

	/* Pack the rest of the andna_cache */
	ac=acache;
	list_for(ac) {
		psz=pack_single_andna_cache(buf, free_sz, ac, pack_type);
		buf+=psz;
		free_sz-=psz;
	}

finish:
	*pack_sz=sz;
	return pack;
}

/*
 * unpack_acq_llist
 *
 * ac->queue_counter must contain the number of acq structs contained in the
 * package.
 *
 * `*unpacked_sz' is incremented by the number of unpacked bytes.
 *
 * `pack_type' specifies if the package will be saved in a file or sent over
 * the net, it is equal to ACACHE_PACK_FILE or to ACACHE_PACK_PKT.
 */
andna_cache_queue *
unpack_acq_llist(char *pack, size_t pack_sz, size_t *unpacked_sz, 
			andna_cache *ac, int pack_type)
{
	andna_cache_queue *acq=0;
	int e, tmp_counter=0;
	u_short snsd_counter;
	time_t cur_t;
	char *buf;
	
	cur_t=time(0);
	buf=pack;
	for(e=0; e < ac->queue_counter; e++) {
		acq=xzalloc(sizeof(andna_cache_queue));

		ints_network_to_host(buf, acq_body_iinfo);

		bufget(&acq->timestamp, sizeof(uint32_t));
		if(pack_type == ACACHE_PACK_PKT)
			acq->timestamp = cur_t - acq->timestamp;

		bufget(&acq->hname_updates, sizeof(u_short));
		bufget(&acq->pubkey, ANDNA_PKEY_LEN);
		bufget(&acq->snsd_counter, sizeof(u_short));

		pack_sz-=ACACHE_BODY_PACK_SZ;
		(*unpacked_sz)+=ACACHE_BODY_PACK_SZ;
		acq->service=snsd_unpack_all_service(buf, pack_sz, unpacked_sz,
							&snsd_counter);
		if(acq->snsd_counter != snsd_counter) {
			debug(DBG_SOFT, ERROR_MSG "unpack_acq:" 
					"snsd_counter (%h) != snsd_counter (%h)",
					ERROR_POS, acq->snsd_counter, 
					snsd_counter);
			xfree(acq);
			list_destroy(ac->acq);
			return 0;
		}

		clist_add(&ac->acq, &tmp_counter, acq);
	}

	return ac->acq;
}

/*
 * unpack_andna_cache
 *
 * Unpacks a packed andna cache linked list and returns the
 * its head.
 * `counter' is set to the number of struct in the llist.
 * `pack_type' specifies if the package will be saved in a file or sent over
 * the net, it is equal to ACACHE_PACK_FILE or to ACACHE_PACK_PKT.
 * 
 * On error 0 is returned and `*counter' is set to -1.
 * Warning: `pack' will be modified during the unpacking.
 */
andna_cache *unpack_andna_cache(char *pack, size_t pack_sz, int *counter,
		int pack_type)
{
	struct andna_cache_pkt_hdr *hdr;
	andna_cache *ac, *ac_head=0;
	char *buf;
	size_t sz=0;
	int i, err=0;
	size_t unpacked_sz=0;

	hdr=(struct andna_cache_pkt_hdr *)pack;
	ints_network_to_host(hdr, andna_cache_pkt_hdr_iinfo);
	*counter=0;
	
	if(!hdr->tot_caches)
		ERROR_FINISH(err, 1, finish);
		
	buf=pack + sizeof(struct andna_cache_pkt_hdr);
	sz=sizeof(struct andna_cache_pkt_hdr);

	for(i=0; i<hdr->tot_caches; i++) {
		sz+=ACACHE_BODY_PACK_SZ;
		if(sz > pack_sz)
			ERROR_FINISH(err, 1, finish); /* overflow */

		ac=xzalloc(sizeof(andna_cache));

		ints_network_to_host(buf, andna_cache_body_iinfo);

		bufget(ac->hash, ANDNA_HASH_SZ);
		bufget(&ac->flags, sizeof(char));
		bufget(&ac->queue_counter, sizeof(u_short));

		sz+=ACQ_PACK_SZ(0)*ac->queue_counter;
		if(sz > pack_sz)
			ERROR_FINISH(err, 1, finish); /* overflow */
		
		unpacked_sz+=ACACHE_BODY_PACK_SZ;
		
		ac->acq=unpack_acq_llist(buf, pack_sz-unpacked_sz, &unpacked_sz,
				ac, pack_type);
		clist_add(&ac_head, counter, ac);
	}
	
finish:
	if(err)
		*counter=-1;
	return ac_head;
}

/*
 * pack_counter_cache: packs the entire counter cache linked list that starts 
 * with the head `counter'. The size of the pack is stored in `pack_sz'.
 * The pointer to the newly allocated pack is returned.
 * The pack will be in network order.
 */
char *pack_counter_cache(counter_c *countercache, size_t *pack_sz)
{
	struct counter_c_pkt_hdr hdr;
	counter_c *cc=countercache;
	counter_c_hashes *cch;
	char *pack, *buf, *p;
	size_t sz;
	time_t cur_t;
	uint32_t t;
	
	/* Calculate the pack size */
	hdr.tot_caches=0;
	sz=sizeof(struct counter_c_pkt_hdr);
	list_for(cc) {
		sz+=COUNTER_CACHE_PACK_SZ(cc->hashes);
		hdr.tot_caches++;
	}
	
	pack=xmalloc(sz);
	memcpy(pack, &hdr, sizeof(struct counter_c_pkt_hdr));
	ints_host_to_network(pack, counter_c_pkt_hdr_iinfo);
	
	if(hdr.tot_caches) {
		cur_t=time(0);

		buf=pack + sizeof(struct counter_c_pkt_hdr);
		cc=countercache;
		list_for(cc) {
			p=buf;
		
			bufput(cc->pubkey, ANDNA_PKEY_LEN);
			bufput(&cc->flags, sizeof(char));
			bufput(&cc->hashes, sizeof(u_short));

			ints_host_to_network(p, counter_c_body_iinfo);
			
			cch=cc->cch;
			list_for(cch) {
				p=buf;
				
				t = cur_t - cch->timestamp;
				bufput(&t, sizeof(uint32_t));

				bufput(&cch->hname_updates, sizeof(u_short));
				bufput(cch->hash, ANDNA_HASH_SZ);

				ints_host_to_network(p, counter_c_hashes_body_iinfo);
			}
		}
	}

	*pack_sz=sz;
	return pack;
}


/*
 * unpack_counter_cache
 *
 * Unpacks a packed counter cache linked list and returns the its head.
 * `counter' is set to the number of struct in the llist.
 *
 * On error 0 is returned and `*counter' is set to -1.
 *
 * Note: `pack' will be modified during the unpacking.
 */
counter_c *unpack_counter_cache(char *pack, size_t pack_sz, int *counter)
{
	struct counter_c_pkt_hdr *hdr;
	counter_c *cc, *cc_head=0;
	counter_c_hashes *cch;
	char *buf;
	size_t sz;
	int i, e, fake_int=0;
	time_t cur_t;

	hdr=(struct counter_c_pkt_hdr *)pack;
	ints_network_to_host(hdr, counter_c_pkt_hdr_iinfo);
	*counter=0;
	
	if(hdr->tot_caches) {
		cur_t = time(0);

		buf=pack + sizeof(struct counter_c_pkt_hdr);
		sz=sizeof(struct counter_c_pkt_hdr);
		
		for(i=0; i<hdr->tot_caches; i++) {
			sz+=COUNTER_CACHE_BODY_PACK_SZ;
			if(sz > pack_sz)
				/* We don't want to overflow */
				ERROR_FINISH(*counter, -1, finish);

			cc=xzalloc(sizeof(counter_c));
			
			ints_network_to_host(buf, counter_c_body_iinfo);
			
			bufget(cc->pubkey, ANDNA_PKEY_LEN);
			bufget(&cc->flags, sizeof(char));
			bufget(&cc->hashes, sizeof(u_short));


			sz+=COUNTER_CACHE_HASHES_PACK_SZ * cc->hashes;
			if(sz > pack_sz)
				/* bleah */
				ERROR_FINISH(*counter, -1, finish);
			
			for(e=0; e < cc->hashes; e++) {
				cch=xzalloc(sizeof(counter_c_hashes));
				
				ints_network_to_host(buf, counter_c_hashes_body_iinfo);

				cch->timestamp=0;
				bufget(&cch->timestamp, sizeof(uint32_t));
				cch->timestamp = cur_t - cch->timestamp;

				bufget(&cch->hname_updates, sizeof(u_short));
				bufget(cch->hash, ANDNA_HASH_SZ);

				clist_add(&cc->cch, &fake_int, cch);
			}

			clist_add(&cc_head, counter, cc);
		}
	}
finish:
	return cc_head;
}


/*
 * pack_rh_cache
 *
 * It packs the entire resolved hnames cache linked list that starts 
 * with the head `rhcache'. The size of the pack is stored in `pack_sz'.
 * The pointer to the newly allocated pack is returned.
 * The pack will be in network order.
 */
char *pack_rh_cache(rh_cache *rhcache, size_t *pack_sz)
{
	struct rh_cache_pkt_hdr rh_hdr;
	rh_cache *rhc=rhcache;
	size_t tot_pack_sz=0, service_sz;
	char *pack, *buf, *body;

	rh_hdr.tot_caches=0;
	tot_pack_sz=sizeof(struct rh_cache_pkt_hdr);
	
	/* Calculate the final pack size */
	list_for(rhc) {
		service_sz=SNSD_SERVICE_LLIST_PACK_SZ(rhc->service);
		tot_pack_sz+=RH_CACHE_BODY_PACK_SZ(service_sz);
		rh_hdr.tot_caches++;
	}
	*pack_sz=tot_pack_sz;

	buf=pack=xmalloc(tot_pack_sz);
	bufput(&rh_hdr, sizeof(struct rh_cache_pkt_hdr));
	tot_pack_sz-=sizeof(struct rh_cache_pkt_hdr);
	
	ints_host_to_network(pack, rh_cache_pkt_hdr_iinfo);

	if(rh_hdr.tot_caches) {
		rhc=rhcache;
		
		list_for(rhc) {
			body=buf;

			bufput(&rhc->hash, sizeof(u_int));
			bufput(&rhc->flags, sizeof(char));
			bufput(&rhc->timestamp, sizeof(time_t));
			
			tot_pack_sz-=RH_CACHE_BODY_PACK_SZ(0);

			tot_pack_sz-=snsd_pack_all_services(buf, tot_pack_sz, 
								 rhc->service);
			
			/* host -> network order */
			ints_host_to_network(buf, rh_cache_pkt_body_iinfo);
		}
	}

	return pack;
}

/*
 * unpack_rh_cache
 *
 * Unpacks a packed resolved hnames cache linked list and returns its head.
 * `counter' is set to the number of struct in the llist.
 *
 * On error 0 is returned and `*counter' is set to -1.
 *
 * Note: `pack' will be modified during the unpacking.
 */
rh_cache *unpack_rh_cache(char *pack, size_t pack_sz, int *counter)
{
	struct rh_cache_pkt_hdr *hdr;
	rh_cache *rhc=0, *rhc_head=0;
	char *buf;
	size_t unpacked_sz=0;
	int i=0;
		
	hdr=(struct rh_cache_pkt_hdr *)pack;
	ints_network_to_host(hdr, rh_cache_pkt_hdr_iinfo);
	*counter=0;

	if(hdr->tot_caches > ANDNA_MAX_RHC_HNAMES)
		ERROR_FINISH(*counter, -1, finish);

	*counter=0;
	if(hdr->tot_caches) {
		buf=pack + sizeof(struct rh_cache_pkt_hdr);
		unpacked_sz=sizeof(struct rh_cache_pkt_hdr);

		for(i=0; i<hdr->tot_caches; i++) {
			unpacked_sz+=RH_CACHE_BODY_PACK_SZ(0);
			if(unpacked_sz > pack_sz)
				ERROR_FINISH(*counter, -1, finish);

			ints_network_to_host(buf, rh_cache_pkt_body_iinfo);
			
			rhc=xzalloc(sizeof(rh_cache));
			
			bufget(&rhc->hash, sizeof(u_int));
			bufget(&rhc->flags, sizeof(char));
			bufget(&rhc->timestamp, sizeof(time_t));

			rhc->service=snsd_unpack_all_service(buf, pack_sz,
					&unpacked_sz, 0);
			
			clist_add(&rhc_head, counter, rhc);
		}
	}

finish:
	return rhc_head;
}


/*
 * 
 *  *  *  *  Save/Load functions  *  *  *
 * 
 */

/*
 * save_lcl_keyring: saves a local cache keyring in the specified `file'.
 */
int save_lcl_keyring(lcl_cache_keyring *keyring, char *file)
{
	FILE *fd;
	size_t pack_sz;
	char *pack;

	/*Pack!*/
	pack=pack_lcl_keyring(keyring, &pack_sz);
	if(!pack_sz || !pack)
		return 0;
	
	if((fd=fopen(file, "w"))==NULL) {
		error("Cannot save the lcl_keyring in %s: %s", file, 
				strerror(errno));
		return -1;
	}

	/*Write!*/
	fwrite(pack, pack_sz, 1, fd);
	
	xfree(pack);
	fclose(fd);
	return 0;
}

/*
 * load_lcl_keyring
 *
 * loads from `file' a local cache keyring and restores in it the RSA keys.
 *
 * On error -1 is returned.
 */
int load_lcl_keyring(lcl_cache_keyring *keyring, char *file)
{
	FILE *fd;
	char *pack=0;
	size_t pack_sz;
	int ret=0;
	
	if(!(fd=fopen(file, "r"))) {
		error("Cannot load the lcl_keyring from %s: %s", file,
				strerror(errno));
		return -1;
	}

	fseek(fd, 0, SEEK_END);
	pack_sz=ftell(fd);
	rewind(fd);
	
	pack=xmalloc(pack_sz);
	if(!fread(pack, pack_sz, 1, fd))
		ERROR_FINISH(ret, -1, finish);
	
	ret=unpack_lcl_keyring(keyring, pack, pack_sz);

finish:
	if(pack)
		xfree(pack);
	fclose(fd);

	if(ret < 0)
		debug(DBG_NORMAL, "Malformed or empty lcl_keyring file. "
				"Aborting load_lcl_keyring().");
	return ret;
}


/*
 * save_lcl_cache: saves a local cache linked list in the specified `file'.
 */
int save_lcl_cache(lcl_cache *lcl, char *file)
{
	FILE *fd;
	size_t pack_sz;
	char *pack;

	/*Pack!*/
	pack=pack_lcl_cache(lcl, &pack_sz);
	if(!pack_sz || !pack)
		return 0;
	
	if((fd=fopen(file, "w"))==NULL) {
		error("Cannot save the lcl_cache in %s: %s", file, strerror(errno));
		return -1;
	}

	/*Write!*/
	fwrite(pack, pack_sz, 1, fd);
	
	xfree(pack);
	fclose(fd);
	return 0;
}

/*
 * load_lcl_cache: loads from `file' a local cache list and returns the head
 * of the newly allocated llist. In `counter' it is stored the number of
 * structs of the llist.
 * On error 0 is returned.
 */
lcl_cache *load_lcl_cache(char *file, int *counter)
{
	lcl_cache *lcl=0;
	FILE *fd;
	char *pack=0;
	size_t pack_sz;
	
	if(!(fd=fopen(file, "r"))) {
		error("Cannot load the lcl_cache from %s: %s", file, strerror(errno));
		return 0;
	}

	fseek(fd, 0, SEEK_END);
	pack_sz=ftell(fd);
	rewind(fd);
	
	pack=xmalloc(pack_sz);
	if(!fread(pack, pack_sz, 1, fd))
		goto finish;
	
	lcl=unpack_lcl_cache(pack, pack_sz, counter);

finish:
	if(pack)
		xfree(pack);
	fclose(fd);
	if(!lcl && counter < 0)
		error("Malformed lcl_cache file (%s)"
				"Aborting load_lcl_cache().", file);
	return lcl;
}


/*
 * save_andna_cache: saves an andna cache linked list in the `file' specified 
 */
int save_andna_cache(andna_cache *acache, char *file)
{
	FILE *fd;
	size_t pack_sz;
	char *pack;

	/*Pack!*/
	pack=pack_andna_cache(acache, &pack_sz, ACACHE_PACK_FILE);
	if(!pack_sz || !pack)
		return 0;
	
	if((fd=fopen(file, "w"))==NULL) {
		error("Cannot save the andna_cache in %s: %s", file, strerror(errno));
		return -1;
	}

	/*Write!*/
	fwrite(pack, pack_sz, 1, fd);
	
	xfree(pack);
	fclose(fd);
	return 0;
}

/*
 * load_andna_cache: loads from `file' an andna cache list and returns the head
 * of the newly allocated llist. In `counter' it is stored the number of
 * list's structs.
 * On error 0 is returned.
 */
andna_cache *load_andna_cache(char *file, int *counter)
{
	andna_cache *acache=0;
	FILE *fd;
	char *pack=0;
	size_t pack_sz;
	
	if((fd=fopen(file, "r"))==NULL) {
		error("Cannot load the andna_cache from %s: %s", file, strerror(errno));
		return 0;
	}

	fseek(fd, 0, SEEK_END);
	pack_sz=ftell(fd);
	rewind(fd);
	
	pack=xmalloc(pack_sz);
	if(!fread(pack, pack_sz, 1, fd))
		goto finish;
	
	acache=unpack_andna_cache(pack, pack_sz, counter, ACACHE_PACK_FILE);

finish:
	if(pack)
		xfree(pack);
	fclose(fd);
	if(!acache && counter < 0)
		error("Malformed andna_cache file."
				" Aborting load_andna_cache().");
	else if(!acache)
		debug(DBG_NORMAL, "Empty andna_cache file.");

	return acache;
}


/*
 * save_counter_c: saves a counter cache linked list in the `file' specified 
 */
int save_counter_c(counter_c *countercache, char *file)
{
	FILE *fd;
	size_t pack_sz;
	char *pack;

	/*Pack!*/
	pack=pack_counter_cache(countercache, &pack_sz);
	if(!pack_sz || !pack)
		return 0;
	
	if((fd=fopen(file, "w"))==NULL) {
		error("Cannot save the counter_c in %s: %s", file, strerror(errno));
		return -1;
	}

	/*Write!*/
	fwrite(pack, pack_sz, 1, fd);
	
	xfree(pack);
	fclose(fd);
	return 0;
}

/*
 * load_counter_c: loads from `file' a counter cache list and returns the head
 * of the newly allocated llist. In `counter' it is stored the number of
 * list's structs.
 * On error 0 is returned.
 */
counter_c *load_counter_c(char *file, int *counter)
{
	counter_c *countercache=0;
	FILE *fd;
	char *pack=0;
	size_t pack_sz;
	
	if((fd=fopen(file, "r"))==NULL) {
		error("Cannot load the counter_c from %s: %s", file, strerror(errno));
		return 0;
	}

	fseek(fd, 0, SEEK_END);
	pack_sz=ftell(fd);
	rewind(fd);
	
	pack=xmalloc(pack_sz);
	if(!fread(pack, pack_sz, 1, fd))
		goto finish;
	
	countercache=unpack_counter_cache(pack, pack_sz, counter);

finish:
	if(pack)
		xfree(pack);
	fclose(fd);
	if(!countercache && counter < 0)
		debug(DBG_NORMAL, "Malformed counter_c file (%s). "
				"Aborting load_counter_c().", file);
	return countercache;
}


/*
 * save_rh_cache: saves the resolved hnames cache linked list `rh' in the
 * `file' specified.
 */
int save_rh_cache(rh_cache *rh, char *file)
{
	FILE *fd=0;
	size_t pack_sz;
	char *pack;

	/*Pack!*/
	pack=pack_rh_cache(rh, &pack_sz);
	if(!pack_sz || !pack)
		return 0;
	
	if(!(fd=fopen(file, "w"))) {
		error("Cannot save the rh_cache in %s: %s",
				file, strerror(errno));
		return -1;
	}

	/*Write!*/
	fwrite(pack, pack_sz, 1, fd);
	
	xfree(pack);
	fclose(fd);
	return 0;
}

/*
 * load_rh_cache: loads from `file' a resolved hnames cache list and returns 
 * the head of the newly allocated llist. In `counter' it is stored the number
 * of structs of the llist.
 * On error 0 is returned.
 */
rh_cache *load_rh_cache(char *file, int *counter)
{
	rh_cache *rh=0;
	FILE *fd;
	char *pack=0;
	size_t pack_sz;
	
	if((fd=fopen(file, "r"))==NULL) {
		error("Cannot load the rh_cache from %s: %s", file, strerror(errno));
		return 0;
	}

	fseek(fd, 0, SEEK_END);
	pack_sz=ftell(fd);
	rewind(fd);
	
	pack=xmalloc(pack_sz);
	if(!fread(pack, pack_sz, 1, fd))
		goto finish;
	
	rh=unpack_rh_cache(pack, pack_sz, counter);

finish:
	if(pack)
		xfree(pack);
	fclose(fd);
	if(!rh && counter < 0)
		error("Malformed rh_cache file (%s). "
				"Aborting load_rh_cache().", file);
	return rh;
}


/*
 * load_hostnames
 *
 * It reads the `file' specified and reads each line in it.
 * The strings read are the hostnames that will be registered in andna.
 * Only ANDNA_MAX_HOSTNAMES lines are read. Each line can be maximum of
 * ANDNA_MAX_HNAME_LEN character long.
 * 
 * This function updates automagically the old local cache that is pointed by 
 * `*old_alcl_head'. The hostnames that are no more present in the loaded
 * `file' are discarded from the local cache.
 * Since a new local cache is allocated and the old is destroyed, the new
 * pointer to it is written in `*old_alcl_head'.
 * 
 * The `old_alcl_counter' is updated too.
 * 
 * This function shall be used each time the `file' changes.
 * 
 * On error -1 is returned, otherwise 0 shall be the sacred value.
 */
int load_hostnames(char *file, lcl_cache **old_alcl_head, int *old_alcl_counter)
{
	FILE *fd;
	char buf[ANDNA_MAX_HNAME_LEN+1];
	size_t slen;
	time_t cur_t, diff;
	int i=0;

	lcl_cache *alcl, *old_alcl, *new_alcl_head=0;
	int new_alcl_counter=0;

	if((fd=fopen(file, "r"))==NULL) {
		error("Cannot load any hostnames from %s: %s", file, strerror(errno));
		return -1;
	}

	cur_t=time(0);
	while(!feof(fd) && i < ANDNA_MAX_HOSTNAMES) {
		setzero(buf, ANDNA_MAX_HNAME_LEN+1);
		fgets(buf, ANDNA_MAX_HNAME_LEN, fd);
		if(feof(fd))
			break;

		if((*buf)=='#' || (*buf)=='\n' || !(*buf)) {
			/* Strip off the comment lines */
			continue;
		} else {
			slen=strlen(buf);
			if(buf[slen-1] == '\n') {
				/* Don't include the newline in the string */
				buf[slen-1]='\0';
				slen=strlen(buf);
			}

			/* Add the hname in the new local cache */
			alcl = lcl_cache_new(buf);
			clist_add(&new_alcl_head, &new_alcl_counter, alcl);

			/*
			 * If there is an equal entry in the old lcl_cache and
			 * it isn't expired, copy the old data in the new 
			 * struct.
			 */
			old_alcl = lcl_cache_find_hname(*old_alcl_head,
					alcl->hostname);
			if(old_alcl) {
				diff=cur_t - old_alcl->timestamp;
				if(diff < ANDNA_EXPIRATION_TIME) {
					alcl->timestamp=old_alcl->timestamp;
					alcl->hname_updates=old_alcl->hname_updates;
				}
			}
			i++;
		}
	}

	/* Remove completely the old lcl_cache */
	lcl_cache_destroy(*old_alcl_head, old_alcl_counter);

	/* Update the pointers */
	*old_alcl_head=new_alcl_head;
	*old_alcl_counter=new_alcl_counter;

	fclose(fd);
	return 0;
}

/*
 * load_snsd
 *
 * It loads the SNSD records to be registered from the given `file'.
 * In the file there shall be one record per line, up to SNSD_MAX_RECORDS-1#
 * records.
 * 
 * Each line has to be written in the following format:
 * 	hostname:snsd_hostname:service:priority:weight[:pub_key_file]
 * or
 * 	hostname:snsd_ip:service:priority:weight[:pub_key_file]
 * 
 * The old records present in `alcl_head' will be deleted and substituted by
 * the loaded ones.
 *
 * On error -1 is returned.
 * If a syntax error is encountered in the file -2 is returned.
 */
int load_snsd(char *file, lcl_cache *alcl_head)
{
#define MAX_SNSD_LINE_SZ		(ANDNA_MAX_HNAME_LEN*4)
	
	FILE *fd;
	size_t slen;
	int line=0, fields, e, service, nodes, ret=0, err;
	char buf[MAX_SNSD_LINE_SZ+1], **records;
	u_char proto, abort=0;

	lcl_cache *alcl;
	snsd_service *sns;
	snsd_prio *snp;
	snsd_node *snd, snsd_node;
	inet_prefix ip;

	/* Delete all the old snsd records */
	alcl=alcl_head;
	list_for(alcl)
		if(alcl->service)
			snsd_service_llist_del(&alcl->service);

	if((fd=fopen(file, "r"))==NULL) {
		error("Cannot open the snsd_nodes file from %s: %s", 
				file, strerror(errno));
		return -1;
	}

	line=1;
	while(!feof(fd) && line <= SNSD_MAX_RECORDS-1) {
		setzero(buf, MAX_SNSD_LINE_SZ+1);
		fgets(buf, MAX_SNSD_LINE_SZ, fd);
		if(feof(fd))
			break;

		if((*buf)=='#' || (*buf)=='\n' || !(*buf)) {
			/* Strip off the comment lines */
			line++;
			continue;
		} else {
			slen=strlen(buf);
			if(buf[slen-1] == '\n') {
				/* Don't include the newline in the string */
				buf[slen-1]='\0';
				slen=strlen(buf);
			}
			
			records=split_string(buf, ":", &fields, MAX_SNSD_FIELDS,
					ANDNA_MAX_HNAME_LEN*2);
			if(fields < MIN_SNSD_FIELDS) {
				error("%s: Syntax error in line %d.\n"
					"  The correct syntax is:\n"
					"  \thostname:snsd_hostname:service:"
					     "priority:weight[:pub_key_file]\n"
					"  or\n"
					"  \thostname:snsd_ip:service:"
					     "priority:weight[:pub_key_file]",
					file, line);
				ERROR_FINISH(abort, 1, skip_line);
			}
			
			/* 
			 * hostname 
			 */
			alcl=lcl_cache_find_hname(alcl_head, records[0]);
			if(!alcl) {
				error("%s: line %d: The hostname \"%s\" doesn't"
					" exist in your local cache.\n"
					"  Register it in the `andna_hostnames' file",
					file, line, records[0]);
				ERROR_FINISH(abort, 1, skip_line);
			}
			
			/* 
			 * snsd record 
			 */
			if(str_to_inet(records[1], &ip) >= 0) {
				inet_copy_ipdata_raw(snsd_node.record, &ip);
				snsd_node.flags=SNSD_NODE_IP;
			} else {
				hash_md5((u_char*)records[1], strlen(records[1]), 
						(u_char *)snsd_node.record);
				snsd_node.flags=SNSD_NODE_HNAME;
			}

			if(!strncmp(records[0], records[1],
					ANDNA_MAX_HNAME_LEN) &&
						!strcmp(records[2], "0"))
				snsd_node.flags=SNSD_NODE_MAIN_IP | SNSD_NODE_IP;
			
			/***
			 * Parse service and protocol
			 */
			err=str_to_snsd_service(records[2], &service, &proto);
			if(err == -1)
				error("%s: error in line %d: \"%s\""
						" isn't a valid protocol\n",
						file, line, records[2]);
			else if(err == -2)
				error("%s: error in line %d: \"%s\""
						" isn't a valid service\n",
						file, line, records[2]);
			if(err < 0)
				ERROR_FINISH(abort, 1, skip_line);
			/**/

			/* Store service and protocol */
			sns=snsd_add_service(&alcl->service, service, proto);
			
			/* priority */
			snp=snsd_add_prio(&sns->prio, atoi(records[3]));
			nodes=snsd_count_prio_nodes(sns->prio);
			if(nodes >= SNSD_MAX_REC_SERV-1) {
				error("%s: The maximum number of records for"
				      " the service \"%s\" has been reached.\n"
				      "  The maximum is %d records per service",
				      file, service, SNSD_MAX_REC_SERV);
				ERROR_FINISH(abort, 1, skip_line);
			}
				
			/* node and weight */
			snd=snsd_add_node(&snp->node, &alcl->snsd_counter,
					SNSD_MAX_RECORDS-1, snsd_node.record);
			snd->weight=SNSD_WEIGHT(atoi(records[4]));
			snd->flags|=snsd_node.flags;
			
			/* pub_key_file 
			 * TODO: 
			 * if(fields >= 6)
			 *   snd->pubkey=load_pubkey(records[5])
			 */


skip_line:
			for(e=0; e<fields; e++)
				xfree(records[e]);
			if(abort)
				ERROR_FINISH(ret, -2, finish);
		}
		line++;
	}

finish:
	fclose(fd);
	return ret;
}


/*
 *
 *  *  *  *  Modify /etc/resolv.conf  *  *  *
 *  
 */


/*
 * add_resolv_conf: It opens `file' and write in the first line `hname' moving
 * down the previous lines. The old `file' is backupped in `file'.bak.
 * Example: add_resolv_conf("nameserver 127.0.0.1", "/etc/resolv.conf").
 * Use del_resolv_conf to restore `file' with its backup.
 * On error -1 is returned.
 */
int add_resolv_conf(char *hname, char *file)
{
	FILE *fin=0,		/* `file' */
	     *fin_bak=0,	/* `file'.bak */
	     *fout=0,		/* The replaced `file' */
	     *fout_back=0;	/* The backup of `file' */
	     
	char *buf=0, *p, *file_bk=0;
	size_t buf_sz;
	int ret=0;

	/*
	 *  Open and read `file' 
	 */
	
	if(!(fin=fopen(file, "r"))) {
		error("add_resolv_conf: cannot load %s: %s", file, strerror(errno));
		ERROR_FINISH(ret, -1, finish);
	}

	/* Prepare the name of the backup file */
	file_bk=xmalloc(strlen(file) + strlen(".bak") + 1);
	*file_bk=0;
	strcpy(file_bk, file);
	strcat(file_bk, ".bak");
	
reread_fin:
	fseek(fin, 0, SEEK_END);
	buf_sz=ftell(fin);
	rewind(fin);
	
	buf=xmalloc(buf_sz);
	if(!fread(buf, buf_sz, 1, fin)) {
		error("add_resolv_conf: it wasn't possible to read the %s file",
				file);
		ERROR_FINISH(ret, -1, finish);
	}

	/* 
	 * If there is already the `hname' string in the first line, try to
	 * read `file'.bak, if it doesn't exist do nothing.
	 */
	if(buf_sz-1 >= strlen(hname) && !strncmp(buf, hname, strlen(hname))) {
		if(fin == fin_bak) {
			/*
			 * We've already read `fin_bak', and it has
			 * the `hname' string in its first line too. Stop it.
			 */
			goto finish;
		}
		
		debug(DBG_NORMAL, "add_resolv_conf: Reading %s instead", 
				file_bk);
		if(!(fin_bak=fopen(file_bk, "r")))
			goto finish;
		
		fclose(fin);
		fin=fin_bak;
		
		goto reread_fin;
	}
	
	/*
	 * Backup `file' in `file'.bak
	 */
	if(!(fout_back=fopen(file_bk, "w"))) {
		error("add_resolv_conf: cannot create a backup copy of %s in %s: %s", file,
			file_bk, strerror(errno));
		ERROR_FINISH(ret, -1, finish);
	}
	fwrite(buf, buf_sz, 1, fout_back);

	/*
	 * Delete `file'
	 */
	fclose(fin);
	fin=0;
	unlink(file);
	
	/*
	 * Add as a first line `hname' in `file'
	 */
	if(!(fout=fopen(file, "w"))) {
		error("add_resolv_conf: cannot reopen %s to overwrite it: %s", file, 
				strerror(errno));
		ERROR_FINISH(ret, -1, finish);
	}
	fprintf(fout, "%s\n", hname);
	p=buf;
	while(*p) {
		if(*p != '#')
			fprintf(fout, "#");
		while(*p) { 
			fprintf(fout, "%c", *p);
			if(*p == '\n')
				break;
			p++;
		}
		if(!*p)
			break;
		p++;
	}
	/*fwrite(buf, buf_sz, 1, fout);*/
	
finish:
	if(buf)
		xfree(buf);
	if(file_bk)
		xfree(file_bk);
	if(fin)
		fclose(fin);
	if(fout)
		fclose(fout);
	if(fout_back)
		fclose(fout_back);

	return ret;
}

/*
 * del_resolv_conf
 * 
 * restores the old `file' modified by add_resolv_conf() by 
 * copying `file'.bak over `file'. If the `hname' string is present in
 * `file'.bak it won't be written in `file'.
 * On error it returns -1.
 */
int del_resolv_conf(char *hname, char *file)
{
	FILE *fin=0, *fout=0;
	     
	char *buf=0, *file_bk=0, tmp_buf[128+1];
	size_t buf_sz;
	int ret=0;

	/*
	 *  Open and read `file'.bak 
	 */
	file_bk=xmalloc(strlen(file) + strlen(".bak") + 1);
	*file_bk=0;
	strcpy(file_bk, file);
	strcat(file_bk, ".bak");
	if(!(fin=fopen(file_bk, "r"))) {
		/*error("del_resolv_conf: cannot load %s: %s", file_bk, strerror(errno));*/
		ERROR_FINISH(ret, -1, finish);
	}

	fseek(fin, 0, SEEK_END);
	buf_sz=ftell(fin);
	rewind(fin);

	if(!buf_sz) {
		/* `file_bk' is empty, delete it */
		unlink(file_bk);
		ERROR_FINISH(ret, -1, finish);
	}
	
	buf=xzalloc(buf_sz);
	while(fgets(tmp_buf, 128, fin)) {
		/* Skip the line which is equal to `hname' */
		if(!strncmp(tmp_buf, hname, strlen(hname)))
			continue;
		strcat(buf, tmp_buf);
	}
	
	/*
	 * Delete `file'
	 */
	unlink(file);

	/*
	 * Copy `file'.bak in `file'
	 */
	
	if(!(fout=fopen(file, "w"))) {
		error("del_resolv_conf: cannot copy %s in %s: %s", file_bk,
			file, strerror(errno));
		ERROR_FINISH(ret, -1, finish);
	}
	fprintf(fout, "%s", buf);

	/*
	 * delete `file'.bak
	 */
	
	fclose(fin);
	fin=0;
	unlink(file_bk);
	
finish:
	if(buf)
		xfree(buf);
	if(file_bk)
		xfree(file_bk);
	if(fin)
		fclose(fin);
	if(fout)
		fclose(fout);

	return ret;
}
