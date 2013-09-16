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
 * hash.c: hash functions
 */

#include "includes.h"
#include "hash.h"

/* Robert Jenkins's 32 bit Mix Function */
unsigned int inthash(unsigned int key)
{
	key += (key << 12);
	key ^= (key >> 22);
	key += (key << 4);
	key ^= (key >> 9);
	key += (key << 10);
	key ^= (key >> 2);
	key += (key << 7);
	key ^= (key >> 12);
	return key;
}

/*		Ripped 32bit Hash function 
 *
 * Fowler/Noll/Vo hash
 *
 * See  http://www.isthe.com/chongo/tech/comp/fnv/index.html
 * for more details as well as other forms of the FNV hash.
 *
 ***
 *
 * Use the recommended 32 bit FNV-1 hash, pass FNV1_32_INIT as the
 * u_long hashval argument to fnv_32_buf().
 *
 ***
 *
 * Please do not copyright this code.  This code is in the public domain.
 *
 * LANDON CURT NOLL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO
 * EVENT SHALL LANDON CURT NOLL BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * By:
 *	chongo <Landon Curt Noll> /\oo/\
 *      http://www.isthe.com/chongo/
 * Share and Enjoy!	:-)
 *
 * fnv_32_buf - perform a 32 bit Fowler/Noll/Vo hash on a buffer
 * `hval'	- previous hash value or 0 if first call
 * returns:
 *	32 bit hash as a static hash type
 */
u_long fnv_32_buf(void *buf, size_t len, u_long hval)
{
    u_char *bp = (u_char *)buf;	/* start of buffer */
    u_char *be = bp + len;		/* beyond end of buffer */

    /*
     * FNV-1 hash each octet in the buffer
     */
    while (bp < be) {

	/* multiply by the 32 bit FNV magic prime mod 2^32 */
	hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);

	/* xor the bottom with the current octet */
	hval ^= (u_long)*bp++;
    }

    /* return our new hash value */
    return hval;
}


/* 
 * Ripped from glibc.
 * This is the hashing function specified by the ELF ABI.  In the
 * first five operations no overflow is possible so we optimized it a
 * bit.  
 */
inline unsigned int dl_elf_hash (const unsigned char *name)
{
  unsigned long int hash = 0;
  if (*name != '\0') {
      hash = *name++;
      if (*name != '\0') {
	  hash = (hash << 4) + *name++;
	  if (*name != '\0') {
	      hash = (hash << 4) + *name++;
	      if (*name != '\0') {
		  hash = (hash << 4) + *name++;
		  if (*name != '\0') {
		      hash = (hash << 4) + *name++;
		      while (*name != '\0') {
			  unsigned long int hi;
			  hash = (hash << 4) + *name++;
			  hi = hash & 0xf0000000;

			  /* The algorithm specified in the ELF ABI is as
			     follows:

			     if (hi != 0)
			       hash ^= hi >> 24;

			     hash &= ~hi;

			     But the following is equivalent and a lot
			     faster, especially on modern processors.  */

			  hash ^= hi;
			  hash ^= hi >> 24;
			}
		    }
		}
	    }
	}
    }
  return hash;
}

/* 
 * hash_time: As the name says: hash time!
 * This function generates the hash of the timeval struct which refer
 * to the current time. 
 * If h_sec or h_usec are not null, it stores in them respectively the hash of
 * the second and the microsecond.
 */
int hash_time(int *h_sec, int *h_usec)
{
	struct timeval t;
	char str[sizeof(struct timeval)+1];
	u_int elf_hash;
	
	gettimeofday(&t, 0);
	memcpy(str, &t, sizeof(struct timeval));
	str[sizeof(struct timeval)]=0;

	elf_hash=dl_elf_hash((u_char *)str);
	
	if(h_sec)
		*h_sec=inthash(t.tv_sec);
	if(h_usec)
		*h_usec=inthash(t.tv_usec);

	return inthash(elf_hash);
}
