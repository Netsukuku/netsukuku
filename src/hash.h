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

#ifndef HASH_H
#define HASH_H

#define FNV_32_PRIME ((u_long)0x01000193)
#define FNV1_32_INIT ((u_long)0x811c9dc5)

/*\
 *   * *  Functions declaration  * *
\*/
u_long fnv_32_buf(void *buf, size_t len, u_long hval);
unsigned int inthash(unsigned int key);
inline unsigned int dl_elf_hash (const unsigned char *name);
char xor_int(int i);
int hash_time(int *h_sec, int *h_usec);

#endif /*HASH_H*/
