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
 * endian.c:
 * stuff to handle endianess mischief.
 */

#include "includes.h"

#include "common.h"
#include "log.h"
#include "endianness.h"

#ifdef DEBUG

/* Call fatal if `i' is equal to IINFO_DYNAMIC_VALUE.
 * Note: this is needed only for debugging purpose */
#define IS_DYNAMIC(i) 							\
({									\
	if((i) == IINFO_DYNAMIC_VALUE)					\
	  fatal("%s:%d: IINFO_DYNAMIC_VALUE encountered", ERROR_POS);	\
})

#else

#define IS_DYNAMIC(i) ({do_nothing();})

#endif	/*DEBUG*/

void *int_info_copy(int_info *dst, const int_info *src)
{
	return memcpy(dst, src, sizeof(int_info));
}
		
void ints_array_ntohl(int *hostlong, int nmemb)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	int i;
	
	for(i=0; i<nmemb; i++)
		hostlong[i]=ntohl(hostlong[i]);
#endif
}

void ints_array_htonl(int *netlong, int nmemb)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	int i;
	
	for(i=0; i<nmemb; i++)
		netlong[i]=htonl(netlong[i]);
#endif
}

void ints_array_ntohs(short *hostshort, int nmemb)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	int i;
	
	for(i=0; i<nmemb; i++)
		hostshort[i]=ntohs(hostshort[i]);
#endif
}

void ints_array_htons(short *netshort, int nmemb)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	int i;
	
	for(i=0; i<nmemb; i++)
		netshort[i]=htons(netshort[i]);
#endif
}


/*
 * ints_network_to_host: converts all the int/short variables present in the
 * struct `s' from network order to host order. The `s' struct must be
 * described in the `iinfo' struct.
 */
void ints_network_to_host(void *s, int_info iinfo)
{
#if BYTE_ORDER == LITTLE_ENDIAN

	int i;
	char *p;

	IS_DYNAMIC(iinfo.total_ints);
	
	for(i=0; i < iinfo.total_ints; i++) {
		if(!iinfo.int_type[i])
			continue;

		IS_DYNAMIC(iinfo.int_offset[i]);
		
		p=(char *)s + iinfo.int_offset[i];
		
		IS_DYNAMIC(iinfo.int_nmemb[i]);
		IS_DYNAMIC(iinfo.int_type[i]);

		/* 
		 * Swap the entire array if it is a single integer and if we 
		 * are on a little endian machine.
		 */
		if(iinfo.int_type[i] & INT_TYPE_WORDS) {
			
			if(iinfo.int_type[i] & INT_TYPE_32BIT)
				swap_ints(iinfo.int_nmemb[i], (u_int *)p,
						(u_int *)p);
			else
				swap_shorts(iinfo.int_nmemb[i], (u_short *)p,
						(u_short *)p);
		}
		
		if(iinfo.int_type[i] & INT_TYPE_32BIT)
			ints_array_ntohl((int *)p, iinfo.int_nmemb[i]);
		else
			ints_array_ntohs((short *)p, iinfo.int_nmemb[i]);
	}
#endif
}

/*
 * ints_host_to_network: converts all the int/short variables present in the
 * struct `s' from host order to network order. The `s' struct must be
 * described in the `iinfo' struct.
 */
void ints_host_to_network(void *s, int_info iinfo)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	int i;
	char *p;

	IS_DYNAMIC(iinfo.total_ints);

	for(i=0; i < iinfo.total_ints; i++) {
		if(!iinfo.int_type[i])
			continue;

		IS_DYNAMIC(iinfo.int_offset[i]);

		p=(char *)s + iinfo.int_offset[i];
		
		IS_DYNAMIC(iinfo.int_nmemb[i]);
		IS_DYNAMIC(iinfo.int_type[i]);

		/* 
		 * Swap the entire array if it is a single integer and if we 
		 * are on a little endian machine.
		 */
		if(iinfo.int_type[i] & INT_TYPE_WORDS) {
			
			if(iinfo.int_type[i] & INT_TYPE_32BIT)
				swap_ints(iinfo.int_nmemb[i], (u_int *)p, (u_int *)p);
			else
				swap_shorts(iinfo.int_nmemb[i], (u_short *)p, (u_short *)p);
		}

		if(iinfo.int_type[i] & INT_TYPE_32BIT)
			ints_array_htonl((int *)p, iinfo.int_nmemb[i]);
		else
			ints_array_htons((short *)p, iinfo.int_nmemb[i]);
	}
#endif
}

/*
 * ints_printf: prints all the int/short vars present in the `s' struct
 * described by `iinfo'. It uses `print_func' as the the printing function
 */
void ints_printf(void *s, int_info iinfo, void(*print_func(const char *, ...)))
{
	int i, e, *i32;
	short *i16;
	char *p;

	IS_DYNAMIC(iinfo.total_ints);

	for(i=0; i < iinfo.total_ints; i++) {
		if(!iinfo.int_type[i])
			continue;

		IS_DYNAMIC(iinfo.int_offset[i]);

		p=(char *)s + iinfo.int_offset[i];
		
		IS_DYNAMIC(iinfo.int_nmemb[i]);
		IS_DYNAMIC(iinfo.int_type[i]);

		for(e=0; e < iinfo.int_nmemb[i]; e++) {

			print_func("ints_printf: offset %d, nmemb %d, ", 
					iinfo.int_offset[i], e);
			
			if(iinfo.int_type[i] & INT_TYPE_32BIT) {
				i32  = (int *)(p + (sizeof(int) * e));
				print_func("32bit value %d\n", *i32);
			} else {
				i16  = (short *)(p + (sizeof(short) * e));
				print_func("16bit value %d\n", *i16);
			}
		}
	}
}
