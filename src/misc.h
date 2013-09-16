/* This file is part of Netsukuku
 * (c) Copyright 2004 Andrea Lo Pumo aka AlpT <alpt@freaknet.org>
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

#ifndef MISC_H
#define MISC_H

/*
 * NMEMB: returns the number of members of the `x' array
 */
#define NMEMB(x)        	(sizeof((x))/sizeof(typeof((x)[0])))

/* 
 * MILLISEC: converts a timeval struct to a int. The time will be returned in
 * milliseconds.
 */
#define MILLISEC(x)		(((x).tv_sec*1000)+((x).tv_usec/1000))

/*
 * MILLISEC_TO_TV: Converts `x', which is an int into `t', a timeval struct
 */
#define MILLISEC_TO_TV(x,t) 						\
do{									\
	(t).tv_sec=(x)/1000; 						\
	(t).tv_usec=((x) - ((x)/1000)*1000)*1000; 			\
}while(0)

/* 
 * Bit map related macros.  
 */
#define SET_BIT(a,i)     ((a)[(i)/CHAR_BIT] |= 1<<((i)%CHAR_BIT))
#define CLR_BIT(a,i)     ((a)[(i)/CHAR_BIT] &= ~(1<<((i)%CHAR_BIT)))
#define TEST_BIT(a,i)    (((a)[(i)/CHAR_BIT] & (1<<((i)%CHAR_BIT))) ? 1 : 0)

/*
 * FIND_PTR
 *
 * Given an array of pointers `a' of `n' members, it searches for a member
 * equal to the pointer `p'. If it is found its position is returned,
 * otherwise -1 is the value returned.
 */
#define FIND_PTR(p, a, n)						\
({									\
 	int _i, _ret;							\
									\
	for(_i=0, _ret=-1; _i<(n); _i++)				\
		if((a)[_i] == (p)) {					\
			_ret=_i;					\
			break;						\
		}							\
	_ret;								\
})

/*
 * _return
 *
 * It is used in this case:
 * 	condition && _return (ret);
 * Since it is not possible to use the standard return in that case, we trick
 * gcc.
 */
#define _return(x)	({return (x); (x);})


/*\
 *   * *  Functions declaration  * *
\*/
char xor_int(int i);

void swap_array(int nmemb, size_t nmemb_sz, void *src, void *dst);
void swap_ints(int nmemb, unsigned int *x, unsigned int *y) ;
void swap_shorts(int nmemb, unsigned short *x, unsigned short *y);

inline int rand_range(int _min, int _max);
void xsrand(void);

char *last_token(char *string, char tok);
void strip_char(char *string, char char_to_strip);
char **split_string(char *str, const char *div_str, int *substrings,
		int max_substrings, int max_substring_sz);

		
int find_int(int x, int *ia, int nmemb);

void xtimer(u_int secs, u_int steps, int *counter);

int check_and_create_dir(char *dir);
int file_exist(char *filename);
int exec_root_script(char *script, char *argv);

void do_nothing(void);

#endif /*MISC_H*/
