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
 * misc.c: some useful functions.
 */

#include "includes.h"
#include <dirent.h>
#include <sys/wait.h>

#include "common.h"

/*
 * xor_int
 * 
 * XORs all the bytes of the `i' integer by merging them in a single
 * byte. It returns the merged byte.
 */
char xor_int(int i)
{
        char c;

        c = (i & 0xff) ^ ((i & 0xff00)>>8) ^ ((i & 0xff0000)>>16) ^ ((i & 0xff000000)>>24);

        return c;
}


/*\
 *
 *  * * *  Swap functions  * * * *
 *
\*/


/*
 * swap_array: swaps the elements of the `src' array and stores the result in
 * `dst'. The `src' array has `nmemb'# elements and each of them is `nmemb_sz'
 * big.
 */
void swap_array(int nmemb, size_t nmemb_sz, void *src, void *dst)
{
	int i, total_sz;
	
	total_sz = nmemb*nmemb_sz;
	
	char buf[total_sz], *z;
	
	if(src == dst)
		z=buf;
	else
		z=dst;
	
	for(i=nmemb-1; i>=0; i--)
		memcpy(z+(nmemb_sz*(nmemb-i-1)), (char *)src+(nmemb_sz*i),
				nmemb_sz);
			
	if(src == dst)
		memcpy(dst, buf, total_sz);
}

/*
 * swap_ints: Swap integers.
 * It swaps the `x' array which has `nmemb' elements and stores the result it 
 * in `y'.
 */
void swap_ints(int nmemb, unsigned int *x, unsigned int *y) 
{
	swap_array(nmemb, sizeof(int), x, y);
}

void swap_shorts(int nmemb, unsigned short *x, unsigned short *y)
{
	swap_array(nmemb, sizeof(short), x, y);
}



/*
 * * * *  Random related functions  * * * *
 */

/* 
 * rand_range: It returns a random number x which is _min <= x <= _max
 */ 
inline int rand_range(int _min, int _max)
{
	return (rand()%(_max - _min + 1)) + _min;
}

/* 
 * xsrand
 *
 * It sets the random seed with a pseudo random number 
 */
void xsrand(void)
{
	FILE *fd;
	int seed;

	if((fd=fopen("/dev/urandom", "r"))) {
		fread(&seed, 4,1,fd);
		fclose(fd);
	} else
		seed=getpid() ^ time(0) ^ clock();

	srand(seed); 
}


/*
 * * * *  String functions  * * * *
 */

char *last_token(char *string, char tok)
{
	while(*string == tok)
		string++;
	return string;
}

/*
 * strip_char: Removes any occurrences of the character `char_to_strip' in the
 * string `string'.
 */
void strip_char(char *string, char char_to_strip)
{
	int i; 
	char *p;
	for(i=0; i<strlen(string); i++) {
		if(string[i]==char_to_strip) {
			p=last_token(&string[i], char_to_strip);
			strcpy(&string[i], p);
		}
	}
}



/*
 * * * *  Search functions  * * * *
 */

/*
 * split_string: splits the `str' strings at maximum in `max_substrings'#
 * substrings using as divisor the `div_str' string.
 * Each substring can be at maximum of `max_substring_sz' bytes.
 * The array of malloced substrings is returned and in `substrings' the number
 * of saved substrings is stored.
 * On error 0 is the return value.
 */
char **split_string(char *str, const char *div_str, int *substrings, 
		int max_substrings, int max_substring_sz)
{
	int i=0, strings=0, str_len=0, buf_len;
	char *buf, **splitted=0, *p;

	*substrings=0;
	
	str_len=strlen(str);

	buf=str-1;
	while((buf=strstr((const char *)buf+1, div_str)))
		strings++;
	if(!strings && !str_len)
		return 0;

	strings++;
	if(strings > max_substrings)
		strings=max_substrings;

	splitted=(char **)xmalloc(sizeof(char *)*strings);
	
	buf=str;
	for(i=0; i<strings; i++) {
		p=strstr((const char *)buf, div_str);
		if(p)
			*p=0;

		buf_len=strlen(buf);
		if(buf_len <= max_substring_sz && buf_len > 0)
			splitted[i]=xstrdup(buf);
		else {
			i--;
			strings--;
			buf=p+1;
		}

		if(!p) {
			i++;
			break;
		}
		buf=p+1;
	}
	
	if(i != strings)
		splitted=(char **)xrealloc(splitted, sizeof(char *)*i);

	*substrings=strings;
	return splitted;
}

/*
 * If `x' is present in the `ia' array, which has `nmemb' members, it returns
 * 1, otherwise 0.
 */
int find_int(int x, int *ia, int nmemb)
{
	int e;
	
	for(e=0; e<nmemb; e++)
		if(ia[e] == x)
			return 1;

	return 0;
}


/*
 *  *  *  *  Time functions  *  *  *  *
 */


/*
 * xtimer: It sleeps for `secs' seconds. 
 * `steps' tells to xtimer() how many "for" cycles it must run to sleep for
 * `secs' secons. At each cycle it updates `counter'.
 */
void xtimer(u_int secs, u_int steps, int *counter)
{
	static int i, ms_sleep;
	static int ms_step; /* how many ms it must sleep at every step */
	static int s_step;  /* seconds per step */
	static int mu_step; /* micro seconds per step */

	if(!steps)
		steps++;
	if(counter)
		*counter=0;
	ms_sleep=secs*1000;
	
	if(ms_sleep < secs) {
		/* We are waiting a LONG TIME, it's useless to have steps < of
		 * one second */
		ms_step=1000;
		steps=secs;
	} else {
		ms_step=ms_sleep/steps;
		
		if(!ms_step) {
			ms_step=1;
			steps=ms_sleep;
		}
	}

	s_step=ms_step/1000;
	mu_step=ms_step*1000;
	
	for(i=0; i<steps; i++) {
		if(ms_step >= 1000)
			sleep(s_step);
		else
			usleep(mu_step);
		if(counter)
			(*counter)++;
	}
}


/*
 *  *  *  *  File & Dir related functions  *  *  *  *
 */


/*
 * check_and_create_dir: tries to access in the specified `dir' directory and
 * if doesn't exist tries to create it.
 * On success it returns 0
 */
int check_and_create_dir(char *dir)
{
	DIR *d;
	
	/* Try to open the directory */
	d=opendir(dir);
	
	if(!d) {
		if(errno == ENOENT) {
			/* The directory doesn't exist, try to create it */
			if(mkdir(dir, S_IRUSR|S_IWUSR|S_IXUSR) < 0) {
				error("Cannot create the %d directory: %s", dir,
						strerror(errno));
				return -1;
			}
		} else {
			error("Cannot access to the %s directory: %s", dir, 
					strerror(errno));
			return -1;
		}
	}
	
	closedir(d);
	return 0;
}

/* 
 * file_exist
 *
 * returns 1 if `filename' is a valid existing file.
 */
int file_exist(char *filename)
{
	FILE *fd;

	if(!(fd=fopen(filename, "r")))
		return !(errno == ENOENT);
	fclose(fd);

	return 1;
}

/*
 * exec_root_script: executes `script' with the given `argv', but checks first if the
 * script is:
 * 	- suid
 * 	- it isn't owned by root
 * 	- it isn't writable by others than root
 * If one of this conditions is true, the script won't be executed.
 * On success 0 is returned.
 */
int exec_root_script(char *script, char *argv)
{
	struct stat sh_stat;
	int ret;
	char command[strlen(script)+strlen(argv)+2];
	
	if(stat(script, &sh_stat)) {
		error("Couldn't stat %s: %s", strerror(errno));
		return -1;
	}

	if(sh_stat.st_uid != 0 || sh_stat.st_mode & S_ISUID ||
	    sh_stat.st_mode & S_ISGID || 
	    (sh_stat.st_gid != 0 && sh_stat.st_mode & S_IWGRP) ||
	    sh_stat.st_mode & S_IWOTH) {
		error("Please adjust the permissions of %s and be sure it "
			"hasn't been modified.\n"
			"  Use this command:\n"
			"  chmod 744 %s; chown root:root %s",
			script, script, script);
		return -1;
	}
	
	sprintf(command, "%s %s", script, argv);
	loginfo("Executing \"%s\"", command);
	
	ret=system(command);
	if(ret == -1) {
		error("Couldn't execute %s: %s", script, strerror(errno));
		return -1;
	}
	
	if(!WIFEXITED(ret) || (WIFEXITED(ret) && WEXITSTATUS(ret) != 0)) {
		error("\"%s\" didn't terminate correctly", command);
		return -1;
	}

	return 0;
}
	
	
/* This is the most important function */
void do_nothing(void)
{
	return;
}
