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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#ifdef DEBUG
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#endif

#include "log.h"

char *__argv0;
int dbg_lvl;
int log_to_stderr;
static int log_facility=LOG_DAEMON;
int log_file_opened=0;
FILE *log_file, *log_fd;

void log_init(char *prog, int dbg, int log_stderr)
{
	__argv0=prog;
	dbg_lvl=dbg;
	log_to_stderr=log_stderr;
	if(log_stderr)
		log_fd=stderr;
	if(!log_file_opened)
		log_file=0;

	if(!log_to_stderr)
		openlog(__argv0, dbg ? LOG_PID : 0, log_facility);
}

/*
 * log_to_file
 *
 * If `filename' is not null, it is opened and set as the logfile.
 * When `filename' is null, it just updates the `log_fd' global variable.
 * 
 * On errors it returns -1;
 */
int log_to_file(char *filename)
{
	if(!filename) {
		if(log_file)
			log_fd=log_file;
		else
			return -1;
		return 0;
	}

	if(!(log_file=fopen(filename, "w"))) {
		log_fd=stderr;
		error("Cannot open the \"%s\" logfile: %s", 
				filename, strerror(errno));
		return -1;
	}

	log_fd=log_file;
	log_file_opened=1;

	return 0;
}

void close_log_file(void)
{
	if(log_file) {
		fflush(log_file);
		fclose(log_file);
	}
}

/* Life is fatal! */
void fatal(const char *fmt,...)
{
	char str[strlen(fmt)+3];
	va_list args;

	if(fmt) {
		str[0]='!';
		str[1]=' ';
		strncpy(str+2, fmt, strlen(fmt));
		str[strlen(fmt)+2]=0;

		va_start(args, fmt);
		print_log(LOG_CRIT, str, args);
		va_end(args);
	}

	/** Flush the stream if we want to read something */
	if(log_to_stderr || log_file)
		fflush(log_fd);
	if(log_file)
		close_log_file();
	/**/

#ifdef DEBUG
	/* Useful to catch the error in gdb */
	kill(getpid(), SIGSEGV);
#endif
	exit(1);
}

/* Misc errors */
void error(const char *fmt,...)
{
	char str[strlen(fmt)+3];
	va_list args;

	str[0]='*';
	str[1]=' ';
	strncpy(str+2, fmt, strlen(fmt));
	str[strlen(fmt)+2]=0;
	
	va_start(args, fmt);
	print_log(LOG_ERR, str, args);
	va_end(args);
}

/* Let's give some news */
void loginfo(const char *fmt,...)
{
	char str[strlen(fmt)+3];
	va_list args;

	str[0]='+';
	str[1]=' ';
	strncpy(str+2, fmt, strlen(fmt));
	str[strlen(fmt)+2]=0;
	
	va_start(args, fmt);
	print_log(LOG_INFO, str, args);
	va_end(args);
}

/* "Debugging is twice as hard as writing the code in the first place.
 * Therefore, if you write the code as cleverly as possible, you are,
 * by definition, not smart enough to debug it." - Brian W. Kernighan
 * Damn!
 */

void debug(int lvl, const char *fmt,...)
{
	char str[strlen(fmt)+3];
	va_list args;

	if(lvl <= dbg_lvl) {
		str[0]='#';
		str[1]=' ';
		strncpy(str+2, fmt, strlen(fmt));
		str[strlen(fmt)+2]=0;

		va_start(args, fmt);
		print_log(LOG_DEBUG, str, args);
		va_end(args);
	}
}

void print_log(int level, const char *fmt, va_list args)
{
	if(log_to_stderr || log_file) {
		vfprintf(log_fd, fmt, args);
		fprintf(log_fd, "\n");
	} else
		vsyslog(level | log_facility, fmt, args);
}
