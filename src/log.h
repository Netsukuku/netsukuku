/* This file is part of Netsukuku system
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

#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

/*
 * Use ERROR_MSG and ERROR_POS in this way:
 * 	printf(ERROR_MSG "damn! damn! damn!", ERROR_POS);
 * 	printf(ERROR_MSG "damn! damn! damn!", ERROR_FUNC);
 */
#define ERROR_MSG  "%s:%d: "
#define ERROR_POS  __FILE__, __LINE__
#define ERROR_FUNC __FUNCTION__, __LINE__

/*Debug levels*/
#define DBG_NORMAL	1
#define DBG_SOFT	2
#define DBG_NOISE 	3
#define DBG_INSANE 	4

/* 
 * ERROR_FINISH:
 * A kind way to say all was messed up, take this example:
 *
 * int func(void) // returns -1 on errors
 * { 
 * 	int ret=0;
 *
 * 	,,,BLA BLA...
 * 	
 *	if(error_condition)
 *		ERROR_FINISH(ret, -1, finish);
 *
 *	error_condition &&
 *		ERROR_FINISH(ret, -1, finish);
 *
 * 	,,,BLA BLA...
 * 	
 *	finish:
 *		return ret;
 * }
 */
#define ERROR_FINISH(ret, err, label_finish)				\
({									\
	void *_label_finish=&&label_finish;				\
	(ret)=(err); 							\
	goto *_label_finish;						\
									\
 	(ret); /* in this way gcc thinks this macro returns
		  an integer */						\
})

#ifdef DEBUG
/* Colors used to highlights things while debugging ;) */
#define DEFCOL		"\033[0m"
#define BLACK(x)	"\033[0;30m" x DEFCOL
#define RED(x)		"\033[0;31m" x DEFCOL
#define GREEN(x)	"\033[0;32m" x DEFCOL
#define BROWN(x)	"\033[0;33m" x DEFCOL
#define BLUE(x)		"\033[0;34m" x DEFCOL
#define PURPLE(x)	"\033[0;35m" x DEFCOL
#define CYAN(x)		"\033[0;36m" x DEFCOL
#define LIGHTGRAY(x)	"\033[0;37m" x DEFCOL
#define DARKGRAY(x)	"\033[1;30m" x DEFCOL
#define LIGHTRED(x)	"\033[1;31m" x DEFCOL
#define LIGHTGREEN(x)	"\033[1;32m" x DEFCOL
#define YELLOW(x)	"\033[1;33m" x DEFCOL
#define LIGHTBLUE(x)	"\033[1;34m" x DEFCOL
#define MAGENTA(x)	"\033[1;35m" x DEFCOL
#define LIGHTCYAN(x)	"\033[1;36m" x DEFCOL
#define WHITE(x)	"\033[1;37m" x DEFCOL
#else
#define BLACK(x)	x
#define RED(x)		x
#define GREEN(x)	x
#define BROWN(x)	x
#define BLUE(x)		x
#define PURPLE(x)	x
#define CYAN(x)		x
#define LIGHTGRAY(x)	x
#define DARKGRAY(x)	x
#define LIGHTRED(x)	x
#define LIGHTGREEN(x)	x
#define YELLOW(x)	x
#define LIGHTBLUE(x)	x
#define MAGENTA(x)	x
#define LIGHTCYAN(x)	x
#define WHITE(x)	x
#endif

/* functions declaration */
void log_init(char *, int, int );
int log_to_file(char *filename);
void close_log_file(void);

void fatal(const char *, ...) __attribute__ ((noreturn));
void error(const char *, ...);
void loginfo(const char *, ...);
void debug(int lvl, const char *, ...);

void print_log(int level, const char *fmt, va_list args);

#endif /*LOG_H*/
