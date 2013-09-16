                 /**************************************
                *     AUTHOR: Federico Tomassini        *
               *     Copyright (C) Federico Tomassini    *
              *     Contact effetom@gmail.com             *
             ***********************************************
               *****                                ******
*************************************************************************
*                                                                       *
*  This program is free software; you can redistribute it and/or modify *
*  it under the terms of the GNU General Public License as published by *
*  the Free Software Foundation; either version 2 of the License, or    *
*  (at your option) any later version.                                  *
*                                                                       *
*  This program is distributed in the hope that it will be useful,      *
*  but WITHOUT ANY WARRANTY; without even the implied warranty of       *
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
*  GNU General Public License for more details.                         *
*                                                                       *
************************************************************************/


#ifndef ERR_ERRNO_H
#define ERR_ERRNO_H

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define ERR_UFOERR	-1
#define ERR_DNSMLO	-2
#define ERR_DNSMSL	-3
#define	ERR_DNSMDP	-4
#define ERR_DNSMDD	-5
#define ERR_DNSTRP	-6
#define ERR_DNSPLB	-7
#define ERR_DNSPTP	-8
#define ERR_DNSMDA	-9
#define ERR_DNSPDS	-10

#define ERR_ANDMAP	-11
#define ERR_ANDPLB	-12
#define ERR_ANDMAD	-13
#define ERR_ANDNCQ	-14

#define ERR_RSLERC	-15
#define ERR_RSLAIE	-16
#define ERR_RSLNNS	-17
#define ERR_RSLFDQ	-18
#define ERR_RSLRSL	-19
#define ERR_RSLAQD	-20

#define ERR_MRKINI	-21
#define ERR_NETFIL	-22
#define ERR_NETRUL	-23
#define ERR_NETCOM	-24
#define ERR_NETCHA	-25
#define ERR_NETDEL	-26
#define ERR_NETSTO	-27
#define ERR_NETRST	-28

#define ERR_SNDMRF	-29
#define ERR_SNDRCS	-30

#define ERR_ZLIBCP	-31
#define ERR_ZLIBUP	-32
#define ERR_ZLIBNU	-33

#define ERR_TOTAL_ERRS	(-(ERR_ZLIBNU))
#define ERR_OVERFLOW    "Error number does not exist."

        /* END OF DEFS */


 /*
  * Core
  */
const char *err_func,*err_file;
#define ERR_NERR                (ERR_TOTAL_ERRS)
#define err_seterrno(n)         errno=(n);err_func=__func__;	\
                                err_file=__FILE__
#define err_ret(n,ret)		{err_seterrno(n);return ret;}
#define err_intret(n)           {err_seterrno(n);return -1;}
#define err_voidret(n)          {err_seterrno(n);return NULL;}
#define err_strerror(e)                                         \
        ((e)>=0)?                                               \
                strerror(e):                                    \
                __err_strerror(e)
#define ERR_FORMAT      "In %s(): %s() returns -> %s"
#define err_str         ERR_FORMAT,__func__,                    \
                        err_func,__err_strerror(errno)


const char *__err_strerror(int n);

#endif /* ERR_ERRNO_H */
