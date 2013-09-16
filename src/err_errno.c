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

#include "err_errno.h"

static const char *err_strings[] = {
	"UFO error -o-",			/* ERR_UFOERR */
	"Malformed Label Octet.",		/* ERR_DNSMLO */
	"Malformed Sequence Label.",		/* ERR_DNSMSL */
	"Malformed Dns Packet.",		/* ERR_DNSMDP */
	"Malformed Dns Data.",			/* ERR_DNSMDD */
	"Too many Recursive Pointers.",		/* ERR_DNSTRP */
	"Dns Packet Len Break.",		/* ERR_DNSPLB */
	"Pointer To Pointer error.",		/* ERR_DNSPTP */
	"Malformed Data.",			/* ERR_DNSMDA */
	"Error Packing Dns Struct.",		/* ERR_DNSPDS */
/**/	
	"Malformed Andna Packet.",		/* ERR_ANDMAP */
	"Andns Packet Len Break.",		/* ERR_ANDPLB */
	"Malformed Andns Data.",		/* ERR_ANDMAD */
	"Andna Not Compatbile Query.", 		/* ERR_ANDNCQ */
/**/
	"Error reading resolv.conf.",		/* ERR_RSLERC */
	"Andns init error.",			/* ERR_RSLAIE */
	"There isn't No NameServer.",		/* ERR_RSLNNS */
	"Error Forwarding DNS Query.",		/* ERR_RSLFDQ */
	"Resolution Error.",			/* ERR_RSLRSL */
	"Andns Query Discarded.", 		/* ERR_RSLAQD */
/**/
	"mark_init error!.",			/* ERR_NETINI */
	"netfilter table not loadable.",	/* ERR_NETFIL */
	"error adding netfilter rules.",	/* ERR_NETRUL */
	"error committing netfilter rules.",	/* ERR_NETCOM */
	"error initializing ntk_mark_chain.",	/* ERR_NETCHA */
	"netfilter delete error.",		/* ERR_NETDEL */
	"error storing rules.",			/* ERR_NETSTO */
	"Nefilter was not restored.",		/* ERR_NETRST */
/**/	
	"SNSD main record not found.",		/* ERR_SNDMRF */
	"SNSD recursion failed.",		/* ERR_SNDRCS */
/**/	
	"Zlib Compression Fail.",		/* ERR_ZLIBCP */
	"Zlib Uncompression Fail.",		/* ERR_ZLIBUP */
	"Zlib compression is useless.",		/* ERR_ZLIBNU */
};

const char *__err_strerror(int n)
{
        int __n=-((n)+1);

	return (__n>=ERR_NERR || __n<0) ? ERR_OVERFLOW : err_strings[__n];
}
