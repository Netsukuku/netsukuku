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
 * 128bit-gmp.c: Damn! The ipv6 numbers are really BIG ^_.
 */

#include "includes.h"

#include "ipv6-gmp.h"

/*y=x+y*/
int sum_128(unsigned int *x, unsigned int *y)
{
	mpz_t xx, yy, res;
	size_t count;
	
	mpz_init(res);
	mpz_init(xx);
	mpz_init(yy);
	mpz_import (xx, 4, HOST_ORDER, sizeof(x[0]), NATIVE_ENDIAN, 0, x);
	mpz_import (yy, 4, HOST_ORDER, sizeof(y[0]), NATIVE_ENDIAN, 0, y);

	mpz_add(res, xx, yy);
	memset(y, '\0', sizeof(y[0])*4);
	mpz_export(y, &count, HOST_ORDER, sizeof(x[0]), NATIVE_ENDIAN, 0, res);
	
	mpz_clear(xx);
	mpz_clear(yy);
	mpz_clear(res);
	return 0;	
}

/*y=x+y*/
int sum_int(unsigned int x, unsigned int *y)
{
	unsigned int z[4]=ZERO128;
	
	z[3]=x;
	return sum_128(z, y);
}

/*y=x-y*/
int sub_128(unsigned int *x, unsigned int *y)
{
	mpz_t xx, yy, res;
	size_t count;
	
	mpz_init(res);
	mpz_init(xx);
	mpz_init(yy);
	mpz_import(xx, 4, HOST_ORDER, sizeof(x[0]), NATIVE_ENDIAN, 0, x);
	mpz_import(yy, 4, HOST_ORDER, sizeof(y[0]), NATIVE_ENDIAN, 0, y);

	mpz_sub(res, xx, yy);
	memset(y, '\0', sizeof(y[0])*4);
	mpz_export(y, &count, HOST_ORDER, sizeof(x[0]), NATIVE_ENDIAN, 0, res);
	
	mpz_clear(xx);
	mpz_clear(yy);
	mpz_clear(res);
	return 0;	
}

/* y=y-x */
int sub_int(unsigned int *y, unsigned int x)
{
	unsigned int z[4]=ZERO128;

	z[3]=x;
	return sub_128(z, y);
}

/*y=x/y*/
int div_128(unsigned int *x, unsigned int *y)
{
	mpz_t xx, yy, res;
	size_t count;
	
	mpz_init(res);
	mpz_init(xx);
	mpz_init(yy);
	mpz_import(xx, 4, HOST_ORDER, sizeof(x[0]), NATIVE_ENDIAN, 0, x);
	mpz_import(yy, 4, HOST_ORDER, sizeof(y[0]), NATIVE_ENDIAN, 0, y);
	
	mpz_tdiv_q(res, xx, yy);
	memset(y, '\0', sizeof(y[0])*4);
	mpz_export(y, &count, HOST_ORDER, sizeof(x[0]), NATIVE_ENDIAN, 0, res);
	
	mpz_clear(xx);
	mpz_clear(yy);
	mpz_clear(res);
	return 0;	
}

/* y=y/x */
int div_int(unsigned int *y, unsigned int x)
{
	unsigned int z[4]=ZERO128;

	z[3]=x;
	return div_128(z, y);
}

/* y=y/x */
int div_mpz(unsigned int *y, mpz_t x)
{
	mpz_t yy, res;
	size_t count;

	mpz_init(res);
	mpz_init(yy);
	mpz_import(yy, 4, HOST_ORDER, sizeof(y[0]), NATIVE_ENDIAN, 0, y);
	
	mpz_tdiv_q(res, yy, x);
	memset(y, '\0', sizeof(y[0])*4);
	mpz_export(y, &count, HOST_ORDER, sizeof(x[0]), NATIVE_ENDIAN, 0, res);
	
	mpz_clear(yy);
	mpz_clear(res);
	return 0;	
}

/* "ORDER can be 1 for most significant word first or -1 for least significant first." */
int htonl_128(unsigned int *x, unsigned int *y)
{
	mpz_t xx;
	size_t count;
	
	mpz_init(xx);
	mpz_import(xx, 4,     HOST_ORDER, sizeof(x[0]), NATIVE_ENDIAN,  0, x);
	memset(y, '\0', sizeof(y[0])*4);
	mpz_export(y, &count, NETWORK_ORDER, sizeof(x[0]), NETWORK_ENDIAN, 0, xx);
	mpz_clear(xx);
	return 0;
}

int ntohl_128(unsigned int *x, unsigned int *y)
{
	mpz_t xx;
	size_t count;
	
	mpz_init(xx);
	mpz_import(xx, 4,     NETWORK_ORDER, sizeof(x[0]), NETWORK_ENDIAN, 0, x);
	memset(y, '\0', sizeof(y[0])*4);
	mpz_export(y, &count, HOST_ORDER, sizeof(x[0]), NATIVE_ENDIAN,  0, xx);	
	mpz_clear(xx);

	return 0;
}
