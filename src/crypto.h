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

#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <sys/types.h>

#define RSA_PUB_EXPONENT	65537

void init_crypto(void);
void free_crypto(void);
char *ssl_strerr(void);
RSA *genrsa(int key_bits, u_char **pub, u_int *pub_len, u_char **priv, u_int *priv_len);
RSA *get_rsa_pub(const u_char **pub_key, long length);
RSA *get_rsa_priv(const u_char **priv_key, long length);
u_char *hash_sha1(u_char *msg, u_int len, u_char *hash);
u_char *hash_md5(u_char *msg, u_int m_len, u_char *hash);
u_char *rsa_sign(u_char *msg, u_int m_len, RSA *priv, u_int *siglen);
int verify_sign(u_char *msg, u_int m_len, u_char *signature, u_int siglen, RSA *pub);

#endif /*CRYPTO_H*/
