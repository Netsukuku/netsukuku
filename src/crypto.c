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
 * crypto.c:
 * front end to the OpenSSL cryptographic functions
 */

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/md5.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "crypto.h"

#include "log.h"
#include "xmalloc.h"

void init_crypto(void)
{
	RAND_load_file("/dev/urandom", 1024);
	ERR_load_crypto_strings();
}

void free_crypto(void)
{
	ERR_free_strings();
}

char *ssl_strerr(void)
{
	return ERR_error_string(ERR_get_error(), 0);
}

/*
 * genrsa: generates a new rsa key pair and returns the private key in the RSA
 * format. If `pub' is not null, it stores in it the pointer to a newly
 * allocated dump of the public key that is `*pub_len' bytes. The same is for
 * `priv' and `priv_len'.
 * On error null is returned.
 */
RSA *genrsa(int key_bits, u_char **pub, u_int *pub_len, u_char **priv, u_int *priv_len)
{
	RSA *rsa=0;
	int len;
	
	rsa=RSA_generate_key(key_bits, RSA_F4, NULL, NULL);
	if (!rsa) {
		debug(DBG_SOFT, "RSA key generation failed"); 
		goto error;
	}

	if(priv) {
		*priv=0;
		len=i2d_RSAPrivateKey(rsa, priv);
		if(priv_len)
			*priv_len=len;
		if(len <= 0) {
			debug(DBG_SOFT, "Cannot dump RSA public key: %s", ssl_strerr());
			goto error;
		}
	}

	if(pub) {
		*pub=0;
		len=i2d_RSAPublicKey(rsa, pub);
		if(pub_len)
			*pub_len=len;
		if(len <= 0) {
			debug(DBG_SOFT, "Cannot dump RSA public key: %s", ssl_strerr());
			goto error;
		}
	}
	
	return rsa;
error:
	if(rsa)
		RSA_free(rsa);	
	return 0;
}

/*
 * get_rsa_pub
 *
 * Converts a dump of a rsa pub key to a RSA structure, which is returned.
 * Remeber to RSA_free() the returned key.
 */
RSA *get_rsa_pub(const u_char **pub_key, long length)
{
	 return d2i_RSAPublicKey(NULL, pub_key, length);
}

/*
 * get_rsa_priv
 *
 * Converts a dump of a rsa priv key to a RSA structure, which is returned.
 * Remeber to RSA_free() the returned key.
 */
RSA *get_rsa_priv(const u_char **priv_key, long length)
{
	 return d2i_RSAPrivateKey(NULL, priv_key, length);
}

u_char *hash_sha1(u_char *msg, u_int m_len, u_char *hash)
{
	return SHA1(msg, m_len, hash);
}

u_char *hash_md5(u_char *msg, u_int m_len, u_char *hash)
{
	return MD5(msg, m_len, hash);
}

/*
 * rsa_sign: It signs the given message `msg' and returns its newly allocated
 * signature. In `siglen' it stores the signature's lenght.
 * On error null is returned.
 */
u_char *rsa_sign(u_char *msg, u_int m_len, RSA *priv, u_int *siglen)
{
	u_char *signature;
	int ret, len;

	ret=RSA_size(priv);
	if(!ret)
		return 0;

	signature=(u_char *)xmalloc(ret);
	ret=RSA_sign(NID_sha1, hash_sha1(msg, m_len, 0), SHA_DIGEST_LENGTH,
			signature,(u_int*) &len, priv);
	if(siglen)
		*siglen=len;

	return !ret ? 0 : signature;
}

/*
 * verify_sign: verifies the rsa `signature' of `msg'.
 * It returns 1 if the signature is valid, otherwise 0 is returned.
 */
int verify_sign(u_char *msg, u_int m_len, u_char *signature, u_int siglen, RSA *pub)
{
        return RSA_verify(NID_sha1, hash_sha1(msg, m_len, 0), SHA_DIGEST_LENGTH,
			signature, siglen, pub);
}
