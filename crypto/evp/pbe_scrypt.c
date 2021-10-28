/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

#ifndef OPENSSL_NO_SCRYPT

/*
 * Maximum permitted memory allow this to be overridden with Configuration
 * option: e.g. -DSCRYPT_MAX_MEM=0 for maximum possible.
 */

#ifdef SCRYPT_MAX_MEM
# if SCRYPT_MAX_MEM == 0
#  undef SCRYPT_MAX_MEM
/*
 * Although we could theoretically allocate SIZE_MAX memory that would leave
 * no memory available for anything else so set limit as half that.
 */
#  define SCRYPT_MAX_MEM (SIZE_MAX/2)
# endif
#else
/* Default memory limit: 32 MB */
# define SCRYPT_MAX_MEM  (1024 * 1024 * 32)
#endif

int EVP_PBE_scrypt(const char *pass, size_t passlen,
                   const unsigned char *salt, size_t saltlen,
                   uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
                   unsigned char *key, size_t keylen)
{
    const char *empty = "";
    int rv = 1;
    EVP_KDF_CTX *kctx;

    if (r > UINT32_MAX || p > UINT32_MAX) {
        EVPerr(EVP_F_EVP_PBE_SCRYPT, EVP_R_PARAMETER_TOO_LARGE);
        return 0;
    }

    /* Maintain existing behaviour. */
    if (pass == NULL) {
        pass = empty;
        passlen = 0;
    }
    if (salt == NULL) {
        salt = (const unsigned char *)empty;
        saltlen = 0;
    }
    if (maxmem == 0)
        maxmem = SCRYPT_MAX_MEM;

    kctx = EVP_KDF_CTX_new_id(EVP_KDF_SCRYPT);
    if (kctx == NULL)
        return 0;

    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_PASS, pass, (size_t)passlen) != 1
            || EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT,
                            salt, (size_t)saltlen) != 1
            || EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_N, N) != 1
            || EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_R, (uint32_t)r) != 1
            || EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_P, (uint32_t)p) != 1
            || EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MAXMEM_BYTES, maxmem) != 1
            || EVP_KDF_derive(kctx, key, keylen) != 1)
        rv = 0;

    EVP_KDF_CTX_free(kctx);
    return rv;
}

#endif
