/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_SM4_H
# define OSSL_CRYPTO_SM4_H

# include <openssl/opensslconf.h>
# include <openssl/e_os2.h>
# include <stdio.h>

# ifdef OPENSSL_NO_SM4
#  error SM4 is disabled.
# endif

# define SM4_ENCRYPT     1
# define SM4_DECRYPT     0

# define SM4_BLOCK_SIZE    16
# define SM4_KEY_SCHEDULE  32

typedef struct SM4_KEY_st {
    uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_KEY;

int SM4_set_key(const uint8_t *key, SM4_KEY *ks);

void SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);

/*
 * Use sm4 affine transformation to aes-ni
 *
 * Here is the thing:
 * For this SM4NI feature, We only check the platform compatibility against
 * compilers. This means only the compilers that support '__has_include' and
 * have 'x86intrin.h' header file, will get SM4NI feature compiled.
 *
 * Probably supported compilers:
 *
 * GCC > 4.5.0
 * Recent clang, including Apple clang
 * Intel icc
 *
 * You can't use MSVC to build this feature since it has no 'x86intrin.h'.
 */
# ifndef OPENSSL_NO_SM4_NI
#  if defined (__has_include) && (__has_include(<x86intrin.h>))
#   include <x86intrin.h>
#   if defined(__SSE__) && defined(__SSE2__) && defined(__SSE3__) && defined(__AES__)
#    define USE_SM4_NI
void SM4_encrypt_affine_ni(const uint8_t *in, uint8_t *out,
                           const SM4_KEY *ks);
#   endif
#  endif
# endif

void SM4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);

void sm4_ctr128_encrypt_blocks (const unsigned char *in, unsigned char *out,size_t blocks, const void *key,
                                const unsigned char ivec[16]);

void sm4_128_block_encrypt (const unsigned char in[16],
                            unsigned char out[16], const void *key);

void sm4_128_block_decrypt (const unsigned char in[16],
                            unsigned char out[16], const void *key);

#endif
