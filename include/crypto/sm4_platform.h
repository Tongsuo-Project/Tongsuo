/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_SM4_PLATFORM_H
# define OSSL_SM4_PLATFORM_H
# pragma once

# include <openssl/opensslconf.h>

# if defined(OPENSSL_CPUID_OBJ)
#  if (defined(__arm__) || defined(__arm) || defined(__aarch64__))
#   include "arm_arch.h"
#   if __ARM_MAX_ARCH__>=8
#    define HWSM4_CAPABLE (OPENSSL_armcap_P & ARMV8_SM4)
#    ifdef HWSM4_set_encrypt_key
#     undef HWSM4_set_encrypt_key
#    endif
#    define HWSM4_set_encrypt_key sm4_v8_set_encrypt_key
#    ifdef HWSM4_set_decrypt_key
#     undef HWSM4_set_decrypt_key
#    endif
#    define HWSM4_set_decrypt_key sm4_v8_set_decrypt_key
#    ifdef HWSM4_encrypt
#     undef HWSM4_encrypt
#    endif
#    define HWSM4_encrypt sm4_v8_encrypt
#    ifdef HWSM4_decrypt
#     undef HWSM4_decrypt
#    endif
#    define HWSM4_decrypt sm4_v8_decrypt
#    ifdef HWSM4_cbc_encrypt
#     undef HWSM4_cbc_encrypt
#    endif
#    define HWSM4_cbc_encrypt sm4_v8_cbc_encrypt
#    ifdef HWSM4_ecb_encrypt
#     undef HWSM4_ecb_encrypt
#    endif
#    define HWSM4_ecb_encrypt sm4_v8_ecb_encrypt
#    ifdef HWSM4_ctr32_encrypt_blocks
#     undef HWSM4_ctr32_encrypt_blocks
#    endif
#    define HWSM4_ctr32_encrypt_blocks sm4_v8_ctr32_encrypt_blocks
#   endif
#  endif
# endif /* OPENSSL_CPUID_OBJ */

# if defined(HWSM4_CAPABLE)
int HWSM4_set_encrypt_key(const unsigned char *userKey, SM4_KEY *key);
int HWSM4_set_decrypt_key(const unsigned char *userKey, SM4_KEY *key);
void HWSM4_encrypt(const unsigned char *in, unsigned char *out,
                   const SM4_KEY *key);
void HWSM4_decrypt(const unsigned char *in, unsigned char *out,
                   const SM4_KEY *key);
void HWSM4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const SM4_KEY *key,
                       unsigned char *ivec, const int enc);
void HWSM4_ecb_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const SM4_KEY *key,
                       const int enc);
void HWSM4_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
                                size_t len, const void *key,
                                const unsigned char ivec[16]);
# endif /* HWSM4_CAPABLE */

#endif /* OSSL_SM4_PLATFORM_H */
