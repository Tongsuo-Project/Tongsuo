/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_CRYPTO_SM2DH_MLKEM768_H
# define OSSL_CRYPTO_SM2DH_MLKEM768_H
# pragma once

# include <openssl/opensslconf.h>

# if !defined(OPENSSL_NO_SM2) && !defined(FIPS_MODULE)

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/kyber.h"
#include "crypto/types.h"

#define SM2_DH_SK_SIZE    32
#define SM2_DH_SS_SIZE    32
#define SM2_DH_PK_SIZE    65

#define MLKEM_768_SS_SIZE 32
#define MLKEM_768_PK_SIZE pqcrystals_kyber768_PUBLICKEYBYTES
#define MLKEM_768_SK_SIZE pqcrystals_kyber768_SECRETKEYBYTES
#define MLKEM_768_CT_SIZE pqcrystals_kyber768_CIPHERTEXTBYTES

#define SM2_DH_MLKEM_768_HYBRID_SS_SIZE (SM2_DH_SS_SIZE + MLKEM_768_SS_SIZE)
#define SM2_DH_MLKEM_768_HYBRID_CT_SIZE (SM2_DH_PK_SIZE + MLKEM_768_CT_SIZE)
#define SM2_DH_MLKEM_768_HYBRID_SK_SIZE (SM2_DH_SK_SIZE + MLKEM_768_SK_SIZE)
#define SM2_DH_MLKEM_768_HYBRID_PK_SIZE (SM2_DH_PK_SIZE + MLKEM_768_PK_SIZE)

typedef struct sm2_dh_mlkem768_hybrid_key {
    int has_kem_sk;
    uint8_t * pk;
    uint8_t * sk;
    uint8_t * ct;
    uint8_t * ss;
    OSSL_LIB_CTX * libctx;
} sm2dh_mlkem768_hybrid_key;


sm2dh_mlkem768_hybrid_key * sm2dh_mlkem768_hybrid_key_new(void);
void sm2dh_mlkem768_hybrid_key_free(sm2dh_mlkem768_hybrid_key * key);

int sm2dh_mlkem768_hybrid_keygen(OSSL_LIB_CTX * libctx, uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len);

int sm2dh_mlkem768_hybrid_encaps(OSSL_LIB_CTX * libctx, uint8_t *ss, size_t ss_len, uint8_t *ct, size_t ct_len,  const uint8_t *pk, size_t pk_len);

int sm2dh_mlkem768_hybrid_decaps(OSSL_LIB_CTX * libctx, uint8_t *ss, size_t ss_len, const uint8_t *ct, size_t ct_len, const uint8_t *sk, size_t sk_len);

# endif

#endif
