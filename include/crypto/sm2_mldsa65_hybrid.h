/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_CRYPTO_SM2sig_MLDSA65_HYBRID_H
# define OSSL_CRYPTO_SM2sig_MLDSA65_HYBRID_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "crypto/ml_dsa.h"

#define SM2_MLDSA65_HYBRID_QNAME "ML-DSA-65"
#define SM2_MLDSA65_HYBRID_TNAME "SM2"
#define SM2_MLDSA65_HYBRID_QID EVP_PKEY_ML_DSA_65
#define SM2_MLDSA65_HYBRID_TID EVP_PKEY_SM2

#define SM2_PK_SIZE 33
#define SM2_SK_SIZE 32
#define SM2_SIG_SIZE 72

#define MLDSA_PK_SIZE ML_DSA_PUBLICKEYBYTES
#define MLDSA_SK_SIZE ML_DSA_SEEDBYTES
#define MLDSA_SIG_SIZE ML_DSA_SIGBYTES

#define SM2_MLDSA65_HYBRID_RANDOM_BYTES 32
#define SM2_MLDSA65_HYBRID_PREFIX_SIZE 32
#define SM2_MLDSA65_HYBRID_DOMAIN_SIZE 13
#define SM2_MLDSA65_HYBRID_MAX_CONTEXT_STRING_BYTES 255

#define SM2_MLDSA65_HYBRID_PK_SIZE (SM2_PK_SIZE + MLDSA_PK_SIZE)
#define SM2_MLDSA65_HYBRID_SK_SIZE (SM2_SK_SIZE + MLDSA_SK_SIZE)
#define SM2_MLDSA65_HYBRID_SIG_SIZE (SM2_MLDSA65_HYBRID_RANDOM_BYTES + \
                                        SM2_SIG_SIZE + MLDSA_SIG_SIZE)

typedef struct {
    OSSL_LIB_CTX * libctx;
    char *propq;

    EVP_PKEY *sm2_key;
    EVP_PKEY *mldsa_key;
    int status;
} SM2_MLDSA65_HYBRID_KEY;

int sm2_mldsa65_hybrid_key_serialize(SM2_MLDSA65_HYBRID_KEY *pkey,
                                    uint8_t *pk, size_t pksize, size_t *pklen,
                                    uint8_t *sk, size_t sksize, size_t *sklen);

int sm2_mldsa65_hybrid_pub_key_deserialize(SM2_MLDSA65_HYBRID_KEY *key,
                                    const uint8_t *pk, size_t pklen);

int sm2_mldsa65_hybrid_priv_key_deserialize(SM2_MLDSA65_HYBRID_KEY *key,
                                    const uint8_t *sk, size_t sklen);

void *sm2_mldsa65_hybrid_key_new(OSSL_LIB_CTX *libctx, const char *propq);

void sm2_mldsa65_hybrid_key_free(SM2_MLDSA65_HYBRID_KEY *key);

#define SM2_MLDSA65_HYBRID_HAVE_NOKEYS 0
#define SM2_MLDSA65_HYBRID_HAVE_PUBKEY 1
#define SM2_MLDSA65_HYBRID_HAVE_PRVKEY 2

#define sm2_mldsa65_hybrid_have_pubkey(key) ((key)->status > 0)
#define sm2_mldsa65_hybrid_have_prvkey(key) ((key)->status > 1)

#ifndef OPENSSL_NO_SM2_MLDSA65_HYBRID
 /*-
  * The DER ASN.1 encoding of sm2-mldsa65-hybrid public keys prepends 24 bytes
  * to the encoded public key:
  *
  * - 4 byte outer sequence tag and length
  * -  2 byte algorithm sequence tag and length
  * -    2 byte algorithm OID tag and length
  * -      11 byte algorithm OID (testing)
  * -  4 byte bit string tag and length
  * -    1 bitstring lead byte
  */
#define SM2_MLDSA_HYBRID_SPKI_OVERHEAD   24

__owur
SM2_MLDSA65_HYBRID_KEY *ossl_sm2_mldsa65_hybrid_d2i_PUBKEY(const uint8_t *pk, int pk_len, OSSL_LIB_CTX *libctx);
__owur
SM2_MLDSA65_HYBRID_KEY *ossl_sm2_mldsa65_hybrid_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf,
                             OSSL_LIB_CTX *libctx, const char *propq);
#endif /* OPENSSL_NO_SM2_MLDSA65_HYBRID */

#endif
