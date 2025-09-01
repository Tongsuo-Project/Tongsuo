/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_CRYPTO_ML_DSA_H
#define OSSL_CRYPTO_ML_DSA_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

#ifndef OPENSSL_NO_ML_DSA

/*
 common parameters for ML-DSA-44、65、87
 */
#define ML_DSA_SEEDBYTES 32
#define ML_DSA_CRHBYTES 64
#define ML_DSA_TRBYTES 64
#define ML_DSA_RNDBYTES 32
#define ML_DSA_N 256
#define ML_DSA_Q 8380417
#define ML_DSA_D 13
#define ML_DSA_ROOT_OF_UNITY 1753
#define ML_DSA_CONTEXT_STRING_BYTES 255

#ifndef ML_DSA_MODE
#define ML_DSA_MODE 65
#endif

#if ML_DSA_MODE == 44
#define CRYPTO_ALGNAME "ML-DSA-44"
#define ML_DSA_NAMESPACETOP pqcrystals_ml_dsa_44
#define ML_DSA_NAMESPACE(s) pqcrystals_ml_dsa_44_##s
#define ML_DSA_PUBLICKEYBYTES 1312
#define ML_DSA_SECRETKEYBYTES 2560
#define ML_DSA_SIGBYTES 2420
#elif ML_DSA_MODE == 65
#define CRYPTO_ALGNAME "ML-DSA-65"
#define ML_DSA_NAMESPACETOP pqcrystals_ml_dsa_65
#define ML_DSA_NAMESPACE(s) pqcrystals_ml_dsa_65_##s
#define ML_DSA_PUBLICKEYBYTES 1952
#define ML_DSA_SECRETKEYBYTES 4032
#define ML_DSA_SIGBYTES 3309
#elif ML_DSA_MODE == 87
#define CRYPTO_ALGNAME "ML-DSA-87"
#define ML_DSA_NAMESPACETOP pqcrystals_ml_dsa_87
#define ML_DSA_NAMESPACE(s) pqcrystals_ml_dsa_87_##s
#define ML_DSA_PUBLICKEYBYTES 2592
#define ML_DSA_SECRETKEYBYTES 4896
#define ML_DSA_SIGBYTES 4627
#else
#error "ML_DSA_MODE must be in {44,65,87}"
#endif

#define crypto_sign_keypair ML_DSA_NAMESPACE(keypair)
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk, uint8_t *seed, int rand_seed);

#define crypto_sign_signature_internal ML_DSA_NAMESPACE(signature_internal)
int crypto_sign_signature_internal(uint8_t *sig,
                                   size_t *siglen,
                                   const uint8_t *mu,
                                   const uint8_t rnd[ML_DSA_RNDBYTES],
                                   const uint8_t *sk);

#define crypto_sign_signature ML_DSA_NAMESPACE(signature)
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *ctx, size_t ctxlen,
                          const int deterministic,
                          const uint8_t *sk);

#define crypto_sign ML_DSA_NAMESPACETOP
int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sk);

#define crypto_sign_verify_internal ML_DSA_NAMESPACE(verify_internal)
int crypto_sign_verify_internal(const uint8_t *sig,
                                size_t siglen,
                                const uint8_t *mu,
                                const uint8_t *pk);

#define crypto_sign_verify ML_DSA_NAMESPACE(verify)
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *pk);

#define crypto_sign_open ML_DSA_NAMESPACE(open)
int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *ctx, size_t ctxlen,
                     const uint8_t *pk);

#define ML_DSA_SK_FORMAT_MAX_BYTES 100

typedef struct {
    uint8_t *seed;
    size_t seed_len;
    uint8_t *privkey;
    size_t privkey_len;
    uint8_t *pubkey;
    size_t pubkey_len;

    char sk_fmt[ML_DSA_SK_FORMAT_MAX_BYTES + 1];

    OSSL_LIB_CTX * libctx;
} ML_DSA_KEY;

ML_DSA_KEY *pqcrystals_ml_dsa_key_new(OSSL_LIB_CTX *libctx);

void pqcrystals_ml_dsa_key_free(ML_DSA_KEY *key);

int pqcrystals_ml_dsa_pk_import(ML_DSA_KEY *key, const uint8_t *pk, size_t pk_len);

int pqcrystals_ml_dsa_sk_import(ML_DSA_KEY *key, const uint8_t *sk, size_t sk_len);

int pqcrystals_ml_dsa_sk2pk(const uint8_t *sk, size_t sklen, uint8_t *pk, size_t pklen);

EVP_MD_CTX *pqcrystals_ml_dsa_init_mu(const ML_DSA_KEY *key, const EVP_MD *md,
                                            const uint8_t *ctx, size_t ctxlen);

#endif /* OPENSSL_NO_ML_DSA */

#endif
