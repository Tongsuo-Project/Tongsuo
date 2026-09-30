/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/ml_kem.h"
#include "ml_kem_avx2.h"

#if defined(ML_KEM_AVX2_ASM) && defined(OPENSSL_CPUID_OBJ) \
    && (defined(__x86_64) || defined(__x86_64__) \
        || defined(_M_AMD64) || defined(_M_X64))
# include "internal/cryptlib.h"

# define ML_KEM_AVX2_CAPABLE \
    ((OPENSSL_ia32cap_P[2] & ((1U << 5) | (1U << 8))) \
        == ((1U << 5) | (1U << 8)) \
     && (OPENSSL_ia32cap_P[1] & (1U << 23)) != 0)

int ossl_ml_kem_512_avx2_keypair_derand(uint8_t *pk, uint8_t *sk,
                                        const uint8_t *coins);
int ossl_ml_kem_512_avx2_enc_derand(uint8_t *ct, uint8_t *ss,
                                    const uint8_t *pk, const uint8_t *coins);
int ossl_ml_kem_512_avx2_dec(uint8_t *ss, const uint8_t *ct,
                             const uint8_t *sk);

int ossl_ml_kem_768_avx2_keypair_derand(uint8_t *pk, uint8_t *sk,
                                        const uint8_t *coins);
int ossl_ml_kem_768_avx2_enc_derand(uint8_t *ct, uint8_t *ss,
                                    const uint8_t *pk, const uint8_t *coins);
int ossl_ml_kem_768_avx2_dec(uint8_t *ss, const uint8_t *ct,
                             const uint8_t *sk);

int ossl_ml_kem_1024_avx2_keypair_derand(uint8_t *pk, uint8_t *sk,
                                         const uint8_t *coins);
int ossl_ml_kem_1024_avx2_enc_derand(uint8_t *ct, uint8_t *ss,
                                     const uint8_t *pk, const uint8_t *coins);
int ossl_ml_kem_1024_avx2_dec(uint8_t *ss, const uint8_t *ct,
                              const uint8_t *sk);

typedef int (*ML_KEM_AVX2_KEYPAIR_DERAND_FUNC)(uint8_t *pk, uint8_t *sk,
                                               const uint8_t *coins);
typedef int (*ML_KEM_AVX2_ENCAP_DERAND_FUNC)(uint8_t *ct, uint8_t *ss,
                                             const uint8_t *pk,
                                             const uint8_t *coins);
typedef int (*ML_KEM_AVX2_DECAP_FUNC)(uint8_t *ss, const uint8_t *ct,
                                      const uint8_t *sk);

static int ml_kem_avx2_capable(void)
{
    return ML_KEM_AVX2_CAPABLE;
}

static ML_KEM_AVX2_KEYPAIR_DERAND_FUNC
ml_kem_avx2_keypair_derand_func(const ML_KEM_VINFO *vinfo)
{
    switch (vinfo->evp_type) {
    case EVP_PKEY_ML_KEM_512:
        return ossl_ml_kem_512_avx2_keypair_derand;
    case EVP_PKEY_ML_KEM_768:
        return ossl_ml_kem_768_avx2_keypair_derand;
    case EVP_PKEY_ML_KEM_1024:
        return ossl_ml_kem_1024_avx2_keypair_derand;
    }
    return NULL;
}

static ML_KEM_AVX2_ENCAP_DERAND_FUNC
ml_kem_avx2_encap_derand_func(const ML_KEM_VINFO *vinfo)
{
    switch (vinfo->evp_type) {
    case EVP_PKEY_ML_KEM_512:
        return ossl_ml_kem_512_avx2_enc_derand;
    case EVP_PKEY_ML_KEM_768:
        return ossl_ml_kem_768_avx2_enc_derand;
    case EVP_PKEY_ML_KEM_1024:
        return ossl_ml_kem_1024_avx2_enc_derand;
    }
    return NULL;
}

static ML_KEM_AVX2_DECAP_FUNC
ml_kem_avx2_decap_func(const ML_KEM_VINFO *vinfo)
{
    switch (vinfo->evp_type) {
    case EVP_PKEY_ML_KEM_512:
        return ossl_ml_kem_512_avx2_dec;
    case EVP_PKEY_ML_KEM_768:
        return ossl_ml_kem_768_avx2_dec;
    case EVP_PKEY_ML_KEM_1024:
        return ossl_ml_kem_1024_avx2_dec;
    }
    return NULL;
}

#else

typedef int (*ML_KEM_AVX2_KEYPAIR_DERAND_FUNC)(uint8_t *pk, uint8_t *sk,
                                               const uint8_t *coins);
typedef int (*ML_KEM_AVX2_ENCAP_DERAND_FUNC)(uint8_t *ct, uint8_t *ss,
                                             const uint8_t *pk,
                                             const uint8_t *coins);
typedef int (*ML_KEM_AVX2_DECAP_FUNC)(uint8_t *ss, const uint8_t *ct,
                                      const uint8_t *sk);

static int ml_kem_avx2_capable(void)
{
    return 0;
}

static ML_KEM_AVX2_KEYPAIR_DERAND_FUNC
ml_kem_avx2_keypair_derand_func(const ML_KEM_VINFO *vinfo)
{
    (void)vinfo;
    return NULL;
}

static ML_KEM_AVX2_ENCAP_DERAND_FUNC
ml_kem_avx2_encap_derand_func(const ML_KEM_VINFO *vinfo)
{
    (void)vinfo;
    return NULL;
}

static ML_KEM_AVX2_DECAP_FUNC
ml_kem_avx2_decap_func(const ML_KEM_VINFO *vinfo)
{
    (void)vinfo;
    return NULL;
}

#endif

int ossl_ml_kem_avx2_keypair_derand(const ML_KEM_VINFO *vinfo,
                                    uint8_t *pk, size_t pklen,
                                    uint8_t *sk, size_t sklen,
                                    const uint8_t *seed, size_t seedlen)
{
    ML_KEM_AVX2_KEYPAIR_DERAND_FUNC keypair_derand;

    if (vinfo == NULL || pk == NULL || sk == NULL || seed == NULL
        || pklen != vinfo->pubkey_bytes || sklen != vinfo->prvkey_bytes
        || seedlen != ML_KEM_SEED_BYTES || !ml_kem_avx2_capable())
        return 0;

    keypair_derand = ml_kem_avx2_keypair_derand_func(vinfo);
    return keypair_derand != NULL && keypair_derand(pk, sk, seed) == 0;
}

int ossl_ml_kem_avx2_encap_derand(const ML_KEM_VINFO *vinfo,
                                  uint8_t *ct, size_t ctlen,
                                  uint8_t *ss, size_t sslen,
                                  const uint8_t *pk, size_t pklen,
                                  const uint8_t *entropy, size_t entropylen)
{
    ML_KEM_AVX2_ENCAP_DERAND_FUNC encap_derand;

    if (vinfo == NULL || ct == NULL || ss == NULL || pk == NULL
        || entropy == NULL || ctlen != vinfo->ctext_bytes
        || sslen != ML_KEM_SHARED_SECRET_BYTES || pklen != vinfo->pubkey_bytes
        || entropylen != ML_KEM_RANDOM_BYTES || !ml_kem_avx2_capable())
        return 0;

    encap_derand = ml_kem_avx2_encap_derand_func(vinfo);
    return encap_derand != NULL && encap_derand(ct, ss, pk, entropy) == 0;
}

int ossl_ml_kem_avx2_decap(const ML_KEM_VINFO *vinfo,
                           uint8_t *ss, size_t sslen,
                           const uint8_t *ct, size_t ctlen,
                           const uint8_t *sk, size_t sklen)
{
    ML_KEM_AVX2_DECAP_FUNC decap;

    if (vinfo == NULL || ss == NULL || ct == NULL || sk == NULL
        || sslen != ML_KEM_SHARED_SECRET_BYTES || ctlen != vinfo->ctext_bytes
        || sklen != vinfo->prvkey_bytes || !ml_kem_avx2_capable())
        return 0;

    decap = ml_kem_avx2_decap_func(vinfo);
    return decap != NULL && decap(ss, ct, sk) == 0;
}
