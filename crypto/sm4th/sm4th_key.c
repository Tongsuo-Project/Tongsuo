/*
 * SM4-in-the-Head (SM4th) signature scheme for Tongsuo.
 *
 * Adapted from the Chinith sm4th NGCC reference implementation, which
 * partly derives from the FAEST project (SPDX-License-Identifier: MIT).
 * See crypto/sm4th/build.info and the NOTICE file for provenance.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Copyright 2023-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Key management layer of the SM4-in-the-Head (SM4th) signature scheme.
 * These functions form the internal API that the (future) signature
 * provider will call; see include/crypto/sm4th.h for the listing.
 */

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "blockcipher.h"
#include "crypto/sm4th.h"
#include "params.h"
#include "sm4th_key.h"
#include "sm4th_sigops.h"

#include <string.h>

/**
 * @brief Get the parameter set of a variant.
 */
static const params_t *tons_sm4th_params_get(int variant)
{
    switch (variant) {
    case SM4TH_VARIANT_F:
        return sm4th_params_d3_f();
    case SM4TH_VARIANT_S:
        return sm4th_params_d3_s();
    default:
        return NULL;
    }
}

/**
 * @brief Get the algorithm name of a variant ("SM4TH-F"/"SM4TH-S").
 */
const char *tons_sm4th_variant_name(int variant)
{
    switch (variant) {
    case SM4TH_VARIANT_F:
        return SN_sm4th_f;
    case SM4TH_VARIANT_S:
        return SN_sm4th_s;
    default:
        return NULL;
    }
}

/**
 * @brief Destroy an SM4TH_KEY object
 */
void tons_sm4th_key_free(SM4TH_KEY *key)
{
    if (key == NULL)
        return;
    EVP_MD_free(key->shake128_md);
    OPENSSL_cleanse(key->k, sizeof(key->k));
    OPENSSL_cleanse(key->p, sizeof(key->p));
    OPENSSL_cleanse(key->c, sizeof(key->c));
    OPENSSL_free(key->propq);
    OPENSSL_free(key);
}

/**
 * @brief Create a new SM4TH_KEY object for a variant.
 *
 * @param libctx A OSSL_LIB_CTX object used for fetching algorithms.
 * @param propq The property query used for fetching algorithms
 * @param variant One of SM4TH_VARIANT_F or SM4TH_VARIANT_S
 * @returns The new SM4TH_KEY object on success, or NULL on failure
 */
SM4TH_KEY *tons_sm4th_key_new(OSSL_LIB_CTX *libctx, const char *propq,
    int variant)
{
    SM4TH_KEY *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    ret->params = tons_sm4th_params_get(variant);
    if (ret->params == NULL)
        goto err;
    ret->variant = variant;
    ret->libctx = libctx;
    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        if (ret->propq == NULL)
            goto err;
    }
    /* Prefetch SHAKE-128 for H_i (cf. ossl_ml_dsa_key_new). */
    ret->shake128_md = EVP_MD_fetch(libctx, "SHAKE-128", propq);
    if (ret->shake128_md == NULL)
        goto err;
    return ret;

err:
    tons_sm4th_key_free(ret);
    return NULL;
}

/**
 * @brief Get the library context of the key.
 */
OSSL_LIB_CTX *tons_sm4th_key_get0_libctx(SM4TH_KEY *key)
{
    return key->libctx;
}

/**
 * @brief Get the variant of the key.
 */
int tons_sm4th_key_get_variant(const SM4TH_KEY *key)
{
    return key->variant;
}

/**
 * @brief Get the algorithm name of the key.
 */
const char *tons_sm4th_key_get_name(const SM4TH_KEY *key)
{
    return tons_sm4th_variant_name(key->variant);
}

/**
 * @brief Get the signature length of the key's variant.
 */
size_t tons_sm4th_key_get_sig_len(const SM4TH_KEY *key)
{
    return (size_t)key->params->sig_len;
}

/**
 * @brief Get the signing seed length (32 bytes for both variants).
 */
size_t tons_sm4th_key_get_randomness_len(const SM4TH_KEY *key)
{
    if (key == NULL)
        return 0;
    switch (key->variant) {
    case SM4TH_VARIANT_F:
    case SM4TH_VARIANT_S:
        return SM4TH_SEED_BYTES;
    default:
        return 0;
    }
}

/**
 * @brief Generate a new key pair.
 *
 * Reject-sample SM4 key k until ((k[0]^0xA3)&3) != 3, then sample plaintext
 * p once and set c = SM4_k(p). The public key is (p, c); the private key is
 * (p, k). Matches SM4th.KeyGen.
 *
 * @param key The key object to fill (libctx is used for RAND).
 * @returns 1 on success or 0 on failure.
 */
int tons_sm4th_generate_key(SM4TH_KEY *key)
{
    uint8_t k[16], x[16], y[16];
    int ok = 0;

    if (key == NULL)
        return 0;
    do {
        if (RAND_priv_bytes_ex(key->libctx, k, sizeof(k), 0) <= 0)
            goto out;
    } while (!sm4th_key_is_valid(k));
    if (RAND_bytes_ex(key->libctx, x, sizeof(x), 0) <= 0)
        goto out;
    sm4_enc(k, x, y);
    memcpy(key->k, k, sizeof(k));
    memcpy(key->p, x, sizeof(x));
    memcpy(key->c, y, sizeof(y));
    key->has_k = 1;
    ok = 1;
out:
    OPENSSL_cleanse(k, sizeof(k));
    OPENSSL_cleanse(x, sizeof(x));
    OPENSSL_cleanse(y, sizeof(y));
    return ok;
}

/**
 * @brief Import a raw private key (p || k) and derive the public key.
 *
 * @param key The key object to fill.
 * @param sk Raw private key bytes (32 bytes: p || k).
 * @param sklen Length of sk, must be SM4TH_SK_BYTES.
 * @returns 1 on success or 0 on failure.
 */
int tons_sm4th_key_set_sk(SM4TH_KEY *key, const uint8_t *sk, size_t sklen)
{
    if (key == NULL || sk == NULL || sklen != SM4TH_SK_BYTES
        || !sm4th_key_is_valid(sk + SM4TH_128_BYTES))
        return 0;

    memcpy(key->p, sk, SM4TH_128_BYTES);
    memcpy(key->k, sk + SM4TH_128_BYTES, SM4TH_128_BYTES);

    /* c = OWF(k, p) */
    sm4_enc(key->k, key->p, key->c);

    key->has_k = 1;
    return 1;
}

/**
 * @brief Import a raw public key (p || c).
 *
 * @param key The key object to fill.
 * @param pk Raw public key bytes (32 bytes: p || c).
 * @param pklen Length of pk, must be SM4TH_PK_BYTES.
 * @returns 1 on success or 0 on failure.
 */
int tons_sm4th_key_set_pk(SM4TH_KEY *key, const uint8_t *pk, size_t pklen)
{
    if (key == NULL || pk == NULL || pklen != SM4TH_PK_BYTES)
        return 0;

    memcpy(key->p, pk, SM4TH_128_BYTES);
    memcpy(key->c, pk + SM4TH_128_BYTES, SM4TH_128_BYTES);
    OPENSSL_cleanse(key->k, sizeof(key->k));
    key->has_k = 0;
    return 1;
}

/**
 * @brief Export the raw public key (p || c) of the key.
 *
 * @returns 1 on success, 0 otherwise.
 */
int tons_sm4th_key_get_pk(const SM4TH_KEY *key, uint8_t *pk, size_t pklen)
{
    if (key == NULL || pk == NULL || pklen < SM4TH_PK_BYTES)
        return 0;

    memcpy(pk, key->p, SM4TH_128_BYTES);
    memcpy(pk + SM4TH_128_BYTES, key->c, SM4TH_128_BYTES);
    return 1;
}

/**
 * @brief Export the raw private key (p || k). Requires has_k.
 */
int tons_sm4th_key_get_sk(const SM4TH_KEY *key, uint8_t *sk, size_t sklen)
{
    if (key == NULL || !key->has_k || sk == NULL || sklen < SM4TH_SK_BYTES)
        return 0;

    memcpy(sk, key->p, SM4TH_128_BYTES);
    memcpy(sk + SM4TH_128_BYTES, key->k, SM4TH_128_BYTES);
    return 1;
}

int tons_sm4th_key_has_private(const SM4TH_KEY *key)
{
    return key != NULL && key->has_k;
}

/**
 * @brief Check that the private part of the key matches the public part.
 *
 * Only makes sense for keys that have a private part (set_sk/generate_key).
 *
 * @returns 1 if the key pair is consistent, 0 otherwise.
 */
int tons_sm4th_key_pairwise_check(const SM4TH_KEY *key)
{
    uint8_t pk[SM4TH_PK_BYTES];
    uint8_t sk[SM4TH_SK_BYTES];
    int ret;

    if (key == NULL || !key->has_k)
        return 0;
    if (!tons_sm4th_key_get_pk(key, pk, sizeof(pk)))
        return 0;

    memcpy(sk, key->p, SM4TH_128_BYTES);
    memcpy(sk + SM4TH_128_BYTES, key->k, SM4TH_128_BYTES);
    ret = sm4th_validate(key->params, pk, sk) == 0;
    OPENSSL_cleanse(sk, sizeof(sk));
    return ret;
}

/**
 * @brief Sign a message with the private key and a 32-byte seed.
 *        Public y is recomputed as SM4.Enc(k, x); no pk input.
 *
 * @param key A key set via set_sk or generate_key.
 * @param msg Message to sign.
 * @param msglen Length of msg (|msg| <= 2^60).
 * @param seed Signing seed (must be SM4TH_SEED_BYTES).
 * @param seedlen Length of seed.
 * @param sig Output buffer for the signature.
 * @param siglen On input the buffer capacity; on output the signature size.
 * @returns 1 on success, 0 on failure.
 */
int tons_sm4th_sign(const SM4TH_KEY *key, const uint8_t *msg, size_t msglen,
    const uint8_t *seed, size_t seedlen,
    uint8_t *sig, size_t *siglen)
{
    uint8_t sk[SM4TH_SK_BYTES];
    size_t outlen;
    int ret;

    if (key == NULL || !key->has_k || !sm4th_key_is_valid(key->k)
        || sig == NULL || siglen == NULL
        || *siglen < (size_t)key->params->sig_len
        || (!msg && msglen)
        || seed == NULL || seedlen != SM4TH_SEED_BYTES
        || msglen > SM4TH_MAX_MSG)
        return 0;

    memcpy(sk, key->p, SM4TH_128_BYTES);
    memcpy(sk + SM4TH_128_BYTES, key->k, SM4TH_128_BYTES);

    outlen = *siglen;
    ret = sm4th_sign(key->params, key->shake128_md, sk, msg, msglen,
                     seed, seedlen, sig, &outlen) == 0;
    if (ret)
        *siglen = outlen;
    OPENSSL_cleanse(sk, sizeof(sk));
    return ret;
}

/**
 * @brief Verify a message signature under the public key of the key
 *        object (set via set_pk, set_sk or generate_key).
 *
 * @returns 1 if valid, 0 on failure/invalid.
 */
int tons_sm4th_verify(const SM4TH_KEY *key, const uint8_t *msg, size_t msglen,
    const uint8_t *sig, size_t siglen)
{
    uint8_t pk[SM4TH_PK_BYTES];
    int ret;

    if (key == NULL || !tons_sm4th_key_get_pk(key, pk, sizeof(pk)))
        return 0;

    ret = sm4th_verify(key->params, key->shake128_md, pk, SM4TH_PK_BYTES,
                       msg, msglen, sig, siglen) == 0;
    return ret;
}
