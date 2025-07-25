/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <string.h>
#include "ml_dsa_local.h"
#include "ml_dsa_polyvec.h"
#include "ml_dsa_packing.h"
#include "ml_dsa_fips202.h"

ML_DSA_KEY *pqcrystals_ml_dsa_key_new(OSSL_LIB_CTX *libctx)
{
    ML_DSA_KEY *key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        goto err;

    key->seed = OPENSSL_zalloc(ML_DSA_SEEDBYTES);
    if (key->seed == NULL)
        goto err;
    key->seed_len = 0;

    key->privkey = OPENSSL_zalloc(ML_DSA_SECRETKEYBYTES);
    if (key->privkey == NULL)
        goto err;
    key->privkey_len = 0;

    key->pubkey = OPENSSL_zalloc(ML_DSA_PUBLICKEYBYTES);
    if (key->pubkey == NULL)
        goto err;
    key->pubkey_len = 0;

    key->libctx = libctx;

    return key;
err:

    if (key != NULL) {
        OPENSSL_free(key->seed);
        OPENSSL_free(key->privkey);
        OPENSSL_free(key->pubkey);
    }
    OPENSSL_free(key);
    return NULL;
}

void pqcrystals_ml_dsa_key_free(ML_DSA_KEY *key)
{
    if (key == NULL)
        return;
    OPENSSL_cleanse(key->seed, key->seed_len);
    OPENSSL_free(key->seed);
    OPENSSL_cleanse(key->privkey, key->privkey_len);
    OPENSSL_free(key->privkey);
    OPENSSL_cleanse(key->pubkey, key->pubkey_len);
    OPENSSL_free(key->pubkey);
    OPENSSL_free(key);
}

int pqcrystals_ml_dsa_pk_import(ML_DSA_KEY *key, const uint8_t *pk, size_t pk_len)
{
    if (key == NULL || pk == NULL || pk_len != ML_DSA_PUBLICKEYBYTES)
        return 0;

    OPENSSL_cleanse(key->pubkey, ML_DSA_PUBLICKEYBYTES);
    memcpy(key->pubkey, pk, pk_len);
    key->pubkey_len = pk_len;
    return 1;
}

int pqcrystals_ml_dsa_sk_import(ML_DSA_KEY *key, const uint8_t *sk, size_t sk_len)
{
    if (key == NULL || sk == NULL || sk_len != ML_DSA_SECRETKEYBYTES)
        return 0;

    OPENSSL_cleanse(key->privkey, ML_DSA_SECRETKEYBYTES);
    memcpy(key->privkey, sk, sk_len);
    key->privkey_len = sk_len;
    return 1;
}

int pqcrystals_ml_dsa_sk2pk(const uint8_t *sk, size_t sklen, uint8_t *pk, size_t pklen)
{
    uint8_t seedbuf[2*ML_DSA_SEEDBYTES + ML_DSA_TRBYTES];
    uint8_t *rho, *tr, *key;
    polyvecl mat[ML_DSA_K], s1, s1hat;
    polyveck s2, t1, t0;

    if (sk == NULL || sklen != ML_DSA_SECRETKEYBYTES
             || pk == NULL || pklen != ML_DSA_PUBLICKEYBYTES)
        return 0;

    rho = seedbuf;
    tr = rho + ML_DSA_SEEDBYTES;
    key = tr + ML_DSA_TRBYTES;
    unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* Expand matrix */
    polyvec_matrix_expand(mat, rho);

    /* Matrix-vector multiplication */
    s1hat = s1;
    polyvecl_ntt(&s1hat);
    polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    polyveck_reduce(&t1);
    polyveck_invntt_tomont(&t1);

    /* Add error vector s2 */
    polyveck_add(&t1, &t1, &s2);

    /* Extract t1 and write public key */
    polyveck_caddq(&t1);
    polyveck_power2round(&t1, &t0, &t1);
    pack_pk(pk, rho, &t1);

    return 0;
}

EVP_MD_CTX *pqcrystals_ml_dsa_init_mu(const ML_DSA_KEY *key, const EVP_MD *md,
                                            const uint8_t *ctx, size_t ctxlen)
{
    size_t i;
    EVP_MD_CTX *mdctx;
    uint8_t pre[ML_DSA_CONTEXT_STRING_BYTES+2];
    uint8_t seedbuf[2*ML_DSA_SEEDBYTES + ML_DSA_TRBYTES + ML_DSA_CRHBYTES];
    uint8_t *rho, *tr, *k;
    polyvecl s1;
    polyveck s2, t0;

    if(ctxlen > ML_DSA_CONTEXT_STRING_BYTES)
        return NULL;

    /* Prepare pre = (0, ctxlen, ctx) */
    pre[0] = 0;
    pre[1] = ctxlen;
    for(i = 0; i < ctxlen; i++)
        pre[2 + i] = ctx[i];

    rho = seedbuf;
    tr = rho + ML_DSA_SEEDBYTES;
    k = tr + ML_DSA_TRBYTES;
    if (key->privkey_len == ML_DSA_SECRETKEYBYTES)
        unpack_sk(rho, tr, k, &t0, &s1, &s2, key->privkey);
    else
        shake256(tr, ML_DSA_TRBYTES, key->pubkey, ML_DSA_PUBLICKEYBYTES);

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        return NULL;
    if (!EVP_DigestInit_ex2(mdctx, md, NULL)
            || !EVP_DigestUpdate(mdctx, tr, ML_DSA_TRBYTES)
            || !EVP_DigestUpdate(mdctx, pre, 2 + ctxlen)) {
        EVP_MD_CTX_free(mdctx);
        return NULL;
    }
    return mdctx;
}
