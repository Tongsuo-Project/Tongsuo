/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "internal/deprecated.h"

#include "cipher_wbsm4_gcm.h"

#ifndef OPENSSL_NO_WBSM4_XIAOLAI
static int wbsm4_xiaolai_gcm_initkey(PROV_GCM_CTX *ctx,
                                     const unsigned char *key, size_t keylen)
{
    PROV_WBSM4_XIAOLAI_GCM_CTX *actx = (PROV_WBSM4_XIAOLAI_GCM_CTX *)ctx;
    wbsm4_xiaolai_key *ks = &actx->ks.ks;

    ctx->ks = ks;

    wbsm4_xiaolai_set_key(key, ks);
    CRYPTO_gcm128_init(&ctx->gcm, ks, (block128_f)wbsm4_xiaolai_encrypt);
    ctx->ctr = (ctr128_f)NULL;

    ctx->key_set = 1;

    return 1;
}

static int generic_wbsm4_xiaolai_gcm_cipher_update(PROV_GCM_CTX *ctx,
                                                   const unsigned char *in,
                                                   size_t len,
                                                   unsigned char *out)
{
    if (ctx->enc) {
        if (ctx->ctr != NULL) {
            if (CRYPTO_gcm128_encrypt_ctr32(&ctx->gcm, in, out, len, ctx->ctr))
                return 0;
        } else {
            if (CRYPTO_gcm128_encrypt(&ctx->gcm, in, out, len))
                return 0;
        }
    } else {
        if (ctx->ctr != NULL) {
            if (CRYPTO_gcm128_decrypt_ctr32(&ctx->gcm, in, out, len, ctx->ctr))
                return 0;
        } else {
            if (CRYPTO_gcm128_decrypt(&ctx->gcm, in, out, len))
                return 0;
        }
    }
    return 1;
}

static const PROV_GCM_HW wbsm4_xiaolai_gcm = {
    wbsm4_xiaolai_gcm_initkey,
    ossl_gcm_setiv,
    ossl_gcm_aad_update,
    generic_wbsm4_xiaolai_gcm_cipher_update,
    ossl_gcm_cipher_final,
    ossl_gcm_one_shot
};

const PROV_GCM_HW *ossl_prov_wbsm4_xiaolai_hw_gcm(size_t keybits)
{
    return &wbsm4_xiaolai_gcm;
}
#endif /* OPENSSL_NO_WBSM4_XIAOLAI */

#ifndef OPENSSL_NO_WBSM4_BAIWU
static int wbsm4_baiwu_gcm_initkey(PROV_GCM_CTX *ctx, const unsigned char *key,
                                   size_t keylen)
{
    PROV_WBSM4_BAIWU_GCM_CTX *actx = (PROV_WBSM4_BAIWU_GCM_CTX *)ctx;
    wbsm4_baiwu_key *ks = &actx->ks.ks;

    ctx->ks = ks;

    wbsm4_baiwu_set_key(key, ks);
    CRYPTO_gcm128_init(&ctx->gcm, ks, (block128_f)wbsm4_baiwu_encrypt);
    ctx->ctr = (ctr128_f)NULL;

    ctx->key_set = 1;

    return 1;
}

static int generic_wbsm4_baiwu_gcm_cipher_update(PROV_GCM_CTX *ctx,
                                                 const unsigned char *in,
                                                 size_t len, unsigned char *out)
{
    if (ctx->enc) {
        if (ctx->ctr != NULL) {
            if (CRYPTO_gcm128_encrypt_ctr32(&ctx->gcm, in, out, len, ctx->ctr))
                return 0;
        } else {
            if (CRYPTO_gcm128_encrypt(&ctx->gcm, in, out, len))
                return 0;
        }
    } else {
        if (ctx->ctr != NULL) {
            if (CRYPTO_gcm128_decrypt_ctr32(&ctx->gcm, in, out, len, ctx->ctr))
                return 0;
        } else {
            if (CRYPTO_gcm128_decrypt(&ctx->gcm, in, out, len))
                return 0;
        }
    }
    return 1;
}

static const PROV_GCM_HW wbsm4_baiwu_gcm = {
    wbsm4_baiwu_gcm_initkey,
    ossl_gcm_setiv,
    ossl_gcm_aad_update,
    generic_wbsm4_baiwu_gcm_cipher_update,
    ossl_gcm_cipher_final,
    ossl_gcm_one_shot
};

const PROV_GCM_HW *ossl_prov_wbsm4_baiwu_hw_gcm(size_t keybits)
{
    return &wbsm4_baiwu_gcm;
}
#endif /* OPENSSL_NO_WBSM4_BAIWU */

#ifndef OPENSSL_NO_WBSM4_WSISE
static int wbsm4_wsise_gcm_initkey(PROV_GCM_CTX *ctx, const unsigned char *key,
                                   size_t keylen)
{
    PROV_WBSM4_WSISE_GCM_CTX *actx = (PROV_WBSM4_WSISE_GCM_CTX *)ctx;
    wbsm4_wsise_key *ks = &actx->ks.ks;

    ctx->ks = ks;

    wbsm4_wsise_set_key(key, ks);
    CRYPTO_gcm128_init(&ctx->gcm, ks, (block128_f)wbsm4_wsise_encrypt);
    ctx->ctr = (ctr128_f)NULL;

    ctx->key_set = 1;

    return 1;
}

static int generic_wbsm4_wsise_gcm_cipher_update(PROV_GCM_CTX *ctx,
                                                 const unsigned char *in,
                                                 size_t len, unsigned char *out)
{
    if (ctx->enc) {
        if (ctx->ctr != NULL) {
            if (CRYPTO_gcm128_encrypt_ctr32(&ctx->gcm, in, out, len, ctx->ctr))
                return 0;
        } else {
            if (CRYPTO_gcm128_encrypt(&ctx->gcm, in, out, len))
                return 0;
        }
    } else {
        if (ctx->ctr != NULL) {
            if (CRYPTO_gcm128_decrypt_ctr32(&ctx->gcm, in, out, len, ctx->ctr))
                return 0;
        } else {
            if (CRYPTO_gcm128_decrypt(&ctx->gcm, in, out, len))
                return 0;
        }
    }
    return 1;
}

static const PROV_GCM_HW wbsm4_wsise_gcm = {
    wbsm4_wsise_gcm_initkey,
    ossl_gcm_setiv,
    ossl_gcm_aad_update,
    generic_wbsm4_wsise_gcm_cipher_update,
    ossl_gcm_cipher_final,
    ossl_gcm_one_shot
};

const PROV_GCM_HW *ossl_prov_wbsm4_wsise_hw_gcm(size_t keybits)
{
    return &wbsm4_wsise_gcm;
}
#endif /* OPENSSL_NO_WBSM4_WSISE */
