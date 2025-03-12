/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for SM4 CCM mode */

/*
 * This file uses the low level SM4 functions (which are deprecated for
 * non-internal use) in order to implement provider SM4 ciphers.
 */
#include "internal/deprecated.h"

#include "cipher_wbsm4_ccm.h"
#include "crypto/sm4_platform.h"

#ifndef OPENSSL_NO_WBSM4_XIAO_STKEY
static int wbsm4_xiao_stkey_ccm_initkey(PROV_CCM_CTX *ctx, const unsigned char *key,
                           size_t keylen)
{
    PROV_WBSM4_XIAO_STKEY_CCM_CTX *actx = (PROV_WBSM4_XIAO_STKEY_CCM_CTX *)ctx;
    wbsm4_xiao_stkey_context *ks = &actx->ks.ks;


    wbsm4_set_key(key, ks, sizeof(wbsm4_xiao_stkey_context));
    CRYPTO_ccm128_init(&ctx->ccm_ctx, ctx->m, ctx->l, &actx->ks.ks,
                        (block128_f) wbsm4_xiao_stkey_encrypt);
    ctx->str = (ccm128_f)NULL;

    ctx->key_set = 1;

    return 1;
}

static const PROV_CCM_HW wbsm4_xiao_stkey_ccm = {
    wbsm4_xiao_stkey_ccm_initkey,
    ossl_ccm_generic_setiv,
    ossl_ccm_generic_setaad,
    ossl_ccm_generic_auth_encrypt,
    ossl_ccm_generic_auth_decrypt,
    ossl_ccm_generic_gettag
};


const PROV_CCM_HW *ossl_prov_wbsm4_xiao_stkey_hw_ccm(size_t keybits)
{
    return &wbsm4_xiao_stkey_ccm;
}
#endif

#ifndef OPENSSL_NO_WBSM4_JIN_STKEY
static int wbsm4_jin_stkey_ccm_initkey(PROV_CCM_CTX *ctx, const unsigned char *key,
                           size_t keylen)
{
    PROV_WBSM4_JIN_STKEY_CCM_CTX *actx = (PROV_WBSM4_JIN_STKEY_CCM_CTX *)ctx;
    wbsm4_jin_stkey_context *ks = &actx->ks.ks;

    wbsm4_set_key(key, ks, sizeof(wbsm4_jin_stkey_context));
    CRYPTO_ccm128_init(&ctx->ccm_ctx, ctx->m, ctx->l, &actx->ks.ks,
                        (block128_f) wbsm4_jin_stkey_encrypt);
    ctx->str = (ccm128_f)NULL;

    ctx->key_set = 1;

    return 1;
}

static const PROV_CCM_HW wbsm4_jin_stkey_ccm = {
    wbsm4_jin_stkey_ccm_initkey,
    ossl_ccm_generic_setiv,
    ossl_ccm_generic_setaad,
    ossl_ccm_generic_auth_encrypt,
    ossl_ccm_generic_auth_decrypt,
    ossl_ccm_generic_gettag
};


const PROV_CCM_HW *ossl_prov_wbsm4_jin_stkey_hw_ccm(size_t keybits)
{
    return &wbsm4_jin_stkey_ccm;
}
#endif

#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
static int wbsm4_xiao_dykey_ccm_initkey(PROV_CCM_CTX *ctx, const unsigned char *key,
                           size_t keylen)
{
    PROV_WBSM4_XIAO_DYKEY_CCM_CTX *actx = (PROV_WBSM4_XIAO_DYKEY_CCM_CTX *)ctx;
    wbsm4_xiao_dykey_context *ks = &actx->ks.ks;

    wbsm4_set_key(key, ks, sizeof(wbsm4_xiao_dykey_context));
    CRYPTO_ccm128_init(&ctx->ccm_ctx, ctx->m, ctx->l, &actx->ks.ks,
                        (block128_f) wbsm4_xiao_dykey_encrypt);
    ctx->str = (ccm128_f)NULL;

    ctx->key_set = 1;

    return 1;
}

static const PROV_CCM_HW wbsm4_xiao_dykey_ccm = {
    wbsm4_xiao_dykey_ccm_initkey,
    ossl_ccm_generic_setiv,
    ossl_ccm_generic_setaad,
    ossl_ccm_generic_auth_encrypt,
    ossl_ccm_generic_auth_decrypt,
    ossl_ccm_generic_gettag
};


const PROV_CCM_HW *ossl_prov_wbsm4_xiao_dykey_hw_ccm(size_t keybits)
{
    return &wbsm4_xiao_dykey_ccm;
}
#endif
