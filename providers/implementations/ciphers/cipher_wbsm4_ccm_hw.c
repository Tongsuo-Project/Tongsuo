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

#include "cipher_wbsm4_ccm.h"

#ifndef OPENSSL_NO_WBSM4_XIAOLAI
static int wbsm4_xiaolai_ccm_initkey(PROV_CCM_CTX *ctx,
                                     const unsigned char *key, size_t keylen)
{
    PROV_WBSM4_XIAOLAI_CCM_CTX *actx = (PROV_WBSM4_XIAOLAI_CCM_CTX *)ctx;
    wbsm4_xiaolai_key *ks = &actx->ks.ks;

    wbsm4_xiaolai_set_key(key, ks);
    CRYPTO_ccm128_init(&ctx->ccm_ctx, ctx->m, ctx->l, &actx->ks.ks,
                       (block128_f)wbsm4_xiaolai_encrypt);
    ctx->str = (ccm128_f)NULL;

    ctx->key_set = 1;

    return 1;
}

static const PROV_CCM_HW wbsm4_xiaolai_ccm = {
    wbsm4_xiaolai_ccm_initkey,
    ossl_ccm_generic_setiv,
    ossl_ccm_generic_setaad,
    ossl_ccm_generic_auth_encrypt,
    ossl_ccm_generic_auth_decrypt,
    ossl_ccm_generic_gettag
};

const PROV_CCM_HW *ossl_prov_wbsm4_xiaolai_hw_ccm(size_t keybits)
{
    return &wbsm4_xiaolai_ccm;
}
#endif /* OPENSSL_NO_WBSM4_XIAOLAI */

#ifndef OPENSSL_NO_WBSM4_BAIWU
static int wbsm4_baiwu_ccm_initkey(PROV_CCM_CTX *ctx, const unsigned char *key,
                                   size_t keylen)
{
    PROV_WBSM4_BAIWU_CCM_CTX *actx = (PROV_WBSM4_BAIWU_CCM_CTX *)ctx;
    wbsm4_baiwu_key *ks = &actx->ks.ks;

    wbsm4_baiwu_set_key(key, ks);
    CRYPTO_ccm128_init(&ctx->ccm_ctx, ctx->m, ctx->l, &actx->ks.ks,
                       (block128_f)wbsm4_baiwu_encrypt);
    ctx->str = (ccm128_f)NULL;

    ctx->key_set = 1;

    return 1;
}

static const PROV_CCM_HW wbsm4_baiwu_ccm = {
    wbsm4_baiwu_ccm_initkey,
    ossl_ccm_generic_setiv,
    ossl_ccm_generic_setaad,
    ossl_ccm_generic_auth_encrypt,
    ossl_ccm_generic_auth_decrypt,
    ossl_ccm_generic_gettag
};

const PROV_CCM_HW *ossl_prov_wbsm4_baiwu_hw_ccm(size_t keybits)
{
    return &wbsm4_baiwu_ccm;
}
#endif /* OPENSSL_NO_WBSM4_BAIWU */

#ifndef OPENSSL_NO_WBSM4_WSISE
static int wbsm4_wsise_ccm_initkey(PROV_CCM_CTX *ctx, const unsigned char *key,
                                   size_t keylen)
{
    PROV_WBSM4_WSISE_CCM_CTX *actx = (PROV_WBSM4_WSISE_CCM_CTX *)ctx;
    wbsm4_wsise_key *ks = &actx->ks.ks;

    wbsm4_wsise_set_key(key, ks);
    CRYPTO_ccm128_init(&ctx->ccm_ctx, ctx->m, ctx->l, &actx->ks.ks,
                       (block128_f)wbsm4_wsise_encrypt);
    ctx->str = (ccm128_f)NULL;

    ctx->key_set = 1;

    return 1;
}

static const PROV_CCM_HW wbsm4_wsise_ccm = {
    wbsm4_wsise_ccm_initkey,
    ossl_ccm_generic_setiv,
    ossl_ccm_generic_setaad,
    ossl_ccm_generic_auth_encrypt,
    ossl_ccm_generic_auth_decrypt,
    ossl_ccm_generic_gettag
};

const PROV_CCM_HW *ossl_prov_wbsm4_wsise_hw_ccm(size_t keybits)
{
    return &wbsm4_wsise_ccm;
}
#endif /* OPENSSL_NO_WBSM4_WSISE */
