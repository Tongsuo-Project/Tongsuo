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
#include "prov/implementations.h"
#include "prov/providercommon.h"

#ifndef OPENSSL_NO_WBSM4_XIAOLAI
static void *wbsm4_xiaolai_ccm_newctx(void *provctx, size_t keybits)
{
    PROV_WBSM4_XIAOLAI_CCM_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ossl_ccm_initctx(&ctx->base, keybits,
                        ossl_prov_wbsm4_xiaolai_hw_ccm(keybits));
    return ctx;
}

static OSSL_FUNC_cipher_freectx_fn wbsm4_xiaolai_ccm_freectx;
static void wbsm4_xiaolai_ccm_freectx(void *vctx)
{
    PROV_WBSM4_XIAOLAI_CCM_CTX *ctx = (PROV_WBSM4_XIAOLAI_CCM_CTX *)vctx;

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/* ossl_wbsm4_xiaolai1225984ccm_functions */
IMPLEMENT_aead_cipher(wbsm4_xiaolai, ccm, CCM, AEAD_FLAGS, 1225984, 8, 96);
#endif /* OPENSSL_NO_WBSM4_XIAOLAI */

#ifndef OPENSSL_NO_WBSM4_BAIWU
static void *wbsm4_baiwu_ccm_newctx(void *provctx, size_t keybits)
{
    PROV_WBSM4_BAIWU_CCM_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ossl_ccm_initctx(&ctx->base, keybits,
                        ossl_prov_wbsm4_baiwu_hw_ccm(keybits));
    return ctx;
}

static OSSL_FUNC_cipher_freectx_fn wbsm4_baiwu_ccm_freectx;
static void wbsm4_baiwu_ccm_freectx(void *vctx)
{
    PROV_WBSM4_BAIWU_CCM_CTX *ctx = (PROV_WBSM4_BAIWU_CCM_CTX *)vctx;

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/* ossl_wbsm4_baiwu272638208ccm_functions */
IMPLEMENT_aead_cipher(wbsm4_baiwu, ccm, CCM, AEAD_FLAGS, 272638208, 8, 96);
#endif /* OPENSSL_NO_WBSM4_BAIWU */

#ifndef OPENSSL_NO_WBSM4_WSISE
static void *wbsm4_wsise_ccm_newctx(void *provctx, size_t keybits)
{
    PROV_WBSM4_WSISE_CCM_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ossl_ccm_initctx(&ctx->base, keybits,
                        ossl_prov_wbsm4_wsise_hw_ccm(keybits));
    return ctx;
}

static OSSL_FUNC_cipher_freectx_fn wbsm4_wsise_ccm_freectx;
static void wbsm4_wsise_ccm_freectx(void *vctx)
{
    PROV_WBSM4_WSISE_CCM_CTX *ctx = (PROV_WBSM4_WSISE_CCM_CTX *)vctx;

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/* ossl_wbsm4_wsise2274560ccm_functions */
IMPLEMENT_aead_cipher(wbsm4_wsise, ccm, CCM, AEAD_FLAGS, 2274560, 8, 96);
#endif /* OPENSSL_NO_WBSM4_WSISE */
