/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

/* Dispatch functions for SM4 CCM mode */

#include "cipher_wbsm4_ccm.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

#ifndef OPENSSL_NO_WBSM4_XIAO_STKEY
static void *wbsm4_xiao_stkey_ccm_newctx(void *provctx, size_t keybits)
{
    PROV_WBSM4_XIAO_STKEY_CCM_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ossl_ccm_initctx(&ctx->base, keybits, ossl_prov_wbsm4_xiao_stkey_hw_ccm(keybits));
    return ctx;
}

static OSSL_FUNC_cipher_freectx_fn wbsm4_xiao_stkey_ccm_freectx;
static void wbsm4_xiao_stkey_ccm_freectx(void *vctx)
{
    PROV_WBSM4_XIAO_STKEY_CCM_CTX *ctx = (PROV_WBSM4_XIAO_STKEY_CCM_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

/* ossl_wbsm4_xiao_stkey128ccm_functions */
IMPLEMENT_aead_cipher(wbsm4_xiao_stkey, ccm, CCM, AEAD_FLAGS, 128, 8, 96);
#endif

#ifndef OPENSSL_NO_WBSM4_JIN_STKEY
static void *wbsm4_jin_stkey_ccm_newctx(void *provctx, size_t keybits)
{
    PROV_WBSM4_JIN_STKEY_CCM_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ossl_ccm_initctx(&ctx->base, keybits, ossl_prov_wbsm4_jin_stkey_hw_ccm(keybits));
    return ctx;
}

static OSSL_FUNC_cipher_freectx_fn wbsm4_jin_stkey_ccm_freectx;
static void wbsm4_jin_stkey_ccm_freectx(void *vctx)
{
    PROV_WBSM4_JIN_STKEY_CCM_CTX *ctx = (PROV_WBSM4_JIN_STKEY_CCM_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

/* ossl_wbsm4_jin_stkey128ccm_functions */
IMPLEMENT_aead_cipher(wbsm4_jin_stkey, ccm, CCM, AEAD_FLAGS, 128, 8, 96);
#endif

#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
static void *wbsm4_xiao_dykey_ccm_newctx(void *provctx, size_t keybits)
{
    PROV_WBSM4_XIAO_DYKEY_CCM_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ossl_ccm_initctx(&ctx->base, keybits, ossl_prov_wbsm4_xiao_dykey_hw_ccm(keybits));
    return ctx;
}

static OSSL_FUNC_cipher_freectx_fn wbsm4_xiao_dykey_ccm_freectx;
static void wbsm4_xiao_dykey_ccm_freectx(void *vctx)
{
    PROV_WBSM4_XIAO_DYKEY_CCM_CTX *ctx = (PROV_WBSM4_XIAO_DYKEY_CCM_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

/* ossl_wbsm4_xiao_dykey128ccm_functions */
IMPLEMENT_aead_cipher(wbsm4_xiao_dykey, ccm, CCM, AEAD_FLAGS, 128, 8, 96);
#endif
