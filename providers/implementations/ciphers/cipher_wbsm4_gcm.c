/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * AES low level APIs are deprecated for public use, but still ok for internal
 * use where we're using them to implement the higher level EVP interface, as is
 * the case here.
 */
#include "internal/deprecated.h"

/* Dispatch functions for AES GCM mode */

#include "cipher_wbsm4_gcm.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
static void *wbsm4_xiao_dykey_gcm_newctx(void *provctx, size_t keybits)
{
    PROV_WBSM4_XIAO_DYKEY_GCM_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ossl_gcm_initctx(provctx, &ctx->base, keybits,
                         ossl_prov_wbsm4_xiao_dykey_hw_gcm(keybits));
    return ctx;
}

static OSSL_FUNC_cipher_freectx_fn wbsm4_xiao_dykey_gcm_freectx;
static void wbsm4_xiao_dykey_gcm_freectx(void *vctx)
{
    PROV_WBSM4_XIAO_DYKEY_GCM_CTX *ctx = (PROV_WBSM4_XIAO_DYKEY_GCM_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

/* ossl_wbsm4_xiao_dykey128gcm_functions */
IMPLEMENT_aead_cipher(wbsm4_xiao_dykey, gcm, GCM, AEAD_FLAGS, 128, 8, 96);
#endif
