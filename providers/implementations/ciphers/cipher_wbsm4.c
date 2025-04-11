/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
/* Dispatch functions for cast cipher modes ecb, cbc, ofb, cfb */

#include "cipher_wbsm4.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
static OSSL_FUNC_cipher_freectx_fn wbsm4_xiao_dykey_freectx;
static OSSL_FUNC_cipher_dupctx_fn wbsm4_xiao_dykey_dupctx;
static OSSL_FUNC_cipher_set_ctx_params_fn ossl_wbsm4_xiao_dykey_set_ctx_params;

static void wbsm4_xiao_dykey_freectx(void *vctx)
{
    PROV_WBSM4_XIAO_DYKEY_CTX *ctx = (PROV_WBSM4_XIAO_DYKEY_CTX *)vctx;

    ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *wbsm4_xiao_dykey_dupctx(void *ctx)
{
    PROV_WBSM4_XIAO_DYKEY_CTX *in = (PROV_WBSM4_XIAO_DYKEY_CTX *)ctx;
    PROV_WBSM4_XIAO_DYKEY_CTX *ret;

    if (!ossl_prov_is_running())
        return NULL;

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    in->base.hw->copyctx(&ret->base, &in->base);

    return ret;
}

const OSSL_PARAM * wbsm4_xiao_dykey_settable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx);

CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(wbsm4_xiao_dykey)
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_WBSM4_WBRK, NULL, 0),
CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(wbsm4_xiao_dykey)

static int ossl_wbsm4_xiao_dykey_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_WBSM4_XIAO_DYKEY_CTX *ctx = (PROV_WBSM4_XIAO_DYKEY_CTX *)vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_WBSM4_WBRK);
    if (p && p->data_type == OSSL_PARAM_OCTET_STRING) {
        uint32_t wbrk[32];
        wbsm4_set_key(p->data, (void *)wbrk, p->data_size);
        wbsm4_xiao_dykey_update_wbrk(&ctx->ks.ks, wbrk);
        return 1;
    }
    return 1;
}


/* ossl_wbsm4_xiao_dykey128ecb_functions */
IMPLEMENT_generic_cipher_wbsm4(wbsm4_xiao_dykey, WBSM4_XIAO_DYKEY, ecb, ECB, 0, 128, 128, 0, block)
IMPLEMENT_generic_cipher_wbsm4(wbsm4_xiao_dykey, WBSM4_XIAO_DYKEY, cbc, CBC, 0, 128, 128, 128, block)
IMPLEMENT_generic_cipher_wbsm4(wbsm4_xiao_dykey, WBSM4_XIAO_DYKEY, ctr, CTR, 0, 128, 8, 128, stream)
IMPLEMENT_generic_cipher_wbsm4(wbsm4_xiao_dykey, WBSM4_XIAO_DYKEY, ofb128, OFB, 0, 128, 8, 128, stream)
IMPLEMENT_generic_cipher_wbsm4(wbsm4_xiao_dykey, WBSM4_XIAO_DYKEY, cfb128, CFB, 0, 128, 8, 128, stream)
#endif
