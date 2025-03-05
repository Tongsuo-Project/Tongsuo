/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
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

#ifndef OPENSSL_NO_WBSM4_XIAOLAI
static OSSL_FUNC_cipher_freectx_fn wbsm4_xiaolai_freectx;
static OSSL_FUNC_cipher_dupctx_fn wbsm4_xiaolai_dupctx;

static void wbsm4_xiaolai_freectx(void *vctx)
{
    PROV_WBSM4_XIAOLAI_CTX *ctx = (PROV_WBSM4_XIAOLAI_CTX *)vctx;

    ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *wbsm4_xiaolai_dupctx(void *ctx)
{
    PROV_WBSM4_XIAOLAI_CTX *in = (PROV_WBSM4_XIAOLAI_CTX *)ctx;
    PROV_WBSM4_XIAOLAI_CTX *ret;

    if (!ossl_prov_is_running())
        return NULL;

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    in->base.hw->copyctx(&ret->base, &in->base);

    return ret;
}

/* ossl_wbsm4_xiaolai1225984ecb_functions */
IMPLEMENT_generic_cipher(wbsm4_xiaolai, WBSM4_XIAOLAI, ecb, ECB, 0, 1225984,
                         128, 0, block);
/* ossl_wbsm4_xiaolai1225984cbc_functions */
IMPLEMENT_generic_cipher(wbsm4_xiaolai, WBSM4_XIAOLAI, cbc, CBC, 0, 1225984,
                         128, 128, block);
/* ossl_wbsm4_xiaolai1225984ctr_functions */
IMPLEMENT_generic_cipher(wbsm4_xiaolai, WBSM4_XIAOLAI, ctr, CTR, 0, 1225984,
                         8, 128, stream);
/* ossl_wbsm4_xiaolai1225984ofb128_functions */
IMPLEMENT_generic_cipher(wbsm4_xiaolai, WBSM4_XIAOLAI, ofb128, OFB, 0, 1225984,
                         8, 128, stream);
/* ossl_wbsm4_xiaolai1225984cfb128_functions */
IMPLEMENT_generic_cipher(wbsm4_xiaolai, WBSM4_XIAOLAI, cfb128, CFB, 0, 1225984,
                         8, 128, stream);
#endif /* OPENSSL_NO_WBSM4_XIAOLAI */

#ifndef OPENSSL_NO_WBSM4_BAIWU
static OSSL_FUNC_cipher_freectx_fn wbsm4_baiwu_freectx;
static OSSL_FUNC_cipher_dupctx_fn wbsm4_baiwu_dupctx;

static void wbsm4_baiwu_freectx(void *vctx)
{
    PROV_WBSM4_BAIWU_CTX *ctx = (PROV_WBSM4_BAIWU_CTX *)vctx;

    ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *wbsm4_baiwu_dupctx(void *ctx)
{
    PROV_WBSM4_BAIWU_CTX *in = (PROV_WBSM4_BAIWU_CTX *)ctx;
    PROV_WBSM4_BAIWU_CTX *ret;

    if (!ossl_prov_is_running())
        return NULL;

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    in->base.hw->copyctx(&ret->base, &in->base);

    return ret;
}

/* ossl_wbsm4_baiwu272638208ecb_functions */
IMPLEMENT_generic_cipher(wbsm4_baiwu, WBSM4_BAIWU, ecb, ECB, 0, 272638208,
                         128, 0, block);
/* ossl_wbsm4_baiwu272638208cbc_functions */
IMPLEMENT_generic_cipher(wbsm4_baiwu, WBSM4_BAIWU, cbc, CBC, 0, 272638208,
                         128, 128, block);
/* ossl_wbsm4_baiwu272638208ctr_functions */
IMPLEMENT_generic_cipher(wbsm4_baiwu, WBSM4_BAIWU, ctr, CTR, 0, 272638208,
                         8, 128, stream);
/* ossl_wbsm4_baiwu272638208ofb128_functions */
IMPLEMENT_generic_cipher(wbsm4_baiwu, WBSM4_BAIWU, ofb128, OFB, 0, 272638208,
                         8, 128, stream);
/* ossl_wbsm4_baiwu272638208cfb128_functions */
IMPLEMENT_generic_cipher(wbsm4_baiwu, WBSM4_BAIWU, cfb128, CFB, 0, 272638208,
                         8, 128, stream);
#endif /* OPENSSL_NO_WBSM4_BAIWU */

#ifndef OPENSSL_NO_WBSM4_WSISE
static OSSL_FUNC_cipher_freectx_fn wbsm4_wsise_freectx;
static OSSL_FUNC_cipher_dupctx_fn wbsm4_wsise_dupctx;

static void wbsm4_wsise_freectx(void *vctx)
{
    PROV_WBSM4_WSISE_CTX *ctx = (PROV_WBSM4_WSISE_CTX *)vctx;

    ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *wbsm4_wsise_dupctx(void *ctx)
{
    PROV_WBSM4_WSISE_CTX *in = (PROV_WBSM4_WSISE_CTX *)ctx;
    PROV_WBSM4_WSISE_CTX *ret;

    if (!ossl_prov_is_running())
        return NULL;

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    in->base.hw->copyctx(&ret->base, &in->base);

    return ret;
}

/* ossl_wbsm4_wsise2274560ecb_functions */
IMPLEMENT_generic_cipher(wbsm4_wsise, WBSM4_WSISE, ecb, ECB, 0, 2274560,
                         128, 0, block);
/* ossl_wbsm4_wsise2274560cbc_functions */
IMPLEMENT_generic_cipher(wbsm4_wsise, WBSM4_WSISE, cbc, CBC, 0, 2274560,
                         128, 128, block);
/* ossl_wbsm4_wsise2274560ctr_functions */
IMPLEMENT_generic_cipher(wbsm4_wsise, WBSM4_WSISE, ctr, CTR, 0, 2274560,
                         8, 128, stream);
/* ossl_wbsm4_wsise2274560ofb128_functions */
IMPLEMENT_generic_cipher(wbsm4_wsise, WBSM4_WSISE, ofb128, OFB, 0, 2274560,
                         8, 128, stream);
/* ossl_wbsm4_wsise2274560cfb128_functions */
IMPLEMENT_generic_cipher(wbsm4_wsise, WBSM4_WSISE, cfb128, CFB, 0, 2274560,
                         8, 128, stream);
#endif /* OPENSSL_NO_WBSM4_WSISE */
