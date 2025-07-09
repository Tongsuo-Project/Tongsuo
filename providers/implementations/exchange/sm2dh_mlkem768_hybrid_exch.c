/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
/*
 * A test implementation for a hybrid KEM combining DH with SM2Curve and ML-KEM-768
 * keyexchange functions
 */

#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/core_dispatch.h>

#include "crypto/sm2dh_mlkem768_hybrid.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"


static OSSL_FUNC_keyexch_newctx_fn                  sm2dh_mlkem768_hybrid_newctx;
static OSSL_FUNC_keyexch_freectx_fn                 sm2dh_mlkem768_hybrid_freectx;
static OSSL_FUNC_keyexch_init_fn                    sm2dh_mlkem768_hybrid_init;
static OSSL_FUNC_keyexch_set_peer_fn                sm2dh_mlkem768_hybrid_set_peer;
static OSSL_FUNC_keyexch_derive_fn                  sm2dh_mlkem768_hybrid_derive;
static OSSL_FUNC_keyexch_set_ctx_params_fn          sm2dh_mlkem768_hybrid_set_ctx_params;
static OSSL_FUNC_keyexch_settable_ctx_params_fn     sm2dh_mlkem768_hybrid_settable_ctx_params;
static OSSL_FUNC_keyexch_get_ctx_params_fn          sm2dh_mlkem768_hybrid_get_ctx_params;
static OSSL_FUNC_keyexch_gettable_ctx_params_fn     sm2dh_mlkem768_hybrid_gettable_ctx_params;

struct sm2dh_mlkem768_hybrid_keyexch_ctx {
    sm2dh_mlkem768_hybrid_key * k;
    sm2dh_mlkem768_hybrid_key * peer_k;
    OSSL_LIB_CTX * libctx;
};

static void * sm2dh_mlkem768_hybrid_newctx(void * provctx)
{
    struct sm2dh_mlkem768_hybrid_keyexch_ctx * ctx;
    if (!ossl_prov_is_running())
        return NULL;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    ctx->libctx = PROV_LIBCTX_OF(provctx);
    return (void *)ctx;
}

static void sm2dh_mlkem768_hybrid_freectx(void * vctx)
{
    struct sm2dh_mlkem768_hybrid_keyexch_ctx * ctx = vctx;
    OPENSSL_free(ctx);
}

static int sm2dh_mlkem768_hybrid_init(void * vctx, void * vkey, const OSSL_PARAM params[])
{
    struct sm2dh_mlkem768_hybrid_keyexch_ctx * ctx = vctx;
    if (!ossl_prov_is_running() || vctx == NULL || vkey == NULL)
        return 0;
    ctx->k = (sm2dh_mlkem768_hybrid_key *)vkey;
    return 1;
}

static int sm2dh_mlkem768_hybrid_set_peer(void * vctx, void * vkey)
{
    struct sm2dh_mlkem768_hybrid_keyexch_ctx * ctx = vctx;
    if(!ossl_prov_is_running() || vctx == NULL || vkey == NULL)
        return 0;
    ctx->peer_k = (sm2dh_mlkem768_hybrid_key *)vkey;
    return 1;
}

static int sm2dh_mlkem768_hybrid_derive(void * vpctx, unsigned char * secret, size_t * psecret_len, size_t outlen)
{
    struct sm2dh_mlkem768_hybrid_keyexch_ctx * ctx = vpctx;
    if(ctx->k == NULL || ctx->peer_k == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;     
    }

    if(outlen == 0)
    {
        * psecret_len = SM2_DH_MLKEM_768_HYBRID_SS_SIZE;
        return 1;
    }

    if(ctx->k->has_kem_sk) {
        /* client: call the decapsulation algorithm */
        if(!sm2dh_mlkem768_hybrid_decaps(ctx->libctx, secret, SM2_DH_MLKEM_768_HYBRID_SS_SIZE, ctx->peer_k->ct, SM2_DH_MLKEM_768_HYBRID_CT_SIZE, ctx->k->sk, SM2_DH_MLKEM_768_HYBRID_SK_SIZE))
            return 0;
    } else {
        /* server: get the shared secret directly */
        memcpy(secret, ctx->k->ss, SM2_DH_MLKEM_768_HYBRID_SS_SIZE);
    }
    * psecret_len = SM2_DH_MLKEM_768_HYBRID_SS_SIZE;
    return 1;
}

static const OSSL_PARAM * sm2dh_mlkem768_hybrid_settable_ctx_params(ossl_unused void * vpctx, ossl_unused void * provctx)
{
    return NULL;
}

static int sm2dh_mlkem768_hybrid_set_ctx_params(void * vpctx, const OSSL_PARAM params[])
{
    return 1;
}

static const OSSL_PARAM * sm2dh_mlkem768_hybrid_gettable_ctx_params(ossl_unused void * vpctx, ossl_unused void * provctx)
{
    return NULL;
}

static int sm2dh_mlkem768_hybrid_get_ctx_params(void * vpctx, OSSL_PARAM params[])
{
    return 1;
}

const OSSL_DISPATCH ossl_sm2dh_mlkem768_hybrid_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX,                 (void (*)(void))sm2dh_mlkem768_hybrid_newctx },
    { OSSL_FUNC_KEYEXCH_FREECTX,                (void (*)(void))sm2dh_mlkem768_hybrid_freectx },
    { OSSL_FUNC_KEYEXCH_INIT,                   (void (*)(void))sm2dh_mlkem768_hybrid_init },
    { OSSL_FUNC_KEYEXCH_SET_PEER,               (void (*)(void))sm2dh_mlkem768_hybrid_set_peer },
    { OSSL_FUNC_KEYEXCH_DERIVE,                 (void (*)(void))sm2dh_mlkem768_hybrid_derive },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,    (void (*)(void))sm2dh_mlkem768_hybrid_settable_ctx_params },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,         (void (*)(void))sm2dh_mlkem768_hybrid_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,    (void (*)(void))sm2dh_mlkem768_hybrid_gettable_ctx_params },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,         (void (*)(void))sm2dh_mlkem768_hybrid_get_ctx_params },
    { 0, NULL }
};
