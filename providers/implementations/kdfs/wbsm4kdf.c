/*
* Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
*/

/*
 * wbsm4kdf.c - A custom KDF that uses WBSM4 (xiao_dykey) internally.
 * Place in: providers/implementations/kdfs/wbsm4kdf.c
 */

#include <stdio.h>
#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/proverr.h>
#include "prov/providercommon.h"
#include "prov/implementations.h"

#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
#include "crypto/sm4.h"
#include "crypto/wbsm4.h"

static OSSL_FUNC_kdf_newctx_fn wbsm4kdf_new;
static OSSL_FUNC_kdf_freectx_fn wbsm4kdf_free;
static OSSL_FUNC_kdf_reset_fn wbsm4kdf_reset;
static OSSL_FUNC_kdf_derive_fn wbsm4kdf_derive;
static OSSL_FUNC_kdf_settable_ctx_params_fn wbsm4kdf_settable_ctx_params;
static OSSL_FUNC_kdf_set_ctx_params_fn wbsm4kdf_set_ctx_params;
static OSSL_FUNC_kdf_gettable_ctx_params_fn wbsm4kdf_gettable_ctx_params;
static OSSL_FUNC_kdf_get_ctx_params_fn wbsm4kdf_get_ctx_params;

typedef struct {
    void *provctx;
    unsigned char *rawkey;
    size_t rawkey_len;
    int mode;
    int update_key;
    wbsm4_xiao_dykey_context wbctx;
    wbsm4_xiao_dykey_ctxrk ctxrk;
} WBSM4_KDF_CTX;

/* ---------- functions ---------- */
static void *wbsm4kdf_new(void *provctx)
{
    WBSM4_KDF_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;
    
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ctx->provctx = provctx;
    return ctx;
}

static void wbsm4kdf_free(void *vctx)
{
    WBSM4_KDF_CTX *ctx = (WBSM4_KDF_CTX *)vctx;
    if (ctx != NULL) {
        wbsm4kdf_reset(ctx);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

static void wbsm4kdf_reset(void *vctx)
{
    WBSM4_KDF_CTX *ctx = (WBSM4_KDF_CTX *)vctx;
    void *provctx = ctx->provctx;

    OPENSSL_clear_free(ctx->rawkey, ctx->rawkey_len);
    OPENSSL_cleanse(&ctx->wbctx, sizeof(ctx->wbctx));
    OPENSSL_cleanse(&ctx->ctxrk, sizeof(ctx->ctxrk));
    memset(ctx, 0, sizeof(*ctx));
    ctx->provctx = provctx;
}

/* 4) 执行派生操作 */
static int wbsm4kdf_derive(void *vctx,
                        unsigned char *key, size_t keylen,
                        const OSSL_PARAM params[])
{
    WBSM4_KDF_CTX *ctx = (WBSM4_KDF_CTX *)vctx;

    if (!ossl_prov_is_running() || !wbsm4kdf_set_ctx_params(ctx, params))
        return 0;

    if (ctx->rawkey == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    if (key == NULL) {
        OPENSSL_cleanse(&ctx->rawkey, ctx->rawkey_len);
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    if (ctx->mode == EVP_KDF_WBSM4KDF_MODE_UPDATE_KEY) {
        if (keylen != SM4_KEY_SCHEDULE * sizeof(uint32_t)) {
            OPENSSL_cleanse(&ctx->rawkey, ctx->rawkey_len);
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }

        uint32_t wbrk[SM4_KEY_SCHEDULE];
        wbsm4_xiao_dykey_key2wbrk(ctx->rawkey, &ctx->ctxrk, wbrk);
        wbsm4_export_key((void *)wbrk, key, keylen);
        OPENSSL_cleanse(&ctx->rawkey, ctx->rawkey_len);

        return 1;
    }
    else if (ctx->mode == EVP_KDF_WBSM4KDF_MODE_ENCRYPT || ctx->mode == EVP_KDF_WBSM4KDF_MODE_DECRYPT) {
        if (keylen != sizeof(wbsm4_xiao_dykey_context)) {
            OPENSSL_cleanse(&ctx->rawkey, ctx->rawkey_len);
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }

        if (ctx->mode == EVP_KDF_WBSM4KDF_MODE_ENCRYPT)
            ctx->wbctx.mode = WBSM4_ENCRYPT_MODE;
        else
            ctx->wbctx.mode = WBSM4_DECRYPT_MODE;
        wbsm4_xiao_dykey_gen(ctx->rawkey, &ctx->wbctx, &ctx->ctxrk);
        wbsm4_export_key(&ctx->wbctx, key, sizeof(wbsm4_xiao_dykey_context));
        OPENSSL_cleanse(&ctx->rawkey, ctx->rawkey_len);
    
        return 1;
    }

    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
    return 0;
}

static const OSSL_PARAM *wbsm4kdf_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),
        OSSL_PARAM_int(OSSL_KDF_PARAM_WBSM4_UPDATE_KEY, NULL),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int wbsm4kdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    WBSM4_KDF_CTX *ctx = (WBSM4_KDF_CTX *)vctx;
    const OSSL_PARAM *p;
    int n;

    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY)) != NULL) {
        OPENSSL_clear_free(ctx->rawkey, ctx->rawkey_len);
        ctx->rawkey = NULL;
        ctx->rawkey_len = 0;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->rawkey, 0,
                                         &ctx->rawkey_len))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE)) != NULL) {
        if (p->data_type != OSSL_PARAM_INTEGER) return 0;
        if (OSSL_PARAM_get_int(p, &n)) {
            if (n != EVP_KDF_WBSM4KDF_MODE_DECRYPT
                && n != EVP_KDF_WBSM4KDF_MODE_ENCRYPT
                && n != EVP_KDF_WBSM4KDF_MODE_UPDATE_KEY) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
                return 0;
            }
            ctx->mode = n;
        } else {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
            return 0;
        }
    }

    return 1;
}

 static const OSSL_PARAM *wbsm4kdf_gettable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static int wbsm4kdf_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, sizeof(wbsm4_xiao_dykey_context));

    return -2;
}

/* ---------- OSSL_DISPATCH table ---------- */
const OSSL_DISPATCH ossl_kdf_wbsm4kdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX,              (void (*)(void))wbsm4kdf_new },
    { OSSL_FUNC_KDF_FREECTX,             (void (*)(void))wbsm4kdf_free },
    { OSSL_FUNC_KDF_RESET,               (void (*)(void))wbsm4kdf_reset },
    { OSSL_FUNC_KDF_DERIVE,              (void (*)(void))wbsm4kdf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))wbsm4kdf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS,      (void (*)(void))wbsm4kdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))wbsm4kdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS,      (void (*)(void))wbsm4kdf_get_ctx_params },
    { 0, NULL }
};

#endif
