/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/* Dispatch functions for zuc_128_eea3 cipher */

#include <openssl/proverr.h>
#include "cipher_zuc_eea3.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

#define ZUC_EEA3_KEYLEN (ZUC_KEY_SIZE)
#define ZUC_EEA3_BLKLEN (1)
#define ZUC_EEA3_IVLEN (ZUC_CTR_SIZE)
#define ZUC_EEA3_FLAGS (PROV_CIPHER_FLAG_VARIABLE_LENGTH)

static OSSL_FUNC_cipher_newctx_fn zuc_128_eea3_newctx;
static OSSL_FUNC_cipher_freectx_fn zuc_128_eea3_freectx;
static OSSL_FUNC_cipher_get_params_fn zuc_128_eea3_get_params;
static OSSL_FUNC_cipher_get_ctx_params_fn zuc_128_eea3_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn zuc_128_eea3_set_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn zuc_128_eea3_gettable_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn zuc_128_eea3_settable_ctx_params;
#define zuc_128_eea3_cipher ossl_cipher_generic_cipher
#define zuc_128_eea3_update ossl_cipher_generic_stream_update
#define zuc_128_eea3_final ossl_cipher_generic_stream_final
#define zuc_128_eea3_gettable_params ossl_cipher_generic_gettable_params

static void *zuc_128_eea3_newctx(void *provctx)
{
    PROV_ZUC_EEA3_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ossl_cipher_generic_initkey(ctx, ZUC_EEA3_KEYLEN * 8,
                                    ZUC_EEA3_BLKLEN * 8,
                                    ZUC_EEA3_IVLEN * 8,
                                    0, ZUC_EEA3_FLAGS,
                                    ossl_prov_cipher_hw_zuc_128_eea3(ZUC_EEA3_KEYLEN * 8),
                                    NULL);
    return ctx;
}

static void zuc_128_eea3_freectx(void *vctx)
{
    PROV_CIPHER_HW_ZUC_EEA3 *hw;
    PROV_ZUC_EEA3_CTX *ctx = (PROV_ZUC_EEA3_CTX *)vctx;

    if (ctx != NULL) {
        hw = (PROV_CIPHER_HW_ZUC_EEA3 *)((PROV_CIPHER_CTX *)vctx)->hw;
        hw->cleanup(ctx);
        ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

static int zuc_128_eea3_get_params(OSSL_PARAM params[])
{
    return ossl_cipher_generic_get_params(params, 0, ZUC_EEA3_FLAGS,
                                          ZUC_EEA3_KEYLEN * 8,
                                          ZUC_EEA3_BLKLEN * 8,
                                          ZUC_EEA3_IVLEN * 8);
}

static int zuc_128_eea3_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ZUC_EEA3_IVLEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ZUC_EEA3_KEYLEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    return 1;
}

static const OSSL_PARAM zuc_128_eea3_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_END
};
const OSSL_PARAM *zuc_128_eea3_gettable_ctx_params(ossl_unused void *cctx,
                                               ossl_unused void *provctx)
{
    return zuc_128_eea3_known_gettable_ctx_params;
}

static int zuc_128_eea3_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    size_t len;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != ZUC_EEA3_KEYLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != ZUC_EEA3_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM zuc_128_eea3_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_END
};
const OSSL_PARAM *zuc_128_eea3_settable_ctx_params(ossl_unused void *cctx,
                                               ossl_unused void *provctx)
{
    return zuc_128_eea3_known_settable_ctx_params;
}

int ossl_zuc_128_eea3_einit(void *vctx, const unsigned char *key, size_t keylen,
                        const unsigned char *iv, size_t ivlen,
                        const OSSL_PARAM params[])
{
    int ret;
    PROV_CIPHER_CTX *ctx;
    PROV_CIPHER_HW_ZUC_EEA3 *hw;

    /* The generic function checks for ossl_prov_is_running() */
    ret = ossl_cipher_generic_einit(vctx, key, keylen, iv, ivlen, NULL);
    if (ret && iv != NULL) {
        ctx = (PROV_CIPHER_CTX *)vctx;
        hw = (PROV_CIPHER_HW_ZUC_EEA3 *)ctx->hw;
        hw->initiv(ctx);
    }
    if (ret && !zuc_128_eea3_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

int ossl_zuc_128_eea3_dinit(void *vctx, const unsigned char *key, size_t keylen,
                        const unsigned char *iv, size_t ivlen,
                        const OSSL_PARAM params[])
{
    int ret;
    PROV_CIPHER_CTX *ctx;
    PROV_CIPHER_HW_ZUC_EEA3 *hw;

    /* The generic function checks for ossl_prov_is_running() */
    ret = ossl_cipher_generic_dinit(vctx, key, keylen, iv, ivlen, NULL);
    if (ret && iv != NULL) {
        ctx = (PROV_CIPHER_CTX *)vctx;
        hw = (PROV_CIPHER_HW_ZUC_EEA3 *)ctx->hw;
        hw->initiv(ctx);
    }
    if (ret && !zuc_128_eea3_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

/* ossl_zuc_128_eea3_functions */
const OSSL_DISPATCH ossl_zuc_128_eea3_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))zuc_128_eea3_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))zuc_128_eea3_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))ossl_zuc_128_eea3_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))ossl_zuc_128_eea3_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))zuc_128_eea3_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))zuc_128_eea3_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))zuc_128_eea3_cipher},
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))zuc_128_eea3_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        (void (*)(void))zuc_128_eea3_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
        (void (*)(void))zuc_128_eea3_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))zuc_128_eea3_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
        (void (*)(void))zuc_128_eea3_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        (void (*)(void))zuc_128_eea3_settable_ctx_params },
    { 0, NULL }
};

