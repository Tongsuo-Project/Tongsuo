/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 1999-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "internal/cryptlib.h"
#include "prov/providercommon.h"

#if !defined(OPENSSL_NO_WBSM4_XIAOLAI) || !defined(OPENSSL_NO_WBSM4_BAIWU) || \
    !defined(OPENSSL_NO_WBSM4_WSISE)
#include "crypto/wbsm4.h"

static OSSL_FUNC_kdf_newctx_fn kdf_wbsm4_new;
static OSSL_FUNC_kdf_freectx_fn kdf_wbsm4_free;
static OSSL_FUNC_kdf_reset_fn kdf_wbsm4_reset;
static OSSL_FUNC_kdf_derive_fn kdf_wbsm4_derive;
static OSSL_FUNC_kdf_settable_ctx_params_fn kdf_wbsm4_settable_ctx_params;
static OSSL_FUNC_kdf_set_ctx_params_fn kdf_wbsm4_set_ctx_params;
static OSSL_FUNC_kdf_gettable_ctx_params_fn kdf_wbsm4_gettable_ctx_params;
static OSSL_FUNC_kdf_get_ctx_params_fn kdf_wbsm4_get_ctx_params;

typedef struct {
    void *provctx;
    unsigned char *key;
    size_t key_len;
    unsigned char *cipher;
    size_t cipher_len;
} KDF_WBSM4;

static void *kdf_wbsm4_new(void *provctx)
{
    KDF_WBSM4 *ctx;

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

static void kdf_wbsm4_cleanup(KDF_WBSM4 *ctx)
{
    if (ctx->cipher)
        OPENSSL_free(ctx->cipher);
    if (ctx->key)
        OPENSSL_cleanse(ctx->key, ctx->key_len);
    memset(ctx, 0, sizeof(*ctx));
}

static void kdf_wbsm4_free(void *vctx)
{
    KDF_WBSM4 *ctx = (KDF_WBSM4 *)vctx;

    if (ctx != NULL) {
        kdf_wbsm4_cleanup(ctx);
        OPENSSL_free(ctx);
    }
}

static void kdf_wbsm4_reset(void *vctx)
{
    KDF_WBSM4 *ctx = (KDF_WBSM4 *)vctx;
    void *provctx = ctx->provctx;

    kdf_wbsm4_cleanup(ctx);
    ctx->provctx = provctx;
}

static int kdf_wbsm4_set_membuf(unsigned char **buffer, size_t *buflen,
                                const OSSL_PARAM *p)
{
    OPENSSL_clear_free(*buffer, *buflen);
    *buffer = NULL;
    *buflen = 0;

    if (p->data_size == 0) {
        if ((*buffer = OPENSSL_zalloc(1)) == NULL) {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    } else if (p->data != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, (char **)buffer, *buflen))
            return 0;
    }
    return 1;
}

static int kdf_wbsm4_derive(void *vctx, unsigned char *key, size_t keylen,
                            const OSSL_PARAM params[])
{
    KDF_WBSM4 *ctx = (KDF_WBSM4 *)vctx;

    if (!ossl_prov_is_running() || !kdf_wbsm4_set_ctx_params(ctx, params))
        return 0;

    if (ctx->cipher == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CIPHER);
        return 0;
    }

    if (ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    if (ctx->key_len != 32) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }

    unsigned char sm4key[16];
    size_t sm4key_len = sizeof(sm4key);
    if (!OPENSSL_hexstr2buf_ex(sm4key, sm4key_len, &sm4key_len,
                               (const char *)ctx->key, 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

#ifndef OPENSSL_NO_WBSM4_XIAOLAI
    if (OPENSSL_strcasecmp((char *)ctx->cipher, "WBSM4-XIAOLAI") == 0) {
        if (keylen != sizeof(wbsm4_xiaolai_key)) {
            OPENSSL_cleanse(sm4key, sm4key_len);
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            return 0;
        }

        if (key == NULL) {
            OPENSSL_cleanse(sm4key, sm4key_len);
            return 1;
        }

        wbsm4_xiaolai_key *wbsm4key = OPENSSL_zalloc(sizeof(wbsm4_xiaolai_key));
        if (wbsm4key == NULL) {
            OPENSSL_cleanse(sm4key, sm4key_len);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }

        wbsm4_xiaolai_gen(sm4key, wbsm4key);
        wbsm4_xiaolai_export_key(wbsm4key, key);

        OPENSSL_cleanse(sm4key, sm4key_len);
        OPENSSL_cleanse(wbsm4key, sizeof(wbsm4_xiaolai_key));

        return 1;
    } else 
#endif /* OPENSSL_NO_WBSM4_XIAOLAI */
#ifndef OPENSSL_NO_WBSM4_BAIWU
    if (OPENSSL_strcasecmp((char *)ctx->cipher, "WBSM4-BAIWU") == 0) {
        if (keylen != sizeof(wbsm4_baiwu_key)) {
            OPENSSL_cleanse(sm4key, sm4key_len);
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            return 0;
        }

        if (key == NULL) {
            OPENSSL_cleanse(sm4key, sm4key_len);
            return 1;
        }

        wbsm4_baiwu_key *wbsm4key = OPENSSL_zalloc(sizeof(wbsm4_baiwu_key));
        if (wbsm4key == NULL) {
            OPENSSL_cleanse(sm4key, sm4key_len);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }

        wbsm4_baiwu_gen(sm4key, wbsm4key);
        wbsm4_baiwu_export_key(wbsm4key, key);

        OPENSSL_cleanse(sm4key, sm4key_len);
        OPENSSL_cleanse(wbsm4key, sizeof(wbsm4_baiwu_key));

        return 1;
    } else 
#endif /* OPENSSL_NO_WBSM4_BAIWU */
#ifndef OPENSSL_NO_WBSM4_WSISE
    if (OPENSSL_strcasecmp((char *)ctx->cipher, "WBSM4-WSISE") == 0) {
        if (keylen != sizeof(wbsm4_wsise_key)) {
            OPENSSL_cleanse(sm4key, sm4key_len);
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            return 0;
        }

        if (key == NULL) {
            OPENSSL_cleanse(sm4key, sm4key_len);
            return 1;
        }

        wbsm4_wsise_key *wbsm4key = OPENSSL_zalloc(sizeof(wbsm4_wsise_key));
        if (wbsm4key == NULL) {
            OPENSSL_cleanse(sm4key, sm4key_len);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }

        wbsm4_wsise_gen(sm4key, wbsm4key);
        wbsm4_wsise_export_key(wbsm4key, key);

        OPENSSL_cleanse(sm4key, sm4key_len);
        OPENSSL_cleanse(wbsm4key, sizeof(wbsm4_wsise_key));

        return 1;
    } else
#endif /* OPENSSL_NO_WBSM4_WSISE */
    {
        OPENSSL_cleanse(sm4key, sm4key_len);
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CIPHER);
        return 0;
    }
}

static int kdf_wbsm4_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    KDF_WBSM4 *ctx = vctx;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY)) != NULL) {
        if (!kdf_wbsm4_set_membuf(&ctx->key, &ctx->key_len, p))
            return 0;
        ctx->key_len = strlen((char *)ctx->key);
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_CIPHER)) != NULL) {
        if (!kdf_wbsm4_set_membuf(&ctx->cipher, &ctx->cipher_len, p))
            return 0;
        ctx->cipher_len = strlen((char *)ctx->cipher);
    }

    return 1;
}

static const OSSL_PARAM *kdf_wbsm4_settable_ctx_params(ossl_unused void *ctx,
                                                       ossl_unused void *p_ctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int kdf_wbsm4_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    KDF_WBSM4 *ctx = (KDF_WBSM4 *)vctx;

    OSSL_PARAM *p;
    size_t keylen = 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL) {
        if (ctx->cipher == NULL)
            keylen = 0;
#ifndef OPENSSL_NO_WBSM4_XIAOLAI
        else if (OPENSSL_strcasecmp((char *)ctx->cipher, "WBSM4-XIAOLAI") == 0)
            keylen = sizeof(wbsm4_xiaolai_key);
#endif
#ifndef OPENSSL_NO_WBSM4_BAIWU
        else if (OPENSSL_strcasecmp((char *)ctx->cipher, "WBSM4-BAIWU") == 0)
            keylen = sizeof(wbsm4_baiwu_key);
#endif
#ifndef OPENSSL_NO_WBSM4_WSISE
        else if (OPENSSL_strcasecmp((char *)ctx->cipher, "WBSM4-WSISE") == 0)
            keylen = sizeof(wbsm4_wsise_key);
#endif
    }

    if (keylen != 0)
        return OSSL_PARAM_set_size_t(p, keylen);

    return -2;
}

static const OSSL_PARAM *kdf_wbsm4_gettable_ctx_params(ossl_unused void *ctx,
                                                       ossl_unused void *p_ctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

const OSSL_DISPATCH ossl_kdf_wbsm4_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))kdf_wbsm4_new},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))kdf_wbsm4_free},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))kdf_wbsm4_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))kdf_wbsm4_derive},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
     (void (*)(void))kdf_wbsm4_settable_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))kdf_wbsm4_set_ctx_params},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
     (void (*)(void))kdf_wbsm4_gettable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))kdf_wbsm4_get_ctx_params},
    {0, NULL}
};
#endif
