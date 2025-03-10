/*
 * wbsm4kdf.c - A custom KDF that uses WBSM4 (xiao_stkey) internally.
 * Place in: providers/implementations/kdfs/wbsm4kdf.c
 */

#include <stdio.h>
#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>

#if !defined(OPENSSL_NO_WBSM4_XIAO_STKEY) || !defined(OPENSSL_NO_WBSM4_JIN_STKEY) \
|| !defined(OPENSSL_NO_WBSM4_XIAO_DYKEY)
#include "crypto/sm4.h"
#include "crypto/wbsm4.h"

typedef struct {
    void *provctx;
    unsigned char rawkey[SM4_BLOCK_SIZE];
    unsigned char *cipher;
    size_t len_wbsm4_type;
    int mode;
    union {
#ifndef OPENSSL_NO_WBSM4_XIAO_STKEY
        wbsm4_xiao_stkey_context ks_xiao_stkey;
#endif
#ifndef OPENSSL_NO_WBSM4_JIN_STKEY
        wbsm4_jin_stkey_context ks_jin_stkey;
#endif
#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
        wbsm4_xiao_dykey_context ks_xiao_dykey;
#endif
    } wbctx;
#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
    int update_key;
    wbsm4_xiao_dykey_ctxrk ctxrk;
#endif
} WBSM4_KDF_CTX;

static void *wbsm4kdf_new(void *provctx);
static void wbsm4kdf_free(void *vctx);
static void wbsm4kdf_reset(void *vctx);
static int wbsm4kdf_derive(void *vctx,
                        unsigned char *key, size_t keylen,
                        const OSSL_PARAM params[]);
static const OSSL_PARAM *wbsm4kdf_settable_ctx_params(void *provctx);
static int wbsm4kdf_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
static const OSSL_PARAM *wbsm4kdf_gettable_ctx_params(void *provctx);
static int wbsm4kdf_get_ctx_params(void *vctx, OSSL_PARAM params[]);

/* ---------- OSSL_DISPATCH table ---------- */
const OSSL_DISPATCH wbsm4kdf_functions[] = {
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

/* ---------- functions ---------- */
static void *wbsm4kdf_new(void *provctx)
{
    WBSM4_KDF_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ctx->provctx = provctx;
    OPENSSL_cleanse(&ctx->wbctx, sizeof(ctx->wbctx));
#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
    OPENSSL_cleanse(&ctx->ctxrk, sizeof(ctx->ctxrk));
#endif
    return ctx;
}

static void wbsm4kdf_free(void *vctx)
{
    WBSM4_KDF_CTX *ctx = (WBSM4_KDF_CTX *)vctx;
    if (ctx != NULL) {
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

static void wbsm4kdf_reset(void *vctx)
{
    WBSM4_KDF_CTX *ctx = (WBSM4_KDF_CTX *)vctx;
    if (ctx != NULL) {
        void *provctx = ctx->provctx;
        OPENSSL_cleanse(&ctx->rawkey, sizeof(ctx->rawkey));
        OPENSSL_cleanse(&ctx->wbctx, sizeof(ctx->wbctx));
#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
        OPENSSL_cleanse(&ctx->ctxrk, sizeof(ctx->ctxrk));
#endif
        ctx->provctx = provctx;
    }
}

/* 4) 执行派生操作 */
static int wbsm4kdf_derive(void *vctx,
                        unsigned char *key, size_t keylen,
                        const OSSL_PARAM params[])
{
    WBSM4_KDF_CTX *ctx = (WBSM4_KDF_CTX *)vctx;

    if (!wbsm4kdf_set_ctx_params(ctx, params))
        return 0;
    if (ctx->cipher == NULL) return 0;

#ifndef OPENSSL_NO_WBSM4_XIAO_STKEY
    if (OPENSSL_strcasecmp((char *)ctx->cipher, "WBSM4-XIAO-STKEY") == 0) {
        if (keylen != sizeof(wbsm4_xiao_stkey_context)) {
            OPENSSL_cleanse(&ctx->rawkey, sizeof(ctx->rawkey));
            return 0;
        }

        if (key == NULL) {
            return 0;
        }
        ctx->wbctx.ks_xiao_stkey.mode = ctx->mode;
        wbsm4_xiao_stkey_gen(ctx->rawkey, &ctx->wbctx.ks_xiao_stkey);
        wbsm4_export_key(&ctx->wbctx.ks_xiao_stkey, key, sizeof(wbsm4_xiao_stkey_context));
        OPENSSL_cleanse(&ctx->rawkey, sizeof(ctx->rawkey));

        return 1;
    } else
#endif
#ifndef OPENSSL_NO_WBSM4_JIN_STKEY
    if (OPENSSL_strcasecmp((char *)ctx->cipher, "WBSM4-JIN-STKEY") == 0) {
        if (keylen != sizeof(wbsm4_jin_stkey_context)) {
            OPENSSL_cleanse(&ctx->rawkey, sizeof(ctx->rawkey));
            return 0;
        }

        if (key == NULL) {
            return 0;
        }
        ctx->wbctx.ks_jin_stkey.mode = ctx->mode;
        wbsm4_jin_stkey_gen(ctx->rawkey, &ctx->wbctx.ks_jin_stkey);
        wbsm4_export_key(&ctx->wbctx.ks_jin_stkey, key, sizeof(wbsm4_jin_stkey_context));
        OPENSSL_cleanse(&ctx->rawkey, sizeof(ctx->rawkey));

        return 1;
    } else
#endif
#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
    if (OPENSSL_strcasecmp((char *)ctx->cipher, "WBSM4-XIAO-DYKEY") == 0) {
        if (ctx->update_key) {
            if (keylen != 32 * sizeof(uint32_t)) {
                OPENSSL_cleanse(&ctx->rawkey, sizeof(ctx->rawkey));
                return 0;
            }
            if (key == NULL) {
                return 0;
            }

            uint32_t wbrk[32];
            wbsm4_xiao_dykey_key2wbrk(ctx->rawkey, &ctx->ctxrk, wbrk);
            wbsm4_export_key((void *)wbrk, key, 32 * sizeof(uint32_t));
            OPENSSL_cleanse(&ctx->rawkey, sizeof(ctx->rawkey));

            return 1;
        }

        if (keylen != sizeof(wbsm4_xiao_dykey_context)) {
            OPENSSL_cleanse(&ctx->rawkey, sizeof(ctx->rawkey));
            return 0;
        }

        if (key == NULL) {
            return 0;
        }
        ctx->wbctx.ks_xiao_dykey.mode = ctx->mode;
        wbsm4_xiao_dykey_gen(ctx->rawkey, &ctx->wbctx.ks_xiao_dykey, &ctx->ctxrk);
        wbsm4_export_key(&ctx->wbctx.ks_xiao_dykey, key, sizeof(wbsm4_xiao_dykey_context));
        OPENSSL_cleanse(&ctx->rawkey, sizeof(ctx->rawkey));

        return 1;
    } else
#endif
    {
        OPENSSL_cleanse(&ctx->rawkey, sizeof(ctx->rawkey));
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *wbsm4kdf_settable_ctx_params(void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),
#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
        OSSL_PARAM_int(OSSL_KDF_PARAM_WBSM4_UPDATE_KEY, NULL),
#endif
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int wbsm4kdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    WBSM4_KDF_CTX *ctx = (WBSM4_KDF_CTX *)vctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) return 0;
        if (p->data_size != SM4_BLOCK_SIZE) return 0;
        if (p->data == NULL) return 0;
        memcpy(ctx->rawkey, p->data, SM4_BLOCK_SIZE);
    }

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_CIPHER);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING) return 0;
        if (p->data == NULL) return 0;
        ctx->cipher = p->data;
    }

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_MODE);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_INTEGER) return 0;
        ctx->mode = *(int*)(p->data);
    }

#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_WBSM4_UPDATE_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_INTEGER) return 0;
        ctx->update_key = *(int*)(p->data);
    }
#endif

    return 1;
}

 static const OSSL_PARAM *wbsm4kdf_gettable_ctx_params(void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static int wbsm4kdf_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    WBSM4_KDF_CTX *ctx = (WBSM4_KDF_CTX *)vctx;
    OSSL_PARAM *p;
    size_t keylen = 0;

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p != NULL) {
        if (ctx->cipher == NULL)
            keylen = 0;
#ifndef OPENSSL_NO_WBSM4_XIAO_STKEY
        else if (OPENSSL_strcasecmp((char *)ctx->cipher, "WBSM4-XIAO-STKEY") == 0)
            keylen = sizeof(wbsm4_xiao_stkey_context);
#endif
#ifndef OPENSSL_NO_WBSM4_JIN_STKEY
        else if (OPENSSL_strcasecmp((char *)ctx->cipher, "WBSM4-JIN-STKEY") == 0)
            keylen = sizeof(wbsm4_jin_stkey_context);
#endif
#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
        else if (OPENSSL_strcasecmp((char *)ctx->cipher, "WBSM4-XIAO-DYKEY") == 0)
            keylen = sizeof(wbsm4_xiao_dykey_context);
#endif
    }

    if (keylen != 0)
        return OSSL_PARAM_set_size_t(p, keylen);

    return 0;
}

#endif
