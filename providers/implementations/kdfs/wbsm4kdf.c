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

#if !defined(OPENSSL_NO_WBSM4_XIAO_STKEY) || !defined(OPENSSL_NO_WBSM4_JIN_STKEY) || \
    !defined(OPENSSL_NO_WBSM4_XIAO_DYKEY)
#include "crypto/wbsm4.h"
/*
* KDF 上下文：存储原始密钥、白盒类型，以及各自的上下文
*/
typedef struct {
unsigned char rawkey[16];  /* SM4 128-bit key */
wbsm4_xiao_stkey_context stctx;
} WBSM4_KDF_CTX;

/* ---------- KDF接口函数声明 ---------- */
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

/* ---------- OSSL_DISPATCH 映射表 ---------- */
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

/*
* 向外暴露的算法描述 (供 provider_init 中使用)
*/
const OSSL_ALGORITHM wbsm4kdf_algorithm[] = {
    { "WBSM4KDF", "provider=tongsuo", wbsm4kdf_functions },
    { NULL, NULL, NULL }
};

/* ---------- 函数实现 ---------- */

/* 1) 构造上下文 */
static void *wbsm4kdf_new(void *provctx)
{
    WBSM4_KDF_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    memset(ctx->rawkey, 0, sizeof(ctx->rawkey));
    ctx->stctx.mode = WBSM4_ENCRYPT_MODE;
    return ctx;
}

/* 2) 释放上下文 */
static void wbsm4kdf_free(void *vctx)
{
    WBSM4_KDF_CTX *ctx = (WBSM4_KDF_CTX *)vctx;
    if (ctx != NULL) {
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

/* 3) 重置上下文 */
static void wbsm4kdf_reset(void *vctx)
{
    WBSM4_KDF_CTX *ctx = (WBSM4_KDF_CTX *)vctx;
    if (ctx != NULL) {
        memset(ctx->rawkey, 0, sizeof(ctx->rawkey));
    //  memset(ctx->stctx, 0, sizeof(ctx->stctx));
        ctx->stctx.mode = WBSM4_ENCRYPT_MODE;
    }
}

/* 4) 执行派生操作 */
static int wbsm4kdf_derive(void *vctx,
                        unsigned char *key, size_t keylen,
                        const OSSL_PARAM params[])
{
    WBSM4_KDF_CTX *ctx = (WBSM4_KDF_CTX *)vctx;

    /* 若传入了额外 params，则先解析 */
    if (!wbsm4kdf_set_ctx_params(ctx, params))
        return 0;

    wbsm4_xiao_stkey_gen(ctx->rawkey, &ctx->stctx);
    if (keylen < sizeof(ctx->stctx)) {
        return 0;
    }
    memcpy(key, &ctx->stctx, sizeof(ctx->stctx));

    return 1; /* 派生成功 */
}

/* 5) 告知可设置哪些参数 */
static const OSSL_PARAM *wbsm4kdf_settable_ctx_params(void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_octet_string("wbsm4_key", NULL, 0),   /* 设置原始SM4密钥(16字节) */
        OSSL_PARAM_utf8_string("wbsm4_type", NULL, 0),   /* "dykey" or "stkey" */
        OSSL_PARAM_utf8_string("mode", NULL, 0),         /* "encrypt" or "decrypt" */
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

/* 6) 设置参数 */
static int wbsm4kdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    WBSM4_KDF_CTX *ctx = (WBSM4_KDF_CTX *)vctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    for (p = params; p->key != NULL; p++) {
        if (strcmp(p->key, "wbsm4_key") == 0) {
            /* 原始SM4密钥 */
            if (p->data_type != OSSL_PARAM_OCTET_STRING) return 0;
            if (p->data_size != 16) return 0;
            memcpy(ctx->rawkey, p->data, 16);
        } else if (strcmp(p->key, "mode") == 0) {
            /* 加解密模式 */
            if (p->data_type != OSSL_PARAM_UTF8_STRING) return 0;
            if (strcmp((const char *)p->data, "decrypt") == 0) {
                ctx->stctx.mode = WBSM4_DECRYPT_MODE;
            } else {
                ctx->stctx.mode = WBSM4_ENCRYPT_MODE;
            }
        }
    }
    return 1;
}

 /* 7) 告知可获取哪些参数（可选） */
 static const OSSL_PARAM *wbsm4kdf_gettable_ctx_params(void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

/* 8) 获取参数（可选实现） */
static int wbsm4kdf_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    /* 如果需要返回当前 type、mode 等，可在此实现 */
    (void)vctx;
    (void)params;
    return 1;
}

#endif
