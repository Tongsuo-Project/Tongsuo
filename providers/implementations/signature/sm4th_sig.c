/*
 * Copyright 2023-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include "crypto/sm4th.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"

#ifndef OPENSSL_NO_SM4TH

typedef struct {
    SM4TH_KEY *key;
    OSSL_LIB_CTX *libctx;
    int variant;
    unsigned char test_rho[SM4TH_S_RANDLEN_BYTES];
    size_t test_rho_len;
} PROV_SM4TH_CTX;

static void sm4th_freectx(void *vctx)
{
    PROV_SM4TH_CTX *ctx = vctx;

    if (ctx == NULL)
        return;
    OPENSSL_cleanse(ctx->test_rho, sizeof(ctx->test_rho));
    OPENSSL_free(ctx);
}

static void *sm4th_newctx(void *provctx, int variant)
{
    PROV_SM4TH_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->variant = variant;
    return ctx;
}

static void *sm4th_dupctx(void *vctx)
{
    PROV_SM4TH_CTX *src = vctx;

    if (!ossl_prov_is_running() || src == NULL)
        return NULL;
    return OPENSSL_memdup(src, sizeof(*src));
}

static int sm4th_signverify_init(void *vctx, void *vkey,
                                 const OSSL_PARAM params[])
{
    PROV_SM4TH_CTX *ctx = vctx;
    SM4TH_KEY *key = vkey;

    if (!ossl_prov_is_running() || ctx == NULL)
        return 0;
    if (key == NULL && ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }
    if (key != NULL) {
        if (tons_sm4th_key_get_variant(key) != ctx->variant)
            return 0;
        ctx->key = key;
    }
    if (params != NULL) {
        const OSSL_PARAM *p =
            OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY);
        if (p != NULL) {
            void *vp = ctx->test_rho;
            size_t max = tons_sm4th_key_get_randomness_len(ctx->key);

            if (max > sizeof(ctx->test_rho))
                max = sizeof(ctx->test_rho);
            if (!OSSL_PARAM_get_octet_string(p, &vp, max, &ctx->test_rho_len)) {
                ctx->test_rho_len = 0;
                return 0;
            }
        }
    }
    return 1;
}

static int sm4th_sign_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return sm4th_signverify_init(vctx, vkey, params);
}

static int sm4th_verify_msg_init(void *vctx, void *vkey,
                                 const OSSL_PARAM params[])
{
    return sm4th_signverify_init(vctx, vkey, params);
}

static int sm4th_digest_signverify_init(void *vctx, const char *mdname,
                                        void *vkey, const OSSL_PARAM params[])
{
    if (mdname != NULL && mdname[0] != '\0') {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "Explicit digest not supported for SM4th");
        return 0;
    }
    return sm4th_signverify_init(vctx, vkey, params);
}

static int sm4th_sign(void *vctx, unsigned char *sig, size_t *siglen,
                      size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    PROV_SM4TH_CTX *ctx = vctx;
    unsigned char seed[SM4TH_SEED_BYTES];
    size_t seedlen;
    size_t outlen;
    int ret;

    if (!ossl_prov_is_running() || ctx == NULL || ctx->key == NULL
        || siglen == NULL)
        return 0;

    outlen = tons_sm4th_key_get_sig_len(ctx->key);
    if (sig == NULL) {
        *siglen = outlen;
        return 1;
    }
    if (sigsize < outlen)
        return 0;

    seedlen = tons_sm4th_key_get_randomness_len(ctx->key);
    if (seedlen != SM4TH_SEED_BYTES)
        return 0;

    if (ctx->test_rho_len != 0) {
        if (ctx->test_rho_len < seedlen)
            return 0;
        memcpy(seed, ctx->test_rho, seedlen);
    } else if (RAND_priv_bytes_ex(ctx->libctx, seed, (int)seedlen, 0) <= 0) {
        return 0;
    }

    *siglen = sigsize;
    ret = tons_sm4th_sign(ctx->key, tbs, tbslen, seed, seedlen, sig, siglen);
    OPENSSL_cleanse(seed, sizeof(seed));
    return ret;
}

static int sm4th_verify(void *vctx, const unsigned char *sig, size_t siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    PROV_SM4TH_CTX *ctx = vctx;

    if (!ossl_prov_is_running() || ctx == NULL || ctx->key == NULL)
        return 0;
    return tons_sm4th_verify(ctx->key, tbs, tbslen, sig, siglen);
}

static int sm4th_digest_sign(void *vctx, unsigned char *sig, size_t *siglen,
                             size_t sigsize, const unsigned char *tbs,
                             size_t tbslen)
{
    return sm4th_sign(vctx, sig, siglen, sigsize, tbs, tbslen);
}

static int sm4th_digest_verify(void *vctx, const unsigned char *sig,
                               size_t siglen, const unsigned char *tbs,
                               size_t tbslen)
{
    return sm4th_verify(vctx, sig, siglen, tbs, tbslen);
}

static int sm4th_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_SM4TH_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY);
    if (p != NULL) {
        void *vp = ctx->test_rho;
        size_t max = sizeof(ctx->test_rho);

        if (!OSSL_PARAM_get_octet_string(p, &vp, max, &ctx->test_rho_len)) {
            ctx->test_rho_len = 0;
            return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM *sm4th_settable_ctx_params(ossl_unused void *vctx,
                                                   ossl_unused void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

#define MAKE_SM4TH_SIG(sfx, variant)                                           \
    static void *sm4th_##sfx##_newctx(void *provctx, const char *propq)        \
    {                                                                          \
        (void)propq;                                                           \
        return sm4th_newctx(provctx, variant);                                 \
    }                                                                          \
    const OSSL_DISPATCH ossl_sm4th_##sfx##_signature_functions[] = {           \
        { OSSL_FUNC_SIGNATURE_NEWCTX,                                          \
          (void (*)(void))sm4th_##sfx##_newctx },                              \
        { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sm4th_freectx },        \
        { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))sm4th_dupctx },          \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,                               \
          (void (*)(void))sm4th_sign_msg_init },                               \
        { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))sm4th_sign },              \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,                             \
          (void (*)(void))sm4th_verify_msg_init },                             \
        { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))sm4th_verify },          \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,                                \
          (void (*)(void))sm4th_digest_signverify_init },                      \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,                                     \
          (void (*)(void))sm4th_digest_sign },                                 \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,                              \
          (void (*)(void))sm4th_digest_signverify_init },                      \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,                                   \
          (void (*)(void))sm4th_digest_verify },                               \
        { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,                                  \
          (void (*)(void))sm4th_set_ctx_params },                              \
        { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,                             \
          (void (*)(void))sm4th_settable_ctx_params },                         \
        OSSL_DISPATCH_END                                                      \
    }

MAKE_SM4TH_SIG(f, SM4TH_VARIANT_F);
MAKE_SM4TH_SIG(s, SM4TH_VARIANT_S);

#endif /* OPENSSL_NO_SM4TH */
