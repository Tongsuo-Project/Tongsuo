/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <string.h> /* memset */
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/proverr.h>
#include "internal/sizes.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"

#include "crypto/ml_dsa.h"
#include "prov/der_ml_dsa.h"

static OSSL_FUNC_signature_newctx_fn ml_dsa_newctx;
static OSSL_FUNC_signature_sign_init_fn ml_dsa_sign_init;
static OSSL_FUNC_signature_verify_init_fn ml_dsa_verify_init;
static OSSL_FUNC_signature_sign_fn ml_dsa_sign;
static OSSL_FUNC_signature_verify_fn ml_dsa_verify;
static OSSL_FUNC_signature_freectx_fn ml_dsa_freectx;
static OSSL_FUNC_signature_dupctx_fn ml_dsa_dupctx;
static OSSL_FUNC_signature_digest_sign_init_fn ml_dsa_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn ml_dsa_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn ml_dsa_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn ml_dsa_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn ml_dsa_digest_signverify_update;
static OSSL_FUNC_signature_digest_verify_final_fn ml_dsa_digest_verify_final;
static OSSL_FUNC_signature_get_ctx_params_fn ml_dsa_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn ml_dsa_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn ml_dsa_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn ml_dsa_settable_ctx_params;

typedef struct {
    ML_DSA_KEY *key;
    OSSL_LIB_CTX *libctx;
    uint8_t context_string[ML_DSA_CONTEXT_STRING_BYTES];
    size_t context_string_len;
    int deterministic;

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;

    EVP_MD *md;
    EVP_MD_CTX *mdctx;

    int operation;
} PROV_ML_DSA_CTX;

static void *ml_dsa_newctx(void *provctx, const char *propq)
{
    PROV_ML_DSA_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_ML_DSA_CTX));
    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->md = EVP_MD_fetch(ctx->libctx, "SHAKE-256", propq);
    if (ctx->md == NULL) {
        ml_dsa_freectx(ctx);
        return NULL;
    }
    return ctx;
}

static void ml_dsa_freectx(void *vctx)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;

    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    OPENSSL_cleanse(ctx->context_string, ctx->context_string_len);
    OPENSSL_free(ctx);
}

static void *ml_dsa_dupctx(void *vctx)
{
    PROV_ML_DSA_CTX *srcctx = (PROV_ML_DSA_CTX *)vctx;
    PROV_ML_DSA_CTX *dstctx;

    if (!ossl_prov_is_running())
        return NULL;

    dstctx = OPENSSL_memdup(srcctx, sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md)) {
        ml_dsa_freectx(dstctx);
        return NULL;
    }
    dstctx->md = srcctx->md;

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx)) {
            ml_dsa_freectx(dstctx);
            return NULL;
        }
    }

    return dstctx;
}

static int ml_dsa_signverify_init(void *vctx, void *vkey,
                                 const OSSL_PARAM params[], int operation)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;

    if (!ossl_prov_is_running() || ctx == NULL)
        return 0;

    if (vkey == NULL && ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (vkey != NULL)
        ctx->key = vkey;

    ctx->operation = operation;
    ctx->deterministic = 0;
    memset(ctx->context_string, 0, sizeof(ctx->context_string));
    ctx->context_string_len = 0;

    if (!ml_dsa_set_ctx_params(ctx, params))
        return 0;

    return 1;
}

static int ml_dsa_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    if (!ossl_prov_is_running())
        return 0;
    return ml_dsa_signverify_init(vctx, vkey, params, EVP_PKEY_OP_SIGN);
}

static int ml_dsa_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    if (!ossl_prov_is_running())
        return 0;
    return ml_dsa_signverify_init(vctx, vkey, params, EVP_PKEY_OP_VERIFY);
}

static int ml_dsa_digest_signverify_init(void *vctx, const char *mdname,
                                         void *vkey, const OSSL_PARAM params[],
                                        int operation)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    WPACKET pkt;

    if (!ml_dsa_signverify_init(vctx, vkey, params, operation))
        return 0;

    if (mdname != NULL && mdname[0] != '\0') {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "Explicit digest not supported for ML-DSA operations");
        return 0;
    }

    /*
     * We do not care about DER writing errors.
     * All it really means is that for some reason, there's no
     * AlgorithmIdentifier to be had, but the operation itself is
     * still valid, just as long as it's not used to construct
     * anything that needs an AlgorithmIdentifier.
     */
    ctx->aid_len = 0;
    if (WPACKET_init_der(&pkt, ctx->aid_buf, sizeof(ctx->aid_buf))
        && ossl_DER_w_algorithmIdentifier_ML_DSA(&pkt, -1, ctx->key)
        && WPACKET_finish(&pkt)) {
        WPACKET_get_total_written(&pkt, &ctx->aid_len);
        ctx->aid = WPACKET_get_curr(&pkt);
    }
    WPACKET_cleanup(&pkt);
    if (ctx->aid != NULL && ctx->aid_len != 0)
        memmove(ctx->aid_buf, ctx->aid, ctx->aid_len);

    return 1;
}

static int ml_dsa_digest_sign_init(void *vctx, const char *mdname,
                                         void *vkey, const OSSL_PARAM params[])
{
    if (!ossl_prov_is_running())
        return 0;
    return ml_dsa_digest_signverify_init(vctx, mdname, vkey, params, EVP_PKEY_OP_SIGN);
}

static int ml_dsa_digest_verify_init(void *vctx, const char *mdname,
                                         void *vkey, const OSSL_PARAM params[])
{
    if (!ossl_prov_is_running())
        return 0;
    return ml_dsa_digest_signverify_init(vctx, mdname, vkey, params, EVP_PKEY_OP_VERIFY);
}

static int ml_dsa_sign(void *vctx, unsigned char *sig, size_t *siglen,
                      size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    size_t ml_dsa_size = ML_DSA_SIGBYTES;
    int ret = 0;

    if (!ossl_prov_is_running())
        return 0;

    if (sig == NULL) {
        *siglen = ml_dsa_size;
        return 1;
    }

    if (sigsize < ml_dsa_size)
        return 0;

    ret = crypto_sign_signature(sig, siglen, tbs, tbslen, \
        ctx->context_string, ctx->context_string_len, ctx->deterministic, ctx->key->privkey);
    return (ret == 0) ? 1 : 0;
}

static int ml_dsa_verify(void *vctx, const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    int ret = 0;

    if (!ossl_prov_is_running())
        return 0;

    ret = crypto_sign_verify(sig, siglen, tbs, tbslen, \
        ctx->context_string, ctx->context_string_len, ctx->key->pubkey);
    return (ret == 0) ? 1 : 0;
}

int ml_dsa_digest_signverify_update(void *vctx, const unsigned char *data,
                                   size_t datalen)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;

    if (ctx == NULL)
        return 0;

    if (ctx->mdctx == NULL) {
        ctx->mdctx = pqcrystals_ml_dsa_init_mu(ctx->key, ctx->md,
                                                ctx->context_string, ctx->context_string_len);
        if (ctx->mdctx == NULL)
            return 0;
    }

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

int ml_dsa_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen,
                            size_t sigsize)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    uint8_t mu[ML_DSA_CRHBYTES];
    uint8_t rnd[ML_DSA_RNDBYTES];
    size_t ml_dsa_size = ML_DSA_SIGBYTES;
    int ret = 0;

    if (!ossl_prov_is_running() || ctx == NULL)
        return 0;
    if (sig == NULL) {
        *siglen = ml_dsa_size;
        return 1;
    }

    if (sigsize < ml_dsa_size)
        return 0;

    if (ctx->mdctx == NULL || !EVP_DigestFinalXOF(ctx->mdctx, mu, sizeof(mu)))
        return 0;

    if (ctx->deterministic)
        memset(rnd, 0, ML_DSA_RNDBYTES);
    else
        RAND_bytes(rnd, ML_DSA_RNDBYTES);

    ret = crypto_sign_signature_internal(sig, siglen, mu, rnd, ctx->key->privkey);
    return (ret == 0) ? 1 : 0;
}

int ml_dsa_digest_verify_final(void *vctx, const unsigned char *sig,
                              size_t siglen)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    uint8_t mu[ML_DSA_CRHBYTES];
    int ret = 0;

    if (!ossl_prov_is_running() || ctx == NULL || ctx->mdctx == NULL)
        return 0;

    if (!EVP_DigestFinalXOF(ctx->mdctx, mu, sizeof(mu)))
        return 0;

    ret = crypto_sign_verify_internal(sig, siglen, mu, ctx->key->pubkey);
    return (ret == 0) ? 1 : 0;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ml_dsa_gettable_ctx_params(ossl_unused void *vctx,
                                                   ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

static int ml_dsa_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID)) != NULL) {
        if (!OSSL_PARAM_set_octet_string(p, ctx->aid_len == 0 ? NULL : ctx->aid_buf, ctx->aid_len)) {
            ctx->aid_len = 0;
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ml_dsa_settable_ctx_params(void *vctx,
                                                   ossl_unused void *provctx)
{
    return settable_ctx_params;
}

static int ml_dsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING)) != NULL) {
        void *vp = ctx->context_string;
        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(ctx->context_string),
                                         &(ctx->context_string_len))) {
            ctx->context_string_len = 0;
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC)) != NULL) {
        if (!OSSL_PARAM_get_int(p, &ctx->deterministic)) {
            ctx->deterministic = 0;
            return 0;
        }
    }

    return 1;
}

const OSSL_DISPATCH ossl_ml_dsa_65_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))ml_dsa_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ml_dsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))ml_dsa_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))ml_dsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ml_dsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))ml_dsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))ml_dsa_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ml_dsa_freectx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))ml_dsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))ml_dsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))ml_dsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))ml_dsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))ml_dsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))ml_dsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))ml_dsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))ml_dsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))ml_dsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))ml_dsa_gettable_ctx_params },
    { 0, NULL }
};
