/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/proverr.h>
#include <openssl/sm3.h>
#include "internal/sizes.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"

#include "crypto/sm2_mldsa65_hybrid.h"
#include "prov/der_sm2_mldsa65_hybrid.h"

static OSSL_FUNC_signature_newctx_fn sm2_mldsa65_hybrid_newctx;
static OSSL_FUNC_signature_sign_init_fn sm2_mldsa65_hybrid_signverify_init;
static OSSL_FUNC_signature_verify_init_fn sm2_mldsa65_hybrid_signverify_init;
static OSSL_FUNC_signature_sign_fn sm2_mldsa65_hybrid_sign;
static OSSL_FUNC_signature_verify_fn sm2_mldsa65_hybrid_verify;
static OSSL_FUNC_signature_digest_sign_init_fn sm2_mldsa65_hybrid_digest_signverify_init;
static OSSL_FUNC_signature_digest_sign_update_fn sm2_mldsa65_hybrid_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn sm2_mldsa65_hybrid_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn sm2_mldsa65_hybrid_digest_signverify_init;
static OSSL_FUNC_signature_digest_verify_update_fn sm2_mldsa65_hybrid_digest_signverify_update;
static OSSL_FUNC_signature_digest_verify_final_fn sm2_mldsa65_hybrid_digest_verify_final;
static OSSL_FUNC_signature_freectx_fn sm2_mldsa65_hybrid_freectx;
static OSSL_FUNC_signature_dupctx_fn sm2_mldsa65_hybrid_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn sm2_mldsa65_hybrid_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn sm2_mldsa65_hybrid_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn sm2_mldsa65_hybrid_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn sm2_mldsa65_hybrid_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn sm2_mldsa65_hybrid_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn sm2_mldsa65_hybrid_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn sm2_mldsa65_hybrid_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn sm2_mldsa65_hybrid_settable_ctx_md_params;

static const uint8_t SM2_MLDSA65_HYBRID_PREFIX[SM2_MLDSA65_HYBRID_PREFIX_SIZE + 1] = "CompositeAlgorithmSignatures2025";
static const uint8_t SM2_MLDSA65_HYBRID_DOMAIN[SM2_MLDSA65_HYBRID_DOMAIN_SIZE] = {
    0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x09, 0x01, 0x15
};

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    SM2_MLDSA65_HYBRID_KEY *key;

    uint8_t context_string[SM2_MLDSA65_HYBRID_MAX_CONTEXT_STRING_BYTES];
    size_t context_string_len;

    char mdname[OSSL_MAX_NAME_SIZE];

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    size_t mdsize;

    /* SM2 ID used for calculating the Z value */
    unsigned char *id;
    size_t id_len;
} PROV_SM2_MLDSA65_HYBRID_CTX;

static void *sm2_mldsa65_hybrid_newctx(void *provctx, const char *propq)
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_SM2_MLDSA65_HYBRID_CTX));
    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(ctx);
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->mdsize = SM3_DIGEST_LENGTH;
    strcpy(ctx->mdname, OSSL_DIGEST_NAME_SM3);
    return ctx;
}

static void sm2_mldsa65_hybrid_freectx(void *vctx)
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;

    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    ctx->mdctx = NULL;
    ctx->md = NULL;
    OPENSSL_cleanse(ctx->context_string, sizeof(ctx->context_string));
    OPENSSL_free(ctx);
}

static void *sm2_mldsa65_hybrid_dupctx(void *vctx)
{
    PROV_SM2_MLDSA65_HYBRID_CTX *srcctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;
    PROV_SM2_MLDSA65_HYBRID_CTX *dstctx;

    dstctx = OPENSSL_memdup(srcctx, sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))
            goto err;
    }

    if (srcctx->id != NULL) {
        dstctx->id = OPENSSL_malloc(srcctx->id_len);
        if (dstctx->id == NULL)
            goto err;
        dstctx->id_len = srcctx->id_len;
        memcpy(dstctx->id, srcctx->id, srcctx->id_len);
    }

    return dstctx;
 err:
    sm2_mldsa65_hybrid_freectx(dstctx);
    return NULL;
}

static int sm2_mldsa65_hybrid_signverify_init(void *vctx, void *vkey,
                                 const OSSL_PARAM params[])
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;

    if (!ossl_prov_is_running()
            || ctx == NULL)
        return 0;

    if (vkey == NULL && ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (vkey != NULL) {
        ctx->key = vkey;
    }

    return sm2_mldsa65_hybrid_set_ctx_params(ctx, params);
}

static int evp_signverify_common(int operation, EVP_PKEY *key, const EVP_MD *md,
                            uint8_t *sig, size_t *siglen, size_t sigsize,
                            const uint8_t *context, size_t contextlen,
                            const uint8_t *id, size_t idlen,
                            const uint8_t *rnd, size_t rndlen,
                            const uint8_t *tbs, size_t tbslen)
{
    int ret = 0;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM params[2], *p = params;

    if ((mctx = EVP_MD_CTX_new()) == NULL)
        goto err;

    if (operation == EVP_PKEY_OP_SIGN) {
        if (!EVP_DigestSignInit(mctx, &pctx, md, NULL, key))
            goto err;
    } else {
        if (!EVP_DigestVerifyInit(mctx, &pctx, md, NULL, key))
            goto err;
    }

    if (EVP_PKEY_get_id(key) == SM2_MLDSA65_HYBRID_QID) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, \
                                            (void*)SM2_MLDSA65_HYBRID_DOMAIN, SM2_MLDSA65_HYBRID_DOMAIN_SIZE);
        *p = OSSL_PARAM_construct_end();
        if (!EVP_PKEY_CTX_set_params(pctx, params))
            goto err;
    } else if (EVP_PKEY_get_id(key) == EVP_PKEY_SM2) {
        if (id != NULL && EVP_PKEY_CTX_set1_id(pctx, id, idlen) <= 0)
            goto err;
    }

    /* m' = prefix | domain(OID) | len(ctx) | ctx | rnd | H(m) */
    if (!EVP_DigestUpdate(mctx, SM2_MLDSA65_HYBRID_PREFIX, SM2_MLDSA65_HYBRID_PREFIX_SIZE)
         || !EVP_DigestUpdate(mctx, SM2_MLDSA65_HYBRID_DOMAIN, SM2_MLDSA65_HYBRID_DOMAIN_SIZE)
         || !EVP_DigestUpdate(mctx, &contextlen, 1)
         || !EVP_DigestUpdate(mctx, context, contextlen)
         || !EVP_DigestUpdate(mctx, rnd, rndlen)
         || !EVP_DigestUpdate(mctx, tbs, tbslen))
        goto err;

    if (operation == EVP_PKEY_OP_SIGN) {
        if (!EVP_DigestSignFinal(mctx, sig, siglen))
            goto err;
    } else {
        if (EVP_DigestVerifyFinal(mctx, sig, sigsize) <= 0)
            goto err;
    }

    ret = 1;
err:
    EVP_MD_CTX_free(mctx);
    return ret;
}

static int sm2_mldsa65_hybrid_sign(void *vctx, unsigned char *sig, size_t *siglen,
                       size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    int ret_mldsa = 0, ret_sm2 = 0;
    size_t sl_mldsa = MLDSA_SIG_SIZE, sl_sm2 = SM2_SIG_SIZE;
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;
    size_t hybrid_size = SM2_MLDSA65_HYBRID_SIG_SIZE;
    uint8_t *rnd = NULL, *mldsa_sig = NULL, *sm2_sig = NULL;

    if (sig == NULL) {
        *siglen = hybrid_size;
        return 1;
    }

    if (sigsize < hybrid_size) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE,
                "is %zu, should be at least %zu", sigsize, *siglen);
        return 0;
    }

    if (ctx->mdsize != 0 && tbslen != ctx->mdsize)
        return 0;

    /* Composite Signature: rnd | mldsa_sig | sm2_sig */
    rnd = sig;
    mldsa_sig = rnd + SM2_MLDSA65_HYBRID_RANDOM_BYTES;
    sm2_sig = mldsa_sig + MLDSA_SIG_SIZE;

    if (!RAND_bytes(rnd, SM2_MLDSA65_HYBRID_RANDOM_BYTES))
        return 0;

    /* mldsa sign */
    ret_mldsa = evp_signverify_common(EVP_PKEY_OP_SIGN, ctx->key->mldsa_key, NULL,
                                mldsa_sig, &sl_mldsa, MLDSA_SIG_SIZE,
                                ctx->context_string, ctx->context_string_len,
                                ctx->id, ctx->id_len,
                                rnd, SM2_MLDSA65_HYBRID_RANDOM_BYTES, tbs, tbslen);

    /* sm2 sign */
    ret_sm2 = evp_signverify_common(EVP_PKEY_OP_SIGN, ctx->key->sm2_key, ctx->md,
                                sm2_sig, &sl_sm2, SM2_SIG_SIZE,
                                ctx->context_string, ctx->context_string_len,
                                ctx->id, ctx->id_len,
                                rnd, SM2_MLDSA65_HYBRID_RANDOM_BYTES, tbs, tbslen);

    if (!ret_mldsa || !ret_sm2)
        return 0;

    *siglen = SM2_MLDSA65_HYBRID_RANDOM_BYTES + sl_mldsa + sl_sm2;

    return 1;
}

static int sm2_mldsa65_hybrid_verify(void *vctx, const unsigned char *sig, size_t siglen,
                         const unsigned char *tbs, size_t tbslen)
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;
    uint8_t *rnd = NULL, *mldsa_sig = NULL, *sm2_sig = NULL;

    if (ctx->mdsize != 0 && tbslen != ctx->mdsize)
        return 0;

    /* Composite Signature: rnd | mldsa_sig | sm2_sig */
    rnd = (uint8_t*)sig;
    mldsa_sig = rnd + SM2_MLDSA65_HYBRID_RANDOM_BYTES;
    sm2_sig = mldsa_sig + MLDSA_SIG_SIZE;

    /* mldsa verify */
    if (!evp_signverify_common(EVP_PKEY_OP_VERIFY, ctx->key->mldsa_key, NULL,
                                mldsa_sig, NULL, MLDSA_SIG_SIZE,
                                ctx->context_string, ctx->context_string_len,
                                ctx->id, ctx->id_len,
                                rnd, SM2_MLDSA65_HYBRID_RANDOM_BYTES, tbs, tbslen))
        return 0;

    /* sm2 verify */
    return evp_signverify_common(EVP_PKEY_OP_VERIFY, ctx->key->sm2_key, ctx->md,
                                sm2_sig, NULL, siglen - SM2_MLDSA65_HYBRID_RANDOM_BYTES - MLDSA_SIG_SIZE,
                                ctx->context_string, ctx->context_string_len,
                                ctx->id, ctx->id_len,
                                rnd, SM2_MLDSA65_HYBRID_RANDOM_BYTES, tbs, tbslen);
}

static int sm2_mldsa65_hybrid_set_mdname(PROV_SM2_MLDSA65_HYBRID_CTX *ctx, const char *mdname)
{
    if (ctx->md == NULL) /* We need an SM3 md to compare with */
        ctx->md = EVP_MD_fetch(ctx->libctx, ctx->mdname,
                                   ctx->propq);
    if (ctx->md == NULL)
        return 0;

    if (mdname == NULL)
        return 1;

    if (strlen(mdname) >= sizeof(ctx->mdname)
        || !EVP_MD_is_a(ctx->md, mdname)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST, "digest=%s",
                       mdname);
        return 0;
    }

    OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
    return 1;
}

static int sm2_mldsa65_hybrid_digest_signverify_init(void *vctx, const char *mdname,
                                         void *vkey, const OSSL_PARAM params[])
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;
    int md_nid;
    WPACKET pkt;
    int ret = 0;

    if (!sm2_mldsa65_hybrid_signverify_init(vctx, vkey, params)
        || !sm2_mldsa65_hybrid_set_mdname(ctx, mdname))
        return ret;

    if (ctx->mdctx == NULL) {
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL)
            goto error;
    }

    md_nid = EVP_MD_get_type(ctx->md);

    /*
     * We do not care about DER writing errors.
     * All it really means is that for some reason, there's no
     * AlgorithmIdentifier to be had, but the operation itself is
     * still valid, just as long as it's not used to construct
     * anything that needs an AlgorithmIdentifier.
     */
    ctx->aid_len = 0;
    if (WPACKET_init_der(&pkt, ctx->aid_buf, sizeof(ctx->aid_buf))
        && ossl_DER_w_algorithmIdentifier_SM2_MLDSA65_HYBRID_with_MD(&pkt, -1, ctx->key, md_nid)
        && WPACKET_finish(&pkt)) {
        WPACKET_get_total_written(&pkt, &ctx->aid_len);
        ctx->aid = WPACKET_get_curr(&pkt);
    }
    WPACKET_cleanup(&pkt);

    if (!EVP_DigestInit_ex2(ctx->mdctx, ctx->md, params))
        goto error;

    ret = 1;

 error:
    return ret;
}

int sm2_mldsa65_hybrid_digest_signverify_update(void *vctx, const unsigned char *data,
                                    size_t datalen)
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;

    if (ctx == NULL || ctx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

int sm2_mldsa65_hybrid_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen,
                             size_t sigsize)
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (ctx == NULL || ctx->mdctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to sm2_mldsa65_hybrid_sign.
     */
    if (sig != NULL) {
        if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
            return 0;
    }

    return sm2_mldsa65_hybrid_sign(vctx, sig, siglen, sigsize, digest, (size_t)dlen);
}

int sm2_mldsa65_hybrid_digest_verify_final(void *vctx, const unsigned char *sig,
                               size_t siglen)
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (ctx == NULL || ctx->mdctx == NULL
        || EVP_MD_get_size(ctx->md) > (int)sizeof(digest))
        return 0;

    if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;

    return sm2_mldsa65_hybrid_verify(vctx, sig, siglen, digest, (size_t)dlen);
}

static int sm2_mldsa65_hybrid_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, ctx->aid, ctx->aid_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->mdsize))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->md == NULL
                                                    ? ctx->mdname
                                                    : EVP_MD_get0_name(ctx->md)))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sm2_mldsa65_hybrid_gettable_ctx_params(ossl_unused void *vctx,
                                                    ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

static int sm2_mldsa65_hybrid_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;
    const OSSL_PARAM *p;
    size_t mdsize;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p != NULL) {
        void *vp = ctx->context_string;
        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(ctx->context_string),
                                         &(ctx->context_string_len))) {
            ctx->context_string_len = 0;
            return 0;
        }
    }

    /*
     * The following code checks that the size is the same as the SM3 digest
     * size returning an error otherwise.
     * If there is ever any different digest algorithm allowed with SM2
     * this needs to be adjusted accordingly.
     */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && (!OSSL_PARAM_get_size_t(p, &mdsize)
                      || mdsize != ctx->mdsize))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        char *mdname = NULL;

        if (!OSSL_PARAM_get_utf8_string(p, &mdname, 0))
            return 0;
        if (!sm2_mldsa65_hybrid_set_mdname(ctx, mdname)) {
            OPENSSL_free(mdname);
            return 0;
        }
        OPENSSL_free(mdname);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DIST_ID);
    if (p != NULL) {
        void *tmp_id = NULL;
        size_t tmp_idlen = 0;

        if (p->data_size != 0
            && !OSSL_PARAM_get_octet_string(p, &tmp_id, 0, &tmp_idlen))
            return 0;
        OPENSSL_free(ctx->id);
        ctx->id = tmp_id;
        ctx->id_len = tmp_idlen;
    }

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DIST_ID, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sm2_mldsa65_hybrid_settable_ctx_params(ossl_unused void *vctx,
                                                    ossl_unused void *provctx)
{
    return known_settable_ctx_params;
}

static int sm2_mldsa65_hybrid_get_ctx_md_params(void *vctx, OSSL_PARAM *params)
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;

    if (ctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(ctx->mdctx, params);
}

static const OSSL_PARAM *sm2_mldsa65_hybrid_gettable_ctx_md_params(void *vctx)
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;

    if (ctx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(ctx->md);
}

static int sm2_mldsa65_hybrid_set_ctx_md_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;

    if (ctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(ctx->mdctx, params);
}

static const OSSL_PARAM *sm2_mldsa65_hybrid_settable_ctx_md_params(void *vctx)
{
    PROV_SM2_MLDSA65_HYBRID_CTX *ctx = (PROV_SM2_MLDSA65_HYBRID_CTX *)vctx;

    if (ctx->md == NULL)
        return 0;

    return EVP_MD_settable_ctx_params(ctx->md);
}

const OSSL_DISPATCH ossl_sm2_mldsa65_hybrid_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sm2_mldsa65_hybrid_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))sm2_mldsa65_hybrid_signverify_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))sm2_mldsa65_hybrid_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))sm2_mldsa65_hybrid_signverify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))sm2_mldsa65_hybrid_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))sm2_mldsa65_hybrid_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))sm2_mldsa65_hybrid_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))sm2_mldsa65_hybrid_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))sm2_mldsa65_hybrid_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))sm2_mldsa65_hybrid_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))sm2_mldsa65_hybrid_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sm2_mldsa65_hybrid_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))sm2_mldsa65_hybrid_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))sm2_mldsa65_hybrid_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))sm2_mldsa65_hybrid_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))sm2_mldsa65_hybrid_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))sm2_mldsa65_hybrid_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))sm2_mldsa65_hybrid_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))sm2_mldsa65_hybrid_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))sm2_mldsa65_hybrid_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))sm2_mldsa65_hybrid_settable_ctx_md_params },
    { 0, NULL }
};
