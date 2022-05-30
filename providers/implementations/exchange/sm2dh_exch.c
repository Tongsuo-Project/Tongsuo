/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * SM2DH low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/securitycheck.h"
#include "crypto/evp.h"
#include "crypto/ec.h"
#include "crypto/sm2.h"

static OSSL_FUNC_keyexch_newctx_fn sm2dh_newctx;
static OSSL_FUNC_keyexch_init_fn sm2dh_init;
static OSSL_FUNC_keyexch_set_peer_fn sm2dh_set_peer;
static OSSL_FUNC_keyexch_derive_fn sm2dh_derive;
static OSSL_FUNC_keyexch_freectx_fn sm2dh_freectx;
static OSSL_FUNC_keyexch_dupctx_fn sm2dh_dupctx;
static OSSL_FUNC_keyexch_set_ctx_params_fn sm2dh_set_ctx_params;
static OSSL_FUNC_keyexch_settable_ctx_params_fn sm2dh_settable_ctx_params;
static OSSL_FUNC_keyexch_get_ctx_params_fn sm2dh_get_ctx_params;
static OSSL_FUNC_keyexch_gettable_ctx_params_fn sm2dh_gettable_ctx_params;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes EC_KEY structures, so
 * we use that here too.
 */

typedef struct {
    OSSL_LIB_CTX *libctx;

    EC_KEY *k;
    EC_KEY *peerk;

    /* private key in self encryption certificate */
    EC_KEY *enc_k;
    /* public key in peer encryption certificate */
    EC_KEY *enc_peerk;

    uint8_t *id;
    size_t id_len;

    uint8_t *peer_id;
    size_t peer_id_len;

    int initiator;

    EVP_MD *md;

    size_t outlen;
} PROV_SM2DH_CTX;

static
void *sm2dh_newctx(void *provctx)
{
    PROV_SM2DH_CTX *pectx;

    if (!ossl_prov_is_running())
        return NULL;

    pectx = OPENSSL_zalloc(sizeof(*pectx));
    if (pectx == NULL)
        return NULL;

    pectx->libctx = PROV_LIBCTX_OF(provctx);

    return (void *)pectx;
}

static
int ecdh_match_params(const EC_KEY *priv, const EC_KEY *peer)
{
    int ret;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group_priv = EC_KEY_get0_group(priv);
    const EC_GROUP *group_peer = EC_KEY_get0_group(peer);

    ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(priv));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = group_priv != NULL
          && group_peer != NULL
          && EC_GROUP_cmp(group_priv, group_peer, ctx) == 0;
    if (!ret)
        ERR_raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS);
    BN_CTX_free(ctx);
    return ret;
}

static
int sm2dh_init(void *vpecdhctx, void *vecdh, const OSSL_PARAM params[])
{
    PROV_SM2DH_CTX *pecdhctx = (PROV_SM2DH_CTX *)vpecdhctx;

    if (!ossl_prov_is_running()
            || pecdhctx == NULL
            || vecdh == NULL
            || !EC_KEY_up_ref(vecdh))
        return 0;

    EC_KEY_free(pecdhctx->k);
    pecdhctx->k = vecdh;

    return sm2dh_set_ctx_params(pecdhctx, params)
           && ossl_ec_check_key(pecdhctx->libctx, vecdh, 1)
           && pecdhctx->enc_k != NULL
           && pecdhctx->enc_peerk != NULL
           && ecdh_match_params(pecdhctx->enc_k, pecdhctx->enc_peerk)
           && ossl_ec_check_key(pecdhctx->libctx, pecdhctx->enc_k, 1)
           && ossl_ec_check_key(pecdhctx->libctx, pecdhctx->enc_peerk, 1);
}

static
int sm2dh_set_peer(void *vpecdhctx, void *vecdh)
{
    PROV_SM2DH_CTX *pecdhctx = (PROV_SM2DH_CTX *)vpecdhctx;

    if (!ossl_prov_is_running()
            || pecdhctx == NULL
            || vecdh == NULL
            || !ecdh_match_params(pecdhctx->k, vecdh)
            || !ossl_ec_check_key(pecdhctx->libctx, vecdh, 1)
            || !EC_KEY_up_ref(vecdh))
        return 0;

    EC_KEY_free(pecdhctx->peerk);
    pecdhctx->peerk = vecdh;
    return 1;
}

static
void sm2dh_freectx(void *vpecdhctx)
{
    PROV_SM2DH_CTX *pecdhctx = (PROV_SM2DH_CTX *)vpecdhctx;

    EC_KEY_free(pecdhctx->k);
    EC_KEY_free(pecdhctx->peerk);

    EC_KEY_free(pecdhctx->enc_k);
    EC_KEY_free(pecdhctx->enc_peerk);

    OPENSSL_free(pecdhctx->id);
    OPENSSL_free(pecdhctx->peer_id);

    EVP_MD_free(pecdhctx->md);

    OPENSSL_free(pecdhctx);
}

static
void *sm2dh_dupctx(void *vpecdhctx)
{
    PROV_SM2DH_CTX *srcctx = (PROV_SM2DH_CTX *)vpecdhctx;
    PROV_SM2DH_CTX *dstctx;

    if (!ossl_prov_is_running())
        return NULL;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;

    /* clear all pointers */
    dstctx->k= NULL;
    dstctx->peerk = NULL;
    dstctx->enc_k = NULL;
    dstctx->enc_peerk = NULL;
    dstctx->md = NULL;
    dstctx->id = NULL;
    dstctx->peer_id = NULL;

    /* up-ref all ref-counted objects referenced in dstctx */
    if (srcctx->k != NULL && !EC_KEY_up_ref(srcctx->k))
        goto err;
    else
        dstctx->k = srcctx->k;

    if (srcctx->peerk != NULL && !EC_KEY_up_ref(srcctx->peerk))
        goto err;
    else
        dstctx->peerk = srcctx->peerk;

    if (srcctx->k != NULL && !EC_KEY_up_ref(srcctx->k))
        goto err;
    else
        dstctx->k = srcctx->k;

    if (srcctx->peerk != NULL && !EC_KEY_up_ref(srcctx->peerk))
        goto err;
    else
        dstctx->peerk = srcctx->peerk;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    else
        dstctx->md = srcctx->md;

    if (srcctx->id != NULL && srcctx->id_len > 0) {
        dstctx->id = OPENSSL_memdup(srcctx->id, srcctx->id_len);
        if (dstctx->id == NULL)
            goto err;
    }

    if (srcctx->peer_id != NULL && srcctx->peer_id_len > 0) {
        dstctx->peer_id = OPENSSL_memdup(srcctx->peer_id, srcctx->peer_id_len);
        if (dstctx->peer_id == NULL)
            goto err;
    }

    return dstctx;

 err:
    sm2dh_freectx(dstctx);
    return NULL;
}

static
int sm2dh_set_ctx_params(void *vpecdhctx, const OSSL_PARAM params[])
{
    PROV_SM2DH_CTX *pectx = (PROV_SM2DH_CTX *)vpecdhctx;
    const OSSL_PARAM *p;
    EVP_PKEY *key = NULL;
    void *tmp_id = NULL;
    size_t tmp_len;
    char name[80] = { '\0' }; /* should be big enough */
    char *str = NULL;

    if (pectx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_INITIATOR);
    if (p != NULL) {
        int initiator;

        if (!OSSL_PARAM_get_int(p, &initiator))
            return 0;

        pectx->initiator = initiator;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_SELF_ENC_KEY);
    if (p != NULL) {
        EVP_KEYMGMT *keymgmt = NULL;

        if (!OSSL_PARAM_get_octet_ptr(p, (const void **)&key, NULL))
            return 0;

        if (key == NULL)
            return 0;

        EC_KEY_free(pectx->enc_k);

        pectx->enc_k = (EC_KEY *)evp_pkey_export_to_provider(key, pectx->libctx,
                                                             &keymgmt, NULL);
        EVP_KEYMGMT_free(keymgmt);

        if (pectx->enc_k == NULL)
            return 0;
        else
            EC_KEY_up_ref(pectx->enc_k);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_PEER_ENC_KEY);
    if (p != NULL) {
        EVP_KEYMGMT *keymgmt = NULL;

        if (!OSSL_PARAM_get_octet_ptr(p, (const void **)&key, NULL))
            return 0;

        if (key == NULL)
            return 0;

        EC_KEY_free(pectx->enc_peerk);
        pectx->enc_peerk = (EC_KEY *)evp_pkey_export_to_provider(key,
                                                                 pectx->libctx,
                                                                 &keymgmt,
                                                                 NULL);
        EVP_KEYMGMT_free(keymgmt);

        if (pectx->enc_peerk == NULL)
            return 0;
        else
            EC_KEY_up_ref(pectx->enc_peerk);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_OUTLEN);
    if (p != NULL) {
        size_t outlen;

        if (!OSSL_PARAM_get_size_t(p, &outlen))
            return 0;
        pectx->outlen = outlen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_DIGEST);
    if (p != NULL) {
        char mdprops[80] = { '\0' }; /* should be big enough */

        str = name;
        if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(name)))
            return 0;

        str = mdprops;
        p = OSSL_PARAM_locate_const(params,
                                    OSSL_EXCHANGE_PARAM_DIGEST_PROPS);

        if (p != NULL) {
            if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdprops)))
                return 0;
        }

        EVP_MD_free(pectx->md);
        pectx->md = EVP_MD_fetch(pectx->libctx, name, mdprops);
        if (!ossl_digest_is_allowed(pectx->libctx, pectx->md)) {
            EVP_MD_free(pectx->md);
            pectx->md = NULL;
        }
        if (pectx->md == NULL)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_SELF_ID);
    if (p != NULL) {
        tmp_id = NULL;
        if (!OSSL_PARAM_get_octet_string(p, &tmp_id, 0, &tmp_len))
            return 0;

        OPENSSL_free(pectx->id);
        pectx->id = tmp_id;
        pectx->id_len = tmp_len;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_PEER_ID);
    if (p != NULL) {
        tmp_id = NULL;
        if (!OSSL_PARAM_get_octet_string(p, &tmp_id, 0, &tmp_len))
            return 0;

        OPENSSL_free(pectx->peer_id);
        pectx->peer_id = tmp_id;
        pectx->peer_id_len = tmp_len;
    }

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_INITIATOR, NULL),
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_SELF_ID, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_PEER_ID, NULL, 0),
    OSSL_PARAM_octet_ptr(OSSL_EXCHANGE_PARAM_SELF_ENC_KEY, NULL, 0),
    OSSL_PARAM_octet_ptr(OSSL_EXCHANGE_PARAM_PEER_ENC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_OUTLEN, NULL),
    OSSL_PARAM_END
};

static
const OSSL_PARAM *sm2dh_settable_ctx_params(ossl_unused void *vpecdhctx,
                                            ossl_unused void *provctx)
{
    return known_settable_ctx_params;
}

static
int sm2dh_get_ctx_params(void *vpecdhctx,
                         OSSL_PARAM params[])
{
    PROV_SM2DH_CTX *pectx = (PROV_SM2DH_CTX *)vpecdhctx;
    OSSL_PARAM *p;

    if (pectx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_DIGEST);
    if (p != NULL
        && !OSSL_PARAM_set_utf8_string(p, pectx->md == NULL
                                          ? ""
                                          : EVP_MD_get0_name(pectx->md))){
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_OUTLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, pectx->outlen))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_OUTLEN, NULL),
    OSSL_PARAM_END
};

static
const OSSL_PARAM *sm2dh_gettable_ctx_params(ossl_unused void *vpecdhctx,
                                            ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

static
int sm2dh_derive(void *vpecdhctx, unsigned char *secret,
                size_t *psecretlen, size_t outlen)
{
    PROV_SM2DH_CTX *pecdhctx = (PROV_SM2DH_CTX *)vpecdhctx;

    if (secret == NULL) {
        *psecretlen = pecdhctx->outlen;
        return 1;
    }

    if (pecdhctx->outlen > outlen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (pecdhctx->k == NULL || pecdhctx->peerk == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    if (SM2_compute_key(secret, pecdhctx->outlen, pecdhctx->initiator,
                        pecdhctx->peer_id, pecdhctx->peer_id_len,
                        pecdhctx->id, pecdhctx->id_len,
                        pecdhctx->peerk, pecdhctx->k,
                        pecdhctx->enc_peerk, pecdhctx->enc_k,
                        pecdhctx->md, pecdhctx->libctx, NULL) <= 0)
        return 0;

    *psecretlen = pecdhctx->outlen;

    return 1;
}

const OSSL_DISPATCH ossl_sm2dh_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))sm2dh_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))sm2dh_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))sm2dh_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))sm2dh_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))sm2dh_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))sm2dh_dupctx },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))sm2dh_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
      (void (*)(void))sm2dh_settable_ctx_params },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))sm2dh_get_ctx_params },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
      (void (*)(void))sm2dh_gettable_ctx_params },
    { 0, NULL }
};
