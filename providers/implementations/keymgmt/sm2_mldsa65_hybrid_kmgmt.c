/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "internal/param_build_set.h"
#include "crypto/sm2_mldsa65_hybrid.h"

static OSSL_FUNC_keymgmt_new_fn sm2_mldsa65_hybrid_new;
static OSSL_FUNC_keymgmt_free_fn sm2_mldsa65_hybrid_free;
static OSSL_FUNC_keymgmt_load_fn sm2_mldsa65_hybrid_load;
static OSSL_FUNC_keymgmt_gen_init_fn sm2_mldsa65_hybrid_gen_init;
static OSSL_FUNC_keymgmt_gen_fn sm2_mldsa65_hybrid_gen;
static OSSL_FUNC_keymgmt_gen_set_params_fn sm2_mldsa65_hybrid_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn sm2_mldsa65_hybrid_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_cleanup_fn sm2_mldsa65_hybrid_gen_cleanup;
static OSSL_FUNC_keymgmt_settable_params_fn sm2_mldsa65_hybrid_settable_params;
static OSSL_FUNC_keymgmt_set_params_fn sm2_mldsa65_hybrid_set_params;
static OSSL_FUNC_keymgmt_gettable_params_fn sm2_mldsa65_hybrid_gettable_params;
static OSSL_FUNC_keymgmt_get_params_fn sm2_mldsa65_hybrid_get_params;
static OSSL_FUNC_keymgmt_has_fn sm2_mldsa65_hybrid_has;
static OSSL_FUNC_keymgmt_match_fn sm2_mldsa65_hybrid_match;
static OSSL_FUNC_keymgmt_import_fn sm2_mldsa65_hybrid_import;
static OSSL_FUNC_keymgmt_export_fn sm2_mldsa65_hybrid_export;
static OSSL_FUNC_keymgmt_import_types_fn sm2_mldsa65_hybrid_import_types;
static OSSL_FUNC_keymgmt_export_types_fn sm2_mldsa65_hybrid_export_types;

static const int minimal_selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
    | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    int selection;
} SM2_MLDSA65_HYBRID_GEN_CTX;

static void *sm2_mldsa65_hybrid_new(void *provctx)
{
    OSSL_LIB_CTX *libctx;
    libctx = provctx == NULL ? NULL : PROV_LIBCTX_OF(provctx);
    return sm2_mldsa65_hybrid_key_new(libctx, NULL);
}

static void sm2_mldsa65_hybrid_free(void *vkey)
{
    SM2_MLDSA65_HYBRID_KEY *key = vkey;
    sm2_mldsa65_hybrid_key_free(key);
}

static void *sm2_mldsa65_hybrid_load(const void *reference, size_t reference_sz)
{
    SM2_MLDSA65_HYBRID_KEY *key = NULL;

    if (ossl_prov_is_running() && reference_sz == sizeof(key)) {
        /* The contents of the reference is the address to our object */
        key = *(SM2_MLDSA65_HYBRID_KEY **)reference;

        /* We grabbed, so we detach it */
        *(SM2_MLDSA65_HYBRID_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

static void *sm2_mldsa65_hybrid_gen_init(void *provctx, int selection,
                             const OSSL_PARAM params[])
{
    SM2_MLDSA65_HYBRID_GEN_CTX *gctx = NULL;

    if (!ossl_prov_is_running()
        || (selection & minimal_selection) == 0)
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = PROV_LIBCTX_OF(provctx);
        gctx->selection = selection;
        if (!sm2_mldsa65_hybrid_gen_set_params(gctx, params)) {
            OPENSSL_free(gctx);
            gctx = NULL;
        }
    }
    return gctx;
}

static void sm2_mldsa65_hybrid_gen_cleanup(void *genctx)
{
    SM2_MLDSA65_HYBRID_GEN_CTX *gctx = genctx;
    if (gctx == NULL)
        return;

    OPENSSL_free(gctx->propq);
    gctx->propq = NULL;
    OPENSSL_free(gctx);
}

static void *sm2_mldsa65_hybrid_gen(void * genctx, OSSL_CALLBACK * osslcb, void * cbarg)
{
    SM2_MLDSA65_HYBRID_GEN_CTX *gctx = genctx;
    SM2_MLDSA65_HYBRID_KEY *key = NULL;
    char *propq = NULL;

    if (gctx == NULL || (gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) ==
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return NULL;

    propq = gctx->propq;
    gctx->propq = NULL;

    if ((key = sm2_mldsa65_hybrid_key_new(gctx->libctx, propq)) == NULL)
        return NULL;

    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return key;

    key->mldsa_key = EVP_PKEY_Q_keygen(key->libctx, key->propq, SM2_MLDSA65_HYBRID_QNAME);
    key->sm2_key = EVP_PKEY_Q_keygen(key->libctx, key->propq, SM2_MLDSA65_HYBRID_TNAME);
    if (key->mldsa_key == NULL || key->sm2_key == NULL) {
        sm2_mldsa65_hybrid_free(key);
        return NULL;
    }

    key->status = SM2_MLDSA65_HYBRID_HAVE_PRVKEY;
    return key;
}

static const OSSL_PARAM sm2_mldsa65_hybrid_gen_set_params_list[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sm2_mldsa65_hybrid_gen_settable_params(ossl_unused void *genctx,
                                                    ossl_unused void *provctx)
{
    return sm2_mldsa65_hybrid_gen_set_params_list;
}

static int sm2_mldsa65_hybrid_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    SM2_MLDSA65_HYBRID_GEN_CTX *gctx = genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES)) != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->propq);
        gctx->propq = OPENSSL_strdup(p->data);
        if (gctx->propq == NULL)
            return 0;
    }

    return 1;
}

static int sm2_mldsa65_hybrid_has(const void *keydata, int selection)
{
    const SM2_MLDSA65_HYBRID_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && !sm2_mldsa65_hybrid_have_prvkey(key))
        return 0; /* No private key */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
            && !sm2_mldsa65_hybrid_have_pubkey(key))
        return 0; /* No public key */

    return 1;
}

static int sm2_mldsa65_hybrid_match(const void *keydata1, const void *keydata2, int selection)
{
    const SM2_MLDSA65_HYBRID_KEY *key1 = keydata1;
    const SM2_MLDSA65_HYBRID_KEY *key2 = keydata2;
    int have_pub1 = sm2_mldsa65_hybrid_have_pubkey(key1);
    int have_pub2 = sm2_mldsa65_hybrid_have_pubkey(key2);

    if (!ossl_prov_is_running())
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 1; /* Nothing to match */

    if (have_pub1 ^ have_pub2)
        return 0; /* One has pubkey, the other does not */

    /* As in other providers, equal when both have no key material. */
    if (!have_pub1)
        return 1;

    return EVP_PKEY_eq(key1->mldsa_key, key2->mldsa_key)
        && EVP_PKEY_eq(key1->sm2_key, key2->sm2_key);
}

static int sm2_mldsa65_hybrid_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    int ret = 0;
    SM2_MLDSA65_HYBRID_KEY *key = keydata;
    const OSSL_PARAM *p;
    uint8_t *pk = NULL, *sk = NULL;
    size_t pk_len = 0, sk_len = 0;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    if (sm2_mldsa65_hybrid_have_pubkey(key))
        return 0; /* Already have public key */

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL
        && !OSSL_PARAM_get_octet_string(p, (void **)&pk, 0, &pk_len))
            goto err;

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY
        && (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL
        && !OSSL_PARAM_get_octet_string(p, (void **)&sk, 0, &sk_len))
            goto err;

    if (pk == NULL && sk == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto err; /* No keys provided */
    }

    if (pk != NULL && pk_len != SM2_MLDSA65_HYBRID_PK_SIZE)
        goto err;
    if (sk != NULL && sk_len != SM2_MLDSA65_HYBRID_SK_SIZE)
        goto err;

    if (sk != NULL)
        /* Ignore public keys when private provided */
        ret = sm2_mldsa65_hybrid_priv_key_deserialize(key, sk, sk_len);
    else if (pk != NULL)
        /* Absent private key data, import public keys */
        ret = sm2_mldsa65_hybrid_pub_key_deserialize(key, pk, pk_len);

err:
    OPENSSL_free(pk);
    OPENSSL_clear_free(sk, sk_len);
    return ret;
}
static int sm2_mldsa65_hybrid_export(void *keydata, int selection,
                         OSSL_CALLBACK *param_cb, void *cbarg)
{
    int ret = 0;
    SM2_MLDSA65_HYBRID_KEY *key = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    uint8_t *pkbuf = NULL, *skbuf = NULL;
    size_t pklen = 0, sklen = 0;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    if (sm2_mldsa65_hybrid_have_pubkey(key))
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        pkbuf = OPENSSL_zalloc(SM2_MLDSA65_HYBRID_PK_SIZE);
        if (pkbuf == NULL)
            goto err;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
            sm2_mldsa65_hybrid_have_prvkey(key)) {
        skbuf = OPENSSL_zalloc(SM2_MLDSA65_HYBRID_SK_SIZE);
        if (skbuf == NULL)
            goto err;
    }

    if (!sm2_mldsa65_hybrid_key_serialize(key, \
            pkbuf, SM2_MLDSA65_HYBRID_PK_SIZE, &pklen, skbuf, SM2_MLDSA65_HYBRID_SK_SIZE, &sklen))
        goto err;

    if (pkbuf != NULL && !ossl_param_build_set_octet_string(
                tmpl, NULL, OSSL_PKEY_PARAM_PUB_KEY, pkbuf, pklen))
        goto err;

    if (skbuf != NULL && !ossl_param_build_set_octet_string(
                tmpl, NULL, OSSL_PKEY_PARAM_PRIV_KEY, skbuf, sklen))
        goto err;

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OPENSSL_free(pkbuf);
    OPENSSL_clear_free(skbuf, SM2_MLDSA65_HYBRID_SK_SIZE);
    OSSL_PARAM_BLD_free(tmpl);
    return ret;
}

static const OSSL_PARAM sm2_mldsa65_hybrid_import_type_params_list[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sm2_mldsa65_hybrid_import_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;
    return sm2_mldsa65_hybrid_import_type_params_list;
}

static const OSSL_PARAM *sm2_mldsa65_hybrid_export_types(int selection)
{
    return sm2_mldsa65_hybrid_import_types(selection);
}

static const OSSL_PARAM sm2_mldsa65_hybrid_set_params_list[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sm2_mldsa65_hybrid_settable_params(void *provctx)
{
    return sm2_mldsa65_hybrid_set_params_list;
}

static int sm2_mldsa65_hybrid_set_params(void *keydata, const OSSL_PARAM params[])
{
    SM2_MLDSA65_HYBRID_KEY *key = keydata;
    const OSSL_PARAM *p;
    const uint8_t *pkbuf = NULL;
    size_t pklen = 0;

    if (key == NULL)
        return 0;

    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL) {
        if (sm2_mldsa65_hybrid_have_pubkey(key))
            return 0;
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void**)&pkbuf, &pklen))
            return 0;
        if (pklen != SM2_MLDSA65_HYBRID_PK_SIZE ||
             !sm2_mldsa65_hybrid_pub_key_deserialize(key, pkbuf, pklen))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES)) != NULL) {
        OPENSSL_free(key->propq);
        key->propq = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &key->propq, 0))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM sm2_mldsa65_hybrid_get_params_list[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sm2_mldsa65_hybrid_gettable_params(void *provctx)
{
    return sm2_mldsa65_hybrid_get_params_list;
}

static int sm2_mldsa65_hybrid_get_params(void *keydata, OSSL_PARAM params[])
{
    int ret = 0;
    SM2_MLDSA65_HYBRID_KEY *key = keydata;
    OSSL_PARAM *p;
    uint8_t *pkbuf = NULL, *skbuf = NULL;
    size_t pklen = 0, sklen = 0;
    int sz_sm2 = 0, sz_mldsa = 0;

    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL) {
        if (!OSSL_PARAM_set_int(p, ML_DSA_PUBLICKEYBYTES * 8))
            return 0;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL) {
        if (!OSSL_PARAM_set_int(p, 192))
            return 0;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL) {
        if (!EVP_PKEY_get_int_param(key->sm2_key, OSSL_PKEY_PARAM_MAX_SIZE, &sz_sm2)
         || !EVP_PKEY_get_int_param(key->mldsa_key, OSSL_PKEY_PARAM_MAX_SIZE, &sz_mldsa)
         || !OSSL_PARAM_set_int(p, sz_mldsa + sz_sm2))
            return 0;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL) {
        pkbuf = OPENSSL_zalloc(SM2_MLDSA65_HYBRID_PK_SIZE);
        if (pkbuf == NULL)
            goto err;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL) {
        skbuf = OPENSSL_zalloc(SM2_MLDSA65_HYBRID_SK_SIZE);
        if (skbuf == NULL)
            goto err;
    }

    if (pkbuf == NULL && skbuf == NULL)
        return 1; /* Nothing to get */

    if (!sm2_mldsa65_hybrid_key_serialize(key,
            pkbuf, SM2_MLDSA65_HYBRID_PK_SIZE, &pklen, skbuf, SM2_MLDSA65_HYBRID_SK_SIZE, &sklen))
        goto err;
    if (pkbuf != NULL &&
         (p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL &&
         !OSSL_PARAM_set_octet_string(p, pkbuf, pklen))
        goto err;
    if (skbuf != NULL &&
         (p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL &&
         !OSSL_PARAM_set_octet_string(p, skbuf, sklen))
        goto err;

    ret = 1;
err:
    OPENSSL_free(pkbuf);
    OPENSSL_clear_free(skbuf, SM2_MLDSA65_HYBRID_SK_SIZE);
    return ret;
}

const OSSL_DISPATCH ossl_sm2_mldsa65_hybrid_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))sm2_mldsa65_hybrid_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sm2_mldsa65_hybrid_free },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sm2_mldsa65_hybrid_load },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))sm2_mldsa65_hybrid_settable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))sm2_mldsa65_hybrid_set_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))sm2_mldsa65_hybrid_gettable_params },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))sm2_mldsa65_hybrid_get_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sm2_mldsa65_hybrid_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))sm2_mldsa65_hybrid_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))sm2_mldsa65_hybrid_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))sm2_mldsa65_hybrid_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))sm2_mldsa65_hybrid_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))sm2_mldsa65_hybrid_export_types },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))sm2_mldsa65_hybrid_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))sm2_mldsa65_hybrid_gen },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))sm2_mldsa65_hybrid_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))sm2_mldsa65_hybrid_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))sm2_mldsa65_hybrid_gen_cleanup },
    { 0, NULL }
};
