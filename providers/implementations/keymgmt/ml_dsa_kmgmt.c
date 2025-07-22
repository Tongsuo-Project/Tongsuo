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
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "internal/param_build_set.h"

#include "crypto/ml_dsa.h"

static OSSL_FUNC_keymgmt_new_fn ml_dsa_newdata;
static OSSL_FUNC_keymgmt_free_fn ml_dsa_freedata;
static OSSL_FUNC_keymgmt_load_fn ml_dsa_load;
static OSSL_FUNC_keymgmt_gen_init_fn ml_dsa_gen_init;
static OSSL_FUNC_keymgmt_gen_fn ml_dsa_gen;
static OSSL_FUNC_keymgmt_gen_set_params_fn ml_dsa_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn ml_dsa_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_cleanup_fn ml_dsa_gen_cleanup;
static OSSL_FUNC_keymgmt_gettable_params_fn ml_dsa_gettable_params;
static OSSL_FUNC_keymgmt_get_params_fn ml_dsa_get_params;
static OSSL_FUNC_keymgmt_has_fn ml_dsa_has;
static OSSL_FUNC_keymgmt_match_fn ml_dsa_match;
static OSSL_FUNC_keymgmt_import_fn ml_dsa_import;
static OSSL_FUNC_keymgmt_export_fn ml_dsa_export;
static OSSL_FUNC_keymgmt_import_types_fn ml_dsa_import_types;
static OSSL_FUNC_keymgmt_export_types_fn ml_dsa_export_types;

struct ml_dsa_gen_ctx {
    PROV_CTX *provctx;

    char sk_fmt[ML_DSA_SK_FORMAT_MAX_BYTES + 1];

    uint8_t seed[ML_DSA_SEEDBYTES];
    size_t seed_len;
};

static void *ml_dsa_newdata(void *provctx)
{
    if (!ossl_prov_is_running())
        return NULL;
    return pqcrystals_ml_dsa_key_new(PROV_LIBCTX_OF(provctx));
}

static void ml_dsa_freedata(void *keydata)
{
    pqcrystals_ml_dsa_key_free(keydata);
}

static void *ml_dsa_load(const void *reference, size_t reference_sz)
{
    ML_DSA_KEY *key = NULL;

    if (ossl_prov_is_running() && reference_sz == sizeof(key)) {
        /* The contents of the reference is the address to our object */
        key = *(ML_DSA_KEY **)reference;

        /* We grabbed, so we detach it */
        *(ML_DSA_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

static void *ml_dsa_gen_init(void *provctx, int selection,
                             const OSSL_PARAM params[])
{
    struct ml_dsa_gen_ctx *gctx = NULL;

    if (!ossl_prov_is_running())
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->provctx = provctx;
        memset(gctx->seed, 0, sizeof(gctx->seed));
        gctx->seed_len = 0;
        if (!ml_dsa_gen_set_params(gctx, params)) {
            OPENSSL_free(gctx);
            gctx = NULL;
        }
    }
    return gctx;
}

static void *ml_dsa_gen(void * genctx, OSSL_CALLBACK * osslcb, void * cbarg)
{
    struct ml_dsa_gen_ctx *gctx = genctx;
    ML_DSA_KEY *key = NULL;
    int rand_seed = 1;

    if (!ossl_prov_is_running())
        return NULL;

    key = pqcrystals_ml_dsa_key_new(PROV_LIBCTX_OF(gctx->provctx));
    if (key == NULL)
        return NULL;

    if (gctx->seed_len != 0) {
        memcpy(key->seed, gctx->seed, gctx->seed_len);
        rand_seed = 0;
    }
    if (crypto_sign_keypair(key->pubkey, key->privkey, key->seed, rand_seed)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        goto err;
    }
    key->pubkey_len = ML_DSA_PUBLICKEYBYTES;
    key->privkey_len = ML_DSA_SECRETKEYBYTES;
    key->seed_len = ML_DSA_SEEDBYTES;
    strncpy(key->sk_fmt, gctx->sk_fmt, ML_DSA_SK_FORMAT_MAX_BYTES);

    return key;
err:
    pqcrystals_ml_dsa_key_free(key);
    return NULL;
}

static const OSSL_PARAM ml_dsa_gen_set_params_list[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_ML_DSA_SK_FORMAT, NULL, 0),
    OSSL_PARAM_END
};

static int ml_dsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct ml_dsa_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED)) != NULL) {
        void *vp = gctx->seed;
        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(gctx->seed),
                                         &(gctx->seed_len))
                || gctx->seed_len != ML_DSA_SEEDBYTES) {
            gctx->seed_len = 0;
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SK_FORMAT)) != NULL) {
        char *vp = gctx->sk_fmt;
        if (!OSSL_PARAM_get_utf8_string(p, &vp, sizeof(gctx->sk_fmt))) {
            gctx->sk_fmt[0] = '\0';
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM *ml_dsa_gen_settable_params(ossl_unused void *genctx,
                                                    ossl_unused void *provctx)
{
    return ml_dsa_gen_set_params_list;
}

static void ml_dsa_gen_cleanup(void *genctx)
{
    struct ml_dsa_gen_ctx *gctx = genctx;

    if (gctx == NULL)
        return;

    OPENSSL_cleanse(gctx->seed, gctx->seed_len);
    OPENSSL_free(gctx);
}

static const OSSL_PARAM ml_dsa_get_params_list[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ml_dsa_gettable_params(void *provctx)
{
    return ml_dsa_get_params_list;
}

static int ml_dsa_get_params(void *keydata, OSSL_PARAM params[])
{
    ML_DSA_KEY *key = keydata;
    OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL) {
        if (!OSSL_PARAM_set_int(p, 8 * ML_DSA_PUBLICKEYBYTES))
            return 0;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL) {
        if (!OSSL_PARAM_set_int(p, ML_DSA_SIGBYTES))
            return 0;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ML_DSA_SEED)) != NULL) {
        if (key->seed_len != 0
                 && !OSSL_PARAM_set_octet_string(p, key->seed, ML_DSA_SEEDBYTES))
            return 0;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL) {
        if (key->pubkey_len != 0
                 && !OSSL_PARAM_set_octet_string(p, key->pubkey, ML_DSA_PUBLICKEYBYTES))
            return 0;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL) {
        if (key->privkey_len != 0
                 && !OSSL_PARAM_set_octet_string(p, key->privkey, ML_DSA_SECRETKEYBYTES))
            return 0;
    }

    return 1;
}

static int ml_dsa_has(const void *keydata, int selection)
{
    const ML_DSA_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && key->privkey_len == 0)
        return 0; /* No private key */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
            && key->pubkey_len == 0)
        return 0; /* No public key */

    return 1;
}

static int ml_dsa_match(const void *keydata1, const void *keydata2, int selection)
{
    const ML_DSA_KEY *key1 = keydata1;
    const ML_DSA_KEY *key2 = keydata2;
    int key_checked = 0;

    if (!ossl_prov_is_running())
        return 0;

    if (key1 == NULL || key2 == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            if (key1->pubkey_len != 0 && key2->pubkey_len != 0) {
                if (memcmp(key1->pubkey, key2->pubkey,
                                  key1->pubkey_len) != 0)
                    return 0;
                key_checked = 1;
            }
        }
        if (!key_checked
                && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            if (key1->privkey_len != 0 && key2->privkey_len != 0) {
                if (memcmp(key1->privkey, key2->privkey,
                           key1->privkey_len) != 0)
                    return 0;
                key_checked = 1;
            }
        }
        return key_checked;
    }
    return 1;
}

static int ml_dsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    int ret = 0;
    ML_DSA_KEY *key = keydata;
    const OSSL_PARAM *p;
    uint8_t *pk = NULL, *sk = NULL, *seed = NULL;
    size_t pk_len = 0, sk_len = 0, seed_len = 0;
    int include_priv = 0;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    include_priv = ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL) {
        if (!OSSL_PARAM_get_octet_string(p, (void **)&pk, 0, &pk_len))
            goto err;
        if (pk != NULL && pk_len != ML_DSA_PUBLICKEYBYTES) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            goto err;
        }
    }

    if (include_priv && (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED)) != NULL) {
        if (!OSSL_PARAM_get_octet_string(p, (void **)&seed, 0, &seed_len))
            goto err;
        if (seed != NULL && seed_len != ML_DSA_SEEDBYTES) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            goto err;
        }
    }

    if (include_priv && (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL) {
        if (!OSSL_PARAM_get_octet_string(p, (void **)&sk, 0, &sk_len))
            goto err;
        if (sk != NULL && sk_len != ML_DSA_SECRETKEYBYTES) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            goto err;
        }
    }

    if (pk_len == 0 && sk_len == 0 && seed_len == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto err;
    }

    if (seed != NULL) {
        if (crypto_sign_keypair(key->pubkey, key->privkey, seed, 0)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
            key->seed_len = 0;
            goto err;
        }
        memcpy(key->seed, seed, seed_len);
        key->pubkey_len = ML_DSA_PUBLICKEYBYTES;
        key->privkey_len = ML_DSA_SECRETKEYBYTES;
        key->seed_len = ML_DSA_SEEDBYTES;
    } else {
        key->seed_len = 0;
        if (pk != NULL && !pqcrystals_ml_dsa_pk_import(key, pk, pk_len)) {
            key->pubkey_len = 0;
            goto err;
        }
        if (sk != NULL && !pqcrystals_ml_dsa_sk_import(key, sk, sk_len)) {
            key->privkey_len = 0;
            goto err;
        }
    }

    ret = 1;
err:
    OPENSSL_free(pk);
    OPENSSL_free(sk);
    OPENSSL_free(seed);
    return ret;
}

static int ml_dsa_export(void *keydata, int selection,
                         OSSL_CALLBACK *param_cb, void *cbarg)
{
    ML_DSA_KEY *key = keydata;
    OSSL_PARAM params[4];
    int pnum = 0;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    if (((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) && (key->seed_len != 0)) {
        params[pnum++] = OSSL_PARAM_construct_octet_string
            (OSSL_PKEY_PARAM_ML_DSA_SEED, (void *)key->seed, key->seed_len);
    }
    if (((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) && (key->privkey_len != 0)) {
        params[pnum++] = OSSL_PARAM_construct_octet_string
            (OSSL_PKEY_PARAM_PRIV_KEY, (void *)key->privkey, key->privkey_len);
    }
    if (((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) && (key->pubkey_len != 0)) {
        params[pnum++] = OSSL_PARAM_construct_octet_string
            (OSSL_PKEY_PARAM_PUB_KEY, (void *)key->pubkey, key->pubkey_len);
    }

    if (pnum == 0)
        return 0;
    params[pnum] = OSSL_PARAM_construct_end();
    return param_cb(params, cbarg);
}

static const OSSL_PARAM ml_dsa_import_type_params_list[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ml_dsa_import_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;
    return ml_dsa_import_type_params_list;
}

static const OSSL_PARAM *ml_dsa_export_types(int selection)
{
    return ml_dsa_import_types(selection);
}

const OSSL_DISPATCH ossl_ml_dsa_65_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ml_dsa_newdata },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ml_dsa_load },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ml_dsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))ml_dsa_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))ml_dsa_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ml_dsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))ml_dsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ml_dsa_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))ml_dsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))ml_dsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ml_dsa_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ml_dsa_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ml_dsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ml_dsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ml_dsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))ml_dsa_export_types },
    { 0, NULL }
};
