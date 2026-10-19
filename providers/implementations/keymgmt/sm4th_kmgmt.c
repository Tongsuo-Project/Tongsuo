/*
 * Copyright 2023-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "crypto/sm4th.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"

#ifndef OPENSSL_NO_SM4TH

typedef struct {
    PROV_CTX *provctx;
    char *propq;
} SM4TH_GEN_CTX;

static void *sm4th_new_key(void *provctx, int variant)
{
    if (!ossl_prov_is_running())
        return NULL;
    return tons_sm4th_key_new(PROV_LIBCTX_OF(provctx), NULL, variant);
}

static void sm4th_free_key(void *keydata)
{
    tons_sm4th_key_free(keydata);
}

static int sm4th_has(const void *keydata, int selection)
{
    const SM4TH_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && !tons_sm4th_key_has_private(key))
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        /* Public material is always present once the object is filled. */
        unsigned char pk[SM4TH_PK_BYTES];

        if (!tons_sm4th_key_get_pk(key, pk, sizeof(pk)))
            return 0;
    }
    return 1;
}

static int sm4th_match(const void *keydata1, const void *keydata2, int selection)
{
    const SM4TH_KEY *a = keydata1, *b = keydata2;
    unsigned char pa[SM4TH_PK_BYTES], pb[SM4TH_PK_BYTES];
    unsigned char sa[SM4TH_SK_BYTES], sb[SM4TH_SK_BYTES];
    int ok = 1;

    if (!ossl_prov_is_running() || a == NULL || b == NULL)
        return 0;
    if (tons_sm4th_key_get_variant(a) != tons_sm4th_key_get_variant(b))
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!tons_sm4th_key_get_pk(a, pa, sizeof(pa))
            || !tons_sm4th_key_get_pk(b, pb, sizeof(pb))
            || CRYPTO_memcmp(pa, pb, SM4TH_PK_BYTES) != 0)
            ok = 0;
    }
    if (ok && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (!tons_sm4th_key_has_private(a) || !tons_sm4th_key_has_private(b)
            || !tons_sm4th_key_get_sk(a, sa, sizeof(sa))
            || !tons_sm4th_key_get_sk(b, sb, sizeof(sb))
            || CRYPTO_memcmp(sa, sb, SM4TH_SK_BYTES) != 0)
            ok = 0;
        OPENSSL_cleanse(sa, sizeof(sa));
        OPENSSL_cleanse(sb, sizeof(sb));
    }
    return ok;
}

static int sm4th_validate(const void *keydata, int selection,
                          ossl_unused int check_type)
{
    const SM4TH_KEY *key = keydata;

    if (!sm4th_has(key, selection))
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR)
        return tons_sm4th_key_pairwise_check(key);
    return 1;
}

static int sm4th_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    SM4TH_KEY *key = keydata;
    const OSSL_PARAM *p;
    const unsigned char *buf = NULL;
    size_t len = 0;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&buf, &len)
                || len != SM4TH_SK_BYTES
                || !tons_sm4th_key_set_sk(key, buf, len))
                return 0;
            return 1;
        }
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p == NULL)
            return 0;
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&buf, &len)
            || len != SM4TH_PK_BYTES
            || !tons_sm4th_key_set_pk(key, buf, len))
            return 0;
        return 1;
    }
    return 0;
}

static const OSSL_PARAM sm4th_key_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sm4th_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;
    return sm4th_key_types;
}

static int sm4th_export(void *keydata, int selection,
                        OSSL_CALLBACK *param_cb, void *cbarg)
{
    SM4TH_KEY *key = keydata;
    OSSL_PARAM params[3];
    unsigned char pk[SM4TH_PK_BYTES], sk[SM4TH_SK_BYTES];
    int pnum = 0;
    int ret;

    if (!ossl_prov_is_running() || key == NULL || param_cb == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (!tons_sm4th_key_get_sk(key, sk, sizeof(sk)))
            return 0;
        params[pnum++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, sk, SM4TH_SK_BYTES);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!tons_sm4th_key_get_pk(key, pk, sizeof(pk)))
            return 0;
        params[pnum++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, pk, SM4TH_PK_BYTES);
    }
    if (pnum == 0)
        return 0;
    params[pnum] = OSSL_PARAM_construct_end();
    ret = param_cb(params, cbarg);
    OPENSSL_cleanse(sk, sizeof(sk));
    return ret;
}

static const OSSL_PARAM sm4th_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sm4th_gettable_params(ossl_unused void *provctx)
{
    return sm4th_params;
}

static int sm4th_get_params(void *keydata, OSSL_PARAM params[])
{
    SM4TH_KEY *key = keydata;
    OSSL_PARAM *p;
    unsigned char pk[SM4TH_PK_BYTES], sk[SM4TH_SK_BYTES];

    if (key == NULL)
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, 128))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, 128))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, (int)tons_sm4th_key_get_sig_len(key)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST)) != NULL
        && !OSSL_PARAM_set_utf8_string(p, ""))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL) {
        if (!tons_sm4th_key_get_pk(key, pk, sizeof(pk))
            || !OSSL_PARAM_set_octet_string(p, pk, SM4TH_PK_BYTES))
            return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL) {
        int ok = tons_sm4th_key_get_sk(key, sk, sizeof(sk))
            && OSSL_PARAM_set_octet_string(p, sk, SM4TH_SK_BYTES);
        OPENSSL_cleanse(sk, sizeof(sk));
        if (!ok)
            return 0;
    }
    return 1;
}

static void *sm4th_gen_init(void *provctx, ossl_unused int selection,
                            const OSSL_PARAM params[])
{
    SM4TH_GEN_CTX *gctx;

    if (!ossl_prov_is_running())
        return NULL;
    gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;
    gctx->provctx = provctx;
    (void)params;
    return gctx;
}

static void sm4th_gen_cleanup(void *genctx)
{
    SM4TH_GEN_CTX *gctx = genctx;

    if (gctx == NULL)
        return;
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

static void *sm4th_gen(void *genctx, int variant)
{
    SM4TH_GEN_CTX *gctx = genctx;
    SM4TH_KEY *key;

    if (!ossl_prov_is_running() || gctx == NULL)
        return NULL;
    key = tons_sm4th_key_new(PROV_LIBCTX_OF(gctx->provctx), gctx->propq,
                             variant);
    if (key == NULL)
        return NULL;
    if (!tons_sm4th_generate_key(key)) {
        tons_sm4th_key_free(key);
        return NULL;
    }
    return key;
}

static void *sm4th_dup_key(const void *keydata_from, int selection)
{
    const SM4TH_KEY *src = keydata_from;
    SM4TH_KEY *dst;
    unsigned char buf[SM4TH_SK_BYTES];

    if (!ossl_prov_is_running() || src == NULL)
        return NULL;
    dst = tons_sm4th_key_new(tons_sm4th_key_get0_libctx((SM4TH_KEY *)src),
                             NULL, tons_sm4th_key_get_variant(src));
    if (dst == NULL)
        return NULL;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && tons_sm4th_key_has_private(src)) {
        if (!tons_sm4th_key_get_sk(src, buf, sizeof(buf))
            || !tons_sm4th_key_set_sk(dst, buf, SM4TH_SK_BYTES)) {
            OPENSSL_cleanse(buf, sizeof(buf));
            tons_sm4th_key_free(dst);
            return NULL;
        }
        OPENSSL_cleanse(buf, sizeof(buf));
        return dst;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!tons_sm4th_key_get_pk(src, buf, SM4TH_PK_BYTES)
            || !tons_sm4th_key_set_pk(dst, buf, SM4TH_PK_BYTES)) {
            tons_sm4th_key_free(dst);
            return NULL;
        }
    }
    return dst;
}

#define MAKE_SM4TH_KEYMGMT(sfx, variant)                                       \
    static void *sm4th_##sfx##_new(void *provctx)                              \
    {                                                                          \
        return sm4th_new_key(provctx, variant);                                \
    }                                                                          \
    static void *sm4th_##sfx##_gen(void *genctx, OSSL_CALLBACK *cb, void *arg)  \
    {                                                                          \
        (void)cb;                                                              \
        (void)arg;                                                             \
        return sm4th_gen(genctx, variant);                                     \
    }                                                                          \
    const OSSL_DISPATCH ossl_sm4th_##sfx##_keymgmt_functions[] = {             \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))sm4th_##sfx##_new },          \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sm4th_free_key },            \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sm4th_has },                  \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))sm4th_match },              \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))sm4th_import },            \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,                                      \
          (void (*)(void))sm4th_imexport_types },                              \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))sm4th_export },            \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,                                      \
          (void (*)(void))sm4th_imexport_types },                              \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))sm4th_get_params },    \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                   \
          (void (*)(void))sm4th_gettable_params },                             \
        { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))sm4th_validate },        \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))sm4th_gen_init },        \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))sm4th_##sfx##_gen },          \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))sm4th_gen_cleanup },  \
        { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))sm4th_dup_key },              \
        OSSL_DISPATCH_END                                                      \
    }

MAKE_SM4TH_KEYMGMT(f, SM4TH_VARIANT_F);
MAKE_SM4TH_KEYMGMT(s, SM4TH_VARIANT_S);

#endif /* OPENSSL_NO_SM4TH */
