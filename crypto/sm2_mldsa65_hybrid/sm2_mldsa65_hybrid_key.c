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
#include <openssl/param_build.h>
#include "prov/providercommon.h"

#include "crypto/sm2_mldsa65_hybrid.h"

void *sm2_mldsa65_hybrid_key_new(OSSL_LIB_CTX *libctx, const char *propq)
{
    SM2_MLDSA65_HYBRID_KEY *key = NULL;

    if (!ossl_prov_is_running())
        goto err;
    key = OPENSSL_zalloc(sizeof(SM2_MLDSA65_HYBRID_KEY));
    if (key == NULL)
        goto err;

    key->libctx = libctx;
    key->status = SM2_MLDSA65_HYBRID_HAVE_NOKEYS;

    if (propq != NULL) {
        key->propq = OPENSSL_strdup(propq);
        if (key->propq == NULL)
            goto err;
    }

    return key;
err:
    OPENSSL_free(key);
    return NULL;
}

static void sm2_mldsa65_hybrid_key_cleanup(SM2_MLDSA65_HYBRID_KEY *key)
{
    if (key == NULL)
        return;

    EVP_PKEY_free(key->sm2_key);
    EVP_PKEY_free(key->mldsa_key);
    key->sm2_key = key->mldsa_key = NULL;
    key->status = SM2_MLDSA65_HYBRID_HAVE_NOKEYS;
}

void sm2_mldsa65_hybrid_key_free(SM2_MLDSA65_HYBRID_KEY *key)
{
    if (key == NULL)
        return;

    sm2_mldsa65_hybrid_key_cleanup(key);
    OPENSSL_free(key->propq);
    OPENSSL_free(key);
}

int sm2_mldsa65_hybrid_key_serialize(SM2_MLDSA65_HYBRID_KEY *pkey,
                                    uint8_t *pk, size_t pksize, size_t *pklen,
                                    uint8_t *sk, size_t sksize, size_t *sklen)
{
    int ret = 0;
    BIGNUM *bn_sm2_sk = NULL;
    size_t len_tmp = 0;

    if (pk != NULL) {
        if (pksize < SM2_MLDSA65_HYBRID_PK_SIZE || pklen == NULL)
            goto err;
        if (!EVP_PKEY_get_octet_string_param(pkey->mldsa_key, OSSL_PKEY_PARAM_PUB_KEY, pk, MLDSA_PK_SIZE, &len_tmp) ||
            len_tmp != MLDSA_PK_SIZE)
            goto err;
        *pklen = len_tmp;
        if (!EVP_PKEY_get_octet_string_param(pkey->sm2_key, OSSL_PKEY_PARAM_PUB_KEY, pk + MLDSA_PK_SIZE, SM2_PK_SIZE, &len_tmp))
            goto err;
        *pklen += len_tmp;
    }

    if (sk != NULL) {
        if (sksize < SM2_MLDSA65_HYBRID_SK_SIZE || sklen == NULL)
            goto err;
        if (!EVP_PKEY_get_octet_string_param(pkey->mldsa_key, OSSL_PKEY_PARAM_ML_DSA_SEED, sk, MLDSA_SK_SIZE, &len_tmp) ||
            len_tmp != MLDSA_SK_SIZE)
            goto err;
        *sklen = len_tmp;
        if (!EVP_PKEY_get_bn_param(pkey->sm2_key, OSSL_PKEY_PARAM_PRIV_KEY, &bn_sm2_sk))
            goto err;
        if (!(len_tmp = BN_bn2binpad(bn_sm2_sk, sk + MLDSA_SK_SIZE, SM2_SK_SIZE)))
            goto err;
        *sklen += len_tmp;
    }
    ret = 1;
err:
    BN_free(bn_sm2_sk);
    return ret;
}

static int do_fromdata(OSSL_LIB_CTX *libctx, const char *propq, OSSL_PARAM *params,
                            EVP_PKEY **ppkey, const char *alg_name, int selection)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx;

    if ((ctx = EVP_PKEY_CTX_new_from_name(libctx, alg_name, propq)) == NULL
            || EVP_PKEY_fromdata_init(ctx) <= 0
            || EVP_PKEY_fromdata(ctx, ppkey, selection, params) <= 0)
        goto err;
    ret = 1;
err:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int sm2_mldsa65_hybrid_pub_key_deserialize(SM2_MLDSA65_HYBRID_KEY *key,
                                    const uint8_t *pk, size_t pklen)
{
    int ret = 0;
    OSSL_PARAM params[3], *p = params;
    char *group_name = SM2_MLDSA65_HYBRID_TNAME;

    if (pk == NULL)
        return SM2_MLDSA65_HYBRID_PK_SIZE;

    if (pklen < SM2_MLDSA65_HYBRID_PK_SIZE)
        goto err;

    /* Set ML-DSA public key */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                    (void*)pk, MLDSA_PK_SIZE);
    *p = OSSL_PARAM_construct_end();
    if (!do_fromdata(key->libctx, key->propq, params, &key->mldsa_key,
            SM2_MLDSA65_HYBRID_QNAME, OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        goto err;

    /* Set SM2 public key */
    p = params;
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                    (void*)(pk + MLDSA_PK_SIZE), SM2_PK_SIZE);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
    *p = OSSL_PARAM_construct_end();
    if (!do_fromdata(key->libctx, key->propq, params, &key->sm2_key,
        SM2_MLDSA65_HYBRID_TNAME, OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS))
        goto err;

    key->status |= SM2_MLDSA65_HYBRID_HAVE_PUBKEY;

    ret = 1;
err:
    if (!ret) {
        sm2_mldsa65_hybrid_key_cleanup(key);
    }
    return ret;
}

int sm2_mldsa65_hybrid_priv_key_deserialize(SM2_MLDSA65_HYBRID_KEY *key,
                                    const uint8_t *sk, size_t sklen)
{
    int ret = 0;
    OSSL_PARAM *p_mldsa = NULL, *p_sm2 = NULL;
    char *group_name = SM2_MLDSA65_HYBRID_TNAME;
    BIGNUM *bn_sm2_sk = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    uint8_t sm2_pub[SM2_PK_SIZE];
    size_t sm2_pub_len = 0;
    EC_GROUP *group = NULL;
    EC_POINT *pub_point = NULL;

    if (sk == NULL)
        return SM2_MLDSA65_HYBRID_SK_SIZE;

    if (sklen < SM2_MLDSA65_HYBRID_SK_SIZE)
        goto err;

    /* Set ML-DSA private key (seed) */
    if ((param_bld = OSSL_PARAM_BLD_new()) == NULL
        || !OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_ML_DSA_SEED, sk, MLDSA_SK_SIZE)
        || (p_mldsa = OSSL_PARAM_BLD_to_param(param_bld)) == NULL)
        goto err;

    if (!do_fromdata(key->libctx, key->propq, p_mldsa, &key->mldsa_key,
            SM2_MLDSA65_HYBRID_QNAME, OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        goto err;

    /* Set SM2 private key */
    if ((bn_sm2_sk = BN_bin2bn(sk + MLDSA_SK_SIZE, SM2_SK_SIZE, NULL)) == NULL)
        goto err;

    /* calc SM2 public key */
    if ((group = EC_GROUP_new_by_curve_name(SM2_MLDSA65_HYBRID_TID)) == NULL
        || (pub_point = EC_POINT_new(group)) == NULL
        || !EC_POINT_mul(group, pub_point, bn_sm2_sk, NULL, NULL, NULL)
        || (sm2_pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_COMPRESSED,
            sm2_pub, sizeof(sm2_pub), NULL)) != SM2_PK_SIZE)
        goto err;

    OSSL_PARAM_BLD_free(param_bld);
    if ((param_bld = OSSL_PARAM_BLD_new()) == NULL
        || !OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0)
        || !OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, sm2_pub, sm2_pub_len)
        || !OSSL_PARAM_BLD_push_BN_pad(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_sm2_sk, SM2_SK_SIZE)
        || (p_sm2 = OSSL_PARAM_BLD_to_param(param_bld)) == NULL)
        goto err;

    if (!do_fromdata(key->libctx, key->propq, p_sm2, &key->sm2_key,
        SM2_MLDSA65_HYBRID_TNAME, OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS))
        goto err;

    key->status |= SM2_MLDSA65_HYBRID_HAVE_PRVKEY;

    ret = 1;
err:
    BN_clear_free(bn_sm2_sk);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PARAM_free(p_mldsa);
    OSSL_PARAM_free(p_sm2);
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    if (!ret) {
        sm2_mldsa65_hybrid_key_cleanup(key);
    }
    return ret;
}
