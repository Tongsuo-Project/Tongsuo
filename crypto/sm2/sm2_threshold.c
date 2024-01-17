/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "internal/deprecated.h"

#include "crypto/sm2.h"
#include "crypto/sm2err.h"
#include "crypto/ec.h"
#include "internal/numbers.h"
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/sm2_threshold.h>
#include <openssl/core_names.h>

EVP_PKEY *SM2_THRESHOLD_derive_partial_pubkey(const EVP_PKEY *key)
{
    EVP_PKEY *ret = NULL;
    const EC_KEY *eckey = NULL;
    EC_KEY *tmpkey = NULL;
    const BIGNUM *dA;
    const EC_GROUP *group;
    EC_POINT *P1 = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *dA_inv = NULL;
    OSSL_LIB_CTX *libctx;

    if (key == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    eckey = EVP_PKEY_get0_EC_KEY(key);
    if (eckey == NULL)
        return 0;

    dA = EC_KEY_get0_private_key(eckey);
    group = EC_KEY_get0_group(eckey);
    libctx = ossl_ec_key_get_libctx(eckey);

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL)
        return 0;

    BN_CTX_start(ctx);
    dA_inv = BN_CTX_get(ctx);
    if (dA_inv == NULL)
        goto err;

    P1 = EC_POINT_new(group);
    if (P1 == NULL)
        goto err;

    /*
     * Compute the partial public key:
     *    P_1 = d_1^(-1) * G
     */
    if (!ossl_ec_group_do_inverse_ord(group, dA_inv, dA, ctx)
        || !EC_POINT_mul(group, P1, dA_inv, NULL, NULL, ctx))
        goto err;

    ret = EVP_PKEY_new();
    if (ret == NULL)
        goto err;

    tmpkey = EC_KEY_new_by_curve_name(NID_sm2);
    if (tmpkey == NULL)
        goto err;

    if (!EC_KEY_set_public_key(tmpkey, P1)
        || !EVP_PKEY_assign_EC_KEY(ret, tmpkey))
        goto err;

    EC_POINT_free(P1);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
err:
    EC_POINT_free(P1);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_KEY_free(tmpkey);
    EVP_PKEY_free(ret);
    return NULL;
}

EVP_PKEY *SM2_THRESHOLD_derive_complete_pubkey(const EVP_PKEY *self_key,
                                               const EVP_PKEY *peer_pubkey)
{
    EVP_PKEY *ret = NULL;
    const EC_KEY *eckey;
    const BIGNUM *d1;
    const EC_GROUP *group;
    EC_KEY *tmpkey = NULL;
    EC_POINT *P = NULL, *G_inv = NULL;
    const EC_POINT *P2;
    BN_CTX *ctx = NULL;
    BIGNUM *d1_inv = NULL;
    OSSL_LIB_CTX *libctx;

    if (self_key == NULL || peer_pubkey == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    eckey = EVP_PKEY_get0_EC_KEY(peer_pubkey);
    if (eckey == NULL)
        return NULL;

    P2 = EC_KEY_get0_public_key(eckey);

    eckey = EVP_PKEY_get0_EC_KEY(self_key);
    if (eckey == NULL)
        return NULL;

    d1 = EC_KEY_get0_private_key(eckey);
    group = EC_KEY_get0_group(eckey);
    libctx = ossl_ec_key_get_libctx(eckey);

    P = EC_POINT_new(group);
    if (P == NULL)
        goto err;

    G_inv = EC_POINT_dup(EC_GROUP_get0_generator(group), group);
    if (G_inv == NULL)
        goto err;

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL)
        goto err;

    BN_CTX_start(ctx);
    d1_inv = BN_CTX_get(ctx);
    if (d1_inv == NULL)
        goto err;

    /*
     * Compute the complete public key:
     *    P = d_1^(-1) * P_2 - G
     */
    if (!ossl_ec_group_do_inverse_ord(group, d1_inv, d1, ctx)
        || !EC_POINT_mul(group, P, NULL, P2, d1_inv, ctx)
        || !EC_POINT_invert(group, G_inv, ctx)
        || !EC_POINT_add(group, P, P, G_inv, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto err;
    }

    ret = EVP_PKEY_new();
    if (ret == NULL)
        goto err;

    tmpkey = EC_KEY_new_by_curve_name(NID_sm2);
    if (tmpkey == NULL)
        goto err;

    if (!EC_KEY_set_public_key(tmpkey, P)
        || !EVP_PKEY_assign_EC_KEY(ret, tmpkey))
        goto err;

    EC_POINT_free(G_inv);
    EC_POINT_free(P);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(G_inv);
    EC_POINT_free(P);
    EVP_PKEY_free(ret);

    return NULL;
}

int SM2_THRESHOLD_sign1_init(EVP_MD_CTX *ctx, const EVP_MD *type,
                             const EVP_PKEY *pubkey, const uint8_t *id,
                             const size_t id_len)
{
    int ret = 0;
    uint8_t *z = NULL;
    const EC_KEY *eckey;
    int md_size;

    if (ctx == NULL || type == NULL || pubkey == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    md_size = EVP_MD_get_size(type);
    z = OPENSSL_zalloc(md_size);
    if (z == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    eckey = EVP_PKEY_get0_EC_KEY(pubkey);
    if (eckey == NULL)
        goto end;

    /* get hashed prefix 'z' of tbs message */
    if (!ossl_sm2_compute_z_digest(z, type, id, id_len, eckey))
        goto end;

    if (!EVP_DigestInit(ctx, type)
        || !EVP_DigestUpdate(ctx, z, md_size))
        goto end;

    ret = 1;
end:
    OPENSSL_free(z);
    return ret;
}

int SM2_THRESHOLD_sign1_update(EVP_MD_CTX *ctx, const uint8_t *msg,
                               size_t msg_len)
{
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return EVP_DigestUpdate(ctx, msg, msg_len);
}

int SM2_THRESHOLD_sign1_final(EVP_MD_CTX *ctx, uint8_t *digest, size_t *dlen)
{
    int ret;
    unsigned int len = 0;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    ret = EVP_DigestFinal(ctx, digest, &len);
    if (dlen != NULL)
        *dlen = len;

    return ret;
}

int SM2_THRESHOLD_sign1_oneshot(const EVP_PKEY *pubkey,
                                const EVP_MD *type,
                                const uint8_t *id,
                                const size_t id_len,
                                const uint8_t *msg, size_t msg_len,
                                uint8_t *digest, size_t *dlen)
{
    EVP_MD_CTX *ctx = NULL;

    if (pubkey == NULL || type == NULL || msg == NULL || digest == NULL
        || dlen == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        return 0;
    }

    if (!SM2_THRESHOLD_sign1_init(ctx, type, pubkey, id, id_len)
        || !SM2_THRESHOLD_sign1_update(ctx, msg, msg_len)
        || !SM2_THRESHOLD_sign1_final(ctx, digest, dlen)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}

int SM2_THRESHOLD_sign2(const EVP_PKEY *key, const EVP_PKEY *peer_Q1,
                        uint8_t *digest, size_t dlen,
                        unsigned char **sig, size_t *siglen)
{
    int ret = 0;
    const EC_KEY *eckey;
    const EC_GROUP *group;
    const BIGNUM *dA, *order;
    EC_POINT *Q = NULL;
    const EC_POINT *Q1 = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *dA_inv = NULL, *w2 = NULL, *x1 = NULL, *r = NULL, *s1 = NULL, *e;
    OSSL_LIB_CTX *libctx;
    ECDSA_SIG *tmpsig = NULL;

    if (key == NULL || peer_Q1 == NULL || digest == NULL || sig == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    e = BN_bin2bn(digest, dlen, NULL);
    if (e == NULL)
        return 0;

    eckey = EVP_PKEY_get0_EC_KEY(peer_Q1);
    if (eckey == NULL)
        return 0;

    Q1 = EC_KEY_get0_public_key(eckey);
    if (Q1 == NULL)
        return 0;

    eckey = EVP_PKEY_get0_EC_KEY(key);
    if (eckey == NULL)
        return 0;

    group = EC_KEY_get0_group(eckey);
    order = EC_GROUP_get0_order(group);
    dA = EC_KEY_get0_private_key(eckey);
    libctx = ossl_ec_key_get_libctx(eckey);

    Q = EC_POINT_new(group);
    if (Q == NULL)
        goto done;

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL)
        goto done;

    BN_CTX_start(ctx);
    dA_inv = BN_CTX_get(ctx);
    w2 = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    if (x1 == NULL)
        goto done;

    /*
     * These values are returned and so should not be allocated out of the
     * context
     */
    r = BN_new();
    if (r == NULL)
        goto done;

    s1 = BN_new();
    if (s1 == NULL)
        goto done;

    /*
     * SM2 threshold signature part 2:
     * 1. Generate a random number w2 in [1,n-1] using random number generators;
     * 2. Compute Q = [w2]G + dA^(-1) * Q1
     * 3. Compute r = (e + x1) mod n
     * 4. Compute s1 = dA(r + w2) mod n
     */

    do {
        if (!BN_priv_rand_range_ex(w2, order, 0, ctx))
            goto done;
    } while (BN_is_zero(w2));

    if (!ossl_ec_group_do_inverse_ord(group, dA_inv, dA, ctx)
        || !EC_POINT_mul(group, Q, w2, Q1, dA_inv, ctx)
        || !EC_POINT_get_affine_coordinates(group, Q, x1, NULL, ctx))
        goto done;

    if (!BN_mod_add(r, e, x1, order, ctx)
        || !BN_add(s1, r, w2)
        || !BN_mod_mul(s1, s1, dA, order, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    tmpsig = ECDSA_SIG_new();
    if (tmpsig == NULL)
        goto done;

    /* a "partial" signature to stored r and s1 */
    if (!ECDSA_SIG_set0(tmpsig, r, s1))
        goto done;

    r = NULL;
    s1 = NULL;

    ret = i2d_ECDSA_SIG(tmpsig, sig);
    if (ret <= 0)
        goto done;

    if (siglen != NULL)
        *siglen = ret;

    ret = 1;

 done:
    BN_free(r);
    BN_free(s1);
    BN_free(e);
    ECDSA_SIG_free(tmpsig);
    EC_POINT_free(Q);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}

int SM2_THRESHOLD_sign3(const EVP_PKEY *key, const EVP_PKEY *temp_key,
                        const unsigned char *sig2, size_t sig2_len,
                        unsigned char **sig, size_t *siglen)
{
    int ret = 0;
    const EC_KEY *eckey;
    BIGNUM *w1 = NULL, *r = NULL, *s = NULL;
    const EC_GROUP *group;
    const BIGNUM *dA, *order;
    BN_CTX *ctx = NULL;
    OSSL_LIB_CTX *libctx;
    ECDSA_SIG *tmpsig = NULL;

    if (key == NULL || temp_key == NULL || sig2 == NULL || sig == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    tmpsig = d2i_ECDSA_SIG(NULL, &sig2, sig2_len);
    if (tmpsig == NULL)
        return 0;

    if (!EVP_PKEY_get_bn_param(temp_key, OSSL_PKEY_PARAM_PRIV_KEY, &w1))
        goto done;

    eckey = EVP_PKEY_get0_EC_KEY(key);
    if (eckey == NULL)
        return 0;

    group = EC_KEY_get0_group(eckey);
    dA = EC_KEY_get0_private_key(eckey);
    order = EC_GROUP_get0_order(group);
    libctx = ossl_ec_key_get_libctx(eckey);

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL)
        goto done;

    /*
     * These values are returned and so should not be allocated out of the
     * context
     */
    r = BN_dup(ECDSA_SIG_get0_r(tmpsig));
    if (r == NULL)
        goto done;

    s = BN_new();
    if (s == NULL)
        goto done;

    /*
     * SM2 threshold signature part 3:
     * s = (d1 * (s1 + w1) - r) mod n
     */
    if (!BN_add(s, ECDSA_SIG_get0_s(tmpsig), w1)
        || !BN_mod_mul(s, s, dA, order, ctx)
        || !BN_mod_sub(s, s, r, order, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    if (!ECDSA_SIG_set0(tmpsig, r, s))
        goto done;

    ret = i2d_ECDSA_SIG(tmpsig, sig);
    if (siglen != NULL)
        *siglen = ret;

    ret = 1;

 done:
    if (ret == 0) {
        BN_free(r);
        BN_free(s);
    }

    BN_CTX_free(ctx);
    BN_free(w1);
    return ret;
}
