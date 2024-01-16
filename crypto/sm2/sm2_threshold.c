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
    int ok = 0, len;
    const EC_KEY *eckey;
    const EC_GROUP *group;
    const BIGNUM *dA, *order;
    EC_POINT *Q = NULL;
    const EC_POINT *Q1 = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *dA_inv, *w2, *x1, *r = NULL, *s1 = NULL, *e = NULL;
    OSSL_LIB_CTX *libctx;
    ECDSA_SIG *tmpsig = NULL;

    if (key == NULL || peer_Q1 == NULL || digest == NULL || sig == NULL
        || siglen == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

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

    e = BN_bin2bn(digest, dlen, NULL);
    if (e == NULL)
        return 0;

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

    r = BN_new();
    if (r == NULL)
        goto done;

    s1 = BN_new();
    if (s1 == NULL)
        goto done;

    /*
     * SM2 threshold signature part 2:
     * 1. Generate a random number w2 in [1,n-1]
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

    len = i2d_ECDSA_SIG(tmpsig, sig);
    if (len < 0)
        goto done;

    *siglen = len;

    ok = 1;
 done:
    ECDSA_SIG_free(tmpsig);
    BN_free(r);
    BN_free(s1);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(Q);
    BN_free(e);

    return ok;
}

int SM2_THRESHOLD_sign3(const EVP_PKEY *key, const EVP_PKEY *temp_key,
                        const unsigned char *sig2, size_t sig2_len,
                        unsigned char **sig, size_t *siglen)
{
    int ok = 0, len;
    const EC_KEY *eckey;
    BIGNUM *w1 = NULL, *r = NULL, *s = NULL;
    const EC_GROUP *group;
    const BIGNUM *dA, *order;
    BN_CTX *ctx = NULL;
    OSSL_LIB_CTX *libctx;
    ECDSA_SIG *tmpsig = NULL;

    if (key == NULL || temp_key == NULL || sig2 == NULL || sig == NULL
        || siglen == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    eckey = EVP_PKEY_get0_EC_KEY(key);
    if (eckey == NULL)
        return 0;

    tmpsig = d2i_ECDSA_SIG(NULL, &sig2, sig2_len);
    if (tmpsig == NULL)
        return 0;

    if (!EVP_PKEY_get_bn_param(temp_key, OSSL_PKEY_PARAM_PRIV_KEY, &w1))
        goto done;

    group = EC_KEY_get0_group(eckey);
    dA = EC_KEY_get0_private_key(eckey);
    order = EC_GROUP_get0_order(group);
    libctx = ossl_ec_key_get_libctx(eckey);

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL)
        goto done;

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

    r = NULL;
    s = NULL;

    len = i2d_ECDSA_SIG(tmpsig, sig);
    if (len < 0)
        goto done;

    *siglen = len;

    ok = 1;
 done:
    BN_free(r);
    BN_free(s);
    BN_CTX_free(ctx);
    BN_free(w1);
    ECDSA_SIG_free(tmpsig);
    return ok;
}

int SM2_THRESHOLD_decrypt1(const unsigned char *ct, size_t ct_len, BIGNUM **wp,
                           EC_POINT **T1p)
{
    int ok = 0;
    BIGNUM *w = NULL;
    BN_CTX *ctx = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *C1 = NULL, *T1 = NULL;
    const BIGNUM *order;

    if (ct == NULL || wp == NULL || T1p == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (!ossl_sm2_ciphertext_decode(ct, ct_len, &C1, NULL, NULL, NULL, NULL))
        return 0;

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, NID_sm2);
    if (group == NULL)
        goto end;

    if (EC_POINT_is_at_infinity(group, C1))
        goto end;

    w = BN_new();
    if (w == NULL)
        goto end;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto end;

    order = EC_GROUP_get0_order(group);

    /* Generate a random number w in [1, n-1] */
    do {
        if (!BN_priv_rand_range_ex(w, order, 0, ctx))
            goto end;
    } while (BN_is_zero(w));

    T1 = EC_POINT_new(group);
    if (T1 == NULL)
        goto end;

    /*
     *  T_1 = [w]C_1
     */
    if (!EC_POINT_mul(group, T1, NULL, C1, w, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto end;
    }

    BN_free(*wp);
    *wp = w;
    w = NULL;
    EC_POINT_free(*T1p);
    *T1p = T1;
    T1 = NULL;

    ok = 1;
end:
    BN_free(w);
    EC_POINT_free(T1);
    EC_POINT_free(C1);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    return ok;
}

int SM2_THRESHOLD_decrypt2(const EVP_PKEY *key, const EC_POINT *T1,
                           EC_POINT **T2p)
{
    int ok = 0;
    const EC_KEY *eckey;
    const EC_GROUP *group;
    const BIGNUM *d2;
    BIGNUM *d2_inv = NULL;
    BN_CTX *ctx = NULL;
    EC_POINT *T2 = NULL;

    if (key == NULL || T1 == NULL || T2p == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    eckey = EVP_PKEY_get0_EC_KEY(key);
    if (eckey == NULL)
        return 0;

    group = EC_KEY_get0_group(eckey);
    d2 = EC_KEY_get0_private_key(eckey);
    if (d2 == NULL)
        return 0;

    ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(eckey));
    if (ctx == NULL)
        return 0;

    BN_CTX_start(ctx);
    d2_inv = BN_CTX_get(ctx);
    if (d2_inv == NULL)
        goto end;

    T2 = EC_POINT_new(group);
    if (T2 == NULL)
        goto end;

    /*
     *  T_2 = d_2^(-1) * T_1
     */
    if (!ossl_ec_group_do_inverse_ord(group, d2_inv, d2, ctx)
        || !EC_POINT_mul(group, T2, NULL, T1, d2_inv, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto end;
    }

    EC_POINT_free(*T2p);
    *T2p = T2;
    T2 = NULL;

    ok = 1;
end:
    EC_POINT_free(T2);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}

int SM2_THRESHOLD_decrypt3(const EVP_PKEY *key, const unsigned char *ct,
                           size_t ct_len, const BIGNUM *w, const EC_POINT *T2,
                           unsigned char **pt, size_t *pt_len)
{
    int ok = 0;
    const EC_KEY *eckey;
    const EC_GROUP *group;
    OSSL_LIB_CTX *libctx;
    const char *propq;
    const BIGNUM *field, *d1;
    BN_CTX *ctx = NULL;
    EC_POINT *C1 = NULL, *kP = NULL, *C1_inv = NULL;
    BIGNUM *x2, *y2, *d1_inv, *w_inv;
    uint8_t *C2 = NULL, *C3 = NULL, *msg_mask = NULL;
    size_t field_size, i, msg_len, C3_len;
    unsigned char *x2y2buf = NULL, *msg = NULL;
    EVP_MD_CTX *hash = NULL;
    const int hash_size = EVP_MD_get_size(EVP_sm3());
    unsigned char computed_C3[EVP_MAX_MD_SIZE];

    if (key == NULL || ct == NULL || w == NULL || T2 == NULL || pt == NULL
        || pt_len == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    eckey = EVP_PKEY_get0_EC_KEY(key);
    if (eckey == NULL)
        return 0;

    group = EC_KEY_get0_group(eckey);
    libctx = ossl_ec_key_get_libctx(eckey);
    propq = ossl_ec_key_get0_propq(eckey);

    d1 = EC_KEY_get0_private_key(eckey);
    if (d1 == NULL)
        return 0;

    if ((field = EC_GROUP_get0_field(group)) == NULL
        || (field_size = BN_num_bytes(field)) == 0)
        return 0;

    if (!ossl_sm2_ciphertext_decode(ct, ct_len, &C1, &C2, &msg_len, &C3,
                                    &C3_len))
        goto end;

    if (C3_len != (size_t)hash_size) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_ENCODING);
        goto end;
    }

    kP = EC_POINT_new(group);
    if (kP == NULL)
        goto end;

    C1_inv = EC_POINT_dup(C1, group);
    if (C1_inv == NULL)
        goto end;

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL)
        goto end;

    BN_CTX_start(ctx);
    x2 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);
    d1_inv = BN_CTX_get(ctx);
    w_inv = BN_CTX_get(ctx);
    if (w_inv == NULL)
        goto end;

    /*
     * [k]P = (x2, y2) = [w^(-1) * d_1^(-1)] * T_2 - C1
     */
    if (!ossl_ec_group_do_inverse_ord(group, d1_inv, d1, ctx)
        || !ossl_ec_group_do_inverse_ord(group, w_inv, w, ctx)
        || !EC_POINT_mul(group, kP, NULL, T2, w_inv, ctx)
        || !EC_POINT_mul(group, kP, NULL, kP, d1_inv, ctx)
        || !EC_POINT_invert(group, C1_inv, ctx)
        || !EC_POINT_add(group, kP, kP, C1_inv, ctx)
        || !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto end;
    }

    msg_mask = OPENSSL_malloc(msg_len);
    if (msg_mask == NULL) {
       ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
       goto end;
    }

    x2y2buf = OPENSSL_zalloc(2 * field_size);
    if (x2y2buf == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (BN_bn2binpad(x2, x2y2buf, field_size) < 0
            || BN_bn2binpad(y2, x2y2buf + field_size, field_size) < 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto end;
    }

    /* X9.63 with no salt happens to match the KDF used in SM2 */
    if (!ossl_ecdh_kdf_X9_63(msg_mask, msg_len, x2y2buf, 2 * field_size, NULL, 0,
                             EVP_sm3(), libctx, propq)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto end;
    }

    msg = OPENSSL_malloc(msg_len);
    if (msg == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    for (i = 0; i != msg_len; ++i)
        msg[i] = C2[i] ^ msg_mask[i];

    hash = EVP_MD_CTX_new();
    if (hash == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto end;
    }

    if (!EVP_DigestInit(hash, EVP_sm3())
            || !EVP_DigestUpdate(hash, x2y2buf, field_size)
            || !EVP_DigestUpdate(hash, msg, msg_len)
            || !EVP_DigestUpdate(hash, x2y2buf + field_size, field_size)
            || !EVP_DigestFinal(hash, computed_C3, NULL)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto end;
    }

    if (CRYPTO_memcmp(computed_C3, C3, hash_size) != 0) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_DIGEST);
        goto end;
    }

    OPENSSL_free(*pt);
    *pt = msg;
    msg = NULL;
    *pt_len = msg_len;

    ok = 1;
end:
    EVP_MD_CTX_free(hash);
    OPENSSL_free(msg);
    OPENSSL_free(x2y2buf);
    OPENSSL_free(msg_mask);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(C1_inv);
    EC_POINT_free(kP);
    OPENSSL_free(C2);
    OPENSSL_free(C3);
    EC_POINT_free(C1);
    return ok;
}
