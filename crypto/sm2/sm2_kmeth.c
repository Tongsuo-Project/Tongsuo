/*
 * Copyright 2022-2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

#include "internal/deprecated.h"

#include "internal/cryptlib.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include "crypto/sm2.h"
#include "crypto/ec.h" /* ecdh_KDF_X9_63() */
#include "crypto/sm2err.h"


int SM2_compute_key(void *out, size_t outlen, int initiator,
                    const uint8_t *peer_id, size_t peer_id_len,
                    const uint8_t *self_id, size_t self_id_len,
                    const EC_KEY *peer_ecdhe_key, const EC_KEY *self_ecdhe_key,
                    const EC_KEY *peer_pub_key, const EC_KEY *self_eckey,
                    const EVP_MD *md, OSSL_LIB_CTX *libctx,
                    const char *propq)
{
    BN_CTX *ctx = NULL;
    EC_POINT *UorV = NULL;
    const EC_POINT *Rs, *Rp;
    BIGNUM *Xuv = NULL, *Yuv = NULL, *Xs = NULL, *Xp = NULL;
    BIGNUM *h = NULL, *t = NULL, *two_power_w = NULL, *order = NULL;
    const BIGNUM *priv_key, *r;
    const EC_GROUP *group;
    int w;
    int ret = 0;
    size_t buflen = 0, md_len;
    unsigned char *buf = NULL;
    size_t field_len, idx = 0;

    if (peer_id == NULL || self_id == NULL || peer_ecdhe_key == NULL
            || self_ecdhe_key == NULL || peer_pub_key == NULL
            || self_eckey == NULL || md == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (outlen > INT_MAX) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    priv_key = EC_KEY_get0_private_key(self_eckey);
    if (priv_key == NULL) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_PRIVATE_KEY);
        return 0;
    }

    Rs = EC_KEY_get0_public_key(self_ecdhe_key);
    Rp = EC_KEY_get0_public_key(peer_ecdhe_key);
    r = EC_KEY_get0_private_key(self_ecdhe_key);

    if (Rs == NULL || Rp == NULL || r == NULL) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_PRIVATE_KEY);
        return 0;
    }

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    Xuv = BN_CTX_get(ctx);
    Yuv = BN_CTX_get(ctx);
    Xs = BN_CTX_get(ctx);
    Xp = BN_CTX_get(ctx);
    h = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);
    two_power_w = BN_CTX_get(ctx);
    order = BN_CTX_get(ctx);

    if (order == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    group = EC_KEY_get0_group(self_eckey);

    if (!EC_GROUP_get_order(group, order, ctx)
            || !EC_GROUP_get_cofactor(group, h, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    w = (BN_num_bits(order) + 1) / 2 - 1;
    if (!BN_lshift(two_power_w, BN_value_one(), w)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto err;
    }

    /*Third: Caculate -- X =  2 ^ w + (x & (2 ^ w - 1)) = 2 ^ w + (x mod 2 ^ w)*/
    UorV = EC_POINT_new(group);
    if (UorV == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Test peer public key On curve */
    if (!EC_POINT_is_on_curve(group, Rp, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto err;
    }

    /* Get x */
    if (!EC_POINT_get_affine_coordinates(group, Rs, Xs, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, Rp, Xp, NULL, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*x mod 2 ^ w*/
    /*Caculate Self x*/
    if (!BN_nnmod(Xs, Xs, two_power_w, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xs, Xs, two_power_w)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto err;
    }

    /*Caculate Peer x*/
    if (!BN_nnmod(Xp, Xp, two_power_w, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xp, Xp, two_power_w)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto err;
    }

    /*Forth: Caculate t*/
    if (!BN_mod_mul(t, Xs, r, order, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_mod_add(t, t, priv_key, order, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto err;
    }

    /*Fifth: Caculate V or U*/
    if (!BN_mul(t, t, h, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto err;
    }

    /* [x]R */
    if (!EC_POINT_mul(group, UorV, NULL, Rp, Xp, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto err;
    }

    /* P + [x]R */
    if (!EC_POINT_add(group, UorV, UorV,
                      EC_KEY_get0_public_key(peer_pub_key), ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_POINT_mul(group, UorV, NULL, UorV, t, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (EC_POINT_is_at_infinity(group, UorV)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*Sixth: Caculate Key -- Need Xuorv, Yuorv, Z_A, Z_B, klen*/
    if (!EC_POINT_get_affine_coordinates(group, UorV, Xuv, Yuv, ctx)) {
        ERR_raise(ERR_LIB_SM2, SM2_R_POINT_ARITHMETIC_FAILURE);
        goto err;
    }

    field_len = ((size_t)EC_GROUP_get_degree(group) + 7) / 8;
    md_len = EVP_MD_size(md);

    /* Xuorv || Yuorv || Z_A || Z_B */
    buflen = field_len * 2 + md_len * 2 ;

    buf = OPENSSL_secure_malloc(buflen);
    if (buf == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*1 : Get public key for UorV, Notice: the first byte is a tag, not a valid char*/
    if (BN_bn2binpad(Xuv, buf, field_len) < 0
            || BN_bn2binpad(Yuv, buf + field_len, field_len) < 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto err;
    }

    idx += field_len * 2;

    if (initiator) {
        if (!ossl_sm2_compute_z_digest((uint8_t *)(buf + idx), md,
                                       self_id, self_id_len,
                                       self_eckey))
            goto err;

        idx += md_len;
    }

    if (!ossl_sm2_compute_z_digest((uint8_t *)(buf + idx), md,
                                   peer_id, peer_id_len,
                                   peer_pub_key))
        goto err;

    idx += md_len;

    if (!initiator) {
        if (!ossl_sm2_compute_z_digest((uint8_t *)(buf + idx), md,
                                       self_id, self_id_len,
                                       self_eckey))
            goto err;

        idx += md_len;
    }

    if (!ossl_ecdh_kdf_X9_63(out, outlen, buf, idx, NULL, 0, md, libctx,
                             propq)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ret = outlen;

 err:
    EC_POINT_free(UorV);
    OPENSSL_secure_clear_free(buf, buflen);
    if (ctx != NULL)
        BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}
