/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <openssl/zkpbperr.h>
#include <openssl/zkp_transcript.h>
#include <crypto/zkp/common/zkp_util.h>
#include <crypto/ec/ec_local.h>
#include "inner_product.h"

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(EC_POINT)

bp_inner_product_pub_param_t *bp_inner_product_pub_param_new(const EC_GROUP *group,
                                                             STACK_OF(EC_POINT) *sk_G,
                                                             STACK_OF(EC_POINT) *sk_H)
{
    bp_inner_product_pub_param_t *pp = NULL;

    if (sk_EC_POINT_num(sk_G) != sk_EC_POINT_num(sk_H)) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (!(pp = OPENSSL_zalloc(sizeof(*pp)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    pp->group = group;
    pp->sk_G = sk_G;
    pp->sk_H = sk_H;

    return pp;
}

void bp_inner_product_pub_param_free(bp_inner_product_pub_param_t *pp)
{
    if (!pp)
        return;

    OPENSSL_clear_free((void *)pp, sizeof(*pp));
}

bp_inner_product_ctx_t *bp_inner_product_ctx_new(bp_inner_product_pub_param_t *pp,
                                                 ZKP_TRANSCRIPT *transcript,
                                                 EC_POINT *U, EC_POINT *P,
                                                 STACK_OF(BIGNUM) *sk_G_factors,
                                                 STACK_OF(BIGNUM) *sk_H_factors)
{
    bp_inner_product_ctx_t *ctx = NULL;

    if (pp == NULL || U == NULL || transcript == NULL
        || sk_G_factors == NULL || sk_H_factors == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (sk_BIGNUM_num(sk_G_factors) != sk_EC_POINT_num(pp->sk_G)
        || sk_BIGNUM_num(sk_H_factors) != sk_EC_POINT_num(pp->sk_H)) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (!(ctx = OPENSSL_zalloc(sizeof(*ctx)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->pp = pp;
    ctx->transcript = transcript;
    ctx->sk_G_factors = sk_G_factors;
    ctx->sk_H_factors = sk_H_factors;

    if (!(ctx->U = EC_POINT_dup(U, pp->group)))
        goto err;

    if (P != NULL && !(ctx->P = EC_POINT_dup(P, pp->group)))
        goto err;

    return ctx;

err:
    bp_inner_product_ctx_free(ctx);
    return NULL;
}

void bp_inner_product_ctx_free(bp_inner_product_ctx_t *ctx)
{
    if (!ctx)
        return;

    EC_POINT_free(ctx->U);
    EC_POINT_free(ctx->P);
    OPENSSL_clear_free((void *)ctx, sizeof(*ctx));
}

bp_inner_product_witness_t *bp_inner_product_witness_new(STACK_OF(BIGNUM) *sk_a,
                                                         STACK_OF(BIGNUM) *sk_b)
{
    bp_inner_product_witness_t *witness = NULL;

    if (!sk_a || !sk_b) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (sk_BIGNUM_num(sk_a) != sk_BIGNUM_num(sk_b)) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (!(witness = OPENSSL_zalloc(sizeof(*witness)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    witness->sk_a = sk_a;
    witness->sk_b = sk_b;

    return witness;
}

void bp_inner_product_witness_free(bp_inner_product_witness_t *witness)
{
    if (!witness)
        return;

    OPENSSL_free(witness);
}

bp_inner_product_proof_t *bp_inner_product_proof_alloc(int n)
{
    bp_inner_product_proof_t *proof = NULL;

    proof = OPENSSL_zalloc(sizeof(*proof));
    if (!proof) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    proof->sk_L = sk_EC_POINT_new_reserve(NULL, n);
    if (!proof->sk_L) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    proof->sk_R = sk_EC_POINT_new_reserve(NULL, n);
    if (!proof->sk_R) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!(proof->a = BN_new()) || !(proof->b = BN_new()))
        goto err;

    return proof;
err:
    bp_inner_product_proof_free(proof);
    return NULL;
}

bp_inner_product_proof_t *bp_inner_product_proof_new(bp_inner_product_ctx_t *ctx)
{
    int n;

    if (ctx == NULL || ctx->pp == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
    }

    n = sk_EC_POINT_num(ctx->pp->sk_G);
    return bp_inner_product_proof_alloc(n);
}

void bp_inner_product_proof_free(bp_inner_product_proof_t *proof)
{
    if (!proof)
        return;

    BN_free(proof->a);
    BN_free(proof->b);

    sk_EC_POINT_pop_free(proof->sk_L, EC_POINT_free);
    sk_EC_POINT_pop_free(proof->sk_R, EC_POINT_free);

    OPENSSL_free(proof);
}

bp_inner_product_proof_t *bp_inner_product_proof_prove(bp_inner_product_ctx_t *ctx,
                                                       bp_inner_product_witness_t *witness)
{
    int i, j, m, n, pp_num, poly_num;
    ZKP_TRANSCRIPT *transcript;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *x, *x_inv, *t, *cL, *cR, *a, *b, *u, *u_inv;
    BIGNUM *G_factors_L, *G_factors_R, *H_factors_L, *H_factors_R;
    BIGNUM *a_L, *a_R, *b_L, *b_R, *aL, *aR, *bL, *bR, *sk_a_L, *sk_b_L;
    EC_POINT *L = NULL, *R = NULL, *P = NULL;
    EC_POINT *G_L, *G_R, *H_L, *H_R, *sk_G_L, *sk_H_L;
    STACK_OF(EC_POINT) *sk_G = NULL, *sk_H = NULL, *p_sk_G, *p_sk_H;
    STACK_OF(BIGNUM) *sk_a = NULL, *sk_b = NULL, *p_sk_a, *p_sk_b;
    zkp_poly_points_t *poly_l = NULL, *poly_r = NULL, *poly_g = NULL, *poly_h = NULL;
    const BIGNUM *order;
    const EC_GROUP *group;
    bp_inner_product_pub_param_t *pp;
    bp_inner_product_proof_t *proof = NULL, *ret = NULL;

    if (!ctx || !witness || !ctx->pp) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    transcript = ctx->transcript;
    pp = ctx->pp;
    group = pp->group;
    order = EC_GROUP_get0_order(group);
    pp_num = sk_EC_POINT_num(pp->sk_G);
    poly_num = pp_num + 1;

    if (pp_num != sk_BIGNUM_num(witness->sk_a)) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (!(proof = bp_inner_product_proof_new(ctx)))
        goto end;

    if (!(poly_l = zkp_poly_points_new(poly_num)) || !(poly_r = zkp_poly_points_new(poly_num))
        || !(poly_g = zkp_poly_points_new(2)) || !(poly_h = zkp_poly_points_new(2)))
        goto end;

    if (!(sk_G = sk_EC_POINT_new_reserve(NULL, pp_num))
        || !(sk_H = sk_EC_POINT_new_reserve(NULL, pp_num))
        || !(sk_a = sk_BIGNUM_new_reserve(NULL, pp_num))
        || !(sk_b = sk_BIGNUM_new_reserve(NULL, pp_num))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    bn_ctx = BN_CTX_new_ex(group->libctx);
    if (bn_ctx == NULL)
        goto end;

    BN_CTX_start(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    x_inv = BN_CTX_get(bn_ctx);
    cL = BN_CTX_get(bn_ctx);
    cR = BN_CTX_get(bn_ctx);
    t = BN_CTX_get(bn_ctx);
    if (t == NULL)
        goto end;

    p_sk_G = pp->sk_G;
    p_sk_H = pp->sk_H;
    p_sk_a = witness->sk_a;
    p_sk_b = witness->sk_b;

    for (i = 0; i < pp_num; i++) {
        if (!(P = EC_POINT_new(group)) || sk_EC_POINT_push(sk_G, P) <= 0)
            goto end;

        P = NULL;

        if (!(P = EC_POINT_new(group)) || sk_EC_POINT_push(sk_H, P) <= 0)
            goto end;

        P = NULL;

        if (!(a = BN_CTX_get(bn_ctx)) || sk_BIGNUM_push(sk_a, a) <= 0
            || !(b = BN_CTX_get(bn_ctx)) || sk_BIGNUM_push(sk_b, b) <= 0)
            goto end;
    }

    for (n = pp_num, j = 0; n > 1; n = m, j++) {
        m = n / 2;

        BN_zero(cL);
        BN_zero(cR);

        if (!(L = EC_POINT_new(group)) || !(R = EC_POINT_new(group)))
            goto end;

        if (!EC_POINT_set_to_infinity(group, L)
            || !EC_POINT_set_to_infinity(group, R))
            goto end;

        zkp_poly_points_reset(poly_l);
        zkp_poly_points_reset(poly_r);

        for (i = 0; i < m; i++) {
            /* (21) */
            a_L = sk_BIGNUM_value(p_sk_a, i);
            b_R = sk_BIGNUM_value(p_sk_b, i + m);
            if (!BN_mul(t, a_L, b_R, bn_ctx)
                || !BN_mod_add(cL, cL, t, order, bn_ctx))
                goto end;

            /* (22) */
            a_R = sk_BIGNUM_value(p_sk_a, i + m);
            b_L = sk_BIGNUM_value(p_sk_b, i);
            if (!BN_mul(t, a_R, b_L, bn_ctx)
                || !BN_mod_add(cR, cR, t, order, bn_ctx))
                goto end;

            aL = BN_CTX_get(bn_ctx);
            aR = BN_CTX_get(bn_ctx);
            bL = BN_CTX_get(bn_ctx);
            bR = BN_CTX_get(bn_ctx);
            if (bR == NULL)
                goto end;

            if (p_sk_G == pp->sk_G) {
                G_factors_L = sk_BIGNUM_value(ctx->sk_G_factors, i);
                G_factors_R = sk_BIGNUM_value(ctx->sk_G_factors, i + m);

                if (!BN_mod_mul(aL, a_L, G_factors_R, order, bn_ctx))
                    goto end;

                if (!BN_mod_mul(aR, a_R, G_factors_L, order, bn_ctx))
                    goto end;

                H_factors_L = sk_BIGNUM_value(ctx->sk_H_factors, i);
                H_factors_R = sk_BIGNUM_value(ctx->sk_H_factors, i + m);

                if (!BN_mod_mul(bL, b_L, H_factors_R, order, bn_ctx))
                    goto end;

                if (!BN_mod_mul(bR, b_R, H_factors_L, order, bn_ctx))
                    goto end;
            } else {
                if (!BN_copy(aL, a_L) || !BN_copy(aR, a_R)
                    || !BN_copy(bL, b_L) || !BN_copy(bR, b_R))
                    goto end;

            }

            G_L = sk_EC_POINT_value(p_sk_G, i);
            G_R = sk_EC_POINT_value(p_sk_G, i + m);
            H_L = sk_EC_POINT_value(p_sk_H, i);
            H_R = sk_EC_POINT_value(p_sk_H, i + m);

            if (!zkp_poly_points_append(poly_l, G_R, aL)
                || !zkp_poly_points_append(poly_l, H_L, bR)
                || !zkp_poly_points_append(poly_r, G_L, aR)
                || !zkp_poly_points_append(poly_r, H_R, bL))
                goto end;
        }

        /* (23, 24) */
        if (!zkp_poly_points_append(poly_l, ctx->U, cL)
            || !zkp_poly_points_append(poly_r, ctx->U, cR))
            goto end;

        if (!zkp_poly_points_mul(poly_l, L, NULL, group, bn_ctx)
            || !zkp_poly_points_mul(poly_r, R, NULL, group, bn_ctx))
            goto end;

        /* compute the challenge */
        if (!ZKP_TRANSCRIPT_append_point(transcript, "L", L, group)
            || !ZKP_TRANSCRIPT_append_point(transcript, "R", R, group))
            goto end;

        if (!ZKP_TRANSCRIPT_challange(transcript, "x", x))
            goto end;

        /* (26, 27) */
        if (!BN_mod_inverse(x_inv, x, order, bn_ctx))
            goto end;

        for (i = 0; i < m; i++) {
            u = BN_CTX_get(bn_ctx);
            u_inv = BN_CTX_get(bn_ctx);
            if (u_inv == NULL)
                goto end;

            if (n == pp_num) {
                G_factors_L = sk_BIGNUM_value(ctx->sk_G_factors, i);
                G_factors_R = sk_BIGNUM_value(ctx->sk_G_factors, i + m);

                if (!BN_mod_mul(u_inv, x_inv, G_factors_L, order, bn_ctx)
                    || !BN_mod_mul(u, x, G_factors_R, order, bn_ctx))
                    goto end;
            } else {
                if (!BN_copy(u, x) || !BN_copy(u_inv, x_inv))
                    goto end;
            }

            zkp_poly_points_reset(poly_g);

            G_L = sk_EC_POINT_value(p_sk_G, i);
            G_R = sk_EC_POINT_value(p_sk_G, i + m);
            sk_G_L = sk_EC_POINT_value(sk_G, i);

            if (!zkp_poly_points_append(poly_g, G_L, u_inv)
                || !zkp_poly_points_append(poly_g, G_R, u))
                goto end;

            /* (29) */
            if (!zkp_poly_points_mul(poly_g, sk_G_L, NULL, group, bn_ctx))
                goto end;

            u = BN_CTX_get(bn_ctx);
            u_inv = BN_CTX_get(bn_ctx);
            if (u_inv == NULL)
                goto end;

            if (n == pp_num) {
                H_factors_L = sk_BIGNUM_value(ctx->sk_H_factors, i);
                H_factors_R = sk_BIGNUM_value(ctx->sk_H_factors, i + m);

                if (!BN_mod_mul(u, x, H_factors_L, order, bn_ctx)
                    || !BN_mod_mul(u_inv, x_inv, H_factors_R, order, bn_ctx))
                    goto end;
            } else {
                if (!BN_copy(u, x) || !BN_copy(u_inv, x_inv))
                    goto end;
            }

            zkp_poly_points_reset(poly_h);

            H_L = sk_EC_POINT_value(p_sk_H, i);
            H_R = sk_EC_POINT_value(p_sk_H, i + m);
            sk_H_L = sk_EC_POINT_value(sk_H, i);

            if (!zkp_poly_points_append(poly_h, H_L, u)
                || !zkp_poly_points_append(poly_h, H_R, u_inv))
                goto end;

            /* (30) */
            if (!zkp_poly_points_mul(poly_h, sk_H_L, NULL, group, bn_ctx))
                goto end;

            sk_a_L = sk_BIGNUM_value(sk_a, i);
            sk_b_L = sk_BIGNUM_value(sk_b, i);
            a_L = sk_BIGNUM_value(p_sk_a, i);
            a_R = sk_BIGNUM_value(p_sk_a, i + m);
            b_L = sk_BIGNUM_value(p_sk_b, i);
            b_R = sk_BIGNUM_value(p_sk_b, i + m);

            /* (33) */
            if (!BN_mod_mul(sk_a_L, a_L, x, order, bn_ctx)
                || !BN_mod_mul(t, a_R, x_inv, order, bn_ctx)
                || !BN_mod_add(sk_a_L, sk_a_L, t, order, bn_ctx))
                goto end;

            /* (34) */
            if (!BN_mod_mul(sk_b_L, b_L, x_inv, order, bn_ctx)
                || !BN_mod_mul(t, b_R, x, order, bn_ctx)
                || !BN_mod_add(sk_b_L, sk_b_L, t, order, bn_ctx))
                goto end;
        }

        if (sk_EC_POINT_push(proof->sk_L, L) <= 0
            || sk_EC_POINT_push(proof->sk_R, R) <= 0)
            goto end;

        L = R = NULL;
        p_sk_G = sk_G;
        p_sk_H = sk_H;
        p_sk_a = sk_a;
        p_sk_b = sk_b;
    }

    if (!BN_copy(proof->a, sk_BIGNUM_value(p_sk_a, 0))
        || !BN_copy(proof->b, sk_BIGNUM_value(p_sk_b, 0)))
        goto end;

    /*
    BN_debug_print(NULL, proof->a, "ip_proof->a");
    BN_debug_print(NULL, proof->b, "ip_proof->b");
    */

    ret = proof;
    proof = NULL;

end:
    sk_BIGNUM_free(sk_a);
    sk_BIGNUM_free(sk_b);
    sk_EC_POINT_pop_free(sk_G, EC_POINT_free);
    sk_EC_POINT_pop_free(sk_H, EC_POINT_free);

    EC_POINT_free(L);
    EC_POINT_free(R);
    EC_POINT_free(P);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    zkp_poly_points_free(poly_l);
    zkp_poly_points_free(poly_r);
    zkp_poly_points_free(poly_g);
    zkp_poly_points_free(poly_h);

    bp_inner_product_proof_free(proof);

    return ret;
}


int bp_inner_product_proof_verify(bp_inner_product_ctx_t *ctx,
                                  bp_inner_product_proof_t *proof)
{
    int ret = 0;
    int i, j, m, n, proof_num, pp_num;
    EC_POINT *P = NULL, *L, *R, *G, *H;
    ZKP_TRANSCRIPT *transcript;
    BN_CTX *bn_ctx = NULL;
    BIGNUM **vec_x = NULL, **vec_x_inv = NULL, *G_factors, *H_factors;
    BIGNUM *s, *s_inv, *u, *u_inv, *x2, *x2_inv;
    zkp_poly_points_t *poly = NULL;
    const BIGNUM *order;
    const EC_GROUP *group;
    bp_inner_product_pub_param_t *pp;

    if (!ctx || !proof) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    transcript = ctx->transcript;
    pp = ctx->pp;
    group = pp->group;
    order = EC_GROUP_get0_order(group);
    pp_num = sk_EC_POINT_num(pp->sk_G);
    proof_num = sk_EC_POINT_num(proof->sk_L);
    n = 2 * proof_num  + 2 * pp_num + 1;

    if (!(vec_x = OPENSSL_zalloc(proof_num * sizeof(*vec_x)))
        || !(vec_x_inv = OPENSSL_zalloc(proof_num * sizeof(*vec_x_inv)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (!(poly = zkp_poly_points_new(n)))
        goto end;

    if (!(P = EC_POINT_new(group)))
        goto end;

    bn_ctx = BN_CTX_new_ex(group->libctx);
    if (!bn_ctx)
        goto end;

    BN_CTX_start(bn_ctx);
    s = BN_CTX_get(bn_ctx);
    s_inv = BN_CTX_get(bn_ctx);
    if (s_inv == NULL)
        goto end;

    for (i = 0; i < proof_num; i++) {
        vec_x[i] = BN_CTX_get(bn_ctx);
        vec_x_inv[i] = BN_CTX_get(bn_ctx);
        x2 = BN_CTX_get(bn_ctx);
        x2_inv = BN_CTX_get(bn_ctx);
        if (x2_inv == NULL)
            goto end;

        L = sk_EC_POINT_value(proof->sk_L, i);
        R = sk_EC_POINT_value(proof->sk_R, i);

        /* compute hash */
        if (!ZKP_TRANSCRIPT_append_point(transcript, "L", L, group)
            || !ZKP_TRANSCRIPT_append_point(transcript, "R", R, group))
            goto end;

        if (!ZKP_TRANSCRIPT_challange(transcript, "x", vec_x[i]))
            goto end;

        if (!BN_mod_inverse(vec_x_inv[i], vec_x[i], order, bn_ctx)
            || !BN_mod_sqr(x2, vec_x[i], order, bn_ctx)
            || !BN_mod_inverse(x2_inv, x2, order, bn_ctx))
            goto end;

        BN_set_negative(x2, !BN_is_negative(x2));
        BN_set_negative(x2_inv, !BN_is_negative(x2_inv));

        if (!zkp_poly_points_append(poly, L, x2) || !zkp_poly_points_append(poly, R, x2_inv))
            goto end;
    }

    for (i = 0; i < pp_num; i++) {
        G = sk_EC_POINT_value(pp->sk_G, i);
        H = sk_EC_POINT_value(pp->sk_H, i);
        G_factors = sk_BIGNUM_value(ctx->sk_G_factors, i);
        H_factors = sk_BIGNUM_value(ctx->sk_H_factors, i);

        u = BN_CTX_get(bn_ctx);
        u_inv = BN_CTX_get(bn_ctx);
        if (u == NULL)
            goto end;

        BN_one(s);
        for (j = 0; j < proof_num; j++) {
            m = i & (1 << (proof_num - j - 1));
            if (!BN_mod_mul(s, s, m ? vec_x[j] : vec_x_inv[j], order, bn_ctx))
                goto end;
        }

        if (!BN_mod_inverse(s_inv, s, order, bn_ctx))
            goto end;

        if (!BN_mod_mul(s, s, proof->a, order, bn_ctx)
            || !BN_mod_mul(u, s, G_factors, order, bn_ctx)
            || !BN_mod_mul(s_inv, s_inv, proof->b, order, bn_ctx)
            || !BN_mod_mul(u_inv, s_inv, H_factors, order, bn_ctx))
            goto end;

        if (!zkp_poly_points_append(poly, G, u) || !zkp_poly_points_append(poly, H, u_inv))
            goto end;
    }

    if (!BN_mod_mul(s, proof->a, proof->b, order, bn_ctx))
        goto end;

    if (!zkp_poly_points_append(poly, ctx->U, s))
        goto end;

    if (!zkp_poly_points_mul(poly, P, NULL, group, bn_ctx))
        goto end;

    ret = EC_POINT_cmp(group, P, ctx->P, bn_ctx) == 0;

end:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    zkp_poly_points_free(poly);
    EC_POINT_free(P);
    OPENSSL_free(vec_x);
    OPENSSL_free(vec_x_inv);
    return ret;
}
