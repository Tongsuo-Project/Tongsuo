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
#include <crypto/ec/ec_local.h>
#include "inner_product.h"
#include "util.h"

#define BP_POINT_BN_COPY(dp, sp, db, sb)                                    \
        do {                                                                \
            if (!dp) {                                                      \
                if (!(dp = EC_POINT_dup(sp, group)) || !(db = BN_dup(sb)))  \
                    goto end;                                               \
            } else {                                                        \
                if (!EC_POINT_copy(dp, sp) || !BN_copy(db, sb))             \
                    goto end;                                               \
            }                                                               \
        } while (0)

bp_inner_product_pub_param_t *bp_inner_product_pub_param_new(int curve_id)
{
    bp_inner_product_pub_param_t *pp = NULL;

    if (!(pp = OPENSSL_zalloc(sizeof(*pp)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    pp->curve_id = curve_id;

    return pp;
}

void bp_inner_product_pub_param_free(bp_inner_product_pub_param_t *pp)
{
    if (!pp)
        return;

    if (pp->initial) {
        bp_random_ec_points_free(pp->vec_G, pp->n);
        bp_random_ec_points_free(pp->vec_H, pp->n);
    }

    OPENSSL_clear_free((void *)pp, sizeof(bp_inner_product_pub_param_t));
}

int bp_inner_product_pub_param_set(bp_inner_product_pub_param_t *pp,
                                   EC_POINT **vec_G, EC_POINT **vec_H,
                                   int n)
{
    if (!pp || !vec_G || !vec_H || n <= 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    pp->n = n;
    pp->vec_G = vec_G;
    pp->vec_H = vec_H;

    return 1;
}

int bp_inner_product_pub_param_gen(bp_inner_product_pub_param_t *pp, int n)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;

    if (!pp || pp->curve_id <= 0 || pp->initial || n <= 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return ret;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, pp->curve_id);
    if (group == NULL)
        goto err;


    bn_ctx = BN_CTX_new_ex(group->libctx);
    if (bn_ctx == NULL)
        goto err;

    pp->n = n;
    pp->initial = 1;

    if (!(pp->vec_G = bp_random_ec_points_new(group, n, bn_ctx))
        || !(pp->vec_H = bp_random_ec_points_new(group, n, bn_ctx)))
        goto err;

    ret = 1;
err:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    bp_inner_product_pub_param_free(pp);
    return ret;
}

bp_inner_product_ctx_t *bp_inner_product_ctx_new(bp_inner_product_pub_param_t *pp,
                                                 BP_TRANSCRIPT *transcript,
                                                 EC_POINT *U, EC_POINT *P,
                                                 BIGNUM **vec_G_factors,
                                                 BIGNUM **vec_H_factors,
                                                 int factors_num)
{
    bp_inner_product_ctx_t *ctx = NULL;

    if (pp == NULL || U == NULL || transcript == NULL
        || vec_G_factors == NULL || vec_H_factors == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (factors_num > pp->n) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (!(ctx = OPENSSL_zalloc(sizeof(*ctx)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    ctx->pp = pp;
    ctx->transcript = transcript;
    ctx->factors_num = factors_num;
    ctx->vec_G_factors = vec_G_factors;
    ctx->vec_H_factors = vec_H_factors;

    //ctx->group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, NID_X9_62_prime256v1);
    ctx->group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, pp->curve_id);
    if (ctx->group == NULL)
        goto err;

    if (!(ctx->U = EC_POINT_dup(U, ctx->group)))
        goto err;

    if (P != NULL && !(ctx->P = EC_POINT_dup(P, ctx->group)))
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
    EC_GROUP_free(ctx->group);
    OPENSSL_clear_free((void *)ctx, sizeof(bp_inner_product_ctx_t));
}

bp_inner_product_witness_t *bp_inner_product_witness_new(BIGNUM **vec_a,
                                                         BIGNUM **vec_b,
                                                         int n)
{
    bp_inner_product_witness_t *witness = NULL;

    if (!vec_a || !vec_b || n <= 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (!(witness = OPENSSL_zalloc(sizeof(*witness)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    witness->vec_a = vec_a;
    witness->vec_b = vec_b;
    witness->n = n;

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

    proof->vec_L = OPENSSL_zalloc(n * sizeof(*proof->vec_L));
    if (!proof->vec_L) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    proof->vec_R = OPENSSL_zalloc(n * sizeof(*proof->vec_R));
    if (!proof->vec_R) {
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
    return bp_inner_product_proof_alloc(ctx->pp->n);
}

void bp_inner_product_proof_free(bp_inner_product_proof_t *proof)
{
    int i;

    if (!proof)
        return;

    BN_free(proof->a);
    BN_free(proof->b);

    for (i = 0; i < proof->n; i++) {
        EC_POINT_free(proof->vec_L[i]);
        EC_POINT_free(proof->vec_R[i]);
    }

    OPENSSL_free(proof->vec_L);
    OPENSSL_free(proof->vec_R);
    OPENSSL_free(proof);
}

int bp_inner_product_proof_prove(bp_inner_product_ctx_t *ctx,
                                 bp_inner_product_witness_t *witness,
                                 bp_inner_product_proof_t *proof)
{
    int ret = 0;
    int i, j, k, m, n, vec_len;
    BP_TRANSCRIPT *transcript;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *T = NULL, *P = NULL, *L = NULL, *R = NULL;
    EC_POINT **pG, **pH, **vec_G = NULL, **vec_H = NULL;
    EC_POINT **vec_L = NULL, **vec_R = NULL;
    BIGNUM **vec_l = NULL, **vec_r = NULL;
    BIGNUM **pa, **pb, **vec_a = NULL, **vec_b = NULL;
    BIGNUM *x, *x_inv, *x2, *x2_inv, *t, *cL, *cR;
    const BIGNUM *order;
    EC_GROUP *group;
    bp_inner_product_pub_param_t *pp;

    if (!ctx || !witness || !proof) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    transcript = ctx->transcript;
    pp = ctx->pp;
    group = ctx->group;
    order = EC_GROUP_get0_order(group);
    vec_len = pp->n + 3;

    if (!(T = EC_POINT_new(group))
        || !(L = EC_POINT_new(group))
        || !(R = EC_POINT_new(group)))
        goto end;

    if (!(vec_G = OPENSSL_zalloc(pp->n * sizeof(*vec_G)))
        || !(vec_H = OPENSSL_zalloc(pp->n * sizeof(*vec_H)))
        || !(vec_a = OPENSSL_zalloc(pp->n * sizeof(*vec_a)))
        || !(vec_b = OPENSSL_zalloc(pp->n * sizeof(*vec_b)))
        || !(vec_L = OPENSSL_zalloc(vec_len * sizeof(*vec_L)))
        || !(vec_l = OPENSSL_zalloc(vec_len * sizeof(*vec_l)))
        || !(vec_R = OPENSSL_zalloc(vec_len * sizeof(*vec_R)))
        || !(vec_r = OPENSSL_zalloc(vec_len * sizeof(*vec_r)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    bn_ctx = BN_CTX_new_ex(group->libctx);
    if (bn_ctx == NULL)
        goto end;

    BN_CTX_start(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    x_inv = BN_CTX_get(bn_ctx);
    x2 = BN_CTX_get(bn_ctx);
    x2_inv = BN_CTX_get(bn_ctx);
    cL = BN_CTX_get(bn_ctx);
    cR = BN_CTX_get(bn_ctx);
    t = BN_CTX_get(bn_ctx);
    if (t == NULL)
        goto end;

    pa = witness->vec_a;
    pb = witness->vec_b;
    pG = pp->vec_G;
    pH = pp->vec_H;

    for (i = 0; i < pp->n; i++) {
        if (!(vec_G[i] = EC_POINT_new(group))
            || !(vec_H[i] = EC_POINT_new(group))
            || !(vec_a[i] = BN_CTX_get(bn_ctx))
            || !(vec_b[i] = BN_CTX_get(bn_ctx)))
            goto end;
    }

    for (n = pp->n, j = 0; n > 1; n = m, j++) {
        m = n / 2;

        BN_zero(cL);
        BN_zero(cR);

        if (!EC_POINT_set_to_infinity(group, L)
            || !EC_POINT_set_to_infinity(group, R))
            goto end;

        for (i = 0, k = 0; i < m; i++, k += 2) {
            /* (21) */
            if (!BN_mul(t, pa[i], pb[m+i], bn_ctx)
                || !BN_mod_add(cL, cL, t, order, bn_ctx))
                goto end;

            /* (22) */
            if (!BN_mul(t, pa[m+i], pb[i], bn_ctx)
                || !BN_mod_add(cR, cR, t, order, bn_ctx))
                goto end;

            BP_POINT_BN_COPY(vec_L[k], pG[m+i], vec_l[k], pa[i]);
            BP_POINT_BN_COPY(vec_L[k+1], pH[i], vec_l[k+1], pb[m+i]);

            BP_POINT_BN_COPY(vec_R[k], pG[i], vec_r[k], pa[m+i]);
            BP_POINT_BN_COPY(vec_R[k+1], pH[m+i], vec_r[k+1], pb[i]);

            if (pG == pp->vec_G) {
                if (!BN_mod_mul(vec_l[k], vec_l[k], ctx->vec_G_factors[m+i],
                                order, bn_ctx)
                    || !BN_mod_mul(vec_r[k], vec_r[k], ctx->vec_G_factors[i],
                                order, bn_ctx))
                    goto end;
            }

            if (pH == pp->vec_H) {
                if (!BN_mod_mul(vec_l[k+1], vec_l[k+1], ctx->vec_H_factors[i],
                                order, bn_ctx)
                    || !BN_mod_mul(vec_r[k+1], vec_r[k+1], ctx->vec_H_factors[m+i],
                                order, bn_ctx))
                    goto end;
            }
        }

        /* (23) */
        BP_POINT_BN_COPY(vec_L[k], ctx->U, vec_l[k], cL);
        if (!EC_POINTs_mul(group, L, NULL, k + 1, (const EC_POINT **)vec_L,
                           (const BIGNUM **)vec_l, bn_ctx))
            goto end;

        /* (24) */
        BP_POINT_BN_COPY(vec_R[k], ctx->U, vec_r[k], cR);
        if (!EC_POINTs_mul(group, R, NULL, k + 1, (const EC_POINT **)vec_R,
                           (const BIGNUM **)vec_r, bn_ctx))
            goto end;

        /* (25) */
        if (!(proof->vec_L[j] = EC_POINT_dup(L, group))
            || !(proof->vec_R[j] = EC_POINT_dup(R, group)))
            goto end;

        /* compute the challenge */
        if (!BP_TRANSCRIPT_append_point(transcript, "L", L, group)
            || !BP_TRANSCRIPT_append_point(transcript, "R", R, group))
            goto end;

        if (!BP_TRANSCRIPT_challange(transcript, "x", x))
            goto end;

        /* (26, 27) */
        if (!BN_mod_inverse(x_inv, x, order, bn_ctx)
            || !BN_mod_sqr(x2, x, order, bn_ctx)
            || !BN_mod_inverse(x2_inv, x2, order, bn_ctx))
            goto end;

        for (i = 0; i < m; i++) {
            /* (29) */
            BP_POINT_BN_COPY(vec_L[0], pG[i], vec_l[0], x_inv);
            BP_POINT_BN_COPY(vec_L[1], pG[m+i], vec_l[1], x);

#if 1
            if (pG == pp->vec_G) {
                if (!BN_mod_mul(vec_l[0], vec_l[0], ctx->vec_G_factors[i],
                                order, bn_ctx)
                    || !BN_mod_mul(vec_l[1], vec_l[1], ctx->vec_G_factors[m+i],
                                order, bn_ctx))
                    goto end;
            }
#endif

            if (!EC_POINTs_mul(group, vec_G[i], NULL, 2, (const EC_POINT **)vec_L,
                               (const BIGNUM **)vec_l, bn_ctx))
                goto end;

            /* (30) */
            BP_POINT_BN_COPY(vec_R[0], pH[i], vec_r[0], x);
            BP_POINT_BN_COPY(vec_R[1], pH[m+i], vec_r[1], x_inv);

#if 1
            if (pH == pp->vec_H) {
                if (!BN_mod_mul(vec_r[0], vec_r[0], ctx->vec_H_factors[i],
                                order, bn_ctx)
                    || !BN_mod_mul(vec_r[1], vec_r[1], ctx->vec_H_factors[m+i],
                                order, bn_ctx))
                    goto end;
            }
#endif

            if (!EC_POINTs_mul(group, vec_H[i], NULL, 2, (const EC_POINT **)vec_R,
                               (const BIGNUM **)vec_r, bn_ctx))
                goto end;

            /* (33) */
            if (!BN_mod_mul(vec_a[i], pa[i], x, order, bn_ctx)
                || !BN_mod_mul(t, pa[m+i], x_inv, order, bn_ctx)
                || !BN_mod_add(vec_a[i], vec_a[i], t, order, bn_ctx))
                goto end;

            /* (34) */
            if (!BN_mod_mul(vec_b[i], pb[i], x_inv, order, bn_ctx)
                || !BN_mod_mul(t, pb[m+i], x, order, bn_ctx)
                || !BN_mod_add(vec_b[i], vec_b[i], t, order, bn_ctx))
                goto end;
        }

#if 0
        /* (31) */
        if (!EC_POINT_mul(group, T, NULL, L, x2, bn_ctx)
            || !EC_POINT_add(group, T, T, P, bn_ctx)
            || !EC_POINT_mul(group, L, NULL, R, x2_inv, bn_ctx)
            || !EC_POINT_add(group, T, T, L, bn_ctx))
            goto end;

        P = T;
#endif
        (void)P;
        (void)T;
        pa = vec_a;
        pb = vec_b;
        pG = vec_G;
        pH = vec_H;
    }

    if (!BN_copy(proof->a, pa[0]) || !BN_copy(proof->b, pb[0]))
        goto end;

    proof->n = j;
    ret = 1;

end:
    for (i = 0; i < pp->n; i++) {
        EC_POINT_free(vec_G[i]);
        EC_POINT_free(vec_H[i]);
    }
    for (i = 0; i < vec_len; i++) {
        EC_POINT_free(vec_L[i]);
        EC_POINT_free(vec_R[i]);
        BN_free(vec_l[i]);
        BN_free(vec_r[i]);
    }
    OPENSSL_free(vec_G);
    OPENSSL_free(vec_H);
    OPENSSL_free(vec_a);
    OPENSSL_free(vec_b);
    EC_POINT_free(L);
    EC_POINT_free(R);
    EC_POINT_free(T);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    return ret;
}


int bp_inner_product_proof_verify(bp_inner_product_ctx_t *ctx,
                                  bp_inner_product_proof_t *proof)
{
    int ret = 0;
    int i, j, m, n, k;
    EC_POINT *P = NULL, **vec_A = NULL;;
    BP_TRANSCRIPT *transcript;
    BN_CTX *bn_ctx = NULL;
    BIGNUM **vec_x = NULL, **vec_x_inv = NULL, *s, *s_inv, *x2, *x2_inv, **vec_a = NULL;
    EC_GROUP *group;
    const BIGNUM *order;
    bp_inner_product_pub_param_t *pp;

    if (!ctx || !proof) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    transcript = ctx->transcript;
    group = ctx->group;
    order = EC_GROUP_get0_order(group);
    pp = ctx->pp;
    n = 2 *proof->n  + 2 * pp->n + 1;

    if (!(vec_x = OPENSSL_zalloc(proof->n * sizeof(*vec_x)))
        || !(vec_x_inv = OPENSSL_zalloc(proof->n * sizeof(*vec_x_inv)))
        || !(vec_A = OPENSSL_zalloc(n * sizeof(*vec_A)))
        || !(vec_a = OPENSSL_zalloc(n * sizeof(*vec_a)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (!(P = EC_POINT_new(group)))
        goto end;

    bn_ctx = BN_CTX_new_ex(group->libctx);
    if (!bn_ctx)
        goto end;

    BN_CTX_start(bn_ctx);
    s = BN_CTX_get(bn_ctx);
    s_inv = BN_CTX_get(bn_ctx);
    x2 = BN_CTX_get(bn_ctx);
    x2_inv = BN_CTX_get(bn_ctx);
    if (s_inv == NULL)
        goto end;

    for (i = 0, k = 0; i < proof->n; i++, k += 2) {
        if (!(vec_x[i] = BN_CTX_get(bn_ctx)) || !(vec_x_inv[i] = BN_CTX_get(bn_ctx)))
            goto end;

        /* compute hash */
        if (!BP_TRANSCRIPT_append_point(transcript, "L", proof->vec_L[i], group)
            || !BP_TRANSCRIPT_append_point(transcript, "R", proof->vec_R[i], group))
            goto end;

        if (!BP_TRANSCRIPT_challange(transcript, "x", vec_x[i]))
            goto end;

        if (!BN_mod_inverse(vec_x_inv[i], vec_x[i], order, bn_ctx)
            || !BN_mod_sqr(x2, vec_x[i], order, bn_ctx)
            || !BN_mod_inverse(x2_inv, x2, order, bn_ctx))
            goto end;

        if (!(vec_A[k] = EC_POINT_dup(proof->vec_L[i], group))
            || !(vec_A[k+1] = EC_POINT_dup(proof->vec_R[i], group))
            || !(vec_a[k] = BN_dup(x2))
            || !(vec_a[k+1] = BN_dup(x2_inv)))
            goto end;

        BN_set_negative(vec_a[k], !BN_is_negative(vec_a[k]));
        BN_set_negative(vec_a[k+1], !BN_is_negative(vec_a[k+1]));
    }

    for (i = 0; i < pp->n; i++, k += 2) {
        BN_one(s);

        for (j = 0; j < proof->n; j++) {
            m = i & (1 << (proof->n - j - 1));
            if (!BN_mod_mul(s, s, m ? vec_x[j] : vec_x_inv[j], order, bn_ctx))
                goto end;
        }

        if (!BN_mod_inverse(s_inv, s, order, bn_ctx))
            goto end;

        if (!BN_mod_mul(s, s, proof->a, order, bn_ctx)
            || !BN_mod_mul(s_inv, s_inv, proof->b, order, bn_ctx))
            goto end;

        if (!(vec_A[k] = EC_POINT_dup(pp->vec_G[i], group))
            || !(vec_a[k] = BN_dup(s))
            || !BN_mod_mul(vec_a[k], vec_a[k], ctx->vec_G_factors[i], order, bn_ctx)
            || !(vec_A[k+1] = EC_POINT_dup(pp->vec_H[i], group))
            || !(vec_a[k+1] = BN_dup(s_inv))
            || !BN_mod_mul(vec_a[k+1], vec_a[k+1], ctx->vec_H_factors[i], order, bn_ctx))
            goto end;
    }

    if (!BN_mod_mul(s, proof->a, proof->b, order, bn_ctx))
        goto end;

    if (!(vec_A[k] = EC_POINT_dup(ctx->U, group)) || !(vec_a[k] = BN_dup(s)))
        goto end;

    if (!EC_POINTs_mul(group, P, NULL, n, (const EC_POINT **)vec_A,
                       (const BIGNUM **)vec_a, bn_ctx)
        || !EC_POINT_invert(group, P, bn_ctx)
        || !EC_POINT_add(group, P, P, ctx->P, bn_ctx))
        goto end;

    ret = EC_POINT_is_at_infinity(group, P);

end:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(P);

    for (i = 0; i < n; i++) {
        EC_POINT_free(vec_A[i]);
        BN_free(vec_a[i]);
    }

    OPENSSL_free(vec_A);
    OPENSSL_free(vec_a);
    OPENSSL_free(vec_x);
    OPENSSL_free(vec_x_inv);
    return ret;
}
