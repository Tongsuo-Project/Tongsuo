/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <crypto/ec.h>
#include <crypto/ctype.h>
#include <crypto/ec/ec_local.h>
#include <crypto/zkp/common/zkp_util.h>
#include "r1cs.h"

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(EC_POINT)
DEFINE_STACK_OF(BP_VARIABLE)
DEFINE_STACK_OF(BP_R1CS_LINEAR_COMBINATION)
DEFINE_STACK_OF(BP_R1CS_LINEAR_COMBINATION_ITEM)

BP_R1CS_CTX *BP_R1CS_CTX_new(BP_PUB_PARAM *pp, BP_WITNESS *witness,
                             ZKP_TRANSCRIPT *transcript)
{
    BP_R1CS_CTX *ctx = NULL;

    if (pp == NULL || witness == NULL || transcript == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->transcript = transcript;

    if (!BP_PUB_PARAM_up_ref(pp))
        goto err;

    ctx->pp = pp;

    if (!BP_WITNESS_up_ref(witness))
        goto err;

    ctx->witness = witness;

    if ((ctx->constraints = sk_BP_R1CS_LINEAR_COMBINATION_new_null()) == NULL
        || (ctx->aL = sk_BIGNUM_new_null()) == NULL
        || (ctx->aR = sk_BIGNUM_new_null()) == NULL
        || (ctx->aO = sk_BIGNUM_new_null()) == NULL)
        goto err;

    return ctx;

err:
    BP_R1CS_CTX_free(ctx);
    return NULL;
}

void BP_R1CS_CTX_free(BP_R1CS_CTX *ctx)
{
    if (ctx == NULL)
        return;

    BP_PUB_PARAM_down_ref(ctx->pp);
    BP_WITNESS_down_ref(ctx->witness);

    sk_BP_R1CS_LINEAR_COMBINATION_pop_free(ctx->constraints,
                                           BP_R1CS_LINEAR_COMBINATION_free);
    sk_BIGNUM_pop_free(ctx->aL, BN_free);
    sk_BIGNUM_pop_free(ctx->aR, BN_free);
    sk_BIGNUM_pop_free(ctx->aO, BN_free);

    OPENSSL_clear_free((void *)ctx, sizeof(*ctx));
}

BP_R1CS_PROOF *BP_R1CS_PROOF_new(BP_R1CS_CTX *ctx)
{
    BP_R1CS_PROOF *proof = NULL;

    proof = OPENSSL_zalloc(sizeof(*proof));
    if (proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if ((proof->AI1 = EC_POINT_new(ctx->pp->group)) == NULL
        || (proof->AO1 = EC_POINT_new(ctx->pp->group)) == NULL
        || (proof->S1 = EC_POINT_new(ctx->pp->group)) == NULL
        || (proof->AI2 = EC_POINT_new(ctx->pp->group)) == NULL
        || (proof->AO2 = EC_POINT_new(ctx->pp->group)) == NULL
        || (proof->S2 = EC_POINT_new(ctx->pp->group)) == NULL
        || (proof->T1 = EC_POINT_new(ctx->pp->group)) == NULL
        || (proof->T3 = EC_POINT_new(ctx->pp->group)) == NULL
        || (proof->T4 = EC_POINT_new(ctx->pp->group)) == NULL
        || (proof->T5 = EC_POINT_new(ctx->pp->group)) == NULL
        || (proof->T6 = EC_POINT_new(ctx->pp->group)) == NULL
        || (proof->taux = BN_new()) == NULL
        || (proof->mu = BN_new()) == NULL
        || (proof->tx = BN_new()) == NULL)
        goto err;

    EC_POINT_set_to_infinity(ctx->pp->group, proof->AI1);
    EC_POINT_set_to_infinity(ctx->pp->group, proof->AO1);
    EC_POINT_set_to_infinity(ctx->pp->group, proof->S1);
    EC_POINT_set_to_infinity(ctx->pp->group, proof->AI2);
    EC_POINT_set_to_infinity(ctx->pp->group, proof->AO2);
    EC_POINT_set_to_infinity(ctx->pp->group, proof->S2);
    EC_POINT_set_to_infinity(ctx->pp->group, proof->T1);
    EC_POINT_set_to_infinity(ctx->pp->group, proof->T3);
    EC_POINT_set_to_infinity(ctx->pp->group, proof->T4);
    EC_POINT_set_to_infinity(ctx->pp->group, proof->T5);
    EC_POINT_set_to_infinity(ctx->pp->group, proof->T6);

    BN_zero(proof->taux);
    BN_zero(proof->mu);
    BN_zero(proof->tx);

    proof->references = 1;

    if ((proof->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    return proof;
err:
    BP_R1CS_PROOF_free(proof);
    return NULL;
}

void BP_R1CS_PROOF_free(BP_R1CS_PROOF *proof)
{
    int ref;

    if (proof == NULL)
        return;

    CRYPTO_DOWN_REF(&proof->references, &ref, proof->lock);
    REF_PRINT_COUNT("BP_R1CS_PROOF", proof);
    if (ref > 0)
        return;
    REF_ASSERT_ISNT(ref < 0);

    EC_POINT_free(proof->AI1);
    EC_POINT_free(proof->AO1);
    EC_POINT_free(proof->S1);
    EC_POINT_free(proof->AI2);
    EC_POINT_free(proof->AO2);
    EC_POINT_free(proof->S2);
    EC_POINT_free(proof->T1);
    EC_POINT_free(proof->T3);
    EC_POINT_free(proof->T4);
    EC_POINT_free(proof->T5);
    EC_POINT_free(proof->T6);
    BN_free(proof->taux);
    BN_free(proof->mu);
    BN_free(proof->tx);
    CRYPTO_THREAD_lock_free(proof->lock);
    OPENSSL_clear_free((void *)proof, sizeof(*proof));
}

int BP_WITNESS_r1cs_commit(BP_WITNESS *witness, const char *name, BIGNUM *v)
{
    const BIGNUM *order;
    BIGNUM *r = NULL, *val = NULL;
    EC_POINT *V = NULL;
    BP_VARIABLE *var = NULL;

    if (witness == NULL || name == NULL || v == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (strlen(name) > BP_VARIABLE_NAME_MAX_LEN) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_VARIABLE_NAME_TOO_LONG);
        return 0;
    }

    order = EC_GROUP_get0_order(witness->group);

    if (BP_WITNESS_get_variable_index(witness, name) >= 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_VARIABLE_DUPLICATED);
        return 0;
    }

    r = BN_new();
    val = BN_dup(v);
    V = EC_POINT_new(witness->group);
    if (r == NULL || val == NULL || V == NULL)
        goto err;

    if (!zkp_rand_range(r, order))
        goto err;

    /* (69) */
    if (!EC_POINT_mul(witness->group, V, v, witness->H, r, NULL))
        goto err;

    if (!(var = BP_VARIABLE_new(name, V, witness->group)))
        goto err;

    if (sk_BIGNUM_push(witness->sk_r, r) <= 0)
        goto err;

    r = NULL;

    if (sk_BIGNUM_push(witness->sk_v, val) <= 0)
        goto err;

    val = NULL;

    if (sk_BP_VARIABLE_push(witness->sk_V, var) <= 0)
        goto err;

    return 1;
err:
    BN_free(r);
    BN_free(val);
    EC_POINT_free(V);
    BP_VARIABLE_free(var);
    return 0;
}

BP_R1CS_LINEAR_COMBINATION *BP_WITNESS_r1cs_linear_combination_commit(BP_WITNESS *witness,
                                                                      const char *name,
                                                                      BIGNUM *v)
{
    int num;
    BP_R1CS_VARIABLE *r1cs_var = NULL;
    BP_R1CS_LINEAR_COMBINATION *lc = NULL;

    if (!BP_WITNESS_r1cs_commit(witness, name, v))
        return 0;

    num = sk_BP_VARIABLE_num(witness->sk_V) - 1;

    if ((r1cs_var = BP_R1CS_VARIABLE_new(BP_R1CS_VARIABLE_COMMITTED, num)) == NULL)
        goto err;

    if (!(lc = BP_R1CS_LINEAR_COMBINATION_new_from_param(r1cs_var, NULL)))
        goto err;

    lc->type = BP_R1CS_LC_TYPE_PROVE;

    return lc;
err:
    BP_R1CS_VARIABLE_free(r1cs_var);
    BP_R1CS_LINEAR_COMBINATION_free(lc);
    return NULL;
}

BP_R1CS_LINEAR_COMBINATION *BP_WITNESS_r1cs_linear_combination_get(BP_WITNESS *witness,
                                                                   const char *name)
{
    int i;
    BP_R1CS_VARIABLE *var = NULL;
    BP_R1CS_LINEAR_COMBINATION *ret = NULL;

    if (witness == NULL || name == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    i = BP_WITNESS_get_variable_index(witness, name);
    if (i < 0)
        return NULL;

    if ((var = BP_R1CS_VARIABLE_new(BP_R1CS_VARIABLE_COMMITTED, i)) == NULL)
        goto err;

    if (!(ret = BP_R1CS_LINEAR_COMBINATION_new_from_param(var, NULL)))
        goto err;

    ret->type = BP_R1CS_LC_TYPE_VERIFY;

    return ret;
err:
    BP_R1CS_VARIABLE_free(var);
    BP_R1CS_LINEAR_COMBINATION_free(ret);
    return NULL;
}

BP_R1CS_PROOF *BP_R1CS_PROOF_prove(BP_R1CS_CTX *ctx)
{
    EC_GROUP *group;
    const BIGNUM *order;
    BN_CTX *bn_ctx = NULL;
    int i, j, k, m, n, nn, n1, seed_buf_len, size, padded_n, pp_capacity;
    unsigned char *seed_buf = NULL, *buf = NULL;
    BIGNUM *alpha, *beta, *rho, *r = NULL, *product;
    BIGNUM **sL = NULL, **sR = NULL;
    BIGNUM *x, *u, *w, *z, *z2, *pow_z, *pw = NULL;
    BIGNUM *y, *y_inv, *pow_y_inv, *pow_y;
    BIGNUM **wL = NULL, **wR = NULL, **wO = NULL, **wV = NULL;
    BIGNUM *tau1, *tau2, *tau3, *tau4, *tau5, *tau6;
    BIGNUM *g_scalar, *h_scalar, *padded_l, *padded_r;
    STACK_OF(EC_POINT) *sk_G = NULL, *sk_H = NULL;
    STACK_OF(BIGNUM) *sk_G_scalars = NULL, *sk_H_scalars = NULL;
    STACK_OF(BIGNUM) *sk_l = NULL, *sk_r = NULL;
    EC_POINT *U = NULL, *G, *H;
    zkp_poly3_t *poly_l = NULL, *poly_r = NULL;
    zkp_poly6_t *poly_t = NULL, *poly_tau = NULL;
    zkp_poly_points_t *poly_ai1 = NULL, *poly_ao1 = NULL, *poly_s1 = NULL;
    bp_inner_product_ctx_t *ip_ctx = NULL;
    bp_inner_product_witness_t *ip_witness = NULL;
    bp_inner_product_pub_param_t *ip_pp = NULL;
    ZKP_TRANSCRIPT *transcript;
    BP_PUB_PARAM *pp;
    BP_WITNESS *witness;
    BP_VARIABLE *var;
    BP_R1CS_VARIABLE *r1cs_var;
    BP_R1CS_LINEAR_COMBINATION *lc;
    BP_R1CS_LINEAR_COMBINATION_ITEM *item;
    BP_R1CS_PROOF *proof = NULL, *ret = NULL;

    if (ctx == NULL || ctx->constraints == NULL || ctx->witness == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    transcript = ctx->transcript;
    witness = ctx->witness;
    pp = ctx->pp;
    group = pp->group;
    order = EC_GROUP_get0_order(group);

    n1 = sk_BIGNUM_num(ctx->aL);
    nn = n1 + 1;
    padded_n = zkp_next_power_of_two(n1);
    pp_capacity = pp->gens_capacity * pp->party_capacity;
    if (pp_capacity < padded_n) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_EXCEEDS_PP_CAPACITY);
        goto err;
    }

    if (!(proof = BP_R1CS_PROOF_new(ctx)) || !(U = EC_POINT_new(group))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!(sk_G = sk_EC_POINT_new_reserve(NULL, padded_n))
        || !(sk_H = sk_EC_POINT_new_reserve(NULL, padded_n))
        || !(sk_G_scalars = sk_BIGNUM_new_reserve(NULL, padded_n))
        || !(sk_H_scalars = sk_BIGNUM_new_reserve(NULL, padded_n))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        return NULL;

    BN_CTX_start(bn_ctx);

    alpha = BN_CTX_get(bn_ctx);
    beta = BN_CTX_get(bn_ctx);
    rho = BN_CTX_get(bn_ctx);
    product = BN_CTX_get(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    y_inv = BN_CTX_get(bn_ctx);
    pow_y = BN_CTX_get(bn_ctx);
    pow_y_inv = BN_CTX_get(bn_ctx);
    z = BN_CTX_get(bn_ctx);
    pow_z = BN_CTX_get(bn_ctx);
    z2 = BN_CTX_get(bn_ctx);
    u = BN_CTX_get(bn_ctx);
    w = BN_CTX_get(bn_ctx);
    if (w == NULL)
        goto err;

    m = sk_BP_VARIABLE_num(witness->sk_V);
    for (i = 0; i < m; i++) {
        var = sk_BP_VARIABLE_value(witness->sk_V, i);
        if (var == NULL)
            goto err;

        if (!ZKP_TRANSCRIPT_append_point(transcript, "V", var->point, group))
            goto err;
    }

    m = sk_BIGNUM_num(witness->sk_v);
    if (!ZKP_TRANSCRIPT_append_int64(transcript, "m", m))
        goto err;

    m = sk_BIGNUM_num(witness->sk_r);
    if (m > 0) {
        r = sk_BIGNUM_value(witness->sk_r, 0);
        if (r == NULL)
            goto err;

        seed_buf_len = BN_num_bytes(r) * m * 2;
        if ((seed_buf = OPENSSL_zalloc(seed_buf_len)) == NULL)
            goto err;
    }

    buf = seed_buf;

    for (i = 0; i < m; i++) {
        r = sk_BIGNUM_value(witness->sk_r, i);
        if (r == NULL)
            goto err;

        size = BN_num_bytes(r);
        if (!BN_bn2bin(r, buf))
            goto err;

        buf += size;
    }

    RAND_seed(seed_buf, buf - seed_buf);

    n = n1 * 2 + 1;

    if (!(poly_ai1 = zkp_poly_points_new(n))
        || !(poly_ao1 = zkp_poly_points_new(n))
        || !(poly_s1 = zkp_poly_points_new(n)))
        goto err;

    if (!zkp_rand_range(alpha, order)
        || !zkp_rand_range(beta, order)
        || !zkp_rand_range(rho, order))
        goto err;

    if (!(sL = OPENSSL_zalloc(sizeof(*sL) * nn))
        || !(sR = OPENSSL_zalloc(sizeof(*sR) * nn))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!zkp_random_bn_gen(group, sL, n1, bn_ctx)
        || !zkp_random_bn_gen(group, sR, n1, bn_ctx))
        goto err;

    if (!zkp_poly_points_append(poly_ai1, pp->H, alpha)
        || !zkp_poly_points_append(poly_ao1, pp->H, beta)
        || !zkp_poly_points_append(poly_s1, pp->H, rho))
        goto err;

    for (i = 0; i < n1; i++) {
        G = sk_EC_POINT_value(pp->sk_G, i);
        H = sk_EC_POINT_value(pp->sk_H, i);
        if (!zkp_poly_points_append(poly_ai1, G, sk_BIGNUM_value(ctx->aL, i))
            || !zkp_poly_points_append(poly_ai1, H, sk_BIGNUM_value(ctx->aR, i))
            || !zkp_poly_points_append(poly_ao1, G, sk_BIGNUM_value(ctx->aO, i))
            || !zkp_poly_points_append(poly_s1, G, sL[i])
            || !zkp_poly_points_append(poly_s1, H, sR[i]))
            goto err;
    }

    if (!zkp_poly_points_mul(poly_ai1, proof->AI1, NULL, group, bn_ctx)
        || !zkp_poly_points_mul(poly_ao1, proof->AO1, NULL, group, bn_ctx)
        || !zkp_poly_points_mul(poly_s1, proof->S1, NULL, group, bn_ctx))
        goto err;

    if (!ZKP_TRANSCRIPT_append_point(transcript, "A_I1", proof->AI1, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "A_O1", proof->AO1, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "S1", proof->S1, group))
        goto err;

    /*
     * TODO
     * Process the remaining constraints.
     */

    n = sk_BIGNUM_num(ctx->aL);
    nn = n + 1;
    padded_n = zkp_next_power_of_two(n);
    if (pp_capacity < padded_n) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_EXCEEDS_PP_CAPACITY);
        goto err;
    }

    if (!ZKP_TRANSCRIPT_append_point(transcript, "A_I2", proof->AI2, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "A_O2", proof->AO2, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "S2", proof->S2, group))
        goto err;

    if (!ZKP_TRANSCRIPT_challange(transcript, "y", y)
        || !ZKP_TRANSCRIPT_challange(transcript, "z", z))
        goto err;

    if (!BN_mod_sqr(z2, z, order, bn_ctx) || !BN_copy(pow_z, z)
        || !BN_mod_inverse(y_inv, y, order, bn_ctx))
        goto err;

    /*
     * flatten the constraints
     */
    m = sk_BIGNUM_num(witness->sk_v);
    if ((wL = OPENSSL_zalloc(sizeof(*wL) * nn)) == NULL
        || (wR = OPENSSL_zalloc(sizeof(*wR) * nn)) == NULL
        || (wO = OPENSSL_zalloc(sizeof(*wO) * nn)) == NULL
        || (wV = OPENSSL_zalloc(sizeof(*wV) * m)) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    for (i = 0; i < n; i++) {
        wL[i] = BN_CTX_get(bn_ctx);
        wR[i] = BN_CTX_get(bn_ctx);
        wO[i] = BN_CTX_get(bn_ctx);
        if (wO[i] == NULL)
            goto err;

        BN_zero(wL[i]);
        BN_zero(wR[i]);
        BN_zero(wO[i]);
    }

    for (i = 0; i < m; i++) {
        wV[i] = BN_CTX_get(bn_ctx);
        if (wV[i] == NULL)
            goto err;

        BN_zero(wV[i]);
    }

    k = sk_BP_R1CS_LINEAR_COMBINATION_num(ctx->constraints);
    for (i = 0; i < k; i++) {
        lc = sk_BP_R1CS_LINEAR_COMBINATION_value(ctx->constraints, i);
        if (lc == NULL)
            goto err;

        if (lc->type != BP_R1CS_LC_TYPE_PROVE)
            continue;

        m = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_num(lc->items);
        for (j = 0; j < m; j++) {
            item = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_value(lc->items, j);
            if (item == NULL)
                goto err;

            r1cs_var = item->variable;

            switch (r1cs_var->type) {
            case BP_R1CS_VARIABLE_COMMITTED:
                pw = wV[r1cs_var->value];
                break;
            case BP_R1CS_VARIABLE_MULTIPLIER_LEFT:
                pw = wL[r1cs_var->value];
                break;
            case BP_R1CS_VARIABLE_MULTIPLIER_RIGHT:
                pw = wR[r1cs_var->value];
                break;
            case BP_R1CS_VARIABLE_MULTIPLIER_OUTPUT:
                pw = wO[r1cs_var->value];
                break;
            default:
                break;
            }

            if (pw == NULL)
                continue;

            if (!BN_mod_mul(product, pow_z, item->scalar, order, bn_ctx))
                goto err;

            if (r1cs_var->type == BP_R1CS_VARIABLE_COMMITTED) {
                if (!BN_mod_sub(pw, pw, product, order, bn_ctx))
                    goto err;
            } else {
                if (!BN_mod_add(pw, pw, product, order, bn_ctx))
                    goto err;
            }

            pw = NULL;
        }

        if (!BN_mod_mul(pow_z, pow_z, z, order, bn_ctx))
            goto err;
    }

    BN_one(pow_y);
    BN_one(pow_y_inv);

    if (!(poly_l = zkp_poly3_new(n, order)) || !(poly_r = zkp_poly3_new(n, order)))
        goto err;

    for (i = 0; i < n; i++) {
        g_scalar = BN_CTX_get(bn_ctx);
        h_scalar = BN_CTX_get(bn_ctx);
        if (h_scalar == NULL)
            goto err;

        if (!BN_mod_mul(poly_l->x1[i], pow_y_inv, wR[i], order, bn_ctx)
            || !BN_mod_add(poly_l->x1[i], poly_l->x1[i], sk_BIGNUM_value(ctx->aL, i),
                           order, bn_ctx)
            || !BN_copy(poly_l->x2[i], sk_BIGNUM_value(ctx->aO, i))
            || !BN_copy(poly_l->x3[i], sL[i]))
            goto err;

        if (!BN_mod_sub(poly_r->x0[i], wO[i], pow_y, order, bn_ctx)
            || !BN_mod_mul(poly_r->x1[i], pow_y, sk_BIGNUM_value(ctx->aR, i),
                           order, bn_ctx)
            || !BN_mod_add(poly_r->x1[i], poly_r->x1[i], wL[i], order, bn_ctx)
            || !BN_mod_mul(poly_r->x3[i], pow_y, sR[i], order, bn_ctx))
            goto err;

        BN_one(g_scalar);

        if (!BN_copy(h_scalar, pow_y_inv))
            goto err;

        G = sk_EC_POINT_value(pp->sk_G, i);
        H = sk_EC_POINT_value(pp->sk_H, i);

        if (sk_EC_POINT_push(sk_G, G) <= 0
            || sk_EC_POINT_push(sk_H, H) <= 0
            || sk_BIGNUM_push(sk_G_scalars, g_scalar) <= 0
            || sk_BIGNUM_push(sk_H_scalars, h_scalar) <= 0)
            goto err;

        if (!BN_mod_mul(pow_y, pow_y, y, order, bn_ctx)
            || !BN_mod_mul(pow_y_inv, pow_y_inv, y_inv, order, bn_ctx))
            goto err;
    }

    if (!(poly_t = zkp_poly6_new(order)))
        goto err;

    if (!zkp_poly3_special_inner_product(poly_t, poly_l, poly_r))
        goto err;

    tau1 = BN_CTX_get(bn_ctx);
    tau2 = BN_CTX_get(bn_ctx);
    tau3 = BN_CTX_get(bn_ctx);
    tau4 = BN_CTX_get(bn_ctx);
    tau5 = BN_CTX_get(bn_ctx);
    if (!(tau6 = BN_CTX_get(bn_ctx)))
        goto err;

    if (!zkp_rand_range(tau1, order)
        || !zkp_rand_range(tau3, order)
        || !zkp_rand_range(tau4, order)
        || !zkp_rand_range(tau5, order)
        || !zkp_rand_range(tau6, order))
        goto err;

    if (!EC_POINT_mul(group, proof->T1, poly_t->t1, pp->H, tau1, bn_ctx)
        || !EC_POINT_mul(group, proof->T3, poly_t->t3, pp->H, tau3, bn_ctx)
        || !EC_POINT_mul(group, proof->T4, poly_t->t4, pp->H, tau4, bn_ctx)
        || !EC_POINT_mul(group, proof->T5, poly_t->t5, pp->H, tau5, bn_ctx)
        || !EC_POINT_mul(group, proof->T6, poly_t->t6, pp->H, tau6, bn_ctx))
        goto err;

    if (!ZKP_TRANSCRIPT_append_point(transcript, "T_1", proof->T1, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "T_3", proof->T3, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "T_4", proof->T4, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "T_5", proof->T5, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "T_6", proof->T6, group))
        goto err;

    if (!ZKP_TRANSCRIPT_challange(transcript, "u", u)
        || !ZKP_TRANSCRIPT_challange(transcript, "x", x))
        goto err;

    BN_zero(tau2);
    m = sk_BIGNUM_num(witness->sk_r);
    for (i = 0; i < m; i++) {
        r = sk_BIGNUM_value(witness->sk_r, i);
        if (r == NULL || !BN_mod_mul(product, wV[i], r, order, bn_ctx))
            goto err;

        if (!BN_mod_add(tau2, tau2, product, order, bn_ctx))
            goto err;
    }

    if (!(poly_tau = zkp_poly6_new(order)))
        goto err;

    poly_tau->t1 = tau1;
    poly_tau->t2 = tau2;
    poly_tau->t3 = tau3;
    poly_tau->t4 = tau4;
    poly_tau->t5 = tau5;
    poly_tau->t6 = tau6;

    if (!zkp_poly6_eval(poly_t, x, proof->tx) || !zkp_poly6_eval(poly_tau, x, proof->taux))
        goto err;

    if (!(sk_l = zkp_poly3_eval(poly_l, x)) || !(sk_r = zkp_poly3_eval(poly_r, x)))
        goto err;

    /* TODO: 2nd phase commitments */

    if (!BN_mod_mul(proof->mu, x, rho, order, bn_ctx)
        || !BN_mod_add(proof->mu, proof->mu, beta, order, bn_ctx)
        || !BN_mod_mul(proof->mu, proof->mu, x, order, bn_ctx)
        || !BN_mod_add(proof->mu, proof->mu, alpha, order, bn_ctx)
        || !BN_mod_mul(proof->mu, proof->mu, x, order, bn_ctx))
        goto err;

    if (!ZKP_TRANSCRIPT_append_bn(transcript, "t_x", proof->tx)
        || !ZKP_TRANSCRIPT_append_bn(transcript, "t_x_blinding", proof->taux)
        || !ZKP_TRANSCRIPT_append_bn(transcript, "e_blinding", proof->mu))
        goto err;

    if (!ZKP_TRANSCRIPT_challange(transcript, "w", w))
        goto err;

    if (!EC_POINT_mul(group, U, w, NULL, NULL, bn_ctx))
        goto err;

    for (i = n; i < padded_n; i++) {
        g_scalar = BN_CTX_get(bn_ctx);
        h_scalar = BN_CTX_get(bn_ctx);
        padded_l = BN_CTX_get(bn_ctx);
        padded_r = BN_CTX_get(bn_ctx);
        if (padded_r == NULL)
            goto err;

        if (!BN_copy(g_scalar, u)
            || !BN_mod_mul(h_scalar, pow_y_inv, u, order, bn_ctx))
            goto err;

        if (!BN_copy(padded_r, pow_y))
            goto err;

        BN_set_negative(padded_r, 1);
        BN_zero(padded_l);

        G = sk_EC_POINT_value(pp->sk_G, i);
        H = sk_EC_POINT_value(pp->sk_H, i);

        if (sk_EC_POINT_push(sk_G, G) <= 0
            || sk_EC_POINT_push(sk_H, H) <= 0
            || sk_BIGNUM_push(sk_G_scalars, g_scalar) <= 0
            || sk_BIGNUM_push(sk_H_scalars, h_scalar) <= 0
            || sk_BIGNUM_push(sk_l, padded_l) <= 0
            || sk_BIGNUM_push(sk_r, padded_r) <= 0)
            goto err;

        if (!BN_mod_mul(pow_y, pow_y, y, order, bn_ctx)
            || !BN_mod_mul(pow_y_inv, pow_y_inv, y_inv, order, bn_ctx))
            goto err;
    }

    if (!(ip_pp = bp_inner_product_pub_param_new(group, sk_G, sk_H))
        || !(ip_ctx = bp_inner_product_ctx_new(ip_pp, transcript, U, NULL,
                                               sk_G_scalars, sk_H_scalars))
        || !(ip_witness = bp_inner_product_witness_new(sk_l, sk_r)))
        goto err;

    if (!(proof->ip_proof = bp_inner_product_proof_prove(ip_ctx, ip_witness)))
        goto err;

    ret = proof;
    proof = NULL;

err:
    ZKP_TRANSCRIPT_reset(transcript);

    bp_inner_product_ctx_free(ip_ctx);
    bp_inner_product_pub_param_free(ip_pp);

    zkp_poly3_free(poly_l);
    zkp_poly3_free(poly_r);
    zkp_poly6_free(poly_t);

    zkp_poly_points_free(poly_ai1);
    zkp_poly_points_free(poly_ao1);
    zkp_poly_points_free(poly_s1);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    OPENSSL_free(sL);
    OPENSSL_free(sR);
    sk_EC_POINT_free(sk_G);
    sk_EC_POINT_free(sk_H);
    sk_BIGNUM_free(sk_G_scalars);
    sk_BIGNUM_free(sk_H_scalars);
    sk_BIGNUM_free(sk_l);
    sk_BIGNUM_free(sk_r);
    EC_POINT_free(U);
    OPENSSL_free(seed_buf);
    BP_R1CS_PROOF_free(proof);
    return ret;
}

int BP_R1CS_PROOF_verify(BP_R1CS_CTX *ctx, BP_R1CS_PROOF *proof)
{
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group;
    const BIGNUM *order;
    int i, j, m, n, nn, padded_n, v_n, lg_i, lg_n, pp_capacity, ret = 0;
    BIGNUM *delta, *bn1;
    BIGNUM **vec_s = NULL, **vec_ip_x2 = NULL;
    BIGNUM *x, *x2, *x3, *ip_x, *ip_x_inv, *ip_x2, *ip_x2_inv;
    BIGNUM *y, *y_inv, *pow_y_inv, *wR_pow_y_inv;
    BIGNUM *z, *u, *w, *wc, *pw = NULL, *pow_z, *tmp, *product;
    BIGNUM *ux, *ux2, *ux3, *r, *rx, *rx2, *rx3, *rx4, *rx5, *rx6;
    BIGNUM *scalar, *g_scalar, *h_scalar, *b_scalar, *v_scalar, *s_a, *s_b;
    BIGNUM **wL = NULL, **wR = NULL, **wO = NULL, **wV = NULL;
    EC_POINT *P = NULL, *L, *R, *G, *H;
    zkp_poly_points_t *poly_p = NULL;
    ZKP_TRANSCRIPT *transcript;
    BP_PUB_PARAM *pp;
    BP_WITNESS *witness;
    BP_VARIABLE *var;
    BP_R1CS_VARIABLE *r1cs_var;
    BP_R1CS_LINEAR_COMBINATION *lc;
    BP_R1CS_LINEAR_COMBINATION_ITEM *item;
    bp_inner_product_proof_t *ip_proof = NULL;

    if (ctx == NULL || ctx->constraints == NULL || ctx->witness == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    pp = ctx->pp;
    transcript = ctx->transcript;
    witness = ctx->witness;
    group = pp->group;
    order = EC_GROUP_get0_order(group);
    ip_proof = proof->ip_proof;
    pp_capacity = pp->gens_capacity * pp->party_capacity;

    nn = ctx->vars_num + 1;
    padded_n = zkp_next_power_of_two(ctx->vars_num);
    if (pp_capacity < padded_n) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_EXCEEDS_PP_CAPACITY);
        goto err;
    }

    v_n = sk_BP_VARIABLE_num(witness->sk_V);
    lg_n = sk_EC_POINT_num(ip_proof->sk_L);
    if (padded_n != 1 << lg_n) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    if (!(poly_p = zkp_poly_points_new(12 + padded_n * 2 + lg_n * 2 + v_n)))
        goto err;

    if (!(P = EC_POINT_new(group))
        || !(vec_ip_x2 = OPENSSL_zalloc((lg_n + 1) * sizeof(*vec_ip_x2)))
        || !(vec_s = OPENSSL_zalloc(padded_n * sizeof(*vec_s)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    BN_CTX_start(bn_ctx);

    bn1 = BN_CTX_get(bn_ctx);
    product = BN_CTX_get(bn_ctx);
    delta = BN_CTX_get(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    y_inv = BN_CTX_get(bn_ctx);
    pow_y_inv = BN_CTX_get(bn_ctx);
    wR_pow_y_inv = BN_CTX_get(bn_ctx);
    z = BN_CTX_get(bn_ctx);
    pow_z = BN_CTX_get(bn_ctx);
    u = BN_CTX_get(bn_ctx);
    w = BN_CTX_get(bn_ctx);
    wc = BN_CTX_get(bn_ctx);
    s_a = BN_CTX_get(bn_ctx);
    s_b = BN_CTX_get(bn_ctx);
    x2 = BN_CTX_get(bn_ctx);
    x3 = BN_CTX_get(bn_ctx);
    ux = BN_CTX_get(bn_ctx);
    ux2 = BN_CTX_get(bn_ctx);
    ux3 = BN_CTX_get(bn_ctx);
    r = BN_CTX_get(bn_ctx);
    rx = BN_CTX_get(bn_ctx);
    rx2 = BN_CTX_get(bn_ctx);
    rx3 = BN_CTX_get(bn_ctx);
    rx4 = BN_CTX_get(bn_ctx);
    rx5 = BN_CTX_get(bn_ctx);
    rx6 = BN_CTX_get(bn_ctx);
    ip_x = BN_CTX_get(bn_ctx);
    ip_x_inv = BN_CTX_get(bn_ctx);
    ip_x2 = BN_CTX_get(bn_ctx);
    ip_x2_inv = BN_CTX_get(bn_ctx);
    vec_s[0] = BN_CTX_get(bn_ctx);
    tmp = BN_CTX_get(bn_ctx);
    if (tmp == NULL)
        goto err;

    BN_zero(delta);
    BN_one(bn1);
    BN_one(pow_y_inv);

    if (!zkp_rand_range(r, order))
        goto err;

    //START
    for (i = 0; i < v_n; i++) {
        var = sk_BP_VARIABLE_value(witness->sk_V, i);
        if (var == NULL)
            goto err;

        if (!ZKP_TRANSCRIPT_append_point(transcript, "V", var->point, group))
            goto err;
    }

    if (!ZKP_TRANSCRIPT_append_int64(transcript, "m", v_n))
        goto err;

    if (!ZKP_TRANSCRIPT_append_point(transcript, "A_I1", proof->AI1, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "A_O1", proof->AO1, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "S1", proof->S1, group))
        goto err;

    /*
     * TODO
     * Process the remaining constraints.
     */

    if (!ZKP_TRANSCRIPT_append_point(transcript, "A_I2", proof->AI2, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "A_O2", proof->AO2, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "S2", proof->S2, group))
        goto err;

    if (!ZKP_TRANSCRIPT_challange(transcript, "y", y)
        || !ZKP_TRANSCRIPT_challange(transcript, "z", z))
        goto err;

    if (!ZKP_TRANSCRIPT_append_point(transcript, "T_1", proof->T1, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "T_3", proof->T3, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "T_4", proof->T4, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "T_5", proof->T5, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "T_6", proof->T6, group))
        goto err;

    if (!ZKP_TRANSCRIPT_challange(transcript, "u", u)
        || !ZKP_TRANSCRIPT_challange(transcript, "x", x))
        goto err;

    if (!ZKP_TRANSCRIPT_append_bn(transcript, "t_x", proof->tx)
        || !ZKP_TRANSCRIPT_append_bn(transcript, "t_x_blinding", proof->taux)
        || !ZKP_TRANSCRIPT_append_bn(transcript, "e_blinding", proof->mu))
        goto err;

    if (!ZKP_TRANSCRIPT_challange(transcript, "w", w))
        goto err;

    if (!BN_mod_inverse(y_inv, y, order, bn_ctx)
        || !BN_mod_sqr(x2, x, order, bn_ctx)
        || !BN_mod_mul(x3, x2, x, order, bn_ctx)
        || !BN_mod_mul(ux, u, x, order, bn_ctx)
        || !BN_mod_mul(ux2, ux, x, order, bn_ctx)
        || !BN_mod_mul(ux3, ux2, x, order, bn_ctx)
        || !BN_mod_mul(rx, r, x, order, bn_ctx)
        || !BN_mod_mul(rx2, rx, x, order, bn_ctx)
        || !BN_mod_mul(rx3, rx2, x, order, bn_ctx)
        || !BN_mod_mul(rx4, rx3, x, order, bn_ctx)
        || !BN_mod_mul(rx5, rx4, x, order, bn_ctx)
        || !BN_mod_mul(rx6, rx5, x, order, bn_ctx)
        || !BN_copy(pow_z, z))
        goto err;

    /*
     * flatten the constraints
     */
    if ((wL = OPENSSL_zalloc(sizeof(*wL) * nn)) == NULL
        || (wR = OPENSSL_zalloc(sizeof(*wR) * nn)) == NULL
        || (wO = OPENSSL_zalloc(sizeof(*wO) * nn)) == NULL
        || (wV = OPENSSL_zalloc(sizeof(*wV) * v_n)) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    for (i = 0; i < ctx->vars_num; i++) {
        wL[i] = BN_CTX_get(bn_ctx);
        wR[i] = BN_CTX_get(bn_ctx);
        wO[i] = BN_CTX_get(bn_ctx);
        if (wO[i] == NULL)
            goto err;

        BN_zero(wL[i]);
        BN_zero(wR[i]);
        BN_zero(wO[i]);
    }

    for (i = 0; i < v_n; i++) {
        wV[i] = BN_CTX_get(bn_ctx);
        if (wV[i] == NULL)
            goto err;

        BN_zero(wV[i]);
    }

    BN_zero(wc);

    m = sk_BP_R1CS_LINEAR_COMBINATION_num(ctx->constraints);
    for (i = 0; i < m; i++) {
        lc = sk_BP_R1CS_LINEAR_COMBINATION_value(ctx->constraints, i);
        if (lc == NULL)
            goto err;

        if (lc->type != BP_R1CS_LC_TYPE_VERIFY)
            continue;

        n = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_num(lc->items);
        for (j = 0; j < n; j++) {
            item = sk_BP_R1CS_LINEAR_COMBINATION_ITEM_value(lc->items, j);
            if (item == NULL)
                goto err;

            r1cs_var = item->variable;

            switch (r1cs_var->type) {
            case BP_R1CS_VARIABLE_COMMITTED:
                pw = wV[r1cs_var->value];
                break;
            case BP_R1CS_VARIABLE_MULTIPLIER_LEFT:
                pw = wL[r1cs_var->value];
                break;
            case BP_R1CS_VARIABLE_MULTIPLIER_RIGHT:
                pw = wR[r1cs_var->value];
                break;
            case BP_R1CS_VARIABLE_MULTIPLIER_OUTPUT:
                pw = wO[r1cs_var->value];
                break;
            case BP_R1CS_VARIABLE_ONE:
                pw = wc;
                break;
            default:
                break;
            }

            if (w == NULL)
                continue;

            if (!BN_mod_mul(product, pow_z, item->scalar, order, bn_ctx))
                goto err;

            if (r1cs_var->type == BP_R1CS_VARIABLE_COMMITTED
                || r1cs_var->type == BP_R1CS_VARIABLE_ONE) {
                if (!BN_mod_sub(pw, pw, product, order, bn_ctx))
                    goto err;
            } else {
                if (!BN_mod_add(pw, pw, product, order, bn_ctx))
                    goto err;
            }

            pw = NULL;
        }

        if (!BN_mod_mul(pow_z, pow_z, z, order, bn_ctx))
            goto err;
    }

    if (!zkp_poly_points_append(poly_p, proof->AI1, x)
        || !zkp_poly_points_append(poly_p, proof->AO1, x2)
        || !zkp_poly_points_append(poly_p, proof->S1, x3)
        || !zkp_poly_points_append(poly_p, proof->AI2, ux)
        || !zkp_poly_points_append(poly_p, proof->AO2, ux2)
        || !zkp_poly_points_append(poly_p, proof->S2, ux3)
        || !zkp_poly_points_append(poly_p, proof->T1, rx)
        || !zkp_poly_points_append(poly_p, proof->T3, rx3)
        || !zkp_poly_points_append(poly_p, proof->T4, rx4)
        || !zkp_poly_points_append(poly_p, proof->T5, rx5)
        || !zkp_poly_points_append(poly_p, proof->T6, rx6))
        goto err;

    BN_one(vec_s[0]);

    for (i = 0; i < lg_n; i++) {
        scalar = BN_CTX_get(bn_ctx);
        vec_ip_x2[i] = BN_CTX_get(bn_ctx);
        if (vec_ip_x2[i] == NULL)
            goto err;

        L = sk_EC_POINT_value(ip_proof->sk_L, i);
        R = sk_EC_POINT_value(ip_proof->sk_R, i);
        if (L == NULL || R == NULL)
            goto err;

        if (!ZKP_TRANSCRIPT_append_point(transcript, "L", L, group)
            || !ZKP_TRANSCRIPT_append_point(transcript, "R", R, group))
            goto err;

        if (!ZKP_TRANSCRIPT_challange(transcript, "x", ip_x))
            goto err;

        if (!BN_mod_sqr(ip_x2, ip_x, order, bn_ctx)
            || !BN_copy(vec_ip_x2[i], ip_x2)
            || !BN_mod_inverse(ip_x_inv, ip_x, order, bn_ctx)
            || !BN_mod_inverse(ip_x2_inv, ip_x2, order, bn_ctx)
            || !BN_mod_mul(vec_s[0], vec_s[0], ip_x_inv, order, bn_ctx))
            goto err;

        if (!BN_copy(scalar, ip_x2) || !zkp_poly_points_append(poly_p, L, scalar))
            goto err;

        scalar = BN_CTX_get(bn_ctx);
        if (scalar == NULL || !BN_copy(scalar, ip_x2_inv) || !zkp_poly_points_append(poly_p, R, scalar))
            goto err;
    }

    for (i = 1; i < padded_n; i++) {
        lg_i = zkp_floor_log2(i);

        vec_s[i] = BN_CTX_get(bn_ctx);
        if (vec_s[i] == NULL)
            goto err;

        if (!BN_mod_mul(vec_s[i], vec_s[i - (1 << lg_i)],
                        vec_ip_x2[lg_n - 1 - lg_i], order, bn_ctx))
            goto err;
    }

    for (i = 0; i < padded_n; i++) {
        g_scalar = BN_CTX_get(bn_ctx);
        h_scalar = BN_CTX_get(bn_ctx);
        if (h_scalar == NULL)
            goto err;

        if (!BN_mod_mul(s_a, ip_proof->a, vec_s[i], order, bn_ctx)
            || !BN_mod_mul(s_b, ip_proof->b, vec_s[padded_n - i - 1], order, bn_ctx))
            goto err;

        BN_set_negative(s_a, 1);
        BN_set_negative(s_b, 1);

        if (i < ctx->vars_num) {
            if (!BN_mod_mul(wR_pow_y_inv, wR[i], pow_y_inv, order, bn_ctx)
                || !BN_mod_mul(tmp, wR_pow_y_inv, wL[i], order, bn_ctx)
                || !BN_mod_add(delta, delta, tmp, order, bn_ctx))
                goto err;

            if (!BN_mod_mul(g_scalar, x, wR_pow_y_inv, order, bn_ctx)
                || !BN_mod_add(g_scalar, g_scalar, s_a, order, bn_ctx))
                goto err;

            if (!BN_mod_mul(h_scalar, x, wL[i], order, bn_ctx)
                || !BN_mod_add(h_scalar, h_scalar, wO[i], order, bn_ctx)
                || !BN_mod_add(h_scalar, h_scalar, s_b, order, bn_ctx)
                || !BN_mod_mul(h_scalar, h_scalar, pow_y_inv, order, bn_ctx)
                || !BN_mod_sub(h_scalar, h_scalar, bn1, order, bn_ctx))
                goto err;
        } else {
            if (!BN_mod_mul(g_scalar, u, s_a, order, bn_ctx))
                goto err;

            if (!BN_mod_mul(h_scalar, pow_y_inv, s_b, order, bn_ctx)
                || !BN_mod_sub(h_scalar, h_scalar, bn1, order, bn_ctx)
                || !BN_mod_mul(h_scalar, h_scalar, u, order, bn_ctx))
                goto err;
        }

        G = sk_EC_POINT_value(pp->sk_G, i);
        H = sk_EC_POINT_value(pp->sk_H, i);
        if (G == NULL || H == NULL)
            goto err;

        if (!zkp_poly_points_append(poly_p, G, g_scalar)
            || !zkp_poly_points_append(poly_p, H, h_scalar))
            goto err;

        if (!BN_mod_mul(pow_y_inv, pow_y_inv, y_inv, order, bn_ctx))
            goto err;
    }

    for (i = 0; i < v_n; i++) {
        var = sk_BP_VARIABLE_value(witness->sk_V, i);
        if (var == NULL || var->point == NULL)
            goto err;

        v_scalar = BN_CTX_get(bn_ctx);
        if (v_scalar == NULL)
            goto err;

        if (!BN_mod_mul(v_scalar, wV[i], rx2, order, bn_ctx))
            goto err;

        if (!zkp_poly_points_append(poly_p, var->point, v_scalar))
            goto err;
    }

    b_scalar = BN_CTX_get(bn_ctx);
    h_scalar = BN_CTX_get(bn_ctx);
    if (h_scalar == NULL)
        goto err;

    if (!BN_mod_add(wc, wc, delta, order, bn_ctx)
        || !BN_mod_mul(wc, wc, x2, order, bn_ctx)
        || !BN_mod_sub(wc, wc, proof->tx, order, bn_ctx)
        || !BN_mod_mul(wc, wc, r, order, bn_ctx)
        || !BN_mod_mul(b_scalar, ip_proof->a, ip_proof->b, order, bn_ctx)
        || !BN_mod_sub(b_scalar, proof->tx, b_scalar, order, bn_ctx)
        || !BN_mod_mul(b_scalar, b_scalar, w, order, bn_ctx)
        || !BN_mod_add(b_scalar, b_scalar, wc, order, bn_ctx)
        || !BN_mod_mul(h_scalar, r, proof->taux, order, bn_ctx)
        || !BN_mod_add(h_scalar, h_scalar, proof->mu, order, bn_ctx))
        goto err;

    BN_set_negative(h_scalar, 1);

    if (!zkp_poly_points_append(poly_p, pp->H, h_scalar)
        || !zkp_poly_points_mul(poly_p, P, b_scalar, group, bn_ctx))
        goto err;

    ret = EC_POINT_is_at_infinity(group, P);

err:
    ZKP_TRANSCRIPT_reset(transcript);

    OPENSSL_free(wV);
    OPENSSL_free(wO);
    OPENSSL_free(wR);
    OPENSSL_free(wL);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    OPENSSL_free(vec_s);
    OPENSSL_free(vec_ip_x2);

    EC_POINT_free(P);

    zkp_poly_points_free(poly_p);

    return ret;
}
