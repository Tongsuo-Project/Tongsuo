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
#include <crypto/ec/ec_local.h>
#include <crypto/zkp/common/zkp_util.h>
#include "range_proof.h"

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(EC_POINT)
DEFINE_STACK_OF(BP_VARIABLE)

static void bp_range_proof_cleanup(BP_RANGE_PROOF *proof);

BP_RANGE_PROOF *bp_range_proof_alloc(const EC_GROUP *group)
{
    BP_RANGE_PROOF *proof = NULL;

    if (group == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    proof = OPENSSL_zalloc(sizeof(*proof));
    if (proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!(proof->A = EC_POINT_new(group))
        || !(proof->S = EC_POINT_new(group))
        || !(proof->T1 = EC_POINT_new(group))
        || !(proof->T2 = EC_POINT_new(group))
        || !(proof->taux = BN_new())
        || !(proof->mu = BN_new())
        || !(proof->tx = BN_new()))
        goto err;

    proof->references = 1;
    if ((proof->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    return proof;
err:
    BP_RANGE_PROOF_free(proof);
    return NULL;
}

/** Creates a new BP_RANGE_CTX object
 *  \param  pp          BP_PUB_PARAM object
 *  \param  witness     BP_WITNESS object
 *  \param  transcript  ZKP_TRANSCRIPT object
 *  \return newly created BP_RANGE_CTX object or NULL in case of an error
 */
BP_RANGE_CTX *BP_RANGE_CTX_new(BP_PUB_PARAM *pp, BP_WITNESS *witness,
                               ZKP_TRANSCRIPT *transcript)
{
    BP_RANGE_CTX *ctx = NULL;

    if (pp == NULL || transcript == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!BP_PUB_PARAM_up_ref(pp))
        goto err;

    ctx->pp = pp;

    if (!BP_WITNESS_up_ref(witness))
        goto err;

    ctx->witness = witness;

    ctx->transcript = transcript;

    return ctx;

err:
    BP_RANGE_CTX_free(ctx);
    return NULL;
}

/** Frees a BP_RANGE_CTX object
 *  \param  ctx       BP_RANGE_CTX object to be freed
 */
void BP_RANGE_CTX_free(BP_RANGE_CTX *ctx)
{
    if (ctx == NULL)
        return;

    BP_PUB_PARAM_down_ref(ctx->pp);
    BP_WITNESS_down_ref(ctx->witness);
    OPENSSL_clear_free((void *)ctx, sizeof(*ctx));
}

/** Creates a new BP_RANGE_PROOF object
 *  \param  pp          BP_PUB_PARAM object
 *  \return newly created BP_RANGE_PROOF object or NULL in case of an error
 */
BP_RANGE_PROOF *BP_RANGE_PROOF_new(const BP_PUB_PARAM *pp)
{
    if (pp == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    return bp_range_proof_alloc(pp->group);
}

/** Frees a BP_RANGE_PROOF object
 *  \param  proof     BP_RANGE_PROOF object to be freed
 */
void BP_RANGE_PROOF_free(BP_RANGE_PROOF *proof)
{
    int ref;

    if (proof == NULL)
        return;

    CRYPTO_DOWN_REF(&proof->references, &ref, proof->lock);
    REF_PRINT_COUNT("BP_RANGE_PROOF", proof);
    if (ref > 0)
        return;
    REF_ASSERT_ISNT(ref < 0);

    EC_POINT_free(proof->A);
    EC_POINT_free(proof->S);
    EC_POINT_free(proof->T1);
    EC_POINT_free(proof->T2);
    BN_free(proof->taux);
    BN_free(proof->mu);
    BN_free(proof->tx);
    bp_inner_product_proof_free(proof->ip_proof);
    CRYPTO_THREAD_lock_free(proof->lock);
    OPENSSL_free(proof);
}

static void bp_range_proof_cleanup(BP_RANGE_PROOF *proof)
{
    if (proof == NULL)
        return;

    bp_inner_product_proof_free(proof->ip_proof);
    proof->ip_proof = NULL;
}

/** Increases the internal reference count of a BP_RANGE_PROOF object.
 *  \param  proof  BP_RANGE_PROOF object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_RANGE_PROOF_up_ref(BP_RANGE_PROOF *proof)
{
    int ref;

    if (CRYPTO_UP_REF(&proof->references, &ref, proof->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("BP_RANGE_PROOF", proof);
    REF_ASSERT_ISNT(ref < 2);
    return ((ref > 1) ? 1 : 0);
}

/** Decreases the internal reference count of a BP_RANGE_PROOF object.
 *  \param  proof  BP_RANGE_PROOF object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_RANGE_PROOF_down_ref(BP_RANGE_PROOF *proof)
{
    int ref;

    if (CRYPTO_DOWN_REF(&proof->references, &ref, proof->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("BP_RANGE_PROOF", proof);
    REF_ASSERT_ISNT(ref > 0);
    return ((ref > 0) ? 1 : 0);
}

/** Prove computes the ZK rangeproof.
 *  \param  ctx       BP_RANGE_CTX object
 *  \param  proof     BP_RANGE_PROOF object
 *  \return 1 on success and 0 if an error occurred.
 */
int BP_RANGE_PROOF_prove(BP_RANGE_CTX *ctx, BP_RANGE_PROOF *proof)
{
    int i, j, m = 0, n, ret = 0;
    int bits, poly_num, witness_n, witness_r_n, witness_v_n, witness_padded_n;
    int *aL = NULL, *aR = NULL;
    ZKP_TRANSCRIPT *transcript;
    BP_PUB_PARAM *pp;
    BP_WITNESS *witness;
    BIGNUM *witness_r, *witness_v;
    BIGNUM *alpha, *rho, *tau1, *tau2, *bn0, *bn1, *bn2, *bn_1, *tmp;
    BIGNUM *x, *y, *y_inv, *pow_y_inv, *z, *z2, *pow_zn, **pow_y = NULL;
    BIGNUM *pow_2, *dv, *t, *t1, *t2, *r0, *r1, **sL = NULL, **sR = NULL;
    BIGNUM **ll0 = NULL, **rr1 = NULL, **rr2 = NULL;
    BIGNUM *g_scalar, *h_scalar, *l, *r;
    STACK_OF(BIGNUM) *sk_G_scalars = NULL, *sk_H_scalars = NULL;
    STACK_OF(BIGNUM) *sk_l = NULL, *sk_r = NULL;
    STACK_OF(EC_POINT) *sk_G = NULL, *sk_H = NULL;
    EC_POINT *P = NULL, *T = NULL, *U = NULL, *G, *H;
    zkp_poly_points_t *poly_a = NULL, *poly_s = NULL, *poly_p = NULL;
    const BIGNUM *order;
    EC_GROUP *group;
    BN_CTX *bn_ctx = NULL;
    bp_inner_product_ctx_t *ip_ctx = NULL;
    bp_inner_product_pub_param_t *ip_pp = NULL;
    bp_inner_product_witness_t *ip_witness = NULL;

    if (ctx == NULL || ctx->pp == NULL || ctx->witness == NULL || proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    pp = ctx->pp;
    witness = ctx->witness;
    transcript = ctx->transcript;
    group = pp->group;
    order = EC_GROUP_get0_order(group);

    bn_ctx = BN_CTX_new_ex(group->libctx);
    if (bn_ctx == NULL)
        goto err;

    BN_CTX_start(bn_ctx);
    alpha = BN_CTX_get(bn_ctx);
    rho = BN_CTX_get(bn_ctx);
    tau1 = BN_CTX_get(bn_ctx);
    tau2 = BN_CTX_get(bn_ctx);
    bn0 = BN_CTX_get(bn_ctx);
    bn1 = BN_CTX_get(bn_ctx);
    bn2 = BN_CTX_get(bn_ctx);
    bn_1 = BN_CTX_get(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    y_inv = BN_CTX_get(bn_ctx);
    pow_y_inv = BN_CTX_get(bn_ctx);
    z = BN_CTX_get(bn_ctx);
    z2 = BN_CTX_get(bn_ctx);
    pow_zn = BN_CTX_get(bn_ctx);
    pow_2 = BN_CTX_get(bn_ctx);
    t1 = BN_CTX_get(bn_ctx);
    t2 = BN_CTX_get(bn_ctx);
    t = BN_CTX_get(bn_ctx);
    r0 = BN_CTX_get(bn_ctx);
    r1 = BN_CTX_get(bn_ctx);
    dv = BN_CTX_get(bn_ctx);
    if (dv == NULL)
        goto err;

    BN_zero(t1);
    BN_zero(t2);
    BN_zero(bn0);
    BN_one(bn1);
    BN_one(bn_1);
    BN_set_negative(bn_1, 1);
    BN_set_word(bn2, 2);
    BN_one(pow_y_inv);

    witness_n = sk_BP_VARIABLE_num(witness->sk_V);
    witness_padded_n = zkp_next_power_of_two(witness_n);
    if (witness_padded_n > ctx->pp->party_capacity) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_EXCEEDS_PARTY_CAPACITY);
        goto err;
    }

    for (i = witness_n; i < witness_padded_n; i++) {
        if (!BP_WITNESS_commit(witness, NULL, bn0))
            goto err;
    }

    witness_r_n = sk_BIGNUM_num(witness->sk_r);
    witness_v_n = sk_BIGNUM_num(witness->sk_v);
    witness_n = sk_BP_VARIABLE_num(witness->sk_V);
    witness_padded_n = zkp_next_power_of_two(witness_n);

    if (witness_r_n != witness_v_n || witness_v_n != witness_n) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_WITNESS_INVALID);
        goto err;
    }

    n = pp->gens_capacity * witness_padded_n;
    poly_num = n * 2  + 1;
    bits = pp->gens_capacity;

    if (!zkp_is_power_of_two(n)) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_RANGE_LEN_MUST_BE_POWER_OF_TWO);
        goto err;
    }

    if (proof->ip_proof != NULL)
        bp_range_proof_cleanup(proof);

    if (!(P = EC_POINT_new(group))
        || !(T = EC_POINT_new(group))
        || !(U = EC_POINT_new(group)))
        goto err;

    if (!(aL = OPENSSL_zalloc(sizeof(*aL) * n))
        || !(aR = OPENSSL_zalloc(sizeof(*aL) * n))
        || !(sL = OPENSSL_zalloc(sizeof(*sL) * n))
        || !(sR = OPENSSL_zalloc(sizeof(*sR) * n))
        || !(sk_G = sk_EC_POINT_new_reserve(NULL, n))
        || !(sk_H = sk_EC_POINT_new_reserve(NULL, n))
        || !(sk_G_scalars = sk_BIGNUM_new_reserve(NULL, n))
        || !(sk_H_scalars = sk_BIGNUM_new_reserve(NULL, n))
        || !(sk_l = sk_BIGNUM_new_reserve(NULL, n))
        || !(sk_r = sk_BIGNUM_new_reserve(NULL, n))
        || !(pow_y = OPENSSL_zalloc(sizeof(*pow_y) * n))
        || !(ll0 = OPENSSL_zalloc(sizeof(*ll0) * n))
        || !(rr1 = OPENSSL_zalloc(sizeof(*rr1) * n))
        || !(rr2 = OPENSSL_zalloc(sizeof(*rr2) * n))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!(poly_a = zkp_poly_points_new(poly_num))
        || !(poly_s = zkp_poly_points_new(poly_num))
        || !(poly_p = zkp_poly_points_new(poly_num)))
        goto err;

    if (!zkp_rand_range(alpha, order)
        || !zkp_rand_range(rho, order)
        || !zkp_rand_range(tau1, order)
        || !zkp_rand_range(tau2, order))
        goto err;

    /* (45) */
    if (!zkp_random_bn_gen(group, sL, n, bn_ctx)
        || !zkp_random_bn_gen(group, sR, n, bn_ctx))
        goto err;

    for (i = 0; i < witness_n; i++) {
        witness_v = sk_BIGNUM_value(witness->sk_v, i);
        for (j = 0; j < bits; j++) {
            if (!BN_div(dv, t, witness_v, bn2, bn_ctx))
                goto err;

            witness_v = dv;
            m = i * pp->gens_capacity + j;
            aL[m] = BN_is_one(t);
            aR[m] = aL[m] - 1;

            G = sk_EC_POINT_value(pp->sk_G, m);
            H = sk_EC_POINT_value(pp->sk_H, m);
            if (G == NULL || H == NULL)
                goto err;

            if (!zkp_poly_points_append(poly_a, G, aL[m] == 1 ? bn1 : bn0)
                || !zkp_poly_points_append(poly_a, H, aR[m] == -1 ? bn_1 : bn0)
                || !zkp_poly_points_append(poly_s, G, sL[m])
                || !zkp_poly_points_append(poly_s, H, sR[m]))
                goto err;
        }
    }

    if (!zkp_poly_points_append(poly_a, pp->H, alpha)
        || !zkp_poly_points_append(poly_s, pp->H, rho))
        goto err;

    /* (44, 47) */
    if (!zkp_poly_points_mul(poly_a, proof->A, NULL, group, bn_ctx)
        || !zkp_poly_points_mul(poly_s, proof->S, NULL, group, bn_ctx))
        goto err;

    /* compute hash */
    if (!ZKP_TRANSCRIPT_append_point(transcript, "A", proof->A, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "S", proof->S, group))
        goto err;

    if (!ZKP_TRANSCRIPT_challange(transcript, "y", y)
        || !ZKP_TRANSCRIPT_challange(transcript, "z", z))
        goto err;

    if (!BN_mod_sqr(z2, z, order, bn_ctx) || !BN_copy(pow_zn, z2)
        || !BN_mod_inverse(y_inv, y, order, bn_ctx))
        goto err;

    pow_y[0] = bn1;
    BN_zero(proof->taux);

    /*
     * ll0 = aL - z * 1^n
     * rr1 = aR + z * 1^n
     * rr2 = z^(n+1) * 2^n
     * r0 = y^n * (aR + z * 1^n) + z^(n+1) * 2^n = y^n * rr1 + rr2
     * r1 = y^n * sR
     * l = ll0 + sL * x
     * r = y^n * (aR + z * 1^n + sR * x) + z^(n+1) * 2^n = y^n * (rr1 + sR * x) + rr2
     * t1 = <ll0 * r1 + sL * r0>
     * t2 = <r1 * r1> = <sL * y^n * sR>
     */
    for (i = 0; i < witness_n; i++) {
        witness_r = sk_BIGNUM_value(witness->sk_r, i);
        BN_one(pow_2);

        for (j = 0; j < bits; j++) {
            m = i * bits + j;
            if (m > 0) {
                if ((pow_y[m] = BN_CTX_get(bn_ctx)) == NULL)
                    goto err;

                if (!BN_mod_mul(pow_y[m], pow_y[m-1], y, order, bn_ctx))
                    goto err;
            }

            if ((ll0[m] = BN_CTX_get(bn_ctx)) == NULL
                || (rr1[m] = BN_CTX_get(bn_ctx)) == NULL
                || (rr2[m] = BN_CTX_get(bn_ctx)) == NULL)
                goto err;

            if (!BN_mod_sub(ll0[m], aL[m] == 1 ? bn1 : bn0, z, order, bn_ctx)
                || !BN_mod_mul(r1, pow_y[m], sR[m], order, bn_ctx)
                || !BN_mod_mul(t, ll0[m], r1, order, bn_ctx)
                || !BN_mod_add(t1, t1, t, order, bn_ctx)
                || !BN_mod_add(rr1[m], aR[m] == 0 ? bn0 : bn_1, z, order, bn_ctx)
                || !BN_mod_mul(t, pow_y[m], rr1[m], order, bn_ctx))
                goto err;

            if (!BN_mod_mul(rr2[m], pow_zn, pow_2, order, bn_ctx)
                || !BN_mod_add(r0, t, rr2[m], order, bn_ctx)
                || !BN_mod_mul(t, r0, sL[m], order, bn_ctx)
                || !BN_mod_add(t1, t1, t, order, bn_ctx)
                || !BN_mod_mul(t, r1, sL[m], order, bn_ctx)
                || !BN_mod_add(t2, t2, t, order, bn_ctx))
                goto err;

            if (!BN_mod_mul(pow_2, pow_2, bn2, order, bn_ctx))
                goto err;
        }

        if (!BN_mul(t, pow_zn, witness_r, bn_ctx)
            || !BN_mod_add(proof->taux, proof->taux, t, order, bn_ctx))
            goto err;

        if (!BN_mod_mul(pow_zn, pow_zn, z, order, bn_ctx))
            goto err;
    }

    /* (53, 54) */
    if (!EC_POINT_mul(group, proof->T1, tau1, pp->H, t1, bn_ctx)
        || !EC_POINT_mul(group, proof->T2, tau2, pp->H, t2, bn_ctx))
        goto err;

    /* (55, 56) */
    if (!ZKP_TRANSCRIPT_append_point(transcript, "T1", proof->T1, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "T2", proof->T2, group))
        goto err;

    if (!ZKP_TRANSCRIPT_challange(transcript, "x", x))
        goto err;

    BN_zero(proof->tx);

    for (i = 0; i < witness_n; i++) {
        for (j = 0; j < bits; j++) {
            m = i * bits + j;
            tmp = BN_CTX_get(bn_ctx);
            l = BN_CTX_get(bn_ctx);
            r = BN_CTX_get(bn_ctx);
            g_scalar = BN_CTX_get(bn_ctx);
            h_scalar = BN_CTX_get(bn_ctx);
            if (h_scalar == NULL)
                goto err;

            G = sk_EC_POINT_value(pp->sk_G, m);
            H = sk_EC_POINT_value(pp->sk_H, m);
            if (G == NULL || H == NULL)
                goto err;

            BN_one(g_scalar);

            /* (58, 59, 60) */
            if (!BN_mod_mul(t, sL[m], x, order, bn_ctx)
                || !BN_mod_add(l, ll0[m], t, order, bn_ctx)
                || !BN_mod_mul(t, sR[m], x, order, bn_ctx)
                || !BN_mod_add(rr1[m], rr1[m], t, order, bn_ctx)
                || !BN_mod_mul(dv, pow_y[m], rr1[m], order, bn_ctx)
                || !BN_mod_add(r, dv, rr2[m], order, bn_ctx)
                || !BN_mod_mul(t, l, r, order, bn_ctx)
                || !BN_mod_add(proof->tx, proof->tx, t, order, bn_ctx))
                goto err;

            if (!BN_copy(h_scalar, pow_y_inv))
                goto err;

            if (sk_EC_POINT_push(sk_G, sk_EC_POINT_value(pp->sk_G, m)) <= 0
                || sk_EC_POINT_push(sk_H, sk_EC_POINT_value(pp->sk_H, m)) <= 0
                || sk_BIGNUM_push(sk_G_scalars, g_scalar) <= 0
                || sk_BIGNUM_push(sk_H_scalars, h_scalar) <= 0
                || sk_BIGNUM_push(sk_l, l) <= 0
                || sk_BIGNUM_push(sk_r, r) <= 0)
                goto err;

            if (!BN_mod_mul(tmp, r, pow_y_inv, order, bn_ctx))
                goto err;

            if (!BN_mod_mul(pow_y_inv, pow_y_inv, y_inv, order, bn_ctx))
                goto err;

            if (!zkp_poly_points_append(poly_p, G, l)
                || !zkp_poly_points_append(poly_p, H, tmp))
                goto err;
        }
    }

    /* (61) */
    if (!BN_mod_sqr(t, x, order, bn_ctx)
        || !BN_mod_mul(t, t, tau2, order, bn_ctx)
        || !BN_mod_add(proof->taux, proof->taux, t, order, bn_ctx)
        || !BN_mod_mul(t, x, tau1, order, bn_ctx)
        || !BN_mod_add(proof->taux, proof->taux, t, order, bn_ctx))
        goto err;

    /* (62) */
    if (!BN_mul(proof->mu, rho, x, bn_ctx)
        || !BN_mod_add(proof->mu, proof->mu, alpha, order, bn_ctx))
        goto err;

    /* (67) */
    if (!EC_POINT_mul(group, U, NULL, pp->U, x, bn_ctx)
        || !zkp_poly_points_append(poly_p, U, proof->tx)
        || !zkp_poly_points_mul(poly_p, P, NULL, group, bn_ctx))
        goto err;

    if (!(ip_pp = bp_inner_product_pub_param_new(group, sk_G, sk_H))
        || !(ip_ctx = bp_inner_product_ctx_new(ip_pp, transcript, U, P,
                                               sk_G_scalars, sk_H_scalars))
        || !(ip_witness = bp_inner_product_witness_new(sk_l, sk_r))
        || !(proof->ip_proof = bp_inner_product_proof_prove(ip_ctx, ip_witness)))
        goto err;

    ret = 1;

err:
    ZKP_TRANSCRIPT_reset(transcript);

    bp_inner_product_witness_free(ip_witness);
    bp_inner_product_pub_param_free(ip_pp);
    bp_inner_product_ctx_free(ip_ctx);

    zkp_poly_points_free(poly_a);
    zkp_poly_points_free(poly_s);
    zkp_poly_points_free(poly_p);

    sk_EC_POINT_free(sk_G);
    sk_EC_POINT_free(sk_H);
    sk_BIGNUM_free(sk_G_scalars);
    sk_BIGNUM_free(sk_H_scalars);
    sk_BIGNUM_free(sk_l);
    sk_BIGNUM_free(sk_r);

    OPENSSL_free(pow_y);
    OPENSSL_free(ll0);
    OPENSSL_free(rr1);
    OPENSSL_free(rr2);
    OPENSSL_free(sL);
    OPENSSL_free(sR);
    OPENSSL_free(aL);
    OPENSSL_free(aR);
    EC_POINT_free(P);
    EC_POINT_free(T);
    EC_POINT_free(U);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Prove computes the ZK rangeproof and new a proof object.
 *  \param  ctx       BP_RANGE_CTX object
 *  \return BP_RANGE_PROOF object on success or NULL in case of an error
 */
BP_RANGE_PROOF *BP_RANGE_PROOF_new_prove(BP_RANGE_CTX *ctx)
{
    BP_RANGE_PROOF *proof = NULL;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (!(proof = BP_RANGE_PROOF_new(ctx->pp)))
        return NULL;

    if (!BP_RANGE_PROOF_prove(ctx, proof))
        goto err;

    return proof;
err:
    BP_RANGE_PROOF_free(proof);
    return NULL;
}

/** Verifies that the supplied proof is a valid proof
 *  for the supplied secret values using the supplied public parameters.
 *  \param  ctx       BP_RANGE_CTX object
 *  \param  proof     BP_RANGE_PROOF object
 *  \return 1 if the proof is valid, 0 if the proof is invalid and -1 on error
 */
int BP_RANGE_PROOF_verify(BP_RANGE_CTX *ctx, const BP_RANGE_PROOF *proof)
{
    int ret = 0, i = 0, j, m, n, bits, poly_p_num, poly_r_num, witness_n, witness_padded_n;
    ZKP_TRANSCRIPT *transcript;
    BP_PUB_PARAM *pp;
    BP_WITNESS *witness;
    BP_VARIABLE *V;
    BIGNUM *bn0, *bn1, *bn2, *delta;
    BIGNUM *x, *x2, *y, *y_inv, *z, *z2, *nz, *t, *tmp, *z_pow_y;
    BIGNUM *pow_y, *pow_y_inv, *pow_z, *pow_2, *sum_pow_y, *sum_pow_z, *sum_pow_2;
    BIGNUM *g_scalar, *h_scalar;
    STACK_OF(BIGNUM) *sk_G_scalars = NULL, *sk_H_scalars = NULL;
    STACK_OF(EC_POINT) *sk_G = NULL, *sk_H = NULL;
    EC_POINT *O = NULL, *P = NULL, *U = NULL, *L = NULL, *R = NULL, *G, *H;
    BN_CTX *bn_ctx = NULL;
    zkp_poly_points_t *poly_p = NULL, *poly_r = NULL;
    EC_GROUP *group;
    const BIGNUM *order;
    bp_inner_product_ctx_t *ip_ctx = NULL;
    bp_inner_product_pub_param_t *ip_pp = NULL;

    if (ctx == NULL || ctx->pp == NULL || ctx->witness == NULL || proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    transcript = ctx->transcript;
    pp = ctx->pp;
    witness = ctx->witness;
    bits = pp->gens_capacity;
    witness_n = sk_BP_VARIABLE_num(witness->sk_V);
    witness_padded_n = zkp_next_power_of_two(witness_n);
    n = bits * witness_padded_n;
    poly_p_num = bits * witness_padded_n * 2 + 4;
    poly_r_num = bits * witness_padded_n + 3;
    group = pp->group;
    order = EC_GROUP_get0_order(group);

    if (!zkp_is_power_of_two(n)) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_RANGE_LEN_MUST_BE_POWER_OF_TWO);
        return 0;
    }

    if (witness_n != witness_padded_n) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_WITNESS_INVALID);
        return 0;
    }

    if (witness_padded_n > ctx->pp->party_capacity) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_EXCEEDS_PARTY_CAPACITY);
        return 0;
    }

    if (EC_GROUP_get_curve_name(pp->group) != EC_POINT_get_curve_name(proof->A)) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    if (!(sk_G = sk_EC_POINT_new_reserve(NULL, n))
        || !(sk_H = sk_EC_POINT_new_reserve(NULL, n))
        || !(sk_G_scalars = sk_BIGNUM_new_reserve(NULL, n))
        || !(sk_H_scalars = sk_BIGNUM_new_reserve(NULL, n))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!(poly_p = zkp_poly_points_new(poly_p_num)) || !(poly_r = zkp_poly_points_new(poly_r_num)))
        goto err;

    if (!(O = EC_POINT_new(group))
        || !(P = EC_POINT_new(group))
        || !(U = EC_POINT_new(group))
        || !(L = EC_POINT_new(group))
        || !(R = EC_POINT_new(group)))
        goto err;

    bn_ctx = BN_CTX_new_ex(group->libctx);
    if (bn_ctx == NULL)
        goto err;

    BN_CTX_start(bn_ctx);
    bn0 = BN_CTX_get(bn_ctx);
    bn1 = BN_CTX_get(bn_ctx);
    bn2 = BN_CTX_get(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    x2 = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    y_inv = BN_CTX_get(bn_ctx);
    z = BN_CTX_get(bn_ctx);
    z2 = BN_CTX_get(bn_ctx);
    z_pow_y = BN_CTX_get(bn_ctx);
    nz = BN_CTX_get(bn_ctx);
    sum_pow_y = BN_CTX_get(bn_ctx);
    sum_pow_z = BN_CTX_get(bn_ctx);
    sum_pow_2 = BN_CTX_get(bn_ctx);
    t = BN_CTX_get(bn_ctx);
    pow_y = BN_CTX_get(bn_ctx);
    pow_y_inv = BN_CTX_get(bn_ctx);
    pow_z = BN_CTX_get(bn_ctx);
    pow_2 = BN_CTX_get(bn_ctx);
    delta = BN_CTX_get(bn_ctx);
    if (delta == NULL)
        goto err;

    BN_zero(sum_pow_y);
    BN_zero(sum_pow_z);
    BN_zero(sum_pow_2);
    BN_one(pow_y);
    BN_one(pow_y_inv);
    BN_one(bn0);
    BN_one(bn1);
    BN_set_word(bn2, 2);

    EC_POINT_set_to_infinity(group, O);

    if (!ZKP_TRANSCRIPT_append_point(transcript, "A", proof->A, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "S", proof->S, group))
        goto err;

    if (!ZKP_TRANSCRIPT_challange(transcript, "y", y)
        || !ZKP_TRANSCRIPT_challange(transcript, "z", z))
        goto err;

    if (!ZKP_TRANSCRIPT_append_point(transcript, "T1", proof->T1, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "T2", proof->T2, group))
        goto err;

    if (!ZKP_TRANSCRIPT_challange(transcript, "x", x))
        goto err;

    if (!BN_mod_inverse(y_inv, y, order, bn_ctx)
        || !BN_mod_sqr(x2, x, order, bn_ctx)
        || !BN_mod_sqr(z2, z, order, bn_ctx)
        || !BN_sub(nz, order, z)
        || !BN_copy(pow_z, z))
        goto err;

    for (i = 0; i < witness_n; i++) {
        V = sk_BP_VARIABLE_value(witness->sk_V, i);
        if (V == NULL)
            goto err;

        BN_one(pow_2);

        if (!BN_mod_mul(pow_z, pow_z, z, order, bn_ctx)
            || !BN_mod_add(sum_pow_z, sum_pow_z, pow_z, order, bn_ctx))
            goto err;

        for (j = 0; j < bits; j++) {
            m = i * bits + j;
            if (i == 0) {
                if (!BN_mod_add(sum_pow_2, sum_pow_2, pow_2, order, bn_ctx))
                    goto err;
            }

            G = sk_EC_POINT_value(pp->sk_G, m);
            H = sk_EC_POINT_value(pp->sk_H, m);
            if (G == NULL || H == NULL)
                goto err;

            tmp = BN_CTX_get(bn_ctx);
            g_scalar = BN_CTX_get(bn_ctx);
            h_scalar = BN_CTX_get(bn_ctx);
            if (h_scalar == NULL)
                goto err;

            BN_one(g_scalar);

            if (!BN_copy(h_scalar, pow_y_inv))
                goto err;

            if (sk_EC_POINT_push(sk_G, sk_EC_POINT_value(pp->sk_G, m)) <= 0
                || sk_EC_POINT_push(sk_H, sk_EC_POINT_value(pp->sk_H, m)) <= 0
                || sk_BIGNUM_push(sk_G_scalars, g_scalar) <= 0
                || sk_BIGNUM_push(sk_H_scalars, h_scalar) <= 0)
                goto err;

            if (!BN_mod_add(sum_pow_y, sum_pow_y, pow_y, order, bn_ctx)
                || !BN_mod_mul(z_pow_y, z, pow_y, order, bn_ctx)
                || !BN_mod_mul(t, pow_z, pow_2, order, bn_ctx)
                || !BN_mod_add(t, t, z_pow_y, order, bn_ctx))
                goto err;

            if (!BN_copy(tmp, t) || !BN_mod_mul(tmp, tmp, pow_y_inv, order, bn_ctx))
                goto err;

            if (!zkp_poly_points_append(poly_p, G, nz)
                || !zkp_poly_points_append(poly_p, H, tmp))
                goto err;

            if (!BN_mod_mul(pow_y, pow_y, y, order, bn_ctx)
                || !BN_mod_mul(pow_y_inv, pow_y_inv, y_inv, order, bn_ctx)
                || !BN_mod_mul(pow_2, pow_2, bn2, order, bn_ctx))
                goto err;
        }

        tmp = BN_CTX_get(bn_ctx);
        if (tmp == NULL || !BN_copy(tmp, pow_z))
            goto err;

        if (!zkp_poly_points_append(poly_r, V->point, tmp))
            goto err;
    }

    if (!BN_mod_mul(sum_pow_z, sum_pow_z, z, order, bn_ctx))
        goto err;

    /* (39) also see page 21 */
    if (!BN_mod_sub(delta, z, z2, order, bn_ctx)
        || !BN_mod_mul(delta, delta, sum_pow_y, order, bn_ctx)
        || !BN_mod_mul(t, sum_pow_z, sum_pow_2, order, bn_ctx)
        || !BN_mod_sub(delta, delta, t, order, bn_ctx))
        goto err;

    /* (72) */
    if (!zkp_poly_points_append(poly_r, pp->H, delta)
        || !zkp_poly_points_append(poly_r, proof->T1, x)
        || !zkp_poly_points_append(poly_r, proof->T2, x2)
        || !zkp_poly_points_mul(poly_r, R, NULL, group, bn_ctx))
        goto err;

    /* (65) */
    if (!EC_POINT_mul(group, L, proof->taux, pp->H, proof->tx, bn_ctx)
        || !EC_POINT_invert(group, L, bn_ctx)
        || !EC_POINT_add(group, R, R, L, bn_ctx)
        || !EC_POINT_is_at_infinity(group, R))
        goto err;

    if (!EC_POINT_mul(group, U, NULL, pp->U, x, bn_ctx))
        goto err;

    tmp = BN_CTX_get(bn_ctx);
    if (tmp == NULL)
        goto err;

    if (!BN_copy(tmp, proof->mu))
        goto err;

    BN_set_negative(tmp, !BN_is_negative(tmp));

    if (!zkp_poly_points_append(poly_p, proof->S, x)
        || !zkp_poly_points_append(poly_p, proof->A, bn1)
        || !zkp_poly_points_append(poly_p, pp->H, tmp)
        || !zkp_poly_points_append(poly_p, U, proof->tx)
        || !zkp_poly_points_mul(poly_p, P, NULL, group, bn_ctx))
        goto err;

    if (!(ip_pp = bp_inner_product_pub_param_new(group, sk_G, sk_H))
        || !(ip_ctx = bp_inner_product_ctx_new(ip_pp, transcript, U, P,
                                               sk_G_scalars, sk_H_scalars)))
        goto err;

    ret = bp_inner_product_proof_verify(ip_ctx, proof->ip_proof);

err:
    ZKP_TRANSCRIPT_reset(transcript);

    bp_inner_product_ctx_free(ip_ctx);
    bp_inner_product_pub_param_free(ip_pp);

    zkp_poly_points_free(poly_p);
    zkp_poly_points_free(poly_r);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    EC_POINT_free(L);
    EC_POINT_free(R);
    EC_POINT_free(U);
    EC_POINT_free(P);
    EC_POINT_free(O);

    sk_EC_POINT_free(sk_G);
    sk_EC_POINT_free(sk_H);
    sk_BIGNUM_free(sk_G_scalars);
    sk_BIGNUM_free(sk_H_scalars);
    return ret;
}
