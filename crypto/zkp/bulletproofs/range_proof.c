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
#include "range_proof.h"
#include "transcript.h"
#include "util.h"

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

/** Creates a new BULLET_PROOF_PUB_PARAM object
 *  \param  curve_id    the elliptic curve id
 *  \param  bits        the range bits that support verification
 *  \param  max_agg_num the number of the aggregate range proofs
 *  \return newly created BULLET_PROOF_PUB_PARAM object or NULL in case of an error
 */
BULLET_PROOF_PUB_PARAM *BULLET_PROOF_PUB_PARAM_new(int curve_id, int bits,
                                                   int max_agg_num)
{
    int n;
    size_t plen;
    unsigned char *pstr = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;
    BULLET_PROOF_PUB_PARAM *pp = NULL;
    point_conversion_form_t format = POINT_CONVERSION_COMPRESSED;

    if (curve_id == NID_undef || bits <= 0 || max_agg_num <= 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (bits > BULLET_PROOF_MAX_BITS) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_EXCEEDS_MAX_BITS);
        return NULL;
    }

    if (max_agg_num > BULLET_PROOF_MAX_AGG_NUM) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_EXCEEDS_MAX_AGG_NUM);
        return NULL;
    }

    pp = OPENSSL_zalloc(sizeof(*pp));
    if (pp == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    pp->curve_id = curve_id;

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto err;

    bn_ctx = BN_CTX_new_ex(group->libctx);
    if (bn_ctx == NULL)
        goto err;

    pp->H = EC_POINT_new(group);
    if (pp->H == NULL)
        goto err;

    plen = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group), format,
                              NULL, 0, bn_ctx);
    if (plen <= 0)
        goto err;

    pstr = OPENSSL_zalloc(plen);
    if (pstr == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EC_POINT_point2oct(group, EC_GROUP_get0_generator(group), format, pstr,
                           plen, bn_ctx) <= 0)
        goto err;

    if (!bp_str2point(group, pstr, plen, pp->H, bn_ctx))
        goto err;

    pp->bits = bits;
    pp->max_agg_num = max_agg_num;
    n = bits * max_agg_num;

    if (!(pp->vec_G = bp_random_ec_points_new(group, n, bn_ctx))
        || !(pp->vec_H = bp_random_ec_points_new(group, n, bn_ctx))
        || !(pp->U = bp_random_ec_point_new(group, bn_ctx)))
        goto err;

    pp->references = 1;
    if ((pp->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    OPENSSL_free(pstr);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return pp;

err:
    OPENSSL_free(pstr);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    BULLET_PROOF_PUB_PARAM_free(pp);
    return NULL;
}

/** Creates a new BULLET_PROOF_PUB_PARAM object by curve name
 *  \param  curve_name    the elliptic curve name
 *  \param  bits        the range bits that support verification
 *  \param  max_agg_num the number of the aggregate range proofs
 *  \return newly created BULLET_PROOF_PUB_PARAM object or NULL in case of an error
 */
BULLET_PROOF_PUB_PARAM *BULLET_PROOF_PUB_PARAM_new_by_curve_name(const char *curve_name,
                                                                 int bits,
                                                                 int max_agg_num)
{
    int curve_id = ossl_ec_curve_name2nid(curve_name);

    if (curve_id == NID_undef) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    return BULLET_PROOF_PUB_PARAM_new(curve_id, bits, max_agg_num);
}

/** Frees a BULLET_PROOF_PUB_PARAM object
 *  \param  pp        BULLET_PROOF_PUB_PARAM object to be freed
 */
void BULLET_PROOF_PUB_PARAM_free(BULLET_PROOF_PUB_PARAM *pp)
{
    int ref;

    if (pp == NULL)
        return;

    CRYPTO_DOWN_REF(&pp->references, &ref, pp->lock);
    REF_PRINT_COUNT("BULLET_PROOF_PUB_PARAM", pp);
    if (ref > 0)
        return;
    REF_ASSERT_ISNT(ref < 0);

    bp_random_ec_points_free(pp->vec_G, pp->bits * pp->max_agg_num);
    bp_random_ec_points_free(pp->vec_H, pp->bits * pp->max_agg_num);
    bp_random_ec_point_free(pp->U);
    EC_POINT_free(pp->H);
    CRYPTO_THREAD_lock_free(pp->lock);
    OPENSSL_clear_free((void *)pp, sizeof(*pp));
}

/** Increases the internal reference count of a BULLET_PROOF_PUB_PARAM object.
 *  \param  pp  BULLET_PROOF_PUB_PARAM object
 *  \return 1 on success and 0 if an error occurred.
 */
int BULLET_PROOF_PUB_PARAM_up_ref(BULLET_PROOF_PUB_PARAM *pp)
{
    int ref;

    if (CRYPTO_UP_REF(&pp->references, &ref, pp->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("BULLET_PROOF_PUB_PARAM", pp);
    REF_ASSERT_ISNT(ref < 2);
    return ((ref > 1) ? 1 : 0);
}

/** Decreases the internal reference count of a BULLET_PROOF_PUB_PARAM object.
 *  \param  pp  BULLET_PROOF_PUB_PARAM object
 *  \return 1 on success and 0 if an error occurred.
 */
int BULLET_PROOF_PUB_PARAM_down_ref(BULLET_PROOF_PUB_PARAM *pp)
{
    int ref;

    if (CRYPTO_DOWN_REF(&pp->references, &ref, pp->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("BULLET_PROOF_PUB_PARAM", proof);
    REF_ASSERT_ISNT(ref > 0);
    return ((ref > 0) ? 1 : 0);
}

/** Creates a new BP_RANGE_PROOF_CTX object
 *  \return newly created BP_RANGE_PROOF_CTX object or NULL in case of an error
 */
BP_RANGE_PROOF_CTX *BP_RANGE_PROOF_CTX_new(BULLET_PROOF_PUB_PARAM *pp,
                                           BP_TRANSCRIPT *transcript)
{
    BP_RANGE_PROOF_CTX *ctx = NULL;

    if (pp == NULL || transcript == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!BULLET_PROOF_PUB_PARAM_up_ref(pp))
        goto err;

    ctx->pp = pp;
    ctx->transcript = transcript;

    ctx->group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, pp->curve_id);
    if (ctx->group == NULL)
        goto err;

    ctx->G = EC_GROUP_get0_generator(ctx->group);

    return ctx;

err:
    BP_RANGE_PROOF_CTX_free(ctx);
    return NULL;
}

/** Frees a BP_RANGE_PROOF_CTX object
 *  \param  ctx       BP_RANGE_PROOF_CTX object to be freed
 */
void BP_RANGE_PROOF_CTX_free(BP_RANGE_PROOF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    BULLET_PROOF_PUB_PARAM_free(ctx->pp);
    EC_GROUP_free(ctx->group);
    OPENSSL_clear_free((void *)ctx, sizeof(*ctx));
}

/** Creates a new BP_RANGE_PROOF_WITNESS object
 *  \param  ctx       BP_RANGE_PROOF_CTX object
 *  \param  secrets   An array of secrets used to generate the witness
 *  \param  len       the length of secrets
 *  \return newly created BP_RANGE_PROOF_WITNESS object or NULL in case of an error
 */
BP_RANGE_PROOF_WITNESS *BP_RANGE_PROOF_WITNESS_new(BP_RANGE_PROOF_CTX *ctx,
                                                   int64_t secrets[], int agg_num)
{
    int i, padding_len = 0;
    const BIGNUM *order;
    BP_RANGE_PROOF_WITNESS *witness = NULL;

    if (ctx == NULL || agg_num <= 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (agg_num > ctx->pp->max_agg_num) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_EXCEEDS_MAX_AGG_NUM);
        return NULL;
    }

    if ((agg_num & (agg_num - 1)) != 0) {
        for (i = agg_num; i <= ctx->pp->max_agg_num; i++) {
            if ((i & (i - 1)) == 0) {
                padding_len = i - agg_num;
                break;
            }
        }
    }

    order = EC_GROUP_get0_order(ctx->group);

    if (!(witness = OPENSSL_zalloc(sizeof(*witness)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    witness->n = agg_num + padding_len;
    if (!(witness->vec_r = OPENSSL_zalloc(sizeof(*witness->vec_r) * witness->n))
        || !(witness->vec_v = OPENSSL_zalloc(sizeof(*witness->vec_v) * witness->n))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    for (i = 0; i < witness->n; i++) {
        if (!(witness->vec_r[i] = BN_new()) || !(witness->vec_v[i] = BN_new())
            || !bp_rand_range(witness->vec_r[i], order))
            goto err;

        if (i < agg_num) {
            if (!BN_lebin2bn((const unsigned char *)&secrets[i],
                             sizeof(secrets[i]), witness->vec_v[i]))
                goto err;
        } else {
            BN_zero(witness->vec_v[i]);
        }
    }

    return witness;
err:
    BP_RANGE_PROOF_WITNESS_free(witness);
    return NULL;
}

/** Frees a BP_RANGE_PROOF_WITNESS object
 *  \param  witness   BP_RANGE_PROOF_WITNESS object to be freed
 */
void BP_RANGE_PROOF_WITNESS_free(BP_RANGE_PROOF_WITNESS *witness)
{
    int i;

    if (witness == NULL)
        return;

    for (i = 0; i < witness->n; i++) {
        if (witness->vec_r)
            BN_free(witness->vec_r[i]);

        if (witness->vec_v)
            BN_free(witness->vec_v[i]);
    }

    OPENSSL_free(witness->vec_r);
    OPENSSL_free(witness->vec_v);
    OPENSSL_free(witness);
}

/** Creates a new BP_RANGE_PROOF object
 *  \param  ctx       BP_RANGE_PROOF_CTX object
 *  \return newly created BP_RANGE_PROOF_CTX object or NULL in case of an error
 */
BP_RANGE_PROOF *BP_RANGE_PROOF_new(BP_RANGE_PROOF_CTX *ctx)
{
    if (ctx == NULL || ctx->pp == NULL || ctx->group == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    return bp_range_proof_alloc(ctx->group);
}

/** Frees a BP_RANGE_PROOF object
 *  \param  proof     BP_RANGE_PROOF object to be freed
 */
void BP_RANGE_PROOF_free(BP_RANGE_PROOF *proof)
{
    int i, ref;

    if (proof == NULL)
        return;

    CRYPTO_DOWN_REF(&proof->references, &ref, proof->lock);
    REF_PRINT_COUNT("BP_RANGE_PROOF", proof);
    if (ref > 0)
        return;
    REF_ASSERT_ISNT(ref < 0);

    for (i = 0; i < proof->n; i++) {
        EC_POINT_free(proof->V[i]);
    }
    OPENSSL_free(proof->V);

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
    int i;

    if (proof == NULL)
        return;

    if (proof->V != NULL) {
        for (i = 0; i < proof->n; i++) {
            EC_POINT_free(proof->V[i]);
            proof->V[i] = NULL;
        }
        proof->V = NULL;
    }

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
 *  \param  ctx       BP_RANGE_PROOF_CTX object
 *  \param  witness   BP_RANGE_PROOF_WITNESS object
 *  \param  proof     BP_RANGE_PROOF object
 *  \return 1 on success and 0 otherwise
 */
int BP_RANGE_PROOF_prove(BP_RANGE_PROOF_CTX *ctx, BP_RANGE_PROOF_WITNESS *witness,
                         BP_RANGE_PROOF *proof)
{
    int i, j, k, m, n, poly_len;
    int ret = 0, *aL = NULL, *aR = NULL;
    size_t plen;
    BP_TRANSCRIPT *transcript;
    BIGNUM *alpha, *rho, *tau1, *tau2, *bn0, *bn1, *bn2, *bn_1, *tmp;
    BIGNUM *x, *y, *y_inv, *pow_y_inv, *z, *z2, *pow_zn, **pow_y = NULL;
    BIGNUM *pow_2, *dv, *t, *t1, *t2, *pv, *r0, *r1, **sL = NULL, **sR = NULL;
    BIGNUM **ll = NULL, **rr = NULL, **ll0 = NULL, **rr1 = NULL, **rr2 = NULL;
    BIGNUM **vec_G_factors = NULL, **vec_H_factors = NULL;
    EC_POINT *P = NULL, *T = NULL, *U = NULL;
    bp_poly_ps_t *poly_a = NULL, *poly_s = NULL, *poly_p = NULL;
    const BIGNUM *order;
    EC_GROUP *group;
    BN_CTX *bn_ctx = NULL;
    BULLET_PROOF_PUB_PARAM *pp;
    bp_inner_product_ctx_t *ip_ctx = NULL;
    bp_inner_product_pub_param_t *ip_pp = NULL;
    bp_inner_product_witness_t *ip_witness = NULL;

    if (ctx == NULL || witness == NULL || proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    if (witness->n > ctx->pp->max_agg_num) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_EXCEEDS_MAX_AGG_NUM);
        return ret;
    }

    if (proof->V != NULL || proof->ip_proof != NULL)
        bp_range_proof_cleanup(proof);

    pp = ctx->pp;
    transcript = ctx->transcript;
    group = ctx->group;
    order = EC_GROUP_get0_order(group);
    n = pp->bits * witness->n;
    poly_len = n * 2  + 1;

    if (!(P = EC_POINT_new(group))
        || !(T = EC_POINT_new(group))
        || !(U = EC_POINT_new(group)))
        goto end;

    if (!(proof->V = OPENSSL_zalloc(witness->n * sizeof(*proof->V)))
        || !(aL = OPENSSL_zalloc(sizeof(*aL) * n))
        || !(aR = OPENSSL_zalloc(sizeof(*aL) * n))
        || !(sL = OPENSSL_zalloc(sizeof(*sL) * n))
        || !(sR = OPENSSL_zalloc(sizeof(*sR) * n))
        || !(vec_G_factors = OPENSSL_zalloc(sizeof(*vec_G_factors) * n))
        || !(vec_H_factors = OPENSSL_zalloc(sizeof(*vec_H_factors) * n))
        || !(pow_y = OPENSSL_zalloc(sizeof(*pow_y) * n))
        || !(ll0 = OPENSSL_zalloc(sizeof(*ll0) * n))
        || !(rr1 = OPENSSL_zalloc(sizeof(*rr1) * n))
        || !(rr2 = OPENSSL_zalloc(sizeof(*rr2) * n))
        || !(ll = OPENSSL_zalloc(sizeof(*ll) * n))
        || !(rr = OPENSSL_zalloc(sizeof(*rr) * n))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (!(poly_a = bp_poly_ps_new(poly_len))
        || !(poly_s = bp_poly_ps_new(poly_len))
        || !(poly_p = bp_poly_ps_new(poly_len)))
        goto end;

    bn_ctx = BN_CTX_new_ex(group->libctx);
    if (bn_ctx == NULL)
        goto end;

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
        goto end;

    BN_zero(t1);
    BN_zero(t2);
    BN_zero(bn0);
    BN_one(bn1);
    BN_one(bn_1);
    BN_set_negative(bn_1, 1);
    BN_set_word(bn2, 2);
    BN_one(pow_y_inv);

    if (!bp_rand_range(alpha, order)
        || !bp_rand_range(rho, order)
        || !bp_rand_range(tau1, order)
        || !bp_rand_range(tau2, order))
        goto end;

    plen = bp_point2oct(group, ctx->G, NULL, bn_ctx);
    if (plen <= 0)
        goto end;

    proof->n = witness->n;
    /* (69) */
    for (i = 0; i < proof->n; i++) {
        if (!(proof->V[i] = EC_POINT_new(group)))
            goto end;

        if (!EC_POINT_mul(group, proof->V[i], witness->vec_r[i],
                          pp->H, witness->vec_v[i], NULL))
            goto end;
    }

    /* (45) */
    if (!bp_random_bn_gen(group, sL, n, bn_ctx)
        || !bp_random_bn_gen(group, sR, n, bn_ctx))
        goto end;

    for (i = 0, k = 0; i < proof->n; i++) {
        pv = witness->vec_v[i];
        for (j = 0; j < pp->bits; j++, k += 2) {
            if (!BN_div(dv, t, pv, bn2, bn_ctx))
                goto end;

            pv = dv;
            m = i * pp->bits + j;
            aL[m] = BN_is_one(t);
            aR[m] = aL[m] - 1;

            if (!bp_poly_ps_append(poly_a, pp->vec_G[m], aL[m] == 1 ? bn1 : bn0)
                || !bp_poly_ps_append(poly_a, pp->vec_H[m], aR[m] == -1 ? bn_1 : bn0)
                || !bp_poly_ps_append(poly_s, pp->vec_G[m], sL[m])
                || !bp_poly_ps_append(poly_s, pp->vec_H[m], sR[m]))
                goto end;
        }
    }

    if (!bp_poly_ps_append(poly_a, pp->H, alpha)
        || !bp_poly_ps_append(poly_s, pp->H, rho))
        goto end;

    /* (44, 47) */
    if (!bp_poly_ps_eval(poly_a, proof->A, NULL, group, bn_ctx)
        || !bp_poly_ps_eval(poly_s, proof->S, NULL, group, bn_ctx))
        goto end;

    /* compute hash */
    if (!BP_TRANSCRIPT_append_point(transcript, "A", proof->A, group)
        || !BP_TRANSCRIPT_append_point(transcript, "S", proof->S, group))
        goto end;

    if (!BP_TRANSCRIPT_challange(transcript, "y", y)
        || !BP_TRANSCRIPT_challange(transcript, "z", z))
        goto end;

    if (!BN_mod_sqr(z2, z, order, bn_ctx) || !BN_copy(pow_zn, z2)
        || !BN_mod_inverse(y_inv, y, order, bn_ctx))
        goto end;

    pow_y[0] = bn1;
    BN_zero(proof->taux);

    /*
     * ll0 = aL - z * 1^n
     * l1 = sL
     * rr1 = aR + z * 1^n
     * rr2 = z^(n+1) * 2^n
     * r0 = y^n * (aR + z * 1^n) + z^(n+1) * 2^n = y^n * rr1 + rr2
     * r1 = y^n * sR
     * ll = ll0 + sL * x
     * rr = y^n * (aR + z * 1^n + sR * x) + z^(n+1) * 2^n = y^n * (rr1 + sR * x) + rr2
     * t1 = <ll0 * r1 + l1 * r0>
     * t2 = <r1 * r1> = <sL * y^n * sR>
     */
    for (i = 0; i < proof->n; i++) {
        BN_one(pow_2);

        for (j = 0; j < pp->bits; j++) {
            m = i * pp->bits + j;
            if (m > 0) {
                if ((pow_y[m] = BN_CTX_get(bn_ctx)) == NULL)
                    goto end;

                if (!BN_mod_mul(pow_y[m], pow_y[m-1], y, order, bn_ctx))
                    goto end;
            }

            if ((ll0[m] = BN_CTX_get(bn_ctx)) == NULL
                || (rr1[m] = BN_CTX_get(bn_ctx)) == NULL
                || (rr2[m] = BN_CTX_get(bn_ctx)) == NULL)
                goto end;

            if (!BN_mod_sub(ll0[m], aL[m] == 1 ? bn1 : bn0, z, order, bn_ctx)
                || !BN_mod_mul(r1, pow_y[m], sR[m], order, bn_ctx)
                || !BN_mod_mul(t, ll0[m], r1, order, bn_ctx)
                || !BN_mod_add(t1, t1, t, order, bn_ctx)
                || !BN_mod_add(rr1[m], aR[m] == 0 ? bn0 : bn_1, z, order, bn_ctx)
                || !BN_mod_mul(t, pow_y[m], rr1[m], order, bn_ctx))
                goto end;

            if (!BN_mod_mul(rr2[m], pow_zn, pow_2, order, bn_ctx)
                || !BN_mod_add(r0, t, rr2[m], order, bn_ctx)
                || !BN_mod_mul(t, r0, sL[m], order, bn_ctx)
                || !BN_mod_add(t1, t1, t, order, bn_ctx)
                || !BN_mod_mul(t, r1, sL[m], order, bn_ctx)
                || !BN_mod_add(t2, t2, t, order, bn_ctx))
                goto end;

            if (!BN_mod_mul(pow_2, pow_2, bn2, order, bn_ctx))
                goto end;
        }

        if (!BN_mul(t, pow_zn, witness->vec_r[i], bn_ctx)
            || !BN_mod_add(proof->taux, proof->taux, t, order, bn_ctx))
            goto end;

        if (!BN_mod_mul(pow_zn, pow_zn, z, order, bn_ctx))
            goto end;
    }

    /* (53, 54) */
    if (!EC_POINT_mul(group, proof->T1, tau1, pp->H, t1, bn_ctx)
        || !EC_POINT_mul(group, proof->T2, tau2, pp->H, t2, bn_ctx))
        goto end;

    /* (55, 56) */
    if (!BP_TRANSCRIPT_append_point(transcript, "T1", proof->T1, group)
        || !BP_TRANSCRIPT_append_point(transcript, "T2", proof->T2, group))
        goto end;

    if (!BP_TRANSCRIPT_challange(transcript, "x", x))
        goto end;

    BN_zero(proof->tx);

    for (i = 0, k = 0; i < proof->n; i++) {
        for (j = 0; j < pp->bits; j++, k += 2) {
            m = i * pp->bits + j;
            tmp = BN_CTX_get(bn_ctx);
            ll[m] = BN_CTX_get(bn_ctx);
            rr[m] = BN_CTX_get(bn_ctx);
            vec_G_factors[m] = BN_CTX_get(bn_ctx);
            vec_H_factors[m] = BN_CTX_get(bn_ctx);
            if (vec_H_factors[m] == NULL)
                goto end;

            BN_one(vec_G_factors[m]);

            /* (58, 59, 60) */
            if (!BN_mod_mul(t, sL[m], x, order, bn_ctx)
                || !BN_mod_add(ll[m], ll0[m], t, order, bn_ctx)
                || !BN_mod_mul(t, sR[m], x, order, bn_ctx)
                || !BN_mod_add(rr1[m], rr1[m], t, order, bn_ctx)
                || !BN_mod_mul(dv, pow_y[m], rr1[m], order, bn_ctx)
                || !BN_mod_add(rr[m], dv, rr2[m], order, bn_ctx)
                || !BN_mod_mul(t, ll[m], rr[m], order, bn_ctx)
                || !BN_mod_add(proof->tx, proof->tx, t, order, bn_ctx))
                goto end;

            if (!BN_copy(vec_H_factors[m], pow_y_inv))
                goto end;

            if (!BN_copy(tmp, rr[m]) || !BN_mod_mul(tmp, tmp, pow_y_inv, order, bn_ctx))
                goto end;

            if (!BN_mod_mul(pow_y_inv, pow_y_inv, y_inv, order, bn_ctx))
                goto end;

            if (!bp_poly_ps_append(poly_p, pp->vec_G[m], ll[m])
                || !bp_poly_ps_append(poly_p, pp->vec_H[m], tmp))
                goto end;
        }
    }

    /* (61) */
    if (!BN_mod_sqr(t, x, order, bn_ctx)
        || !BN_mod_mul(t, t, tau2, order, bn_ctx)
        || !BN_mod_add(proof->taux, proof->taux, t, order, bn_ctx)
        || !BN_mod_mul(t, x, tau1, order, bn_ctx)
        || !BN_mod_add(proof->taux, proof->taux, t, order, bn_ctx))
        goto end;

    /* (62) */
    if (!BN_mul(proof->mu, rho, x, bn_ctx)
        || !BN_mod_add(proof->mu, proof->mu, alpha, order, bn_ctx))
        goto end;

    /* (67) */
    if (!EC_POINT_mul(group, U, NULL, pp->U, x, bn_ctx)
        || !bp_poly_ps_append(poly_p, U, proof->tx)
        || !bp_poly_ps_eval(poly_p, P, NULL, group, bn_ctx))
        goto end;

    if (!(ip_pp = bp_inner_product_pub_param_new(pp->curve_id))
        || !bp_inner_product_pub_param_set(ip_pp, pp->vec_G, pp->vec_H, n)
        || !(ip_ctx = bp_inner_product_ctx_new(ip_pp, transcript, U, P,
                                               vec_G_factors, vec_H_factors, n))
        || !(ip_witness = bp_inner_product_witness_new(ll, rr, n))
        || !(proof->ip_proof = bp_inner_product_proof_new(ip_ctx)))
        goto end;

    ret = bp_inner_product_proof_prove(ip_ctx, ip_witness, proof->ip_proof);

end:
    BP_TRANSCRIPT_reset(transcript);

    if (!ret)
        bp_range_proof_cleanup(proof);

    bp_inner_product_witness_free(ip_witness);
    bp_inner_product_pub_param_free(ip_pp);
    bp_inner_product_ctx_free(ip_ctx);

    bp_poly_ps_free(poly_a);
    bp_poly_ps_free(poly_s);
    bp_poly_ps_free(poly_p);

    OPENSSL_free(vec_G_factors);
    OPENSSL_free(vec_H_factors);

    OPENSSL_free(ll);
    OPENSSL_free(rr);
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

/** Verifies that the supplied proof is a valid proof
 *  for the supplied secret values using the supplied public parameters.
 *  \param  ctx       BP_RANGE_PROOF_CTX object
 *  \param  proof     BP_RANGE_PROOF object
 *  \return 1 if the proof is valid, 0 if the proof is invalid and -1 on error
 */
int BP_RANGE_PROOF_verify(BP_RANGE_PROOF_CTX *ctx, BP_RANGE_PROOF *proof)
{
    int ret = 0, i = 0, j, m, n, poly_p_len, poly_r_len;
    BP_TRANSCRIPT *transcript;
    BIGNUM *bn1, *bn2, *x, *x2, *y, *y_inv, *z, *z2, *nz, *t, *tmp, *z_pow_y, *delta;
    BIGNUM *pow_y, *pow_y_inv, *pow_z, *pow_2, *sum_pow_y, *sum_pow_z, *sum_pow_2;
    BIGNUM **vec_G_factors = NULL, **vec_H_factors = NULL;
    EC_POINT *P = NULL, *U = NULL, *L = NULL, *R = NULL;
    BN_CTX *bn_ctx = NULL;
    bp_poly_ps_t *poly_p = NULL, *poly_r = NULL;
    EC_GROUP *group;
    const BIGNUM *order;
    bp_inner_product_ctx_t *ip_ctx = NULL;
    bp_inner_product_pub_param_t *ip_pp = NULL;
    BULLET_PROOF_PUB_PARAM *pp;

    if (ctx == NULL || ctx->pp == NULL || proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    transcript = ctx->transcript;
    pp = ctx->pp;
    n = pp->bits * proof->n;
    poly_p_len = n * 2 + 4;
    poly_r_len = n + 3;
    group = ctx->group;
    order = EC_GROUP_get0_order(group);

    if (pp->curve_id != EC_POINT_get_curve_name(proof->A)) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return ret;
    }

    if (!(vec_G_factors = OPENSSL_zalloc(sizeof(*vec_G_factors) * n))
        || !(vec_H_factors = OPENSSL_zalloc(sizeof(*vec_H_factors) * n))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (!(poly_p = bp_poly_ps_new(poly_p_len)) || !(poly_r = bp_poly_ps_new(poly_r_len)))
        goto end;

    if (!(P = EC_POINT_new(group))
        || !(U = EC_POINT_new(group))
        || !(L = EC_POINT_new(group))
        || !(R = EC_POINT_new(group)))
        goto end;

    bn_ctx = BN_CTX_new_ex(group->libctx);
    if (bn_ctx == NULL)
        goto end;

    BN_CTX_start(bn_ctx);
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
        goto end;

    BN_zero(sum_pow_y);
    BN_zero(sum_pow_z);
    BN_zero(sum_pow_2);
    BN_one(pow_y);
    BN_one(pow_y_inv);
    BN_one(bn1);
    BN_set_word(bn2, 2);

    if (!BP_TRANSCRIPT_append_point(transcript, "A", proof->A, group)
        || !BP_TRANSCRIPT_append_point(transcript, "S", proof->S, group))
        goto end;

    if (!BP_TRANSCRIPT_challange(transcript, "y", y)
        || !BP_TRANSCRIPT_challange(transcript, "z", z))
        goto end;

    if (!BP_TRANSCRIPT_append_point(transcript, "T1", proof->T1, group)
        || !BP_TRANSCRIPT_append_point(transcript, "T2", proof->T2, group))
        goto end;

    if (!BP_TRANSCRIPT_challange(transcript, "x", x))
        goto end;

    if (!BN_mod_inverse(y_inv, y, order, bn_ctx)
        || !BN_mod_sqr(x2, x, order, bn_ctx)
        || !BN_mod_sqr(z2, z, order, bn_ctx)
        || !BN_sub(nz, order, z)
        || !BN_copy(pow_z, z))
        goto end;

    for (i = 0; i < proof->n; i++) {
        BN_one(pow_2);

        if (!BN_mod_mul(pow_z, pow_z, z, order, bn_ctx)
            || !BN_mod_add(sum_pow_z, sum_pow_z, pow_z, order, bn_ctx))
            goto end;

        for (j = 0; j < pp->bits; j++) {
            m = i * pp->bits + j;
            if (i == 0) {
                if (!BN_mod_add(sum_pow_2, sum_pow_2, pow_2, order, bn_ctx))
                    goto end;
            }

            tmp = BN_CTX_get(bn_ctx);
            vec_G_factors[m] = BN_CTX_get(bn_ctx);
            vec_H_factors[m] = BN_CTX_get(bn_ctx);
            if (vec_H_factors[m] == NULL)
                goto end;

            BN_one(vec_G_factors[m]);

            if (!BN_copy(vec_H_factors[m], pow_y_inv))
                goto end;

            if (!BN_mod_add(sum_pow_y, sum_pow_y, pow_y, order, bn_ctx)
                || !BN_mod_mul(z_pow_y, z, pow_y, order, bn_ctx)
                || !BN_mod_mul(t, pow_z, pow_2, order, bn_ctx)
                || !BN_mod_add(t, t, z_pow_y, order, bn_ctx))
                goto end;

            if (!BN_copy(tmp, t) || !BN_mod_mul(tmp, tmp, pow_y_inv, order, bn_ctx))
                goto end;

            if (!bp_poly_ps_append(poly_p, pp->vec_G[m], nz)
                || !bp_poly_ps_append(poly_p, pp->vec_H[m], tmp))
                goto end;

            if (!BN_mod_mul(pow_y, pow_y, y, order, bn_ctx)
                || !BN_mod_mul(pow_y_inv, pow_y_inv, y_inv, order, bn_ctx)
                || !BN_mod_mul(pow_2, pow_2, bn2, order, bn_ctx))
                goto end;
        }

        tmp = BN_CTX_get(bn_ctx);
        if (tmp == NULL || !BN_copy(tmp, pow_z))
            goto end;

        if (!bp_poly_ps_append(poly_r, proof->V[i], tmp))
            goto end;
    }

    if (!BN_mod_mul(sum_pow_z, sum_pow_z, z, order, bn_ctx))
        goto end;

    /* (39) also see page 21 */
    if (!BN_mod_sub(delta, z, z2, order, bn_ctx)
        || !BN_mod_mul(delta, delta, sum_pow_y, order, bn_ctx)
        || !BN_mod_mul(t, sum_pow_z, sum_pow_2, order, bn_ctx)
        || !BN_mod_sub(delta, delta, t, order, bn_ctx))
        goto end;

    /* (72) */
    if (!bp_poly_ps_append(poly_r, pp->H, delta)
        || !bp_poly_ps_append(poly_r, proof->T1, x)
        || !bp_poly_ps_append(poly_r, proof->T2, x2)
        || !bp_poly_ps_eval(poly_r, R, NULL, group, bn_ctx))
        goto end;

    /* (65) */
    if (!EC_POINT_mul(group, L, proof->taux, pp->H, proof->tx, bn_ctx)
        || !EC_POINT_invert(group, L, bn_ctx)
        || !EC_POINT_add(group, R, R, L, bn_ctx)
        || !EC_POINT_is_at_infinity(group, R))
        goto end;

    if (!EC_POINT_mul(group, U, NULL, pp->U, x, bn_ctx))
        goto end;

    tmp = BN_CTX_get(bn_ctx);
    if (tmp == NULL)
        goto end;

    if (!BN_copy(tmp, proof->mu))
        goto end;

    BN_set_negative(tmp, !BN_is_negative(tmp));

    if (!bp_poly_ps_append(poly_p, proof->S, x)
        || !bp_poly_ps_append(poly_p, proof->A, bn1)
        || !bp_poly_ps_append(poly_p, pp->H, tmp)
        || !bp_poly_ps_append(poly_p, U, proof->tx)
        || !bp_poly_ps_eval(poly_p, P, NULL, group, bn_ctx))
        goto end;

    if (!(ip_pp = bp_inner_product_pub_param_new(pp->curve_id))
        || !bp_inner_product_pub_param_set(ip_pp, pp->vec_G, pp->vec_H, n)
        || !(ip_ctx = bp_inner_product_ctx_new(ip_pp, transcript, U, P,
                                               vec_G_factors, vec_H_factors, n)))
        goto end;

    ret = bp_inner_product_proof_verify(ip_ctx, proof->ip_proof);

end:
    BP_TRANSCRIPT_reset(transcript);

    bp_inner_product_ctx_free(ip_ctx);
    bp_inner_product_pub_param_free(ip_pp);

    bp_poly_ps_free(poly_p);
    bp_poly_ps_free(poly_r);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    EC_POINT_free(L);
    EC_POINT_free(R);
    EC_POINT_free(U);
    EC_POINT_free(P);

    OPENSSL_free(vec_G_factors);
    OPENSSL_free(vec_H_factors);
    return ret;
}
