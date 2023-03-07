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
#include "bullet_proof.h"
#include "util.h"

static void bullet_proof_cleanup(BULLET_PROOF *proof);

BULLET_PROOF *bullet_proof_alloc(const EC_GROUP *group)
{
    BULLET_PROOF *proof = NULL;

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
    BULLET_PROOF_free(proof);
    return NULL;
}

/** Creates a new BULLET_PROOF_PUB_PARAM object
 *  \param  curve_id    the elliptic curve id
 *  \param  bits        the range bits that support verification
 *  \param  max_agg_num the number of the aggregate range proofs
 *  \return newly created BULLET_PROOF_PUB_PARAM object or NULL in case of an error
 */
BULLET_PROOF_PUB_PARAM *BULLET_PROOF_PUB_PARAM_new(int curve_id, size_t bits,
                                                   size_t max_agg_num)
{
    size_t plen, n;
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

    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return pp;

err:
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
                                                                 size_t bits,
                                                                 size_t max_agg_num)
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
    OPENSSL_clear_free((void *)pp, sizeof(BULLET_PROOF_CTX));
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

/** Creates a new BULLET_PROOF_CTX object
 *  \return newly created BULLET_PROOF_CTX object or NULL in case of an error
 */
BULLET_PROOF_CTX *BULLET_PROOF_CTX_new(BULLET_PROOF_PUB_PARAM *pp, const char *st)
{
    BULLET_PROOF_CTX *ctx = NULL;

    if (pp == NULL) {
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

    ctx->group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, pp->curve_id);
    if (ctx->group == NULL)
        goto err;

    ctx->G = EC_GROUP_get0_generator(ctx->group);

    if (st != NULL) {
        if (!(ctx->st = OPENSSL_strdup(st))) {
            ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        ctx->st_len = strlen(st);
    }

    return ctx;

err:
    BULLET_PROOF_CTX_free(ctx);
    return NULL;
}

/** Frees a BULLET_PROOF_CTX object
 *  \param  ctx       BULLET_PROOF_CTX object to be freed
 */
void BULLET_PROOF_CTX_free(BULLET_PROOF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx->st);

    BULLET_PROOF_PUB_PARAM_free(ctx->pp);
    EC_GROUP_free(ctx->group);
    OPENSSL_clear_free((void *)ctx, sizeof(BULLET_PROOF_CTX));
}

/** Creates a new BULLET_PROOF_WITNESS object
 *  \param  ctx       BULLET_PROOF_CTX object
 *  \param  secrets   An array of secrets used to generate the witness
 *  \param  len       the length of secrets
 *  \return newly created BULLET_PROOF_WITNESS object or NULL in case of an error
 */
BULLET_PROOF_WITNESS *BULLET_PROOF_WITNESS_new(BULLET_PROOF_CTX *ctx,
                                               int64_t secrets[], size_t agg_num)
{
    size_t i, padding_len = 0;
    const BIGNUM *order;
    BULLET_PROOF_WITNESS *witness = NULL;

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
    BULLET_PROOF_WITNESS_free(witness);
    return NULL;
}

/** Frees a BULLET_PROOF_WITNESS object
 *  \param  witness   BULLET_PROOF_WITNESS object to be freed
 */
void BULLET_PROOF_WITNESS_free(BULLET_PROOF_WITNESS *witness)
{
    size_t i;

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

/** Creates a new BULLET_PROOF object
 *  \param  ctx       BULLET_PROOF_CTX object
 *  \return newly created BULLET_PROOF_CTX object or NULL in case of an error
 */
BULLET_PROOF *BULLET_PROOF_new(BULLET_PROOF_CTX *ctx)
{
    if (ctx == NULL || ctx->pp == NULL || ctx->group == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    return bullet_proof_alloc(ctx->group);
}

/** Frees a BULLET_PROOF object
 *  \param  proof     BULLET_PROOF object to be freed
 */
void BULLET_PROOF_free(BULLET_PROOF *proof)
{
    int ref;
    size_t i;

    if (proof == NULL)
        return;

    CRYPTO_DOWN_REF(&proof->references, &ref, proof->lock);
    REF_PRINT_COUNT("BULLET_PROOF", proof);
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

static void bullet_proof_cleanup(BULLET_PROOF *proof)
{
    size_t i;

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

/** Increases the internal reference count of a BULLET_PROOF object.
 *  \param  proof  BULLET_PROOF object
 *  \return 1 on success and 0 if an error occurred.
 */
int BULLET_PROOF_up_ref(BULLET_PROOF *proof)
{
    int ref;

    if (CRYPTO_UP_REF(&proof->references, &ref, proof->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("BULLET_PROOF", proof);
    REF_ASSERT_ISNT(ref < 2);
    return ((ref > 1) ? 1 : 0);
}

/** Decreases the internal reference count of a BULLET_PROOF object.
 *  \param  proof  BULLET_PROOF object
 *  \return 1 on success and 0 if an error occurred.
 */
int BULLET_PROOF_down_ref(BULLET_PROOF *proof)
{
    int ref;

    if (CRYPTO_DOWN_REF(&proof->references, &ref, proof->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("BULLET_PROOF", proof);
    REF_ASSERT_ISNT(ref > 0);
    return ((ref > 0) ? 1 : 0);
}

/** Prove computes the ZK rangeproof.
 *  \param  ctx       BULLET_PROOF_CTX object
 *  \param  witness   BULLET_PROOF_WITNESS object
 *  \param  proof     BULLET_PROOF object
 *  \return 1 on success and 0 otherwise
 */
int BULLET_PROOF_prove(BULLET_PROOF_CTX *ctx, BULLET_PROOF_WITNESS *witness,
                       BULLET_PROOF *proof)
{
    size_t i, j, k, m, n, plen, vec_p_len;
    int ret = 0, *aL = NULL, *aR = NULL;
    unsigned char *pstr, *transcript = NULL;
    BIGNUM *alpha, *rho, *tau1, *tau2, *bn0, *bn1, *bn2, *bn_1;
    BIGNUM *x, *y, *y_inv, *pow_y_inv, *z, *z2, *pow_zn, **pow_y = NULL;
    BIGNUM *pow_2, *dv, *t, *t1, *t2, *pv, *r0, *r1, **sL = NULL, **sR = NULL;
    BIGNUM **ll = NULL, **rr = NULL, **ll0 = NULL, **rr1 = NULL, **rr2 = NULL;
    BIGNUM **vec_p = NULL, **vec_s = NULL;
    EC_POINT *P = NULL, *T = NULL, *U = NULL, **vec_H = NULL, **vec_P = NULL;
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
        bullet_proof_cleanup(proof);

    pp = ctx->pp;
    group = ctx->group;
    order = EC_GROUP_get0_order(group);
    n = pp->bits * witness->n;
    vec_p_len = n * 2  + 1;

    if (!(P = EC_POINT_new(group))
        || !(T = EC_POINT_new(group))
        || !(U = EC_POINT_new(group)))
        goto end;

    if (!(proof->V = OPENSSL_zalloc(witness->n * sizeof(*proof->V)))
        || !(aL = OPENSSL_zalloc(sizeof(*aL) * n))
        || !(aR = OPENSSL_zalloc(sizeof(*aL) * n))
        || !(sL = OPENSSL_zalloc(sizeof(*sL) * n))
        || !(sR = OPENSSL_zalloc(sizeof(*sR) * n))
        || !(vec_H = OPENSSL_zalloc(sizeof(*vec_H) * n))
        || !(vec_P = OPENSSL_zalloc(sizeof(*vec_P) * vec_p_len))
        || !(vec_p = OPENSSL_zalloc(sizeof(*vec_p) * vec_p_len))
        || !(vec_s = OPENSSL_zalloc(sizeof(*vec_s) * vec_p_len))
        || !(pow_y = OPENSSL_zalloc(sizeof(*pow_y) * n))
        || !(ll0 = OPENSSL_zalloc(sizeof(*ll0) * n))
        || !(rr1 = OPENSSL_zalloc(sizeof(*rr1) * n))
        || !(rr2 = OPENSSL_zalloc(sizeof(*rr2) * n))
        || !(ll = OPENSSL_zalloc(sizeof(*ll) * n))
        || !(rr = OPENSSL_zalloc(sizeof(*rr) * n))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

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

    pstr = transcript = OPENSSL_zalloc(4 * plen + ctx->st_len);
    if (pstr == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (ctx->st) {
        memcpy(pstr, ctx->st, ctx->st_len);
        pstr += ctx->st_len;
    }

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

            if (!(vec_P[k] = EC_POINT_dup(pp->vec_G[m], group))
                || !(vec_p[k] = BN_dup(aL[m] == 1 ? bn1 : bn0))
                || !(vec_P[k+1] = EC_POINT_dup(pp->vec_H[m], group))
                || !(vec_p[k+1] = BN_dup(aR[m] == -1 ? bn_1 : bn0))
                || !(vec_s[k] = BN_dup(sL[m]))
                || !(vec_s[k+1] = BN_dup(sR[m])))
                goto end;
        }
    }

    if (!(vec_P[k] = EC_POINT_dup(pp->H, group))
        || !(vec_p[k] = BN_dup(alpha))
        || !(vec_s[k] = BN_dup(rho)))
        goto end;

    k++;

    /* (44, 47) */
    if (!EC_POINTs_mul(group, proof->A, NULL, k, (const EC_POINT **)vec_P,
                       (const BIGNUM **)vec_p, bn_ctx)
        || !EC_POINTs_mul(group, proof->S, NULL, k, (const EC_POINT **)vec_P,
                          (const BIGNUM **)vec_s, bn_ctx))
        goto end;

    if (bp_point2oct(group, proof->A, pstr, bn_ctx) <= 0)
        goto end;

    pstr += plen;

    if (!bp_bin_hash2bn(transcript, pstr - transcript, y))
        goto end;

    if (bp_point2oct(group, proof->S, pstr, bn_ctx) <= 0)
        goto end;

    pstr += plen;

    if (!bp_bin_hash2bn(transcript, pstr - transcript, z))
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
    if (bp_point2oct(group, proof->T1, pstr, bn_ctx) <= 0)
        goto end;

    pstr += plen;

    if (bp_point2oct(group, proof->T2, pstr, bn_ctx) <= 0)
        goto end;

    pstr += plen;

    if (!bp_bin_hash2bn(transcript, pstr - transcript, x))
        goto end;

    BN_zero(proof->tx);

    for (i = 0, k = 0; i < proof->n; i++) {
        for (j = 0; j < pp->bits; j++, k += 2) {
            m = i * pp->bits + j;
            if ((ll[m] = BN_CTX_get(bn_ctx)) == NULL
                || (rr[m] = BN_CTX_get(bn_ctx)) == NULL)
                goto end;

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

            /* (64) */
            if (!(vec_H[m] = EC_POINT_new(group))
                || !EC_POINT_mul(group, vec_H[m], NULL, pp->vec_H[m], pow_y_inv, bn_ctx)
                || !BN_mod_mul(pow_y_inv, pow_y_inv, y_inv, order, bn_ctx))
                goto end;

            if (!EC_POINT_copy(vec_P[k], pp->vec_G[m])
                || !BN_copy(vec_p[k], ll[m])
                || !EC_POINT_copy(vec_P[k+1], vec_H[m])
                || !BN_copy(vec_p[k+1], rr[m]))
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
        || !EC_POINT_copy(vec_P[k], U)
        || !BN_copy(vec_p[k], proof->tx)
        || !EC_POINTs_mul(group, P, NULL, ++k, (const EC_POINT **)vec_P,
                       (const BIGNUM **)vec_p, bn_ctx))
        goto end;

    if (!(ip_pp = bp_inner_product_pub_param_new(pp->curve_id))
        || !bp_inner_product_pub_param_set(ip_pp, pp->vec_G, vec_H, n, U)
        || !(ip_ctx = bp_inner_product_ctx_new(ip_pp, P, (char *)transcript,
                                               pstr - transcript))
        || !(ip_witness = bp_inner_product_witness_new(ll, rr, n))
        || !(proof->ip_proof = bp_inner_product_proof_new(ip_ctx)))
        goto end;

    ret = bp_inner_product_proof_prove(ip_ctx, ip_witness, proof->ip_proof);

end:
    if (!ret)
        bullet_proof_cleanup(proof);

    bp_inner_product_witness_free(ip_witness);
    bp_inner_product_pub_param_free(ip_pp);
    bp_inner_product_ctx_free(ip_ctx);

    for (i = 0; i < n; i++) {
        EC_POINT_free(vec_H[i]);
    }
    for (i = 0; i < vec_p_len; i++) {
        EC_POINT_free(vec_P[i]);
        BN_free(vec_p[i]);
        BN_free(vec_s[i]);
    }
    OPENSSL_free(vec_H);
    OPENSSL_free(vec_P);
    OPENSSL_free(vec_p);
    OPENSSL_free(vec_s);

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
    OPENSSL_free(transcript);
    return ret;
}

/** Verifies that the supplied proof is a valid proof
 *  for the supplied secret values using the supplied public parameters.
 *  \param  ctx       BULLET_PROOF_CTX object
 *  \param  proof     BULLET_PROOF object
 *  \return 1 if the proof is valid, 0 if the proof is invalid and -1 on error
 */
int BULLET_PROOF_verify(BULLET_PROOF_CTX *ctx, BULLET_PROOF *proof)
{
    int ret = 0;
    size_t i = 0, j, m, n, k, plen, vec_h_len, vec_p_len, vec_r_len;
    unsigned char *pstr, *transcript = NULL;
    BIGNUM *bn1, *bn2, *x, *x2, *y, *y_inv, *z, *z2, *nz, *t, *z_pow_y, *delta;
    BIGNUM *pow_y, *pow_y_inv, *pow_z, *pow_2, *sum_pow_y, *sum_pow_z, *sum_pow_2;
    BIGNUM **vec_p = NULL, **vec_r = NULL;
    EC_POINT *P = NULL, *U = NULL, *L = NULL, *R = NULL;
    EC_POINT **vec_P = NULL, **vec_R = NULL, **vec_H = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group;
    const BIGNUM *order;
    bp_inner_product_ctx_t *ip_ctx = NULL;
    bp_inner_product_pub_param_t *ip_pp = NULL;
    BULLET_PROOF_PUB_PARAM *pp;

    if (ctx == NULL || ctx->pp == NULL || proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    pp = ctx->pp;
    n = pp->bits * proof->n;
    vec_h_len = n;
    vec_p_len = n * 2 + 4;
    vec_r_len = n + 3;
    group = ctx->group;
    order = EC_GROUP_get0_order(group);

    if (pp->curve_id != EC_POINT_get_curve_name(proof->A)) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return ret;
    }

    if (!(vec_H = OPENSSL_zalloc(sizeof(*vec_H) * vec_h_len))
        || !(vec_P = OPENSSL_zalloc(sizeof(*vec_P) * vec_p_len))
        || !(vec_R = OPENSSL_zalloc(sizeof(*vec_R) * vec_r_len))
        || !(vec_p = OPENSSL_zalloc(sizeof(*vec_p) * vec_p_len))
        || !(vec_r = OPENSSL_zalloc(sizeof(*vec_r) * vec_r_len))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

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

    plen = bp_point2oct(group, ctx->G, NULL, bn_ctx);
    if (plen <= 0)
        goto end;

    pstr = transcript = OPENSSL_zalloc(4 * plen + ctx->st_len);
    if (pstr == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (ctx->st) {
        memcpy(pstr, ctx->st, ctx->st_len);
        pstr += ctx->st_len;
    }

    if (bp_point2oct(group, proof->A, pstr, bn_ctx) <= 0)
        goto end;

    pstr += plen;

    if (!bp_bin_hash2bn(transcript, pstr - transcript, y)
        || !BN_mod_inverse(y_inv, y, order, bn_ctx))
        goto end;

    if (bp_point2oct(group, proof->S, pstr, bn_ctx) <= 0)
        goto end;

    pstr += plen;

    if (!bp_bin_hash2bn(transcript, pstr - transcript, z))
        goto end;

    if (bp_point2oct(group, proof->T1, pstr, bn_ctx) <= 0)
        goto end;

    pstr += plen;

    if (bp_point2oct(group, proof->T2, pstr, bn_ctx) <= 0)
        goto end;

    pstr += plen;

    if (!bp_bin_hash2bn(transcript, pstr - transcript, x))
        goto end;

    if (!BN_mod_sqr(x2, x, order, bn_ctx)
        || !BN_mod_sqr(z2, z, order, bn_ctx)
        || !BN_sub(nz, order, z)
        || !BN_copy(pow_z, z))
        goto end;

    for (i = 0, k = 0; i < proof->n; i++) {
        BN_one(pow_2);

        if (!BN_mod_mul(pow_z, pow_z, z, order, bn_ctx)
            || !BN_mod_add(sum_pow_z, sum_pow_z, pow_z, order, bn_ctx))
            goto end;

        for (j = 0; j < pp->bits; j++, k += 2) {
            m = i * pp->bits + j;
            if (i == 0) {
                if (!BN_mod_add(sum_pow_2, sum_pow_2, pow_2, order, bn_ctx))
                    goto end;
            }

            if (!BN_mod_add(sum_pow_y, sum_pow_y, pow_y, order, bn_ctx)
                || !BN_mod_mul(z_pow_y, z, pow_y, order, bn_ctx)
                || !BN_mod_mul(t, pow_z, pow_2, order, bn_ctx)
                || !BN_mod_add(t, t, z_pow_y, order, bn_ctx))
                goto end;

            if (!(vec_H[m] = EC_POINT_new(group))
                || !EC_POINT_mul(group, vec_H[m], NULL, pp->vec_H[m],
                                 pow_y_inv, bn_ctx))
                goto end;

            if (!(vec_P[k] = EC_POINT_dup(pp->vec_G[m], group))
                || !(vec_p[k] = BN_dup(nz))
                || !(vec_P[k + 1] = EC_POINT_dup(vec_H[m], group))
                || !(vec_p[k + 1] = BN_dup(t)))
                goto end;

            if (!BN_mod_mul(pow_y, pow_y, y, order, bn_ctx)
                || !BN_mod_mul(pow_y_inv, pow_y_inv, y_inv, order, bn_ctx)
                || !BN_mod_mul(pow_2, pow_2, bn2, order, bn_ctx))
                goto end;
        }

        if (!(vec_R[i] = EC_POINT_dup(proof->V[i], group))
            || !(vec_r[i] = BN_dup(pow_z)))
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
    if (!(vec_R[i] = EC_POINT_dup(pp->H, group))
        || !(vec_r[i] = BN_dup(delta))
        || !(vec_R[i + 1] = EC_POINT_dup(proof->T1, group))
        || !(vec_r[i + 1] = BN_dup(x))
        || !(vec_R[i + 2] = EC_POINT_dup(proof->T2, group))
        || !(vec_r[i + 2] = BN_dup(x2)))
        goto end;

    i += 3;

    if (!EC_POINTs_mul(group, R, NULL, i, (const EC_POINT **)vec_R,
                       (const BIGNUM **)vec_r, bn_ctx))
        goto end;

    /* (65) */
    if (!EC_POINT_mul(group, L, proof->taux, pp->H, proof->tx, bn_ctx)
        || !EC_POINT_invert(group, L, bn_ctx)
        || !EC_POINT_add(group, R, R, L, bn_ctx)
        || !EC_POINT_is_at_infinity(group, R))
        goto end;

    if (!EC_POINT_mul(group, U, NULL, pp->U, x, bn_ctx))
        goto end;

    if (!(vec_P[k] = EC_POINT_dup(proof->S, group))
        || !(vec_p[k] = BN_dup(x))
        || !(vec_P[k + 1] = EC_POINT_dup(proof->A, group))
        || !(vec_p[k + 1] = BN_dup(bn1))
        || !(vec_P[k + 2] = EC_POINT_dup(pp->H, group))
        || !(vec_p[k + 2] = BN_dup(proof->mu))
        || !(vec_P[k + 3] = EC_POINT_dup(U, group))
        || !(vec_p[k + 3] = BN_dup(proof->tx)))
        goto end;

    BN_set_negative(vec_p[k + 2], !BN_is_negative(vec_p[k + 2]));

    k += 4;

    if (!EC_POINTs_mul(group, P, NULL, k, (const EC_POINT **)vec_P,
                       (const BIGNUM **)vec_p, bn_ctx))
        goto end;

    if (!(ip_pp = bp_inner_product_pub_param_new(pp->curve_id))
        || !bp_inner_product_pub_param_set(ip_pp, pp->vec_G, vec_H, vec_h_len, U)
        || !(ip_ctx = bp_inner_product_ctx_new(ip_pp, P, (char *)transcript,
                                               pstr - transcript)))
        goto end;

    ret = bp_inner_product_proof_verify(ip_ctx, proof->ip_proof);

end:
    bp_inner_product_ctx_free(ip_ctx);
    bp_inner_product_pub_param_free(ip_pp);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    EC_POINT_free(L);
    EC_POINT_free(R);
    EC_POINT_free(U);
    EC_POINT_free(P);

    for (i = 0; i < vec_h_len; i++) {
        EC_POINT_free(vec_H[i]);
    }
    for (i = 0; i < vec_p_len; i++) {
        EC_POINT_free(vec_P[i]);
        BN_free(vec_p[i]);
    }
    for (i = 0; i < vec_r_len; i++) {
        EC_POINT_free(vec_R[i]);
        BN_free(vec_r[i]);
    }

    OPENSSL_free(vec_H);
    OPENSSL_free(vec_P);
    OPENSSL_free(vec_R);
    OPENSSL_free(vec_p);
    OPENSSL_free(vec_r);
    OPENSSL_free(transcript);
    return ret;
}
