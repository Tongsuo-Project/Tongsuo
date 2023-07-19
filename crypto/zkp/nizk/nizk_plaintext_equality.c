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
#include <crypto/ec/ec_elgamal.h>
#include <crypto/zkp/common/zkp_util.h>
#include "nizk_plaintext_equality.h"

DEFINE_STACK_OF(EC_POINT)

NIZK_PLAINTEXT_EQUALITY_CTX *NIZK_PLAINTEXT_EQUALITY_CTX_new(ZKP_TRANSCRIPT *transcript,
                                                             NIZK_PUB_PARAM *pp,
                                                             NIZK_WITNESS *witness,
                                                             STACK_OF(EC_POINT) *pk,
                                                             EC_ELGAMAL_MR_CIPHERTEXT *ct)
{
    int i;
    EC_POINT *PK, *P = NULL;
    NIZK_PLAINTEXT_EQUALITY_CTX *ctx = NULL;

    if (pp == NULL || transcript == NULL || pk == NULL || ct == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (sk_EC_POINT_num(pk) == 0 ||
        sk_EC_POINT_num(pk) !=  sk_EC_POINT_num(ct->sk_C1)) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->transcript = transcript;

    if (!NIZK_PUB_PARAM_up_ref(pp))
        goto err;

    ctx->pp = pp;

    if (witness != NULL) {
        if (!NIZK_WITNESS_up_ref(witness))
            goto err;

        ctx->witness = witness;
    }

    if (!(ctx->sk_PK = sk_EC_POINT_new_null()))
        goto err;

    for (i = 0; i < sk_EC_POINT_num(pk); i++) {
        PK = sk_EC_POINT_value(pk, i);
        if (!(P = EC_POINT_dup(PK, pp->group)))
            goto err;

        if (sk_EC_POINT_push(ctx->sk_PK, P) <= 0)
            goto err;

        P = NULL;
    }

    if (!(ctx->ct = EC_ELGAMAL_MR_CIPHERTEXT_dup(ct, pp->group)))
        goto err;

    return ctx;
err:
    EC_POINT_free(P);
    NIZK_PLAINTEXT_EQUALITY_CTX_free(ctx);
    return NULL;
}

void NIZK_PLAINTEXT_EQUALITY_CTX_free(NIZK_PLAINTEXT_EQUALITY_CTX *ctx)
{
    if (ctx == NULL)
        return;

    NIZK_PUB_PARAM_down_ref(ctx->pp);
    NIZK_WITNESS_down_ref(ctx->witness);

    sk_EC_POINT_pop_free(ctx->sk_PK, EC_POINT_free);
    EC_ELGAMAL_MR_CIPHERTEXT_free(ctx->ct);

    OPENSSL_clear_free((void *)ctx, sizeof(*ctx));
}

NIZK_PLAINTEXT_EQUALITY_PROOF *NIZK_PLAINTEXT_EQUALITY_PROOF_new(NIZK_PLAINTEXT_EQUALITY_CTX *ctx)
{
    NIZK_PLAINTEXT_EQUALITY_PROOF *proof = NULL;

    proof = OPENSSL_zalloc(sizeof(*proof));
    if (proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if ((proof->sk_A = sk_EC_POINT_new_null()) == NULL
        || (proof->B = EC_POINT_new(ctx->pp->group)) == NULL
        || (proof->z = BN_new()) == NULL
        || (proof->t = BN_new()) == NULL)
        goto err;

    EC_POINT_set_to_infinity(ctx->pp->group, proof->B);

    BN_zero(proof->z);
    BN_zero(proof->t);

    return proof;
err:
    NIZK_PLAINTEXT_EQUALITY_PROOF_free(proof);
    return NULL;
}

void NIZK_PLAINTEXT_EQUALITY_PROOF_free(NIZK_PLAINTEXT_EQUALITY_PROOF *proof)
{
    if (proof == NULL)
        return;

    sk_EC_POINT_pop_free(proof->sk_A, EC_POINT_free);
    EC_POINT_free(proof->B);
    BN_free(proof->z);
    BN_free(proof->t);
    OPENSSL_clear_free((void *)proof, sizeof(*proof));
}

NIZK_PLAINTEXT_EQUALITY_PROOF *NIZK_PLAINTEXT_EQUALITY_PROOF_prove(NIZK_PLAINTEXT_EQUALITY_CTX *ctx)
{
    int i;
    ZKP_TRANSCRIPT *transcript;
    NIZK_PUB_PARAM *pp;
    NIZK_WITNESS *witness;
    NIZK_PLAINTEXT_EQUALITY_PROOF *proof = NULL, *ret = NULL;
    const BIGNUM *order;
    EC_GROUP *group;
    EC_POINT *A = NULL, *P;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *a, *b, *t, *e;
    zkp_poly_points_t *poly = NULL;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (ctx->pp == NULL || ctx->sk_PK == NULL || ctx->ct == NULL ||
        sk_EC_POINT_num(ctx->sk_PK) !=  sk_EC_POINT_num(ctx->ct->sk_C1)) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (!(proof = NIZK_PLAINTEXT_EQUALITY_PROOF_new(ctx)))
        return NULL;

    pp = ctx->pp;
    witness = ctx->witness;
    transcript = ctx->transcript;
    group = pp->group;
    order = EC_GROUP_get0_order(group);

    bn_ctx = BN_CTX_new_ex(group->libctx);
    if (bn_ctx == NULL)
        goto err;

    a = BN_CTX_get(bn_ctx);
    b = BN_CTX_get(bn_ctx);
    e = BN_CTX_get(bn_ctx);
    t = BN_CTX_get(bn_ctx);
    if (t == NULL)
        goto err;

    if (!zkp_rand_range(a, order) || !zkp_rand_range(b, order))
        goto err;

    for (i = 0; i < sk_EC_POINT_num(ctx->sk_PK); i++) {
        P = sk_EC_POINT_value(ctx->sk_PK, i);
        if (!ZKP_TRANSCRIPT_append_point(transcript, "PK", P, group))
            goto err;

        A = EC_POINT_new(group);
        if (A == NULL)
            goto err;

        if (!EC_POINT_mul(group, A, NULL, P, a, bn_ctx))
            goto err;

        if (sk_EC_POINT_push(proof->sk_A, A) <= 0)
            goto err;

        A = NULL;

        P = sk_EC_POINT_value(ctx->ct->sk_C1, i);
        if (!ZKP_TRANSCRIPT_append_point(transcript, "C1", P, group))
            goto err;

        P = sk_EC_POINT_value(proof->sk_A, i);
        if (!ZKP_TRANSCRIPT_append_point(transcript, "A", P, group))
            goto err;
    }

    if (!(poly = zkp_poly_points_new(2)))
        goto err;

    if (!zkp_poly_points_append(poly, pp->G, a)
        || !zkp_poly_points_append(poly, pp->H, b))
        goto err;

    if (!zkp_poly_points_mul(poly, proof->B, NULL, group, bn_ctx))
        goto err;

    if (!ZKP_TRANSCRIPT_append_point(transcript, "C2", ctx->ct->C2, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "B", proof->B, group))
        goto err;

    if (!ZKP_TRANSCRIPT_challange(transcript, "e", e))
        goto err;

    if (!BN_mul(t, e, witness->r, bn_ctx)
        || !BN_mod_add(proof->z, a, t, order, bn_ctx)
        || !BN_mul(t, e, witness->v, bn_ctx)
        || !BN_mod_add(proof->t, b, t, order, bn_ctx))
        goto err;

    ret = proof;
    proof = NULL;
err:
    EC_POINT_free(A);
    BN_CTX_free(bn_ctx);
    zkp_poly_points_free(poly);
    NIZK_PLAINTEXT_EQUALITY_PROOF_free(proof);
    ZKP_TRANSCRIPT_reset(transcript);
    return ret;
}

int NIZK_PLAINTEXT_EQUALITY_PROOF_verify(NIZK_PLAINTEXT_EQUALITY_CTX *ctx,
                                         NIZK_PLAINTEXT_EQUALITY_PROOF *proof)
{
    int ret = 0, i;
    ZKP_TRANSCRIPT *transcript;
    NIZK_PUB_PARAM *pp;
    EC_GROUP *group;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *e, *bn1;
    EC_POINT *A, *P, *L = NULL, *R = NULL;
    zkp_poly_points_t *poly = NULL;

    if (ctx == NULL || proof == NULL) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (ctx->pp == NULL || ctx->sk_PK == NULL || ctx->ct == NULL ||
        sk_EC_POINT_num(ctx->sk_PK) !=  sk_EC_POINT_num(ctx->ct->sk_C1)) {
        ERR_raise(ERR_LIB_ZKP_NIZK, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    pp = ctx->pp;
    transcript = ctx->transcript;
    group = pp->group;

    if (!(L = EC_POINT_new(group)) || !(R = EC_POINT_new(group)))
        goto err;

    bn_ctx = BN_CTX_new_ex(group->libctx);
    if (bn_ctx == NULL)
        goto err;

    e = BN_CTX_get(bn_ctx);
    bn1 = BN_CTX_get(bn_ctx);
    if (bn1 == NULL)
        goto err;

    BN_one(bn1);

    for (i = 0; i < sk_EC_POINT_num(ctx->sk_PK); i++) {
        P = sk_EC_POINT_value(ctx->sk_PK, i);
        if (!ZKP_TRANSCRIPT_append_point(transcript, "PK", P, group))
            goto err;

        P = sk_EC_POINT_value(ctx->ct->sk_C1, i);
        if (!ZKP_TRANSCRIPT_append_point(transcript, "C1", P, group))
            goto err;

        P = sk_EC_POINT_value(proof->sk_A, i);
        if (!ZKP_TRANSCRIPT_append_point(transcript, "A", P, group))
            goto err;
    }

    if (!ZKP_TRANSCRIPT_append_point(transcript, "C2", ctx->ct->C2, group)
        || !ZKP_TRANSCRIPT_append_point(transcript, "B", proof->B, group))
        goto err;

    if (!ZKP_TRANSCRIPT_challange(transcript, "e", e))
        goto err;

    if (!(poly = zkp_poly_points_new(2)))
        goto err;

    for (i = 0; i < sk_EC_POINT_num(ctx->sk_PK); i++) {
        P = sk_EC_POINT_value(ctx->sk_PK, i);
        if (!EC_POINT_mul(group, L, NULL, P, proof->z, bn_ctx))
            goto err;

        A = sk_EC_POINT_value(proof->sk_A, i);
        P = sk_EC_POINT_value(ctx->ct->sk_C1, i);

        if (!zkp_poly_points_append(poly, A, bn1)
            || !zkp_poly_points_append(poly, P, e))
            goto err;

        if (!zkp_poly_points_mul(poly, R, NULL, group, bn_ctx))
            goto err;

        if (EC_POINT_cmp(group, L, R, bn_ctx) != 0)
            goto err;

        zkp_poly_points_reset(poly);
    }

    if (!zkp_poly_points_append(poly, pp->G, proof->z)
        || !zkp_poly_points_append(poly, pp->H, proof->t))
        goto err;

    if (!zkp_poly_points_mul(poly, L, NULL, group, bn_ctx))
        goto err;

    zkp_poly_points_reset(poly);

    if (!zkp_poly_points_append(poly, proof->B, bn1)
        || !zkp_poly_points_append(poly, ctx->ct->C2, e))
        goto err;

    if (!zkp_poly_points_mul(poly, R, NULL, group, bn_ctx))
        goto err;

    if (EC_POINT_cmp(group, L, R, bn_ctx) != 0)
        goto err;

    ret = 1;
err:
    EC_POINT_free(L);
    EC_POINT_free(R);
    zkp_poly_points_free(poly);
    ZKP_TRANSCRIPT_reset(transcript);
    return ret;
}
