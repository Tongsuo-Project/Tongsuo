/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <openssl/ec.h>
#include <crypto/ec/ec_local.h>
#include "debug.h"

int bp_rand_range(BIGNUM *rnd, const BIGNUM *range)
{
    BN_set_word(rnd, 1);
    return 1;
}

void BN_print2(BIO *b, const BIGNUM *n, const char *name)
{
    BIO *bi = NULL;

    if (b == NULL) {
        b = bi = BIO_new(BIO_s_file());
        BIO_set_fp(b, stderr, BIO_NOCLOSE);
    }

    BIO_printf(b, "%s: ", name);
    BN_print(b, n);
    BIO_printf(b, "\n");

    BIO_free(bi);
}

void EC_POINT_print(BIO *b, const EC_POINT *p, const char *name)
{
    BIO *bi = NULL;

    if (b == NULL) {
        b = bi = BIO_new(BIO_s_file());
        BIO_set_fp(b, stderr, BIO_NOCLOSE);
    }

    BIO_printf(b, "%s->X: ", name);
    BN_print(b, p->X);
    BIO_printf(b, ", %s->Y: ", name);
    BN_print(b, p->Y);
    BIO_printf(b, ", %s->Z: ", name);
    BN_print(b, p->Z);
    BIO_printf(b, "\n");

    BIO_free(bi);
}

void EC_POINT_print_affine(BIO *b, const EC_GROUP *group, const EC_POINT *p,
                           const char *name, BN_CTX *ctx)
{
    BIO *bi = NULL;
    BIGNUM *x, *y;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL)
        return;

    if (b == NULL) {
        b = bi = BIO_new(BIO_s_file());
        BIO_set_fp(b, stderr, BIO_NOCLOSE);
    }

    if (ctx == NULL) {
        bn_ctx = ctx = BN_CTX_new();
        if (bn_ctx == NULL)
            goto err;
    }

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (y == NULL)
        goto err;

    EC_POINT_get_affine_coordinates(group, p, x, y, ctx);

    BIO_printf(b, "%s->x: ", name);
    BN_print(b, x);
    BIO_printf(b, ", %s->y: ", name);
    BN_print(b, y);
    BIO_printf(b, "\n");

err:
    BN_CTX_end(ctx);
    BN_CTX_free(bn_ctx);
    BIO_free(bi);
}

void BULLET_PROOF_PUB_PARAM_print(BULLET_PROOF_PUB_PARAM *pp, const char *note)
{
    size_t i, n;
    BIO *bio = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    if (!(group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, pp->curve_id)))
        goto err;

    BIO_printf(bio, "%s: \n", note);
    BIO_printf(bio, "pp->bits: %zu\n", pp->bits);
    BIO_printf(bio, "pp->max_agg_num: %zu\n", pp->max_agg_num);
    BIO_printf(bio, "pp->curve_id: %zu\n", pp->curve_id);

    n = pp->bits * pp->max_agg_num;
    for (i = 0; i < n; i++) {
        EC_POINT_print_affine(bio, group, pp->vec_G[i], "pp->vec_G", bn_ctx);
    }
    for (i = 0; i < n; i++) {
        EC_POINT_print_affine(bio, group, pp->vec_H[i], "pp->vec_H", bn_ctx);
    }
    EC_POINT_print_affine(bio, group, pp->H, "pp->H", bn_ctx);
    EC_POINT_print_affine(bio, group, pp->U, "pp->U", bn_ctx);

err:
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    BIO_free(bio);
}

void BULLET_PROOF_WITNESS_print(BULLET_PROOF_WITNESS *witness, const char *note)
{
    size_t i;
    BIO *bio = NULL;
    BN_CTX *bn_ctx = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    BIO_printf(bio, "%s: \n", note);
    BIO_printf(bio, "witness->n: %zu\n", witness->n);

    for (i = 0; i < witness->n; i++) {
        BN_print2(bio, witness->vec_r[i], "witness->vec_r");
    }
    for (i = 0; i < witness->n; i++) {
        BN_print2(bio, witness->vec_v[i], "witness->vec_v");
    }

err:
    BN_CTX_free(bn_ctx);
    BIO_free(bio);
}

void BULLET_PROOF_print(BULLET_PROOF *proof, const EC_GROUP *group, const char *note)
{
    size_t i;
    BIO *bio = NULL;
    BN_CTX *bn_ctx = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    BIO_printf(bio, "%s: \n", note);
    BIO_printf(bio, "proof->n: %zu\n", proof->n);

    for (i = 0; i < proof->n; i++) {
        EC_POINT_print_affine(bio, group, proof->V[i], "proof->V", bn_ctx);
    }
    EC_POINT_print_affine(bio, group, proof->A, "proof->A", bn_ctx);
    EC_POINT_print_affine(bio, group, proof->S, "proof->S", bn_ctx);
    EC_POINT_print_affine(bio, group, proof->T1, "proof->T1", bn_ctx);
    EC_POINT_print_affine(bio, group, proof->T2, "proof->T2", bn_ctx);
    BN_print2(bio, proof->taux, "proof->taux");
    BN_print2(bio, proof->mu, "proof->mu");
    BN_print2(bio, proof->tx, "proof->tx");
    bp_inner_product_proof_print(proof->ip_proof, group, "ip_proof");

err:
    BN_CTX_free(bn_ctx);
    BIO_free(bio);
}

void bp_inner_product_pub_param_print(bp_inner_product_pub_param_t *pp,
                                      const char *note)
{
    size_t i;
    BIO *bio = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    if (!(group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, pp->curve_id)))
        goto err;

    BIO_printf(bio, "%s: \n", note);
    BIO_printf(bio, "ip_pp->curve_id: %zu\n", pp->curve_id);
    BIO_printf(bio, "ip_pp->initial: %zu\n", pp->initial);
    BIO_printf(bio, "ip_pp->n: %zu\n", pp->n);

    for (i = 0; i < pp->n; i++) {
        EC_POINT_print_affine(bio, group, pp->vec_G[i], "ip_pp->vec_G", bn_ctx);
    }
    for (i = 0; i < pp->n; i++) {
        EC_POINT_print_affine(bio, group, pp->vec_H[i], "ip_pp->vec_H", bn_ctx);
    }
    EC_POINT_print_affine(bio, group, pp->U, "ip_pp->U", bn_ctx);

err:
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    BIO_free(bio);
}

void bp_inner_product_witness_print(bp_inner_product_witness_t *witness,
                                    const char *note)
{
    size_t i;
    BIO *bio = NULL;
    BN_CTX *bn_ctx = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    BIO_printf(bio, "%s: \n", note);
    BIO_printf(bio, "ip_witness->n: %zu\n", witness->n);

    for (i = 0; i < witness->n; i++) {
        BN_print2(bio, witness->vec_a[i], "ip_witness->vec_a");
    }
    for (i = 0; i < witness->n; i++) {
        BN_print2(bio, witness->vec_b[i], "ip_witness->vec_b");
    }

err:
    BN_CTX_free(bn_ctx);
    BIO_free(bio);
}

void bp_inner_product_proof_print(bp_inner_product_proof_t *proof,
                                  const EC_GROUP *group, const char *note)
{
    size_t i;
    BIO *bio = NULL;
    BN_CTX *bn_ctx = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    BIO_printf(bio, "%s: \n", note);
    BIO_printf(bio, "ip_proof->n: %zu\n", proof->n);

    for (i = 0; i < proof->n; i++) {
        EC_POINT_print_affine(bio, group, proof->vec_L[i], "ip_proof->vec_L", bn_ctx);
    }
    for (i = 0; i < proof->n; i++) {
        EC_POINT_print_affine(bio, group, proof->vec_R[i], "ip_proof->vec_R", bn_ctx);
    }
    BN_print2(bio, proof->a, "ip_proof->a");
    BN_print2(bio, proof->b, "ip_proof->b");

err:
    BN_CTX_free(bn_ctx);
    BIO_free(bio);
}

void bp_bn_vector_print(BIO *bio, BIGNUM **bv, size_t n, const char *note)
{
    size_t i;

    if (bv == NULL)
        return;

    for (i = 0; i < n; i++) {
        BN_print2(bio, bv[i], note);
    }
}

void bp_point_vector_print(BIO *bio, const EC_GROUP *group,
                           EC_POINT **pv, size_t n,
                           const char *note, BN_CTX *bn_ctx)
{
    size_t i;

    if (group == NULL || pv == NULL)
        return;

    for (i = 0; i < n; i++) {
        EC_POINT_print_affine(bio, group, pv[i], note, bn_ctx);
    }
}
