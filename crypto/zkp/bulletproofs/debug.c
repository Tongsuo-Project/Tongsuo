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

void BN_debug_print(BIO *b, const BIGNUM *n, const char *name)
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

void EC_POINT_debug_print(BIO *b, const EC_POINT *p, const char *name)
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

void EC_POINT_debug_print_affine(BIO *b, const EC_GROUP *group, const EC_POINT *p,
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

void BP_PUB_PARAM_debug_print(BP_PUB_PARAM *pp, const char *note)
{
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
    BIO_printf(bio, "pp->gens_capacity: %zu\n", pp->gens_capacity);
    BIO_printf(bio, "pp->party_capacity: %zu\n", pp->party_capacity);
    BIO_printf(bio, "pp->curve_id: %zu\n", pp->curve_id);

    bp_stack_of_point_debug_print(bio, pp->sk_G, "pp->sk_G");
    bp_stack_of_point_debug_print(bio, pp->sk_H, "pp->sk_H");

err:
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    BIO_free(bio);
}

void BP_RANGE_WITNESS_debug_print(BP_RANGE_WITNESS *witness, const char *note)
{
    BIO *bio = NULL;
    BN_CTX *bn_ctx = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    BIO_printf(bio, "%s: \n", note);
    BIO_printf(bio, "witness->n: %d\n", sk_EC_POINT_num(witness->sk_V));

    bp_stack_of_bignum_debug_print(bio, witness->sk_r, "witness->sk_r");
    bp_stack_of_bignum_debug_print(bio, witness->sk_v, "witness->sk_v");
    bp_stack_of_point_debug_print(bio, witness->sk_V, "witness->sk_V");

err:
    BN_CTX_free(bn_ctx);
    BIO_free(bio);
}

void BP_RANGE_PROOF_debug_print(BP_RANGE_PROOF *proof, const EC_GROUP *group, const char *note)
{
    BIO *bio = NULL;
    BN_CTX *bn_ctx = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    BIO_printf(bio, "%s: \n", note);

    EC_POINT_debug_print_affine(bio, group, proof->A, "proof->A", bn_ctx);
    EC_POINT_debug_print_affine(bio, group, proof->S, "proof->S", bn_ctx);
    EC_POINT_debug_print_affine(bio, group, proof->T1, "proof->T1", bn_ctx);
    EC_POINT_debug_print_affine(bio, group, proof->T2, "proof->T2", bn_ctx);
    BN_debug_print(bio, proof->taux, "proof->taux");
    BN_debug_print(bio, proof->mu, "proof->mu");
    BN_debug_print(bio, proof->tx, "proof->tx");
    bp_inner_product_proof_debug_print(proof->ip_proof, group, "ip_proof");

err:
    BN_CTX_free(bn_ctx);
    BIO_free(bio);
}

void bp_inner_product_pub_param_debug_print(bp_inner_product_pub_param_t *pp,
                                            const char *note)
{
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
    BIO_printf(bio, "ip_pp->n: %zu\n", sk_EC_POINT_num(pp->sk_G));

    bp_stack_of_point_debug_print(bio, pp->sk_G, "ip_pp->sk_G");
    bp_stack_of_point_debug_print(bio, pp->sk_H, "ip_pp->sk_H");

err:
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    BIO_free(bio);
}

void bp_inner_product_witness_debug_print(bp_inner_product_witness_t *witness,
                                          const char *note)
{
    BIO *bio = NULL;
    BN_CTX *bn_ctx = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    BIO_printf(bio, "%s: \n", note);
    BIO_printf(bio, "ip_witness->n: %zu\n", sk_BIGNUM_num(witness->sk_a));

    bp_stack_of_bignum_debug_print(bio, witness->sk_a, "ip_witness->sk_a");
    bp_stack_of_bignum_debug_print(bio, witness->sk_b, "ip_witness->sk_b");

err:
    BN_CTX_free(bn_ctx);
    BIO_free(bio);
}

void bp_inner_product_proof_debug_print(bp_inner_product_proof_t *proof,
                                        const EC_GROUP *group, const char *note)
{
    BIO *bio = NULL;
    BN_CTX *bn_ctx = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    BIO_printf(bio, "%s: \n", note);
    BIO_printf(bio, "ip_proof->n: %zu\n", sk_EC_POINT_num(proof->sk_L));

    bp_stack_of_point_debug_print(bio, proof->sk_L, "ip_proof->sk_L");
    bp_stack_of_point_debug_print(bio, proof->sk_R, "ip_proof->sk_R");

    BN_debug_print(bio, proof->a, "ip_proof->a");
    BN_debug_print(bio, proof->b, "ip_proof->b");

err:
    BN_CTX_free(bn_ctx);
    BIO_free(bio);
}

void bp_bn_vector_debug_print(BIO *bio, BIGNUM **bv, int n, const char *note)
{
    int i;

    if (bv == NULL)
        return;

    for (i = 0; i < n; i++) {
        BN_debug_print(bio, bv[i], note);
    }
}

void bp_point_vector_debug_print(BIO *bio, const EC_GROUP *group,
                                 EC_POINT **pv, int n,
                                 const char *note, BN_CTX *bn_ctx)
{
    int i;

    if (group == NULL || pv == NULL)
        return;

    for (i = 0; i < n; i++) {
        EC_POINT_debug_print_affine(bio, group, pv[i], note, bn_ctx);
    }
}

void bp_stack_of_bignum_debug_print(BIO *bio, STACK_OF(BIGNUM) *sk, const char *name)
{
    BIO *b = NULL;
    int i, n;
    BIGNUM *bn;

    if (sk == NULL)
        return;

    if (bio == NULL) {
        b = bio = BIO_new(BIO_s_file());
        BIO_set_fp(b, stderr, BIO_NOCLOSE);
    }

    n = sk_BIGNUM_num(sk);
    for (i = 0; i < n; i++) {
        bn = sk_BIGNUM_value(sk, i);
        if (bn == NULL)
            goto err;

        BIO_printf(bio, "%s[%d]: ", name, i);
        BN_print(bio, bn);
        BIO_printf(bio, "\n");
    }

err:
    BIO_free(b);
}

void bp_stack_of_point_debug_print(BIO *bio, STACK_OF(EC_POINT) *sk, const char *name)
{
    BIO *b = NULL;
    int i, n;
    EC_POINT *p;

    if (sk == NULL)
        return;

    if (bio == NULL) {
        b = bio = BIO_new(BIO_s_file());
        BIO_set_fp(b, stderr, BIO_NOCLOSE);
    }

    n = sk_EC_POINT_num(sk);
    for (i = 0; i < n; i++) {
        p = sk_EC_POINT_value(sk, i);
        if (p == NULL)
            goto err;

        BIO_printf(b, "%s[%d]->X: ", name, i);
        BN_print(b, p->X);
        BIO_printf(b, ", %s[%d]->Y: ", name, i);
        BN_print(b, p->Y);
        BIO_printf(b, ", %s[%d]->Z: ", name, i);
        BN_print(b, p->Z);
        BIO_printf(b, "\n");
    }

err:
    BIO_free(b);
}
