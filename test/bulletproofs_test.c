/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "internal/deprecated.h"
#include "testutil.h"
#include <openssl/conf.h>
#include <openssl/opensslconf.h>
#include <openssl/bulletproofs.h>
#include "crypto/zkp/bulletproofs/r1cs.h"
#include "crypto/zkp/bulletproofs/util.h"

typedef struct bp_r1cs_example_linaer_combinations_st {
    BP_R1CS_LINEAR_COMBINATION *a1;
    BP_R1CS_LINEAR_COMBINATION *a2;
    BP_R1CS_LINEAR_COMBINATION *b1;
    BP_R1CS_LINEAR_COMBINATION *b2;
    BP_R1CS_LINEAR_COMBINATION *c1;
    BP_R1CS_LINEAR_COMBINATION *c2;
} bp_r1cs_example_linaer_combinations;

static int bp_poly3_eval_test(void)
{
    int ret = 0, n = 2, i;
    bp_poly3_t *p = NULL;
    BIGNUM *order, *x, *r[2], *eval;
    BN_CTX *bn_ctx = NULL;
    STACK_OF(BIGNUM) *sk_eval = NULL;

    if (!(sk_eval = sk_BIGNUM_new_reserve(NULL, n)))
        goto err;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    BN_CTX_start(bn_ctx);

    r[0] = BN_CTX_get(bn_ctx);
    r[1] = BN_CTX_get(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    order = BN_CTX_get(bn_ctx);
    if (order == NULL)
        goto err;

    BN_set_word(r[0], 1672);
    BN_set_word(r[1], 2257);
    BN_set_word(x, 8);
    BN_set_word(order, 100000000);

    p = bp_poly3_new(n, order);
    if (p == NULL)
        goto err;

    for (i = 0; i < n; i++) {
        BN_set_word(p->x0[i], i);
        BN_set_word(p->x1[i], i+1);
        BN_set_word(p->x2[i], i+2);
        BN_set_word(p->x3[i], i+3);
    }

    if (!(sk_eval = bp_poly3_eval(p, x)))
        goto err;

    for (i = 0; i < n; i++) {
        eval = sk_BIGNUM_value(sk_eval, i);
        if (!TEST_ptr(eval))
            goto err;

        if (BN_cmp(eval, r[i]) != 0)
            goto err;
    }

    ret = 1;

err:
    bp_poly3_free(p);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    sk_BIGNUM_free(sk_eval);
    return ret;
}

static int bp_poly6_eval_test(void)
{
    int ret = 0;
    bp_poly6_t *p = NULL;
    BIGNUM *order, *x, *r, *e;
    BN_CTX *bn_ctx = NULL;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    BN_CTX_start(bn_ctx);

    r = BN_CTX_get(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    e = BN_CTX_get(bn_ctx);
    order = BN_CTX_get(bn_ctx);
    if (order == NULL)
        goto err;

    BN_set_word(x, 8);
    BN_set_word(e, 0x1ac688);
    BN_set_word(order, 100000000);

    p = bp_poly6_new(order);
    if (p == NULL)
        goto err;

    BN_set_word(p->t1, 1);
    BN_set_word(p->t2, 2);
    BN_set_word(p->t3, 3);
    BN_set_word(p->t4, 4);
    BN_set_word(p->t5, 5);
    BN_set_word(p->t6, 6);

    if (!TEST_true(bp_poly6_eval(p, x, r)))
        goto err;

    if (BN_cmp(r, e) != 0)
        goto err;

    ret = 1;

err:
    bp_poly6_free(p);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int bp_poly3_special_inner_product_test(void)
{
    int ret = 0, n = 2, i;
    bp_poly3_t *p1 = NULL, *p2 = NULL;
    bp_poly6_t *p = NULL;
    BIGNUM *order, *x, *e, *r;
    BN_CTX *bn_ctx = NULL;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    BN_CTX_start(bn_ctx);

    x = BN_CTX_get(bn_ctx);
    e = BN_CTX_get(bn_ctx);
    r = BN_CTX_get(bn_ctx);
    order = BN_CTX_get(bn_ctx);
    if (order == NULL)
        goto err;

    BN_set_word(x, 8);
    BN_set_word(e, 0xeb6270);
    BN_set_word(order, 100000000);

    p = bp_poly6_new(order);
    p1 = bp_poly3_new(n, order);
    p2 = bp_poly3_new(n, order);
    if (p == NULL || p1 == NULL || p2 == NULL)
        goto err;

    for (i = 0; i < n; i++) {
        BN_set_word(p1->x0[i], i);
        BN_set_word(p1->x1[i], i+1);
        BN_set_word(p1->x2[i], i+2);
        BN_set_word(p1->x3[i], i+3);

        BN_set_word(p2->x0[i], i+4);
        BN_set_word(p2->x1[i], i+5);
        BN_set_word(p2->x2[i], i+6);
        BN_set_word(p2->x3[i], i+7);
    }

    if (!TEST_true(bp_poly3_special_inner_product(p, p1, p2)))
        goto err;

    if (!TEST_true(bp_poly6_eval(p, x, r)))
        goto err;

    if (BN_cmp(r, e) != 0)
        goto err;

    ret = 1;

err:
    bp_poly6_free(p);
    bp_poly3_free(p1);
    bp_poly3_free(p2);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

/*
 * Constrains (a1 + a2) * (b1 + b2) = (c1 + c2)
 */
static int r1cs_example_logic1(BP_R1CS_CTX *ctx,
                               bp_r1cs_example_linaer_combinations *lc)
{
    int ret = 0;
    BP_R1CS_LINEAR_COMBINATION *a = NULL, *b = NULL, *c = NULL;

    if (ctx == NULL || lc == NULL) {
        return 0;
    }

    if (!(a = BP_R1CS_LINEAR_COMBINATION_dup(lc->a1))
        || !(b = BP_R1CS_LINEAR_COMBINATION_dup(lc->b1))
        || !(c = BP_R1CS_LINEAR_COMBINATION_dup(lc->c1))) {
        return 0;
    }

    if (!BP_R1CS_LINEAR_COMBINATION_add(a, lc->a2)
        || !BP_R1CS_LINEAR_COMBINATION_add(b, lc->b2)
        || !BP_R1CS_LINEAR_COMBINATION_add(c, lc->c2)
        || !BP_R1CS_LINEAR_COMBINATION_mul(a, b, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_sub(a, c)
        || !BP_R1CS_LINEAR_COMBINATION_constrain(a, ctx)) {
        goto err;
    }

    ret = 1;

err:
    BP_R1CS_LINEAR_COMBINATION_free(a);
    BP_R1CS_LINEAR_COMBINATION_free(b);
    BP_R1CS_LINEAR_COMBINATION_free(c);

    return ret;
}

/*
 * Constrains a1*a2 + b1*b2 = c1*c2
 */
static int r1cs_example_logic2(BP_R1CS_CTX *ctx,
                               bp_r1cs_example_linaer_combinations *lc)
{
    int ret = 0;
    BP_R1CS_LINEAR_COMBINATION *a = NULL, *b = NULL, *c = NULL;

    if (ctx == NULL || lc == NULL) {
        return 0;
    }

    if (!(a = BP_R1CS_LINEAR_COMBINATION_dup(lc->a1))
        || !(b = BP_R1CS_LINEAR_COMBINATION_dup(lc->b1))
        || !(c = BP_R1CS_LINEAR_COMBINATION_dup(lc->c1))) {
        return 0;
    }

    if (!BP_R1CS_LINEAR_COMBINATION_mul(a, lc->a2, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_mul(b, lc->b2, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_add(a, b)
        || !BP_R1CS_LINEAR_COMBINATION_mul(c, lc->c2, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_sub(a, c)
        || !BP_R1CS_LINEAR_COMBINATION_constrain(a, ctx)) {
        goto err;
    }

    ret = 1;

err:
    BP_R1CS_LINEAR_COMBINATION_free(a);
    BP_R1CS_LINEAR_COMBINATION_free(b);
    BP_R1CS_LINEAR_COMBINATION_free(c);

    return ret;
}

/*
 * Constrains a1*a2 + b1*b2 = c1+c2
 */
static int r1cs_example_logic3(BP_R1CS_CTX *ctx,
                               bp_r1cs_example_linaer_combinations *lc)
{
    int ret = 0;
    BP_R1CS_LINEAR_COMBINATION *a = NULL, *b = NULL, *c = NULL;

    if (ctx == NULL || lc == NULL) {
        return 0;
    }

    if (!(a = BP_R1CS_LINEAR_COMBINATION_dup(lc->a1))
        || !(b = BP_R1CS_LINEAR_COMBINATION_dup(lc->b1))
        || !(c = BP_R1CS_LINEAR_COMBINATION_dup(lc->c1))) {
        return 0;
    }

    if (!BP_R1CS_LINEAR_COMBINATION_mul(a, lc->a2, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_mul(b, lc->b2, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_add(a, b)
        || !BP_R1CS_LINEAR_COMBINATION_add(c, lc->c2)
        || !BP_R1CS_LINEAR_COMBINATION_sub(a, c)
        || !BP_R1CS_LINEAR_COMBINATION_constrain(a, ctx)) {
        goto err;
    }

    ret = 1;

err:
    BP_R1CS_LINEAR_COMBINATION_free(a);
    BP_R1CS_LINEAR_COMBINATION_free(b);
    BP_R1CS_LINEAR_COMBINATION_free(c);

    return ret;
}

/*
 * Constrains a1*a2 + b1*b2 = c1*c2*7
 */
static int r1cs_example_logic4(BP_R1CS_CTX *ctx,
                               bp_r1cs_example_linaer_combinations *lc)
{
    int ret = 0;
    BIGNUM *bn7 = NULL;
    BP_R1CS_LINEAR_COMBINATION *a = NULL, *b = NULL, *c = NULL;

    if (ctx == NULL || lc == NULL) {
        return 0;
    }

    if (!(bn7 = BN_new()))
        goto err;

    BN_set_word(bn7, 7);

    if (!(a = BP_R1CS_LINEAR_COMBINATION_dup(lc->a1))
        || !(b = BP_R1CS_LINEAR_COMBINATION_dup(lc->b1))
        || !(c = BP_R1CS_LINEAR_COMBINATION_dup(lc->c1))) {
        return 0;
    }

    if (!BP_R1CS_LINEAR_COMBINATION_mul(a, lc->a2, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_mul(b, lc->b2, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_add(a, b)
        || !BP_R1CS_LINEAR_COMBINATION_mul(c, lc->c2, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_mul_bn(c, bn7)
        || !BP_R1CS_LINEAR_COMBINATION_sub(a, c)
        || !BP_R1CS_LINEAR_COMBINATION_constrain(a, ctx)) {
        goto err;
    }

    ret = 1;

err:
    BP_R1CS_LINEAR_COMBINATION_free(a);
    BP_R1CS_LINEAR_COMBINATION_free(b);
    BP_R1CS_LINEAR_COMBINATION_free(c);
    BN_free(bn7);

    return ret;
}

/*
 * Constrains a1*a2 + b1*b2 = c1*c2 + 7
 */
static int r1cs_example_logic5(BP_R1CS_CTX *ctx,
                               bp_r1cs_example_linaer_combinations *lc)
{
    int ret = 0;
    BIGNUM *bn7 = NULL;
    BP_R1CS_LINEAR_COMBINATION *a = NULL, *b = NULL, *c = NULL;

    if (ctx == NULL || lc == NULL) {
        return 0;
    }

    if (!(bn7 = BN_new()))
        goto err;

    BN_set_word(bn7, 7);

    if (!(a = BP_R1CS_LINEAR_COMBINATION_dup(lc->a1))
        || !(b = BP_R1CS_LINEAR_COMBINATION_dup(lc->b1))
        || !(c = BP_R1CS_LINEAR_COMBINATION_dup(lc->c1))) {
        return 0;
    }

    if (!BP_R1CS_LINEAR_COMBINATION_mul(a, lc->a2, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_mul(b, lc->b2, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_add(a, b)
        || !BP_R1CS_LINEAR_COMBINATION_mul(c, lc->c2, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_add_bn(c, bn7)
        || !BP_R1CS_LINEAR_COMBINATION_sub(a, c)
        || !BP_R1CS_LINEAR_COMBINATION_constrain(a, ctx)) {
        goto err;
    }

    ret = 1;

err:
    BP_R1CS_LINEAR_COMBINATION_free(a);
    BP_R1CS_LINEAR_COMBINATION_free(b);
    BP_R1CS_LINEAR_COMBINATION_free(c);
    BN_free(bn7);

    return ret;
}

/*
 * Constrains a1 + b1 = c1
 */
static int r1cs_example_logic6(BP_R1CS_CTX *ctx,
                               bp_r1cs_example_linaer_combinations *lc)
{
    int ret = 0;
    BP_R1CS_LINEAR_COMBINATION *a = NULL;

    if (ctx == NULL || lc == NULL) {
        return 0;
    }

    if (!(a = BP_R1CS_LINEAR_COMBINATION_dup(lc->a1))) {
        return 0;
    }

    if (!BP_R1CS_LINEAR_COMBINATION_add(a, lc->b1)
        || !BP_R1CS_LINEAR_COMBINATION_sub(a, lc->c1)
        || !BP_R1CS_LINEAR_COMBINATION_constrain(a, ctx)) {
        goto err;
    }

    ret = 1;

err:
    BP_R1CS_LINEAR_COMBINATION_free(a);

    return ret;
}

/*
 * Constrains a1*a2 = 10
 */
static int r1cs_example_logic7(BP_R1CS_CTX *ctx,
                               bp_r1cs_example_linaer_combinations *lc)
{
    int ret = 0;
    BIGNUM *bn10 = NULL;
    BP_R1CS_LINEAR_COMBINATION *a = NULL;

    if (ctx == NULL || lc == NULL) {
        return 0;
    }

    if (!(bn10 = BN_new()))
        goto err;

    BN_set_word(bn10, 10);

    if (!(a = BP_R1CS_LINEAR_COMBINATION_dup(lc->a1))) {
        return 0;
    }

    if (!BP_R1CS_LINEAR_COMBINATION_mul(a, lc->a2, ctx)
        || !BP_R1CS_LINEAR_COMBINATION_sub_bn(a, bn10)
        || !BP_R1CS_LINEAR_COMBINATION_constrain(a, ctx)) {
        goto err;
    }

    ret = 1;

err:
    BP_R1CS_LINEAR_COMBINATION_free(a);
    BN_free(bn10);

    return ret;
}

/*
 * Constrains a1 + b1 + c1 = 0
 */
static int r1cs_example_logic8(BP_R1CS_CTX *ctx,
                               bp_r1cs_example_linaer_combinations *lc)
{
    int ret = 0;
    BP_R1CS_LINEAR_COMBINATION *a = NULL;

    if (ctx == NULL || lc == NULL) {
        return 0;
    }

    if (!(a = BP_R1CS_LINEAR_COMBINATION_dup(lc->a1))) {
        return 0;
    }

    if (!BP_R1CS_LINEAR_COMBINATION_add(a, lc->b1)
        || !BP_R1CS_LINEAR_COMBINATION_add(a, lc->c1)
        || !BP_R1CS_LINEAR_COMBINATION_constrain(a, ctx)) {
        goto err;
    }

    ret = 1;

err:
    BP_R1CS_LINEAR_COMBINATION_free(a);

    return ret;
}

static void bp_r1cs_example_linaer_combinations_free(bp_r1cs_example_linaer_combinations *lc)
{
    if (lc == NULL)
        return;

    BP_R1CS_LINEAR_COMBINATION_free(lc->a1);
    BP_R1CS_LINEAR_COMBINATION_free(lc->a2);
    BP_R1CS_LINEAR_COMBINATION_free(lc->b1);
    BP_R1CS_LINEAR_COMBINATION_free(lc->b2);
    BP_R1CS_LINEAR_COMBINATION_free(lc->c1);
    BP_R1CS_LINEAR_COMBINATION_free(lc->c2);

    OPENSSL_free(lc);
}

static BP_R1CS_PROOF *r1cs_example_prove(BP_R1CS_CTX *ctx, BP_WITNESS *witness,
                                         BIGNUM *a1, BIGNUM *a2,
                                         BIGNUM *b1, BIGNUM *b2,
                                         BIGNUM *c1, BIGNUM *c2,
                                         bp_r1cs_example_linaer_combinations **plc,
                                         int (*logic)(BP_R1CS_CTX *, bp_r1cs_example_linaer_combinations *))
{
    BP_R1CS_LINEAR_COMBINATION *lc_a1 = NULL, *lc_a2 = NULL;
    BP_R1CS_LINEAR_COMBINATION *lc_b1 = NULL, *lc_b2 = NULL;
    BP_R1CS_LINEAR_COMBINATION *lc_c1 = NULL, *lc_c2 = NULL;
    bp_r1cs_example_linaer_combinations *lc;
    BP_R1CS_PROOF *proof = NULL;

    if (ctx == NULL || plc == NULL || logic == NULL)
        return NULL;

    if (!(lc = OPENSSL_zalloc(sizeof(*lc))))
        return NULL;

    if (!(lc_a1 = BP_WITNESS_r1cs_linear_combination_commit(witness, "a1", a1))
        || !(lc_a2 = BP_WITNESS_r1cs_linear_combination_commit(witness, "a2", a2))
        || !(lc_b1 = BP_WITNESS_r1cs_linear_combination_commit(witness, "b1", b1))
        || !(lc_b2 = BP_WITNESS_r1cs_linear_combination_commit(witness, "b2", b2))
        || !(lc_c1 = BP_WITNESS_r1cs_linear_combination_commit(witness, "c1", c1))
        || !(lc_c2 = BP_WITNESS_r1cs_linear_combination_commit(witness, "c2", c2)))
        goto err;

    lc->a1 = lc_a1;
    lc->a2 = lc_a2;
    lc->b1 = lc_b1;
    lc->b2 = lc_b2;
    lc->c1 = lc_c1;
    lc->c2 = lc_c2;

    if (!logic(ctx, lc))
        goto err;

    if (!(proof = BP_R1CS_PROOF_prove(ctx)))
        goto err;

    *plc = lc;

    return proof;

err:
    BP_R1CS_LINEAR_COMBINATION_free(lc_a1);
    BP_R1CS_LINEAR_COMBINATION_free(lc_a2);
    BP_R1CS_LINEAR_COMBINATION_free(lc_b1);
    BP_R1CS_LINEAR_COMBINATION_free(lc_b2);
    BP_R1CS_LINEAR_COMBINATION_free(lc_c1);
    BP_R1CS_LINEAR_COMBINATION_free(lc_c2);
    BP_R1CS_PROOF_free(proof);
    OPENSSL_free(lc);
    return NULL;
}

static int r1cs_example_verify(BP_R1CS_CTX *ctx, BP_WITNESS *witness,
                               BP_R1CS_PROOF *proof,
                               bp_r1cs_example_linaer_combinations *lc,
                               int (*logic)(BP_R1CS_CTX *, bp_r1cs_example_linaer_combinations *))
{
    BP_R1CS_LINEAR_COMBINATION *lc_a1 = NULL, *lc_a2 = NULL;
    BP_R1CS_LINEAR_COMBINATION *lc_b1 = NULL, *lc_b2 = NULL;
    BP_R1CS_LINEAR_COMBINATION *lc_c1 = NULL, *lc_c2 = NULL;
    bp_r1cs_example_linaer_combinations *l;

    if (ctx == NULL || proof == NULL || lc == NULL || logic == NULL)
        return 0;

    if (!(l = OPENSSL_zalloc(sizeof(*l))))
        return 0;

    if (!(lc_a1 = BP_WITNESS_r1cs_linear_combination_get(witness, "a1"))
        || !(lc_a2 = BP_WITNESS_r1cs_linear_combination_get(witness, "a2"))
        || !(lc_b1 = BP_WITNESS_r1cs_linear_combination_get(witness, "b1"))
        || !(lc_b2 = BP_WITNESS_r1cs_linear_combination_get(witness, "b2"))
        || !(lc_c1 = BP_WITNESS_r1cs_linear_combination_get(witness, "c1"))
        || !(lc_c2 = BP_WITNESS_r1cs_linear_combination_get(witness, "c2")))
        goto err;

    l->a1 = lc_a1;
    l->a2 = lc_a2;
    l->b1 = lc_b1;
    l->b2 = lc_b2;
    l->c1 = lc_c1;
    l->c2 = lc_c2;

    if (!logic(ctx, l))
        goto err;

    if (!BP_R1CS_PROOF_verify(ctx, proof))
        goto err;

    return 1;

err:
    BP_R1CS_LINEAR_COMBINATION_free(lc_a1);
    BP_R1CS_LINEAR_COMBINATION_free(lc_a2);
    BP_R1CS_LINEAR_COMBINATION_free(lc_b1);
    BP_R1CS_LINEAR_COMBINATION_free(lc_b2);
    BP_R1CS_LINEAR_COMBINATION_free(lc_c1);
    BP_R1CS_LINEAR_COMBINATION_free(lc_c2);
    OPENSSL_free(l);
    return 0;
}

static int r1cs_proof_test(BIGNUM *a1, BIGNUM *a2, BIGNUM *b1, BIGNUM *b2, BIGNUM *c1, BIGNUM *c2,
                           int (*logic)(BP_R1CS_CTX *, bp_r1cs_example_linaer_combinations *))
{
    int ret = 0;
    BP_TRANSCRIPT *transcript = NULL;
    BP_PUB_PARAM *pp = NULL;
    BP_WITNESS *witness = NULL;
    BP_R1CS_CTX *ctx = NULL;
    BP_R1CS_PROOF *proof = NULL;
    bp_r1cs_example_linaer_combinations *lc = NULL;

    if (!TEST_ptr(transcript = BP_TRANSCRIPT_new(BP_TRANSCRIPT_METHOD_sha256(), "r1cs_test")))
        goto err;

    if (!TEST_ptr(pp = BP_PUB_PARAM_new_by_curve_id(NID_secp256k1, 128, 1)))
        goto err;

    if (!TEST_ptr(witness = BP_WITNESS_new(pp)))
        goto err;

    if (!TEST_ptr(ctx = BP_R1CS_CTX_new(pp, witness, transcript)))
        goto err;

    if (!TEST_ptr(proof = r1cs_example_prove(ctx, witness, a1, a2, b1, b2, c1, c2, &lc, logic)))
        goto err;

    if (!TEST_true(r1cs_example_verify(ctx, witness, proof, lc, logic)))
        goto err;

    ret = 1;
err:
    bp_r1cs_example_linaer_combinations_free(lc);
    BP_R1CS_PROOF_free(proof);
    BP_R1CS_CTX_free(ctx);
    BP_TRANSCRIPT_free(transcript);
    BP_PUB_PARAM_free(pp);

    return ret;

}

static int r1cs_proof_test1_should_ok(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 5);
    BN_set_word(b1, 6);
    BN_set_word(b2, 1);
    BN_set_word(c1, 40);
    BN_set_word(c2, 9);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic1);
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test1_should_failed(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 5);
    BN_set_word(b1, 6);
    BN_set_word(b2, 1);
    BN_set_word(c1, 40);
    BN_set_word(c2, 10);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic1) == 1 ? 0 : 1;
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test2_should_ok(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 5);
    BN_set_word(b1, 6);
    BN_set_word(b2, 3);
    BN_set_word(c1, 4);
    BN_set_word(c2, 7);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic2);
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test2_should_failed(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 5);
    BN_set_word(b1, 6);
    BN_set_word(b2, 3);
    BN_set_word(c1, 4);
    BN_set_word(c2, 8);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic2) == 1 ? 0 : 1;
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test3_should_ok(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 5);
    BN_set_word(b1, 6);
    BN_set_word(b2, 3);
    BN_set_word(c1, 13);
    BN_set_word(c2, 15);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic3);
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test3_should_failed(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 5);
    BN_set_word(b1, 6);
    BN_set_word(b2, 3);
    BN_set_word(c1, 13);
    BN_set_word(c2, 16);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic3) == 1 ? 0 : 1;
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test4_should_ok(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 5);
    BN_set_word(b1, 6);
    BN_set_word(b2, 3);
    BN_set_word(c1, 2);
    BN_set_word(c2, 2);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic4);
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test4_should_failed(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 5);
    BN_set_word(b1, 6);
    BN_set_word(b2, 3);
    BN_set_word(c1, 2);
    BN_set_word(c2, 3);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic4) == 1 ? 0 : 1;
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test5_should_ok(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 5);
    BN_set_word(b1, 6);
    BN_set_word(b2, 3);
    BN_set_word(c1, 3);
    BN_set_word(c2, 7);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic5);
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test5_should_failed(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 5);
    BN_set_word(b1, 6);
    BN_set_word(b2, 3);
    BN_set_word(c1, 3);
    BN_set_word(c2, 8);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic5) == 1 ? 0 : 1;
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test6_should_ok(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 0);
    BN_set_word(b1, 3);
    BN_set_word(b2, 0);
    BN_set_word(c1, 5);
    BN_set_word(c2, 0);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic6);
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test6_should_failed(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 0);
    BN_set_word(b1, 3);
    BN_set_word(b2, 0);
    BN_set_word(c1, 4);
    BN_set_word(c2, 0);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic6) == 1 ? 0 : 1;
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test7_should_ok(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 5);
    BN_set_word(b1, 0);
    BN_set_word(b2, 0);
    BN_set_word(c1, 0);
    BN_set_word(c2, 0);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic7);
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test7_should_failed(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 2);
    BN_set_word(a2, 6);
    BN_set_word(b1, 0);
    BN_set_word(b2, 0);
    BN_set_word(c1, 0);
    BN_set_word(c2, 0);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic7) == 1 ? 0 : 1;
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test8_should_ok(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 1);
    BN_set_word(a2, 0);
    BN_set_word(b1, 2);
    BN_set_word(b2, 0);
    BN_set_word(c1, 3);
    BN_set_word(c2, 0);
    BN_set_negative(c1, 1);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic8);
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_proof_test8_should_failed(void)
{
    int ret = 0;
    BIGNUM *a1, *a2, *b1, *b2, *c1, *c2;
    BN_CTX *bn_ctx = NULL;

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);

    a1 = BN_CTX_get(bn_ctx);
    a2 = BN_CTX_get(bn_ctx);
    b1 = BN_CTX_get(bn_ctx);
    b2 = BN_CTX_get(bn_ctx);
    c1 = BN_CTX_get(bn_ctx);
    c2 = BN_CTX_get(bn_ctx);
    if (!TEST_ptr(c2))
        goto err;

    BN_set_word(a1, 1);
    BN_set_word(a2, 0);
    BN_set_word(b1, 2);
    BN_set_word(b2, 0);
    BN_set_word(c1, 4);
    BN_set_word(c2, 0);
    BN_set_negative(c1, 1);

    ret = r1cs_proof_test(a1, a2, b1, b2, c1, c2, r1cs_example_logic8) == 1 ? 0 : 1;
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int r1cs_range_logic(BP_R1CS_CTX *ctx, int64_t *value, int32_t bits,
                            BP_R1CS_LINEAR_COMBINATION *v)
{
    int ret = 0, i, m, n;
    BIGNUM *l = NULL, *r = NULL, *bn_1 = NULL, *pow_2 = NULL;
    BP_R1CS_LINEAR_COMBINATION *a = NULL, *b = NULL, *o = NULL;

    if (ctx == NULL || v == NULL) {
        return 0;
    }

    pow_2 = BN_new();
    bn_1 = BN_new();
    l = BN_new();
    r = BN_new();
    if (pow_2 == NULL || bn_1 == NULL || l == NULL || r == NULL)
        goto err;

    BN_one(pow_2);
    BN_one(bn_1);

    for (i = 0; i < bits; i++) {
        if (value != NULL) {
            n = *value >> i & 0x1;
            m = 1 - n;
            BN_set_word(l, m);
            BN_set_word(r, n);

            if (!BP_R1CS_LINEAR_COMBINATION_raw_mul(&o, &a, &b, l, r, ctx))
                goto err;
        } else {
            if (!BP_R1CS_LINEAR_COMBINATION_raw_mul(&o, &a, &b, NULL, NULL, ctx))
                goto err;
        }

        if (!BP_R1CS_LINEAR_COMBINATION_constrain(o, ctx))
            goto err;

        if (!BP_R1CS_LINEAR_COMBINATION_add(a, b)
            || !BP_R1CS_LINEAR_COMBINATION_sub_bn(a, bn_1))
            goto err;

        /* v = v - b * 2^i */
        if (!BP_R1CS_LINEAR_COMBINATION_mul_bn(b, pow_2)
            || !BP_R1CS_LINEAR_COMBINATION_sub(v, b))
            goto err;

        if (!BN_add(pow_2, pow_2, pow_2))
            goto err;

        BP_R1CS_LINEAR_COMBINATION_free(a);
        BP_R1CS_LINEAR_COMBINATION_free(b);
        BP_R1CS_LINEAR_COMBINATION_free(o);
        a = b = o = NULL;
    }

    if (!BP_R1CS_LINEAR_COMBINATION_constrain(v, ctx))
        goto err;

    ret = 1;

err:
    BP_R1CS_LINEAR_COMBINATION_free(a);
    BP_R1CS_LINEAR_COMBINATION_free(b);
    BP_R1CS_LINEAR_COMBINATION_free(o);

    BN_free(l);
    BN_free(r);

    return ret;
}

static BP_R1CS_PROOF *r1cs_range_prove(BP_R1CS_CTX *ctx, BP_WITNESS *witness,
                                       int64_t value, int32_t bits)
{
    BIGNUM *v = NULL;
    BP_R1CS_LINEAR_COMBINATION *lc = NULL;
    BP_R1CS_PROOF *proof = NULL;

    if (ctx == NULL || witness == NULL)
        return NULL;

    v = BN_new();
    if (v == NULL)
        return NULL;

    BN_set_word(v, value);

    if (!(lc = BP_WITNESS_r1cs_linear_combination_commit(witness, "v", v)))
        goto err;

    if (!r1cs_range_logic(ctx, &value, bits, lc))
        goto err;

    if (!(proof = BP_R1CS_PROOF_prove(ctx)))
        goto err;

    return proof;

err:
    BP_R1CS_LINEAR_COMBINATION_free(lc);
    BP_R1CS_PROOF_free(proof);
    return NULL;
}

static int r1cs_range_verify(BP_R1CS_CTX *ctx, BP_WITNESS *witness, BP_R1CS_PROOF *proof,
                             int32_t bits)
{
    BP_R1CS_LINEAR_COMBINATION *lc = NULL;

    if (ctx == NULL || witness == NULL || proof == NULL)
        return 0;

    if (!(lc = BP_WITNESS_r1cs_linear_combination_get(witness, "v")))
        goto err;

    if (!r1cs_range_logic(ctx, NULL, bits, lc))
        goto err;

    if (!BP_R1CS_PROOF_verify(ctx, proof))
        goto err;

    return 1;

err:
    BP_R1CS_LINEAR_COMBINATION_free(lc);
    return 0;
}

static int r1cs_range_test(int32_t bits, int64_t value)
{
    int ret = 0;
    BP_TRANSCRIPT *transcript = NULL;
    BP_PUB_PARAM *pp = NULL;
    BP_WITNESS *witness = NULL;
    BP_R1CS_CTX *ctx = NULL;
    BP_R1CS_PROOF *proof = NULL;

    if (!TEST_ptr(transcript = BP_TRANSCRIPT_new(BP_TRANSCRIPT_METHOD_sha256(), "r1cs_range_test")))
        goto err;

    if (!TEST_ptr(pp = BP_PUB_PARAM_new_by_curve_id(NID_secp256k1, 128, 1)))
        goto err;

    if (!TEST_ptr(witness = BP_WITNESS_new(pp)))
        goto err;

    if (!TEST_ptr(ctx = BP_R1CS_CTX_new(pp, witness, transcript)))
        goto err;

    if (!TEST_ptr(proof = r1cs_range_prove(ctx, witness, value, bits)))
        goto err;

    if (!TEST_true(r1cs_range_verify(ctx, witness, proof, bits)))
        goto err;

    ret = 1;
err:
    BP_R1CS_PROOF_free(proof);
    BP_R1CS_CTX_free(ctx);
    BP_TRANSCRIPT_free(transcript);
    BP_PUB_PARAM_free(pp);

    return ret;

}

static int r1cs_ranges_test(int bits, int64_t secrets[], int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (!r1cs_range_test(bits, secrets[i]))
            return 0;
    }

    return 1;
}

static int r1cs_range_tests(void)
{
    int64_t secrets1[] = {0, 1<<7};
    int64_t secrets2[] = {0, 1<<15, (1<<16)-1};
    int64_t secrets3[] = {0, 1<<15, (1<<16)-1, 1<<16};
    int64_t secrets4[] = {0, 1<<15, (1<<16)-1, 1<<16, (1<<16)+1};
    int64_t secrets5[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    int64_t secrets6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    if (!TEST_true(r1cs_range_test(8, 0))
        || !TEST_true(r1cs_range_test(16, 1<<1))
        || !TEST_true(r1cs_range_test(16, 1<<15))
        || !TEST_true(r1cs_range_test(16, (1<<16)-1))
        || TEST_true(r1cs_range_test(16, 1<<16))
        || TEST_true(r1cs_range_test(16, (1<<16)+1))
        || TEST_true(r1cs_range_test(16, 1<<24))
        || TEST_true(r1cs_range_test(16, 1LL<<31))
        || !TEST_true(r1cs_range_test(32, 0))
        || !TEST_true(r1cs_range_test(32, 1<<1))
        || !TEST_true(r1cs_range_test(32, 1<<16))
        || !TEST_true(r1cs_range_test(32, 1LL<<31))
        || !TEST_true(r1cs_range_test(32, (1LL<<32)-1))
        || TEST_true(r1cs_range_test(32, 1LL<<32))
        || TEST_true(r1cs_range_test(32, (1LL<<32)+1))
        || !TEST_true(r1cs_range_test(64, (1LL<<31) * (1LL<<31)))
        || !TEST_true(r1cs_ranges_test(16, secrets1, sizeof(secrets1)/sizeof(secrets1[0])))
        || !TEST_true(r1cs_ranges_test(16, secrets2, sizeof(secrets2)/sizeof(secrets2[0])))
        || TEST_true(r1cs_ranges_test(16, secrets3, sizeof(secrets3)/sizeof(secrets3[0])))
        || TEST_true(r1cs_ranges_test(16, secrets4, sizeof(secrets4)/sizeof(secrets4[0])))
        || !TEST_true(r1cs_ranges_test(16, secrets5, sizeof(secrets5)/sizeof(secrets5[0])))
        || !TEST_true(r1cs_ranges_test(16, secrets6, sizeof(secrets6)/sizeof(secrets6[0]))))
        return 0;

    return 1;
}

static int range_proofs_test(int bits, int64_t secrets[], int len)
{
    int ret = 0, i;
    BIGNUM *v = NULL;
    BP_PUB_PARAM *pp = NULL;
    BP_WITNESS *witness = NULL;
    BP_TRANSCRIPT *transcript = NULL;
    BP_RANGE_CTX *ctx = NULL;
    BP_RANGE_PROOF *proof = NULL;

    if (!(v = BN_new()))
        goto err;

    if (!TEST_ptr(pp = BP_PUB_PARAM_new_by_curve_id(NID_secp256k1, bits, 8)))
        goto err;

    if (!TEST_ptr(transcript = BP_TRANSCRIPT_new(BP_TRANSCRIPT_METHOD_sha256(), "test")))
        goto err;

    if (!TEST_ptr(witness = BP_WITNESS_new(pp)))
        goto err;

    for (i = 0; i < len; i++) {
        if (!BN_lebin2bn((const unsigned char *)&secrets[i], sizeof(secrets[i]), v))
            goto err;

        if (!TEST_true(BP_WITNESS_commit(witness, NULL, v)))
            goto err;
    }

    if (!TEST_ptr(ctx = BP_RANGE_CTX_new(pp, witness, transcript)))
        goto err;

    if (!TEST_ptr(proof = BP_RANGE_PROOF_new_prove(ctx)))
        goto err;

    if (!TEST_true(BP_RANGE_PROOF_verify(ctx, proof)))
        goto err;

    ret = 1;
err:
    BP_RANGE_PROOF_free(proof);
    BP_RANGE_CTX_free(ctx);
    BP_WITNESS_free(witness);
    BP_PUB_PARAM_free(pp);
    BP_TRANSCRIPT_free(transcript);
    BN_free(v);

    return ret;
}

static int range_proof_test(int bits, int64_t secret)
{
    int64_t secrets[1];

    secrets[0] = secret;

    return range_proofs_test(bits, secrets, 1);
}

static int range_proof_encode_test(int bits, int64_t secret)
{
    int ret = 0;
    size_t size;
    unsigned char *pp_bin = NULL, *proof_bin = NULL;
    BIGNUM *v = NULL;
    BP_PUB_PARAM *pp = NULL, *pp2 = NULL;
    BP_TRANSCRIPT *transcript = NULL, *transcript2 = NULL;
    BP_WITNESS *witness = NULL;
    BP_RANGE_CTX *ctx = NULL, *ctx2 = NULL;
    BP_RANGE_PROOF *proof = NULL, *proof2 = NULL;

    if (!(v = BN_new()))
        goto err;

    if (!TEST_ptr(pp = BP_PUB_PARAM_new_by_curve_id(NID_secp256k1, bits, 8)))
        goto err;

    if (!TEST_ptr(transcript = BP_TRANSCRIPT_new(BP_TRANSCRIPT_METHOD_sha256(), "test"))
        || !TEST_ptr(transcript2 = BP_TRANSCRIPT_dup(transcript)))
        goto err;

    if (!TEST_ptr(witness = BP_WITNESS_new(pp)))
        goto err;

    if (!BN_lebin2bn((const unsigned char *)&secret, sizeof(secret), v))
        goto err;

    if (!TEST_true(BP_WITNESS_commit(witness, NULL, v)))
        goto err;

    if (!TEST_ptr(ctx = BP_RANGE_CTX_new(pp, witness, transcript)))
        goto err;

    if (!TEST_ptr(proof = BP_RANGE_PROOF_new_prove(ctx)))
        goto err;

    if (!TEST_true(BP_RANGE_PROOF_verify(ctx, proof)))
        goto err;

    size = BP_PUB_PARAM_encode(pp, NULL, 0);
    if (size == 0)
        goto err;

    if (!TEST_ptr(pp_bin = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_size_t_eq(BP_PUB_PARAM_encode(pp, pp_bin, size), size))
        goto err;

    if (!TEST_ptr(pp2 = BP_PUB_PARAM_decode(pp_bin, size)))
        goto err;

    if (!TEST_ptr(ctx2 = BP_RANGE_CTX_new(pp2, witness, transcript2)))
        goto err;

    if (!TEST_true(BP_RANGE_PROOF_verify(ctx2, proof)))
        goto err;

    size = BP_RANGE_PROOF_encode(proof, NULL, 0);
    if (size == 0)
        goto err;

    if (!TEST_ptr(proof_bin = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_size_t_eq(BP_RANGE_PROOF_encode(proof, proof_bin, size), size))
        goto err;

    if (!TEST_ptr(proof2 = BP_RANGE_PROOF_decode(proof_bin, size)))
        goto err;

    if (!TEST_true(BP_RANGE_PROOF_verify(ctx, proof2)))
        goto err;

    if (!TEST_true(BP_RANGE_PROOF_verify(ctx2, proof2)))
        goto err;

    ret = 1;
err:
    OPENSSL_free(pp_bin);
    OPENSSL_free(proof_bin);
    BP_RANGE_PROOF_free(proof);
    BP_RANGE_PROOF_free(proof2);
    BP_RANGE_CTX_free(ctx);
    BP_RANGE_CTX_free(ctx2);
    BP_WITNESS_free(witness);
    BP_TRANSCRIPT_free(transcript);
    BP_TRANSCRIPT_free(transcript2);
    BP_PUB_PARAM_free(pp);
    BP_PUB_PARAM_free(pp2);
    BN_free(v);

    return ret;
}

static int range_proof_tests(void)
{
    int64_t secrets1[] = {0, 1<<7};
    int64_t secrets2[] = {0, 1<<15, (1<<16)-1};
    int64_t secrets3[] = {0, 1<<15, (1<<16)-1, 1<<16};
    int64_t secrets4[] = {0, 1<<15, (1<<16)-1, 1<<16, (1<<16)+1};
    int64_t secrets5[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    int64_t secrets6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    if (!TEST_true(range_proof_test(8, 0))
        || !TEST_true(range_proof_test(16, 1<<1))
        || !TEST_true(range_proof_test(16, 1<<15))
        || !TEST_true(range_proof_test(16, (1<<16)-1))
        || TEST_true(range_proof_test(16, 1<<16))
        || TEST_true(range_proof_test(16, (1<<16)+1))
        || TEST_true(range_proof_test(16, 1<<24))
        || TEST_true(range_proof_test(16, 1LL<<31))
        || !TEST_true(range_proof_test(32, 0))
        || !TEST_true(range_proof_test(32, 1<<1))
        || !TEST_true(range_proof_test(32, 1<<16))
        || !TEST_true(range_proof_test(32, 1LL<<31))
        || !TEST_true(range_proof_test(32, (1LL<<32)-1))
        || TEST_true(range_proof_test(32, 1LL<<32))
        || TEST_true(range_proof_test(32, (1LL<<32)+1))
        || !TEST_true(range_proof_test(64, (1LL<<31) * (1LL<<31)))
        || !TEST_true(range_proofs_test(16, secrets1, sizeof(secrets1)/sizeof(secrets1[0])))
        || !TEST_true(range_proofs_test(16, secrets2, sizeof(secrets2)/sizeof(secrets2[0])))
        || TEST_true(range_proofs_test(16, secrets3, sizeof(secrets3)/sizeof(secrets3[0])))
        || TEST_true(range_proofs_test(16, secrets4, sizeof(secrets4)/sizeof(secrets4[0])))
        || TEST_true(range_proofs_test(16, secrets5, sizeof(secrets5)/sizeof(secrets5[0])))
        || TEST_true(range_proofs_test(16, secrets6, sizeof(secrets6)/sizeof(secrets6[0]))))
        return 0;

    return 1;
}

static int range_proof_encode_tests(void)
{
    if (!TEST_true(range_proof_encode_test(8, 0))
        || !TEST_true(range_proof_encode_test(16, 1<<1))
        || !TEST_true(range_proof_encode_test(16, 1<<15))
        || !TEST_true(range_proof_encode_test(16, (1<<16)-1)))
        return 0;

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(range_proof_tests);
    ADD_TEST(range_proof_encode_tests);
    ADD_TEST(r1cs_range_tests);
    ADD_TEST(r1cs_proof_test1_should_ok);
    ADD_TEST(r1cs_proof_test1_should_failed);
    ADD_TEST(r1cs_proof_test2_should_ok);
    ADD_TEST(r1cs_proof_test2_should_failed);
    ADD_TEST(r1cs_proof_test3_should_ok);
    ADD_TEST(r1cs_proof_test3_should_failed);
    ADD_TEST(r1cs_proof_test4_should_ok);
    ADD_TEST(r1cs_proof_test4_should_failed);
    ADD_TEST(r1cs_proof_test5_should_ok);
    ADD_TEST(r1cs_proof_test5_should_failed);
    ADD_TEST(r1cs_proof_test6_should_ok);
    ADD_TEST(r1cs_proof_test6_should_failed);
    ADD_TEST(r1cs_proof_test7_should_ok);
    ADD_TEST(r1cs_proof_test7_should_failed);
    ADD_TEST(r1cs_proof_test8_should_ok);
    ADD_TEST(r1cs_proof_test8_should_failed);
    ADD_TEST(bp_poly3_eval_test);
    ADD_TEST(bp_poly6_eval_test);
    ADD_TEST(bp_poly3_special_inner_product_test);
    return 1;
}

void cleanup_tests(void)
{
}
