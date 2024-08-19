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
#include <stdlib.h>
#include <time.h>
#include <openssl/conf.h>
#include <openssl/opensslconf.h>
#include <openssl/zkp_gadget.h>
#include <crypto/ec/ec_local.h>
#include <crypto/zkp/bulletproofs/bulletproofs.h>
#include <crypto/zkp/common/zkp_util.h>

DEFINE_STACK_OF(BIGNUM)

static int generate_random_number(int min, int max)
{
    srand(time(NULL));

    int random_number = rand() % (max - min + 1) + min;
    random_number -= random_number == max ? 1 : 0;
    return random_number;
}

static int zkp_poly3_eval_test(void)
{
    int ret = 0, n = 2, i;
    zkp_poly3_t *p = NULL;
    BIGNUM *order, *x, *r[2], *eval;
    BN_CTX *bn_ctx = NULL;
    STACK_OF(BIGNUM) *sk_eval = NULL;

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

    p = zkp_poly3_new(n, order);
    if (p == NULL)
        goto err;

    for (i = 0; i < n; i++) {
        BN_set_word(p->x0[i], i);
        BN_set_word(p->x1[i], i+1);
        BN_set_word(p->x2[i], i+2);
        BN_set_word(p->x3[i], i+3);
    }

    if (!(sk_eval = zkp_poly3_eval(p, x)))
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
    zkp_poly3_free(p);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    sk_BIGNUM_free(sk_eval);
    return ret;
}

static int zkp_poly6_eval_test(void)
{
    int ret = 0;
    zkp_poly6_t *p = NULL;
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

    p = zkp_poly6_new(order);
    if (p == NULL)
        goto err;

    BN_set_word(p->t1, 1);
    BN_set_word(p->t2, 2);
    BN_set_word(p->t3, 3);
    BN_set_word(p->t4, 4);
    BN_set_word(p->t5, 5);
    BN_set_word(p->t6, 6);

    if (!TEST_true(zkp_poly6_eval(p, x, r)))
        goto err;

    if (BN_cmp(r, e) != 0)
        goto err;

    ret = 1;

err:
    zkp_poly6_free(p);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int zkp_poly3_special_inner_product_test(void)
{
    int ret = 0, n = 2, i;
    zkp_poly3_t *p1 = NULL, *p2 = NULL;
    zkp_poly6_t *p = NULL;
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

    p = zkp_poly6_new(order);
    p1 = zkp_poly3_new(n, order);
    p2 = zkp_poly3_new(n, order);
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

    if (!TEST_true(zkp_poly3_special_inner_product(p, p1, p2)))
        goto err;

    if (!TEST_true(zkp_poly6_eval(p, x, r)))
        goto err;

    if (BN_cmp(r, e) != 0)
        goto err;

    ret = 1;

err:
    zkp_poly6_free(p);
    zkp_poly3_free(p1);
    zkp_poly3_free(p2);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int zkp_range_proof_raw_test(int plaintext, int left_bound_bits, int right_bound_bits)
{
    int ret = 0;
    int curve_id = NID_X9_62_prime256v1;
    ZKP_TRANSCRIPT *transcript = NULL;
    ZKP_RANGE_PUB_PARAM *pp = NULL;
    ZKP_RANGE_WITNESS *witness = NULL;
    ZKP_RANGE_CTX *ctx = NULL;
    ZKP_RANGE_PROOF *proof = NULL;
    EC_KEY *key = NULL;
    EC_ELGAMAL_CTX *enc_ctx = NULL;
    EC_ELGAMAL_CIPHERTEXT *enc_ct = NULL;
    BP_PUB_PARAM *bp_pp = NULL;
    BIGNUM *r, *v;
    BN_CTX *bn_ctx = NULL;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    r = BN_CTX_get(bn_ctx);
    v = BN_CTX_get(bn_ctx);
    if (v == NULL)
        goto err;

    BN_set_word(v, plaintext);

    if (!TEST_ptr(transcript = ZKP_TRANSCRIPT_new(ZKP_TRANSCRIPT_METHOD_sha256(), "test")))
        goto err;

    if (!TEST_ptr(key = EC_KEY_new_by_curve_name(curve_id)))
        goto err;

    if (!TEST_true(EC_KEY_generate_key(key)))
        goto err;

    BN_rand_range(r, EC_GROUP_get0_order(key->group));

    if (!TEST_ptr(bp_pp = BP_PUB_PARAM_new(key->group, 32, 2)))
        goto err;

    if (!TEST_ptr(enc_ctx = EC_ELGAMAL_CTX_new(key, bp_pp->H, EC_ELGAMAL_FLAG_TWISTED)))
        goto err;

    if (!TEST_ptr(enc_ct = EC_ELGAMAL_CIPHERTEXT_new(enc_ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_bn_encrypt(enc_ctx, enc_ct, v, r)))
        goto err;

    if (!TEST_ptr(pp = ZKP_RANGE_PUB_PARAM_raw_new(bp_pp)))
        goto err;

    if (!TEST_ptr(witness = ZKP_RANGE_WITNESS_new(pp, r, v)))
        goto err;

    if (!TEST_ptr(ctx = ZKP_RANGE_CTX_raw_new(transcript, pp, witness, key->pub_key,
                                              enc_ctx, enc_ct)))
        goto err;

    if (!TEST_ptr(proof = ZKP_RANGE_PROOF_prove(ctx, left_bound_bits, right_bound_bits)))
        goto err;

    if (!TEST_true(ZKP_RANGE_PROOF_verify(ctx, proof, left_bound_bits, right_bound_bits)))
        goto err;

    ret = 1;

err:
    ZKP_RANGE_PROOF_free(proof);
    ZKP_RANGE_CTX_free(ctx);
    ZKP_RANGE_WITNESS_free(witness);
    ZKP_RANGE_PUB_PARAM_free(pp);
    BP_PUB_PARAM_free(bp_pp);
    EC_ELGAMAL_CIPHERTEXT_free(enc_ct);
    EC_ELGAMAL_CTX_free(enc_ctx);
    EC_KEY_free(key);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int zkp_range_proof_test(int plaintext, int left_bound_bits, int right_bound_bits)
{
    int ret = 0;
    int curve_id = NID_X9_62_prime256v1;
    ZKP_TRANSCRIPT *transcript = NULL;
    ZKP_RANGE_PUB_PARAM *pp = NULL;
    ZKP_RANGE_WITNESS *witness = NULL;
    ZKP_RANGE_CTX *ctx = NULL;
    ZKP_RANGE_PROOF *proof = NULL;
    EC_KEY *key = NULL;
    BIGNUM *v;
    BN_CTX *bn_ctx = NULL;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    v = BN_CTX_get(bn_ctx);
    if (v == NULL)
        goto err;

    BN_set_word(v, plaintext);

    if (!TEST_ptr(transcript = ZKP_TRANSCRIPT_new(ZKP_TRANSCRIPT_METHOD_sha256(), "test")))
        goto err;

    if (!TEST_ptr(key = EC_KEY_new_by_curve_name(curve_id)))
        goto err;

    if (!TEST_true(EC_KEY_generate_key(key)))
        goto err;

    if (!TEST_ptr(pp = ZKP_RANGE_PUB_PARAM_new(key->group, 32)))
        goto err;

    if (!TEST_ptr(witness = ZKP_RANGE_WITNESS_new(pp, NULL, v)))
        goto err;

    if (!TEST_ptr(ctx = ZKP_RANGE_CTX_new(transcript, pp, witness, key)))
        goto err;

    if (!TEST_ptr(proof = ZKP_RANGE_PROOF_prove(ctx, left_bound_bits, right_bound_bits)))
        goto err;

    if (!TEST_true(ZKP_RANGE_PROOF_verify(ctx, proof, left_bound_bits, right_bound_bits)))
        goto err;

    ret = 1;

err:
    ZKP_RANGE_PROOF_free(proof);
    ZKP_RANGE_CTX_free(ctx);
    ZKP_RANGE_WITNESS_free(witness);
    ZKP_RANGE_PUB_PARAM_free(pp);
    EC_KEY_free(key);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int zkp_range_proof_tests(void)
{
    int plaintext = 0;
    int left_bound_bits = 2, right_bound_bits = 16;

	plaintext = generate_random_number(1 << left_bound_bits, 1 << right_bound_bits);

    if (!TEST_true(zkp_range_proof_raw_test(plaintext, left_bound_bits, right_bound_bits)))
        return 0;

    if (!TEST_true(zkp_range_proof_test(plaintext, left_bound_bits, right_bound_bits)))
        return 0;

    if (TEST_true(zkp_range_proof_test((1 << left_bound_bits) - 1, left_bound_bits, right_bound_bits)))
        return 0;

    if (TEST_true(zkp_range_proof_test(1 << right_bound_bits, left_bound_bits, right_bound_bits)))
        return 0;

    if (!TEST_true(zkp_range_proof_test((1 << right_bound_bits) - 1, left_bound_bits, right_bound_bits)))
        return 0;

    if (!TEST_true(zkp_range_proof_test(1 << 3, 3, 7)))
        return 0;

    if (!TEST_true(zkp_range_proof_test(1 << 4, 3, 7)))
        return 0;

    if (TEST_true(zkp_range_proof_test(1 << 7, 3, 7)))
        return 0;

    if (!TEST_true(zkp_range_proof_test((1 << 7) - 1, 3, 7)))
        return 0;

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(zkp_poly3_eval_test);
    ADD_TEST(zkp_poly6_eval_test);
    ADD_TEST(zkp_poly3_special_inner_product_test);
    ADD_TEST(zkp_range_proof_tests);
    return 1;
}

void cleanup_tests(void)
{
}
