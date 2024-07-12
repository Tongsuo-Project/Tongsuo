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
#include <openssl/nizk.h>
#include <crypto/ec/ec_elgamal.h>
#include <crypto/zkp/nizk/nizk.h>
#include <crypto/zkp/common/zkp_util.h>

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(EC_KEY)
DEFINE_STACK_OF(EC_POINT)

static int curve_id = NID_X9_62_prime256v1;

static int generate_random_number(int min, int max)
{
    srand(time(NULL));

    int random_number = rand() % (max - min + 1) + min;
    random_number -= random_number == max ? 1 : 0;
    return random_number;
}

static int nizk_plaintext_knowledge_test(int plaintext)
{
    int ret = 0;
    ZKP_TRANSCRIPT *transcript = NULL;
    NIZK_PUB_PARAM *pp = NULL;
    NIZK_WITNESS *witness = NULL;
    NIZK_PLAINTEXT_KNOWLEDGE_CTX *ctx = NULL;
    NIZK_PLAINTEXT_KNOWLEDGE_PROOF *proof = NULL;
    EC_KEY *key = NULL;
    EC_ELGAMAL_CTX *enc_ctx = NULL;
    EC_ELGAMAL_CIPHERTEXT *enc_ct = NULL;
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

    if (!TEST_ptr(enc_ctx = EC_ELGAMAL_CTX_new(key, NULL, EC_ELGAMAL_FLAG_TWISTED)))
        goto err;

    if (!TEST_ptr(enc_ct = EC_ELGAMAL_CIPHERTEXT_new(enc_ctx)))
        goto err;

    if (!TEST_ptr(pp = NIZK_PUB_PARAM_new(key->group, NULL, enc_ctx->h)))
        goto err;

    if (!TEST_ptr(witness = NIZK_WITNESS_new(pp, NULL, v)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_bn_encrypt(enc_ctx, enc_ct, v, witness->r)))
        goto err;

    if (!TEST_ptr(ctx = NIZK_PLAINTEXT_KNOWLEDGE_CTX_new(transcript, pp, witness, key->pub_key, enc_ct)))
        goto err;

    if (!TEST_ptr(proof = NIZK_PLAINTEXT_KNOWLEDGE_PROOF_prove(ctx)))
        goto err;

    if (!TEST_true(NIZK_PLAINTEXT_KNOWLEDGE_PROOF_verify(ctx, proof)))
        goto err;

    ret = 1;

err:
    EC_ELGAMAL_CIPHERTEXT_free(enc_ct);
    EC_ELGAMAL_CTX_free(enc_ctx);
    NIZK_PLAINTEXT_KNOWLEDGE_PROOF_free(proof);
    NIZK_PLAINTEXT_KNOWLEDGE_CTX_free(ctx);
    NIZK_WITNESS_free(witness);
    NIZK_PUB_PARAM_free(pp);
    EC_KEY_free(key);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int nizk_plaintext_equality_test(int plaintext)
{
    int ret = 0;
    ZKP_TRANSCRIPT *transcript = NULL;
    NIZK_PUB_PARAM *pp = NULL;
    NIZK_WITNESS *witness = NULL;
    NIZK_PLAINTEXT_EQUALITY_CTX *ctx = NULL;
    NIZK_PLAINTEXT_EQUALITY_PROOF *proof = NULL;
    EC_KEY *key1 = NULL, *key2 = NULL, *key3 = NULL;
    STACK_OF(EC_KEY) *sk_key = NULL;
    STACK_OF(EC_POINT) *sk_PK = NULL;
    EC_ELGAMAL_MR_CTX *enc_ctx = NULL;
    EC_ELGAMAL_MR_CIPHERTEXT *enc_ct = NULL;
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

    key1 = EC_KEY_new_by_curve_name(curve_id);
    key2 = EC_KEY_new_by_curve_name(curve_id);
    key3 = EC_KEY_new_by_curve_name(curve_id);
    if (!TEST_ptr(key1) || !TEST_ptr(key2) || !TEST_ptr(key3)
        || !TEST_true(EC_KEY_generate_key(key1))
        || !TEST_true(EC_KEY_generate_key(key2))
        || !TEST_true(EC_KEY_generate_key(key3))
        || !TEST_ptr(sk_key = sk_EC_KEY_new_null())
        || !TEST_ptr(sk_PK = sk_EC_POINT_new_null()))
        goto err;

    sk_EC_KEY_push(sk_key, key1);
    sk_EC_KEY_push(sk_key, key2);
    sk_EC_KEY_push(sk_key, key3);
    sk_EC_POINT_push(sk_PK, key1->pub_key);
    sk_EC_POINT_push(sk_PK, key2->pub_key);
    sk_EC_POINT_push(sk_PK, key3->pub_key);

    if (!TEST_ptr(enc_ctx = EC_ELGAMAL_MR_CTX_new(sk_key, NULL, EC_ELGAMAL_FLAG_TWISTED)))
        goto err;

    if (!TEST_ptr(enc_ct = EC_ELGAMAL_MR_CIPHERTEXT_new(enc_ctx)))
        goto err;

    if (!TEST_ptr(pp = NIZK_PUB_PARAM_new(key1->group, NULL, enc_ctx->h)))
        goto err;

    if (!TEST_ptr(witness = NIZK_WITNESS_new(pp, NULL, v)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_MR_encrypt(enc_ctx, enc_ct, v, witness->r)))
        goto err;

    if (!TEST_ptr(ctx = NIZK_PLAINTEXT_EQUALITY_CTX_new(transcript, pp, witness, sk_PK, enc_ct)))
        goto err;

    if (!TEST_ptr(proof = NIZK_PLAINTEXT_EQUALITY_PROOF_prove(ctx)))
        goto err;

    if (!TEST_true(NIZK_PLAINTEXT_EQUALITY_PROOF_verify(ctx, proof)))
        goto err;

    ret = 1;

err:
    EC_ELGAMAL_MR_CTX_free(enc_ctx);
    EC_ELGAMAL_MR_CIPHERTEXT_free(enc_ct);
    NIZK_PLAINTEXT_EQUALITY_PROOF_free(proof);
    NIZK_PLAINTEXT_EQUALITY_CTX_free(ctx);
    NIZK_WITNESS_free(witness);
    NIZK_PUB_PARAM_free(pp);
    BN_CTX_free(bn_ctx);
    sk_EC_POINT_free(sk_PK);
    sk_EC_KEY_free(sk_key);
    EC_KEY_free(key1);
    EC_KEY_free(key2);
    EC_KEY_free(key3);
    return ret;
}

static int nizk_dlog_knowledge_test(int plaintext)
{
    int ret = 0;
    ZKP_TRANSCRIPT *transcript = NULL;
    NIZK_PUB_PARAM *pp = NULL;
    NIZK_WITNESS *witness = NULL;
    NIZK_DLOG_KNOWLEDGE_CTX *ctx = NULL;
    NIZK_DLOG_KNOWLEDGE_PROOF *proof = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *H = NULL;
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

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(curve_id)))
        goto err;

    if (!TEST_ptr(H = EC_POINT_new(group))
        || !TEST_true(EC_POINT_mul(group, H, v, NULL, NULL, bn_ctx)))
        goto err;

    if (!TEST_ptr(pp = NIZK_PUB_PARAM_new(group, NULL, H)))
        goto err;

    if (!TEST_ptr(witness = NIZK_WITNESS_new(pp, NULL, v)))
        goto err;

    if (!TEST_ptr(ctx = NIZK_DLOG_KNOWLEDGE_CTX_new(transcript, pp, witness)))
        goto err;

    if (!TEST_ptr(proof = NIZK_DLOG_KNOWLEDGE_PROOF_prove(ctx)))
        goto err;

    if (!TEST_true(NIZK_DLOG_KNOWLEDGE_PROOF_verify(ctx, proof)))
        goto err;

    ret = 1;

err:
    NIZK_DLOG_KNOWLEDGE_PROOF_free(proof);
    NIZK_DLOG_KNOWLEDGE_CTX_free(ctx);
    NIZK_WITNESS_free(witness);
    NIZK_PUB_PARAM_free(pp);
    EC_GROUP_free(group);
    EC_POINT_free(H);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int nizk_dlog_equality_test(int plaintext)
{
    int ret = 0;
    ZKP_TRANSCRIPT *transcript = NULL;
    NIZK_PUB_PARAM *pp = NULL;
    NIZK_WITNESS *witness = NULL;
    NIZK_DLOG_EQUALITY_CTX *ctx = NULL;
    NIZK_DLOG_EQUALITY_PROOF *proof = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *G1 = NULL, *G2 = NULL, *H1 = NULL, *H2 = NULL;
    BIGNUM *v, *r1, *r2;
    BN_CTX *bn_ctx = NULL;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    r1 = BN_CTX_get(bn_ctx);
    r2 = BN_CTX_get(bn_ctx);
    v = BN_CTX_get(bn_ctx);
    if (v == NULL)
        goto err;

    BN_set_word(v, plaintext);

    if (!TEST_ptr(transcript = ZKP_TRANSCRIPT_new(ZKP_TRANSCRIPT_METHOD_sha256(), "test")))
        goto err;

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(curve_id)))
        goto err;

    zkp_rand_range(r1, EC_GROUP_get0_order(group));
    zkp_rand_range(r2, EC_GROUP_get0_order(group));

    if (!TEST_ptr(G1 = EC_POINT_new(group))
        || !TEST_ptr(G2 = EC_POINT_new(group))
        || !TEST_ptr(H1 = EC_POINT_new(group))
        || !TEST_ptr(H2 = EC_POINT_new(group))
        || !TEST_true(EC_POINT_mul(group, G1, r1, NULL, NULL, bn_ctx))
        || !TEST_true(EC_POINT_mul(group, G2, r2, NULL, NULL, bn_ctx))
        || !TEST_true(EC_POINT_mul(group, H1, NULL, G1, v, bn_ctx))
        || !TEST_true(EC_POINT_mul(group, H2, NULL, G2, v, bn_ctx)))
        goto err;

    if (!TEST_ptr(pp = NIZK_PUB_PARAM_new(group, G1, H1)))
        goto err;

    if (!TEST_ptr(witness = NIZK_WITNESS_new(pp, NULL, v)))
        goto err;

    if (!TEST_ptr(ctx = NIZK_DLOG_EQUALITY_CTX_new(transcript, pp, witness, G2, H2)))
        goto err;

    if (!TEST_ptr(proof = NIZK_DLOG_EQUALITY_PROOF_prove(ctx)))
        goto err;

    if (!TEST_true(NIZK_DLOG_EQUALITY_PROOF_verify(ctx, proof)))
        goto err;

    ret = 1;

err:
    NIZK_DLOG_EQUALITY_PROOF_free(proof);
    NIZK_DLOG_EQUALITY_CTX_free(ctx);
    NIZK_WITNESS_free(witness);
    NIZK_PUB_PARAM_free(pp);
    EC_GROUP_free(group);
    EC_POINT_free(G1);
    EC_POINT_free(G2);
    EC_POINT_free(H1);
    EC_POINT_free(H2);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int nizk_tests(void)
{
    int plaintext = 0;

	plaintext = generate_random_number(0, 1 << 30);

    if (!TEST_true(nizk_plaintext_knowledge_test(plaintext)))
        return 0;

    if (!TEST_true(nizk_plaintext_equality_test(plaintext)))
        return 0;

    if (!TEST_true(nizk_dlog_knowledge_test(plaintext)))
        return 0;

    if (!TEST_true(nizk_dlog_equality_test(plaintext)))
        return 0;

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(nizk_tests);
    return 1;
}

void cleanup_tests(void)
{
}
