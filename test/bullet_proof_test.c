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

static int bullet_proofs_test(int bits, int64_t secrets[], size_t len)
{
    int ret = 0;
    BULLET_PROOF_PUB_PARAM *pp = NULL;
    BULLET_PROOF_WITNESS *witness = NULL;
    BULLET_PROOF_CTX *ctx = NULL;
    BULLET_PROOF *proof = NULL;

    if (!TEST_ptr(pp = BULLET_PROOF_PUB_PARAM_new(NID_secp256k1, bits, 8)))
        goto err;

    if (!TEST_ptr(ctx = BULLET_PROOF_CTX_new(pp, NULL)))
        goto err;

    if (!TEST_ptr(witness = BULLET_PROOF_WITNESS_new(ctx, secrets, len)))
        goto err;

    if (!TEST_ptr(proof = BULLET_PROOF_new(ctx)))
        goto err;

    if (!TEST_true(BULLET_PROOF_prove(ctx, witness, proof)))
        goto err;

    if (!TEST_true(BULLET_PROOF_verify(ctx, proof)))
        goto err;

    ret = 1;
err:
    BULLET_PROOF_free(proof);
    BULLET_PROOF_WITNESS_free(witness);
    BULLET_PROOF_CTX_free(ctx);
    BULLET_PROOF_PUB_PARAM_free(pp);

    return ret;
}

static int bullet_proof_test(int bits, int64_t secret)
{
    int64_t secrets[1];

    secrets[0] = secret;

    return bullet_proofs_test(bits, secrets, 1);
}

static int bullet_proof_encode_test(int bits, int64_t secret)
{
    int ret = 0;
    int64_t secrets[1];
    size_t size;
    unsigned char *pp_bin = NULL, *proof_bin = NULL;
    BULLET_PROOF_PUB_PARAM *pp = NULL, *pp2 = NULL;
    BULLET_PROOF_WITNESS *witness = NULL;
    BULLET_PROOF_CTX *ctx = NULL, *ctx2 = NULL;
    BULLET_PROOF *proof = NULL, *proof2 = NULL;

    secrets[0] = secret;

    if (!TEST_ptr(pp = BULLET_PROOF_PUB_PARAM_new(NID_secp256k1, bits, 8)))
        goto err;

    if (!TEST_ptr(ctx = BULLET_PROOF_CTX_new(pp, NULL)))
        goto err;

    if (!TEST_ptr(witness = BULLET_PROOF_WITNESS_new(ctx, secrets, 1)))
        goto err;

    if (!TEST_ptr(proof = BULLET_PROOF_new(ctx)))
        goto err;

    if (!TEST_true(BULLET_PROOF_prove(ctx, witness, proof)))
        goto err;

    if (!TEST_true(BULLET_PROOF_verify(ctx, proof)))
        goto err;

    size = BULLET_PROOF_PUB_PARAM_encode(pp, NULL, 0);
    if (size == 0)
        goto err;

    if (!TEST_ptr(pp_bin = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_size_t_eq(BULLET_PROOF_PUB_PARAM_encode(pp, pp_bin, size), size))
        goto err;

    if (!TEST_ptr(pp2 = BULLET_PROOF_PUB_PARAM_decode(pp_bin, size)))
        goto err;

    if (!TEST_ptr(ctx2 = BULLET_PROOF_CTX_new(pp2, NULL)))
        goto err;

    if (!TEST_true(BULLET_PROOF_verify(ctx2, proof)))
        goto err;

    size = BULLET_PROOF_encode(ctx, proof, NULL, 0);
    if (size == 0)
        goto err;

    if (!TEST_ptr(proof_bin = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_size_t_eq(BULLET_PROOF_encode(ctx, proof, proof_bin, size), size))
        goto err;

    if (!TEST_ptr(proof2 = BULLET_PROOF_decode(ctx, proof_bin, size)))
        goto err;

    if (!TEST_true(BULLET_PROOF_verify(ctx, proof2)))
        goto err;

    if (!TEST_true(BULLET_PROOF_verify(ctx2, proof2)))
        goto err;

    ret = 1;
err:
    OPENSSL_free(pp_bin);
    OPENSSL_free(proof_bin);
    BULLET_PROOF_free(proof);
    BULLET_PROOF_free(proof2);
    BULLET_PROOF_WITNESS_free(witness);
    BULLET_PROOF_CTX_free(ctx);
    BULLET_PROOF_CTX_free(ctx2);
    BULLET_PROOF_PUB_PARAM_free(pp);
    BULLET_PROOF_PUB_PARAM_free(pp2);

    return ret;
}

static int bullet_proof_tests(void)
{
    int64_t secrets1[] = {0, 1<<7};
    int64_t secrets2[] = {0, 1<<15, (1<<16)-1};
    int64_t secrets3[] = {0, 1<<15, (1<<16)-1, 1<<16};
    int64_t secrets4[] = {0, 1<<15, (1<<16)-1, 1<<16, (1<<16)+1};
    int64_t secrets5[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    int64_t secrets6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    if (!TEST_true(bullet_proof_test(8, 0))
        || !TEST_true(bullet_proof_test(16, 1<<1))
        || !TEST_true(bullet_proof_test(16, 1<<15))
        || !TEST_true(bullet_proof_test(16, (1<<16)-1))
        || TEST_true(bullet_proof_test(16, 1<<16))
        || TEST_true(bullet_proof_test(16, (1<<16)+1))
        || TEST_true(bullet_proof_test(16, 1<<24))
        || TEST_true(bullet_proof_test(16, 1LL<<31))
        || !TEST_true(bullet_proof_test(32, 0))
        || !TEST_true(bullet_proof_test(32, 1<<1))
        || !TEST_true(bullet_proof_test(32, 1<<16))
        || !TEST_true(bullet_proof_test(32, 1LL<<31))
        || !TEST_true(bullet_proof_test(32, (1LL<<32)-1))
        || TEST_true(bullet_proof_test(32, 1LL<<32))
        || TEST_true(bullet_proof_test(32, (1LL<<32)+1))
        || !TEST_true(bullet_proof_test(64, (1LL<<31) * (1LL<<31)))
        || !TEST_true(bullet_proofs_test(16, secrets1, sizeof(secrets1)/sizeof(secrets1[0])))
        || !TEST_true(bullet_proofs_test(16, secrets2, sizeof(secrets2)/sizeof(secrets2[0])))
        || TEST_true(bullet_proofs_test(16, secrets3, sizeof(secrets3)/sizeof(secrets3[0])))
        || TEST_true(bullet_proofs_test(16, secrets4, sizeof(secrets4)/sizeof(secrets4[0])))
        || TEST_true(bullet_proofs_test(16, secrets5, sizeof(secrets5)/sizeof(secrets5[0])))
        || TEST_true(bullet_proofs_test(16, secrets6, sizeof(secrets6)/sizeof(secrets6[0]))))
        return 0;

    if (!TEST_true(bullet_proof_encode_test(8, 0))
        || !TEST_true(bullet_proof_encode_test(16, 1<<1))
        || !TEST_true(bullet_proof_encode_test(16, 1<<15))
        || !TEST_true(bullet_proof_encode_test(16, (1<<16)-1)))
        return 0;

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(bullet_proof_tests);
    return 1;
}

void cleanup_tests(void)
{
}
