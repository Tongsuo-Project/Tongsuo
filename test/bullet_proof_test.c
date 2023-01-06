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

static int bullet_proof_test(int bits, int64_t secret)
{
    int ret = 0;
    int64_t secrets[1];
    BULLET_PROOF_PUB_PARAM *pp = NULL;
    BULLET_PROOF_WITNESS *witness = NULL;
    BULLET_PROOF_CTX *ctx = NULL;
    BULLET_PROOF *proof = NULL;

    TEST_info("Testing bullet_proof, secret: %lld\n", secret);

    secrets[0] = secret;

    //if (!TEST_ptr(pp = BULLET_PROOF_PUB_PARAM_new(NID_X9_62_prime256v1, bits, 1)))
    if (!TEST_ptr(pp = BULLET_PROOF_PUB_PARAM_new(NID_secp256k1, bits, 1)))
        goto err;

    if (!TEST_ptr(ctx = BULLET_PROOF_CTX_new(pp)))
        goto err;

    if (!TEST_ptr(witness = BULLET_PROOF_WITNESS_new(ctx, secrets, 1)))
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

static int bullet_proof_tests(void)
{
    if (!TEST_true(bullet_proof_test(8, 0))
        || !TEST_true(bullet_proof_test(16, 1<<1))
        || !TEST_true(bullet_proof_test(16, 1<<15))
        || !TEST_true(bullet_proof_test(16, (1<<16)-1))
        || TEST_true(bullet_proof_test(16, 1<<16))
        || TEST_true(bullet_proof_test(16, (1<<16)+1))
        || TEST_true(bullet_proof_test(16, 1<<24))
        || TEST_true(bullet_proof_test(16, 1<<31))
        || !TEST_true(bullet_proof_test(32, 0))
        || !TEST_true(bullet_proof_test(32, 1<<1))
        || !TEST_true(bullet_proof_test(32, 1<<16))
        || !TEST_true(bullet_proof_test(32, 1LL<<31))
        || !TEST_true(bullet_proof_test(32, (1LL<<32)-1))
        || TEST_true(bullet_proof_test(32, 1LL<<32))
        || TEST_true(bullet_proof_test(32, (1LL<<32)+1)))
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
