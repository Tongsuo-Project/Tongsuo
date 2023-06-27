/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Low level APIs are deprecated for public use, but still ok for internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include "testutil.h"

#ifndef OPENSSL_NO_SM2

static const char *p_hex = 
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";

static int sm2_mod_test(void){
    int testresult = 0;
    size_t i = 0;

    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *ab = NULL;
    BIGNUM *ab_fast = NULL;
    BN_CTX *ctx = NULL;

    if (!TEST_true(ctx = BN_CTX_new())) {
		goto done;
	}

    /* test BN_get0_sm2_prime_256*/
    if (!TEST_true(BN_hex2bn(&p, p_hex))
        || !TEST_int_eq(BN_ucmp(p, BN_get0_sm2_prime_256()), 0)){
        goto done;
    }

    /* test BN_sm2_mod_256*/
    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    ab_fast = BN_CTX_get(ctx);
    ab = BN_CTX_get(ctx);

    /*
     * Randomly generate two numbers in the prime field and multiply them，
     * then compare the results of fast modular reduction and conventional algorithms.
     */
    for (i = 0; i < 100; i++){
        if (!TEST_true(BN_priv_rand_range_ex(a, p, 0, ctx))
            || !TEST_true(BN_priv_rand_range_ex(b, p, 0, ctx))
            || !TEST_true(BN_mul(ab_fast, a, b, ctx))
            || !TEST_true(BN_sm2_mod_256(ab_fast, ab_fast, p, ctx))
            || !TEST_true(BN_mod_mul(ab, a, b, p, ctx))) {
            goto done;
        }

        if (!TEST_int_eq(BN_ucmp(ab, ab_fast), 0)){
            goto done;
        }
    }

    testresult = 1;

done:
    BN_CTX_free(ctx);
    BN_free(p);

    return testresult;
}

#endif

int setup_tests(void)
{
#ifdef OPENSSL_NO_SM2
    TEST_note("SM2 is disabled.");
#else
    ADD_TEST(sm2_mod_test);
#endif
    return 1;
}
