/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/opensslconf.h>
#include <openssl/bn.h>
#include <openssl/bio.h>

#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#include "testutil.h"

#ifndef OPENSSL_NO_ENGINE
static ENGINE *e;
#endif

static const char *hex_numbers[] = {
    "0000000000000000000000000000000000000000000000000000000000000004",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "0000000000000000000000000000000000000000000000000000000000000003",
};

static int bnmeth_engine_test(void)
{
    int ret = 0;
    BN_CTX *ctx1 = NULL, *ctx2 = NULL;
    BIGNUM *a, *b, *m, *r1, *r2;

    ctx1 = BN_CTX_new();
    ctx2 = BN_CTX_new();
    if (ctx1 == NULL || ctx2 == NULL)
        goto err;

    BN_CTX_start(ctx1);
    a = BN_CTX_get(ctx1);
    b = BN_CTX_get(ctx1);
    m = BN_CTX_get(ctx1);
    r1 = BN_CTX_get(ctx1);
    r2 = BN_CTX_get(ctx1);
    if (!TEST_ptr(r2)
        || !TEST_true(BN_CTX_set_engine(ctx1, e))
        || !TEST_true(BN_hex2bn(&a, hex_numbers[0]))
        || !TEST_true(BN_hex2bn(&b, hex_numbers[1]))
        || !TEST_true(BN_hex2bn(&m, hex_numbers[2]))
        || !TEST_true(BN_mod_add(r1, a, b, m, ctx1))
        || !TEST_true(BN_mod_add(r2, a, b, m, ctx2))
        || !TEST_true(BN_add_word(r2, 1))
        || !TEST_int_eq(BN_cmp(r1, r2), 0)
        || !TEST_true(BN_mod_sub(r1, a, b, m, ctx1))
        || !TEST_true(BN_mod_sub(r2, a, b, m, ctx2))
        || !TEST_true(BN_add_word(r2, 1))
        || !TEST_int_eq(BN_cmp(r1, r2), 0)
        || !TEST_true(BN_mul(r1, a, b, ctx1))
        || !TEST_true(BN_mul(r2, a, b, ctx2))
        || !TEST_true(BN_add_word(r2, 1))
        || !TEST_int_eq(BN_cmp(r1, r2), 0)
        || !TEST_true(BN_mod_mul(r1, a, b, m, ctx1))
        || !TEST_true(BN_mod_mul(r2, a, b, m, ctx2))
        || !TEST_true(BN_add_word(r2, 1))
        || !TEST_int_eq(BN_cmp(r1, r2), 0)
        || !TEST_true(BN_mod_exp(r1, a, b, m, ctx1))
        || !TEST_true(BN_mod_exp(r2, a, b, m, ctx2))
        || !TEST_true(BN_add_word(r2, 1))
        || !TEST_int_eq(BN_cmp(r1, r2), 0)
        || !TEST_true(BN_mod_sqr(r1, a, m, ctx1))
        || !TEST_true(BN_mod_sqr(r2, a, m, ctx2))
        || !TEST_true(BN_add_word(r2, 1))
        || !TEST_int_eq(BN_cmp(r1, r2), 0)
        || !TEST_ptr(BN_mod_sqrt(r1, a, m, ctx1))
        || !TEST_ptr(BN_mod_sqrt(r2, a, m, ctx2))
        || !TEST_true(BN_add_word(r2, 1))
        || !TEST_int_eq(BN_cmp(r1, r2), 0)
        || !TEST_ptr(BN_mod_inverse(r1, a, m, ctx1))
        || !TEST_ptr(BN_mod_inverse(r2, a, m, ctx2))
        || !TEST_true(BN_add_word(r2, 1))
        || !TEST_int_eq(BN_cmp(r1, r2), 0)
        || !TEST_true(BN_div(r1, NULL, a, b, ctx1))
        || !TEST_true(BN_div(r2, NULL, a, b, ctx2))
        || !TEST_true(BN_add_word(r2, 1))
        || !TEST_int_eq(BN_cmp(r1, r2), 0))
        goto err;

    ret = 1;
err:
    BN_CTX_end(ctx1);
    BN_CTX_free(ctx1);
    BN_CTX_free(ctx2);
    return ret;
}

#ifndef OPENSSL_NO_ENGINE
int global_init(void)
{
    OPENSSL_load_builtin_modules();
    ENGINE_load_builtin_engines();
    return 1;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ENGINE
    if ((e = ENGINE_by_id("bntest")) == NULL) {
        /* Probably a platform env issue, not a test failure. */
        TEST_info("Can't load bntest engine");
    }
#endif

    ADD_TEST(bnmeth_engine_test);

    return 1;
}

#ifndef OPENSSL_NO_ENGINE
void cleanup_tests(void)
{
    ENGINE_free(e);
}
#endif
