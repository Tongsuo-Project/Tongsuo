/*
 * Copyright 2022 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

#include <stdio.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/bio.h>

#ifndef OPENSSL_NO_EC
# include <openssl/ec.h>
# ifndef OPENSSL_NO_ENGINE
#  include <openssl/engine.h>
# endif
#include "testutil.h"

# ifndef OPENSSL_NO_ENGINE
static ENGINE *e;
# endif

static const char *scalars_arr[] = {
    "785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10D1FA229B5",
    "0000000000000000000000000000000000000000000000000000000000000002",
};

static int do_ecpmeth_engine_test(int curve_id)
{
    int ret = 0, count;

    BN_CTX *ctx = NULL;
    BIGNUM *scalar1, *scalar2;
    EC_GROUP *group = NULL;
    EC_POINT *R = NULL;
    EC_POINTS *rs = NULL;
    const EC_POINT *G, *points[2];
    const BIGNUM *scalars[2];
# ifndef OPENSSL_NO_ENGINE
    const unsigned char *strings[] = {
        (unsigned char *)"aabb",
        (unsigned char *)"1122334455",
    };
# endif

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    scalar1 = BN_CTX_get(ctx);
    scalar2 = BN_CTX_get(ctx);
    if (!TEST_ptr(scalar2)
        || !TEST_ptr(group = EC_GROUP_new_by_curve_name(curve_id))
# ifndef OPENSSL_NO_ENGINE
        || !TEST_true(EC_GROUP_set_engine(group, e))
# endif
        || !TEST_ptr(G = EC_GROUP_get0_generator(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(BN_hex2bn(&scalar1, scalars_arr[0]))
        || !TEST_true(BN_hex2bn(&scalar2, scalars_arr[1])))
        goto err;

    points[0] = points[1] = G;

    scalars[0] = scalar1;
    scalars[1] = scalar2;

    count = sizeof(points) / sizeof(points[0]);

    if (!TEST_true(EC_POINTs_scalars_mul(group, &rs, count, points, scalars, NULL))
        || !TEST_ptr(rs)
        || !TEST_int_eq(EC_POINTS_count(rs), count))
        goto err;

    EC_POINTS_free(rs);
    rs = NULL;

    if (!TEST_true(EC_POINTs_scalar_mul(group, &rs, count, points, scalar1, NULL))
        || !TEST_ptr(rs)
        || !TEST_int_eq(EC_POINTS_count(rs), count))
        goto err;

    EC_POINTS_free(rs);
    rs = NULL;

# ifndef OPENSSL_NO_ENGINE
    count = sizeof(strings) / sizeof(strings[0]);

    if (!TEST_true(EC_POINTs_from_strings(group, &rs, count, strings, NULL))
        || !TEST_ptr(rs)
        || !TEST_int_eq(EC_POINTS_count(rs), count))
        goto err;

    EC_POINTS_free(rs);
    rs = NULL;

    if (!TEST_true(EC_POINTs_from_strings_scalar_mul(group, &rs, count, strings,
                                                     scalar2, NULL))
        || !TEST_ptr(rs)
        || !TEST_int_eq(EC_POINTS_count(rs), count))
        goto err;
# endif

    ret = 1;

err:
    EC_POINTS_free(rs);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    EC_POINT_free(R);

    EC_GROUP_free(group);

    return ret;
}

static int ecpmeth_engine_test(void)
{
    if (!TEST_true(do_ecpmeth_engine_test(NID_X9_62_prime256v1)))
        return 0;

# ifndef OPENSSL_NO_SM2
    if (!TEST_true(do_ecpmeth_engine_test(NID_sm2)))
        return 0;
# endif

    return 1;
}

#endif /* OPENSSL_NO_EC */

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
    if ((e = ENGINE_by_id("ecptest")) == NULL) {
        /* Probably a platform env issue, not a test failure. */
        TEST_info("Can't load ecptest engine");
    }
#endif

#ifndef OPENSSL_NO_EC
    ADD_TEST(ecpmeth_engine_test);
#endif

    return 1;
}

#ifndef OPENSSL_NO_ENGINE
void cleanup_tests(void)
{
    ENGINE_free(e);
}
#endif
